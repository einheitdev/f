#!/usr/bin/env python3
"""A masquerading box with an empty neighbour table resolves its own hop.

The finding this exists for was measured, twice, under qemu on
2026-08-15, and it is worse than "the first flow after a reboot is
lost". A masquerading box cannot resolve a next hop from the traffic it
forwards AT ALL. `bpf_fib_lookup` answers NO_NEIGH, the datapath hands
the frame to the stack precisely so the stack will ARP for it, and the
stack does not: the source has already been translated to one of the
box's own addresses and `fib_validate_source` discards it as a martian
before anything asks for a neighbour. Seven forwarded frames across a
TCP client's entire retry window all counted in `no_neigh`, `routed`
stayed 0, nothing reached the far side's wire, and afterwards the box's
neighbour table STILL held no entry of ANY state for that next hop —
not REACHABLE, not FAILED, not INCOMPLETE. No ARP was ever sent.

A reboot empties the neighbour table. So a masquerading appliance comes
back from a power cut with every field reading healthy and carries
nothing, until something the box itself originates happens to go the
same way. On a real box chrony or dnsmasq would probably do it by
accident — and failing closed makes that luck LESS likely, not more,
because a box that is not forwarding is also not serving the queries
that would have resolved the hop.

What the fix does
-----------------
`bpf_fib_lookup` has already resolved the route by the time it reports
NO_NEIGH: the next hop is in `fib.ipv4_dst` and the egress device in
`fib.ifindex`. The datapath records the pair in `fwl_neigh_wanted`, and
`fd` asks the KERNEL to resolve what turns up there (rtnetlink
RTM_NEWNEIGH + NTF_USE, so the only frames on the wire are the ARP the
kernel would have sent for the packet, under the kernel's own retransmit
limits). The first frame is still lost and still counted; the sender's
retransmit crosses.

The topology, and why it has two hops
-------------------------------------
::

  ns cnclient  10.20.1.5 --- cnlan0 [XDP: masquerade + redirect to wan]
                              | 10.20.1.1
                            cnwan0  10.20.2.1  [XDP: de-NAT + redirect]
                              |
                            10.20.2.2  ns cnrouter  10.20.3.1
                              |
                            ns cnfar  10.20.3.9  (a real TCP server)

The box routes to 10.20.3.0/24 VIA 10.20.2.2, so the destination and
the next hop are different addresses. That is deliberate: it is the
only way to show that what gets resolved is the FIB's next hop and not
the packet's destination, which is the difference between resolving the
gateway and ARPing for a host two hops away that nothing will answer
for. The other netns bench in this tree is single-hop, and so is the
qemu walk the finding came from, so neither could put that question.

What must be true for a PASS
----------------------------
1. The neighbour table is EMPTY for the next hop before the probe, in
   every state — read back from the kernel, not assumed. That is the
   post-reboot condition, established rather than described.
2. Nothing else on the box speaks. Proven, not asserted: an independent
   ARP witness runs in the ROUTER's namespace — the far side of the
   segment, not the box making the claim — and the control below
   records ZERO ARP requests for the next hop across the same window.
3. A real TCP flow from the client completes, and the far side's own
   kernel names the peer as 10.20.2.1, the uplink address. Acceptance
   and translation in one object; neither is evidence without the other.
4. `routed` moves and `no_neigh` moves. The symptom must not have
   become invisible — only rare. A run where `no_neigh` stayed at 0
   would mean something other than this path carried the packets.
5. The kernel's neighbour table holds the NEXT HOP in a usable state
   afterwards, and holds no entry at all for the destination two hops
   away.

The control, and why it is a plant rather than a second topology
---------------------------------------------------------------
A box that forwards because something else woke the hop is
indistinguishable from one that resolved it itself. So the same
topology, the same policy, the same sockets and the same quiet segment
are run against a bundle whose datapath has had exactly one line
removed — the `fwl_want_neigh()` call — which is the pre-fix datapath
and nothing else. It still loads, still attaches, still masquerades,
still counts `no_neigh`. If the flow crosses there too, then something
other than this change is resolving the hop and the green run above
proves nothing.

THIS BENCH WRITES A GLOBAL KERNEL KNOB. `net.ipv4.ip_forward` is
per-namespace but not per-bench: on a workstation that routes for its
own VMs, the seconds this file spends with it anywhere but where it
found it are seconds those guests may have no path out. It happened
once, and it cost the operator his VM's routing. So the restore is
registered with `atexit` AND with the three signals that otherwise skip
it, it is verified by reading the knob back, and the value is PRINTED on
every run.

Usage:
  sudo python3 cold_neighbour_netns.py --fd build/fd [--fwl fwl]
"""
import argparse
import atexit
import json
import os
import pathlib
import shutil
import signal
import subprocess
import sys
import tempfile
import time

HERE = pathlib.Path(__file__).resolve().parent
WS = HERE.parent.parent
sys.path.insert(0, str(WS))
REALSOCK = HERE / "hw" / "realsock.py"
ARP_WITNESS = HERE / "arp_witness.py"
XDP_PASS_SRC = HERE / "xdp_pass.bpf.c"
PIN_ROOT = "/sys/fs/bpf/f-coldneigh"
FWD = pathlib.Path("/proc/sys/net/ipv4/ip_forward")

# The box's two data-plane legs, and the namespace on the far end of
# each: <box device>, <namespace>, <peer device>, <box addr>, <peer addr>.
LAN = ("cnlan0", "cnclient", "cnlan0p", "10.20.1.1", "10.20.1.5")
WAN = ("cnwan0", "cnrouter", "cnwan0p", "10.20.2.1", "10.20.2.2")
LEGS = (LAN, WAN)
# The router's second leg, into the far namespace. The box has no
# address on this segment and no interface on it; it reaches it only
# through the next hop.
FAR_DEV = "cnfar0"
FAR_PEER = "cnfar0p"
FAR_NS = "cnfar"
ROUTER_FAR_ADDR = "10.20.3.1"
FAR_ADDR = "10.20.3.9"
FAR_NET = "10.20.3.0/24"

UPLINK_ADDR = WAN[3]
NEXT_HOP = WAN[4]
PORT = 8455
N_CONNS = 3
ROUTE_SLOT = ("routed", "bridged", "no_route", "no_neigh")
# The generated call this bench removes to build its control. One line,
# and it is the whole change under test on the datapath side.
WANT_CALL = "fwl_want_neigh(fib.ifindex, fib.ipv4_dst);"


class Result:
  """Verdicts, printed as they are reached."""

  def __init__(self):
    """Start with nothing decided."""
    self.failed = 0
    self.checks = 0

  def check(self, ok, what):
    """Record one verdict and return it."""
    self.checks += 1
    if not ok:
      self.failed += 1
    print(f"[cn] {'PASS' if ok else 'FAIL'}: {what}", flush=True)
    return bool(ok)

  def note(self, what):
    """Record something observed that is not a verdict."""
    print(f"[cn] NOTE: {what}", flush=True)


def run(cmd, check=False, ns=None):
  """Run `cmd`, optionally inside network namespace `ns`."""
  argv = list(cmd)
  if ns is not None:
    argv = ["ip", "netns", "exec", ns] + argv
  return subprocess.run(argv, check=check, text=True,
                        capture_output=True)


def quiet(cmd, ns=None):
  """Run `cmd` and ignore its outcome. Teardown only."""
  try:
    run(cmd, ns=ns)
  except OSError:
    pass


def policy_text():
  """The office gateway, in the shape `deploy/firstboot` writes it.

  One inside zone that masquerades and redirects to the uplink, and an
  uplink that de-NATs the replies and sends them back. `masquerade` is
  what makes the next hop unresolvable from forwarded traffic, so it is
  not decoration here: the same policy without it heals by itself and
  measures nothing.
  """
  return f"""\
zone lan = [{LAN[0]}]
zone wan = [{WAN[0]}]

@xdp(lan)

count lan_out
masquerade if pkt.proto == tcp
redirect to wan
allow

@xdp(wan)

count wan_in
redirect to lan if pkt.dst_ip in 10.20.1.0/24
allow
"""


def teardown():
  """Remove everything this bench creates. Safe to call twice."""
  for dev, ns, peer, _, _ in LEGS:
    quiet(["ip", "link", "set", "dev", dev, "xdp", "off"])
    quiet(["ip", "link", "set", "dev", peer, "xdp", "off"], ns=ns)
    quiet(["ip", "link", "del", dev])
  quiet(["ip", "link", "del", FAR_DEV])
  for ns in (LAN[1], WAN[1], FAR_NS):
    quiet(["ip", "netns", "del", ns])
  shutil.rmtree(PIN_ROOT, ignore_errors=True)


def arm_forwarding_restore(saved):
  """Put the HOST's own forwarding back on every exit path, loudly."""
  done = []

  def restore(*_):
    """Restore once, verify by reading back, and report either way."""
    if done:
      return
    done.append(True)
    try:
      FWD.write_text(saved)
    except OSError as exc:
      print(f"[cn] RESTORE FAILED: could not write {FWD} ({exc}); set "
            f"it back with `sysctl -w "
            f"net.ipv4.ip_forward={saved.strip()}`",
            file=sys.stderr, flush=True)
      return
    now = FWD.read_text().strip()
    print(f"[cn] restored net.ipv4.ip_forward = {now} (it was "
          f"{saved.strip()} when this run started)", flush=True)
    if now != saved.strip():
      print(f"[cn] RESTORE FAILED: {FWD} reads {now}, wanted "
            f"{saved.strip()}", file=sys.stderr, flush=True)

  atexit.register(restore)
  for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
    signal.signal(sig, lambda *_: sys.exit(1))


def build_topology(work, res):
  """Two veth pairs off the box, plus the router's leg to the far side."""
  obj = work / "xdp_pass.bpf.o"
  clang = subprocess.run(
      ["clang", "-O2", "-g", "-target", "bpf",
       "-I/usr/include/x86_64-linux-gnu",
       "-I/usr/include/aarch64-linux-gnu",
       "-c", str(XDP_PASS_SRC), "-o", str(obj)],
      text=True, capture_output=True)
  if not res.check(clang.returncode == 0,
                   f"compiled xdp_pass ({clang.stderr.strip() or 'ok'})"):
    return False
  for ns in (LAN[1], WAN[1], FAR_NS):
    run(["ip", "netns", "add", ns], check=True)
    run(["ip", "link", "set", "lo", "up"], ns=ns, check=True)
  for dev, ns, peer, box_addr, peer_addr in LEGS:
    run(["ip", "link", "add", dev, "type", "veth", "peer", "name",
         peer], check=True)
    run(["ip", "link", "set", peer, "netns", ns], check=True)
    run(["ip", "link", "set", dev, "up"], check=True)
    run(["ip", "addr", "add", f"{box_addr}/24", "dev", dev], check=True)
    run(["ip", "link", "set", peer, "up"], ns=ns, check=True)
    run(["ip", "addr", "add", f"{peer_addr}/24", "dev", peer], ns=ns,
        check=True)
    # A veth pair keeps CHECKSUM_PARTIAL end to end, so a NAT's
    # incremental checksum update lands on a base that was never valid
    # and the far stack drops the frame with Tcp:InCsumErrors. On copper
    # the sending NIC has already computed it, which is why this is a
    # bench artifact and not a product one.
    for end, where in ((dev, None), (peer, ns)):
      run(["ethtool", "-K", end, "tx", "off", "rx", "off", "tso", "off",
           "gso", "off", "gro", "off"], ns=where)
    # veth's ndo_xdp_xmit needs an XDP program on the RECEIVING side, or
    # a redirect into this leg is dropped below the host.
    attached = run(["ip", "link", "set", "dev", peer, "xdpdrv", "obj",
                    str(obj), "sec", "xdp"], ns=ns)
    if attached.returncode != 0:
      attached = run(["ip", "link", "set", "dev", peer, "xdp", "obj",
                      str(obj), "sec", "xdp"], ns=ns)
    if not res.check(attached.returncode == 0,
                     f"xdp_pass on {peer} "
                     f"({attached.stderr.strip() or 'ok'})"):
      return False

  # The router's second leg, and the far host behind it.
  run(["ip", "link", "add", FAR_DEV, "type", "veth", "peer", "name",
       FAR_PEER], check=True)
  run(["ip", "link", "set", FAR_DEV, "netns", WAN[1]], check=True)
  run(["ip", "link", "set", FAR_PEER, "netns", FAR_NS], check=True)
  run(["ip", "link", "set", FAR_DEV, "up"], ns=WAN[1], check=True)
  run(["ip", "addr", "add", f"{ROUTER_FAR_ADDR}/24", "dev", FAR_DEV],
      ns=WAN[1], check=True)
  run(["ip", "link", "set", FAR_PEER, "up"], ns=FAR_NS, check=True)
  run(["ip", "addr", "add", f"{FAR_ADDR}/24", "dev", FAR_PEER],
      ns=FAR_NS, check=True)
  for end, where in ((FAR_DEV, WAN[1]), (FAR_PEER, FAR_NS)):
    run(["ethtool", "-K", end, "tx", "off", "rx", "off", "tso", "off",
         "gso", "off", "gro", "off"], ns=where)
  # Per-namespace, so the host's own knob is untouched by this line.
  run(["sysctl", "-w", "net.ipv4.ip_forward=1"], ns=WAN[1], check=True)
  run(["ip", "route", "add", "default", "via", ROUTER_FAR_ADDR],
      ns=FAR_NS, check=True)
  run(["ip", "route", "add", "default", "via", LAN[3]], ns=LAN[1],
      check=True)
  # THE route that makes this bench two-hop: the far network is reached
  # through the next hop, so the address that has to be resolved is not
  # the address the client is talking to.
  run(["ip", "route", "add", FAR_NET, "via", NEXT_HOP, "dev", WAN[0]],
      check=True)
  return True


def compile_bundles(args, work, res):
  """Compile the policy twice: as it is, and with the record removed.

  The second is the control, and it is a plant of the DEFECT rather than
  of an error: one generated call goes, the object is rebuilt with the
  same compiler, and everything else about the bundle is identical. A
  control built from a different topology or a different policy would
  not be one variable.

  Returns:
    (live_dir, blind_dir) or (None, None).
  """
  from fwl import bpf_runner
  src = work / "gw.fw"
  src.write_text(policy_text())
  live = work / "live"
  env = dict(os.environ)
  env["PYTHONPATH"] = os.pathsep.join(
      [str(WS)] + ([env["PYTHONPATH"]] if "PYTHONPATH" in env else []))
  compiled = subprocess.run(
      [args.fwl, "compile", str(src), "--bundle", str(live / "current")],
      text=True, capture_output=True, env=env)
  if not res.check(compiled.returncode == 0,
                   f"fwl compiled the gateway bundle "
                   f"({compiled.stderr.strip() or 'ok'})"):
    return None, None
  lan_c = (live / "current" / "lan.bpf.c").read_text()
  if not res.check(WANT_CALL in lan_c,
                   "the datapath records the next hop it could not "
                   "address"):
    return None, None
  if not res.check(
      'fwl_neigh_wanted SEC(".maps")' in lan_c,
      "...into a map the daemon can read"):
    return None, None

  blind = work / "blind"
  shutil.copytree(live, blind)
  for zone in ("lan", "wan"):
    path = blind / "current" / f"{zone}.bpf.c"
    text = path.read_text()
    if WANT_CALL not in text:
      continue
    text = text.replace(WANT_CALL, "")
    path.write_text(text)
    try:
      built = bpf_runner.compile_c(text, work_dir=blind / "current")
    except Exception as exc:  # noqa: BLE001 - reported, not swallowed
      res.check(False, f"control: could not rebuild {zone}.bpf.o ({exc})")
      return None, None
    built.obj_path.replace(blind / "current" / f"{zone}.bpf.o")
  res.check(
      WANT_CALL not in (blind / "current" / "lan.bpf.c").read_text(),
      "control bundle built: the same policy with the next-hop record "
      "removed, and nothing else")
  return live, blind


def start_fd(fd_bin, bundle, work, name, sock):
  """Cold-boot `fd` against a bundle directory."""
  log = open(work / f"fd-{name}.log", "w")
  return subprocess.Popen(
      [fd_bin, "--bundle-dir", str(bundle), "--pin-path", PIN_ROOT,
       "--socket", sock, "-l", "debug", "run"],
      stdout=log, stderr=subprocess.STDOUT)


def wait_for_attach(timeout_s=25.0):
  """The box devices carrying an XDP program, once both do."""
  deadline = time.monotonic() + timeout_s
  while time.monotonic() < deadline:
    live = [dev for dev, _, _, _, _ in LEGS
            if "xdp" in run(["ip", "link", "show", dev]).stdout]
    if len(live) == len(LEGS):
      return live
    time.sleep(0.25)
  return [dev for dev, _, _, _, _ in LEGS
          if "xdp" in run(["ip", "link", "show", dev]).stdout]


def neigh_lines(dev=None):
  """The kernel's IPv4 neighbour table, as lines."""
  cmd = ["ip", "-4", "neigh", "show"]
  if dev is not None:
    cmd += ["dev", dev]
  return [ln.strip() for ln in run(cmd).stdout.splitlines() if ln.strip()]


def neigh_entry(addr, dev=None):
  """The table's line for `addr`, or "" when there is none of ANY state.

  The distinction the whole finding turns on. A box that had dropped
  seven forwarded frames held no entry of any state — not REACHABLE, not
  FAILED, not INCOMPLETE — because nothing had ever asked.
  """
  for line in neigh_lines(dev):
    if line.split()[0] == addr:
      return line
  return ""


def usable(line):
  """Whether a neighbour line is one bpf_fib_lookup would take a MAC from.

  NUD_VALID, which is six states and not two: a next hop in STALE or
  DELAY routes perfectly well. `ip` prints the state as the last word.
  """
  return "lladdr" in line and any(
      s in line for s in ("REACHABLE", "STALE", "DELAY", "PROBE",
                          "PERMANENT", "NOARP"))


def fd_state(fctl, sock):
  """`fctl status`, through the path an operator has."""
  out = run([fctl, "-s", sock, "status"])
  if out.returncode != 0:
    return {}
  try:
    return json.loads(out.stdout)
  except json.JSONDecodeError:
    return {}


def route_tally(state):
  """The datapath's routing counters out of a status reply."""
  route = state.get("route", {})
  return {name: int(route.get(name, 0)) for name in ROUTE_SLOT}


def start_arp_witness(work, name, seconds):
  """Watch the wan segment from the ROUTER's side, not the box's."""
  out = open(work / f"arp-{name}.json", "w")
  return subprocess.Popen(
      ["ip", "netns", "exec", WAN[1], sys.executable, str(ARP_WITNESS),
       WAN[2], str(seconds)],
      stdout=out, stderr=subprocess.PIPE, text=True)


def read_arp_witness(proc, work, name):
  """Collect the witness's frames. Never raises into a verdict."""
  try:
    proc.wait(timeout=60)
  except subprocess.TimeoutExpired:
    proc.terminate()
    proc.wait(timeout=10)
  try:
    return json.loads((work / f"arp-{name}.json").read_text())["frames"]
  except (OSError, ValueError, KeyError):
    return []


def exchange(work, name, expect):
  """One real TCP exchange from the client to the far side.

  Both ends are ordinary blocking sockets on ordinary Linux stacks, so
  a byte arrives only if the kernel accepted the frame that carried it:
  right MAC, right address, right checksum, and a handshake that
  completed. Returns (client_report, server_report).
  """
  server = subprocess.Popen(
      ["ip", "netns", "exec", FAR_NS, sys.executable, str(REALSOCK),
       "server", FAR_ADDR, str(PORT), str(N_CONNS), "25"],
      stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
  time.sleep(1.0)
  client = subprocess.Popen(
      ["ip", "netns", "exec", LAN[1], sys.executable, str(REALSOCK),
       "client", FAR_ADDR, str(PORT), str(N_CONNS), "12"],
      stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
  cli_out, cli_err = client.communicate(timeout=120)
  srv_out, _ = server.communicate(timeout=60)
  try:
    cli = json.loads(cli_out)
  except json.JSONDecodeError:
    cli = {"completed": -1, "raw": cli_out, "err": cli_err}
  try:
    srv = json.loads(srv_out)
  except json.JSONDecodeError:
    srv = {"accepted": -1, "peer_addrs": [], "raw": srv_out}
  (work / f"exchange-{name}.json").write_text(
      json.dumps({"expect": expect, "client": cli, "server": srv},
                 indent=2))
  return cli, srv


def go_cold(res, label):
  """Empty the neighbour table and PROVE it is empty.

  This is the post-reboot condition, and it is established rather than
  described: a phase that flushed and carried on would be claiming the
  most important precondition it has.
  """
  for dev, _, _, _, _ in LEGS:
    run(["ip", "neigh", "flush", "dev", dev])
  time.sleep(0.3)
  entry = neigh_entry(NEXT_HOP)
  return res.check(
      entry == "",
      f"{label}: the box holds NO neighbour entry for the next hop "
      f"{NEXT_HOP}, in any state (table: {neigh_lines() or 'empty'})")


def phase(res, args, fctl, work, bundle, name, expect_cross):
  """One cold-boot probe against one bundle. The whole measurement.

  `expect_cross` is what the flow must do: True for the fixed datapath,
  False for the control. Both run the identical topology, policy,
  sockets and quiet segment.
  """
  sock = f"ipc://{work}/{name}.sock"
  proc = start_fd(args.fd, bundle, work, name, sock)
  try:
    live = wait_for_attach()
    if not res.check(len(live) == len(LEGS),
                     f"{name}: fd attached both zones (got {live})"):
      print((work / f"fd-{name}.log").read_text())
      return
    if not go_cold(res, name):
      return
    before = fd_state(fctl, sock)
    res.note(f"{name}: route tally before {route_tally(before)}")
    # The witness starts BEFORE the probe and outlives it, so an ARP
    # exchange that happened at any point in the window is seen — and
    # so that the control's zero is a zero over the whole window rather
    # than over a slice of it.
    witness = start_arp_witness(work, name, 40)
    time.sleep(0.5)
    cli, srv = exchange(work, name, expect_cross)
    frames = read_arp_witness(witness, work, name)
    after = fd_state(fctl, sock)
    tally_before, tally_after = route_tally(before), route_tally(after)
    res.note(f"{name}: route tally after {tally_after}")
    res.note(f"{name}: fd neigh state {after.get('neigh')}")

    completed = cli.get("completed", -1)
    accepted = srv.get("accepted", -1)
    peers = srv.get("peer_addrs", [])
    want = N_CONNS if expect_cross else 0
    res.check(completed == want,
              f"{name}: the client completed {completed}/{N_CONNS} "
              f"(expected {want})")
    res.check(accepted == want,
              f"{name}: the far side accepted {accepted} connection(s) "
              f"(expected {want})")

    asked = [f for f in frames
             if f["op"] == "request" and f["target_ip"] == NEXT_HOP]
    res.note(f"{name}: {len(frames)} ARP frame(s) on the wan wire, "
             f"{len(asked)} of them asking for {NEXT_HOP}")
    entry = neigh_entry(NEXT_HOP)
    routed = tally_after["routed"] - tally_before["routed"]
    no_neigh = tally_after["no_neigh"] - tally_before["no_neigh"]
    neigh = after.get("neigh", {})

    if expect_cross:
      res.check(peers == [UPLINK_ADDR],
                f"{name}: every peer the far side saw was the uplink "
                f"address {UPLINK_ADDR} (saw {peers})")
      res.check(routed > 0,
                f"{name}: the datapath ROUTED {routed} frame(s) "
                f"(no_route {tally_after['no_route']})")
      # The symptom stays visible. A run in which no_neigh never moved
      # would mean the hop was already resolved and this phase measured
      # nothing at all.
      res.check(no_neigh > 0,
                f"{name}: no_neigh moved by {no_neigh} — the first "
                f"frame was still lost, and still counted")
      res.check(usable(entry),
                f"{name}: the kernel's neighbour table now holds the "
                f"next hop in a usable state: {entry or '(absent)'}")
      res.check(neigh.get("solicited", 0) > 0,
                f"{name}: fd asked the kernel to resolve it "
                f"{neigh.get('solicited')} time(s)")
      res.check(neigh.get("resolved", 0) > 0,
                f"{name}: fd saw {neigh.get('resolved')} next hop(s) "
                f"resolve, and stopped asking")
      res.check(not neigh.get("unresolved"),
                f"{name}: nothing is left unresolved "
                f"({neigh.get('unresolved')})")
      res.check(neigh.get("off_datapath", 0) == 0,
                f"{name}: fd solicited nothing off the datapath "
                f"({neigh.get('off_datapath')})")
      res.check(len(asked) > 0,
                f"{name}: the wan wire carried {len(asked)} ARP "
                f"request(s) for {NEXT_HOP}, witnessed from the far "
                f"side of the segment")
      # The two-hop question: what got resolved is the FIB's next hop,
      # not the address the client was talking to. A daemon that
      # recorded the packet's destination would ARP for a host two hops
      # away and nothing would answer.
      res.check(neigh_entry(FAR_ADDR) == "",
                f"{name}: the box holds no neighbour entry for the "
                f"DESTINATION {FAR_ADDR} — it resolved the next hop, "
                f"not the far host")
    else:
      # The control. Same everything, one generated line removed.
      res.check(no_neigh > 0,
                f"{name}: control: no_neigh moved by {no_neigh}, so "
                f"the datapath did meet the condition")
      res.check(routed == 0,
                f"{name}: control: nothing was routed ({routed})")
      res.check(entry == "",
                f"{name}: control: the neighbour table STILL holds no "
                f"entry of any state for {NEXT_HOP} "
                f"(got {entry or '(absent)'})")
      res.check(len(asked) == 0,
                f"{name}: control: the segment stayed quiet — {len(asked)} "
                f"ARP request(s) for {NEXT_HOP} in the same window, so "
                f"nothing else on this box resolves it")
      res.check(neigh.get("solicited", 0) == 0,
                f"{name}: control: fd solicited nothing "
                f"({neigh.get('solicited')})")
  finally:
    proc.send_signal(signal.SIGTERM)
    try:
      proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
      proc.kill()
    shutil.rmtree(PIN_ROOT, ignore_errors=True)
    os.makedirs(PIN_ROOT, exist_ok=True)


def report_quiet(res):
  """Record what else on this host could have woken the hop.

  Not a verdict: the control is what proves the segment is quiet. This
  is here because the claim being made is about a box on which nothing
  else speaks, and a reader is entitled to see the state of the services
  the finding named.
  """
  for unit in ("chrony", "chronyd", "systemd-timesyncd", "dnsmasq",
               "ntp", "ntpsec"):
    out = run(["systemctl", "is-active", unit])
    res.note(f"quiet check: {unit} is {out.stdout.strip() or 'unknown'}")


def main():
  """Build the bench, run both phases, and report."""
  ap = argparse.ArgumentParser(description=__doc__)
  ap.add_argument("--fd", required=True, help="path to the fd binary")
  ap.add_argument("--fwl", default="fwl", help="the fwl compiler")
  ap.add_argument("--fctl", default=None,
                  help="path to fctl (default: beside fd)")
  args = ap.parse_args()
  res = Result()
  if os.geteuid() != 0:
    print("[cn] needs root (bpffs, netns, XDP, rtnetlink)",
          file=sys.stderr)
    return 2
  if not os.access(args.fd, os.X_OK):
    print(f"[cn] not executable: {args.fd}", file=sys.stderr)
    return 2
  if not os.path.ismount("/sys/fs/bpf"):
    run(["mount", "-t", "bpf", "bpf", "/sys/fs/bpf"], check=True)
  # /sbin is not on a non-login root shell's PATH on Debian, and
  # `shutil.which` alone once reported `not installed: ethtool` on a
  # host where it is installed. `ethtool` is load-bearing here, not
  # cosmetic — see build_topology.
  sbin = ["/usr/local/sbin", "/usr/sbin", "/sbin"]
  path = os.pathsep.join([os.environ.get("PATH", "")] + sbin)
  missing = [t for t in ("ip", "ethtool", "clang", "sysctl")
             if shutil.which(t, path=path) is None]
  if missing:
    print(f"[cn] BLOCKED: not installed: {', '.join(missing)}",
          file=sys.stderr)
    return 2
  os.environ["PATH"] = path
  fctl = args.fctl or str(pathlib.Path(args.fd).resolve().parent / "fctl")
  if not os.access(fctl, os.X_OK):
    print(f"[cn] not executable: {fctl}", file=sys.stderr)
    return 2

  work = pathlib.Path(tempfile.mkdtemp(prefix="fcn-"))
  saved = FWD.read_text()
  arm_forwarding_restore(saved)
  teardown()
  os.makedirs(PIN_ROOT, exist_ok=True)
  try:
    live, blind = compile_bundles(args, work, res)
    if live is None:
      return 1
    if not build_topology(work, res):
      return 1
    report_quiet(res)
    FWD.write_text("1\n")
    # The control FIRST, so the fixed run cannot inherit a neighbour
    # entry the control happened to create. Each phase flushes anyway
    # and asserts the flush took, which is the belt to this brace.
    phase(res, args, fctl, work, blind, "control", False)
    phase(res, args, fctl, work, live, "resolves", True)
  finally:
    teardown()
  print(f"[cn] work kept at {work}")
  verdict = "PASS" if res.failed == 0 else "FAIL"
  print(f"[cn] {verdict}: {res.checks - res.failed}/{res.checks} checks")
  return 0 if res.failed == 0 else 1


if __name__ == "__main__":
  sys.exit(main())
