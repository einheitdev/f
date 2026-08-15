#!/usr/bin/env python3
"""A three-zone gateway: two inside zones behind one uplink.

This is the topology `deploy/firstboot` generates for any box with more
than two ports — `masquerade` + `redirect to <uplink>` for EVERY
non-uplink zone — and until the devmap reclassification it could not be
LOADED at all. Both inside zone objects declare `fwl_devmap_<uplink>`;
when that map was pinned by name, the second object's load failed with

    libbpf: couldn't reuse pinned map at '.../fwl_devmap_wan':
            parameter mismatch

because the kernel forces `BPF_F_RDONLY_PROG` inside `dev_map_alloc`
while the object declares `map_flags 0`, and libbpf's reuse check
compares the two (0 vs 128, which can never agree). Declaring the flag
is not the fix either: `DEV_CREATE_FLAG_MASK` excludes it, so map
creation returns -EINVAL. The fix is that a devmap is no longer pinned
at all — `fd` populates each object's OWN copy from the manifest.

What this asserts, and why in this shape
----------------------------------------
A load that succeeds and forwards nothing is the failure this project
keeps finding, so the verdict is a completed TCP exchange from BOTH
inside zones, witnessed by an ordinary non-promiscuous socket on the
far side:

    ns hlan  10.10.1.5 --- lan0 [XDP: masquerade + redirect to wan]
                             |  10.10.1.1
    ns hdmz  10.10.2.5 --- dmz0 [XDP: masquerade + redirect to wan]
                             |  10.10.2.1
                           wan0  10.10.3.1  [XDP: de-NAT + redirect back]
                             |
                           ns hwan  10.10.3.9  (real TCP server)

The server reports the PEER address of every connection it accepted.
Both zones' flows must arrive as 10.10.3.1 — the uplink address — so
one object proves the far side took the bytes AND that the translation
happened. Neither is evidence without the other.

Two controls, so a pass is attributable:

  1. `net.ipv4.ip_forward=0`. The FIB lookup answers FWD_DISABLED, the
     redirect falls back to the L2-adjacent forward, and the IDENTICAL
     exchange must fail from both zones. A test that cannot go red on
     a box that forwards nothing is not measuring forwarding.
  2. The datapath's own `routed` tally must move, and `no_route` must
     not — if the sockets succeed while `routed` is 0, something other
     than this code path carried the packets.

This is also the acceptance witness `nat_gateway_netns.sh` records as
missing at this level ("would need addresses on lan0/wan0 in the root
namespace plus ip_forward, and is worth doing"). It needs root and a
kernel with veth XDP; it does not need the rig.

Usage:
  sudo python3 three_zone_gateway_netns.py --fd build/fd [--fwl fwl]
"""
import argparse
import atexit
import json
import os
import pathlib
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time

HERE = pathlib.Path(__file__).resolve().parent
WS = HERE.parent.parent
REALSOCK = HERE / "hw" / "realsock.py"
XDP_PASS_SRC = HERE / "xdp_pass.bpf.c"
PIN_ROOT = "/sys/fs/bpf/f3z"
# One veth pair per zone: <root-side device>, <namespace>, <peer device>.
LEGS = (
  ("lan0", "h3zlan", "lan0p", "10.10.1.1", "10.10.1.5"),
  ("dmz0", "h3zdmz", "dmz0p", "10.10.2.1", "10.10.2.5"),
  ("wan0", "h3zwan", "wan0p", "10.10.3.1", "10.10.3.9"),
)
UPLINK_ADDR = "10.10.3.1"
SERVER = "10.10.3.9"
PORT = 8443
N_CONNS = 5
# The route-tally fields `fctl status` renders (src/route_mgr.cc).
ROUTE_SLOT = ("routed", "bridged", "no_route", "no_neigh")
# A `struct { ... } name SEC(".maps");` declaration in generated C.
_MAP_DECL_RE = re.compile(
    r"struct\s*\{(?P<body>[^{}]*)\}\s*(?P<name>\w+)\s*SEC\(\"\.maps\"\);")


class Result:
  """The running verdict: every check, and whether any failed."""

  def __init__(self):
    self.failed = 0
    self.checks = 0

  def check(self, ok: bool, what: str) -> bool:
    """Record one assertion and print it."""
    self.checks += 1
    if not ok:
      self.failed += 1
    print(f"[3z] {'PASS' if ok else 'FAIL'}: {what}", flush=True)
    return ok

  def note(self, what: str) -> None:
    """Record a bench observation that is not a verdict."""
    print(f"[3z] NOTE: {what}", flush=True)


def run(cmd, check=False, ns=None, capture=True):
  """Run `cmd`, optionally inside network namespace `ns`."""
  argv = list(cmd)
  if ns is not None:
    argv = ["ip", "netns", "exec", ns] + argv
  return subprocess.run(argv, check=check, text=True,
                        capture_output=capture)


def quiet(cmd, ns=None) -> None:
  """Run `cmd` and ignore its outcome (teardown, best effort)."""
  try:
    run(cmd, ns=ns)
  except OSError:
    pass


def policy_text() -> str:
  """The gateway policy: two inside zones, one uplink.

  Both inside zones name `wan` in a `redirect`, which is what makes
  both objects declare `fwl_devmap_wan` — the shape that could not
  load. The uplink's own body redirects each de-NATed reply back to
  the zone its address belongs to; those two devmaps have different
  names and were never the problem.
  """
  return f"""\
zone lan = [lan0]
zone dmz = [dmz0]
zone wan = [wan0]

@xdp(lan)

count lan_out
masquerade if pkt.proto == tcp
redirect to wan
allow

@xdp(dmz)

count dmz_out
masquerade if pkt.proto == tcp
redirect to wan
allow

@xdp(wan)

count wan_in
redirect to lan if pkt.dst_ip in 10.10.1.0/24
redirect to dmz if pkt.dst_ip in 10.10.2.0/24
allow
"""


def teardown() -> None:
  """Remove everything this test creates. Safe to call twice."""
  for dev, ns, peer, _, _ in LEGS:
    quiet(["ip", "link", "set", "dev", dev, "xdp", "off"])
    quiet(["ip", "link", "set", "dev", peer, "xdp", "off"], ns=ns)
    quiet(["ip", "link", "del", dev])
    quiet(["ip", "netns", "del", ns])
  shutil.rmtree(PIN_ROOT, ignore_errors=True)


def build_topology(work: pathlib.Path, res: Result) -> bool:
  """Three veth pairs, three host namespaces, addresses both sides."""
  obj = work / "xdp_pass.bpf.o"
  clang = subprocess.run(
      ["clang", "-O2", "-g", "-target", "bpf",
       "-I/usr/include/x86_64-linux-gnu",
       "-I/usr/include/aarch64-linux-gnu",
       "-c", str(XDP_PASS_SRC), "-o", str(obj)],
      text=True, capture_output=True)
  if clang.returncode != 0:
    res.check(False, f"compile xdp_pass: {clang.stderr.strip()}")
    return False
  for dev, ns, peer, gw_addr, host_addr in LEGS:
    run(["ip", "netns", "add", ns], check=True)
    run(["ip", "link", "add", dev, "type", "veth",
         "peer", "name", peer], check=True)
    run(["ip", "link", "set", peer, "netns", ns], check=True)
    run(["ip", "link", "set", dev, "up"], check=True)
    # The firewall's own leg on this segment. Without an address it has
    # no route to the segment and can resolve no next hop for it: a
    # router with no addresses is not a router.
    run(["ip", "addr", "add", f"{gw_addr}/24", "dev", dev], check=True)
    run(["ip", "link", "set", "lo", "up"], ns=ns, check=True)
    run(["ip", "link", "set", peer, "up"], ns=ns, check=True)
    run(["ip", "addr", "add", f"{host_addr}/24", "dev", peer],
        ns=ns, check=True)
    run(["ip", "route", "add", "default", "via", gw_addr],
        ns=ns, check=True)
    # Real checksums on the wire, both directions. A veth pair keeps
    # CHECKSUM_PARTIAL end to end — the header carries the pseudo-header
    # sum and never the final one — so the NAT's incremental update
    # lands on a base that was never valid and the far stack drops the
    # frame with Tcp:InCsumErrors. On copper the sending NIC has already
    # computed it, which is why this bench and only this bench needs it.
    # Measured before it was added: SYNs arrived at wan0p with correct
    # addresses and the server's stack counted 9 InCsumErrors.
    for end, where in ((dev, None), (peer, ns)):
      run(["ethtool", "-K", end, "tx", "off", "rx", "off",
           "tso", "off", "gso", "off", "gro", "off"], ns=where)
    # veth's ndo_xdp_xmit needs an XDP program on the RECEIVING side,
    # so a redirect into this leg reaches the host rather than being
    # dropped below it.
    attached = run(["ip", "link", "set", "dev", peer, "xdpdrv",
                    "obj", str(obj), "sec", "xdp"], ns=ns)
    if attached.returncode != 0:
      attached = run(["ip", "link", "set", "dev", peer, "xdp",
                      "obj", str(obj), "sec", "xdp"], ns=ns)
    if attached.returncode != 0:
      res.check(False, f"xdp_pass on {peer}: {attached.stderr.strip()}")
      return False
  return True


def start_fd(fd_bin: str, bundle: pathlib.Path, work: pathlib.Path,
             sock: str) -> subprocess.Popen:
  """Cold-boot `fd` against the bundle and return the process."""
  log = open(work / "fd.log", "w")
  return subprocess.Popen(
      [fd_bin, "--bundle-dir", str(bundle),
       "--pin-path", PIN_ROOT, "--socket", sock,
       "-l", "debug", "run"],
      stdout=log, stderr=subprocess.STDOUT)


def wait_for_attach(timeout_s: float = 20.0) -> list[str]:
  """The zone devices carrying an XDP program, once all three do."""
  deadline = time.monotonic() + timeout_s
  while time.monotonic() < deadline:
    live = [dev for dev, _, _, _, _ in LEGS
            if "xdp" in run(["ip", "link", "show", dev]).stdout]
    if len(live) == len(LEGS):
      return live
    time.sleep(0.5)
  return [dev for dev, _, _, _, _ in LEGS
          if "xdp" in run(["ip", "link", "show", dev]).stdout]


def warm_neighbours(res: Result) -> None:
  """Resolve each host's MAC from the firewall's own stack.

  XDP cannot ARP; the stack can, and on a live box it already has (the
  router talks to its own gateway for DNS and NTP). Doing it here keeps
  the measurement about forwarding rather than about ARP timing — the
  cold-ARP gap is a separate, recorded finding.
  """
  for dev, _, _, _, host_addr in LEGS:
    run(["ping", "-c1", "-W2", "-I", dev, host_addr])
  have = run(["ip", "neigh", "show"]).stdout
  for _, _, _, _, host_addr in LEGS:
    res.check(any(line.startswith(host_addr + " ") and "lladdr" in line
                  for line in have.splitlines()),
              f"firewall resolved {host_addr}'s MAC")


def route_stats(fctl: str, socket_addr: str) -> dict[str, int]:
  """The datapath's own routing tally, as the daemon reports it.

  Read through `fctl status` rather than off the pin: that is the path
  an operator has, so a tally that only a test can reach would not be
  evidence about the product. It is also the reason the `route` section
  exists at all — neither of these failures has any other symptom.
  """
  out = run([fctl, "-s", socket_addr, "status"])
  if out.returncode != 0:
    return {}
  try:
    state = json.loads(out.stdout)
  except json.JSONDecodeError:
    return {}
  route = state.get("route", {})
  return {name: int(route.get(name, 0)) for name in ROUTE_SLOT}


def exchange(res: Result, label: str, expect: int) -> list[dict]:
  """One TCP exchange from each inside zone, through the box.

  Returns the two server reports. `expect` is how many connections
  each zone must complete — 0 for the non-forwarding control.
  """
  server = subprocess.Popen(
      ["ip", "netns", "exec", LEGS[2][1], sys.executable, str(REALSOCK),
       "server", SERVER, str(PORT), str(2 * N_CONNS), "12"],
      stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
  time.sleep(1.0)
  clients = []
  for dev, ns, _, _, _ in LEGS[:2]:
    clients.append((dev, subprocess.Popen(
        ["ip", "netns", "exec", ns, sys.executable, str(REALSOCK),
         "client", SERVER, str(PORT), str(N_CONNS), "4"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)))
  reports = []
  for dev, proc in clients:
    out, err = proc.communicate(timeout=60)
    try:
      report = json.loads(out)
    except json.JSONDecodeError:
      report = {"completed": -1, "raw": out, "err": err}
    report["zone_dev"] = dev
    reports.append(report)
    res.check(report.get("completed", -1) == expect,
              f"{label}: {dev} completed "
              f"{report.get('completed')}/{N_CONNS} "
              f"(expected {expect})")
  srv_out, _ = server.communicate(timeout=30)
  try:
    srv = json.loads(srv_out)
  except json.JSONDecodeError:
    srv = {"accepted": -1, "peer_addrs": [], "raw": srv_out}
  reports.append(srv)
  return reports


def arm_forwarding_restore(saved):
  """Put net.ipv4.ip_forward back on every exit path, and say so."""
  path = pathlib.Path("/proc/sys/net/ipv4/ip_forward")
  done = []

  def restore(*_):
    """Restore once, verify, and report."""
    if done:
      return
    done.append(True)
    try:
      path.write_text(saved)
    except OSError as exc:
      print(f"[3z] RESTORE FAILED: could not write {path} ({exc}); "
            f"set it back with `sysctl -w "
            f"net.ipv4.ip_forward={saved.strip()}`",
            file=sys.stderr, flush=True)
      return
    now = path.read_text().strip()
    print(f"[3z] restored net.ipv4.ip_forward = {now} "
          f"(it was {saved.strip()} when this run started)",
          flush=True)
    if now != saved.strip():
      print(f"[3z] RESTORE FAILED: {path} reads {now}, wanted "
            f"{saved.strip()}", file=sys.stderr, flush=True)

  atexit.register(restore)
  for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
    signal.signal(sig, lambda *_: sys.exit(1))


def main() -> int:
  """Build the bench, run both exchanges, and report."""
  ap = argparse.ArgumentParser(description=__doc__)
  ap.add_argument("--fd", required=True, help="path to the fd binary")
  ap.add_argument("--fwl", default="fwl", help="the fwl compiler")
  ap.add_argument("--fctl", default=None,
                  help="path to fctl (default: beside fd)")
  args = ap.parse_args()
  res = Result()
  if os.geteuid() != 0:
    print("[3z] needs root (bpffs, netns, XDP)", file=sys.stderr)
    return 2
  if not os.access(args.fd, os.X_OK):
    print(f"[3z] not executable: {args.fd}", file=sys.stderr)
    return 2
  if not os.path.ismount("/sys/fs/bpf"):
    run(["mount", "-t", "bpf", "bpf", "/sys/fs/bpf"], check=True)
  # Every external tool this bench needs, named before anything is
  # built. `ethtool` in particular is load-bearing rather than
  # cosmetic — see build_topology: without it a veth pair keeps
  # CHECKSUM_PARTIAL end to end and every NAT'd frame is dropped by the
  # far stack — so its absence has to be a reported blocker and not a
  # traceback out of the middle of a half-built topology.
  #
  # `shutil.which` alone answered the wrong question and answered it
  # confidently. `ip` and `ethtool` are in /sbin and /usr/sbin, which
  # are not on a non-login root shell's PATH on Debian, so this bench
  # reported `BLOCKED: not installed: ethtool` on a host where
  # `dpkg -l ethtool` says `ii`. A blocker that names the wrong cause
  # sends the next person to `apt-get install` something they already
  # have.
  sbin = ["/usr/local/sbin", "/usr/sbin", "/sbin"]
  path = os.pathsep.join([os.environ.get("PATH", "")] + sbin)
  missing = [t for t in ("ip", "ethtool", "clang")
             if shutil.which(t, path=path) is None]
  if missing:
    print(f"[3z] BLOCKED: not installed: {', '.join(missing)}",
          file=sys.stderr)
    return 2
  # Found them; make sure the subprocesses below can too.
  os.environ["PATH"] = path

  fctl = args.fctl or str(pathlib.Path(args.fd).resolve().parent / "fctl")
  if not os.access(fctl, os.X_OK):
    print(f"[3z] not executable: {fctl}", file=sys.stderr)
    return 2
  work = pathlib.Path(tempfile.mkdtemp(prefix="f3z-"))
  sock = f"ipc://{work}/fd.sock"
  bundle = work / "bundle"
  fd_proc = None
  fwd_saved = pathlib.Path("/proc/sys/net/ipv4/ip_forward").read_text()
  # `net.ipv4.ip_forward` is the HOST's, not this bench's. On a
  # workstation that routes for its own VMs, the seconds this file
  # spends with it at 0 — the control below sets it deliberately —
  # are seconds those guests have no path out, and a run that dies
  # without restoring takes their network with it silently. It
  # happened. Registered with atexit and with the signals a `finally`
  # does not cover, verified by reading it back, and printed either
  # way: a restore nobody can see is one nobody can tell did not
  # happen.
  arm_forwarding_restore(fwd_saved)
  teardown()
  os.makedirs(PIN_ROOT, exist_ok=True)
  try:
    (work / "gw.fw").write_text(policy_text())
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        [str(WS)] + ([env["PYTHONPATH"]] if "PYTHONPATH" in env else []))
    compiled = subprocess.run(
        [args.fwl, "compile", str(work / "gw.fw"),
         "--bundle", str(bundle / "current")],
        text=True, capture_output=True, env=env)
    if not res.check(compiled.returncode == 0,
                     f"fwl compiled the three-zone bundle "
                     f"({compiled.stderr.strip() or 'ok'})"):
      return 1
    # The shape under test, asserted rather than assumed: both inside
    # objects really do name the same devmap. If a future emitter gave
    # them different names, everything below would pass without ever
    # putting the question.
    src = {z: (bundle / "current" / f"{z}.bpf.c").read_text()
           for z in ("lan", "dmz", "wan")}
    res.check(all("fwl_devmap_wan SEC(\".maps\")" in src[z]
                  for z in ("lan", "dmz")),
              "both inside zone objects declare fwl_devmap_wan")
    pinned_devmaps = [
        f"{z}:{m.group('name')}"
        for z in ("lan", "dmz", "wan")
        for m in _MAP_DECL_RE.finditer(src[z])
        if m.group("name").startswith("fwl_devmap_")
        and "LIBBPF_PIN_BY_NAME" in m.group("body")]
    res.check(not pinned_devmaps,
              f"no devmap is declared LIBBPF_PIN_BY_NAME "
              f"(found {pinned_devmaps})")
    manifest = json.loads(
        (bundle / "current" / "manifest.json").read_text())
    res.check(not any(n.startswith("fwl_devmap_")
                      for n in manifest["shared_pinned_maps"]),
              "the manifest claims no devmap as a bundle-global pin")
    # The masquerade source is per zone, and this bench is where that
    # can be asserted without four ports. `masquerade` translates to
    # the address of the zone THIS one redirects to; under the
    # bundle-global name `fwl_nat_cfg` every object resolved one kernel
    # map with one slot 0, written once per masquerading zone, so the
    # last zone loaded decided what every masquerading program
    # translated to. Here both inside zones DO redirect to the same
    # uplink — so this bench cannot see the consequence on the wire
    # (l2_09_two_uplinks does, on the rig) — but it can see the shape,
    # and the shape is what the consequence follows from.
    res.check(all(f'}} fwl_nat_cfg_{z} SEC(".maps");' in src[z]
                  for z in ("lan", "dmz", "wan")),
              "each zone declares its OWN masquerade source map")
    res.check(not any('} fwl_nat_cfg SEC(".maps");' in src[z]
                      for z in ("lan", "dmz", "wan")),
              "no object declares a bundle-global fwl_nat_cfg")
    res.check("fwl_nat_cfg" not in manifest["shared_pinned_maps"],
              "the manifest claims no bundle-global masquerade source")

    if not build_topology(work, res):
      return 1
    pathlib.Path("/proc/sys/net/ipv4/ip_forward").write_text("1\n")

    fd_proc = start_fd(args.fd, bundle, work, sock)
    live = wait_for_attach()
    if not res.check(len(live) == 3,
                     f"fd attached all three zones (got {live})"):
      print((work / "fd.log").read_text())
      return 1
    res.check(not any(pathlib.Path(PIN_ROOT).glob("fwl_devmap_*")),
              "no devmap reached bpffs")
    fd_log = (work / "fd.log").read_text()
    res.check(f"masquerade address {UPLINK_ADDR}" in fd_log,
              f"fd resolved the uplink masquerade address "
              f"{UPLINK_ADDR} for both inside zones")
    warm_neighbours(res)

    before = route_stats(fctl, sock)
    reports = exchange(res, "forwarding", N_CONNS)
    after = route_stats(fctl, sock)
    srv = reports[-1]
    res.check(srv.get("accepted") == 2 * N_CONNS,
              f"the far side accepted {srv.get('accepted')} "
              f"connections from two zones (expected {2 * N_CONNS})")
    res.check(srv.get("peer_addrs") == [UPLINK_ADDR],
              f"every peer the server saw was the uplink address "
              f"(saw {srv.get('peer_addrs')})")
    res.note(f"route tally before={before} after={after}")
    routed = after.get("routed", 0) - before.get("routed", 0)
    res.check(routed > 0,
              f"the datapath routed {routed} frames "
              f"(no_route {after.get('no_route', 0)})")

    # Control. The same bundle, the same sockets, forwarding off: the
    # FIB answers FWD_DISABLED, the redirect bridges instead, and the
    # exchange must fail from BOTH zones.
    pathlib.Path("/proc/sys/net/ipv4/ip_forward").write_text("0\n")
    time.sleep(0.5)
    control = exchange(res, "control (ip_forward=0)", 0)
    res.check(control[-1].get("accepted") == 0,
              f"control: the far side accepted "
              f"{control[-1].get('accepted')} connections")
  finally:
    # Restored by the atexit hook armed above, which also covers the
    # signal paths and reports what the kernel ended up holding.
    pass
    if fd_proc is not None:
      fd_proc.terminate()
      try:
        fd_proc.wait(timeout=10)
      except subprocess.TimeoutExpired:
        fd_proc.kill()
    teardown()
  verdict = "PASS" if res.failed == 0 else "FAIL"
  print(f"[3z] {verdict}: {res.checks - res.failed}/{res.checks} checks")
  return 0 if res.failed == 0 else 1


if __name__ == "__main__":
  sys.exit(main())
