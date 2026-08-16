"""The office-gateway soak: build it, run it, sample it, take it down.

Why a third soak
----------------
The 48.1 h soak of 2026-08-08 is the project's stability evidence and it
is stale. It ran on v0.4 before routing via `bpf_fib_lookup`, before
fail-closed forwarding, before per-zone NAT configuration, before the
devmap unpin, before next-hop resolution, before the v0.1 surface was
deleted and before the service-lifecycle work. Its policy covered
counters, rate limiting, sampled logging, conntrack and a drop matrix,
on one zone, with no NAT and no routing at all. The only soak that
touched NAT ran for 1.53 h on a two-zone bundle.

This one is a gateway under continuous load, on the code that exists
now: two inside zones masquerading behind one uplink, the return path
gated on `conntrack(pkt).state in [established, related]`, the box's own
flows going out through the TC egress tracker, and the old soak's whole
noise matrix on both inside zones.

What every sample carries, and why
----------------------------------
A counter delta and an INDEPENDENT WIRE WITNESS, always paired. Every
counter in a NAT policy keeps climbing with the rewrite disabled
entirely — `a_masq` counts the frame that matched the predicate, not the
frame that left. So each sample also completes real TCP exchanges, and
where a claim depends on DELIVERY the witness is an ordinary
non-promiscuous socket on an ordinary Linux stack in its own namespace,
with the far side's own kernel reporting the peer address it saw. A
promiscuous sniffer counts frames a real stack reports PACKET_OTHERHOST
and discards, which is how a redirect that never rewrote the destination
MAC survived 1822 unit cases, eleven scenarios and a whole NAT soak.

Four delivery claims per sample:

  1. Zone A (copper) masquerades and the reply comes back — the far
     side accepted and echoed, and names 10.99.210.2 as the peer.
  2. Zone B does the same through the SAME uplink, which is the bundle
     that could not load until the devmap was unpinned, and the address
     that was one bundle-global slot until it became per-zone.
  3. Both of those complete only because the uplink's `redirect` is
     gated on `in [established, related]` — the composition that did not
     work behind masquerade until `fwl_snat_egress` began inserting the
     post-translation tuple. If it stops composing, `completed` is 0.
  4. A flow the BOX originates completes through the uplink's
     `default drop`, which is possible only if the TC egress tracker
     made its conntrack entry. This is the DNS failure, asked once a
     minute.

Rate limiting and sampled logging are counter-witnessed, as in the old
soak: there is no delivery claim in "the limiter dropped the excess", so
the pairing is between two counters that no single failure moves
together (`a_flood`, everything the flood subnet sent, against the
datapath's own drop accounting). The report says so rather than letting
a reader assume a wire witness that is not there.

Topology
--------
    netns gwsa  10.99.31.5  (macvlan on f0, untagged -> vlan 801)
          |
       [ EX2300 ]
          |
    enp1s0f1  10.99.31.1   zone ina  [masquerade + redirect wanz]
    fs3b      10.99.32.1   zone inb  [masquerade + redirect wanz]
          |                          (veth, peer in netns gwsb)
    enp1s0f2  10.99.210.2  zone wanz [de-NAT + redirect back, default drop]
          |
       [ EX2300 vlan 802 ]
          |
    netns gwss  10.99.210.9  (vlan 802 subinterface of f0)

A three-zone gateway needs three firewall ports plus one port for the
far hosts and the i350 has three usable ones — f3 carries the rig's own
SSH and is off limits. So the second inside zone is a veth pair rather
than copper, exactly as l2_08 does it, and this file says so rather than
leaving it to be assumed. The `ina` leg is real copper through the
switch in both directions and covers the igb driver's ndo_xdp_xmit; what
the veth leg exercises, and what it is here for, is two zone objects
declaring one devmap name in one bundle, both loading, both attaching,
both masquerading to one resolved address.

The churn destination network is routed via a next hop that is answered
by a PERMANENT neighbour entry for a MAC nobody owns. That is
deliberate: the churn has to be routed (so `routed` climbs and the NAT
table fills at a known rate) without soliciting an address that will
never reply (which would make `no_neigh` climb forever and hide the one
thing a long run is supposed to show about it).

ip_forward
----------
This harness NEVER writes net.ipv4.ip_forward. `fd` owns it — it raises
it after the attach and records why — and a bench that lowered it behind
the daemon's back is what left the rig reporting `[FAIL] OFF, and fd did
not do it` on 2026-08-16. The start refuses to run if the knob is not
where fd says it should be, and reports what the kernel holds rather
than creating a disagreement.

Usage, on the rig, as root:

  python3 gwsoak.py start [--hours N]
  python3 gwsoak.py status
  python3 gwsoak.py sample            # driven by the systemd timer
  python3 gwsoak.py probe             # the wire witness alone, by hand
  python3 gwsoak.py stop
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from concurrent import futures
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
PIN = "/sys/fs/bpf/f"
BUNDLE_ROOT = "/usr/share/f/compiled"
LOG = "/var/log/f/gwsoak.jsonl"
STATE = "/var/log/f/gwsoak.state.json"
RULES = "/etc/f/rules.fw"
POLICY = os.path.join(HERE, "gwsoak_policy.fw")
BUNDLE = os.path.join(BUNDLE_ROOT, "v-gwsoak")

# Interfaces. Keep in step with gwsoak_policy.fw, which names them
# literally because a bundle manifest does.
PARENT = "enp1s0f0"     # trunk carrying both copper-side far hosts
INA_IF = "enp1s0f1"     # inside zone A — copper
WAN_IF = "enp1s0f2"     # the uplink — copper
INB_IF = "fs3b"         # inside zone B — veth, root-ns end
INB_PEER = "fs3bp"      # its peer, inside netns gwsb
WAN_VLAN = 802

# Addresses.
INA_ADDR = "10.99.31.1"
INB_ADDR = "10.99.32.1"
MASQ_ADDR = "10.99.210.2"   # the uplink's address == masquerade source
GUEST_A = "10.99.31.5"
GUEST_B = "10.99.32.5"
SERVER = "10.99.210.9"
CHURN_NET = "10.99.240.0/22"
CHURN_GW = "10.99.210.250"
CHURN_GW_MAC = "02:00:00:00:99:fa"

NS_A, NS_B, NS_S = "gwsa", "gwsb", "gwss"
PORT_GUEST = 8461     # the guests' far-side listener
PORT_BOX = 8462       # the box's own far-side listener
CONNS_PER_ZONE = 3

TRAFFIC_UNITS = ("f-gwsoak-traffic-a", "f-gwsoak-traffic-b",
                 "f-gwsoak-reply")
SAMPLE_UNIT = "f-gwsoak-sample"
DEFAULT_HOURS = 96

SMOKE_POLICY = """\
# Layer-0 smoke policy: attach to all three data-plane ports, count
# every frame, pass everything. Proves load+attach+counters only.
zone data = [enp1s0f0, enp1s0f1, enp1s0f2]

@xdp(data)

count data_total
default allow
"""


def now() -> str:
  """UTC timestamp in the shape every soak log in this tree uses."""
  return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def child_env() -> dict:
  """The environment every child gets.

  The rig has no pip and no venv, so the FWL package and its vendored
  dependencies are reachable only through PYTHONPATH — hwlib.sh exports
  it and every shell scenario inherits it. A Python harness has to do
  the same deliberately: without it `sendmany.py` dies on
  `from fwl import pkt`, and the caller sees only "the wire never came
  back", which is a true statement about the wrong thing.
  """
  env = dict(os.environ)
  wanted = ["/opt/fwl", "/opt/fwl-deps"]
  have = [p for p in env.get("PYTHONPATH", "").split(":") if p]
  env["PYTHONPATH"] = ":".join(
    wanted + [p for p in have if p not in wanted])
  return env


def run(args, check=False, ns=None, timeout=120):
  """Run a command, returning the CompletedProcess. Never raises on
  a non-zero exit unless `check`."""
  if ns:
    args = ["ip", "netns", "exec", ns] + list(args)
  return subprocess.run(args, capture_output=True, text=True,
                        check=check, timeout=timeout, env=child_env())


def out(args, ns=None, timeout=120) -> str:
  """stdout of a command, stripped; empty string on any failure."""
  try:
    proc = run(args, ns=ns, timeout=timeout)
  except (OSError, subprocess.SubprocessError):
    return ""
  return proc.stdout.strip()


def require_root() -> None:
  if os.geteuid() != 0:
    sys.exit("must run as root (on the rig)")


def read_int(path: str, default: int = -1) -> int:
  try:
    with open(path) as fh:
      return int(fh.read().strip())
  except (OSError, ValueError):
    return default


# --- reading the box -------------------------------------------------

def fctl_status() -> dict:
  """`fctl status` as a dict, or {} when it cannot be had.

  Read through the CLI rather than through bpftool on purpose: half of
  every finding this file watches for was that an operator had no way to
  see the state at all, and a sampler that reached around fctl would
  pass over exactly that half.
  """
  try:
    return json.loads(out(["fctl", "status"], timeout=20) or "{}")
  except json.JSONDecodeError:
    return {}


def counter_slots() -> dict:
  """{zone: {counter_name: slot}} from the running bundle's own C.

  The name->slot mapping is the `fwl_counter_table` comment block the
  emitter writes for exactly this purpose. Reading counters by NAME is
  the point: a slot index is a number that stays valid while the policy
  under it changes, and this soak has to survive being read by somebody
  who did not deploy it.
  """
  table: dict[str, dict[str, int]] = {}
  cur = os.path.join(BUNDLE_ROOT, "current")
  try:
    names = sorted(os.listdir(cur))
  except OSError:
    return table
  for name in names:
    if not name.endswith(".bpf.c") or name == "fwl_egress.bpf.c":
      continue
    zone = name[:-len(".bpf.c")]
    slots: dict[str, int] = {}
    seen_header = False
    with open(os.path.join(cur, name)) as fh:
      for line in fh:
        if "fwl_counter_table:" in line:
          seen_header = True
          continue
        if not seen_header:
          continue
        match = re.match(r"//\s+(\d+)\s+(\S+)", line)
        if not match:
          break
        slots[match.group(2)] = int(match.group(1))
    if slots:
      table[zone] = slots
  return table


def _as_int(value) -> int:
  """A bpftool scalar, whichever way this build spells it.

  `bpftool map dump` renders keys and values as integers; the same
  command with `-j` renders both as little-endian lists of hex byte
  strings. Reading only one spelling turns every counter into -1 —
  which the report does fail on, but the failure names an absent
  counter rather than the parser, so both spellings are handled here
  and asserted in test_gwsoak.py.
  """
  if isinstance(value, list):
    return int.from_bytes(bytes(int(b, 0) for b in value), "little")
  return int(value)


def read_counters() -> dict:
  """Every declared counter, by name, summed over CPUs.

  A counter the running bundle does not declare reads -1, never 0.
  "Absent" and "zero" are different measurements, and a check that
  cannot tell them apart is not checking anything — four assertions in
  the hardware suite were satisfied by a silently renamed counter before
  hw::counter started saying -1.
  """
  values: dict[str, int] = {}
  for zone, slots in counter_slots().items():
    dumped = out(["bpftool", "map", "dump", "pinned",
                  f"{PIN}/fwl_counters_{zone}"], timeout=30)
    per_slot: dict[int, int] = {}
    try:
      for entry in json.loads(dumped or "[]"):
        per_slot[_as_int(entry["key"])] = sum(
          _as_int(v["value"]) for v in entry["values"])
    except (json.JSONDecodeError, KeyError, TypeError, ValueError):
      per_slot = {}
    for name, slot in slots.items():
      values[name] = per_slot.get(slot, -1) if per_slot else -1
  return values


def map_entries(pin: str) -> int:
  """Entries in a pinned map, or -1 when the pin does not exist."""
  path = f"{PIN}/{pin}"
  if not os.path.exists(path):
    return -1
  dumped = out(["bpftool", "-j", "map", "dump", "pinned", path],
               timeout=60)
  try:
    return len(json.loads(dumped or "[]"))
  except json.JSONDecodeError:
    return -1


def hwmon_by_name(name: str) -> str:
  """Path to a hwmon input by SENSOR NAME. The index shifts across
  boots; rig.md says to resolve by name and this does."""
  base = "/sys/class/hwmon"
  try:
    for entry in sorted(os.listdir(base)):
      try:
        with open(os.path.join(base, entry, "name")) as fh:
          if fh.read().strip() == name:
            return os.path.join(base, entry, "temp1_input")
      except OSError:
        continue
  except OSError:
    pass
  return ""


def fd_process() -> dict:
  """fd's RSS, CPU and uptime, read from /proc rather than claimed."""
  pid = out(["pidof", "fd"]).split()
  info = {"pid": -1, "rss_kb": -1, "cpu_ms": -1}
  if not pid:
    return info
  info["pid"] = int(pid[0])
  try:
    with open(f"/proc/{pid[0]}/status") as fh:
      for line in fh:
        if line.startswith("VmRSS:"):
          info["rss_kb"] = int(line.split()[1])
    with open(f"/proc/{pid[0]}/stat") as fh:
      fields = fh.read().rsplit(") ", 1)[1].split()
    ticks = os.sysconf("SC_CLK_TCK")
    info["cpu_ms"] = int((int(fields[11]) + int(fields[12]))
                         * 1000 / ticks)
  except (OSError, IndexError, ValueError):
    pass
  return info


def link_up_events() -> int:
  """Cumulative data-port link-up events since boot.

  A flap is invisible in every counter this soak reads — the datapath
  just stops seeing frames for a moment — so it is counted from the
  kernel ring buffer, the same way the two earlier soaks did it.
  """
  text = out(["dmesg"], timeout=30)
  return len(re.findall(r"enp1s0f[012].*Link is Up", text))


def readings() -> dict:
  """Everything about the box that is not a wire witness."""
  status = fctl_status()

  def section(name, *fields):
    src = status.get(name, {})
    return {f: src.get(f, -1) for f in fields}

  proc = fd_process()
  soc = (hwmon_by_name("package_thermal")
         or "/sys/class/thermal/thermal_zone0/temp")
  nic = hwmon_by_name("i350bb")
  errs = out(["journalctl", "-u", "fd", "--since", "-5min", "-p", "err",
              "--no-pager", "-q"], timeout=30)
  return {
    "ts": now(),
    "boot_id": out(["cat", "/proc/sys/kernel/random/boot_id"]),
    "uptime_s": int(float(open("/proc/uptime").read().split()[0])),
    "counters": read_counters(),
    "nat": section("nat", "enabled", "entries", "installed",
                   "total_reclaimed", "refused", "table_full",
                   "occupancy_pct", "high_water", "denat",
                   "port_reallocated", "icmp_error", "max_entries"),
    "conntrack": section("conntrack", "enabled", "entries",
                         "total_evicted", "timeout_s"),
    "egress": section("egress", "enabled", "attached", "seen",
                      "not_local", "tracked", "refreshed", "untracked",
                      "refused", "tracker_declared"),
    "route": section("route", "enabled", "routed", "bridged",
                     "no_route", "no_neigh", "ttl_expired", "off_zone",
                     "ip_forward", "forwarding_overridden",
                     "forwarding_corrections"),
    "neigh": section("neigh", "enabled", "solicited", "resolved",
                     "failed", "off_datapath", "forgotten_stale"),
    "maps": {
      "fwl_nat": map_entries("fwl_nat"),
      "conntrack": map_entries("conntrack"),
      "fwl_neigh_wanted": map_entries("fwl_neigh_wanted"),
    },
    "xdp_ifaces": sum(
      1 for i in status.get("interfaces", {}).get("interfaces", [])
      if i.get("xdp_attached")),
    "fd": {
      "active": out(["systemctl", "is-active", "fd"]) or "unknown",
      "rss_kb": proc["rss_kb"],
      "cpu_ms": proc["cpu_ms"],
      "nrestarts": int(out(["systemctl", "show", "fd", "-p",
                            "NRestarts", "--value"]) or -1),
      "err_5min": len([x for x in errs.splitlines() if x.strip()]),
    },
    "linkup_total": link_up_events(),
    "traffic_active": [out(["systemctl", "is-active", u])
                       for u in TRAFFIC_UNITS],
    "sys": {
      "soc_temp_mC": read_int(soc),
      "i350_die_mC": read_int(nic) if nic else -1,
      "load1": float(open("/proc/loadavg").read().split()[0]),
      "mem_avail_kb": read_int_field("/proc/meminfo", "MemAvailable:"),
      "rx_packets": nic_stat(INA_IF, "rx_packets"),
    },
  }


def read_int_field(path: str, prefix: str) -> int:
  try:
    with open(path) as fh:
      for line in fh:
        if line.startswith(prefix):
          return int(line.split()[1])
  except (OSError, ValueError, IndexError):
    pass
  return -1


def iface_mac(iface: str, ns=None) -> str:
  """An interface's hardware address, or "" when it has none."""
  match = re.search(r"link/ether (\S+)",
                    out(["ip", "link", "show", iface], ns=ns))
  return match.group(1) if match else ""


def nic_stat(iface: str, stat: str) -> int:
  text = out(["ethtool", "-S", iface], timeout=30)
  match = re.search(rf"^\s*{re.escape(stat)}:\s*(\d+)$", text,
                    re.MULTILINE)
  return int(match.group(1)) if match else -1


# --- the wire witness ------------------------------------------------

def _realsock(mode: str, ns: str, *args):
  """Spawn realsock.py in a namespace; the caller collects it."""
  cmd = ["ip", "netns", "exec", ns, sys.executable,
         os.path.join(HERE, "realsock.py"), mode] + [str(a)
                                                     for a in args]
  return subprocess.Popen(cmd, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, text=True,
                          env=child_env())


def _collect(proc, timeout: float) -> dict:
  """Read one JSON object from a realsock.py process.

  Terminated with SIGTERM and never SIGKILL: a `kill()` at this spot
  once left an orphan holding the listening port, so the next probe's
  listener could not bind and the phase reported that the far side had
  seen nobody while the client in the same run said it had connected.
  """
  try:
    stdout, _ = proc.communicate(timeout=timeout)
  except subprocess.TimeoutExpired:
    proc.terminate()
    try:
      stdout, _ = proc.communicate(timeout=5)
    except subprocess.TimeoutExpired:
      proc.kill()
      return {"error": "probe timed out"}
  try:
    return json.loads(stdout.strip().splitlines()[-1])
  except (json.JSONDecodeError, IndexError):
    return {"error": "no report"}


def probe() -> dict:
  """One sample's wire witnesses. Real sockets on real stacks only.

  The two guest namespaces and the far side are ordinary Linux hosts
  that are NOT promiscuous (asserted when they are built, not assumed),
  so a byte only arrives at a socket here if the frame was addressed to
  it, translated correctly, checksummed correctly, and completed a
  three-way handshake. The box's own client runs in the ROOT namespace,
  because the flow this soak needs it to originate is the appliance's
  own.
  """
  started = time.monotonic()
  want = CONNS_PER_ZONE * 2
  srv_guest = _realsock("server", NS_S, SERVER, PORT_GUEST, want, 14)
  srv_box = _realsock("server", NS_S, SERVER, PORT_BOX, 1, 14)
  time.sleep(0.5)

  def client(ns):
    return run([sys.executable, os.path.join(HERE, "realsock.py"),
                "client", SERVER, str(PORT_GUEST),
                str(CONNS_PER_ZONE), "4"], ns=ns, timeout=30)

  def box_client():
    return run([sys.executable, os.path.join(HERE, "realsock.py"),
                "client", SERVER, str(PORT_BOX), "1", "4"], timeout=30)

  def parse(proc) -> dict:
    try:
      return json.loads(proc.stdout.strip().splitlines()[-1])
    except (AttributeError, json.JSONDecodeError, IndexError):
      return {"error": "no report"}

  with futures.ThreadPoolExecutor(max_workers=3) as pool:
    fut_a = pool.submit(client, NS_A)
    fut_b = pool.submit(client, NS_B)
    fut_box = pool.submit(box_client)
    result = {
      "a": parse(fut_a.result()),
      "b": parse(fut_b.result()),
      "box": parse(fut_box.result()),
    }
  result["srv"] = _collect(srv_guest, 18)
  result["boxsrv"] = _collect(srv_box, 18)
  result["want_per_zone"] = CONNS_PER_ZONE
  result["masq_addr"] = MASQ_ADDR
  result["elapsed_s"] = round(time.monotonic() - started, 2)
  return result


# --- topology --------------------------------------------------------

def _xdp_pass_object() -> str:
  """Build the XDP pass program the veth legs need.

  veth's ndo_xdp_xmit needs an XDP program on the RECEIVING side, or a
  redirect into the leg is dropped below the peer's stack — the frame
  never reaches an IP stack and no socket sees it.
  """
  obj = "/run/gwsoak_xdp_pass.o"
  src = os.path.join(HERE, "..", "xdp_pass.bpf.c")
  proc = run(["clang", "-O2", "-g", "-target", "bpf",
              "-I/usr/include/aarch64-linux-gnu",
              "-c", src, "-o", obj])
  if proc.returncode != 0:
    sys.exit(f"compiling xdp_pass failed: {proc.stderr}")
  return obj


def topology_up() -> None:
  """Build the far hosts and the second inside zone's wire.

  Built BEFORE the bundle is deployed: `fd` attaches to the interfaces
  the manifest names, and a zone whose interface does not exist yet is
  warned about and skipped — which would leave a two-zone gateway
  claiming to be a three-zone one.
  """
  topology_down()
  obj = _xdp_pass_object()

  # The veth leg: inside zone B.
  run(["ip", "link", "add", INB_IF, "type", "veth", "peer", "name",
       INB_PEER], check=True)
  run(["ip", "netns", "add", NS_B], check=True)
  run(["ip", "link", "set", INB_PEER, "netns", NS_B], check=True)
  run(["ip", "link", "set", INB_IF, "up"], check=True)
  run(["ip", "link", "set", "lo", "up"], ns=NS_B)
  run(["ip", "link", "set", INB_PEER, "up"], ns=NS_B)
  run(["ip", "addr", "add", f"{GUEST_B}/24", "dev", INB_PEER], ns=NS_B)
  run(["ip", "route", "add", "default", "via", INB_ADDR, "dev",
       INB_PEER], ns=NS_B)
  # A veth pair keeps CHECKSUM_PARTIAL end to end — the header carries
  # the pseudo-header sum and never the final one — so the NAT's
  # incremental update lands on a base that was never valid and the far
  # stack drops the frame with Tcp:InCsumErrors. On copper the sending
  # NIC has already computed it.
  for dev, ns in ((INB_IF, None), (INB_PEER, NS_B)):
    run(["ethtool", "-K", dev, "tx", "off", "rx", "off", "tso", "off",
         "gso", "off", "gro", "off"], ns=ns)
  if run(["ip", "link", "set", "dev", INB_PEER, "xdpdrv", "obj", obj,
          "sec", "xdp"], ns=NS_B).returncode != 0:
    run(["ip", "link", "set", "dev", INB_PEER, "xdp", "obj", obj,
         "sec", "xdp"], ns=NS_B, check=True)

  # The copper-side far hosts: guest A untagged on the trunk's native
  # VLAN, the server on the tagged WAN VLAN.
  _host_up(NS_A, PARENT, None, f"{GUEST_A}/24", INA_ADDR)
  _host_up(NS_S, PARENT, WAN_VLAN, f"{SERVER}/24", None)

  # The firewall's own legs. A router with no addresses is not a
  # router: without them there is no route to any segment and no next
  # hop can be resolved for anything.
  run(["ip", "addr", "add", f"{INA_ADDR}/24", "dev", INA_IF])
  run(["ip", "addr", "add", f"{INB_ADDR}/24", "dev", INB_IF])
  run(["ip", "addr", "add", f"{MASQ_ADDR}/24", "dev", WAN_IF])

  # The churn's black hole: a routed next hop with a permanent
  # neighbour entry for a MAC nobody owns. The churn is genuinely
  # ROUTED (MACs rewritten, TTL decremented, `routed` climbing) and
  # solicits nothing, so `no_neigh` can be read for what it is meant to
  # show — whether the box re-loses a next hop it once resolved — and
  # not swamped by 5 unresolvable destinations a second.
  run(["ip", "neigh", "replace", CHURN_GW, "lladdr", CHURN_GW_MAC,
       "dev", WAN_IF, "nud", "permanent"])
  run(["ip", "route", "replace", CHURN_NET, "via", CHURN_GW, "dev",
       WAN_IF])


def _host_up(ns: str, parent: str, vlan, cidr: str, gw) -> None:
  """An ordinary Linux host of its own on the trunk.

  Not promiscuous, and that is ASSERTED rather than assumed: a
  promiscuous far side accepts frames a real host drops, which is the
  exact defect this machinery exists to make visible.
  """
  run(["ip", "netns", "add", ns], check=True)
  if vlan is None:
    dev = f"mv{ns}"
    run(["ip", "link", "del", dev])
    run(["ip", "link", "add", dev, "link", parent, "type", "macvlan",
         "mode", "bridge"], check=True)
  else:
    dev = f"vl{vlan}{ns}"
    run(["ip", "link", "del", dev])
    run(["ip", "link", "add", "link", parent, "name", dev, "type",
         "vlan", "id", str(vlan)], check=True)
  run(["ip", "link", "set", dev, "netns", ns], check=True)
  run(["ip", "link", "set", "lo", "up"], ns=ns)
  run(["ip", "link", "set", dev, "up"], ns=ns)
  run(["ip", "addr", "add", cidr, "dev", dev], ns=ns)
  if gw:
    run(["ip", "route", "add", "default", "via", gw, "dev", dev],
        ns=ns, check=True)
  if "PROMISC" in out(["ip", "link", "show", dev], ns=ns):
    sys.exit(f"{ns}/{dev} is PROMISC; it would accept frames a real "
             f"host drops")


def topology_down() -> None:
  """Take everything this harness made off the box. Idempotent."""
  run(["ip", "route", "del", CHURN_NET, "via", CHURN_GW, "dev",
       WAN_IF])
  run(["ip", "neigh", "del", CHURN_GW, "dev", WAN_IF])
  run(["ip", "link", "set", "dev", INB_IF, "xdp", "off"])
  run(["ip", "link", "del", INB_IF])
  for ns in (NS_A, NS_B, NS_S):
    run(["ip", "netns", "del", ns])
  for dev in (f"mv{NS_A}", f"vl{WAN_VLAN}{NS_S}"):
    run(["ip", "link", "del", dev])
  run(["ip", "addr", "del", f"{INA_ADDR}/24", "dev", INA_IF])
  run(["ip", "addr", "del", f"{MASQ_ADDR}/24", "dev", WAN_IF])
  # net.ipv4.ip_forward is NOT touched here. See the module docstring:
  # it belongs to fd, and a bench that put it back behind the daemon's
  # back is what left the rig contradicting itself once already.


# --- deploy ----------------------------------------------------------

def deploy(policy: str, bundle: str, tag: str) -> None:
  """Compile a policy into a bundle and restart fd on it.

  The policy is also copied to /etc/f/rules.fw, and that is not
  cosmetic: fd's watcher recompiles that file, so a soak that left the
  smoke policy there would have the product revert its own bundle
  within six seconds and every measurement afterwards would be of a
  policy nobody deployed.
  """
  if run(["fwl", "check", policy]).returncode != 0:
    sys.exit(f"policy rejected: {policy}")
  shutil.rmtree(bundle, ignore_errors=True)
  proc = run(["fwl", "compile", "--bundle", bundle, policy],
             timeout=600)
  if proc.returncode != 0:
    sys.exit(f"bundle compile failed: {proc.stderr}")
  with open(os.path.join(bundle, "manifest.json")) as fh:
    if '"object": null' in fh.read():
      sys.exit("bundle has uncompiled zone objects")
  run(["systemctl", "stop", "fd"], timeout=60)
  shutil.copyfile(policy, RULES)
  tmp = os.path.join(BUNDLE_ROOT, ".current.new")
  run(["ln", "-sfT", bundle, tmp], check=True)
  os.rename(tmp, os.path.join(BUNDLE_ROOT, "current"))
  run(["systemctl", "reset-failed", "fd"])
  run(["systemctl", "start", "fd"], timeout=120)

  for _ in range(40):
    if fctl_status().get("interfaces", {}).get("count", 0):
      status = fctl_status()
      attached = sum(1 for i in status["interfaces"]["interfaces"]
                     if i.get("xdp_attached"))
      if attached >= 3:
        break
    time.sleep(0.5)
  status = fctl_status()
  attached = sum(1 for i in status.get("interfaces", {})
                 .get("interfaces", []) if i.get("xdp_attached"))
  if attached < 3:
    print(out(["journalctl", "-u", "fd", "-n", "20", "--no-pager"]))
    sys.exit(f"fd attached XDP to {attached} interface(s), wanted 3")
  print(f"deployed {tag}: {bundle}, XDP on {attached} interfaces")


def wire_flags() -> dict:
  """The interface flags this bench borrows, as found.

  `prime_wire` turns promiscuous mode ON and VLAN receive-offload OFF
  on the inside copper port, because native XDP runs after the NIC's
  MAC filter and the i350 strips 802.1Q tags in hardware before XDP
  sees them. Both are borrowed, so both are recorded here and put back
  by `restore_smoke`. Borrowing a host-wide knob and not recording
  what it was is how a bench once left the operator's own routing
  down.
  """
  offload = out(["ethtool", "-k", INA_IF], timeout=30)
  match = re.search(r"^rx-vlan-offload:\s*(\w+)", offload, re.MULTILINE)
  return {
    "promisc": "PROMISC" in out(["ip", "link", "show", INA_IF]),
    "rxvlan": match.group(1) if match else "on",
  }


def restore_wire_flags(saved: dict) -> None:
  """Put them back. Absent a record, back to the driver's defaults —
  which is what a walk-up rig has always been described as."""
  run(["ip", "link", "set", "dev", INA_IF, "promisc",
       "on" if saved.get("promisc") else "off"])
  run(["ethtool", "-K", INA_IF, "rxvlan",
       saved.get("rxvlan", "on")])


def prime_wire() -> None:
  """Make the copper usable and the neighbour table warm.

  Native XDP runs after the NIC's MAC filter, so the port that receives
  the generator's builder-MAC frames has to be promiscuous; the i350
  strips 802.1Q tags in hardware before XDP sees them; and an XDP
  attach resets the igb links, so the wire has to be proven back before
  any traffic is believed.
  """
  run(["ip", "link", "set", "dev", INA_IF, "promisc", "on"])
  run(["ethtool", "-K", INA_IF, "rxvlan", "off"])
  probe_cmd = [sys.executable, os.path.join(HERE, "sendmany.py"),
               "--probe", PARENT, INA_IF, "45"]
  proc = run(probe_cmd, timeout=180)
  if proc.returncode != 0:
    # The child's own words, not a summary of them: "the wire never
    # came back" is a true statement about the wrong thing when what
    # actually happened is that the sender could not import fwl.
    sys.exit(f"wire never came back after the XDP attach "
             f"({PARENT} -> {INA_IF}): {proc.stdout.strip()} "
             f"{proc.stderr.strip()}")
  run([sys.executable, os.path.join(HERE, "sendmany.py"), "--teach",
       INA_IF, PARENT], timeout=60)
  # XDP cannot ARP; the stack can, and on a live box it already has.
  # The first forwarded frame to an unresolved next hop is still lost
  # and still counted — that is deliberate and visible — so the soak's
  # baseline is taken after the box has resolved what it routes to.
  for iface, addr in ((INA_IF, GUEST_A), (INB_IF, GUEST_B),
                      (WAN_IF, SERVER)):
    run(["ping", "-c1", "-W2", "-I", iface, addr], timeout=15)


# --- subcommands -----------------------------------------------------

def cmd_start(args) -> int:
  """Start the soak, and leave the rig walk-up ready if it cannot.

  Every refusal below is a real one — a gateway that does not forward
  must not be soaked, because days of green samples against a broken
  box is the worst outcome available. But a half-built bench with a
  soak policy loaded and nothing running is a rig only I understand,
  so a failed start tears its own topology down and puts the operator's
  smoke policy back.
  """
  require_root()
  try:
    return _start(args)
  except BaseException as exc:
    if isinstance(exc, SystemExit) and not exc.code:
      raise
    print(f"start did not complete ({exc}); restoring the walk-up "
          f"state")
    for unit in TRAFFIC_UNITS:
      run(["systemctl", "stop", unit])
    run(["systemctl", "stop", SAMPLE_UNIT + ".timer"])
    restore_smoke()
    raise


def _start(args) -> int:
  for unit in TRAFFIC_UNITS:
    if out(["systemctl", "is-active", unit]) == "active":
      sys.exit(f"a gateway soak is already running ({unit} active)")

  forward = read_int("/proc/sys/net/ipv4/ip_forward")
  print(f"net.ipv4.ip_forward is {forward} (fd's, not ours)")

  found = wire_flags()
  print(f"{INA_IF} as found: {found}")

  print("== building the topology ==")
  topology_up()
  print("== deploying the gateway soak policy ==")
  deploy(POLICY, BUNDLE, "gwsoak")
  prime_wire()

  status = fctl_status()
  route = status.get("route", {})
  nat = status.get("nat", {})
  egress = status.get("egress", {})
  sources = sorted(f"{e['zone']}={e['address']}"
                   for e in nat.get("masq_sources", []))
  print(f"masquerade sources: {' '.join(sources) or '(none)'}")
  print(f"egress tracker on {egress.get('attached', -1)} interface(s), "
        f"declared={egress.get('tracker_declared')}")
  print(f"ip_forward={route.get('ip_forward')} "
        f"({route.get('forwarding_reason', '?')})")
  if not nat.get("enabled"):
    sys.exit("fd does not report NAT as enabled; refusing to soak")
  if egress.get("attached", 0) < 3:
    sys.exit("the egress tracker is not on every datapath interface")
  if len(sources) != 2:
    sys.exit(f"expected two masquerading zones, got {sources}")
  if not all(s.endswith(MASQ_ADDR) for s in sources):
    sys.exit(f"both zones must resolve {MASQ_ADDR}, got {sources}")

  print("== proving the wire before anything is believed ==")
  first = probe()
  print(json.dumps(first, indent=2))
  problems = verify_probe(first)
  if problems:
    for problem in problems:
      print(f"  BAD: {problem}")
    sys.exit("the gateway does not work; not starting a soak on it")

  os.makedirs("/var/log/f", exist_ok=True)
  open(LOG, "w").close()
  deadline = datetime.now(timezone.utc) + timedelta(hours=args.hours)
  with open(STATE, "w") as fh:
    json.dump({
      "started": now(),
      "target_hours": args.hours,
      "target_end": deadline.strftime("%Y-%m-%dT%H:%M:%SZ"),
      "log": LOG,
      "policy": POLICY,
      "bundle": BUNDLE,
      "masq_addr": MASQ_ADDR,
      "wire_flags_as_found": found,
      "note": "does not stop itself; `gwsoak.py stop` ends it",
    }, fh, indent=2)

  print("== starting traffic + sampler ==")
  gen = os.path.join(HERE, "gwsoak_traffic.py")
  wan_dev = f"vl{WAN_VLAN}{NS_S}"
  # Zone A keeps the builder MACs, which hw::teach_fdb-style priming
  # has just taught the EX2300; the veth and the far-side injector are
  # addressed at the real hardware addresses of the ports that must
  # receive them, because native XDP runs after the NIC's MAC filter.
  jobs = (
    (TRAFFIC_UNITS[0], None,
     ["--role", "inside", "--iface", PARENT, "--zone", "a"]),
    (TRAFFIC_UNITS[1], NS_B,
     ["--role", "inside", "--iface", INB_PEER, "--zone", "b",
      "--dst-mac", iface_mac(INB_IF),
      "--src-mac", iface_mac(INB_PEER, ns=NS_B)]),
    (TRAFFIC_UNITS[2], NS_S,
     ["--role", "reply", "--iface", wan_dev,
      "--dst-mac", iface_mac(WAN_IF),
      "--src-mac", iface_mac(wan_dev, ns=NS_S)]),
  )
  for unit, ns, extra in jobs:
    prefix = ["ip", "netns", "exec", ns] if ns else []
    run(["systemd-run", f"--unit={unit}",
         "--property=Restart=always", "--property=RestartSec=5",
         "--setenv=PYTHONPATH=/opt/fwl:/opt/fwl-deps"]
        + prefix + [sys.executable, gen] + extra, check=True)

  # The reply injector is the one load path the wire probe above does
  # not cover, so it is proven here rather than assumed: de-NAT has to
  # move under it. A generator that silently sends nothing would leave
  # the uplink zone idle for days while every sample still passed.
  before = fctl_status().get("nat", {}).get("denat", 0)
  time.sleep(8)
  after = fctl_status().get("nat", {}).get("denat", 0)
  print(f"de-NAT under the reply injector: {before} -> {after}")
  if after <= before:
    sys.exit("the reply injector put nothing through the de-NAT pass")

  run(["systemd-run", f"--unit={SAMPLE_UNIT}",
       "--on-calendar=*:*:00", "--timer-property=AccuracySec=1s",
       "--setenv=PYTHONPATH=/opt/fwl:/opt/fwl-deps",
       sys.executable, os.path.abspath(__file__), "sample"],
      check=True)
  cmd_sample(args)

  print()
  print(f"GATEWAY SOAK RUNNING. Started {now()}.")
  print(f"{args.hours} h target ends: "
        f"{deadline.strftime('%Y-%m-%dT%H:%M:%SZ')}")
  print("It does NOT stop itself. Read it and end it with:")
  print(f"  python3 {__file__} status")
  print(f"  python3 {HERE}/gwsoak_report.py {LOG}")
  print(f"  python3 {__file__} stop")
  return 0


def verify_probe(result: dict) -> list:
  """The wire claims a sample has to satisfy, in one place.

  Shared by `start` (which refuses to soak a gateway that does not
  work) and by gwsoak_report.py (which re-derives the verdict from the
  log alone). One implementation, so the bar a run is judged against
  cannot drift from the bar it was admitted on.
  """
  want = result.get("want_per_zone", CONNS_PER_ZONE)
  masq = result.get("masq_addr", MASQ_ADDR)
  bad = []
  for zone in ("a", "b"):
    got = result.get(zone, {})
    if got.get("completed", -1) != want:
      bad.append(f"zone {zone} completed "
                 f"{got.get('completed', 'no report')}/{want} "
                 f"end-to-end exchanges")
  srv = result.get("srv", {})
  if srv.get("accepted", -1) != want * 2:
    bad.append(f"the far side accepted {srv.get('accepted', 'nothing')}"
               f" of {want * 2}")
  if srv.get("echoed", -1) != want * 2:
    bad.append(f"the far side echoed {srv.get('echoed', 'nothing')} "
               f"of {want * 2}")
  if srv.get("peer_addrs") != [masq]:
    bad.append(f"the far side's own kernel saw peers "
               f"{srv.get('peer_addrs')}, wanted exactly [{masq}] "
               f"(both zones masquerading to the one uplink address)")
  box = result.get("box", {})
  if box.get("completed", -1) != 1:
    bad.append("the flow the BOX originated did not complete through "
               "the uplink's default drop (egress tracker)")
  boxsrv = result.get("boxsrv", {})
  if boxsrv.get("accepted", -1) != 1:
    bad.append("the far side never accepted the box's own flow")
  return bad


def cmd_sample(args) -> int:
  require_root()
  sample = readings()
  sample["probe"] = probe()
  sample["wire_problems"] = verify_probe(sample["probe"])
  with open(LOG, "a") as fh:
    fh.write(json.dumps(sample, sort_keys=True) + "\n")
  return 0


def cmd_probe(args) -> int:
  require_root()
  result = probe()
  print(json.dumps(result, indent=2))
  problems = verify_probe(result)
  for problem in problems:
    print(f"BAD: {problem}")
  return 1 if problems else 0


def cmd_status(args) -> int:
  for unit in TRAFFIC_UNITS + (SAMPLE_UNIT + ".timer",):
    print(f"{unit}: {out(['systemctl', 'is-active', unit])}")
  report = os.path.join(HERE, "gwsoak_report.py")
  return subprocess.run([sys.executable, report, LOG]).returncode


def cmd_stop(args) -> int:
  require_root()
  for unit in TRAFFIC_UNITS:
    run(["systemctl", "stop", unit])
  run(["systemctl", "stop", SAMPLE_UNIT + ".timer"])
  run(["systemctl", "stop", SAMPLE_UNIT])
  print(f"soak stopped; log kept at {LOG}")
  print("== verdict ==")
  subprocess.run([sys.executable,
                  os.path.join(HERE, "gwsoak_report.py"), LOG])

  restore_smoke()
  return 0


def restore_smoke() -> int:
  """Put the operator's walk-up policy back and say what the box holds.

  The pin root IS cleared here, unlike on the deploy path: this is the
  recovery path, it runs after a failed start as well as after a clean
  stop, and a walk-up operator has to find a working rig whatever
  happened. ip_forward is left to fd and only REPORTED — writing it
  back on an armed box is what left the rig reading `[FAIL] OFF, and
  fd did not do it` after the sweep's own tidy-up on 2026-08-16.
  """
  print("== restoring the walk-up smoke policy ==")
  saved = {"promisc": False, "rxvlan": "on"}
  try:
    with open(STATE) as fh:
      saved = json.load(fh).get("wire_flags_as_found", saved)
  except (OSError, json.JSONDecodeError, AttributeError):
    pass
  restore_wire_flags(saved)
  topology_down()
  with open(RULES, "w") as fh:
    fh.write(SMOKE_POLICY)
  smoke = os.path.join(BUNDLE_ROOT, "v-smoke")
  shutil.rmtree(smoke, ignore_errors=True)
  run(["systemctl", "stop", "fd"], timeout=60)
  if run(["fwl", "compile", "--bundle", smoke, RULES],
         timeout=600).returncode != 0:
    print("recompiling the smoke policy FAILED; fd is stopped")
    return 1
  for name in os.listdir(PIN) if os.path.isdir(PIN) else []:
    if name.startswith("fwl_") or name == "conntrack":
      try:
        os.unlink(os.path.join(PIN, name))
      except OSError:
        pass
  run(["ln", "-sfT", smoke, os.path.join(BUNDLE_ROOT, "current")])
  run(["systemctl", "reset-failed", "fd"])
  run(["systemctl", "start", "fd"], timeout=120)
  shutil.rmtree(BUNDLE, ignore_errors=True)
  time.sleep(3)
  status = fctl_status()
  attached = sum(1 for i in status.get("interfaces", {})
                 .get("interfaces", []) if i.get("xdp_attached"))
  reason = status.get("route", {}).get("forwarding_reason", "?")
  print(f"fd {out(['systemctl', 'is-active', 'fd'])}, XDP on "
        f"{attached} interface(s), ip_forward="
        f"{read_int('/proc/sys/net/ipv4/ip_forward')} ({reason})")
  return 0


def main() -> int:
  parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
  sub = parser.add_subparsers(dest="cmd", required=True)
  start = sub.add_parser("start", help="build, deploy and begin")
  start.add_argument("--hours", type=int, default=DEFAULT_HOURS,
                     help="target run length; the soak does not stop "
                          "itself, this is what the report judges "
                          "completeness against")
  sub.add_parser("sample", help="append one sample (timer-driven)")
  sub.add_parser("probe", help="the wire witness alone, by hand")
  sub.add_parser("status", help="live glance + verdict so far")
  sub.add_parser("stop", help="end it and restore the smoke policy")
  args = parser.parse_args()
  return {
    "start": cmd_start, "sample": cmd_sample, "probe": cmd_probe,
    "status": cmd_status, "stop": cmd_stop,
  }[args.cmd](args)


if __name__ == "__main__":
  sys.exit(main())
