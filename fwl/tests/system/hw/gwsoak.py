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
  python3 gwsoak.py append            # add the Tier 2 half, hot
  python3 gwsoak.py stop

Epochs
------
A run may change policy while it is running — `append` does exactly
that, by a deliberate hot reload — and every aggregate in this log
would be ambiguous across such a change if it were not recorded.
`fwl_counters` is MapLifetime.POLICY: slot i belongs to the
compilation that allocated it, so a reload resets every counter to
zero by design. So does `fwl_nat_stats`, `fwl_route_stats` and
`fwl_egress_stats`. Read across a boundary without knowing it is
there, that reads as nineteen counters going backwards at once.

Every sample therefore carries an `epoch`: an integer that only
`append` moves, alongside the sha256 of the policy that was loaded
when it moved. `gwsoak_report.py` segments the run on it and judges
each epoch's counters against that epoch's own baseline. A sample
with no `epoch` field is epoch 1 by definition — the field did not
exist before the first append, and its absence is the marker.

The boundary is a DECLARATION and not an amnesty. Anything that is
genuinely one fact about one process — fd's RSS, its restart count,
the boot id, link flaps — stays judged across the whole run, so a
policy change cannot be used to hide a daemon that died. And a reload
performed WITHOUT bumping the epoch still shows up as every counter
going backwards, which the report still fails on.
"""
import argparse
import hashlib
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
POLICY_T2 = os.path.join(HERE, "gwsoak_policy_t2.fw")
BUNDLE = os.path.join(BUNDLE_ROOT, "v-gwsoak")

# Interfaces. Keep in step with gwsoak_policy.fw, which names them
# literally because a bundle manifest does.
PARENT = "enp1s0f0"     # trunk carrying both copper-side far hosts
INA_IF = "enp1s0f1"     # inside zone A — copper
WAN_IF = "enp1s0f2"     # the uplink — copper
INB_IF = "fs3b"         # inside zone B — veth, root-ns end
INB_PEER = "fs3bp"      # its peer, inside netns gwsb
# The two Tier 2 zones (epoch 2). Veth for the same reason inb is: the
# i350 has three usable ports and all three are already zones. What a
# veth leg cannot exercise is the igb driver's ndo_xdp_xmit; what it
# exercises perfectly well is the question these zones exist for — a
# Tier 2 `def` body, a real BPF-to-BPF helper call, a Tier 2
# `masquerade` and a Tier 2 `redirect`, all under continuous load.
INC_IF = "fs4c"
INC_PEER = "fs4cp"
IND_IF = "fs4d"
IND_PEER = "fs4dp"
WAN_VLAN = 802

# Addresses.
INA_ADDR = "10.99.31.1"
INB_ADDR = "10.99.32.1"
MASQ_ADDR = "10.99.210.2"   # the uplink's address == masquerade source
INC_ADDR = "10.99.33.1"
IND_ADDR = "10.99.34.1"
GUEST_A = "10.99.31.5"
GUEST_B = "10.99.32.5"
GUEST_C = "10.99.33.5"
GUEST_D = "10.99.34.5"
SERVER = "10.99.210.9"
CHURN_NET = "10.99.240.0/22"
CHURN_GW = "10.99.210.250"
CHURN_GW_MAC = "02:00:00:00:99:fa"

NS_A, NS_B, NS_S = "gwsa", "gwsb", "gwss"
NS_C, NS_D = "gwsc", "gwsd"
PORT_GUEST = 8461     # the guests' far-side listener
PORT_BOX = 8462       # the box's own far-side listener
CONNS_PER_ZONE = 3

TRAFFIC_UNITS = ("f-gwsoak-traffic-a", "f-gwsoak-traffic-b",
                 "f-gwsoak-reply")
T2_TRAFFIC_UNITS = ("f-gwsoak-traffic-c", "f-gwsoak-traffic-d")
SAMPLE_UNIT = "f-gwsoak-sample"
DEFAULT_HOURS = 96

# What each epoch claims, in one place, so `append`, `probe`,
# `verify_probe` and the report cannot disagree about it. The `zones`
# tuple is the set of inside zones whose delivery must be witnessed by
# a real socket in a sample taken under that epoch; `identities` are
# the Tier 2 counter identities the report checks every sample.
EPOCHS = {
  1: {
    "policy": POLICY,
    "zones": ("a", "b"),
    "what": "Tier 1 only: three @xdp zones of rules, no `def` anywhere",
    "identities": (),
    "must_move": ("a_masq", "b_masq", "w_est"),
    # Epoch 1 keeps the reading this run started under, DELIBERATELY.
    # `__rate_limit_overflow` is declared by both rate-limited zones,
    # so under this spelling it reports whichever zone was read last
    # — a real defect, and one that is fixed forward rather than
    # backward: renaming a counter under a measurement in progress
    # would make it vanish mid-epoch, which the report would fail on,
    # correctly. From epoch 2 both zones' values are reported.
    "qualify_duplicates": False,
  },
  2: {
    "policy": POLICY_T2,
    "zones": ("a", "b", "c", "d"),
    "what": ("+ two Tier 2 zones (inc hoists its guards into locals, "
             "ind writes them inline) and one shared helper reached "
             "from both"),
    # (total, leaves...) — every frame the zone's `def` sees lands in
    # exactly one leaf, so the sum IS the total. Written here rather
    # than in the report because it is a property of the POLICY.
    "identities": (
      ("c_total", ("inc.t2_mcast", "inc.t2_nbns", "c_workload",
                   "c_web", "c_other_tcp", "c_udp", "c_other_proto",
                   "c_offnet")),
      ("d_total", ("ind.t2_mcast", "ind.t2_nbns", "d_workload",
                   "d_web", "d_other_tcp", "d_udp", "d_other_proto",
                   "d_offnet")),
    ),
    # Both halves of each Tier 2 guard, on purpose. `c_workload`
    # moving says the guard ADMITS; `c_offnet` moving says the same
    # guard REJECTS. A guard that had stopped discriminating would
    # keep one of them climbing, which is why neither is enough
    # alone. `c_syn` is the bool LOCAL read as a bare primary and
    # `d_syn` the bare flag field — the pair is the refactor-
    # invariance claim. `inc.t2_mcast`/`ind.t2_mcast` are the one
    # shared helper compiled into two objects, read separately.
    "must_move": (
      "a_masq", "b_masq", "w_est",
      "c_total", "c_workload", "c_syn", "c_udp", "c_offnet",
      "d_total", "d_workload", "d_syn", "d_udp", "d_offnet",
      "inc.t2_mcast", "inc.t2_nbns", "ind.t2_mcast", "ind.t2_nbns",
    ),
    # A shared helper's counters land in EVERY calling zone's own
    # private map, so from here on a duplicated name is reported once
    # per zone. `__rate_limit_overflow` changes spelling with them,
    # and that is the point of tying it to the epoch: the rename and
    # the policy change are the same event, so nothing disappears
    # inside an epoch and a rollback keeps the old spelling.
    "qualify_duplicates": True,
  },
}
FIRST_EPOCH = 1

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


def counter_slots(current: str = "") -> dict:
  """{zone: {counter_name: slot}} from the running bundle's own C.

  The name->slot mapping is the `fwl_counter_table` comment block the
  emitter writes for exactly this purpose. Reading counters by NAME is
  the point: a slot index is a number that stays valid while the policy
  under it changes, and this soak has to survive being read by somebody
  who did not deploy it.

  `current` overrides the rig's bundle directory. It exists so that
  `tier2_gateway_netns.py` reads its counters through THIS function
  rather than through a copy of it — the reader is part of what the
  VM has to validate, and a bench that reimplements it agrees with
  itself.
  """
  table: dict[str, dict[str, int]] = {}
  cur = current or os.path.join(BUNDLE_ROOT, "current")
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


def read_counters(current: str = "", pin: str = "",
                  qualify: bool = True) -> dict:
  """Every declared counter, by name, summed over CPUs.

  A counter the running bundle does not declare reads -1, never 0.
  "Absent" and "zero" are different measurements, and a check that
  cannot tell them apart is not checking anything — four assertions in
  the hardware suite were satisfied by a silently renamed counter before
  hw::counter started saying -1.

  A name declared by MORE THAN ONE zone is keyed `<zone>.<name>` and
  the bare name is not emitted at all. `fwl_counters` is
  MapScope.PRIVATE — slot i is THIS zone's i-th counter — so one name
  in two zones is two independent kernel counters, and the earlier
  spelling of this function wrote them both to one dictionary key and
  kept whichever zone it read last. That was invisible while every
  counter in this soak's policy was unique to its zone. It stops being
  invisible the moment a SHARED HELPER declares one: `t2_noise`'s
  counters are compiled into inc.bpf.o and ind.bpf.o both, and reading
  one of them as if it were the pair is exactly the reading that would
  hide a helper that had stopped working in one object. (`hw::counter`
  in hwlib.sh has the same shape and takes the FIRST zone instead;
  named here rather than fixed there, because a shell scenario that
  deploys a one-zone policy cannot reach the case.)

  `qualify=False` restores the older spelling exactly. It is not a
  compatibility shim for its own sake: the epoch a sample is taken
  under decides it (`EPOCHS[n]["qualify_duplicates"]`), so a counter
  can only change name AT a declared policy boundary and never inside
  one. A rename inside an epoch reads as a counter that vanished, and
  the report fails on that — correctly.
  """
  values: dict[str, int] = {}
  slots_by_zone = counter_slots(current)
  root = pin or PIN
  seen: dict[str, int] = {}
  for slots in slots_by_zone.values():
    for name in slots:
      seen[name] = seen.get(name, 0) + 1
  for zone, slots in slots_by_zone.items():
    dumped = out(["bpftool", "map", "dump", "pinned",
                  f"{root}/fwl_counters_{zone}"], timeout=30)
    per_slot: dict[int, int] = {}
    try:
      for entry in json.loads(dumped or "[]"):
        per_slot[_as_int(entry["key"])] = sum(
          _as_int(v["value"]) for v in entry["values"])
    except (json.JSONDecodeError, KeyError, TypeError, ValueError):
      per_slot = {}
    for name, slot in slots.items():
      key = name if (seen[name] == 1 or not qualify) else \
          f"{zone}.{name}"
      values[key] = per_slot.get(slot, -1) if per_slot else -1
  return values


def read_state() -> dict:
  """The run's state file, or {} when there is no run."""
  try:
    with open(STATE) as fh:
      return json.load(fh)
  except (OSError, json.JSONDecodeError):
    return {}


def current_epoch() -> int:
  """Which policy this box is soaking, as an integer.

  Only `append` moves it, and it moves only after the reload has been
  proven to have taken. A sample written before the field existed has
  no `epoch` key at all, which the report reads as epoch 1.
  """
  epoch = read_state().get("epoch", FIRST_EPOCH)
  return epoch if epoch in EPOCHS else FIRST_EPOCH


def traffic_units(epoch: int) -> tuple:
  """The generator units that must be running under this epoch."""
  if epoch >= 2:
    return TRAFFIC_UNITS + T2_TRAFFIC_UNITS
  return TRAFFIC_UNITS


def sha256(path: str) -> str:
  """The policy's own digest, so a reader can tell one from another."""
  try:
    with open(path, "rb") as fh:
      return hashlib.sha256(fh.read()).hexdigest()
  except OSError:
    return ""


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
  state = read_state()
  epoch = current_epoch()
  return {
    "ts": now(),
    "boot_id": out(["cat", "/proc/sys/kernel/random/boot_id"]),
    "uptime_s": int(float(open("/proc/uptime").read().split()[0])),
    # Which policy this sample was taken under. Every counter below is
    # read out of a MapLifetime.POLICY map, so this field is what
    # makes the numbers either side of an `append` comparable to
    # themselves and not to each other.
    "epoch": epoch,
    "policy_sha": state.get("policy_sha", ""),
    "counters": read_counters(
      qualify=EPOCHS[epoch].get("qualify_duplicates", True)),
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
                       for u in traffic_units(epoch)],
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


def probe(epoch: int = 0) -> dict:
  """One sample's wire witnesses. Real sockets on real stacks only.

  The two guest namespaces and the far side are ordinary Linux hosts
  that are NOT promiscuous (asserted when they are built, not assumed),
  so a byte only arrives at a socket here if the frame was addressed to
  it, translated correctly, checksummed correctly, and completed a
  three-way handshake. The box's own client runs in the ROOT namespace,
  because the flow this soak needs it to originate is the appliance's
  own.

  `epoch` names the shape to probe and defaults to the running one.
  `append` passes it explicitly — it has to prove the four-zone wire
  BEFORE the run is declared to be at epoch 2, and writing a
  provisional epoch into the state file to arrange that would leave a
  stray epoch-2 sample in the log if the append then rolled back.
  """
  started = time.monotonic()
  epoch = epoch or current_epoch()
  zones = EPOCHS[epoch]["zones"]
  namespaces = {"a": NS_A, "b": NS_B, "c": NS_C, "d": NS_D}
  want = CONNS_PER_ZONE * len(zones)
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

  result = {}
  with futures.ThreadPoolExecutor(max_workers=len(zones) + 1) as pool:
    guests = {z: pool.submit(client, namespaces[z]) for z in zones}
    fut_box = pool.submit(box_client)
    for zone, fut in guests.items():
      result[zone] = parse(fut.result())
    result["box"] = parse(fut_box.result())
  result["srv"] = _collect(srv_guest, 18)
  result["boxsrv"] = _collect(srv_box, 18)
  result["want_per_zone"] = CONNS_PER_ZONE
  result["masq_addr"] = MASQ_ADDR
  result["epoch"] = epoch
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
  # Both multiarch include roots are offered and the missing one is
  # harmless: this file has to build on the rig (aarch64) and on the
  # x86_64 VM the Tier 2 additions were validated on, and hard-coding
  # one triplet made the VM run die on a header rather than on
  # anything about the firewall.
  proc = run(["clang", "-O2", "-g", "-target", "bpf",
              "-I/usr/include/aarch64-linux-gnu",
              "-I/usr/include/x86_64-linux-gnu",
              "-c", src, "-o", obj])
  if proc.returncode != 0:
    sys.exit(f"compiling xdp_pass failed: {proc.stderr}")
  return obj


def _veth_leg(dev: str, peer: str, ns: str, gw: str, guest: str,
              obj: str) -> None:
  """One inside zone on a veth pair, with a host on the far end.

  The offload flags are not optional. A veth pair keeps
  CHECKSUM_PARTIAL end to end — the header carries the pseudo-header
  sum and never the final one — so the NAT's incremental update lands
  on a base that was never valid and the far stack drops the frame
  with Tcp:InCsumErrors. On copper the sending NIC has computed it
  already. Neither is the XDP program on the peer: veth's
  ndo_xdp_xmit needs one on the RECEIVING side or a redirect into the
  leg is dropped below the peer's stack and no socket ever sees it.
  """
  run(["ip", "link", "add", dev, "type", "veth", "peer", "name", peer],
      check=True)
  run(["ip", "netns", "add", ns], check=True)
  run(["ip", "link", "set", peer, "netns", ns], check=True)
  run(["ip", "link", "set", dev, "up"], check=True)
  run(["ip", "link", "set", "lo", "up"], ns=ns)
  run(["ip", "link", "set", peer, "up"], ns=ns)
  run(["ip", "addr", "add", f"{guest}/24", "dev", peer], ns=ns)
  run(["ip", "route", "add", "default", "via", gw, "dev", peer], ns=ns)
  for end, where in ((dev, None), (peer, ns)):
    run(["ethtool", "-K", end, "tx", "off", "rx", "off", "tso", "off",
         "gso", "off", "gro", "off"], ns=where)
  if run(["ip", "link", "set", "dev", peer, "xdpdrv", "obj", obj,
          "sec", "xdp"], ns=ns).returncode != 0:
    run(["ip", "link", "set", "dev", peer, "xdp", "obj", obj,
         "sec", "xdp"], ns=ns, check=True)
  if "PROMISC" in out(["ip", "link", "show", peer], ns=ns):
    sys.exit(f"{ns}/{peer} is PROMISC; it would accept frames a real "
             f"host drops")


def topology_t2_up() -> None:
  """The two Tier 2 legs, built without disturbing anything running.

  Separate from `topology_up` on purpose: this runs on a box that is
  MID-SOAK. It touches nothing that exists — no address on f0/f1/f2,
  no route, no neighbour entry, no interface flag — and everything it
  does create is named `fs4*` or `gwsc`/`gwsd`, so `topology_t2_down`
  can be exact rather than best-effort.
  """
  topology_t2_down()
  obj = _xdp_pass_object()
  _veth_leg(INC_IF, INC_PEER, NS_C, INC_ADDR, GUEST_C, obj)
  _veth_leg(IND_IF, IND_PEER, NS_D, IND_ADDR, GUEST_D, obj)
  run(["ip", "addr", "add", f"{INC_ADDR}/24", "dev", INC_IF])
  run(["ip", "addr", "add", f"{IND_ADDR}/24", "dev", IND_IF])


def topology_t2_down() -> None:
  """Take the Tier 2 legs off the box. Idempotent, and exact."""
  for dev, ns in ((INC_IF, NS_C), (IND_IF, NS_D)):
    run(["ip", "link", "set", "dev", dev, "xdp", "off"])
    run(["ip", "link", "del", dev])
    run(["ip", "netns", "del", ns])


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
  topology_t2_down()
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
    for unit in TRAFFIC_UNITS + T2_TRAFFIC_UNITS:
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
      "epoch": FIRST_EPOCH,
      "policy_sha": sha256(POLICY),
      "epochs": [{"epoch": FIRST_EPOCH, "from": now(),
                  "policy": POLICY, "policy_sha": sha256(POLICY),
                  "what": EPOCHS[FIRST_EPOCH]["what"]}],
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


def verify_probe(result: dict, epoch: int = FIRST_EPOCH) -> list:
  """The wire claims a sample has to satisfy, in one place.

  Shared by `start` (which refuses to soak a gateway that does not
  work), by `append` (which refuses to widen a run onto a gateway that
  does not work) and by gwsoak_report.py (which re-derives the verdict
  from the log alone). One implementation, so the bar a run is judged
  against cannot drift from the bar it was admitted on.

  The bar is a function of the EPOCH and not of the probe. A sample
  taken under epoch 2 is judged on four inside zones whether or not
  its probe recorded four, because a bar derived from what the
  instrument happened to write down is a bar an instrument that wrote
  nothing down would pass.
  """
  want = result.get("want_per_zone", CONNS_PER_ZONE)
  masq = result.get("masq_addr", MASQ_ADDR)
  zones = EPOCHS.get(epoch, EPOCHS[FIRST_EPOCH])["zones"]
  total = want * len(zones)
  bad = []
  for zone in zones:
    got = result.get(zone, {})
    if got.get("completed", -1) != want:
      bad.append(f"zone {zone} completed "
                 f"{got.get('completed', 'no report')}/{want} "
                 f"end-to-end exchanges")
  srv = result.get("srv", {})
  if srv.get("accepted", -1) != total:
    bad.append(f"the far side accepted {srv.get('accepted', 'nothing')}"
               f" of {total}")
  if srv.get("echoed", -1) != total:
    bad.append(f"the far side echoed {srv.get('echoed', 'nothing')} "
               f"of {total}")
  if srv.get("peer_addrs") != [masq]:
    bad.append(f"the far side's own kernel saw peers "
               f"{srv.get('peer_addrs')}, wanted exactly [{masq}] "
               f"(all {len(zones)} inside zones masquerading to the "
               f"one uplink address)")
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
  sample["wire_problems"] = verify_probe(sample["probe"],
                                         sample["epoch"])
  with open(LOG, "a") as fh:
    fh.write(json.dumps(sample, sort_keys=True) + "\n")
  return 0


def cmd_probe(args) -> int:
  require_root()
  result = probe()
  print(json.dumps(result, indent=2))
  problems = verify_probe(result, result.get("epoch", FIRST_EPOCH))
  for problem in problems:
    print(f"BAD: {problem}")
  return 1 if problems else 0


def _hot_reload(policy: str, want_ifaces: int, tag: str) -> bool:
  """Hand a policy to fd's watcher and wait for it to be adopted.

  This is NOT `deploy`. `deploy` stops fd, moves the `current`
  symlink and starts it again — a cold restart, which on a running
  soak would bump NRestarts (the report fails on that, correctly),
  detach every XDP program, and drop `ip_forward` on the way through.
  The watcher path is the product's own hot reload: fd recompiles
  /etc/f/rules.fw, builds a bundle, swaps `current` atomically and
  reloads without the process going anywhere. It is the same path
  l3_01 measures zero packet loss across.

  Returns True once `current` has MOVED and the datapath is attached
  to `want_ifaces` interfaces. A reload that is refused leaves the
  running bundle intact — that is l3_06 — so a False here means the
  run is still on the policy it was on.
  """
  before = os.path.realpath(os.path.join(BUNDLE_ROOT, "current"))
  shutil.copyfile(policy, RULES)
  print(f"handed {tag} to fd's watcher at {RULES}; waiting for the "
        f"atomic swap")
  for _ in range(120):
    time.sleep(1)
    after = os.path.realpath(os.path.join(BUNDLE_ROOT, "current"))
    if after == before:
      continue
    status = fctl_status()
    attached = sum(1 for i in status.get("interfaces", {})
                   .get("interfaces", []) if i.get("xdp_attached"))
    if attached >= want_ifaces:
      print(f"adopted: {before} -> {after}, XDP on {attached} "
            f"interface(s)")
      return True
  after = os.path.realpath(os.path.join(BUNDLE_ROOT, "current"))
  print(f"the watcher did not adopt {tag}: current is {after} "
        f"(was {before})")
  print(out(["journalctl", "-u", "fd", "-n", "30", "--no-pager"]))
  return False


def cmd_append(args) -> int:
  """Widen a RUNNING soak onto the Tier 2 emission path.

  Deliberately not a scenario. Every hardware scenario's EXIT trap
  calls `hw::restore_smoke`, which would end this run silently; this
  command touches the policy and nothing else, and every failure path
  puts the epoch-1 policy back rather than leaving a half-widened
  bench nobody can read.

  What it does NOT do, and each omission is load-bearing: it does not
  stop or restart fd, it does not touch the `current` symlink itself,
  it does not stop the running generators or the sampler, it does not
  write net.ipv4.ip_forward, it does not touch f0/f1/f2 or any address
  or flag that already exists, and it does not truncate the log. The
  run continues; its second half is simply wider.
  """
  require_root()
  state = read_state()
  if not state:
    sys.exit(f"no run in progress ({STATE} is missing); `append` "
             f"widens a soak that is already going")
  if state.get("epoch", FIRST_EPOCH) >= 2:
    sys.exit(f"this run is already at epoch {state['epoch']}")
  for unit in TRAFFIC_UNITS + (SAMPLE_UNIT + ".timer",):
    if out(["systemctl", "is-active", unit]) != "active":
      sys.exit(f"{unit} is not active; there is no healthy run to "
               f"widen — read `gwsoak.py status` first")

  # Refuse to widen a run that is not green. Appending to a failing
  # soak would put a policy change into the middle of the evidence
  # somebody is trying to read.
  verdict = subprocess.run(
    [sys.executable, os.path.join(HERE, "gwsoak_report.py"), LOG],
    capture_output=True, text=True)
  if verdict.returncode != 0:
    print(verdict.stdout)
    sys.exit(f"the run is not green (report exit {verdict.returncode});"
             f" refusing to change policy under it")
  print("the run is green so far; widening it")

  # Compile FIRST, into a scratch directory, so a policy that cannot
  # be built never reaches /etc/f/rules.fw and the watcher never sees
  # it. `fwl check` alone is not enough — it does not clang.
  scratch = "/run/gwsoak-append-check"
  shutil.rmtree(scratch, ignore_errors=True)
  if run(["fwl", "check", POLICY_T2]).returncode != 0:
    sys.exit(f"the epoch-2 policy is rejected: {POLICY_T2}")
  built = run(["fwl", "compile", "--bundle", scratch, POLICY_T2],
              timeout=900)
  if built.returncode != 0:
    sys.exit(f"the epoch-2 policy does not compile: {built.stderr}")
  with open(os.path.join(scratch, "manifest.json")) as fh:
    if '"object": null' in fh.read():
      sys.exit("the epoch-2 bundle has uncompiled zone objects")
  print(f"epoch-2 policy compiles: 5 zone objects in {scratch}")

  # The interfaces have to exist BEFORE the reload: fd attaches to the
  # interfaces the manifest names, and a zone whose interface is
  # missing is warned about and skipped, which would leave a
  # five-zone bundle running as a three-zone one.
  print("== building the two Tier 2 legs ==")
  topology_t2_up()
  for iface, addr in ((INC_IF, GUEST_C), (IND_IF, GUEST_D)):
    run(["ping", "-c1", "-W2", "-I", iface, addr], timeout=15)

  print("== hot reload ==")
  if not _hot_reload(POLICY_T2, 5, "the epoch-2 policy"):
    print("rolling back to the epoch-1 policy")
    _hot_reload(POLICY, 3, "the epoch-1 policy")
    topology_t2_down()
    sys.exit("append failed; the run continues at epoch 1")

  status = fctl_status()
  nat = status.get("nat", {})
  sources = sorted(f"{e['zone']}={e['address']}"
                   for e in nat.get("masq_sources", []))
  egress = status.get("egress", {})
  print(f"masquerade sources: {' '.join(sources) or '(none)'}")
  print(f"egress tracker on {egress.get('attached', -1)} interface(s)")
  problems = []
  if len(sources) != 4:
    problems.append(f"expected four masquerading zones, got {sources}")
  if not all(s.endswith(MASQ_ADDR) for s in sources):
    problems.append(f"every zone must resolve {MASQ_ADDR}: {sources}")
  if egress.get("attached", 0) < 5:
    problems.append("the egress tracker is not on every interface")
  names = set(read_counters(qualify=True))
  for wanted in ("c_total", "d_total", "inc.t2_mcast", "ind.t2_mcast"):
    if wanted not in names:
      problems.append(f"counter {wanted} is not in the running bundle")

  print("== proving the wider wire before the epoch moves ==")
  # The epoch has NOT moved yet — nothing may declare it moved until
  # the four new zones have been witnessed by a real socket — so the
  # wider shape is asked for explicitly rather than by writing a
  # provisional epoch into the state file, which would leave a stray
  # epoch-2 sample in the log if this rolled back.
  first = probe(2)
  problems += verify_probe(first, 2)
  if problems:
    print(json.dumps(first, indent=2))
    for problem in problems:
      print(f"  BAD: {problem}")
    print("rolling back to the epoch-1 policy")
    _hot_reload(POLICY, 3, "the epoch-1 policy")
    topology_t2_down()
    sys.exit("the widened gateway does not work; the run continues "
             "at epoch 1")

  print("== starting the two Tier 2 generators ==")
  gen = os.path.join(HERE, "gwsoak_traffic.py")
  jobs = (
    (T2_TRAFFIC_UNITS[0], NS_C,
     ["--role", "t2inside", "--iface", INC_PEER, "--zone", "c",
      "--dst-mac", iface_mac(INC_IF),
      "--src-mac", iface_mac(INC_PEER, ns=NS_C)]),
    (T2_TRAFFIC_UNITS[1], NS_D,
     ["--role", "t2inside", "--iface", IND_PEER, "--zone", "d",
      "--dst-mac", iface_mac(IND_IF),
      "--src-mac", iface_mac(IND_PEER, ns=NS_D)]),
  )
  for unit, ns, extra in jobs:
    run(["systemctl", "stop", unit])
    run(["systemd-run", f"--unit={unit}",
         "--property=Restart=always", "--property=RestartSec=5",
         "--setenv=PYTHONPATH=/opt/fwl:/opt/fwl-deps",
         "ip", "netns", "exec", ns, sys.executable, gen] + extra,
        check=True)
  # A generator that silently sends nothing would leave both Tier 2
  # zones idle for days while every sample still passed, so it is
  # proven here rather than assumed.
  before = read_counters(qualify=True)
  time.sleep(8)
  after = read_counters(qualify=True)
  moved = [n for n in ("c_total", "d_total", "inc.t2_mcast",
                       "ind.t2_mcast")
           if after.get(n, -1) > before.get(n, -1)]
  print(f"under the Tier 2 generators, moved in 8 s: {moved}")
  if len(moved) != 4:
    print("the Tier 2 generators put nothing through the new zones")

  # A run started before epochs existed has no record of its first
  # one, and the report would have to fall back on a constant to say
  # what the samples before the boundary were taken under. Backfill it
  # from what the state file DOES know, so both halves are described
  # by the same mechanism.
  history = list(state.get("epochs", []))
  if not any(e.get("epoch") == FIRST_EPOCH for e in history):
    history.insert(0, {
      "epoch": FIRST_EPOCH,
      "from": state.get("started", ""),
      "policy": state.get("policy", POLICY),
      "policy_sha": sha256(state.get("policy", POLICY)),
      "what": EPOCHS[FIRST_EPOCH]["what"],
    })
  _write_state(dict(
    state,
    epoch=2,
    policy=POLICY_T2,
    policy_sha=sha256(POLICY_T2),
    epochs=history + [{
      "epoch": 2, "from": now(), "policy": POLICY_T2,
      "policy_sha": sha256(POLICY_T2), "what": EPOCHS[2]["what"],
    }],
  ))
  shutil.rmtree(scratch, ignore_errors=True)
  cmd_sample(args)
  print()
  print(f"APPENDED. Epoch 2 from {now()}.")
  print("The report marks the boundary and judges each epoch's "
        "counters against that epoch's own baseline:")
  print(f"  python3 {HERE}/gwsoak_report.py {LOG}")
  return 0


def _write_state(state: dict) -> None:
  """Replace the state file atomically."""
  tmp = STATE + ".new"
  with open(tmp, "w") as fh:
    json.dump(state, fh, indent=2)
  os.rename(tmp, STATE)


def cmd_status(args) -> int:
  """The live glance, then the verdict.

  A unit that died thirty seconds ago is not in the log yet — the
  report will catch it at the next sample, but `status` is the thing
  somebody runs when they want to know NOW, so a dead unit makes this
  non-zero on its own rather than waiting for the log to agree.
  """
  dead = []
  epoch = current_epoch()
  print(f"epoch: {epoch} — {EPOCHS[epoch]['what']}")
  for unit in traffic_units(epoch) + (SAMPLE_UNIT + ".timer",):
    state = out(["systemctl", "is-active", unit])
    print(f"{unit}: {state}")
    if state != "active":
      dead.append(unit)
  report = os.path.join(HERE, "gwsoak_report.py")
  # The report is a subprocess writing straight to fd 1 while these
  # prints sit in Python's own buffer, so without this the live glance
  # lands AFTER the verdict it is supposed to introduce — and the
  # epoch line is the first thing a reader of a two-epoch run needs.
  sys.stdout.flush()
  verdict = subprocess.run([sys.executable, report, LOG]).returncode
  if dead:
    print(f"NOT RUNNING: {', '.join(dead)} — the soak has stopped "
          f"generating or sampling; the log above ends where it did")
    return 1
  return verdict


def cmd_stop(args) -> int:
  require_root()
  for unit in TRAFFIC_UNITS + T2_TRAFFIC_UNITS:
    run(["systemctl", "stop", unit])
  run(["systemctl", "stop", SAMPLE_UNIT + ".timer"])
  run(["systemctl", "stop", SAMPLE_UNIT])
  print(f"soak stopped; log kept at {LOG}")
  print("== verdict ==")
  subprocess.run([sys.executable,
                  os.path.join(HERE, "gwsoak_report.py"), LOG])

  # The restore's own result, not a blanket 0: somebody scripting
  # `stop` needs a non-zero exit when the rig was NOT put back.
  return restore_smoke()


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
  sub.add_parser("append", help="widen a running soak onto the Tier 2 "
                                "emission path, by hot reload")
  sub.add_parser("stop", help="end it and restore the smoke policy")
  args = parser.parse_args()
  return {
    "start": cmd_start, "sample": cmd_sample, "probe": cmd_probe,
    "status": cmd_status, "append": cmd_append, "stop": cmd_stop,
  }[args.cmd](args)


if __name__ == "__main__":
  sys.exit(main())
