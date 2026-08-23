#!/usr/bin/env python3
"""Datapath tuning that is not a kernel default and is worth 40%.

Three settings, measured on the RK3588 rig on 2026-08-23 against
RFC 2544 and recorded in `f.planning/rig-evidence/
RFC2544_10G_2026-08-23.md`. None of them is on by default, all of
them are lost on reboot, and two of them look like nothing.

**Deep cpuidle off.** The box was dropping packets with 45% of its
CPU idle, every core at maximum clock, 43 C against a 55 C trip. The
`cpu-sleep` state on this SoC has a 220 microsecond exit latency; at
1.4 Mpps that is roughly 300 frames arriving before the core that has
to poll them is running again, against a 1024-entry ring. Disabling
it was worth 31% at 64 bytes and 43% at IMIX -- and, more usefully,
it turned a loss threshold that moved 40% between identical runs into
one that does not move. A measurement that will not repeat is not a
measurement, and the cause was here.

**The performance governor.** Same reasoning: ramping costs latency
at exactly the moment a burst arrives, and an appliance that is
sizing its own clocks against a load it is late to notice is trading
throughput for power it was not asked to save.

**RSS weighted toward the fast cores.** big.LITTLE plus a flat
indirection table feeds 1.8 GHz A55s exactly as hard as 2.4 GHz A76s,
so the little cores saturate while the big ones idle. Weighting the
table is worth 25-32%, confirmed independently on igb and on mlx5.

The weight is empirical, not derived. A 3:1 split beat everything
else tried on RK3588, which is steeper than the 1.33:1 clock ratio
because an A76 also retires far more per clock than an A55. So the
ratio is a parameter with a measured default rather than a
calculation dressed up as one, and this prints the queue-to-CPU map
it inferred so an operator can see whether it makes sense on their
board.

Two things this deliberately does NOT do.

It does not touch ring sizes. That is the obvious knob, it has been
tested twice -- 256 to 4096 on igb, 1024 to 8192 on mlx5 -- and it
did nothing either time. Buffering smooths jitter; it does not add
throughput.

It does not pin interrupts to the big cores. That was tried, and it
*halved* throughput: removing four of eight cores costs more than
feeding the slow ones costs. The fix is rebalancing, not excluding,
and the two are easy to confuse.

Costs, stated because they are real: no deep idle and a fixed
governor means the box burns a few watts more at rest and runs
warmer doing nothing. On a fanned appliance that is a fair trade for
a datapath that does not stutter. On a sealed fanless box, measure
before assuming.
"""

import argparse
import pathlib
import re
import subprocess
import sys

CPU_ROOT = pathlib.Path("/sys/devices/system/cpu")
NET_ROOT = pathlib.Path("/sys/class/net")

def read(path, default=None):
  """Text contents of a sysfs file, or `default` if it is not there."""
  try:
    return pathlib.Path(path).read_text().strip()
  except OSError:
    return default

def read_int(path, default=-1):
  """Integer contents of a sysfs file, or `default`."""
  value = read(path)
  try:
    return int(value)
  except (TypeError, ValueError):
    return default

def write(path, value):
  """Write to a sysfs file. Returns an error string, or None on success."""
  try:
    pathlib.Path(path).write_text(value)
    return None
  except OSError as exc:
    return str(exc)

class Report:
  """What was changed, what was already right, what could not be done.

  Kept as three lists rather than printed as it goes because the
  useful output of a tuning run is the summary: an operator wants to
  know whether the box is now in the state the performance numbers
  were measured in, not to read a log of sysfs writes.
  """

  def __init__(self):
    self.changed = []
    self.already = []
    self.skipped = []
    self.failed = []

  def emit(self):
    for line in self.changed:
      print(f"  set      {line}")
    for line in self.already:
      print(f"  ok       {line}")
    for line in self.skipped:
      print(f"  skip     {line}")
    for line in self.failed:
      print(f"  FAILED   {line}")
    print()
    if self.failed:
      print(f"{len(self.failed)} setting(s) could not be applied. The "
            "box is NOT in the state the published throughput figures "
            "were measured in.")
      return 1
    print("datapath tuning applied.")
    return 0

def cpu_ids():
  """Every present CPU, by number."""
  return sorted(int(e.name[3:]) for e in CPU_ROOT.glob("cpu[0-9]*")
                if e.name[3:].isdigit())

def tune_cpuidle(report, max_latency_us):
  """Disable idle states slower to leave than a packet can wait.

  Reported per state rather than per CPU -- eight cores times two
  states is sixteen lines saying one thing -- and the states left
  alone are reported too, because the threshold is a judgement call
  and the next person needs to see what it was applied to.
  """
  states = {}
  for cpu in cpu_ids():
    for state in sorted((CPU_ROOT / f"cpu{cpu}" / "cpuidle").glob(
        "state[0-9]*")):
      disable = state / "disable"
      if not disable.exists():
        continue
      name = read(state / "name", state.name)
      latency = read_int(state / "latency")
      key = (name, latency)
      states.setdefault(key, {"changed": 0, "already": 0, "failed": []})
      want = "1" if latency > max_latency_us else "0"
      if read(disable) == want:
        states[key]["already"] += 1
        continue
      err = write(disable, want)
      if err:
        states[key]["failed"].append(f"cpu{cpu}: {err}")
      else:
        states[key]["changed"] += 1

  if not states:
    report.skipped.append("cpuidle: no per-state disable control, "
                          "nothing to do")
    return

  for (name, latency), counts in sorted(states.items()):
    verdict = ("disabled" if latency > max_latency_us
               else f"left enabled, under {max_latency_us} us")
    label = f"idle state {name} ({latency} us exit) {verdict}"
    if counts["failed"]:
      report.failed.append(f'{label}: {counts["failed"][0]}')
    elif counts["changed"]:
      report.changed.append(f'{label} on {counts["changed"]} cpu(s)')
    else:
      report.already.append(f'{label} on {counts["already"]} cpu(s)')

def tune_governor(report, governor):
  """Pin every cpufreq policy to one governor."""
  policies = sorted((CPU_ROOT / "cpufreq").glob("policy*"))
  if not policies:
    report.skipped.append("cpufreq: no policies, nothing to do")
    return
  for policy in policies:
    available = read(policy / "scaling_available_governors", "")
    if governor not in (available or "").split():
      report.failed.append(
        f"{policy.name} governor: {governor} not available "
        f"(have: {available})")
      continue
    have = read(policy / "scaling_governor")
    if have == governor:
      report.already.append(f"{policy.name} governor {governor}")
      continue
    err = write(policy / "scaling_governor", governor)
    if err:
      report.failed.append(f"{policy.name} governor: {err}")
    else:
      report.changed.append(
        f"{policy.name} governor {have} -> {governor}")

def cpu_max_khz():
  """{cpu: its policy's maximum frequency in kHz}."""
  out = {}
  for cpu in cpu_ids():
    path = CPU_ROOT / f"cpu{cpu}" / "cpufreq" / "cpuinfo_max_freq"
    value = read_int(path)
    if value > 0:
      out[cpu] = value
  return out

def irq_names():
  """{irq number: the action name at the end of its /proc/interrupts row}."""
  out = {}
  try:
    lines = pathlib.Path("/proc/interrupts").read_text().splitlines()
  except OSError:
    return out
  for line in lines:
    head, _, rest = line.partition(":")
    head = head.strip()
    if not head.isdigit():
      continue
    out[int(head)] = rest.split()[-1] if rest.split() else ""
  return out

def queue_cpu_map(iface):
  """{rx queue index: cpu it is steered to}, or {} if it cannot be told.

  Interrupt names are driver-specific -- mlx5 says
  `mlx5_comp3@pci:0000:01:00.0` and igb says `enp1s0f3-TxRx-3` -- so
  the device's own msi_irqs list is the anchor and the queue index is
  the trailing number of the name. Returning {} rather than guessing
  is deliberate: a weight vector applied to the wrong queues is worse
  than no weight vector, and it would not look wrong anywhere.
  """
  irq_dir = NET_ROOT / iface / "device" / "msi_irqs"
  if not irq_dir.is_dir():
    return {}
  names = irq_names()
  out = {}
  for entry in irq_dir.iterdir():
    if not entry.name.isdigit():
      continue
    irq = int(entry.name)
    name = names.get(irq, "")
    # Completion/receive queues only. An async or command queue has
    # no packets on it and would shift every index if counted.
    if not re.search(r"(comp|TxRx|rx|Rx)", name):
      continue
    match = re.search(r'(\d+)(?:@|$)', name.split("@")[0])
    if not match:
      continue
    affinity = read(f"/proc/irq/{irq}/smp_affinity_list", "")
    # A queue pinned to a set of CPUs cannot be weighted meaningfully:
    # the whole premise is that one queue means one core.
    if not affinity or not affinity.isdigit():
      continue
    out[int(match.group(1))] = int(affinity)
  return out

def rx_ring_count(iface):
  """How many RX rings ethtool will expect weights for."""
  proc = subprocess.run(["ethtool", "-x", iface], capture_output=True,
                        text=True)
  match = re.search(r'with (\d+) RX ring', proc.stdout)
  return int(match.group(1)) if match else 0

def indirection_table(iface):
  """The current indirection table as a flat list of queue indices."""
  proc = subprocess.run(["ethtool", "-x", iface], capture_output=True,
                        text=True)
  out = []
  for line in proc.stdout.splitlines():
    head, _, rest = line.partition(":")
    if head.strip().isdigit():
      out.extend(int(x) for x in rest.split() if x.isdigit())
  return out

def candidate_ifaces():
  """Physical interfaces that are up and have more than one RX ring."""
  out = []
  for entry in sorted(NET_ROOT.iterdir()):
    if not (entry / "device").exists():
      continue
    if read(entry / "operstate") != "up":
      continue
    out.append(entry.name)
  return out

def tune_rss(report, iface, big_weight, little_weight):
  """Weight the RSS table toward the cores that are actually faster.

  Skips rather than guesses in every case where the premise does not
  hold: a machine whose cores are all the same speed has nothing to
  rebalance, and a driver that will not say which CPU serves which
  queue cannot be rebalanced correctly.
  """
  rings = rx_ring_count(iface)
  if rings < 2:
    report.skipped.append(f"{iface} RSS: {rings} RX ring(s), "
                          "nothing to spread")
    return

  maxima = cpu_max_khz()
  if not maxima or len(set(maxima.values())) < 2:
    report.skipped.append(
      f"{iface} RSS: all cores report the same maximum frequency, so "
      "there is no fast cluster to weight toward")
    return
  fastest = max(maxima.values())

  qmap = queue_cpu_map(iface)
  missing = [q for q in range(rings) if q not in qmap]
  if missing:
    report.skipped.append(
      f"{iface} RSS: cannot tell which CPU serves queue(s) "
      f'{",".join(str(q) for q in missing)} -- refusing to weight a '
      "map it had to guess")
    return

  weights, description = [], []
  for q in range(rings):
    cpu = qmap[q]
    big = maxima.get(cpu, 0) >= fastest
    weights.append(big_weight if big else little_weight)
    description.append(f"q{q}->cpu{cpu}"
                       f'{"(fast)" if big else "(slow)"}')

  if len(set(weights)) < 2:
    report.skipped.append(
      f"{iface} RSS: every queue lands on the same class of core, "
      "nothing to weight")
    return

  # Already weighted? Compare against what the table would look like,
  # by counting how many slots each queue holds.
  current = indirection_table(iface)
  if current:
    counts = [current.count(q) for q in range(rings)]
    total = sum(counts) or 1
    want = [w / float(sum(weights)) for w in weights]
    have = [c / float(total) for c in counts]
    if all(abs(a - b) < 0.02 for a, b in zip(want, have)):
      report.already.append(
        f'{iface} RSS weighted {":".join(str(w) for w in weights)} '
        f'({" ".join(description)})')
      return

  cmd = ["ethtool", "-X", iface, "weight"] + [str(w) for w in weights]
  proc = subprocess.run(cmd, capture_output=True, text=True)
  if proc.returncode != 0:
    report.failed.append(
      f"{iface} RSS: {(proc.stderr or proc.stdout).strip()[:160]}")
    return

  # Read it back. `ethtool -X` can return 0 having done nothing the
  # driver disagreed with.
  after = indirection_table(iface)
  counts = [after.count(q) for q in range(rings)]
  if counts and max(counts) == min(counts):
    report.failed.append(
      f"{iface} RSS: ethtool accepted the weights and the table came "
      "back flat")
    return
  report.changed.append(
    f'{iface} RSS weight {" ".join(str(w) for w in weights)} '
    f'({" ".join(description)})')

def main():
  ap = argparse.ArgumentParser(
    description="Apply the datapath tuning the throughput figures "
                "were measured with.")
  ap.add_argument("interfaces", nargs="*",
                  help="interfaces to weight; default is every "
                       "physical interface that is up")
  ap.add_argument("--max-idle-latency-us", type=int, default=50,
                  help="disable idle states slower to exit than this. "
                       "RK3588 cpu-sleep is 220 us, which is 300 "
                       "frames at 1.4 Mpps.")
  ap.add_argument("--governor", default="performance")
  ap.add_argument("--big-weight", type=int, default=3,
                  help="RSS weight for queues served by a core at the "
                       "highest available clock. Measured, not "
                       "derived: 3:1 beat everything else on RK3588, "
                       "where the clock ratio alone is 1.33:1.")
  ap.add_argument("--little-weight", type=int, default=1)
  ap.add_argument("--no-cpuidle", action="store_true",
                  help="leave idle states alone")
  ap.add_argument("--no-governor", action="store_true",
                  help="leave the governor alone")
  ap.add_argument("--no-rss", action="store_true",
                  help="leave the indirection tables alone")
  args = ap.parse_args()

  report = Report()
  if not args.no_cpuidle:
    tune_cpuidle(report, args.max_idle_latency_us)
  if not args.no_governor:
    tune_governor(report, args.governor)
  if not args.no_rss:
    for iface in (args.interfaces or candidate_ifaces()):
      tune_rss(report, iface, args.big_weight, args.little_weight)
  return report.emit()

if __name__ == "__main__":
  sys.exit(main())
