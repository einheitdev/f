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
import shutil
import time
import subprocess
import sys
import yaml

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
  """Every physical interface, up or not.

  Deliberately does NOT require the link to be up. This unit runs
  before fd, which runs before network.target, so on a cold boot the
  interfaces it has to weight are still administratively down -- and
  an earlier version that filtered on `operstate == up` silently
  weighted nothing on every reboot while reporting success. mlx5
  accepts `ethtool -X` on a closed interface and keeps the table
  across the open, which is what makes the ordering work at all.
  """
  return sorted(entry.name for entry in NET_ROOT.iterdir()
                if (entry / "device").exists())

# The three postures, worst-to-best for throughput and best-to-worst
# for isolation, with the kernel parameter that selects each and the
# group type it produces. Measured forwarding IMIX on RK3588, RFC 2544
# at 0.01% loss, from a cold boot in each mode:
#
#   strict       1,392,633 pps   42.5% of 10 GbE line
#   lazy         2,495,233 pps   76.2%
#   passthrough  3,230,294 pps   98.7%
#
# The gap is not tuning noise. XDP_REDIRECT DMA-maps a frame on the
# transmit device and unmaps it on completion, per packet, and strict
# mode makes every unmap wait for an SMMU invalidation -- 37% of the
# big cores on this board, in one function.
IOMMU_MODES = {
  "strict": {
    "group_type": "DMA",
    "cmdline": None,
    "why": "kernel default. Every DMA unmap waits for an SMMU "
           "invalidation, which on this workload is half the machine.",
  },
  "lazy": {
    "group_type": "DMA-FQ",
    "cmdline": "iommu.strict=0",
    "why": "translation and isolation stay; invalidation is batched. "
           "A just-unmapped buffer is reachable by the device for a "
           "short window, and nothing else is.",
  },
  "passthrough": {
    "group_type": "identity",
    "cmdline": "iommu.passthrough=1",
    "why": "no translation at all. The device addresses physical "
           "memory directly. Fastest, and the only mode that gives up "
           "DMA isolation outright.",
  },
}

def iommu_mode(iface):
  """How the SMMU is translating DMA for this interface, or None.

  "DMA" is strict mode, the kernel default: every DMA unmap issues an
  SMMU TLB invalidation and waits for it. XDP_REDIRECT maps and
  unmaps a buffer on the transmit device for **every forwarded
  packet**, so strict mode puts a synchronous IOMMU command round
  trip in the datapath's inner loop. On the rig it was 37% of the big
  cores in `arm_smmu_cmdq_issue_cmdlist` alone, and turning it off
  doubled forwarding throughput.

  It also explains a difference that looked like a hardware property:
  dropping was 2.4x cheaper than forwarding, because dropping never
  maps anything for transmit. After this was fixed the two came out
  within 20% of each other.
  """
  group = NET_ROOT / iface / "device" / "iommu_group"
  if not group.exists():
    return None
  return read(group.resolve() / "type")

def mode_of_group_type(group_type):
  """Reverse IOMMU_MODES: a group type back to the mode that made it."""
  for name, spec in IOMMU_MODES.items():
    if spec["group_type"] == group_type:
      return name
  return None

def swap_total_kb():
  """Swap configured on this box, in kB. 0 if none, -1 if unreadable."""
  try:
    for line in pathlib.Path("/proc/meminfo").read_text().splitlines():
      if line.startswith("SwapTotal:"):
        return int(line.split()[1])
  except (OSError, ValueError, IndexError):
    return -1
  return 0

def check_swap(report, total=None):
  """Report swap, because here it turns a clean failure into a wedge.

  Measured: `fwl compile` on an over-large policy drove a 4 GB board
  into 1.8 GB of zram and pinned every core compressing, with nothing
  scheduled and no OOM kill. The box answered ping and nothing else
  until it was power-cycled. Without swap the same compile is an
  ordinary OOM -- clang is killed, `fwl` returns an error, `fd`
  refuses the bundle, and the datapath keeps running.

  An appliance whose daemon has an 8 MB resident set has nothing worth
  swapping. What swap buys here is the ability to fail slowly rather
  than quickly, and on a remote box slow failure is the worse one.

  Advisory rather than applied: `swapoff` on a running box is
  disruptive, and the right place to not have swap is the image.
  """
  if total is None:
    total = swap_total_kb()
  if total < 0:
    return
  if total == 0:
    report.already.append("swap: none, so memory pressure fails fast")
    return
  report.failed.append(
    f"swap is enabled ({total // 1024} MB). Here that converts an "
    "over-large compile from an OOM kill into an unrecoverable "
    "thrash -- every core compressing, nothing scheduled, no OOM "
    "kill, and only a power cycle or the watchdog gets it back. "
    "Disable it in the image.")

def check_iommu(report, ifaces, want):
  """Compare the running SMMU posture against the one asked for.

  Report-only, and deliberately so. `iommu.strict` and
  `iommu.passthrough` are kernel command-line parameters, so applying
  one means editing a bootloader configuration and rebooting --
  which is not something a unit that runs on every boot should do by
  itself. `--apply-boot` is the explicit operator action; this is the
  thing that tells them it is needed.
  """
  seen = {}
  for iface in ifaces:
    group_type = iommu_mode(iface)
    if group_type is None:
      continue
    seen[iface] = mode_of_group_type(group_type) or group_type
  if not seen:
    report.skipped.append(
      "SMMU: no IOMMU in the path for any interface, nothing to "
      "choose")
    return
  wrong = sorted(i for i, mode in seen.items() if mode != want)
  if not wrong:
    report.already.append(
      f"SMMU {want} for {', '.join(sorted(seen))} "
      f"({IOMMU_MODES[want]['group_type']})")
    return
  have = ", ".join(f"{i}={seen[i]}" for i in wrong)
  cmdline = IOMMU_MODES[want]["cmdline"] or "(no parameter; the default)"
  report.failed.append(
    f"SMMU is {have}, configured for {want}. Needs {cmdline} on the "
    f"kernel command line and a reboot: run `f-datapath-tune "
    f"--apply-boot`. Until then this box forwards at "
    f"{'about half' if 'strict' in seen.values() else 'a different'} "
    f"speed to its datasheet.")

# Where each platform keeps the kernel command line, and the variable
# on which the parameters live. Only bootloaders we have actually
# written to are listed: guessing at one and being wrong does not
# produce an error message, it produces a box that does not boot.
BOOT_CONFIGS = (
  ("/boot/armbianEnv.txt", "extraargs", "armbian"),
  ("/etc/default/grub", "GRUB_CMDLINE_LINUX_DEFAULT", "grub"),
)

def find_boot_config():
  """(path, variable, flavour) for this box, or None."""
  for path, var, flavour in BOOT_CONFIGS:
    if pathlib.Path(path).exists():
      return path, var, flavour
  return None

def apply_boot(want, dry_run=False):
  """Put the mode's kernel parameter on the command line.

  Backs the file up first, edits exactly one line, removes any
  parameter belonging to a *different* mode so the two cannot both be
  present, and reads the result back. Prints what to do next rather
  than rebooting: a tool that reboots a firewall because a config
  value changed is a tool that reboots a firewall.
  """
  found = find_boot_config()
  if not found:
    print("cannot apply: no bootloader configuration recognised. "
          "Looked for " + ", ".join(p for p, _, _ in BOOT_CONFIGS) +
          ". Add the parameter by hand:")
    manual = (IOMMU_MODES[want]["cmdline"]
              or "(remove both iommu.* parameters)")
    print(f"  {manual}")
    return 1
  path, var, flavour = found
  wanted = IOMMU_MODES[want]["cmdline"]
  others = [spec["cmdline"] for name, spec in IOMMU_MODES.items()
            if name != want and spec["cmdline"]]

  lines = pathlib.Path(path).read_text().splitlines()
  out, touched = [], False
  for line in lines:
    stripped = line.strip()
    if not stripped.startswith(f"{var}="):
      out.append(line)
      continue
    head, _, value = stripped.partition("=")
    # grub quotes its value; armbian does not.
    quote = ""
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
      quote, value = value[0], value[1:-1]
    params = [p for p in value.split() if p not in others]
    if wanted and wanted not in params:
      params.append(wanted)
    out.append(f"{head}={quote}{' '.join(params)}{quote}")
    touched = True
  if not touched:
    quote = '"' if flavour == "grub" else ""
    out.append(f"{var}={quote}{wanted or ''}{quote}")

  new = "\n".join(out) + "\n"
  if dry_run:
    print(f"would write {path}:")
    for line in out:
      if line.strip().startswith(f"{var}="):
        print(f"  {line}")
    return 0

  backup = f"{path}.bak-f-datapath"
  shutil.copy2(path, backup)
  pathlib.Path(path).write_text(new)
  after = [ln for ln in pathlib.Path(path).read_text().splitlines()
           if ln.strip().startswith(f"{var}=")]
  if wanted and not any(wanted in ln for ln in after):
    shutil.copy2(backup, path)
    print(f"write to {path} did not take; restored from {backup}")
    return 1
  print(f"{path} updated (backup at {backup}):")
  for line in after:
    print(f"  {line}")
  if flavour == "grub":
    rc = subprocess.run(["update-grub"], capture_output=True,
                        text=True).returncode
    if rc != 0:
      print("update-grub failed; the box will boot the OLD command "
            "line until it succeeds")
      return 1
    print("  update-grub ok")
  print(f"\nreboot to take effect. Mode after reboot: {want} "
        f"({IOMMU_MODES[want]['why']})")
  return 0

def wait_for_queue_map(iface, rings, seconds):
  """Wait for the driver to publish a queue-to-CPU map, or give up.

  This unit runs early -- before fd, which runs before network.target
  -- and on a cold boot that is early enough to lose a race twice
  over. Measured on the rig: when it ran, the mlx5 ports were still
  named `eth0` because udev had not renamed them yet, and their
  completion-queue interrupts did not exist, so the map could not be
  resolved and the weighting was skipped. The box then ran at about
  three quarters of its measured capability until somebody noticed,
  which took a day.

  Ordering directives do not fix this: the interfaces are not a unit
  to be ordered after, and udev-settle is deprecated and would not
  wait for interrupts anyway. Waiting for the thing actually needed is
  the honest version, and it costs nothing where the map already
  exists.
  """
  deadline = time.monotonic() + seconds
  while True:
    qmap = queue_cpu_map(iface)
    if all(q in qmap for q in range(rings)):
      return qmap
    if time.monotonic() >= deadline:
      return qmap
    time.sleep(0.5)

def tune_rss(report, iface, big_weight, little_weight, wait_s=0):
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

  qmap = wait_for_queue_map(iface, rings, wait_s)
  missing = [q for q in range(rings) if q not in qmap]
  if missing:
    # A FAILURE, not a skip. A NIC with several receive queues is one
    # the weighting was meant for, and leaving it flat costs 25-32% on
    # big.LITTLE. A skip line inside a report that ends "datapath
    # tuning applied" is how this box spent a day at three quarters of
    # its capability with nothing saying so.
    report.failed.append(
      f"{iface} RSS: {rings} RX rings but cannot tell which CPU "
      f"serves queue(s) "
      f'{",".join(str(q) for q in missing)} after waiting {wait_s}s '
      "-- refusing to weight a map it had to guess. This interface is "
      "running an unweighted table.")
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

CONFIG_PATH = "/etc/f/datapath.yaml"

DEFAULTS = {
  # Isolation posture. See IOMMU_MODES for what each costs and buys.
  # `lazy` rather than `passthrough` is the default on purpose: it
  # recovers most of the throughput without an appliance giving up
  # DMA isolation by inheriting a value nobody chose. Boxes that want
  # the rest have to say so.
  "iommu": "lazy",
  "governor": "performance",
  "max_idle_latency_us": 50,
  "rss_big_weight": 3,
  "rss_little_weight": 1,
  "interfaces": [],
}

def load_config(path):
  """Merge `path` over the defaults. A missing file is not an error.

  Returns (settings, note) where note is a line for the report -- the
  operator should be able to see which posture is in force and where
  it came from without going and looking.
  """
  settings = dict(DEFAULTS)
  file = pathlib.Path(path)
  if not file.exists():
    return settings, f"config: {path} absent, using defaults"
  try:
    loaded = yaml.safe_load(file.read_text()) or {}
  except yaml.YAMLError as exc:
    return settings, f"config: {path} is not valid YAML ({exc}); " \
                     "using defaults"
  if not isinstance(loaded, dict):
    return settings, f"config: {path} is not a mapping; using defaults"
  unknown = sorted(set(loaded) - set(DEFAULTS))
  settings.update({k: v for k, v in loaded.items() if k in DEFAULTS})
  note = f"config: {path}"
  if unknown:
    note += f" (ignored unknown key(s): {', '.join(unknown)})"
  return settings, note

def main():
  ap = argparse.ArgumentParser(
    description="Apply the datapath tuning the throughput figures "
                "were measured with, and report the parts of it that "
                "only a reboot can change.")
  ap.add_argument("interfaces", nargs="*",
                  help="interfaces to weight; default is every "
                       "physical interface")
  ap.add_argument("--config", default=CONFIG_PATH,
                  help=f"settings file (default {CONFIG_PATH}). "
                       "Absent is fine; the defaults are the shipped "
                       "posture.")
  ap.add_argument("--iommu", choices=sorted(IOMMU_MODES),
                  help="override the configured isolation posture. "
                       "strict is the kernel default and about half "
                       "the speed; lazy keeps DMA isolation and "
                       "recovers most of it; passthrough gives up "
                       "isolation for the rest.")
  ap.add_argument("--apply-boot", action="store_true",
                  help="write the chosen posture's kernel parameter "
                       "to this box's bootloader configuration and "
                       "stop. Takes effect on the next boot; does "
                       "not reboot anything.")
  ap.add_argument("--dry-run", action="store_true",
                  help="with --apply-boot, show the line that would "
                       "be written and change nothing")
  ap.add_argument("--max-idle-latency-us", type=int,
                  help="disable idle states slower to exit than this. "
                       "RK3588 cpu-sleep is 220 us, which is 300 "
                       "frames at 1.4 Mpps.")
  ap.add_argument("--governor")
  ap.add_argument("--big-weight", type=int,
                  help="RSS weight for queues served by a core at the "
                       "highest available clock. Measured, not "
                       "derived: 3:1 beat everything else on RK3588, "
                       "where the clock ratio alone is 1.33:1.")
  ap.add_argument("--little-weight", type=int)
  ap.add_argument("--no-cpuidle", action="store_true",
                  help="leave idle states alone")
  ap.add_argument("--no-governor", action="store_true",
                  help="leave the governor alone")
  ap.add_argument("--queue-map-wait", type=int, default=30,
                  help="seconds to wait for a NIC to publish its "
                       "queue-to-CPU map. This unit runs before "
                       "network.target, which on a cold boot is "
                       "before udev has renamed the interfaces and "
                       "before the driver's completion-queue "
                       "interrupts exist.")
  ap.add_argument("--no-rss", action="store_true",
                  help="leave the indirection tables alone")
  args = ap.parse_args()

  settings, note = load_config(args.config)
  for key, value in (("iommu", args.iommu),
                     ("governor", args.governor),
                     ("max_idle_latency_us", args.max_idle_latency_us),
                     ("rss_big_weight", args.big_weight),
                     ("rss_little_weight", args.little_weight),
                     ("interfaces", args.interfaces or None)):
    if value is not None:
      settings[key] = value
      note += f", {key} overridden on the command line"
  if settings["iommu"] not in IOMMU_MODES:
    sys.exit(f"unknown iommu mode {settings['iommu']!r}; expected one "
             f"of {', '.join(sorted(IOMMU_MODES))}")

  if args.apply_boot:
    return apply_boot(settings["iommu"], args.dry_run)

  report = Report()
  report.already.append(note)
  if not args.no_cpuidle:
    tune_cpuidle(report, settings["max_idle_latency_us"])
  if not args.no_governor:
    tune_governor(report, settings["governor"])
  ifaces = settings["interfaces"] or candidate_ifaces()
  check_swap(report)
  check_iommu(report, ifaces, settings["iommu"])
  if not args.no_rss:
    # A run that examined no interface at all is not a clean run. The
    # first version filtered them out and still printed "tuning
    # applied", so every reboot came up with a flat indirection table
    # and nothing said so.
    if not ifaces:
      report.failed.append(
        "RSS: no physical interface found to examine. Either this "
        "box has none, or this ran before the drivers were bound.")
    for iface in ifaces:
      tune_rss(report, iface, settings["rss_big_weight"],
               settings["rss_little_weight"], args.queue_map_wait)
  return report.emit()

if __name__ == "__main__":
  sys.exit(main())
