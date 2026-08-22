#!/usr/bin/env python3
"""Sample everything measurable on the DUT, on the DUT.

Runs for a fixed duration and prints one JSON object per sample to
stdout. Meant to be launched over ssh by `l13_01_policy_cost_ladder.py`
and parsed by it.

It exists because the ladder's first real run reported 2.16 Mpps
arriving on a 1 GbE port, whose 64-byte ceiling is 1.488 Mpps. The
cause was that every counter was read over its own ssh round trip while
the rate was computed against the *nominal* duration, so seconds of
network latency landed inside a measurement that assumed none. Reading
on the box, against real timestamps, removes both errors -- and makes
sub-second sampling affordable, which a round trip per sample never was.

Sampled per tick:

  * every hwmon temperature the board exposes -- SoC package, both A76
    clusters, the A55 cluster, centre, GPU, NPU, and the i350 die
  * per-policy CPU frequency, so thermal throttling is visible as
    itself rather than as an expensive policy
  * per-CPU jiffies, so the softirq load XDP runs in can be seen per
    core rather than averaged into meaninglessness
  * the receiving NIC's own counters, including the drop and miss
    counters that say whether the loss happened before the datapath
    ever saw the packet
  * fd's RSS, because a datapath that leaks under load is a different
    finding from one that is merely slow
"""

import json
import pathlib
import sys
import time

def read(path, default=''):
  try:
    return pathlib.Path(path).read_text().strip()
  except OSError:
    return default

def read_int(path):
  try:
    return int(read(path, '-1'))
  except ValueError:
    return -1

def hwmon_map():
  """{sensor name: temp1_input path} for every hwmon that has one."""
  out = {}
  base = pathlib.Path('/sys/class/hwmon')
  if not base.is_dir():
    return out
  for entry in sorted(base.iterdir()):
    name = read(entry / 'name')
    temp = entry / 'temp1_input'
    if name and temp.exists():
      out[name] = str(temp)
  return out

def freq_map():
  """{policy: (cur_path, max_khz)} for every cpufreq policy."""
  out = {}
  base = pathlib.Path('/sys/devices/system/cpu/cpufreq')
  if not base.is_dir():
    return out
  for p in sorted(base.glob('policy*')):
    mx = read_int(p / 'cpuinfo_max_freq')
    if mx > 0:
      out[p.name] = (str(p / 'scaling_cur_freq'), mx)
  return out

def cpu_jiffies():
  """{cpuN: [jiffies...]} from /proc/stat, per core only."""
  out = {}
  for line in read('/proc/stat').splitlines():
    if line.startswith('cpu') and not line.startswith('cpu '):
      parts = line.split()
      out[parts[0]] = [int(x) for x in parts[1:]]
  return out

def nic_stats(iface):
  """The receiving NIC's counters that bear on a loss measurement."""
  base = f'/sys/class/net/{iface}/statistics'
  keys = ('rx_packets', 'rx_bytes', 'rx_dropped', 'rx_errors',
          'rx_missed_errors', 'rx_over_errors', 'rx_fifo_errors',
          'tx_packets')
  return {k: read_int(f'{base}/{k}') for k in keys}

def fd_rss_kb():
  """Resident set of the fd process, or -1 if it is not running."""
  for p in pathlib.Path('/proc').iterdir():
    if not p.name.isdigit():
      continue
    if read(p / 'comm') != 'fd':
      continue
    for line in read(p / 'status').splitlines():
      if line.startswith('VmRSS:'):
        return int(line.split()[1])
  return -1

def softirq_total():
  """Total NET_RX softirqs, the count XDP work is dispatched under."""
  for line in read('/proc/softirqs').splitlines():
    if 'NET_RX' in line:
      return sum(int(x) for x in line.split()[1:])
  return -1

def main():
  if len(sys.argv) < 3:
    sys.exit('usage: l13_sampler.py <seconds> <iface> [interval]')
  seconds = float(sys.argv[1])
  iface = sys.argv[2]
  interval = float(sys.argv[3]) if len(sys.argv) > 3 else 0.5

  temps = hwmon_map()
  freqs = freq_map()
  deadline = time.monotonic() + seconds
  while True:
    now = time.monotonic()
    sample = {
      # monotonic, so a clock step mid-run cannot invent or erase time
      't': now,
      'temps_mC': {n: read_int(p) for n, p in temps.items()},
      'freq_khz': {n: read_int(p) for n, (p, _) in freqs.items()},
      'freq_max_khz': {n: mx for n, (_, mx) in freqs.items()},
      'cpu': cpu_jiffies(),
      'nic': nic_stats(iface),
      'fd_rss_kb': fd_rss_kb(),
      'net_rx_softirq': softirq_total(),
    }
    print(json.dumps(sample), flush=True)
    if now >= deadline:
      break
    time.sleep(interval)

if __name__ == '__main__':
  main()
