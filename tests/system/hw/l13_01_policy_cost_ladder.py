#!/usr/bin/env python3
"""Where the SoC gives out, and what each language construct costs.

Two questions, one rig run:

  * how many packets per second can this box actually push through an
    XDP policy, and
  * what does each construct cost, in nanoseconds of CPU per packet?

The second is the one worth having. A single throughput number ages
badly and says nothing about a policy nobody has written yet; a *cost
per construct* lets you predict one. So the same offered load runs
against a ladder of policies that differ by one construct at a time,
and the difference between two rungs is that construct's price.

  0  attach only, `default allow`  — the floor: parse prelude, nothing else
  1  + a 5-tuple match             — field reads and comparisons
  2  + conntrack lookup            — a hash probe per packet
  3  + masquerade                  — NAT rewrite and its table
  4  + geoip                       — an LPM trie probe
  5  + rate_limit                  — a per-CPU map read/modify/write

## What this measures, and what it does not

The generator runs on the box under test. There is no second machine on
this bench, so generator and datapath compete for the same CPUs, and
every number here is therefore a **lower bound** on what the datapath
could do if fed from outside. That is stated in the report rather than
buried: a lower bound is a real answer as long as nobody quotes it as a
ceiling.

Two things make the bound tight enough to be useful. pktgen runs in
kernel threads that are pinned to CPUs the datapath's receive queues
are pinned away from, so the two are not fighting over the same core.
And the report prints per-CPU softirq time next to the packet rate, so
a run where the *generator* saturated first is visible as such instead
of being read as the datapath's limit.

If the ladder's rungs all land at the same rate, that is the signature
of a generator-bound run, and the answer is a second machine rather
than a bigger number.

## Why pktgen

`sendmany.py`, which every other test here uses, does one `send()` per
frame. That is right for a test that sends a thousand frames and checks
a verdict, and hopeless for one that needs millions: on ARM it tops out
far below the line rate the i350 can carry, so it would measure itself.

pktgen builds and transmits inside the kernel, is in mainline, needs no
package, and can be pinned per thread. It is the standard instrument
for exactly this measurement.
"""

import argparse
import json
import os
import pathlib
import re
import shlex
import shutil
import subprocess
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
PKTGEN = pathlib.Path('/proc/net/pktgen')

# The ladder. Each rung adds exactly one construct to the one above it,
# so a difference between adjacent rungs is attributable. `wan` is the
# receiving port; traffic is generated onto it from this same box.
LADDER = [
  ('floor', 'attach only — parse prelude and a default verdict', '''
zone wan = [{recv}]

@xdp(wan)

default allow
'''),
  ('match', 'a 5-tuple match', '''
zone wan = [{recv}]

@xdp(wan)

count seen if pkt.proto == udp and pkt.dst_port == 9000
default allow
'''),
  ('conntrack', 'a conntrack state lookup per packet', '''
zone wan = [{recv}]

@xdp(wan)

count seen if pkt.proto == udp and pkt.dst_port == 9000
allow if conntrack(pkt).state == established
default allow
'''),
  ('nat', 'masquerade — NAT rewrite and its table', '''
zone wan = [{recv}]
zone lan = [{send}]

@xdp(wan)

count seen if pkt.proto == udp and pkt.dst_port == 9000
allow if conntrack(pkt).state == established
default allow

@xdp(lan)

masquerade
default allow
'''),
  # Needs --geoip data at compile time; the rung is skipped rather
  # than silently dropped when none is supplied. See --geoip-data.
  ('geoip', 'an LPM trie probe', '''
zone wan = [{recv}]

@xdp(wan)

count seen if pkt.proto == udp and pkt.dst_port == 9000
drop if pkt.src_ip in geoip(RU, CN, KP)
allow if conntrack(pkt).state == established
default allow
'''),
  ('rate_limit', 'a per-CPU bucket read/modify/write', '''
zone wan = [{recv}]

@xdp(wan)

count seen if pkt.proto == udp and pkt.dst_port == 9000
drop if pkt.proto == udp limited by rate_limit(4000000, per=src_ip)
allow if conntrack(pkt).state == established
default allow
'''),
]

def run(cmd, **kw):
  """Run a command, returning CompletedProcess. Never raises on rc."""
  return subprocess.run(cmd, shell=isinstance(cmd, str),
                        capture_output=True, text=True, **kw)


def root_sh(script):
  """Run a shell snippet as root, elevating only if we are not already.

  The script itself must NOT be run under sudo: local pktgen needs
  root, but reaching the DUT needs the invoking user's ssh config and
  agent, and root has neither. So privilege is taken here, for the
  pktgen writes alone, and everything else stays as the user.
  """
  if os.geteuid() == 0:
    return run(['sh', '-c', script])
  return run(['sudo', '-n', 'sh', '-c', script])

def die(msg):
  print(f'FAIL: {msg}', file=sys.stderr)
  sys.exit(1)

class Host:
  """The box under test, local or reached over ssh.

  The generator and the DUT are different machines, and which one runs
  this script is decided by which direction ssh actually works. On this
  bench that is workstation -> rig, so the script runs on the generator
  and drives the DUT remotely. Everything the DUT side does goes
  through here rather than calling subprocess directly, so the two
  cases cannot drift.
  """

  def __init__(self, ssh_target=None):
    self.ssh_target = ssh_target

  @property
  def name(self):
    return self.ssh_target or 'localhost'

  def run(self, argv, input=None):
    """Run a command on the host."""
    if self.ssh_target is None:
      return run(argv, input=input)
    quoted = ' '.join(shlex.quote(a) for a in argv)
    return run(['ssh', '-o', 'BatchMode=yes', self.ssh_target, quoted],
               input=input)

  def read_text(self, path):
    """Read a file on the host, or '' if unreadable."""
    if self.ssh_target is None:
      try:
        return pathlib.Path(path).read_text()
      except OSError:
        return ''
    r = self.run(['cat', path])
    return r.stdout if r.returncode == 0 else ''

  def read_int(self, path):
    try:
      return int(self.read_text(path).strip())
    except ValueError:
      return -1

  def write_text(self, path, content):
    """Write a file on the host."""
    if self.ssh_target is None:
      pathlib.Path(path).parent.mkdir(parents=True, exist_ok=True)
      pathlib.Path(path).write_text(content)
      return True
    r = self.run(['sh', '-c', f'mkdir -p $(dirname {shlex.quote(path)}) '
                              f'&& cat > {shlex.quote(path)}'],
                 input=content)
    return r.returncode == 0

  def reachable(self):
    return self.run(['true']).returncode == 0


def read_int(path):
  """Read an integer from a sysfs file, or -1."""
  try:
    return int(pathlib.Path(path).read_text().strip())
  except (OSError, ValueError):
    return -1

def hwmon_by_name(host, want):
  """Find /sys/class/hwmon/*/temp1_input for a named sensor.

  Same lookup gwsoak.py uses, so the two report the same numbers from
  the same places rather than two guesses about where a sensor lives.
  """
  base = '/sys/class/hwmon'
  listing = host.run(['ls', base])
  if listing.returncode != 0:
    return None
  for entry in listing.stdout.split():
    name_path = os.path.join(base, entry, 'name')
    if host.read_text(name_path).strip() == want:
      return os.path.join(base, entry, 'temp1_input')
  return None

def cpu_times(host):
  """Per-CPU jiffy counters from /proc/stat, keyed by cpu name."""
  out = {}
  for line in host.read_text('/proc/stat').splitlines():
    if not line.startswith('cpu') or line.startswith('cpu '):
      continue
    parts = line.split()
    out[parts[0]] = [int(x) for x in parts[1:]]
  return out

def cpu_busy_delta(before, after):
  """Return {cpu: (softirq_frac, busy_frac)} between two samples.

  softirq is the interesting column: XDP runs there, and so does
  pktgen's transmit path, so a run where the two are on the same core
  is visible rather than inferred.
  """
  out = {}
  for cpu, a in after.items():
    b = before.get(cpu)
    if not b:
      continue
    delta = [x - y for x, y in zip(a, b)]
    total = sum(delta)
    if total <= 0:
      continue
    idle = delta[3] + delta[4]
    softirq = delta[6] if len(delta) > 6 else 0
    out[cpu] = (softirq / total, (total - idle) / total)
  return out

class Pktgen:
  """Drive kernel pktgen threads bound to specific CPUs."""

  def __init__(self, iface, cpus, dst_mac, dst_ip, pkt_size, clone=0,
               pps=0):
    self.pps = pps
    self.iface = iface
    self.cpus = cpus
    self.dst_mac = dst_mac
    self.dst_ip = dst_ip
    self.pkt_size = pkt_size
    self.clone = clone
    self.devices = []

  @staticmethod
  def available():
    if PKTGEN.exists():
      return True
    root_sh('modprobe pktgen')
    return PKTGEN.exists()

  def _write(self, path, value):
    r = root_sh(f'echo {shlex.quote(value)} > {shlex.quote(path)}')
    if r.returncode != 0:
      print(f'  pktgen write failed {path}: {r.stderr.strip()[:160]}',
            file=sys.stderr)
      return False
    return True

  def configure(self, count=0):
    """Bind one pktgen device per CPU. count=0 means run until stopped."""
    self._write(str(PKTGEN / 'pgctrl'), 'reset')
    self.devices = []
    for cpu in self.cpus:
      thread = PKTGEN / f'kpktgend_{cpu}'
      if not thread.exists():
        print(f'  no pktgen thread for cpu {cpu}; skipping it')
        continue
      # One device alias per thread so several threads can drive one
      # NIC. The @ suffix is pktgen's own naming for that.
      dev = f'{self.iface}@{cpu}'
      self._write(str(thread), f'add_device {dev}')
      d = str(PKTGEN / dev)
      for line in (
        f'count {count}',
        f'clone_skb {self.clone}',
        f'pkt_size {self.pkt_size}',
        'delay 0',
        f'dst_mac {self.dst_mac}',
        f'dst {self.dst_ip}',
        'udp_src_min 1024',
        'udp_src_max 65000',
        'udp_dst_min 9000',
        'udp_dst_max 9000',
        # A spread of sources: a single source IP would make every
        # packet hit one conntrack entry and one rate-limit bucket,
        # which measures a cache-friendly best case rather than a
        # policy under real load.
        'flag IPSRC_RND',
        'src_min 10.60.0.1',
        'src_max 10.60.255.254',
      ) + ((f'ratep {self.pps}',) if self.pps else ()):
        self._write(d, line)
      self.devices.append(d)
    return bool(self.devices)

  def start_background(self):
    """Start transmitting. Returns the Popen; pgctrl blocks while running."""
    cmd = f'echo start > {PKTGEN / "pgctrl"}'
    argv = (['sh', '-c', cmd] if os.geteuid() == 0
            else ['sudo', '-n', 'sh', '-c', cmd])
    return subprocess.Popen(argv, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)

  def stop(self):
    self._write(str(PKTGEN / 'pgctrl'), 'stop')

  def sent(self):
    """Total packets pktgen reports having transmitted."""
    total = 0
    for d in self.devices:
      text = root_sh(f'cat {shlex.quote(d)}').stdout
      m = re.search(r'^\s*pkts-sofar:\s*(\d+)', text, re.M)
      if m:
        total += int(m.group(1))
    return total

  def cleanup(self):
    self.stop()
    self._write(str(PKTGEN / 'pgctrl'), 'reset')

class RemotePktgen:
  """pktgen on another machine, driven over ssh.

  This is the configuration that makes the measurement mean something.
  With the generator on the box under test, the two compete for CPU and
  every reading is a lower bound. With the generator on a workstation
  feeding the switch, the DUT does nothing but receive, and the number
  is the datapath's own.

  Sizing: the i350 is four 1 GbE ports, so line rate at 64-byte frames
  is 4 x 1.488 = 5.95 Mpps. That is the figure to think in, not 4 Gbit
  -- XDP costs are per packet, and a 64-byte flood is 24 times the
  packet rate of a 1500-byte one at the same bandwidth. An x86 box with
  pktgen clears 5.95 Mpps across a few threads without difficulty, so
  the generator should outrun the DUT, which is the point.

  A 10 GbE source into 1 GbE ports means the SWITCH drops the excess,
  and then the ladder measures the EX2300's egress queue rather than
  the firewall. Pace the generator at or just above per-port line rate
  instead of blasting, and read `offered` from the far side rather than
  assuming it.
  """

  def __init__(self, host, iface, cpus, dst_mac, dst_ip, pkt_size,
               ssh='ssh', pps=0):
    self.pps = pps
    self.host = host
    self.ssh = ssh
    self.iface = iface
    self.cpus = cpus
    self.dst_mac = dst_mac
    self.dst_ip = dst_ip
    self.pkt_size = pkt_size
    self.devices = []

  def _remote(self, script):
    return run([self.ssh, '-o', 'BatchMode=yes', self.host,
                'sudo sh -s'], input=script)

  def available(self):
    r = self._remote('modprobe pktgen 2>/dev/null; '
                     'test -d /proc/net/pktgen && echo yes')
    return 'yes' in r.stdout

  def configure(self, count=0):
    lines = ['set -e', 'echo reset > /proc/net/pktgen/pgctrl']
    self.devices = []
    for cpu in self.cpus:
      dev = f'{self.iface}@{cpu}'
      d = f'/proc/net/pktgen/{dev}'
      lines.append(f'echo "add_device {dev}" > '
                   f'/proc/net/pktgen/kpktgend_{cpu}')
      for setting in (
        f'count {count}', 'clone_skb 0', f'pkt_size {self.pkt_size}',
        'delay 0', f'dst_mac {self.dst_mac}', f'dst {self.dst_ip}',
        'udp_src_min 1024', 'udp_src_max 65000',
        'udp_dst_min 9000', 'udp_dst_max 9000',
        'flag IPSRC_RND', 'src_min 10.60.0.1', 'src_max 10.60.255.254',
      ) + ((f'ratep {self.pps}',) if self.pps else ()):
        lines.append(f'echo "{setting}" > {d}')
      self.devices.append(d)
    r = self._remote('\n'.join(lines))
    if r.returncode != 0:
      print(f'  remote pktgen config failed: {r.stderr.strip()[:300]}')
      return False
    return True

  def start_background(self):
    return subprocess.Popen(
      [self.ssh, '-o', 'BatchMode=yes', self.host,
       'sudo sh -c "echo start > /proc/net/pktgen/pgctrl"'],
      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

  def stop(self):
    self._remote('echo stop > /proc/net/pktgen/pgctrl')

  def sent(self):
    reads = ' '.join(f'cat {d} 2>/dev/null;' for d in self.devices)
    r = self._remote(reads)
    return sum(int(m) for m in
               re.findall(r'^\s*pkts-sofar:\s*(\d+)', r.stdout, re.M))

  def cleanup(self):
    self.stop()
    self._remote('echo reset > /proc/net/pktgen/pgctrl')


def cpu_freqs(host):
  """Per-policy (current, max) CPU frequency in kHz on the DUT.

  RK3588 has several cpufreq policies -- the A55 cluster and the two
  A76 pairs -- so this globs policy* rather than assuming cpu0 speaks
  for the machine.

  UNVERIFIED against the rig: it was already powered down for heatsink
  work when this was written. If the paths are wrong the reading is
  empty and `throttled` reports None, which is honest; it does not
  invent a number.
  """
  listing = host.run(['sh', '-c',
                      'for p in /sys/devices/system/cpu/cpufreq/policy*; '
                      'do echo "$(basename $p) '
                      '$(cat $p/scaling_cur_freq 2>/dev/null) '
                      '$(cat $p/cpuinfo_max_freq 2>/dev/null)"; done'])
  out = {}
  for line in listing.stdout.splitlines():
    parts = line.split()
    if len(parts) == 3 and parts[1].isdigit() and parts[2].isdigit():
      out[parts[0]] = (int(parts[1]), int(parts[2]))
  return out


def throttle_verdict(freqs):
  """Fraction of max clock the slowest policy is running at, or None.

  This is the difference between "the datapath tops out here" and "the
  cooling tops out here". A rung measured on a throttled SoC is not a
  ceiling, and without this the two are indistinguishable in the
  numbers -- a throttled run just looks like an expensive policy.
  """
  if not freqs:
    return None
  ratios = [cur / mx for cur, mx in freqs.values() if mx > 0]
  return min(ratios) if ratios else None


def iface_rx(host, iface):
  """Frames the NIC says it received, from its own counters."""
  return host.read_int(
    f'/sys/class/net/{iface}/statistics/rx_packets')

def deploy(host, source, fwl_bin, workdir, bundle_root,
           recv_if, tag, geoip_data=None):
  """Compile a policy and make fd run it.

  Deliberately the same sequence `hw::deploy` uses in hwlib.sh: compile
  a bundle, point <root>/current at it, restart fd, wait for the attach
  to be reported. Notably it does NOT clear the pin root — that
  workaround is why no test could see the cold-boot stale-pin defect,
  and a second copy of the deploy sequence that quietly behaves
  differently is how the harness stops testing what the field runs.

  Returns True, or False with the reason printed.
  """
  fw = workdir / f'{tag}.fw'
  if not host.write_text(str(fw), source):
    print('  could not write the policy to the DUT')
    return False
  r = host.run([fwl_bin, 'check', str(fw)])
  if r.returncode != 0:
    print(f'  policy rejected: {r.stderr.strip()[:300]}')
    return False
  version = pathlib.Path(bundle_root) / f'v-l13-{tag}-{os.getpid()}'
  host.run(['rm', '-rf', str(version)])
  r = host.run([fwl_bin, 'compile', '--bundle', str(version), str(fw)])
  if r.returncode != 0:
    print(f'  bundle compile failed: {r.stderr.strip()[:300]}')
    return False
  manifest = version / 'manifest.json'
  if '"object": null' in host.read_text(str(manifest)):
    print('  bundle has uncompiled zone objects')
    return False

  host.run(['systemctl', 'stop', 'fd'])
  current = pathlib.Path(bundle_root) / 'current'
  host.run(['ln', '-sfT', str(version), str(current)])
  host.run(['systemctl', 'start', 'fd'])

  for _ in range(20):
    status = host.run(['fctl', 'status'])
    if '"xdp_attached":true' in status.stdout:
      break
    time.sleep(0.5)
  else:
    print('  fd did not attach XDP')
    print(host.run(['journalctl', '-u', 'fd', '-n', '12',
                    '--no-pager']).stdout[-600:])
    return False

  host.run(['ip', 'link', 'set', 'dev', recv_if, 'promisc', 'on'])
  # XDP attach resets the igb links. Give them a beat before load; the
  # on-box tests probe the wire with sendmany.py, which is not
  # available from here when the generator is a different machine.
  time.sleep(3)
  return True


def _live_line(rung, first, prev, cur):
  """One watchable line per sample: instantaneous rates and heat."""
  dt = cur['t'] - prev['t']
  if dt <= 0:
    return
  rx = (cur['nic']['rx_packets'] - prev['nic']['rx_packets']) / dt
  miss = ((cur['nic'].get('rx_missed_errors', 0)
           - prev['nic'].get('rx_missed_errors', 0)) / dt)
  mbps = ((cur['nic']['rx_bytes'] - prev['nic']['rx_bytes'])
          * 8 / dt / 1e6)
  soc = cur['temps_mC'].get('package_thermal', 0) / 1000
  nic_t = cur['temps_mC'].get('i350bb', 0) / 1000
  clk = 1.0
  for pol, c in cur['freq_khz'].items():
    m = cur['freq_max_khz'].get(pol, 0)
    if m > 0 and c > 0:
      clk = min(clk, c / m)
  busy = 0
  for cpu, after in cur['cpu'].items():
    before = prev['cpu'].get(cpu)
    if before:
      d = [a - b for a, b in zip(after, before)]
      tot = sum(d)
      if tot > 0 and len(d) > 6 and d[6] / tot > 0.2:
        busy += 1
  print(f'  {rung:<10} t+{cur["t"] - first["t"]:5.1f}s  '
        f'rx {rx / 1000:7.0f}k/s  miss {miss / 1000:6.0f}k/s  '
        f'{mbps:6.0f}Mb/s  {busy} core  clk {clk:.2f}  '
        f'SoC {soc:5.1f}C  NIC {nic_t:5.1f}C', flush=True)


def measure(host, rung, gen, seconds, iface, sampler_path,
            live=False, raw_path=None):
  """Run one rung, sampling the DUT from the DUT.

  Everything is timed against the sampler's own monotonic clock rather
  than the nominal duration. The first real run divided by `seconds`
  while each counter came over its own ssh round trip, and reported
  2.16 Mpps arriving on a 1 GbE port -- above the 1.488 Mpps a 64-byte
  frame allows, so plainly the instrument and not the datapath.
  """
  argv = ['python3', sampler_path, str(seconds), iface, '0.5']
  if host.ssh_target:
    argv = ['ssh', '-o', 'BatchMode=yes', host.ssh_target,
            ' '.join(argv)]
  sampler = subprocess.Popen(argv, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, text=True,
                             bufsize=1)
  proc = gen.start_background()

  # Read as it arrives rather than at the end, so a run can be watched
  # instead of waited out, and so a run that goes wrong is visible
  # while there is still time to stop it.
  samples = []
  raw = open(raw_path, 'w') if raw_path else None
  prev = None
  for line in sampler.stdout:
    try:
      cur = json.loads(line)
    except ValueError:
      continue
    samples.append(cur)
    if raw:
      raw.write(line)
      raw.flush()
    if live and prev is not None:
      _live_line(rung, samples[0], prev, cur)
    prev = cur
  sampler.wait(timeout=30)
  gen.stop()
  proc.wait(timeout=15)
  if raw:
    raw.close()

  if len(samples) < 2:
    return {'rung': rung, 'error': 'sampler returned nothing usable'}

  first, last = samples[0], samples[-1]
  elapsed = last['t'] - first['t']
  if elapsed <= 0:
    return {'rung': rung, 'error': 'zero elapsed'}

  def nic_delta(key):
    return last['nic'].get(key, 0) - first['nic'].get(key, 0)

  received = nic_delta('rx_packets')
  missed = nic_delta('rx_missed_errors')
  dropped = nic_delta('rx_dropped')

  # Temperatures across the whole rung, not one reading at its end.
  temps = {}
  for name in first['temps_mC']:
    vals = [s['temps_mC'][name] for s in samples
            if s['temps_mC'].get(name, -1) > 0]
    if vals:
      temps[name] = {'min': min(vals) / 1000, 'max': max(vals) / 1000,
                     'end': vals[-1] / 1000}

  # Thermal throttling is a package-wide event on this SoC, so the
  # question is whether ANY cluster still reached its ceiling, not
  # whether every one did. Taking the minimum across policies reported
  # 0.34 at 38 C with a 55 C trip -- that was the A55 cluster idling
  # at 600 MHz while the A76s ran flat out, which is a governor doing
  # its job, not heat. Per-cluster detail is kept for reading.
  per_policy = {}
  for s in samples:
    for pol, cur in s['freq_khz'].items():
      mx = s['freq_max_khz'].get(pol, 0)
      if mx > 0 and cur > 0:
        frac = cur / mx
        lo, hi = per_policy.get(pol, (frac, frac))
        per_policy[pol] = (min(lo, frac), max(hi, frac))
  clock_frac = max((hi for _, hi in per_policy.values()), default=1.0)

  # Per-core softirq share: XDP runs there, so this says how many
  # cores actually carried the datapath rather than averaging it away.
  softirq = {}
  for cpu, after in last['cpu'].items():
    before = first['cpu'].get(cpu)
    if not before:
      continue
    delta = [a - b for a, b in zip(after, before)]
    total = sum(delta)
    if total > 0 and len(delta) > 6:
      softirq[cpu] = delta[6] / total

  return {
    'rung': rung,
    'elapsed_s': round(elapsed, 2),
    'samples': len(samples),
    'offered_pps': round(gen.sent() / elapsed),
    'received_pps': round(received / elapsed),
    'nic_missed_pps': round(missed / elapsed),
    'nic_dropped_pps': round(dropped / elapsed),
    'rx_bytes_per_s': round(nic_delta('rx_bytes') / elapsed),
    'softirq_by_cpu': {c: round(v, 3) for c, v in softirq.items()},
    'softirq_max': round(max(softirq.values(), default=0), 3),
    'softirq_cores_busy': sum(1 for v in softirq.values() if v > 0.2),
    'clock_frac': round(clock_frac, 3),
    'clock_by_policy': {k: (round(lo, 3), round(hi, 3))
                        for k, (lo, hi) in per_policy.items()},
    'temps_C': temps,
    'fd_rss_kb': last.get('fd_rss_kb', -1),
    'fd_rss_delta_kb': (last.get('fd_rss_kb', 0)
                        - first.get('fd_rss_kb', 0)),
    'net_rx_softirq_per_s': round(
      (last.get('net_rx_softirq', 0)
       - first.get('net_rx_softirq', 0)) / elapsed),
  }


def report(readings, remote_host=None):
  """Print the ladder, the per-construct costs, and the caveats."""
  ok = [r for r in readings if 'error' not in r]
  print()
  print('=' * 78)
  print('POLICY COST LADDER')
  print('=' * 78)
  print(f'{"rung":<11}{"offered":>10}{"through":>10}{"nic miss":>10}'
        f'{"Mb/s":>8}{"si":>6}{"cores":>6}{"clk":>6}{"SoC":>7}{"NIC":>7}')
  for r in ok:
    soc = r['temps_C'].get('package_thermal', {})
    nic = r['temps_C'].get('i350bb', {})
    print(f'{r["rung"]:<11}{r["offered_pps"]:>10,}'
          f'{r["received_pps"]:>10,}{r["nic_missed_pps"]:>10,}'
          f'{r["rx_bytes_per_s"] * 8 // 1_000_000:>8}'
          f'{r["softirq_max"]:>6.2f}{r["softirq_cores_busy"]:>6}'
          f'{r["clock_frac"]:>6.2f}'
          f'{soc.get("max", 0):>6.1f}C{nic.get("max", 0):>6.1f}C')

  for r in readings:
    if 'error' in r:
      print(f'  {r["rung"]}: {r["error"]}')

  print()
  print('cost of each construct, against the rung above it:')
  for prev, cur in zip(ok, ok[1:]):
    a, b = prev['received_pps'], cur['received_pps']
    if a <= 0 or b <= 0:
      continue
    added_ns = (1e9 / b) - (1e9 / a)
    pct = 100.0 * (a - b) / a
    verb = 'fewer' if pct >= 0 else 'MORE'
    print(f'  {cur["rung"]:<11} {added_ns:>9.1f} ns/pkt   '
          f'{abs(pct):>5.1f}% {verb} pps than `{prev["rung"]}`')

  # The NIC dropping before the datapath sees a packet is a different
  # finding from the datapath being slow, and the two are easy to
  # confuse: both show up as fewer packets through.
  starved = [r for r in ok
             if r['nic_missed_pps'] > r['received_pps'] * 0.05]
  if starved:
    print()
    print('NIC-LIMITED: rx_missed_errors is significant on: '
          + ', '.join(r['rung'] for r in starved))
    print('Those frames never reached XDP -- the NIC ring overflowed')
    print('before the datapath was involved. The cost figures above')
    print('are then bounded by the driver, not by the policy.')

  throttled = [r for r in ok if r['clock_frac'] < 0.95]
  if throttled:
    print()
    print('THROTTLED: no cluster reached its maximum clock during: '
          + ', '.join(r['rung'] for r in throttled))
    print('Those rungs measured the cooling, not the datapath.')

  leaked = [r for r in ok if r.get('fd_rss_delta_kb', 0) > 512]
  if leaked:
    print()
    print('fd RSS GREW during: '
          + ', '.join(f'{r["rung"]} (+{r["fd_rss_delta_kb"]}kB)'
                      for r in leaked))

  rates = [r['received_pps'] for r in ok if r['received_pps'] > 0]
  print()
  if rates and (max(rates) - min(rates)) / max(rates) < 0.05:
    print('WARNING: every rung landed within 5% of every other one --')
    print('the signature of a generator- or NIC-bound run, not a')
    print('datapath-bound one. The policies were not what limited it.')
  if remote_host:
    print(f'Generator: {remote_host}, off-box. Frame size matters: at')
    print('64 bytes 1 GbE carries 1,488,095 pps, and a 1500-byte flood')
    print('at the same bandwidth is 24x fewer packets. Say which size')
    print('a number came from.')
  else:
    print('Generator ran ON the box under test, so these are LOWER')
    print('BOUNDS -- it competed for CPU with what it measured.')


def main():
  ap = argparse.ArgumentParser(description=__doc__)
  ap.add_argument('--iface', default=os.environ.get('RECV_IF', 'enp1s0f1'),
                  help='interface the policy is attached to')
  ap.add_argument('--send-iface', default=os.environ.get('SEND_IF',
                                                         'enp1s0f0'))
  ap.add_argument('--gen-cpus', default='0,1',
                  help='CPUs pktgen threads run on')
  ap.add_argument('--dut-host', default=None,
                  help='drive the box under test over ssh (e.g. f-rig) '
                       'and generate locally. Use this when ssh works '
                       'generator -> DUT but not the other way, which '
                       'is the case on this bench.')
  ap.add_argument('--gen-host', default=None,
                  help='run pktgen on this host over ssh instead of '
                       'locally. THIS is the configuration that makes '
                       'the numbers a measurement rather than a lower '
                       'bound — see RemotePktgen.')
  ap.add_argument('--gen-iface', default=None,
                  help='the generating interface on --gen-host '
                       '(defaults to --send-iface)')
  ap.add_argument('--seconds', type=int, default=20)
  ap.add_argument('--pkt-size', type=int, default=64)
  ap.add_argument('--pps', type=int, default=1600000,
                  help='pace the generator, packets per second. The '
                       'default sits just above 1 GbE line rate at 64 '
                       'bytes (1,488,095 pps) so the DUT port is '
                       'saturated without the switch discarding the '
                       'excess -- an unpaced 10 GbE source into a 1 '
                       'GbE port measures the switch egress queue, not '
                       'the firewall. 0 disables pacing.')
  ap.add_argument('--dst-mac', default='02:00:00:00:00:02')
  ap.add_argument('--dst-ip', default='10.99.9.9')
  ap.add_argument('--fwl', default='/opt/fwl/.venv/bin/fwl')
  ap.add_argument('--quiet', action='store_true',
                  help='suppress the per-sample live lines')
  ap.add_argument('--out', default='/tmp/l13',
                  help='local directory for raw per-sample JSONL and '
                       'the summary; every sample is kept so a run can '
                       'be re-read without repeating it')
  ap.add_argument('--sampler',
                  default='/opt/fwl/tests/system/hw/l13_sampler.py',
                  help='path to the sampler ON THE DUT')
  ap.add_argument('--geoip-data', default=None,
                  help='geoip json for the geoip rung; without it that '
                       'rung is skipped rather than silently dropped')
  ap.add_argument('--bundle-root',
                  default=os.environ.get('BUNDLE_ROOT',
                                         '/usr/share/f/compiled'),
                  help='where <root>/current points at the live bundle')
  ap.add_argument('--dry-run', action='store_true',
                  help='print the ladder and exit, changing nothing')
  args = ap.parse_args()

  if args.dry_run:
    for name, why, src in LADDER:
      print(f'--- {name}: {why}')
      print(src.format(recv=args.iface, send=args.send_iface))
    return 0

  dut = Host(args.dut_host)
  if not dut.reachable():
    die(f'cannot reach the DUT at {dut.name}')
  if os.geteuid() == 0 and args.dut_host:
    die('do not run this under sudo when driving a remote DUT: root '
        'has neither your ssh config nor your agent, so it cannot '
        'reach the DUT. Run it as yourself; pktgen is elevated '
        'internally via sudo.')
  if not Pktgen.available():
    die('pktgen unavailable — modprobe pktgen failed. '
        'CONFIG_NET_PKTGEN is not built on this kernel.')
  # fwl runs on the DUT, which may not be this machine.
  if dut.run(['test', '-x', args.fwl]).returncode != 0:
    die(f'no executable fwl at {args.fwl} on {dut.name}')

  gen_cpus = [int(c) for c in args.gen_cpus.split(',')]
  if args.gen_host:
    gen = RemotePktgen(args.gen_host, args.gen_iface or args.send_iface,
                       gen_cpus, args.dst_mac, args.dst_ip,
                       args.pkt_size, pps=args.pps)
    if not gen.available():
      die(f'no pktgen on {args.gen_host} (modprobe pktgen failed '
          f'there, or ssh/sudo is not set up)')
    print(f'generator: pktgen on {args.gen_host} — readings are the '
          f'datapath\'s own')
  else:
    gen = Pktgen(args.send_iface, gen_cpus, args.dst_mac, args.dst_ip,
                 args.pkt_size, pps=args.pps)
    print('generator: pktgen on THIS box — readings are lower bounds. '
          'Use --gen-host for a real measurement.')
  if not gen.configure():
    die('pktgen configured no devices')

  workdir = pathlib.Path('/tmp/l13_ladder')
  dut.run(['mkdir', '-p', str(workdir)])
  workdir_local = pathlib.Path(args.out)
  workdir_local.mkdir(parents=True, exist_ok=True)

  # Prove the wire before believing any rung. The first trial run on
  # the rig reported 1 pps through on every rung and dutifully computed
  # "0.0 ns/pkt" costs from it -- numbers that looked like data and
  # meant nothing. The i350 ports were in different switch VLANs, so
  # nothing generated on one could ever reach the other. A ladder that
  # cannot see its own traffic must say so instead of reporting zeros.
  probe_before = iface_rx(dut, args.iface)
  probe = gen.start_background()
  time.sleep(3)
  gen.stop()
  probe.wait(timeout=10)
  probe_rx = iface_rx(dut, args.iface) - probe_before
  if probe_rx < 100:
    die(f'only {probe_rx} frames reached {args.iface} in 3s. The '
        f'generator and the receiving port have no layer-2 path '
        f'between them -- check they share a VLAN, or patch them '
        f'directly. Refusing to report a ladder measured on no '
        f'traffic.')
  print(f'wire ok: {probe_rx} frames reached {args.iface} in 3s\n')
  readings = []
  try:
    for name, why, template in LADDER:
      src = template.format(recv=args.iface, send=args.send_iface)
      print(f'--- {name}: {why}')
      if 'geoip(' in src and not args.geoip_data:
        print('  skipped: needs --geoip-data')
        continue
      if not deploy(dut, src, args.fwl, workdir, args.bundle_root,
                    args.iface, name, args.geoip_data):
        print('  skipped: could not deploy this rung')
        continue
      time.sleep(2)
      raw = workdir_local / f'samples-{name}.jsonl'
      readings.append(measure(dut, name, gen, args.seconds,
                              args.iface, args.sampler,
                              live=not args.quiet, raw_path=str(raw)))
      r = readings[-1]
      if 'error' in r:
        print(f'  no reading: {r["error"]}')
      else:
        soc = r['temps_C'].get('package_thermal', {}).get('max', 0)
        print(f'  {r["received_pps"]:,} pps through, '
              f'{r["nic_missed_pps"]:,} missed at the NIC, '
              f'SoC {soc:.1f}C, clk {r["clock_frac"]:.2f}')
  finally:
    gen.cleanup()

  if not readings:
    die('no rung produced a reading')
  report(readings, args.gen_host)
  out = workdir_local / 'ladder.json'
  out.write_text(json.dumps(readings, indent=2))
  print(f'\nsummary:      {out}')
  print(f'raw samples:  {workdir_local}/samples-*.jsonl')
  return 0

if __name__ == '__main__':
  sys.exit(main())
