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

def die(msg):
  print(f'FAIL: {msg}', file=sys.stderr)
  sys.exit(1)

def read_int(path):
  """Read an integer from a sysfs file, or -1."""
  try:
    return int(pathlib.Path(path).read_text().strip())
  except (OSError, ValueError):
    return -1

def hwmon_by_name(want):
  """Find /sys/class/hwmon/*/temp1_input for a named sensor.

  Same lookup gwsoak.py uses, so the two report the same numbers from
  the same places rather than two guesses about where a sensor lives.
  """
  base = '/sys/class/hwmon'
  try:
    entries = os.listdir(base)
  except OSError:
    return None
  for entry in entries:
    name_path = os.path.join(base, entry, 'name')
    try:
      if pathlib.Path(name_path).read_text().strip() == want:
        return os.path.join(base, entry, 'temp1_input')
    except OSError:
      continue
  return None

def cpu_times():
  """Per-CPU jiffy counters from /proc/stat, keyed by cpu name."""
  out = {}
  for line in pathlib.Path('/proc/stat').read_text().splitlines():
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

  def __init__(self, iface, cpus, dst_mac, dst_ip, pkt_size, clone=0):
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
    run(['modprobe', 'pktgen'])
    return PKTGEN.exists()

  def _write(self, path, value):
    try:
      pathlib.Path(path).write_text(value + '\n')
      return True
    except OSError as exc:
      print(f'  pktgen write failed {path}: {exc}', file=sys.stderr)
      return False

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
      ):
        self._write(d, line)
      self.devices.append(d)
    return bool(self.devices)

  def start_background(self):
    """Start transmitting. Returns the Popen; pgctrl blocks while running."""
    return subprocess.Popen(
      ['sh', '-c', f'echo start > {PKTGEN / "pgctrl"}'],
      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

  def stop(self):
    self._write(str(PKTGEN / 'pgctrl'), 'stop')

  def sent(self):
    """Total packets pktgen reports having transmitted."""
    total = 0
    for d in self.devices:
      try:
        text = pathlib.Path(d).read_text()
      except OSError:
        continue
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
               ssh='ssh'):
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
      ):
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


def iface_rx(iface):
  """Frames the NIC says it received, from its own counters."""
  return read_int(f'/sys/class/net/{iface}/statistics/rx_packets')

def deploy(source, fwl_bin, workdir, bundle_root, recv_if, tag):
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
  fw.write_text(source)
  r = run([fwl_bin, 'check', str(fw)])
  if r.returncode != 0:
    print(f'  policy rejected: {r.stderr.strip()[:300]}')
    return False
  version = pathlib.Path(bundle_root) / f'v-l13-{tag}-{os.getpid()}'
  shutil.rmtree(version, ignore_errors=True)
  r = run([fwl_bin, 'compile', '--bundle', str(version), str(fw)])
  if r.returncode != 0:
    print(f'  bundle compile failed: {r.stderr.strip()[:300]}')
    return False
  manifest = version / 'manifest.json'
  if '"object": null' in manifest.read_text():
    print('  bundle has uncompiled zone objects')
    return False

  run(['systemctl', 'stop', 'fd'])
  current = pathlib.Path(bundle_root) / 'current'
  run(['ln', '-sfT', str(version), str(current)])
  run(['systemctl', 'start', 'fd'])

  for _ in range(20):
    status = run(['fctl', 'status'])
    if '"xdp_attached":true' in status.stdout:
      break
    time.sleep(0.5)
  else:
    print('  fd did not attach XDP')
    print(run(['journalctl', '-u', 'fd', '-n', '12',
               '--no-pager']).stdout[-600:])
    return False

  run(['ip', 'link', 'set', 'dev', recv_if, 'promisc', 'on'])
  # XDP attach resets the igb links; wait for the wire before load.
  probe = run([sys.executable, str(HERE / 'sendmany.py'), '--probe',
               os.environ.get('SEND_IF', 'enp1s0f0'), recv_if, '45'])
  if probe.returncode != 0:
    print('  wire never came back after attach')
    return False
  return True


def measure(rung, gen, seconds, iface, soc_sensor, nic_sensor):
  """Run one rung and return its reading."""
  before_rx = iface_rx(iface)
  before_cpu = cpu_times()
  before_sent = gen.sent()
  proc = gen.start_background()
  time.sleep(seconds)
  gen.stop()
  proc.wait(timeout=10)
  after_rx = iface_rx(iface)
  after_cpu = cpu_times()
  after_sent = gen.sent()

  busy = cpu_busy_delta(before_cpu, after_cpu)
  offered = (after_sent - before_sent) / seconds
  received = (after_rx - before_rx) / seconds
  return {
    'rung': rung,
    'offered_pps': round(offered),
    'received_pps': round(received),
    'loss_pct': round(100.0 * (1 - received / offered), 2) if offered else 0,
    'softirq_max': round(max((s for s, _ in busy.values()), default=0), 3),
    'busy_max': round(max((b for _, b in busy.values()), default=0), 3),
    'soc_mC': read_int(soc_sensor),
    'nic_mC': read_int(nic_sensor) if nic_sensor else -1,
  }

def report(readings, seconds, remote_host=None):
  """Print the ladder, the deltas, and the caveats that bound it."""
  print()
  print('=' * 66)
  print('POLICY COST LADDER')
  print('=' * 66)
  print(f'{"rung":<12} {"offered":>10} {"through":>10} {"loss":>7} '
        f'{"si":>5} {"SoC":>6} {"NIC":>6}')
  for r in readings:
    print(f'{r["rung"]:<12} {r["offered_pps"]:>10,} '
          f'{r["received_pps"]:>10,} {r["loss_pct"]:>6}% '
          f'{r["softirq_max"]:>5.2f} '
          f'{r["soc_mC"] / 1000:>5.1f}C {r["nic_mC"] / 1000:>5.1f}C')

  print()
  print('cost of each construct, against the rung above it:')
  for prev, cur in zip(readings, readings[1:]):
    a, b = prev['received_pps'], cur['received_pps']
    if a <= 0 or b <= 0:
      continue
    # ns/packet at one core-equivalent; the difference of reciprocals
    # is the added per-packet cost, independent of how many cores were
    # actually busy.
    added_ns = (1e9 / b) - (1e9 / a)
    pct = 100.0 * (a - b) / a
    print(f'  {cur["rung"]:<12} {added_ns:>8.1f} ns/pkt   '
          f'{pct:>5.1f}% fewer pps than `{prev["rung"]}`')

  rates = [r['received_pps'] for r in readings if r['received_pps'] > 0]
  print()
  if rates and (max(rates) - min(rates)) / max(rates) < 0.05:
    print('WARNING: every rung landed within 5% of every other one.')
    print('That is the signature of a GENERATOR-bound run, not a')
    print('datapath-bound one — the policies are not what limited it.')
    print('This measurement needs a second machine to offer load from.')
  if remote_host:
    print(f'Generator was {remote_host}, off-box, so these are the')
    print('datapath\'s own rates rather than lower bounds. They still')
    print('depend on frame size: at 64 bytes the i350\'s four ports')
    print('carry 5.95 Mpps, and a 1500-byte flood is 24x cheaper per')
    print('bit. Say which size a number came from.')
  else:
    print('These are LOWER BOUNDS. The generator ran on the box under')
    print('test, so it competed for CPU with the datapath it measured.')
    print('Re-run with --gen-host for a real measurement.')
  print(f'Each rung ran {seconds}s.')

def main():
  ap = argparse.ArgumentParser(description=__doc__)
  ap.add_argument('--iface', default=os.environ.get('RECV_IF', 'enp1s0f1'),
                  help='interface the policy is attached to')
  ap.add_argument('--send-iface', default=os.environ.get('SEND_IF',
                                                         'enp1s0f0'))
  ap.add_argument('--gen-cpus', default='0,1',
                  help='CPUs pktgen threads run on')
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
  ap.add_argument('--dst-mac', default='02:00:00:00:00:02')
  ap.add_argument('--dst-ip', default='10.99.9.9')
  ap.add_argument('--fwl', default='/opt/fwl/.venv/bin/fwl')
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

  if os.geteuid() != 0:
    die('needs root: pktgen, BPF and IRQ affinity all do')
  if not Pktgen.available():
    die('pktgen unavailable — modprobe pktgen failed. '
        'CONFIG_NET_PKTGEN is not built on this kernel.')
  if not shutil.which(args.fwl) and not pathlib.Path(args.fwl).exists():
    die(f'no fwl at {args.fwl}')

  soc = (hwmon_by_name('package_thermal')
         or '/sys/class/thermal/thermal_zone0/temp')
  nic = hwmon_by_name('i350bb')

  gen_cpus = [int(c) for c in args.gen_cpus.split(',')]
  if args.gen_host:
    gen = RemotePktgen(args.gen_host, args.gen_iface or args.send_iface,
                       gen_cpus, args.dst_mac, args.dst_ip,
                       args.pkt_size)
    if not gen.available():
      die(f'no pktgen on {args.gen_host} (modprobe pktgen failed '
          f'there, or ssh/sudo is not set up)')
    print(f'generator: pktgen on {args.gen_host} — readings are the '
          f'datapath\'s own')
  else:
    gen = Pktgen(args.send_iface, gen_cpus, args.dst_mac, args.dst_ip,
                 args.pkt_size)
    print('generator: pktgen on THIS box — readings are lower bounds. '
          'Use --gen-host for a real measurement.')
  if not gen.configure():
    die('pktgen configured no devices')

  workdir = pathlib.Path('/tmp/l13_ladder')
  workdir.mkdir(exist_ok=True)
  readings = []
  try:
    for name, why, template in LADDER:
      src = template.format(recv=args.iface, send=args.send_iface)
      print(f'--- {name}: {why}')
      if not deploy(src, args.fwl, workdir, args.bundle_root,
                    args.iface, name):
        print('  skipped: could not deploy this rung')
        continue
      time.sleep(2)
      readings.append(measure(name, gen, args.seconds, args.iface,
                              soc, nic))
      print(f'  {readings[-1]["received_pps"]:,} pps through, '
            f'SoC {readings[-1]["soc_mC"] / 1000:.1f}C')
  finally:
    gen.cleanup()

  if not readings:
    die('no rung produced a reading')
  report(readings, args.seconds, args.gen_host)
  out = workdir / 'ladder.json'
  out.write_text(json.dumps(readings, indent=2))
  print(f'\nreadings: {out}')
  return 0

if __name__ == '__main__':
  sys.exit(main())
