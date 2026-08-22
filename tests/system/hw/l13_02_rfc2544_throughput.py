#!/usr/bin/env python3
"""Lossless throughput, by binary search. RFC 2544 section 26.1.

The honest answer to "how much of line rate does this do" is not the
packet rate observed while the box is overloaded. Under overload a
firewall still moves packets -- it just silently discards the rest, and
quoting the survivors as throughput describes a broken configuration as
if it were a working one.

RFC 2544 defines throughput as **the highest offered rate at which
nothing is lost**, found by search: offer a rate, count what came out,
and move the bound. That is the number this reports.

The first ladder run illustrated why the distinction matters. It showed
780 kpps "through" while 516 kpps were dying in the NIC ring -- 40% of
the traffic gone. That box was not doing 780 kpps of anything useful;
it was failing at 1.3 Mpps. Its true lossless throughput was lower than
either figure and nobody had measured it.

## What is being measured

Three verdicts, deliberately separated, because they answer different
questions and only one of them is about the firewall:

  drop     XDP_DROP. The datapath alone: parse, match, discard. No
           packet reaches the kernel stack. This is the ceiling of what
           the XDP program itself can sustain.

  pass     XDP_PASS. Every packet goes up the Linux stack, where an
           unmatched UDP port produces an ICMP unreachable -- so this
           measures the stack and the box's own transmit path, not the
           firewall. It is included because the first version of the
           cost ladder used it as its baseline and therefore measured
           the wrong subsystem for an afternoon.

  forward  The gateway workload: received on one zone, sent out
           another. This is what an appliance in the field actually
           does, and the only one of the three worth quoting as a
           product number.

## Honesty rules this enforces

  * The generator's achieved rate is read back from pktgen and
    compared against what was requested. A trial where the generator
    fell short of its target is discarded rather than recorded as a
    successful pass at a rate that was never offered.
  * Loss counts everything: frames the NIC never took
    (rx_missed_errors), frames the driver dropped (rx_dropped), and
    for the forwarding case the difference between what arrived and
    what left.
  * Every rate is computed against a measured elapsed time, never a
    nominal sleep duration.
  * The frame size is reported beside every number, because 64-byte
    line rate is 1.488 Mpps and 1518-byte line rate is 81 kpps -- the
    same box trivially achieves one and may fail the other, and a
    figure without its frame size is not a measurement.
"""

import argparse
import json
import os
import pathlib
import shlex
import subprocess
import sys
import time

# 1 GbE. A frame occupies its own bytes plus 8 of preamble/SFD and a
# 12-byte inter-frame gap, which is why 64-byte line rate is 1.488 Mpps
# rather than 1.953 Mpps.
LINE_BITS = 1_000_000_000
FRAME_OVERHEAD = 20

def line_rate_pps(frame_bytes):
  return LINE_BITS // ((frame_bytes + FRAME_OVERHEAD) * 8)

def run(cmd, **kw):
  return subprocess.run(cmd, capture_output=True, text=True, **kw)

def root_sh(script):
  """Run as root, elevating only if needed. See l13_01 for why."""
  if os.geteuid() == 0:
    return run(['sh', '-c', script])
  return run(['sudo', '-n', 'sh', '-c', script])

class Dut:
  """The box under test, reached over ssh."""

  def __init__(self, target, rx_iface, tx_iface=None):
    self.target = target
    self.rx = rx_iface
    self.tx = tx_iface

  def sh(self, cmd):
    return run(['ssh', '-o', 'BatchMode=yes', self.target, cmd])

  def counters(self):
    """One round trip for every counter a loss calculation needs."""
    paths = [f'/sys/class/net/{self.rx}/statistics/{k}'
             for k in ('rx_packets', 'rx_missed_errors', 'rx_dropped')]
    if self.tx:
      paths.append(f'/sys/class/net/{self.tx}/statistics/tx_packets')
    out = self.sh('cat ' + ' '.join(paths)).stdout.split()
    vals = [int(x) for x in out if x.strip().isdigit()]
    keys = ['rx', 'missed', 'dropped'] + (['tx'] if self.tx else [])
    return dict(zip(keys, vals))

class Generator:
  """pktgen, paced to an exact rate and checked for having achieved it."""

  def __init__(self, iface, cpus, dst_mac, dst_ip, frame_bytes):
    self.iface = iface
    self.cpus = cpus
    self.dst_mac = dst_mac
    self.dst_ip = dst_ip
    # pktgen's pkt_size excludes the 4-byte FCS the NIC appends.
    self.pkt_size = frame_bytes - 4
    self.devices = []

  def configure(self, pps_total):
    per_thread = max(1, pps_total // len(self.cpus))
    lines = ['echo reset > /proc/net/pktgen/pgctrl']
    self.devices = []
    for cpu in self.cpus:
      dev = f'{self.iface}@{cpu}'
      d = f'/proc/net/pktgen/{dev}'
      lines.append(f'echo "add_device {dev}" > '
                   f'/proc/net/pktgen/kpktgend_{cpu}')
      for setting in (
        'count 0', 'clone_skb 0', f'pkt_size {self.pkt_size}', 'delay 0',
        f'dst_mac {self.dst_mac}', f'dst {self.dst_ip}',
        'udp_dst_min 9000', 'udp_dst_max 9000',
        'udp_src_min 1024', 'udp_src_max 65000',
        # One flag per write. pktgen keeps the first token of a
        # space-separated list and drops the rest without complaining.
        'flag IPSRC_RND', 'flag UDPSRC_RND',
        'src_min 10.60.0.1', 'src_max 10.60.255.254',
        f'ratep {per_thread}',
      ):
        lines.append(f'echo "{setting}" > {d}')
      self.devices.append(d)
    r = root_sh('; '.join(lines))
    return r.returncode == 0

  def sent(self):
    total = 0
    for d in self.devices:
      for line in root_sh(f'cat {shlex.quote(d)}').stdout.splitlines():
        if 'pkts-sofar:' in line:
          total += int(line.split('pkts-sofar:')[1].split()[0])
    return total

  def run_for(self, seconds):
    """Transmit for `seconds`. Returns (sent, measured elapsed)."""
    before = self.sent()
    t0 = time.monotonic()
    proc = subprocess.Popen(
      (['sudo', '-n'] if os.geteuid() else [])
      + ['sh', '-c', 'echo start > /proc/net/pktgen/pgctrl'],
      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(seconds)
    root_sh('echo stop > /proc/net/pktgen/pgctrl')
    proc.wait(timeout=20)
    elapsed = time.monotonic() - t0
    return self.sent() - before, elapsed

  def cleanup(self):
    root_sh('echo stop > /proc/net/pktgen/pgctrl; '
            'echo reset > /proc/net/pktgen/pgctrl')

POLICIES = {
  'drop': ('the datapath alone -- nothing reaches the kernel stack',
           'zone wan = [{rx}]\n\n@xdp(wan)\n\ndefault drop\n'),
  'pass': ('datapath PLUS the Linux stack, which answers unmatched '
           'UDP with ICMP unreachable -- not a firewall measurement',
           'zone wan = [{rx}]\n\n@xdp(wan)\n\ndefault allow\n'),
  'forward': ('the gateway workload: in one zone, out another',
              'zone wan = [{rx}]\nzone lan = [{tx}]\n\n@xdp(wan)\n\n'
              'redirect to lan\n\n@xdp(lan)\n\ndefault drop\n'),
}

def deploy(dut, name, source, fwl, bundle_root):
  """Compile and load a policy. Same sequence as hw::deploy."""
  version = f'{bundle_root}/v-rfc-{name}'
  script = (
    f'cat > /tmp/rfc-{name}.fw <<\'POLICY\'\n{source}POLICY\n'
    f'rm -rf {version} && '
    f'{fwl} compile --bundle {version} /tmp/rfc-{name}.fw >/dev/null && '
    f'systemctl stop fd && '
    f'ln -sfT {version} {bundle_root}/current && '
    f'systemctl start fd')
  if dut.sh(script).returncode != 0:
    return False
  for _ in range(20):
    if '"xdp_attached":true' in dut.sh('fctl status 2>/dev/null').stdout:
      return True
    time.sleep(0.5)
  return False

def trial(dut, gen, pps, seconds, frame_bytes, mode):
  """Offer `pps` and report what was lost. Lower is the search's goal."""
  gen.configure(pps)
  before = dut.counters()
  sent, elapsed = gen.run_for(seconds)
  time.sleep(1.0)          # let counters settle before reading
  after = dut.counters()

  d = {k: after[k] - before[k] for k in before}
  offered_pps = sent / elapsed
  # A trial the generator could not actually deliver proves nothing.
  achieved = offered_pps / pps if pps else 0

  if mode == 'forward':
    delivered = d.get('tx', 0)
  else:
    delivered = d['rx']
  lost = max(0, sent - delivered)

  return {
    'requested_pps': pps,
    'offered_pps': round(offered_pps),
    'generator_achieved': round(achieved, 3),
    'delivered': delivered,
    'sent': sent,
    'lost': lost,
    'loss_pct': round(100.0 * lost / sent, 4) if sent else 100.0,
    'nic_missed': d['missed'],
    'nic_dropped': d['dropped'],
    'elapsed_s': round(elapsed, 2),
    'line_pct': round(100.0 * offered_pps / line_rate_pps(frame_bytes), 1),
  }

def search(dut, gen, seconds, frame_bytes, mode, tolerance, log):
  """Binary search for the highest rate with no loss."""
  lo, hi = 0, line_rate_pps(frame_bytes)
  best = None
  # Start at line rate: if the box handles it, there is nothing to
  # search for and the answer is "line rate", which is worth stating
  # plainly rather than approaching from below.
  probe = hi
  while True:
    t = trial(dut, gen, probe, seconds, frame_bytes, mode)
    log.append(t)
    ok = t['loss_pct'] <= tolerance and t['generator_achieved'] >= 0.95
    why = ('ok' if ok else
           f'loss {t["loss_pct"]}%' if t['loss_pct'] > tolerance else
           f'generator only reached {t["generator_achieved"] * 100:.0f}%')
    print(f'    {probe:>10,} pps ({t["line_pct"]:>5.1f}% line)  '
          f'delivered {t["delivered"]:>10,}  lost {t["loss_pct"]:>7.3f}%'
          f'  {why}', flush=True)
    if ok:
      best = t
      lo = probe
    else:
      hi = probe
    if hi - lo <= max(1000, line_rate_pps(frame_bytes) // 100):
      break
    probe = (lo + hi) // 2
  return best

def main():
  ap = argparse.ArgumentParser(description=__doc__)
  ap.add_argument('--dut-host', required=True)
  ap.add_argument('--rx-iface', required=True,
                  help='the DUT interface traffic arrives on')
  ap.add_argument('--tx-iface', default=None,
                  help='the DUT interface traffic leaves by, for the '
                       'forward mode')
  ap.add_argument('--gen-iface', required=True)
  ap.add_argument('--dst-mac', required=True)
  ap.add_argument('--dst-ip', default='10.99.9.9')
  ap.add_argument('--gen-cpus', default='0,1,2,3')
  ap.add_argument('--frames', default='64,128,512,1518',
                  help='frame sizes to sweep; 64 is the hard case')
  ap.add_argument('--modes', default='drop,pass',
                  help=f'any of: {",".join(POLICIES)}')
  ap.add_argument('--seconds', type=float, default=10)
  ap.add_argument('--tolerance', type=float, default=0.0,
                  help='loss %% still counted as passing. RFC 2544 '
                       'says zero; raise it only deliberately')
  ap.add_argument('--fwl', default='/usr/local/bin/fwl')
  ap.add_argument('--bundle-root', default='/usr/share/f/compiled')
  ap.add_argument('--out', default='/tmp/rfc2544')
  args = ap.parse_args()

  if os.geteuid() == 0:
    sys.exit('run as yourself, not under sudo: root has neither your '
             'ssh config nor your agent. pktgen is elevated internally.')

  dut = Dut(args.dut_host, args.rx_iface, args.tx_iface)
  if dut.sh('true').returncode != 0:
    sys.exit(f'cannot reach {args.dut_host}')

  out = pathlib.Path(args.out)
  out.mkdir(parents=True, exist_ok=True)
  cpus = [int(c) for c in args.gen_cpus.split(',')]
  results = []

  for mode in args.modes.split(','):
    if mode not in POLICIES:
      print(f'unknown mode {mode}, skipping')
      continue
    if mode == 'forward' and not args.tx_iface:
      print('forward mode needs --tx-iface, skipping')
      continue
    why, template = POLICIES[mode]
    src = template.format(rx=args.rx_iface, tx=args.tx_iface or '')
    print(f'\n=== {mode}: {why}')
    if not deploy(dut, mode, src, args.fwl, args.bundle_root):
      print('  deploy failed, skipping')
      continue
    for frame in [int(f) for f in args.frames.split(',')]:
      lr = line_rate_pps(frame)
      print(f'  {frame}-byte frames, line rate {lr:,} pps:')
      gen = Generator(args.gen_iface, cpus, args.dst_mac, args.dst_ip,
                      frame)
      log = []
      try:
        best = search(dut, gen, args.seconds, frame, mode,
                      args.tolerance, log)
      finally:
        gen.cleanup()
      pct = 100.0 * best['offered_pps'] / lr if best else 0.0
      results.append({'mode': mode, 'frame_bytes': frame,
                      'line_rate_pps': lr,
                      'throughput_pps': best['offered_pps'] if best else 0,
                      'line_pct': round(pct, 1), 'trials': log})
      verdict = (f'{best["offered_pps"]:,} pps = {pct:.1f}% of line'
                 if best else 'NO lossless rate found')
      print(f'    -> throughput: {verdict}')

  print('\n' + '=' * 72)
  print('RFC 2544 THROUGHPUT — highest offered rate with zero loss')
  print('=' * 72)
  print(f'{"mode":<9}{"frame":>7}{"line rate":>13}{"throughput":>13}'
        f'{"% of line":>11}')
  for r in results:
    print(f'{r["mode"]:<9}{r["frame_bytes"]:>7}{r["line_rate_pps"]:>13,}'
          f'{r["throughput_pps"]:>13,}{r["line_pct"]:>10.1f}%')
  path = out / 'rfc2544.json'
  path.write_text(json.dumps(results, indent=2))
  print(f'\nfull trial log: {path}')
  return 0

if __name__ == '__main__':
  sys.exit(main())
