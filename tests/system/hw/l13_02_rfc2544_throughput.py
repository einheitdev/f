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
           does, and the only one worth quoting as a product number.

  bidir    The same, in both directions at once. Appliance datasheets
           publish "throughput across all ports" counting both
           directions, so a one-way figure compared against one of
           theirs understates by up to a factor of two -- and a box
           that forwards one way at line rate does not necessarily do
           both, since the two directions contend for the same cores.

## Frame sizes, and the mix vendors actually publish

`--frames` takes sizes, and also the token `imix`: sets of 7 x 64,
4 x 594 and 1 x 1518 byte frames, the "simple IMIX" that appears in
Netgate's footnotes and most other datasheets. Average frame is 361.8
bytes, so 10 GbE carries 3.27 Mpps of it. It exists here because a
vendor's large-frame number and their mixed number differ by 3x on the
same hardware, and matching only one of them is not a comparison.

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

def line_rate_pps(frame_bytes, line_bits=None):
  return (line_bits or LINE_BITS) // ((frame_bytes + FRAME_OVERHEAD) * 8)

class FrameMix:
  """A frame-size distribution, given as packet-count weights.

  A single size is the degenerate case and behaves exactly as before.
  The reason the abstraction exists is that appliance vendors do not
  publish single-size numbers -- they publish one figure for large
  frames and one for a mix, and the mix is where the interesting
  collapse happens. Comparing our 64-byte figure against their mixed
  figure is not a comparison, so the harness has to be able to offer
  the same distribution they did.
  """

  def __init__(self, label, sizes_weights):
    self.label = label
    self.sizes_weights = list(sizes_weights)
    self.total_weight = sum(w for _, w in self.sizes_weights)

  @property
  def avg_frame_bytes(self):
    return (sum(s * w for s, w in self.sizes_weights)
            / float(self.total_weight))

  def line_rate_pps(self, line_bits=None):
    """Packets per second that fill the link, at this mix's average."""
    wire = self.avg_frame_bytes + FRAME_OVERHEAD
    return int((line_bits or LINE_BITS) // (wire * 8))

  def gbit(self, pps):
    """Layer-2 bits per second for a packet rate, in Gb/s.

    Frame bytes only -- preamble and inter-frame gap are on the wire
    but are not payload, and quoting them inflates the number by 3-5%
    at small frame sizes. Line rate percentages use the wire figure;
    throughput in Gb/s uses this one.
    """
    return pps * self.avg_frame_bytes * 8 / 1e9

# "Simple IMIX" exactly as Netgate defines it in the footnotes of their
# hardware comparison chart: sets of 7 x 40-byte, 4 x 576-byte and
# 1 x 1500-byte IP packets, plus Ethernet framing. 40 + 14 + 4 is 58,
# below the 64-byte Ethernet minimum, so the small frames go on the
# wire padded to 64. Average frame is 361.8 bytes, so a 10 GbE link
# carries 3.27 Mpps of it -- a rate that costs far more per bit than
# 1518-byte traffic and far less than 64-byte traffic.
IMIX = FrameMix('imix', [(64, 7), (594, 4), (1518, 1)])

def parse_mixes(spec):
  """'64,512,imix' -> [FrameMix, ...]."""
  out = []
  for token in spec.split(','):
    token = token.strip()
    if token == 'imix':
      out.append(IMIX)
    else:
      out.append(FrameMix(token, [(int(token), 1)]))
  return out

def run(cmd, **kw):
  return subprocess.run(cmd, capture_output=True, text=True, **kw)

def root_sh(script):
  """Run as root, elevating only if needed. See l13_01 for why."""
  if os.geteuid() == 0:
    return run(['sh', '-c', script])
  return run(['sudo', '-n', 'sh', '-c', script])

class Dut:
  """The box under test, reached over ssh."""

  def __init__(self, target):
    self.target = target

  def sh(self, cmd):
    return run(['ssh', '-o', 'BatchMode=yes', self.target, cmd])

  def counters(self, rx, tx=None):
    """Everything a loss calculation needs, in one round trip.

    `rx_packets` alone is NOT enough, and believing it produced a
    completely wrong verdict once: **mlx5 does not count XDP-dropped
    frames in rx_packets, while igb does.** A `default drop` policy on
    a ConnectX therefore reads as zero received and 100% loss, when in
    fact every frame arrived and the datapath discarded it exactly as
    asked.

    The XDP counters have to be read by exact name, which is the
    second thing this got wrong. `ethtool -S` on mlx5 prints both an
    aggregate `rx_xdp_drop` and a per-queue `rx0_xdp_drop` ... for
    every queue, and a regex loose enough to match the per-queue names
    also matches the aggregate. Summing the lot credits the datapath
    with exactly twice what it did, which reads as a box comfortably
    inside its budget while half the traffic is dying in the ring. The
    awk below takes the aggregate when the driver publishes one and
    falls back to summing the per-queue counters only when it does
    not.

    Egress is read from the transmit port's own `tx_xdp_xmit`, not
    from sysfs `tx_packets`: mlx5's netdev tx_packets does not count
    XDP transmits at all and sits at whatever the management traffic
    left it at, which is indistinguishable from a forwarding path
    that has stopped working.
    """
    def pick(iface, aggregate, per_queue):
      """awk that prefers a driver's aggregate counter over the sum."""
      return (f'ethtool -S {iface} 2>/dev/null | awk -F: \''
              f'$1 ~ /^ *{aggregate}$/ {{a=$2; have=1}} '
              f'$1 ~ /^ *{per_queue}$/ {{q+=$2}} '
              'END {print (have ? a+0 : q+0)}\'')

    paths = [f'/sys/class/net/{rx}/statistics/{k}'
             for k in ('rx_packets', 'rx_missed_errors', 'rx_dropped')]
    parts = ['cat ' + ' '.join(paths)]
    parts.append(pick(rx, 'rx_xdp_drop', 'rx[0-9]+_xdp_drop'))
    parts.append(pick(rx, 'rx_xdp_redirect', 'rx[0-9]+_xdp_redirect'))
    keys = ['rx', 'missed', 'dropped', 'xdp_drop', 'xdp_redirect']
    if tx:
      parts.append(f'cat /sys/class/net/{tx}/statistics/tx_packets')
      parts.append(pick(tx, 'tx_xdp_xmit', 'tx[0-9]+_xdp_xmit'))
      keys += ['tx', 'tx_xdp']
    out = self.sh('; '.join(parts)).stdout.split()
    vals = [int(x) for x in out if x.strip().lstrip('-').isdigit()]
    d = dict(zip(keys, vals))
    for k in keys:
      d.setdefault(k, 0)
    return d

class Direction:
  """One direction of traffic under test.

  A generator port, the DUT port its frames land on, and the DUT port
  they are expected to leave by. Two of these pointed at each other is
  a bidirectional test, which is what appliance vendors mean when they
  publish "throughput across all ports" -- their figure counts both
  directions, so a one-way number compared against it understates by
  a factor of two.
  """

  def __init__(self, gen_iface, cpus, dst_mac, rx, tx=None,
               dst_ip='10.99.9.9'):
    self.gen_iface = gen_iface
    self.cpus = cpus
    self.dst_mac = dst_mac
    self.rx = rx
    self.tx = tx
    self.dst_ip = dst_ip
    self.devices = []

  def __str__(self):
    arrow = f'{self.rx}->{self.tx}' if self.tx else self.rx
    return f'{self.gen_iface} => {arrow}'

class Generator:
  """pktgen, paced to an exact rate and checked for having achieved it.

  One instance drives every direction at once. That is not a
  convenience: `echo start > pgctrl` starts every device pktgen has
  configured, so two directions cannot be two independent objects
  without one of them starting the other's traffic.
  """

  def __init__(self, directions, mix):
    self.directions = directions
    self.mix = mix
    for d in directions:
      if len(d.cpus) < len(mix.sizes_weights):
        sys.exit(f'{d.gen_iface}: a {mix.label} mix needs at least '
                 f'{len(mix.sizes_weights)} generator cpus, one per '
                 f'frame size; got {len(d.cpus)}')

  @staticmethod
  def _split(n, weights):
    """Hand out `n` threads over `weights`, at least one each."""
    total = float(sum(weights))
    counts = [max(1, int(n * w / total)) for w in weights]
    while sum(counts) > n:
      i = max(range(len(counts)), key=lambda j: counts[j])
      if counts[i] == 1:
        break
      counts[i] -= 1
    while sum(counts) < n:
      # the spare goes to whichever size is furthest below its share
      i = max(range(len(counts)),
              key=lambda j: weights[j] / total - counts[j] / float(n))
      counts[i] += 1
    return counts

  def _plan(self, direction, pps):
    """[(cpu, frame_bytes, ratep)] for one direction.

    pktgen gives a thread one frame size, so a mix is produced by
    running threads at different sizes and pacing each so the packet
    *counts* come out in the mix's ratio. Threads are handed out in
    proportion to each size's share; the pacing then corrects for
    whatever the rounding did, which matters because a 7:4:1 mix over
    four threads cannot be expressed by thread count alone.
    """
    weights = [w for _, w in self.mix.sizes_weights]
    counts = self._split(len(direction.cpus), weights)
    plan, cpus = [], list(direction.cpus)
    for (size, weight), count in zip(self.mix.sizes_weights, counts):
      share = pps * weight / float(self.mix.total_weight)
      for _ in range(count):
        plan.append((cpus.pop(0), size, max(1, int(share / count))))
    return plan

  def configure(self, pps_per_direction):
    lines = ['echo reset > /proc/net/pktgen/pgctrl']
    for direction in self.directions:
      direction.devices = []
      for cpu, frame_bytes, ratep in self._plan(direction,
                                                pps_per_direction):
        dev = f'{direction.gen_iface}@{cpu}'
        d = f'/proc/net/pktgen/{dev}'
        lines.append(f'echo "add_device {dev}" > '
                     f'/proc/net/pktgen/kpktgend_{cpu}')
        for setting in (
          'count 0', 'clone_skb 0',
          # pktgen's pkt_size excludes the 4-byte FCS the NIC appends.
          f'pkt_size {frame_bytes - 4}', 'delay 0',
          f'dst_mac {direction.dst_mac}', f'dst {direction.dst_ip}',
          'udp_dst_min 9000', 'udp_dst_max 9000',
          'udp_src_min 1024', 'udp_src_max 65000',
          # One flag per write. pktgen keeps the first token of a
          # space-separated list and drops the rest without complaining.
          'flag IPSRC_RND', 'flag UDPSRC_RND',
          'src_min 10.60.0.1', 'src_max 10.60.255.254',
          # Give every thread its OWN transmit queue. Without this they
          # all serialise on queue 0, and the generator tops out around
          # 2.5 Mpps no matter how many threads are added -- which reads
          # exactly like a device under test that cannot go faster.
          # Setting it took one generator from 2,578,271 to 10,956,407
          # pps, a 4.25x difference that was pure misconfiguration and
          # was briefly mistaken for the DUT's ceiling.
          f'queue_map_min {cpu}', f'queue_map_max {cpu}',
          f'ratep {ratep}',
        ):
          lines.append(f'echo "{setting}" > {d}')
        direction.devices.append(d)
    r = root_sh('; '.join(lines))
    return r.returncode == 0

  def sent(self):
    """{gen_iface: packets sent so far}."""
    paths = [d for direction in self.directions
             for d in direction.devices]
    if not paths:
      return {}
    quoted = ' '.join(shlex.quote(x) for x in paths)
    out = root_sh(f'for f in {quoted}; do echo "== $f"; cat "$f"; '
                  'done').stdout
    per_device, current = {}, None
    for line in out.splitlines():
      if line.startswith('== '):
        current = line[3:]
      elif 'pkts-sofar:' in line and current:
        per_device[current] = int(
          line.split('pkts-sofar:')[1].split()[0])
    totals = {}
    for direction in self.directions:
      totals[direction.gen_iface] = sum(
        per_device.get(d, 0) for d in direction.devices)
    return totals

  def run_for(self, seconds):
    """Transmit for `seconds`. Returns ({iface: sent}, elapsed)."""
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
    after = self.sent()
    return ({k: after[k] - before.get(k, 0) for k in after}, elapsed)

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
  'bidir': ('the gateway workload in BOTH directions at once, which '
            'is what appliance datasheets count',
            'zone wan = [{rx}]\nzone lan = [{tx}]\n\n@xdp(wan)\n\n'
            'redirect to lan\n\n@xdp(lan)\n\nredirect to wan\n'),
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

def trial(dut, gen, pps, seconds, mix, mode):
  """Offer `pps` on every direction and report what was lost.

  `pps` is per direction, not aggregate, because line rate is a
  property of a port. A bidirectional run offering 800 kpps is
  offering 800 kpps to each of two ports; the aggregate is reported
  beside it but is not what the search moves.
  """
  gen.configure(pps)
  before = {d.rx: dut.counters(d.rx, d.tx) for d in gen.directions}
  sent_by, elapsed = gen.run_for(seconds)
  time.sleep(1.0)          # let counters settle before reading
  after = {d.rx: dut.counters(d.rx, d.tx) for d in gen.directions}

  sent = delivered = missed = dropped = 0
  per_direction = []
  for direction in gen.directions:
    b, a = before[direction.rx], after[direction.rx]
    d = {k: a[k] - b[k] for k in b}
    s_i = sent_by.get(direction.gen_iface, 0)
    if direction.tx:
      # What actually went out the egress port. mlx5 publishes it as
      # tx_xdp_xmit and leaves netdev tx_packets alone; igb has no
      # such counter and moves tx_packets instead.
      got = d.get('tx_xdp', 0) or d.get('tx', 0)
    elif mode == 'drop':
      # mlx5 counts an XDP_DROP only in rx_xdp_drop; igb counts it in
      # rx_packets and has no xdp counter at all.
      got = d.get('xdp_drop', 0) or d['rx']
    else:
      got = d['rx']
    # A box cannot deliver more than it was given. When this trips it
    # is always the counter, never the hardware -- it tripped for real
    # on mlx5, where a regex matched both the aggregate and per-queue
    # XDP counters and credited the datapath with double. That run
    # reported comfortable zero-loss throughput while half the frames
    # were dying in the receive ring, so this is fatal rather than a
    # warning.
    if got > s_i * 1.01 + 1000:
      sys.exit(
        f'\ncounter bug: {direction} delivered {got:,} of {s_i:,} '
        f'offered. Nothing physical does that. Check what '
        f'counters() is summing on this driver before trusting any '
        f'number from this harness.')
    sent += s_i
    delivered += got
    missed += d['missed']
    dropped += d['dropped']
    per_direction.append({
      'direction': str(direction), 'sent': s_i, 'delivered': got,
      'lost': max(0, s_i - got),
    })

  lost = max(0, sent - delivered)
  n = len(gen.directions)
  offered_pps = sent / elapsed / n     # per direction
  # A trial the generator could not actually deliver proves nothing.
  achieved = offered_pps / pps if pps else 0

  return {
    'requested_pps': pps,
    'offered_pps': round(offered_pps),
    'aggregate_pps': round(sent / elapsed),
    'aggregate_gbit': round(mix.gbit(sent / elapsed), 3),
    'directions': n,
    'generator_achieved': round(achieved, 3),
    'delivered': delivered,
    'sent': sent,
    'lost': lost,
    'loss_pct': round(100.0 * lost / sent, 4) if sent else 100.0,
    'nic_missed': missed,
    'nic_dropped': dropped,
    # Should be ~0: every frame sent is either delivered, missed by
    # the ring, or dropped by the driver. A large residue means some
    # counter is not being read, not that frames evaporated.
    'unaccounted': sent - delivered - missed - dropped,
    'elapsed_s': round(elapsed, 2),
    'line_pct': round(100.0 * offered_pps / mix.line_rate_pps(), 1),
    'per_direction': per_direction,
  }

def search(dut, gen, seconds, mix, mode, tolerance, log,
           precision=0.02):
  """Binary search for the highest per-port rate with no loss."""
  lo, hi = 0, mix.line_rate_pps()
  best = None
  # Start at line rate: if the box handles it, there is nothing to
  # search for and the answer is "line rate", which is worth stating
  # plainly rather than approaching from below.
  probe = hi
  while True:
    t = trial(dut, gen, probe, seconds, mix, mode)
    log.append(t)
    ok = t['loss_pct'] <= tolerance and t['generator_achieved'] >= 0.95
    why = ('ok' if ok else
           f'loss {t["loss_pct"]}%' if t['loss_pct'] > tolerance else
           f'generator only reached {t["generator_achieved"] * 100:.0f}%')
    resid = t['unaccounted']
    slack = max(1000, t['sent'] // 1000)
    audit = f'  [unaccounted {resid:+,}]' if abs(resid) > slack else ''
    print(f'    {probe:>10,} pps ({t["line_pct"]:>5.1f}% line)  '
          f'delivered {t["delivered"]:>11,}  lost {t["loss_pct"]:>7.3f}%'
          f'  missed {t["nic_missed"]:>10,}  {why}{audit}', flush=True)
    if ok:
      best = t
      lo = probe
    else:
      hi = probe
    # Stop when the bracket is narrow relative to the ANSWER, not to
    # line rate. Against line rate, a 64-byte search on 10 GbE stops
    # with a 148,000 pps bracket -- so a box that forwards 1.03 Mpps
    # and one that forwards 1.15 Mpps produce the same reading, and
    # two runs of the same configuration disagree by more than the
    # tuning change being tested. That happened.
    if hi - lo <= max(1000, int(max(lo, 1) * precision)):
      break
    probe = (lo + hi) // 2
  return best

def selftest():
  """Check the arithmetic that decides the reported number.

  Bench harnesses do not get unit tests here, but the parts of this
  one that turn counters into a throughput figure are pure and have
  already been wrong once in a way that inflated a published result.
  Run this before a session, the way hone's selftest runs before a
  soak.
  """
  failures = []

  def check(what, got, want):
    if got != want:
      failures.append(f'{what}: got {got!r}, want {want!r}')

  # IMIX as the datasheets define it: 7x64 + 4x594 + 1x1518 averages
  # 361.833 bytes, so 10 GbE carries 3,273,679 of them per second.
  check('imix avg', round(IMIX.avg_frame_bytes, 3), 361.833)
  check('imix line rate at 10G', IMIX.line_rate_pps(10_000_000_000),
        3273679)
  check('64B line rate at 1G', FrameMix('64', [(64, 1)])
        .line_rate_pps(1_000_000_000), 1488095)
  check('1518B line rate at 10G', FrameMix('1518', [(1518, 1)])
        .line_rate_pps(10_000_000_000), 812743)

  # Threads are handed out by share, but the *pacing* is what has to
  # reproduce the ratio exactly -- a 7:4:1 mix cannot be expressed by
  # thread count alone on any small pool, so getting this wrong
  # silently offers a different mix than the one being reported.
  for n in range(len(IMIX.sizes_weights), 13):
    d = Direction('gen0', list(range(n)), 'aa:bb:cc:dd:ee:ff', 'rx',
                  'tx')
    plan = Generator([d], IMIX)._plan(d, 1_200_000)
    check(f'{n} threads all used', len(plan), n)
    by_size = {}
    for _, size, rate in plan:
      by_size[size] = by_size.get(size, 0) + rate
    total = sum(by_size.values())
    for size, weight in IMIX.sizes_weights:
      share = by_size.get(size, 0) / total * IMIX.total_weight
      check(f'{n} threads, {size}B share', round(share, 1),
            float(weight))

  # A single size must still work, and must not be paced as a mix.
  d = Direction('gen0', [0, 1], 'aa:bb:cc:dd:ee:ff', 'rx')
  plan = Generator([d], FrameMix('64', [(64, 1)]))._plan(d, 1_000_000)
  check('single size threads', [x[1] for x in plan], [64, 64])
  check('single size pacing', sum(x[2] for x in plan), 1_000_000)

  # Gb/s is frame bits, not wire bits: preamble and inter-frame gap
  # are on the wire but are not payload, and counting them inflates
  # small-frame figures by 30%.
  check('imix gbit at line',
        round(IMIX.gbit(IMIX.line_rate_pps(10_000_000_000)), 2), 9.48)

  for f in failures:
    print(f'  FAIL  {f}')
  print(f'selftest: {"FAILED" if failures else "ok"}, '
        f'{len(failures)} failure(s)')
  return 1 if failures else 0

def main():
  ap = argparse.ArgumentParser(description=__doc__)
  ap.add_argument('--dut-host', required=True)
  ap.add_argument('--rx-iface', required=True,
                  help='the DUT interface traffic arrives on')
  ap.add_argument('--tx-iface', default=None,
                  help='the DUT interface traffic leaves by, for the '
                       'forward and bidir modes')
  ap.add_argument('--gen-iface', required=True)
  ap.add_argument('--dst-mac', required=True)
  ap.add_argument('--gen-iface-b', default=None,
                  help='second generator port, for bidir: the one '
                       'cabled to --tx-iface')
  ap.add_argument('--dst-mac-b', default=None,
                  help='MAC of --tx-iface, for bidir')
  ap.add_argument('--gen-cpus-b', default=None,
                  help='generator cpus for the reverse direction. '
                       'Must not overlap --gen-cpus: a pktgen thread '
                       'belongs to exactly one cpu.')
  ap.add_argument('--dst-ip', default='10.99.9.9')
  ap.add_argument('--gen-cpus', default='0,1,2,3')
  ap.add_argument('--frames', default='64,128,512,1518',
                  help='frame sizes to sweep; 64 is the hard case. '
                       'The token "imix" offers the 7:4:1 mix of '
                       '64/594/1518 that appliance datasheets quote.')
  ap.add_argument('--modes', default='drop,pass',
                  help=f'any of: {",".join(POLICIES)}')
  ap.add_argument('--line-gbit', type=float, default=1.0,
                  help='link speed of the DUT port, for computing line '
                       'rate. 1 GbE at 64B is 1,488,095 pps; 10 GbE is '
                       '14,880,952.')
  ap.add_argument('--seconds', type=float, default=10)
  ap.add_argument('--precision', type=float, default=0.02,
                  help='stop the search when the bracket is this '
                       'fraction of the rate found. Relative to the '
                       'answer, not to line rate: 1%% of 10 GbE at 64 '
                       'bytes is 148,000 pps, which is wider than the '
                       'effects being measured.')
  ap.add_argument('--tolerance', type=float, default=0.0,
                  help='loss %% still counted as passing. RFC 2544 '
                       'says zero; raise it only deliberately')
  ap.add_argument('--fwl', default='/usr/local/bin/fwl')
  ap.add_argument('--bundle-root', default='/usr/share/f/compiled')
  ap.add_argument('--out', default='/tmp/rfc2544')
  ap.add_argument('--selftest', action='store_true',
                  help='check the harness arithmetic and exit; needs '
                       'no hardware and no other arguments')
  # Checked before parsing, because the arguments that name hardware
  # are required and a selftest is exactly the case where there is
  # none.
  if '--selftest' in sys.argv[1:]:
    return selftest()
  args = ap.parse_args()
  global LINE_BITS
  LINE_BITS = int(args.line_gbit * 1_000_000_000)

  if os.geteuid() == 0:
    sys.exit('run as yourself, not under sudo: root has neither your '
             'ssh config nor your agent. pktgen is elevated internally.')

  dut = Dut(args.dut_host)
  if dut.sh('true').returncode != 0:
    sys.exit(f'cannot reach {args.dut_host}')

  out = pathlib.Path(args.out)
  out.mkdir(parents=True, exist_ok=True)
  cpus = [int(c) for c in args.gen_cpus.split(',')]
  cpus_b = ([int(c) for c in args.gen_cpus_b.split(',')]
            if args.gen_cpus_b else [])
  if set(cpus) & set(cpus_b):
    sys.exit('--gen-cpus and --gen-cpus-b overlap; a pktgen thread '
             'belongs to exactly one cpu and the second stream would '
             'silently replace the first')
  results = []

  for mode in args.modes.split(','):
    if mode not in POLICIES:
      print(f'unknown mode {mode}, skipping')
      continue
    if mode in ('forward', 'bidir') and not args.tx_iface:
      print(f'{mode} mode needs --tx-iface, skipping')
      continue
    if mode == 'bidir' and not (args.gen_iface_b and args.dst_mac_b
                                and cpus_b):
      print('bidir mode needs --gen-iface-b, --dst-mac-b and '
            '--gen-cpus-b, skipping')
      continue
    why, template = POLICIES[mode]
    src = template.format(rx=args.rx_iface, tx=args.tx_iface or '')
    print(f'\n=== {mode}: {why}')
    if not deploy(dut, mode, src, args.fwl, args.bundle_root):
      print('  deploy failed, skipping')
      continue

    directions = [Direction(args.gen_iface, cpus, args.dst_mac,
                            args.rx_iface,
                            args.tx_iface if mode in ('forward',
                                                      'bidir') else None,
                            args.dst_ip)]
    if mode == 'bidir':
      directions.append(Direction(args.gen_iface_b, cpus_b,
                                  args.dst_mac_b, args.tx_iface,
                                  args.rx_iface, args.dst_ip))

    for mix in parse_mixes(args.frames):
      lr = mix.line_rate_pps()
      avg = mix.avg_frame_bytes
      print(f'  {mix.label} frames (avg {avg:.1f} B), line rate '
            f'{lr:,} pps per port:')
      gen = Generator(directions, mix)
      log = []
      try:
        best = search(dut, gen, args.seconds, mix, mode,
                      args.tolerance, log, args.precision)
      finally:
        gen.cleanup()
      pct = 100.0 * best['offered_pps'] / lr if best else 0.0
      agg = best['aggregate_pps'] if best else 0
      results.append({'mode': mode, 'frames': mix.label,
                      'avg_frame_bytes': round(avg, 1),
                      'directions': len(directions),
                      'line_rate_pps': lr,
                      'throughput_pps': best['offered_pps'] if best else 0,
                      'aggregate_pps': agg,
                      'aggregate_gbit': round(mix.gbit(agg), 3),
                      'line_pct': round(pct, 1), 'trials': log})
      verdict = (f'{best["offered_pps"]:,} pps/port = {pct:.1f}% of '
                 f'line, {mix.gbit(agg):.2f} Gb/s aggregate'
                 if best else 'NO lossless rate found')
      print(f'    -> throughput: {verdict}')

  print('\n' + '=' * 78)
  print('RFC 2544 THROUGHPUT — highest offered rate with zero loss')
  print('=' * 78)
  print(f'{"mode":<9}{"frames":>7}{"dirs":>6}{"line rate":>13}'
        f'{"per port":>13}{"% line":>9}{"aggregate":>12}')
  for r in results:
    print(f'{r["mode"]:<9}{r["frames"]:>7}{r["directions"]:>6}'
          f'{r["line_rate_pps"]:>13,}{r["throughput_pps"]:>13,}'
          f'{r["line_pct"]:>8.1f}%{r["aggregate_gbit"]:>10.2f} Gb/s')
  path = out / 'rfc2544.json'
  path.write_text(json.dumps(results, indent=2))
  print(f'\nfull trial log: {path}')
  return 0

if __name__ == '__main__':
  sys.exit(main())
