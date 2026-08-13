"""Continuous NAT/masquerade traffic for the soak.

Sent from the send port through the EX2300 into the XDP port, forever,
at a modest aggregate rate. Four components, each there for a reason:

  1. STEADY masqueraded flows — 20 guests behind one address, each on
     its own source port, with the matching reply addressed to the
     masquerade address. Exercises fwl_snat_egress and fwl_nat_denat
     on every cycle, in both directions.
  2. CHURN — one brand-new (destination, source port) pair per second,
     so `fwl_nat` grows at a known rate. The table has no aging path,
     so its slope over the soak is the measurement that says how long
     a real deployment has before it fills.
  3. DNAT — inbound port forward to a host behind the firewall.
  4. NOISE — multicast drops, a logged UDP flow, and a periodic burst
     from the rate-limited subnet.

Run via natsoak_start.sh (systemd transient unit), not by hand.
"""
import itertools
import socket
import struct
import sys
import time

from fwl import pkt

SEND_IF = "enp1s0f0"
MASQ = "10.99.200.2"
PEER = "10.99.71.9"
GUESTS = 20


def _frame(builder: str) -> bytearray:
  return bytearray(pkt.build_packet(pkt.parse_builder(builder)).raw)


def _fold(total: int) -> int:
  while total >> 16:
    total = (total & 0xFFFF) + (total >> 16)
  return total


def _fix_csums(f: bytearray) -> None:
  """Recompute BOTH checksums after patching addresses and ports.

  Fixing only the IPv4 one is not enough and the shortfall is not
  cosmetic: the NAT rewrite updates the L4 checksum INCREMENTALLY, so
  a wrong value going in stays wrong going out, and the soak's own
  witness would then record every translated churn frame as corrupt.
  A generator artefact that looks exactly like the defect being
  watched for is worse than no measurement.
  """
  struct.pack_into(">H", f, 24, 0)
  struct.pack_into(">H", f, 24,
                   (~_fold(sum(struct.unpack(">10H",
                                             bytes(f[14:34]))))) & 0xFFFF)
  tot_len = struct.unpack_from(">H", f, 16)[0]
  tcp_len = tot_len - 20
  struct.pack_into(">H", f, 34 + 16, 0)
  tcp = bytes(f[34:34 + tcp_len])
  if len(tcp) % 2:
    tcp += b"\x00"
  pseudo = bytes(f[26:34]) + struct.pack(">BBH", 0, 6, tcp_len)
  total = (sum(struct.unpack(f">{len(pseudo) // 2}H", pseudo))
           + sum(struct.unpack(f">{len(tcp) // 2}H", tcp)))
  struct.pack_into(">H", f, 34 + 16, (~_fold(total)) & 0xFFFF)


def steady_frames() -> list[bytes]:
  """One egress + one reply per guest, pre-built."""
  out = []
  for i in range(GUESTS):
    sport = 41000 + i
    out.append(bytes(_frame(
      f'tcp(src_ip="10.99.61.{1 + i}", dst_ip="{PEER}", '
      f'src_port={sport}, dst_port=443, syn=true)'
    )))
    out.append(bytes(_frame(
      f'tcp(src_ip="{PEER}", dst_ip="{MASQ}", src_port=443, '
      f'dst_port={sport}, ack=true)'
    )))
  return out


def main() -> int:
  s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
  s.bind((SEND_IF, 0))
  steady = steady_frames()
  noise = [
    bytes(_frame('udp(src_ip="10.99.62.1", dst_port=9999)')),
    bytes(_frame('udp(src_ip="10.99.62.3", '
                 'dst_ip="239.255.255.250", dst_port=1900)')),
    # Inbound port forward: hits the dnat rule, installs the reverse
    # mapping, and is answered by the internal host.
    bytes(_frame(f'tcp(src_ip="10.99.72.4", dst_ip="{MASQ}", '
                 'src_port=52000, dst_port=8080, syn=true)')),
  ]
  burst = bytes(_frame('udp(src_ip="10.99.60.5", dst_port=7000)'))
  # The churn template: patched per send so every packet is a new
  # reply-mapping key.
  churn = _frame(
    'tcp(src_ip="10.99.61.99", dst_ip="10.99.80.1", '
    'src_port=1024, dst_port=443, syn=true)'
  )
  n = 0
  churned = 0
  for i in itertools.count():
    for frame in steady:
      try:
        s.send(frame)
        n += 1
      except OSError:
        time.sleep(1)
    for frame in noise:
      try:
        s.send(frame)
        n += 1
      except OSError:
        pass
    # ~20 cycles/s at the 0.05 s sleep below, so one churn packet
    # every 20th cycle is ~1 new mapping per second.
    if i % 20 == 0:
      churn[31] = 80 + (churned >> 16) % 8
      churn[32] = (churned >> 8) & 0xFF
      churn[33] = 1 + (churned & 0x7F)
      struct.pack_into(">H", churn, 34, 20000 + (churned % 20000))
      _fix_csums(churn)
      try:
        s.send(bytes(churn))
        churned += 1
        n += 1
      except OSError:
        pass
    # Every ~30 s: a 2 s flood from the rate-limited subnet.
    if i % 600 == 0 and i > 0:
      for _ in range(2000):
        try:
          s.send(burst)
        except OSError:
          break
    if i % 12000 == 0:
      print(f"alive, {n} frames sent, {churned} churn flows",
            flush=True)
    time.sleep(0.05)
  return 0


if __name__ == "__main__":
  sys.exit(main())
