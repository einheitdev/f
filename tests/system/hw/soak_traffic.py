"""Continuous mixed traffic for the 48h soak, sent from the send
port through the EX2300 into the XDP port.

Cycles forever at a modest aggregate rate (~120 pps):
  - an "established" TCP flow (initiator SYN + replies)
  - allowed and dropped UDP
  - a logged UDP flow (log sample=100)
  - NetBIOS-port drops and IPv4-multicast drops (unicast MACs)
  - a periodic 2 s burst from the rate-limited subnet

Run via soak_start.sh (systemd transient unit), not by hand.
"""
import itertools
import sys
import time

from fwl import pkt

sys.path.insert(0, "/opt/fwl/tests/system/hw")

SEND_IF = "enp1s0f0"

def frames():
  builders = [
    # Initiator SYN (creates/refreshes the conntrack entry).
    'tcp(src_ip="10.99.61.1", dst_ip="10.99.61.9", src_port=41000, '
    'dst_port=443, syn=true)',
    # Replies ride the established state.
    'tcp(src_ip="10.99.61.9", dst_ip="10.99.61.1", src_port=443, '
    'dst_port=41000, ack=true)',
    'udp(src_ip="10.99.62.1", dst_port=9999)',
    'udp(src_ip="10.99.62.2", dst_port=137)',
    'udp(src_ip="10.99.62.3", dst_ip="239.255.255.250", '
    'dst_port=1900)',
    'udp(src_ip="10.99.62.4", dst_port=5060)',
  ]
  return [pkt.build_packet(pkt.parse_builder(b)).raw
          for b in builders]

def main() -> int:
  import socket
  s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
  s.bind((SEND_IF, 0))
  base = frames()
  burst = pkt.build_packet(pkt.parse_builder(
    'udp(src_ip="10.99.60.5", dst_port=7000)'
  )).raw
  n = 0
  for i in itertools.count():
    for frame in base:
      try:
        s.send(frame)
        n += 1
      except OSError:
        time.sleep(1)
    # Every ~30 s: a 2 s flood from the rate-limited subnet.
    if i % 600 == 0 and i > 0:
      for _ in range(2000):
        try:
          s.send(burst)
        except OSError:
          break
    if i % 12000 == 0:
      print(f"alive, {n} frames sent", flush=True)
    time.sleep(0.05)
  return 0

if __name__ == "__main__":
  sys.exit(main())
