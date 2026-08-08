"""Receiving-port witness for the hardware tests.

Captures frames on <iface> for <seconds> via AF_PACKET (which taps
AFTER XDP on ingress — XDP_DROPped frames never appear here) and
tallies test frames by flow key. Only frames whose IPv4 source is in
10.99.0.0/16 count; switch chatter and household noise are ignored.

Key format (JSON object printed on exit):
  tcp:<src_ip>:<dst_port>    TCP frames
  udp:<src_ip>:<dst_port>    UDP frames
  icmp:<src_ip>:<type>       ICMP frames
  vlan<id>:<proto>:<src_ip>  802.1Q-tagged frames

Usage: sniff.py <iface> <seconds>
"""
import json
import select
import socket
import struct
import sys
import time

ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800
ETH_P_8021Q = 0x8100

def flow_key(frame: bytes) -> str | None:
  if len(frame) < 34:
    return None
  ethertype = struct.unpack_from(">H", frame, 12)[0]
  l3_off = 14
  vlan_id = None
  if ethertype == ETH_P_8021Q:
    if len(frame) < 38:
      return None
    tci, ethertype = struct.unpack_from(">HH", frame, 14)
    vlan_id = tci & 0x0FFF
    l3_off = 18
  if ethertype != ETH_P_IP:
    return None
  ihl = (frame[l3_off] & 0x0F) * 4
  proto = frame[l3_off + 9]
  src_ip = socket.inet_ntoa(frame[l3_off + 12:l3_off + 16])
  if not src_ip.startswith("10.99."):
    return None
  l4_off = l3_off + ihl
  if proto == 6 or proto == 17:
    if len(frame) < l4_off + 4:
      return None
    dst_port = struct.unpack_from(">H", frame, l4_off + 2)[0]
    name = "tcp" if proto == 6 else "udp"
    base = f"{name}:{src_ip}:{dst_port}"
  elif proto == 1:
    if len(frame) < l4_off + 2:
      return None
    base = f"icmp:{src_ip}:{frame[l4_off]}"
  else:
    base = f"proto{proto}:{src_ip}:0"
  if vlan_id is not None:
    return f"vlan{vlan_id}:{base}"
  return base

def main() -> int:
  iface, seconds = sys.argv[1], float(sys.argv[2])
  s = socket.socket(
    socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL)
  )
  s.bind((iface, 0))
  # Bursts land while we're parsing; a small default rcvbuf drops
  # frames the counters prove arrived. 8 MB absorbs any test burst.
  s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
  s.setblocking(False)
  tallies: dict[str, int] = {}
  deadline = time.monotonic() + seconds
  while True:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
      break
    readable, _, _ = select.select([s], [], [], min(remaining, 0.2))
    if not readable:
      continue
    while True:
      try:
        frame, meta = s.recvfrom(65535)
      except BlockingIOError:
        break
      # Only ingress frames; outgoing copies would double-count.
      if meta[2] == socket.PACKET_OUTGOING:
        continue
      key = flow_key(frame)
      if key is not None:
        tallies[key] = tallies.get(key, 0) + 1
  # PACKET_STATISTICS: (packets, drops) since socket creation. A
  # non-zero drop count means a tally above under-reports.
  # SOL_PACKET (263) is absent from some python builds.
  sol_packet = getattr(socket, "SOL_PACKET", 263)
  stats = s.getsockopt(sol_packet, 6, 8)
  drops = struct.unpack("II", stats)[1]
  s.close()
  if drops:
    tallies["_socket_drops"] = drops
  json.dump(tallies, sys.stdout)
  print()
  return 0

if __name__ == "__main__":
  sys.exit(main())
