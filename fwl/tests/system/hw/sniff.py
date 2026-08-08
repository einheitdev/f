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

With --detail (NAT evidence), TCP/UDP keys instead carry both
addresses and a checksum verdict:
  tcp:<src_ip>>{dst_ip}:<dst_port>:<ok|badcsum>

Usage: sniff.py <iface> <seconds> [--detail]
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

def _fold(total: int) -> int:
  while total >> 16:
    total = (total & 0xFFFF) + (total >> 16)
  return total

def _sum16(data: bytes) -> int:
  if len(data) % 2:
    data += b"\x00"
  return sum(struct.unpack(f">{len(data) // 2}H", data))

def checksums_ok(frame: bytes, l3_off: int) -> bool:
  """Validate the IPv4 header checksum and the TCP/UDP checksum."""
  ihl = (frame[l3_off] & 0x0F) * 4
  ip_hdr = frame[l3_off:l3_off + ihl]
  if _fold(_sum16(ip_hdr)) != 0xFFFF:
    return False
  proto = frame[l3_off + 9]
  if proto not in (6, 17):
    return True
  total_len = struct.unpack_from(">H", frame, l3_off + 2)[0]
  l4 = frame[l3_off + ihl:l3_off + total_len]
  if proto == 17 and len(l4) >= 8:
    if struct.unpack_from(">H", l4, 6)[0] == 0:
      # UDP checksum 0 = "no checksum".
      return True
  pseudo = (frame[l3_off + 12:l3_off + 20]
            + bytes([0, proto])
            + struct.pack(">H", len(l4)))
  return _fold(_sum16(pseudo) + _sum16(l4)) == 0xFFFF

def flow_key(frame: bytes, detail: bool = False) -> str | None:
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
  dst_ip = socket.inet_ntoa(frame[l3_off + 16:l3_off + 20])
  if not (src_ip.startswith("10.99.")
          or dst_ip.startswith("10.99.")):
    return None
  l4_off = l3_off + ihl
  if proto == 6 or proto == 17:
    if len(frame) < l4_off + 4:
      return None
    dst_port = struct.unpack_from(">H", frame, l4_off + 2)[0]
    name = "tcp" if proto == 6 else "udp"
    if detail:
      verdict = "ok" if checksums_ok(frame, l3_off) else "badcsum"
      base = f"{name}:{src_ip}>{dst_ip}:{dst_port}:{verdict}"
    else:
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
  detail = "--detail" in sys.argv[3:]
  s = socket.socket(
    socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL)
  )
  s.bind((iface, 0))
  # Bursts land while we're parsing; a small default rcvbuf drops
  # frames the counters prove arrived. 8 MB absorbs any test burst.
  s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
  # The kernel software-untags 802.1Q before packet taps; the tag is
  # only recoverable via PACKET_AUXDATA ancillary data.
  sol_packet = getattr(socket, "SOL_PACKET", 263)
  PACKET_AUXDATA = 8
  s.setsockopt(sol_packet, PACKET_AUXDATA, 1)
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
        frame, ancdata, _flags, meta = s.recvmsg(65535, 4096)
      except BlockingIOError:
        break
      # Only ingress frames; outgoing copies would double-count.
      if meta[2] == socket.PACKET_OUTGOING:
        continue
      # Re-insert a kernel-stripped VLAN tag from the auxdata so
      # tagged flows keep their vlan<id>: key prefix.
      for lvl, typ, data in ancdata:
        if lvl == sol_packet and typ == PACKET_AUXDATA and \
            len(data) >= 20:
          status, _l, _sl, _mac, _net, tci, _tpid = \
            struct.unpack_from("IIIHHHH", data)
          TP_STATUS_VLAN_VALID = 1 << 4
          if status & TP_STATUS_VLAN_VALID:
            frame = (frame[:12]
                     + struct.pack(">HH", ETH_P_8021Q, tci)
                     + frame[12:])
          break
      key = flow_key(frame, detail)
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
