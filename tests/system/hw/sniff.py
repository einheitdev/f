"""Receiving-port witness for the hardware tests.

Captures frames on <iface> for <seconds> via AF_PACKET (which taps
AFTER XDP on ingress — XDP_DROPped frames never appear here) and
tallies test frames by flow key. Only frames addressed within the
test ranges count (10.99.0.0/16 for v4, 2001:db8:99::/48 for v6);
switch chatter and household noise are ignored.

Key format (JSON object printed on exit):
  tcp:<src_ip>:<dst_port>    TCP frames
  udp:<src_ip>:<dst_port>    UDP frames
  icmp:<src_ip>:<type>       ICMP frames
  tcp6:<src_ip>:<dst_port>   IPv6 TCP frames (same for udp6/icmp6)
  vlan<id>:<proto>:<src_ip>  802.1Q-tagged frames

With --detail (NAT evidence), TCP/UDP keys instead carry both
addresses and a checksum verdict:
  tcp:<src_ip>>{dst_ip}:<dst_port>:<ok|badcsum>
and ICMP keys carry both addresses plus type and code:
  icmp:<src_ip>>{dst_ip}:<type>.<code>
An ICMP ERROR additionally gets a second key naming the datagram it
CARRIES, which is the half an outer-header witness cannot see:
  icmperr:<delivered_to>:<inner_src>:<inner_sport>>{inner_dst}:<inner_dport>:<ok|badcsum>
The verdict covers all three checksums an RFC 5508 rewrite touches
(outer IP, the ICMP checksum over the embedded datagram, and the
embedded IP header's own).

With --srcport (on top of --detail), the TCP/UDP key also names the
SOURCE port:
  tcp:<src_ip>:<src_port>>{dst_ip}:<dst_port>:<ok|badcsum>
That is the only way to witness whether a NAT rewrote the port or
preserved it, which is the difference between a masquerade that can
multiplex several hosts and one that cannot.

Usage: sniff.py <iface> <seconds> [--detail] [--srcport]
"""
import json
import select
import socket
import struct
import sys
import time

ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800
ETH_P_IPV6 = 0x86DD
ETH_P_8021Q = 0x8100
# 802.1ad (QinQ) outer tag. v0.4 does not parse it, but the witness
# must still see such frames: otherwise a dropped frame and
# an unobservable one look identical.
ETH_P_8021AD = 0x88A8
# Test traffic lives in 10.99.0.0/16 (v4) and 2001:db8:99::/48 (v6);
# everything else on the wire is ambient noise to be ignored.
V4_TEST_PREFIX = "10.99."
V6_TEST_PREFIX = "2001:db8:99:"


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


# ICMPv4 types carrying the datagram that provoked them (RFC 792).
ICMP_ERROR_TYPES = frozenset({3, 4, 5, 11, 12})


def icmp_error_key(frame: bytes) -> str | None:
  """A second key for an ICMP error, naming its EMBEDDED datagram.

  The outer key says who the error was delivered to. That is half the
  question: an RFC 5508 translation rewrites the embedded header too,
  and an error that reaches the right host still describing the
  translated connection is discarded by that host's own stack — the
  same black hole as never delivering it, reached quietly. Without
  this, the wire could not tell the two apart.

  Key: `icmperr:<delivered_to>:<inner_src>:<inner_sport}>
  {inner_dst>:<inner_dport>:<ok|badcsum>` — the whole property in one
  key, checksums included, so a test asserts it with one number.
  Returns None for anything that is not a complete IPv4 ICMP error
  inside the test ranges.
  """
  if len(frame) < 34:
    return None
  ethertype = struct.unpack_from(">H", frame, 12)[0]
  l3_off = 14
  if ethertype == ETH_P_8021Q:
    if len(frame) < 38:
      return None
    ethertype = struct.unpack_from(">H", frame, 16)[0]
    l3_off = 18
  if ethertype != ETH_P_IP:
    return None
  if len(frame) < l3_off + 20 or frame[l3_off + 9] != 1:
    return None
  ihl = (frame[l3_off] & 0x0F) * 4
  icmp_off = l3_off + ihl
  in_off = icmp_off + 8
  in_l4 = in_off + 20
  if len(frame) < in_l4 + 8:
    return None
  if frame[icmp_off] not in ICMP_ERROR_TYPES:
    return None
  if (frame[in_off] & 0x0F) != 5:
    return None
  dst_ip = socket.inet_ntoa(frame[l3_off + 16:l3_off + 20])
  in_src = socket.inet_ntoa(frame[in_off + 12:in_off + 16])
  in_dst = socket.inet_ntoa(frame[in_off + 16:in_off + 20])
  if not (dst_ip.startswith(V4_TEST_PREFIX)
          or in_src.startswith(V4_TEST_PREFIX)):
    return None
  if frame[in_off + 9] in (6, 17):
    in_sp, in_dp = struct.unpack_from(">HH", frame, in_l4)
  else:
    in_sp = in_dp = 0
  verdict = "ok" if icmp_error_csums_ok(frame, l3_off) else "badcsum"
  return (f"icmperr:{dst_ip}:{in_src}:{in_sp}>{in_dst}:{in_dp}"
          f":{verdict}")


def icmp_error_csums_ok(frame: bytes, l3_off: int) -> bool:
  """All three checksums an ICMP-error translation touches.

  Outer IP, the ICMP checksum (which covers the embedded datagram),
  and the embedded IP header's own. A rewrite that gets any of them
  wrong is discarded by the receiver in silence, which on this wire
  is indistinguishable from a firewall that never forwarded it.
  """
  ihl = (frame[l3_off] & 0x0F) * 4
  if _fold(_sum16(frame[l3_off:l3_off + ihl])) != 0xFFFF:
    return False
  total_len = struct.unpack_from(">H", frame, l3_off + 2)[0]
  if l3_off + total_len > len(frame) or total_len < ihl:
    return False
  icmp = frame[l3_off + ihl:l3_off + total_len]
  if _fold(_sum16(icmp)) != 0xFFFF:
    return False
  in_off = l3_off + ihl + 8
  if len(frame) < in_off + 20:
    return False
  in_ihl = (frame[in_off] & 0x0F) * 4
  if len(frame) < in_off + in_ihl:
    return False
  return _fold(_sum16(frame[in_off:in_off + in_ihl])) == 0xFFFF


def _v6_key(frame: bytes, l3_off: int, vlan_id) -> str | None:
  """Flow key for an IPv6 frame.

  v0.4 reads the fixed 40-byte header only (no extension-header
  walk), so the key mirrors that: next_header is treated as the
  protocol, exactly like the XDP program sees it. A frame carrying
  extension headers therefore keys on the extension type — which is
  the point when testing that the program does not match L4 rules on
  such a frame.
  """
  if len(frame) < l3_off + 40:
    return None
  next_hdr = frame[l3_off + 6]
  src = socket.inet_ntop(
    socket.AF_INET6, frame[l3_off + 8:l3_off + 24]
  )
  dst = socket.inet_ntop(
    socket.AF_INET6, frame[l3_off + 24:l3_off + 40]
  )
  if not (src.startswith(V6_TEST_PREFIX)
          or dst.startswith(V6_TEST_PREFIX)):
    return None
  l4_off = l3_off + 40
  if next_hdr in (6, 17):
    if len(frame) < l4_off + 4:
      return None
    dst_port = struct.unpack_from(">H", frame, l4_off + 2)[0]
    name = "tcp6" if next_hdr == 6 else "udp6"
    base = f"{name}:{src}:{dst_port}"
  elif next_hdr == 58:
    if len(frame) < l4_off + 2:
      return None
    base = f"icmp6:{src}:{frame[l4_off]}"
  else:
    base = f"v6nh{next_hdr}:{src}:0"
  if vlan_id is not None:
    return f"vlan{vlan_id}:{base}"
  return base


def flow_key(frame: bytes, detail: bool = False,
             srcport: bool = False) -> str | None:
  if len(frame) < 34:
    return None
  ethertype = struct.unpack_from(">H", frame, 12)[0]
  l3_off = 14
  vlan_id = None
  if ethertype == ETH_P_8021AD:
    # Outer 802.1ad tag, then an inner 802.1Q tag, then L3.
    if len(frame) < 22:
      return None
    outer = struct.unpack_from(">H", frame, 14)[0] & 0x0FFF
    inner = struct.unpack_from(">H", frame, 18)[0] & 0x0FFF
    return f"qinq{outer}.{inner}"
  if ethertype == ETH_P_8021Q:
    if len(frame) < 38:
      return None
    tci, ethertype = struct.unpack_from(">HH", frame, 14)
    vlan_id = tci & 0x0FFF
    l3_off = 18
  if ethertype == ETH_P_IPV6:
    return _v6_key(frame, l3_off, vlan_id)
  if ethertype != ETH_P_IP:
    return None
  ihl = (frame[l3_off] & 0x0F) * 4
  proto = frame[l3_off + 9]
  src_ip = socket.inet_ntoa(frame[l3_off + 12:l3_off + 16])
  dst_ip = socket.inet_ntoa(frame[l3_off + 16:l3_off + 20])
  if not (src_ip.startswith(V4_TEST_PREFIX)
          or dst_ip.startswith(V4_TEST_PREFIX)):
    return None
  l4_off = l3_off + ihl
  if proto == 6 or proto == 17:
    if len(frame) < l4_off + 4:
      return None
    src_port, dst_port = struct.unpack_from(">HH", frame, l4_off)
    name = "tcp" if proto == 6 else "udp"
    if detail:
      verdict = "ok" if checksums_ok(frame, l3_off) else "badcsum"
      left = f"{src_ip}:{src_port}" if srcport else src_ip
      base = f"{name}:{left}>{dst_ip}:{dst_port}:{verdict}"
    else:
      base = f"{name}:{src_ip}:{dst_port}"
  elif proto == 1:
    if len(frame) < l4_off + 2:
      return None
    if detail:
      # An ICMP error is only interesting together with WHO it was
      # delivered to: a frag-needed that reaches the NAT address but
      # not the host behind it has not been delivered at all.
      base = (f"icmp:{src_ip}>{dst_ip}:"
              f"{frame[l4_off]}.{frame[l4_off + 1]}")
    else:
      base = f"icmp:{src_ip}:{frame[l4_off]}"
  else:
    base = f"proto{proto}:{src_ip}:0"
  if vlan_id is not None:
    return f"vlan{vlan_id}:{base}"
  return base


def main() -> int:
  iface, seconds = sys.argv[1], float(sys.argv[2])
  detail = "--detail" in sys.argv[3:]
  srcport = "--srcport" in sys.argv[3:]
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
      key = flow_key(frame, detail, srcport)
      if key is not None:
        tallies[key] = tallies.get(key, 0) + 1
      if detail:
        deep = icmp_error_key(frame)
        if deep is not None:
          tallies[deep] = tallies.get(deep, 0) + 1
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
