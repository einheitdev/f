"""Craft and send deliberately malformed frames.

`fwl.pkt` builders only produce well-formed packets, which is right
for the corpus but useless for asking "what does the datapath do
with a frame no honest sender would emit". This sends the ugly
cases: fragments, IP options, truncated L4, bad checksums, QinQ,
IPv6 extension headers, odd TCP flag combinations.

Usage: sendraw.py <iface> <count> <kind> [key=value ...]

Kinds (key=value overrides in parentheses):
  frag        non-first IPv4 fragment; its payload bytes are what a
              header-reading filter would see as L4
              (src_ip, dst_ip, proto, offset, sport, dport)
  firstfrag   first fragment (offset 0, MF set) with a real L4
              header (src_ip, dst_ip, sport, dport)
  ipopt       IPv4 with options, IHL>5 (src_ip, dst_ip, sport,
              dport, optlen — bytes of options, multiple of 4)
  shortip     IP total_length declares no L4 payload, but trailing
              bytes follow that a data_end-bounded read would treat
              as an L4 header (src_ip, dst_ip, sport, dport)
  tcpflags    arbitrary TCP flag byte (src_ip, dst_ip, sport,
              dport, flags — e.g. 0x29 XMAS, 0x00 NULL)
  badcsum     valid shape, deliberately wrong IPv4 header checksum
              (src_ip, dst_ip, sport, dport)
  qinq        802.1ad double VLAN tag (outer, inner, src_ip, dport)
  v6ext       IPv6 carrying a hop-by-hop extension header before
              TCP (src_ip6, dst_ip6, dport)
"""
import socket
import struct
import sys

SRC_MAC = b"\x02\x00\x00\x00\x00\x01"
DST_MAC = b"\x02\x00\x00\x00\x00\x02"
ETH_P_IP = 0x0800
ETH_P_IPV6 = 0x86DD
ETH_P_8021Q = 0x8100
ETH_P_8021AD = 0x88A8


def csum16(data: bytes) -> int:
  if len(data) % 2:
    data += b"\x00"
  total = sum(struct.unpack(f">{len(data) // 2}H", data))
  while total >> 16:
    total = (total & 0xFFFF) + (total >> 16)
  return (~total) & 0xFFFF


def ipv4(src, dst, proto, payload, *, frag_off=0, mf=False,
         options=b"", tot_len=None, bad_csum=False) -> bytes:
  ihl = 5 + len(options) // 4
  length = (tot_len if tot_len is not None
            else ihl * 4 + len(payload))
  flags_frag = (frag_off // 8) & 0x1FFF
  if mf:
    flags_frag |= 0x2000
  header = struct.pack(
    ">BBHHHBBH4s4s",
    0x40 | ihl, 0, length, 0x1234, flags_frag, 64, proto, 0,
    socket.inet_aton(src), socket.inet_aton(dst),
  ) + options
  chk = csum16(header)
  if bad_csum:
    chk ^= 0xFFFF
  header = header[:10] + struct.pack(">H", chk) + header[12:]
  return header + payload


def tcp_hdr(sport, dport, flags=0x02) -> bytes:
  return struct.pack(
    ">HHIIBBHHH", sport, dport, 0, 0, 0x50, flags, 8192, 0, 0
  )


def udp_hdr(sport, dport, payload=b"") -> bytes:
  return struct.pack(
    ">HHHH", sport, dport, 8 + len(payload), 0
  ) + payload


def eth(ethertype: int, payload: bytes) -> bytes:
  return DST_MAC + SRC_MAC + struct.pack(">H", ethertype) + payload


def build(kind: str, o: dict) -> bytes:
  src = o.get("src_ip", "10.99.20.1")
  dst = o.get("dst_ip", "10.99.20.9")
  sport = int(o.get("sport", 40000))
  dport = int(o.get("dport", 443))

  if kind == "frag":
    # A non-first fragment carries NO L4 header. These payload bytes
    # are ordinary data — but a filter that reads L4 at ihl*4 without
    # checking the fragment offset will parse them as one.
    proto = int(o.get("proto", 6))
    fake = struct.pack(">HH", sport, dport) + bytes(28)
    return eth(ETH_P_IP, ipv4(
      src, dst, proto, fake,
      frag_off=int(o.get("offset", 8)), mf=False,
    ))

  if kind == "firstfrag":
    return eth(ETH_P_IP, ipv4(
      src, dst, 6, tcp_hdr(sport, dport) + bytes(8),
      frag_off=0, mf=True,
    ))

  if kind == "ipopt":
    optlen = int(o.get("optlen", 4))
    # NOP padding then End-of-Option-List, a legal option block.
    options = b"\x01" * (optlen - 1) + b"\x00"
    return eth(ETH_P_IP, ipv4(
      src, dst, 6, tcp_hdr(sport, dport), options=options,
    ))

  if kind == "shortip":
    # tot_len covers the IP header only: per the IP layer there is
    # no L4 payload. The trailing bytes are still on the wire.
    trailing = tcp_hdr(sport, dport)
    return eth(ETH_P_IP, ipv4(
      src, dst, 6, trailing, tot_len=20,
    ))

  if kind == "tcpflags":
    flags = int(str(o.get("flags", "0x29")), 0)
    return eth(ETH_P_IP, ipv4(
      src, dst, 6, tcp_hdr(sport, dport, flags),
    ))

  if kind == "badcsum":
    return eth(ETH_P_IP, ipv4(
      src, dst, 6, tcp_hdr(sport, dport), bad_csum=True,
    ))

  if kind == "qinq":
    outer = int(o.get("outer", 100))
    inner = int(o.get("inner", 200))
    body = struct.pack(">HH", inner, ETH_P_IP) + ipv4(
      src, dst, 17, udp_hdr(sport, dport)
    )
    return (DST_MAC + SRC_MAC
            + struct.pack(">HH", ETH_P_8021AD, outer) + body)

  if kind == "v6ext":
    s6 = o.get("src_ip6", "2001:db8:99:aa::1")
    d6 = o.get("dst_ip6", "2001:db8:99:aa::2")
    l4 = tcp_hdr(sport, dport)
    # Hop-by-hop (next_header 0), 8 bytes, then TCP.
    ext = struct.pack(">BB", 6, 0) + bytes(6)
    payload = ext + l4
    v6 = struct.pack(
      ">IHBB16s16s", 0x60000000, len(payload), 0, 64,
      socket.inet_pton(socket.AF_INET6, s6),
      socket.inet_pton(socket.AF_INET6, d6),
    ) + payload
    return eth(ETH_P_IPV6, v6)

  raise SystemExit(f"unknown kind: {kind}")


def main() -> int:
  iface, count, kind = sys.argv[1], int(sys.argv[2]), sys.argv[3]
  opts = dict(a.split("=", 1) for a in sys.argv[4:])
  frame = build(kind, opts)
  s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
  s.bind((iface, 0))
  for _ in range(count):
    s.send(frame)
  s.close()
  print(f"sent {count} x {len(frame)}B '{kind}' out {iface} {opts}")
  return 0


if __name__ == "__main__":
  sys.exit(main())
