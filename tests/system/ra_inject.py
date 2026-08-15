#!/usr/bin/env python3
"""Inject IPv6 router advertisements, as an office router would.

This is the office's router, standing on the far end of the uplink
cable. It sends a well-formed RA with a prefix carrying the autonomous
flag, which is the entire mechanism by which a device on a flat L2
segment acquires a globally routable v6 address without ever asking
anybody.

    sudo ./ra_inject.py up0 --prefix 2001:db8:dead:: --count 3

The frame is hand-built from RFC 4861 §4.2 and §4.6.2 rather than
produced by any encoder of ours. Nothing in `f` writes RAs, so there
is no encoder to agree with — but the discipline still matters: the
kernel on the other end is the decoder under test, and it must be fed
something an actual router would emit, not something shaped like what
we expect to reject.

Exit status is 0 when the frames went out, so a test can tell "the
injector failed" from "the injector worked and nothing happened",
which are the two readings of a silent client.
"""
import argparse
import socket
import struct
import sys

ETH_P_IPV6 = 0x86DD
IPPROTO_ICMPV6 = 58
ND_ROUTER_ADVERT = 134

# RFC 4291 §2.7.1: the all-nodes link-local multicast group, and the
# Ethernet address it maps onto (RFC 2464 §7).
ALL_NODES = "ff02::1"
ALL_NODES_MAC = "33:33:00:00:00:01"


def mac_bytes(mac):
  """Six octets from aa:bb:cc:dd:ee:ff."""
  return bytes.fromhex(mac.replace(":", ""))


def link_local_from_mac(mac):
  """The modified EUI-64 link-local address a router would source from."""
  b = bytearray(mac_bytes(mac))
  b[0] ^= 0x02
  return (b"\xfe\x80" + b"\x00" * 6 + bytes(b[0:3]) + b"\xff\xfe" +
          bytes(b[3:6]))


def icmp6_checksum(src, dst, body):
  """RFC 4443 §2.3: the checksum covers an IPv6 pseudo-header."""
  pseudo = (src + dst + struct.pack("!I", len(body)) +
            b"\x00\x00\x00" + bytes([IPPROTO_ICMPV6]))
  data = pseudo + body
  if len(data) % 2:
    data += b"\x00"
  total = 0
  for i in range(0, len(data), 2):
    total += (data[i] << 8) | data[i + 1]
    total = (total & 0xFFFF) + (total >> 16)
  return (~total) & 0xFFFF


def build_ra(src_mac, prefix, prefix_len=64, lifetime=1800,
             valid=3600, preferred=1800, managed=False, other=False):
  """One router advertisement, Ethernet frame included."""
  src = link_local_from_mac(src_mac)
  dst = socket.inet_pton(socket.AF_INET6, ALL_NODES)

  flags = 0
  if managed:
    flags |= 0x80
  if other:
    flags |= 0x40

  # RFC 4861 §4.2: type, code, checksum, cur hop limit, flags,
  # router lifetime, reachable time, retrans timer.
  body = struct.pack("!BBHBBHII", ND_ROUTER_ADVERT, 0, 0, 64, flags,
                     lifetime, 0, 0)

  # §4.6.1 source link-layer address option.
  body += struct.pack("!BB", 1, 1) + mac_bytes(src_mac)

  # §4.6.2 prefix information. L (on-link) and A (autonomous) set: A
  # is the flag that makes a listening host form an address, which is
  # the whole bypass.
  body += (struct.pack("!BBBB", 3, 4, prefix_len, 0xC0) +
           struct.pack("!III", valid, preferred, 0) +
           socket.inet_pton(socket.AF_INET6, prefix))

  # Checksum in place.
  ck = icmp6_checksum(src, dst, body)
  body = body[:2] + struct.pack("!H", ck) + body[4:]

  # IPv6 header. Hop limit 255 is mandatory for neighbour discovery
  # (RFC 4861 §6.1.2); a receiver drops anything else, so getting it
  # wrong would produce a quiet client for the wrong reason.
  ip6 = (struct.pack("!IHBB", (6 << 28), len(body), IPPROTO_ICMPV6,
                     255) + src + dst)

  eth = (mac_bytes(ALL_NODES_MAC) + mac_bytes(src_mac) +
         struct.pack("!H", ETH_P_IPV6))
  return eth + ip6 + body


def main():
  ap = argparse.ArgumentParser(description=__doc__)
  ap.add_argument("iface", help="Interface to send from")
  ap.add_argument("--prefix", default="2001:db8:dead::",
                  help="Prefix to advertise")
  ap.add_argument("--prefix-len", type=int, default=64)
  ap.add_argument("--count", type=int, default=3,
                  help="How many advertisements to send")
  ap.add_argument("--lifetime", type=int, default=1800,
                  help="Router lifetime in seconds; 0 means 'not a "
                       "default router' but still carries the prefix")
  ap.add_argument("--src-mac", default=None,
                  help="Override the source MAC (default: the "
                       "interface's own)")
  args = ap.parse_args()

  sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
  sock.bind((args.iface, 0))
  src_mac = args.src_mac
  if src_mac is None:
    with open("/sys/class/net/%s/address" % args.iface) as fh:
      src_mac = fh.read().strip()

  frame = build_ra(src_mac, args.prefix, args.prefix_len,
                   args.lifetime)
  for _ in range(args.count):
    sock.send(frame)
  print("SENT %d ra(s) prefix=%s/%d from %s on %s len=%d"
        % (args.count, args.prefix, args.prefix_len, src_mac,
           args.iface, len(frame)))
  return 0


if __name__ == "__main__":
  sys.exit(main())
