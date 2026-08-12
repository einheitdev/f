#!/usr/bin/env python3
"""Send a DHCPDISCOVER on one interface and report whether it is
answered.

This is the wire witness for the rogue-DHCP gate. It exists to answer
one question about a running dnsmasq: *does anything offer me a lease
on this port?*

Frames are built by hand from RFC 2131 rather than with a library the
product also uses, for the same reason `lldp_inject.py` does: a test
that encodes and decodes with the same code proves only that the code
agrees with itself.

Usage:
  sudo ./dhcp_probe.py <interface> [--timeout 4] [--tries 3]

Prints one of:
  OFFER yiaddr=<addr> server=<addr>
  NO_OFFER

Exit status is 0 when an offer arrived and 1 when none did, so a
caller can branch either way — but the harness reads stdout, because
"no offer" is a result, not an error.
"""
import argparse
import fcntl
import os
import random
import select
import socket
import struct
import sys
import time

ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800
SIOCGIFHWADDR = 0x8927

DHCP_MAGIC = b"\x63\x82\x53\x63"
DHCPDISCOVER = 1
DHCPOFFER = 2

OPT_MSG_TYPE = 53
OPT_PARAM_REQ = 55
OPT_SERVER_ID = 54
OPT_END = 255


def hwaddr(iface):
  """The interface's MAC, read from the kernel rather than invented."""
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  try:
    info = fcntl.ioctl(
      s.fileno(), SIOCGIFHWADDR,
      struct.pack("256s", iface.encode()[:15]))
    return info[18:24]
  finally:
    s.close()


def checksum16(data):
  """Standard internet checksum over an even-padded buffer."""
  if len(data) % 2:
    data += b"\x00"
  total = 0
  for i in range(0, len(data), 2):
    total += (data[i] << 8) + data[i + 1]
  while total >> 16:
    total = (total & 0xFFFF) + (total >> 16)
  return (~total) & 0xFFFF


def build_options(mac, hostname):
  """DHCP options: message type, requested params, client id, end."""
  opts = bytes([OPT_MSG_TYPE, 1, DHCPDISCOVER])
  # subnet mask, router, dns, domain name, broadcast
  opts += bytes([OPT_PARAM_REQ, 5, 1, 3, 6, 15, 28])
  # client identifier: hardware type 1 + MAC
  opts += bytes([61, 7, 1]) + mac
  name = hostname.encode()
  opts += bytes([12, len(name)]) + name
  opts += bytes([OPT_END])
  # RFC 2131 wants a BOOTP payload of at least 300 bytes; a server may
  # drop anything shorter.
  return opts


def build_bootp(mac, xid, hostname):
  """The BOOTP/DHCP payload of a DISCOVER."""
  pkt = struct.pack(
    "!BBBBIHHIIII",
    1,        # op: BOOTREQUEST
    1,        # htype: ethernet
    6,        # hlen
    0,        # hops
    xid,
    0,        # secs
    0x8000,   # flags: broadcast — we have no address to unicast to
    0,        # ciaddr
    0,        # yiaddr
    0,        # siaddr
    0,        # giaddr
  )
  pkt += mac + b"\x00" * 10   # chaddr, padded to 16
  pkt += b"\x00" * 64          # sname
  pkt += b"\x00" * 128         # file
  pkt += DHCP_MAGIC
  pkt += build_options(mac, hostname)
  if len(pkt) < 300:
    pkt += b"\x00" * (300 - len(pkt))
  return pkt


def build_frame(mac, xid, hostname):
  """A complete broadcast Ethernet/IPv4/UDP/DHCP DISCOVER frame."""
  payload = build_bootp(mac, xid, hostname)

  udp_len = 8 + len(payload)
  src_ip = b"\x00\x00\x00\x00"
  dst_ip = b"\xff\xff\xff\xff"
  udp = struct.pack("!HHHH", 68, 67, udp_len, 0) + payload
  pseudo = src_ip + dst_ip + struct.pack("!BBH", 0, 17, udp_len)
  csum = checksum16(pseudo + udp)
  if csum == 0:
    csum = 0xFFFF
  udp = struct.pack("!HHHH", 68, 67, udp_len, csum) + payload

  total_len = 20 + udp_len
  ip = struct.pack(
    "!BBHHHBBH", 0x45, 0, total_len, random.randint(0, 0xFFFF),
    0, 64, 17, 0) + src_ip + dst_ip
  ip = ip[:10] + struct.pack("!H", checksum16(ip)) + ip[12:]

  frame = b"\xff" * 6 + mac + struct.pack("!H", ETH_P_IP) + ip + udp
  if len(frame) < 60:
    frame += b"\x00" * (60 - len(frame))
  return frame


def parse_offer(frame, xid, mac):
  """Return (yiaddr, server) when `frame` is a DHCPOFFER for us."""
  if len(frame) < 14 + 20 + 8 + 240:
    return None
  if struct.unpack("!H", frame[12:14])[0] != ETH_P_IP:
    return None
  ip = frame[14:]
  ihl = (ip[0] & 0x0F) * 4
  if ip[9] != 17:
    return None
  udp = ip[ihl:]
  sport, dport = struct.unpack("!HH", udp[0:4])
  if dport != 68 or sport != 67:
    return None
  boot = udp[8:]
  if len(boot) < 240 or boot[0] != 2:
    return None
  if struct.unpack("!I", boot[4:8])[0] != xid:
    return None
  if boot[28:34] != mac:
    return None
  if boot[236:240] != DHCP_MAGIC:
    return None

  yiaddr = socket.inet_ntoa(boot[16:20])
  msg_type = None
  server = socket.inet_ntoa(boot[20:24])
  i = 240
  while i < len(boot):
    code = boot[i]
    if code == OPT_END:
      break
    if code == 0:
      i += 1
      continue
    if i + 1 >= len(boot):
      break
    length = boot[i + 1]
    body = boot[i + 2:i + 2 + length]
    if code == OPT_MSG_TYPE and length == 1:
      msg_type = body[0]
    elif code == OPT_SERVER_ID and length == 4:
      server = socket.inet_ntoa(body)
    i += 2 + length
  if msg_type != DHCPOFFER:
    return None
  return yiaddr, server


def probe(iface, timeout, tries):
  """Broadcast a DISCOVER on `iface` and wait for an OFFER."""
  mac = hwaddr(iface)
  xid = random.getrandbits(32)
  hostname = "f-probe-%s" % iface

  sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                       socket.htons(ETH_P_ALL))
  sock.bind((iface, 0))
  sock.setblocking(False)

  frame = build_frame(mac, xid, hostname)
  deadline = time.time() + timeout
  next_send = 0.0
  sent = 0
  while time.time() < deadline:
    now = time.time()
    if now >= next_send and sent < tries:
      sock.send(frame)
      sent += 1
      next_send = now + max(0.2, timeout / (tries + 1))
    remaining = min(0.25, max(0.0, deadline - now))
    ready, _, _ = select.select([sock], [], [], remaining)
    if not ready:
      continue
    try:
      data = sock.recv(65535)
    except BlockingIOError:
      continue
    hit = parse_offer(data, xid, mac)
    if hit:
      return hit
  return None


def main():
  ap = argparse.ArgumentParser(description=__doc__)
  ap.add_argument("interface")
  ap.add_argument("--timeout", type=float, default=4.0)
  ap.add_argument("--tries", type=int, default=3)
  args = ap.parse_args()

  if os.geteuid() != 0:
    print("dhcp_probe.py needs root for AF_PACKET", file=sys.stderr)
    return 2

  hit = probe(args.interface, args.timeout, args.tries)
  if hit is None:
    print("NO_OFFER")
    return 1
  print("OFFER yiaddr=%s server=%s" % hit)
  return 0


if __name__ == "__main__":
  sys.exit(main())
