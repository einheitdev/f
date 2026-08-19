"""The soak's per-sample wire assertion.

A soak that only watches counters rise proves the daemon is alive, not
that it is still doing its job: every counter in this policy would keep
climbing with the NAT rewrite disabled entirely. So each sample sends a
known burst and reads the actual bytes back off the receiving port,
pairing every claim with an independent witness.

Three claims, all checked against the frame on the wire:

  1. EGRESS — a guest's packet leaves with the masquerade address as
     its source and a valid checksum, and its original address does
     not appear (no un-translated leak).
  2. LONG-LIVED MAPPING — the reply to a flow whose mapping was
     installed once, at soak start, is still de-NAT'd to that guest.
     This is the claim a long run exists to test: `fwl_nat` has no
     aging path, but it is a fixed-size hash that survives reloads and
     restarts, so "does an hours-old mapping still resolve" is a real
     question and nothing else asks it.
  3. FRESH MAPPING — a brand-new flow installs a mapping and its reply
     de-NATs, i.e. the table has not silently stopped accepting
     inserts (which is exactly what it does once full).

Usage:
  natsoak_probe.py --install <send_if>          once, at soak start
  natsoak_probe.py <send_if> <recv_if> <port>   one sample
"""
import json
import socket
import struct
import sys
import threading
import time

sys.path.insert(0, "/opt/fwl")
sys.path.insert(0, "/opt/fwl-deps")
sys.path.insert(0, "/opt/fwl/tests/system/hw")

from fwl import pkt  # noqa: E402
from sniff import checksums_ok  # noqa: E402

MASQ = "10.99.200.2"
PEER = "10.99.71.9"
# The guest whose mapping is installed once and then only ever read.
STABLE_GUEST = "10.99.61.200"
STABLE_PORT = 41200
# The guest used for a new flow every sample.
FRESH_GUEST = "10.99.61.201"
FRESH_PEER = "10.99.81.9"
BURST = 10


def build(builder: str) -> bytes:
  return pkt.build_packet(pkt.parse_builder(builder)).raw


def stable_egress() -> bytes:
  return build(f'tcp(src_ip="{STABLE_GUEST}", dst_ip="{PEER}", '
               f'src_port={STABLE_PORT}, dst_port=443, syn=true)')


def stable_reply() -> bytes:
  return build(f'tcp(src_ip="{PEER}", dst_ip="{MASQ}", src_port=443, '
               f'dst_port={STABLE_PORT}, ack=true)')


def fresh_egress(port: int) -> bytes:
  return build(f'tcp(src_ip="{FRESH_GUEST}", dst_ip="{FRESH_PEER}", '
               f'src_port={port}, dst_port=443, syn=true)')


def fresh_reply(port: int) -> bytes:
  return build(f'tcp(src_ip="{FRESH_PEER}", dst_ip="{MASQ}", '
               f'src_port=443, dst_port={port}, ack=true)')


def _key(frame: bytes) -> tuple | None:
  """(src_ip, src_port, dst_ip, dst_port, csum_ok) for IPv4 TCP."""
  if len(frame) < 54:
    return None
  if struct.unpack_from(">H", frame, 12)[0] != 0x0800:
    return None
  if frame[14 + 9] != 6:
    return None
  ihl = (frame[14] & 0x0F) * 4
  src = socket.inet_ntoa(frame[26:30])
  dst = socket.inet_ntoa(frame[30:34])
  sport, dport = struct.unpack_from(">HH", frame, 14 + ihl)
  return (src, sport, dst, dport, checksums_ok(frame, 14))


class Tap:
  """AF_PACKET reader on the receiving port, running while we send."""

  def __init__(self, iface: str):
    self.sock = socket.socket(
      socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003)
    )
    self.sock.bind((iface, 0))
    self.sock.setsockopt(
      socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024
    )
    self.sock.settimeout(0.2)
    self.seen: dict[tuple, int] = {}
    self.stop = False
    self.thread = threading.Thread(target=self._run, daemon=True)

  def _run(self):
    while not self.stop:
      try:
        frame, meta = self.sock.recvfrom(65535)
      except (socket.timeout, OSError):
        continue
      if meta[2] == socket.PACKET_OUTGOING:
        continue
      k = _key(frame)
      if k is not None:
        self.seen[k] = self.seen.get(k, 0) + 1

  def start(self):
    self.thread.start()

  def finish(self) -> dict:
    self.stop = True
    self.thread.join(timeout=2)
    self.sock.close()
    return self.seen

  def count(self, src, sport, dst, dport, ok=True) -> int:
    return self.seen.get((src, sport, dst, dport, ok), 0)


def install(send_if: str) -> int:
  s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
  s.bind((send_if, 0))
  frame = stable_egress()
  for _ in range(BURST):
    s.send(frame)
  s.close()
  print(json.dumps({"installed": STABLE_GUEST + ":"
                    + str(STABLE_PORT)}))
  return 0


def sample(send_if: str, recv_if: str, port: int) -> int:
  tap = Tap(recv_if)
  tap.start()
  time.sleep(0.3)
  s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
  s.bind((send_if, 0))
  frames = [
    fresh_egress(port),
    stable_reply(),
    fresh_reply(port),
  ]
  for frame in frames:
    for _ in range(BURST):
      s.send(frame)
    time.sleep(0.1)
  s.close()
  time.sleep(1.0)
  tap.finish()

  out = {
    # The fresh flow's outbound half, translated.
    "egress_ok": tap.count(MASQ, port, FRESH_PEER, 443),
    # ... and the same packet with the guest address still on it.
    "egress_leak": tap.count(FRESH_GUEST, port, FRESH_PEER, 443),
    # The hours-old mapping still resolves to its guest.
    "stable_denat": tap.count(PEER, 443, STABLE_GUEST, STABLE_PORT),
    # ... or was left addressed at the firewall itself.
    "stable_stranded": tap.count(PEER, 443, MASQ, STABLE_PORT),
    # A mapping installed seconds ago resolves.
    "fresh_denat": tap.count(FRESH_PEER, 443, FRESH_GUEST, port),
    "fresh_stranded": tap.count(FRESH_PEER, 443, MASQ, port),
    # Any of the six frames above that arrived with a checksum the
    # wire would reject: counted separately so "delivered" cannot hide
    # "corrupt". Scoped to THIS probe's exact 5-tuples — a broader
    # filter would sweep up the background generator's traffic and
    # report the generator as a firewall defect.
    "badcsum": sum(
      tap.count(*t, ok=False) for t in (
        (MASQ, port, FRESH_PEER, 443),
        (FRESH_GUEST, port, FRESH_PEER, 443),
        (PEER, 443, STABLE_GUEST, STABLE_PORT),
        (PEER, 443, MASQ, STABLE_PORT),
        (FRESH_PEER, 443, FRESH_GUEST, port),
        (FRESH_PEER, 443, MASQ, port),
      )
    ),
    "burst": BURST,
  }
  print(json.dumps(out))
  return 0


def main() -> int:
  if sys.argv[1] == "--install":
    return install(sys.argv[2])
  return sample(sys.argv[1], sys.argv[2], int(sys.argv[3]))


if __name__ == "__main__":
  sys.exit(main())
