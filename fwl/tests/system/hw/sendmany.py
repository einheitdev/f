"""Batch AF_PACKET sender for the hardware tests.

Two modes:

  sendmany.py <iface> <count> '<builder>'
    Send <count> copies of the fwl.pkt builder frame out <iface>.
    The frame carries the builder-default MACs
    (02:00:00:00:00:01 -> 02:00:00:00:00:02), which hw::teach_fdb has
    already taught to the switch.

  sendmany.py --teach <recv_iface> <send_iface>
    Teach the EX2300 FDB where the two builder MACs live: the dst MAC
    (..:02) on the receiving port, the src MAC (..:01) on the sending
    port. Uses inert experimental EtherType 0x88B5 frames. The first
    frame may flood once within the test VLAN (unknown unicast); every
    later test frame unicasts port-to-port.
"""
import socket
import sys

from fwl import pkt

SRC_MAC = b"\x02\x00\x00\x00\x00\x01"
DST_MAC = b"\x02\x00\x00\x00\x00\x02"
TEACH_ETHERTYPE = b"\x88\xb5"

def _raw_socket(iface: str) -> socket.socket:
  s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
  s.bind((iface, 0))
  return s

def teach(recv_iface: str, send_iface: str) -> None:
  """Seed the switch FDB with the builder MACs.

  A frame's SOURCE MAC is what the switch learns on the ingress port.
  """
  pad = b"FWL-FDB-TEACH" + bytes(47)
  # From the receiving port, source ..:02: the switch learns ..:02 on
  # the recv port. dst ..:01 is unknown at this instant, so this one
  # frame may flood once within the test VLAN (inert EtherType).
  s = _raw_socket(recv_iface)
  for _ in range(2):
    s.send(SRC_MAC + DST_MAC + TEACH_ETHERTYPE + pad)
  s.close()
  # From the sending port, source ..:01: learned on the send port.
  # dst ..:02 is known now, so this unicasts to the recv port only.
  s = _raw_socket(send_iface)
  for _ in range(2):
    s.send(DST_MAC + SRC_MAC + TEACH_ETHERTYPE + pad)
  s.close()

def probe(send_iface: str, recv_iface: str, timeout: float) -> bool:
  """Wait until the send->switch->recv path actually forwards.

  XDP attach resets the igb NICs; the link and the switch port need
  seconds to renegotiate and re-enter forwarding. Sends an inert
  teach-style frame every 0.5 s and listens for it on the receiving
  port; returns True once one crosses.
  """
  import select
  import time
  rx = socket.socket(
    socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x88B5)
  )
  rx.bind((recv_iface, 0))
  rx.setblocking(False)
  tx = _raw_socket(send_iface)
  pad = b"FWL-WIRE-PROBE" + bytes(46)
  deadline = time.monotonic() + timeout
  ok = False
  while time.monotonic() < deadline and not ok:
    try:
      tx.send(DST_MAC + SRC_MAC + TEACH_ETHERTYPE + pad)
    except OSError:
      # Link still down; keep trying.
      time.sleep(0.5)
      continue
    readable, _, _ = select.select([rx], [], [], 0.5)
    for sock in readable:
      try:
        frame, meta = sock.recvfrom(2048)
      except BlockingIOError:
        continue
      if meta[2] != socket.PACKET_OUTGOING and frame[12:14] == \
          TEACH_ETHERTYPE:
        ok = True
  tx.close()
  rx.close()
  return ok

def send(iface: str, count: int, builder: str) -> None:
  import time
  frame = pkt.build_packet(pkt.parse_builder(builder)).raw
  s = _raw_socket(iface)
  for i in range(count):
    s.send(frame)
    # Light pacing so receiver-side witnesses keep up; ~10k fps still
    # floods any per-second rate limit a test configures.
    if i % 100 == 99:
      time.sleep(0.01)
  s.close()
  print(f"sent {count} x {len(frame)}B out {iface}: {builder}")

def main() -> int:
  if sys.argv[1] == "--teach":
    teach(sys.argv[2], sys.argv[3])
    return 0
  if sys.argv[1] == "--probe":
    # --probe <send_iface> <recv_iface> <timeout_s>
    if probe(sys.argv[2], sys.argv[3], float(sys.argv[4])):
      print("wire live")
      return 0
    print("wire dead: probe frames never crossed", file=sys.stderr)
    return 1
  send(sys.argv[1], int(sys.argv[2]), sys.argv[3])
  return 0

if __name__ == "__main__":
  sys.exit(main())
