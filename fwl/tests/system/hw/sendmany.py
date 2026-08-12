"""Batch AF_PACKET sender for the hardware tests.

Two modes:

  sendmany.py <iface> <count> '<builder>'
    Send <count> copies of the fwl.pkt builder frame out <iface>.
    The frame carries the builder-default MACs
    (02:00:00:00:00:01 -> 02:00:00:00:00:02), which hw::teach_fdb has
    already taught to the switch.

  sendmany.py --burst <iface> <count> '<builder>' [<count> '<b>' ...]
    Send several bursts back to back out one interface, with every
    frame pre-built and one socket shared, so the gap between bursts
    is microseconds. Use when the bursts must land inside the same
    one-second rate-limit window.

  sendmany.py --teach <recv_iface> <send_iface>
    Teach the EX2300 FDB where the two builder MACs live: the dst MAC
    (..:02) on the receiving port, the src MAC (..:01) on the sending
    port. Uses inert experimental EtherType 0x88B5 frames. The first
    frame may flood once within the test VLAN (unknown unicast); every
    later test frame unicasts port-to-port.

  sendmany.py --reverse <iface> <count> '<builder>'
    As the plain form, but with the frame's source and destination MAC
    swapped, so it unicasts back down the taught path: out of the
    normal RECEIVING port, into the normal SENDING port. The builder
    hardcodes ..:01 -> ..:02, and the switch has learned ..:02 on the
    recv port, so an unmodified frame sent from there would be
    addressed at the port it left. Needed by any test where BOTH
    interfaces must receive traffic (a bundle whose zones each log).
    The receiving port must be promiscuous: ..:01 is not its hardware
    address, and native XDP runs after the NIC's MAC filter.
"""
import socket
import sys
import time

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

def probe(send_iface: str, recv_iface: str, timeout: float,
          reverse: bool = False) -> bool:
  """Wait until the send->switch->recv path actually forwards.

  XDP attach resets the igb NICs; the link and the switch port need
  seconds to renegotiate and re-enter forwarding. Sends an inert
  teach-style frame every 0.5 s and listens for it on the receiving
  port; returns True once one crosses.

  `reverse` probes the taught path backwards (out of the normal
  receiving port, into the normal sending port). The frame must be
  addressed the other way round for that: the switch has learned ..:02
  on the recv port, so a frame sent from there to ..:02 goes nowhere.
  The receiving end must be promiscuous, ..:01 not being its hardware
  address.
  """
  import select
  import time
  rx = socket.socket(
    socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x88B5)
  )
  rx.bind((recv_iface, 0))
  rx.setblocking(False)
  tx = _raw_socket(send_iface)
  macs = (SRC_MAC + DST_MAC) if reverse else (DST_MAC + SRC_MAC)
  pad = b"FWL-WIRE-PROBE" + bytes(46)
  deadline = time.monotonic() + timeout
  ok = False
  while time.monotonic() < deadline and not ok:
    try:
      tx.send(macs + TEACH_ETHERTYPE + pad)
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

def _swap_macs(frame: bytes) -> bytes:
  """Exchange the frame's destination and source MAC."""
  return frame[6:12] + frame[0:6] + frame[12:]


def send(iface: str, count: int, builder: str,
         pps: float | None = None, reverse: bool = False) -> None:
  import time
  frame = pkt.build_packet(pkt.parse_builder(builder)).raw
  if reverse:
    frame = _swap_macs(frame)
  s = _raw_socket(iface)
  if pps:
    # Steady paced stream (reload/soak tests): absolute schedule so
    # send() latency doesn't accumulate drift.
    start = time.monotonic()
    sent = 0
    for i in range(count):
      target = start + i / pps
      delay = target - time.monotonic()
      if delay > 0:
        time.sleep(delay)
      try:
        s.send(frame)
        sent += 1
      except OSError:
        # Link mid-reset (e.g. an XDP attach bounced it) — the lost
        # send IS the measurement; keep pacing.
        pass
    s.close()
    print(f"sent {sent}/{count} x {len(frame)}B out {iface} "
          f"at {pps}pps: {builder}")
    return
  for i in range(count):
    s.send(frame)
    # Light pacing so receiver-side witnesses keep up; ~10k fps still
    # floods any per-second rate limit a test configures.
    if i % 100 == 99:
      time.sleep(0.01)
  s.close()
  print(f"sent {count} x {len(frame)}B out {iface}: {builder}")

def burst(iface: str, specs: list[tuple[int, str]]) -> None:
  """Send several builder bursts back to back out one interface.

  Every frame is built and the socket opened BEFORE the first send, so
  the gap between bursts is a few microseconds rather than the ~0.3 s
  of a second Python start-up. That matters for any test whose subject
  is one-second-window state: two `hw::send` calls can straddle a
  window boundary, and the resulting flake looks exactly like the bug
  under test.
  """
  frames = [
    (count, pkt.build_packet(pkt.parse_builder(b)).raw, b)
    for count, b in specs
  ]
  s = _raw_socket(iface)
  sent = []
  for count, frame, _builder in frames:
    n = 0
    for i in range(count):
      s.send(frame)
      n += 1
      # Same light pacing as send(): keeps receiver-side witnesses up
      # without slowing the burst enough to matter to a 1 s window.
      if i % 100 == 99:
        time.sleep(0.01)
    sent.append(n)
  s.close()
  for (count, _frame, builder), n in zip(frames, sent):
    print(f"sent {n}/{count} out {iface}: {builder}")


def main() -> int:
  if sys.argv[1] == "--burst":
    # --burst <iface> <count> '<builder>' [<count> '<builder>' ...]
    rest = sys.argv[3:]
    specs = [
      (int(rest[i]), rest[i + 1]) for i in range(0, len(rest), 2)
    ]
    burst(sys.argv[2], specs)
    return 0
  if sys.argv[1] == "--teach":
    teach(sys.argv[2], sys.argv[3])
    return 0
  if sys.argv[1] == "--reverse":
    # --reverse <iface> <count> '<builder>'
    send(sys.argv[2], int(sys.argv[3]), sys.argv[4], reverse=True)
    return 0
  if sys.argv[1] in ("--probe", "--probe-rev"):
    # --probe[-rev] <send_iface> <recv_iface> <timeout_s>
    rev = sys.argv[1] == "--probe-rev"
    if probe(sys.argv[2], sys.argv[3], float(sys.argv[4]), reverse=rev):
      print("wire live")
      return 0
    print("wire dead: probe frames never crossed", file=sys.stderr)
    return 1
  if sys.argv[1] == "--pps":
    # --pps <rate> <iface> <count> <builder>
    send(sys.argv[3], int(sys.argv[4]), sys.argv[5],
         pps=float(sys.argv[2]))
    return 0
  send(sys.argv[1], int(sys.argv[2]), sys.argv[3])
  return 0

if __name__ == "__main__":
  sys.exit(main())
