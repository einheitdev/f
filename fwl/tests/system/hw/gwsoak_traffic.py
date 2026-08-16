"""Continuous gateway load for the office soak.

Three roles, one program, selected with `--role`:

  inside   Everything an inside zone sees. Steady masqueraded flows on
           a fixed set of source ports (so mappings are REFRESHED and
           the conntrack anchor stays warm), churn on fresh ports to
           fresh destinations (so `fwl_nat` fills at a rate we chose
           and its collector has something to collect), and the whole
           noise matrix the 2026-08-08 soak carried — multicast and
           NetBIOS into the drop rules, a sampled-logging flow, and a
           periodic flood from the rate-limited subnet.

  reply    The return half, injected on the far side of the uplink so
           the de-NAT pass, the conntrack composition and the redirect
           back to the inside zone are under load BETWEEN the once-a-
           minute real-socket probes rather than only during them.
           Replies are addressed to the masquerade address on the
           steady flows' own source ports, which the translation
           preserves in the absence of a collision — and the two inside
           zones are given disjoint port ranges precisely so there is
           no collision to work around.

Nothing here is evidence. Every frame this program sends is one a
promiscuous witness would count whether or not the firewall did
anything to it; the evidence is gwsoak.py's real sockets. What this is
for is LOAD — the tables, the collector, the rate-limit buckets and the
log ring under continuous pressure for days, so that the wire
assertions are being made against a box that has been working rather
than an idle one.

Run through gwsoak.py's transient units, not by hand.
"""
import argparse
import itertools
import socket
import struct
import sys
import time

sys.path.insert(0, "/opt/fwl")
sys.path.insert(0, "/opt/fwl-deps")

from fwl import pkt  # noqa: E402

SERVER = "10.99.210.9"
MASQ = "10.99.210.2"
# Disjoint per zone so two guests behind one masquerade address never
# want the same translated port. A collision is legal and handled
# (`port_reallocated` counts it), but it would make the reply role
# address a port the translation had moved, and this program must not
# manufacture the symptom it is here to keep pressure on.
# `churn` is likewise disjoint, and for a reason that only showed up on
# the wire: both zones masquerade to ONE address, so two zones walking
# the same source-port sequence to the same destination sequence
# collide on every churn flow. That path works — the allocator
# reallocates and counts it — but half the churn was being spent
# proving `port_reallocated` instead of filling the table at the rate
# this soak chose, and an occupancy curve is only readable if the
# arrival rate is the one on the label.
ZONES = {
  "a": {"net": "10.99.31", "guest": "10.99.31.5", "sport": 41000,
        "churn": 2000},
  "b": {"net": "10.99.32", "guest": "10.99.32.5", "sport": 42000,
        "churn": 32000},
}
CHURN_SPAN = 28000
STEADY_FLOWS = 6
CHURN_EVERY = 4        # cycles between churn frames -> ~5/s at 0.05 s
FLOOD_EVERY = 600      # cycles between rate-limit floods -> ~30 s
FLOOD_FRAMES = 2000
CYCLE_S = 0.05


def _mac(text: str) -> bytes:
  return bytes(int(b, 16) for b in text.split(":"))


def _frame(builder: str) -> bytearray:
  return bytearray(pkt.build_packet(pkt.parse_builder(builder)).raw)


def _set_macs(frame: bytearray, dst: str, src: str) -> None:
  if dst:
    frame[0:6] = _mac(dst)
  if src:
    frame[6:12] = _mac(src)


def _fold(total: int) -> int:
  while total >> 16:
    total = (total & 0xFFFF) + (total >> 16)
  return total


def fix_csums(frame: bytearray) -> None:
  """Recompute BOTH checksums after patching addresses and ports.

  Fixing only the IPv4 one is not enough and the shortfall is not
  cosmetic: the NAT rewrite updates the L4 checksum INCREMENTALLY, so a
  wrong value going in stays wrong going out, the far stack drops the
  frame, and the soak's own witness records a generator artefact as a
  firewall defect. A bench that manufactures the symptom it watches for
  is worse than no bench.
  """
  struct.pack_into(">H", frame, 24, 0)
  struct.pack_into(
    ">H", frame, 24,
    (~_fold(sum(struct.unpack(">10H", bytes(frame[14:34]))))) & 0xFFFF)
  proto = frame[14 + 9]
  tot_len = struct.unpack_from(">H", frame, 16)[0]
  l4_len = tot_len - 20
  csum_off = 34 + (16 if proto == 6 else 6)
  struct.pack_into(">H", frame, csum_off, 0)
  l4 = bytes(frame[34:34 + l4_len])
  if len(l4) % 2:
    l4 += b"\x00"
  pseudo = bytes(frame[26:34]) + struct.pack(">BBH", 0, proto, l4_len)
  total = (sum(struct.unpack(f">{len(pseudo) // 2}H", pseudo))
           + sum(struct.unpack(f">{len(l4) // 2}H", l4)))
  value = (~_fold(total)) & 0xFFFF
  # A UDP checksum of zero means "not computed"; the wire spelling for
  # a computed zero is 0xFFFF.
  if proto == 17 and value == 0:
    value = 0xFFFF
  struct.pack_into(">H", frame, csum_off, value)


def patch_churn(frame: bytearray, zone: dict, churned: int) -> None:
  """Walk one churn frame to the next distinct flow key.

  Byte 26..29 is the source address and 30..33 the destination, so the
  third and fourth octets of the destination are 32 and 33. Getting
  that wrong — as the first writing did — walks the churn out of the
  black-holed /22 and into addresses the box would try to resolve
  forever, which is exactly the reading a long run exists to take.
  Named, so `test_gwsoak.py` can assert the shipped arithmetic against
  `inet_ntoa` instead of reimplementing it and agreeing with itself.
  """
  frame[29] = 100 + (churned // CHURN_SPAN) % 100   # src host
  frame[32] = 240 + ((churned >> 8) & 0x03)         # dst /22
  frame[33] = churned & 0xFF
  struct.pack_into(">H", frame, 34,
                   zone["churn"] + (churned % CHURN_SPAN))
  fix_csums(frame)


def _sock(iface: str) -> socket.socket:
  s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
  s.bind((iface, 0))
  return s


def run_inside(args) -> int:
  """One inside zone's whole workload."""
  zone = ZONES[args.zone]
  net, guest, sport0 = zone["net"], zone["guest"], zone["sport"]

  steady = []
  for i in range(STEADY_FLOWS):
    frame = _frame(f'tcp(src_ip="{guest}", dst_ip="{SERVER}", '
                   f'src_port={sport0 + i}, dst_port=443, syn=true)')
    _set_macs(frame, args.dst_mac, args.src_mac)
    steady.append(bytes(frame))

  # Every noise frame carries an EXPLICIT destination on the uplink
  # segment. The builder default routes out the box's own default
  # gateway, which is the management port — so the sampled-logging flow
  # (the one noise frame no `drop` rule catches) matched
  # `redirect to wanz` while the FIB answered a different interface,
  # and the datapath correctly refused: `off_zone` and the L2-adjacent
  # `bridged` fallback climbed at 40/s. That is the guard working, and
  # it made `bridged` — the one number that says a routed forward
  # silently became a bridged one — useless as an alarm for the whole
  # run. A bench must not spend the alarm it is meant to be watching.
  noise = []
  for builder in (
      f'udp(src_ip="{net}.201", dst_ip="{SERVER}", dst_port=9999)',
      f'udp(src_ip="{net}.202", dst_ip="{SERVER}", dst_port=137)',
      f'udp(src_ip="{net}.203", dst_ip="239.255.255.250", '
      f'dst_port=1900)',
  ):
    frame = _frame(builder)
    _set_macs(frame, args.dst_mac, args.src_mac)
    noise.append(bytes(frame))

  flood = _frame('udp(src_ip="10.99.60.5", dst_port=7000)')
  _set_macs(flood, args.dst_mac, args.src_mac)
  flood = bytes(flood)

  # The churn template, patched per send so every packet is a distinct
  # reply-mapping key. Its destinations live in the black-holed network
  # gwsoak.py routes via a permanent neighbour entry, so the frames are
  # genuinely ROUTED and solicit nothing.
  churn = _frame(f'tcp(src_ip="{net}.100", dst_ip="10.99.240.1", '
                 f'src_port=1024, dst_port=443, syn=true)')
  _set_macs(churn, args.dst_mac, args.src_mac)

  sock = _sock(args.iface)
  sent = churned = 0
  for cycle in itertools.count():
    for frame in steady:
      try:
        sock.send(frame)
        sent += 1
      except OSError:
        time.sleep(1)
    for frame in noise:
      try:
        sock.send(frame)
        sent += 1
      except OSError:
        pass
    if cycle % CHURN_EVERY == 0:
      patch_churn(churn, zone, churned)
      try:
        sock.send(bytes(churn))
        churned += 1
        sent += 1
      except OSError:
        pass
    if cycle % FLOOD_EVERY == 0 and cycle:
      for _ in range(FLOOD_FRAMES):
        try:
          sock.send(flood)
          sent += 1
        except OSError:
          break
    if cycle % 12000 == 0:
      print(f"zone {args.zone}: {sent} frames, {churned} churn flows",
            flush=True)
    time.sleep(CYCLE_S)
  return 0


def run_reply(args) -> int:
  """The return half, injected on the uplink's far side.

  Every frame here is an ACK from the far side addressed to the
  masquerade address on a steady flow's own source port. It has to be
  de-NATed to the guest, matched as `established` on the tuple it
  carries on the wire, and redirected back into the inside zone — the
  three things the uplink zone exists to do, kept under load between
  the real-socket probes.
  """
  frames = []
  for zone in ZONES.values():
    for i in range(STEADY_FLOWS):
      frame = _frame(f'tcp(src_ip="{SERVER}", dst_ip="{MASQ}", '
                     f'src_port=443, dst_port={zone["sport"] + i}, '
                     f'ack=true)')
      _set_macs(frame, args.dst_mac, args.src_mac)
      fix_csums(frame)
      frames.append(bytes(frame))

  sock = _sock(args.iface)
  sent = 0
  for cycle in itertools.count():
    for frame in frames:
      try:
        sock.send(frame)
        sent += 1
      except OSError:
        time.sleep(1)
    if cycle % 600 == 0:
      print(f"reply: {sent} frames", flush=True)
    time.sleep(1.0)
  return 0


def main() -> int:
  parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
  parser.add_argument("--role", choices=("inside", "reply"),
                      required=True)
  parser.add_argument("--iface", required=True)
  parser.add_argument("--zone", choices=tuple(ZONES), default="a")
  parser.add_argument("--dst-mac", default="")
  parser.add_argument("--src-mac", default="")
  args = parser.parse_args()
  return (run_inside if args.role == "inside" else run_reply)(args)


if __name__ == "__main__":
  sys.exit(main())
