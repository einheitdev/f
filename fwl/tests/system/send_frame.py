"""Send one FWL-builder frame out an interface via AF_PACKET.

Reuses the firewall's own packet builder (fwl.pkt) so the netns system
test sends exactly the bytes a `.pkt` case describes. Run inside the
sender namespace; the frame goes out `iface` (the veth peer), arrives on
the XDP-attached interface, and — when the firewall redirects — crosses
to the destination zone's interface.

Usage: send_frame.py <iface> '<builder>'
"""
import socket
import sys

from fwl import pkt


def main() -> int:
  iface, builder = sys.argv[1], sys.argv[2]
  frame = pkt.build_packet(pkt.parse_builder(builder)).raw
  s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
  s.bind((iface, 0))
  s.send(frame)
  s.close()
  print(f"sent {len(frame)} bytes out {iface}: {builder}")
  return 0


if __name__ == "__main__":
  sys.exit(main())
