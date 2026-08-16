"""Who asked for a MAC on this wire, and who answered.

The neighbour table says a next hop got resolved. It does not say by
WHAT — and that is the whole question when the claim is "this box
resolved its own next hop rather than being woken by something else".
A table entry looks identical whether `fd` asked for it, whether the
box's own dnsmasq happened to talk upstream, or whether the far side
ARPed first and Linux learned the sender.

So this listens on the wire itself and reports every ARP frame with its
sender. Run it in the namespace on the FAR side of the segment under
test: it is then an independent witness, on a host that is not the one
making the claim.

Output is one JSON object on stdout:

  {"frames": [{"op": "request"|"reply",
               "sender_ip": ..., "sender_mac": ...,
               "target_ip": ...}, ...]}

Usage: arp_witness.py <iface> <seconds>
"""
import json
import select
import socket
import struct
import sys
import time

ETH_P_ARP = 0x0806
# Ethernet header, then the ARP body we care about: hardware type,
# protocol type, lengths, opcode, then the four address fields.
_ARP = struct.Struct("!HHBBH6s4s6s4s")


def _mac(raw: bytes) -> str:
  """Colon-separated form of a six-byte hardware address."""
  return ":".join(f"{b:02x}" for b in raw)


def _ip(raw: bytes) -> str:
  """Dotted quad for a four-byte address."""
  return ".".join(str(b) for b in raw)


def capture(iface: str, seconds: float) -> dict:
  """Every ARP frame seen on `iface` for `seconds`."""
  sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                       socket.htons(ETH_P_ARP))
  sock.bind((iface, 0))
  sock.setblocking(False)
  frames = []
  deadline = time.monotonic() + seconds
  while time.monotonic() < deadline:
    ready, _, _ = select.select([sock], [], [], 0.25)
    if not ready:
      continue
    try:
      data = sock.recv(2048)
    except OSError:
      continue
    if len(data) < 14 + _ARP.size:
      continue
    body = data[14:14 + _ARP.size]
    (_htype, ptype, _hlen, plen, op, sha, spa, _tha,
     tpa) = _ARP.unpack(body)
    # IPv4 over Ethernet only. Anything else on this wire is not the
    # question, and decoding it would be guessing at the field offsets.
    if ptype != 0x0800 or plen != 4:
      continue
    frames.append({
      "op": {1: "request", 2: "reply"}.get(op, str(op)),
      "sender_ip": _ip(spa),
      "sender_mac": _mac(sha),
      "target_ip": _ip(tpa),
    })
  sock.close()
  return {"frames": frames}


def main() -> int:
  """Capture and print. Errors go to stderr, never into the JSON."""
  if len(sys.argv) != 3:
    print(__doc__, file=sys.stderr)
    return 2
  print(json.dumps(capture(sys.argv[1], float(sys.argv[2]))))
  return 0


if __name__ == "__main__":
  sys.exit(main())
