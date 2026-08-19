#!/usr/bin/env python3
"""A real DNS exchange, for proving the appliance can forward one.

Two modes:

  server <bind> <port> <answer-ip> <count> <timeout_s> [--delay S]
      An authoritative-enough UDP responder: answers any A query with
      `answer-ip`. Runs on the far side of the firewall, in its own
      namespace with its own MAC, so a query only reaches it if the
      frame was addressed to it and was valid.

  query <resolver> <port> <name> <timeout_s>
      One A query, with a real answer parsed out of the reply.

Why not `dig`: the point of the scenario is the ANSWER — a unique
address only the far-side responder can produce — and a tool that
prints "status: NOERROR" invites an assertion on the status line, which
a cached or locally-synthesised answer satisfies just as well. Reporting
the address as JSON makes the check the address.

No scapy, no third-party DNS library: the rig has neither, and the
wire format needed here is a header, one question and one A record.
"""
import argparse
import json
import socket
import struct
import sys
import time

# A record, IN class.
TYPE_A = 1
CLASS_IN = 1


def encode_name(name: str) -> bytes:
  """A dotted name as DNS length-prefixed labels."""
  out = b""
  for label in name.strip(".").split("."):
    b = label.encode("ascii")
    out += bytes([len(b)]) + b
  return out + b"\x00"


def decode_name(buf: bytes, off: int) -> tuple[str, int]:
  """Read a (possibly compressed) name; return it and the next offset."""
  labels = []
  jumped = False
  end = off
  while True:
    if off >= len(buf):
      raise ValueError("name runs off the end")
    length = buf[off]
    if length == 0:
      off += 1
      if not jumped:
        end = off
      break
    if length & 0xC0 == 0xC0:
      pointer = ((length & 0x3F) << 8) | buf[off + 1]
      if not jumped:
        end = off + 2
      off = pointer
      jumped = True
      continue
    labels.append(buf[off + 1:off + 1 + length].decode("ascii"))
    off += 1 + length
  return ".".join(labels), end


def build_query(name: str, txid: int) -> bytes:
  """A standard recursive A query."""
  header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
  return header + encode_name(name) + struct.pack(
    "!HH", TYPE_A, CLASS_IN)


def build_answer(query: bytes, answer_ip: str) -> bytes:
  """Echo the question and append one A record for `answer_ip`."""
  txid = struct.unpack("!H", query[0:2])[0]
  name, off = decode_name(query, 12)
  qtail = query[12:off + 4]
  # QR=1, AA=1, RD=1, RA=1.
  header = struct.pack("!HHHHHH", txid, 0x8580, 1, 1, 0, 0)
  rr = (encode_name(name)
        + struct.pack("!HHIH", TYPE_A, CLASS_IN, 30, 4)
        + socket.inet_aton(answer_ip))
  return header + qtail + rr


def parse_answers(reply: bytes) -> list[str]:
  """Every A record address in a reply, in order."""
  txid, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", reply[:12])
  off = 12
  for _ in range(qd):
    _, off = decode_name(reply, off)
    off += 4
  out = []
  for _ in range(an):
    _, off = decode_name(reply, off)
    rtype, _rclass, _ttl, rdlen = struct.unpack(
      "!HHIH", reply[off:off + 10])
    off += 10
    if rtype == TYPE_A and rdlen == 4:
      out.append(socket.inet_ntoa(reply[off:off + 4]))
    off += rdlen
  return out


def run_server(args) -> int:
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  s.bind((args.bind, args.port))
  s.settimeout(args.timeout_s)
  served = 0
  names = []
  deadline = time.time() + args.timeout_s
  while served < args.count and time.time() < deadline:
    try:
      data, peer = s.recvfrom(2048)
    except socket.timeout:
      break
    try:
      name, _ = decode_name(data, 12)
    except ValueError:
      continue
    names.append(name)
    if args.delay_s:
      # Held open on purpose: the scenario uses this window to remove
      # the conntrack entry the egress hook created, so the reply
      # arrives at a firewall that has no state for it. That is the
      # control which proves the answer in the uncontrolled leg came
      # through that entry and not through some permissive path.
      time.sleep(args.delay_s)
    s.sendto(build_answer(data, args.answer_ip), peer)
    served += 1
  print(json.dumps({"served": served, "names": names}))
  return 0


def run_query(args) -> int:
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  s.settimeout(args.timeout_s)
  txid = 0x4711
  started = time.time()
  answers: list[str] = []
  error = ""
  try:
    s.sendto(build_query(args.name, txid), (args.resolver, args.port))
    reply, _ = s.recvfrom(4096)
    answers = parse_answers(reply)
  except socket.timeout:
    error = "timeout"
  except Exception as exc:  # noqa: BLE001 - reported, not swallowed
    error = str(exc)
  print(json.dumps({
    "name": args.name,
    "answers": answers,
    "count": len(answers),
    "error": error,
    "elapsed_s": round(time.time() - started, 3),
  }))
  return 0


def main() -> int:
  ap = argparse.ArgumentParser(description=__doc__)
  sub = ap.add_subparsers(dest="mode", required=True)

  srv = sub.add_parser("server")
  srv.add_argument("bind")
  srv.add_argument("port", type=int)
  srv.add_argument("answer_ip")
  srv.add_argument("count", type=int)
  srv.add_argument("timeout_s", type=float)
  srv.add_argument("--delay-s", type=float, default=0.0,
                   dest="delay_s")
  srv.set_defaults(func=run_server)

  qry = sub.add_parser("query")
  qry.add_argument("resolver")
  qry.add_argument("port", type=int)
  qry.add_argument("name")
  qry.add_argument("timeout_s", type=float)
  qry.set_defaults(func=run_query)

  args = ap.parse_args()
  return args.func(args)


if __name__ == "__main__":
  sys.exit(main())
