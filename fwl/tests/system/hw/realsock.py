"""A real socket on the far side, for tests that must be ACCEPTED.

Every NAT witness on this rig has been `sniff.py`: an AF_PACKET socket
on a promiscuous interface. That answers "did the frame reach this
cable", which is not the question a firewall has to pass. A frame
addressed to the wrong destination MAC is on the cable and in the
capture, and the receiving NIC reports it as PACKET_OTHERHOST and the
IP stack discards it before any socket exists. So a redirect that never
rewrote the destination MAC produced a perfect capture and a network
that carried nothing, and 1822 unit cases, eleven `l11_*` scenarios and
a NAT soak all agreed it worked.

This is the other witness. Both ends are ordinary blocking sockets on
an ordinary Linux stack — no promiscuous mode, no packet taps — so a
byte only arrives here if the kernel accepted the frame that carried
it: right MAC, right address, right checksum, right port, and a TCP
handshake that actually completed. It cannot pass on a frame a real
host would have dropped, because it IS a real host.

Both modes print one JSON object on stdout.

  server <bind_addr> <port> <n_conns> <timeout_s>
    Accepts up to n_conns connections, echoes what each sends, and
    reports the PEER address of each. Behind a masquerade the peer is
    the translated source, so the same object proves acceptance and
    proves the translation happened — one is not evidence without the
    other. `peers` is the whole assertion in one field.

  client <dst> <port> <n> <timeout_s> [src_port]
    Opens n connections, sends a token, and requires it back. Reports
    how many completed end to end. A masqueraded client's reply only
    arrives if the return frame was de-NATed AND re-addressed to it.
"""
import json
import socket
import sys
import time

TOKEN = b"fwl-real-socket-probe\n"


def run_server(bind_addr: str, port: int, n: int,
               timeout_s: float) -> dict:
  """Accept up to `n` connections, echo, and report every peer."""
  srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  srv.bind((bind_addr, port))
  srv.listen(max(n, 8))
  srv.settimeout(0.5)
  peers: list[str] = []
  echoed = 0
  deadline = time.monotonic() + timeout_s
  while len(peers) < n and time.monotonic() < deadline:
    try:
      conn, addr = srv.accept()
    except socket.timeout:
      continue
    except OSError:
      break
    peers.append(f"{addr[0]}:{addr[1]}")
    conn.settimeout(2.0)
    try:
      data = conn.recv(len(TOKEN))
      if data:
        conn.sendall(data)
        echoed += 1
    except OSError:
      pass
    finally:
      conn.close()
  srv.close()
  # The distinct source ADDRESS each connection arrived from. One entry
  # is what a masquerade is for; two means the translation is not
  # hiding the inside addresses at all.
  addrs = sorted({p.rsplit(":", 1)[0] for p in peers})
  return {
    "accepted": len(peers),
    "echoed": echoed,
    "peers": peers,
    "peer_addrs": addrs,
  }


def run_client(dst: str, port: int, n: int, timeout_s: float,
               src_port: int = 0) -> dict:
  """Open `n` connections and require the echo back on each."""
  completed = 0
  connected = 0
  errors: list[str] = []
  for i in range(n):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout_s)
    if src_port:
      s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
      try:
        s.bind(("", src_port + i))
      except OSError as exc:
        errors.append(f"bind: {exc}")
        s.close()
        continue
    try:
      s.connect((dst, port))
      connected += 1
      s.sendall(TOKEN)
      back = s.recv(len(TOKEN))
      if back == TOKEN:
        completed += 1
      else:
        errors.append(f"short echo: {back!r}")
    except OSError as exc:
      errors.append(str(exc))
    finally:
      s.close()
  return {
    "attempted": n,
    # A completed 3-way handshake. The forward direction reached a
    # listening socket AND the SYN-ACK came back through the NAT.
    "connected": connected,
    # ...and a payload made the round trip, which no capture can claim.
    "completed": completed,
    "errors": errors[:5],
  }


def main() -> int:
  mode = sys.argv[1]
  if mode == "server":
    out = run_server(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]),
                     float(sys.argv[5]))
  elif mode == "client":
    src_port = int(sys.argv[6]) if len(sys.argv) > 6 else 0
    out = run_client(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]),
                     float(sys.argv[5]), src_port)
  else:
    print(f"unknown mode {mode}", file=sys.stderr)
    return 2
  json.dump(out, sys.stdout)
  print()
  return 0


if __name__ == "__main__":
  sys.exit(main())
