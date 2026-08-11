"""Replay the .pkt corpus on real hardware and diff against it.

The three oracles (spec table, interpreter, BPF_PROG_TEST_RUN) agree
with each other by construction — they encode one model. Every bug
this rig has found so far lived in the gap between that model and a
real NIC on a real switch: fragments parsed as L4, IPv6 escaping the
default action. Both were invisible to all three oracles at once.

This makes the wire a fourth oracle and runs the whole corpus
through it. Each case's program is deployed, its packet is sent
across the EX2300, and the observed disposition is compared with the
corpus's own expectation. A divergence means either the datapath or
the corpus is wrong — both are worth knowing.

Runs ON THE RIG (root): orchestrating per-case over ssh would cost
more in round-trips than the test itself.

Deployment goes through the watcher rather than a daemon restart:
the atomic XDP_FLAGS_REPLACE swap does not reset the igb link, so a
program change costs ~2 s instead of the ~45 s a detach/attach cycle
needs to get the wire back.

Usage: corpus_replay.py <cases.json> [--limit N] [--out report.json]
  cases.json: [[case_path, source_fw, builder, expected_action], ...]
"""
import json
import os
import select
import socket
import sys
import time

sys.path.insert(0, "/opt/fwl")
sys.path.insert(0, "/opt/fwl-deps")
from fwl import pkt  # noqa: E402

SEND_IF = os.environ.get("SEND_IF", "enp1s0f0")
RECV_IF = os.environ.get("RECV_IF", "enp1s0f1")
RULES = "/etc/f/rules.fw"
BUNDLE_CURRENT = "/usr/share/f/compiled/current"
REPEAT = 10
ETH_P_ALL = 0x0003


def current_bundle():
  try:
    return os.readlink(BUNDLE_CURRENT)
  except OSError:
    return ""


def zone_wrap(source_fw):
  """Rewrite a corpus program onto this rig's zone/interface.

  Corpus programs target a nominal `@xdp(eth0)`. Give them a real
  zone bound to the receiving port, leaving the rules untouched.
  """
  lines = []
  for line in source_fw.splitlines():
    s = line.strip()
    if s.startswith("zone "):
      continue
    if s.startswith("@xdp("):
      lines.append("@xdp(t)")
      continue
    lines.append(line)
  body = "\n".join(lines)
  return f"zone t = [{RECV_IF}]\n\n{body}\n"


def deploy(source_fw, timeout=25.0):
  """Hand a policy to the watcher; wait for the swap to land."""
  before = current_bundle()
  with open(RULES, "w") as fh:
    fh.write(zone_wrap(source_fw))
  deadline = time.monotonic() + timeout
  while time.monotonic() < deadline:
    now = current_bundle()
    if now and now != before:
      # The symlink moves only after a successful apply.
      time.sleep(0.3)
      return True
    time.sleep(0.2)
  return False


class Wire:
  """Send exact frames and count exact arrivals.

  Matching whole frames rather than parsing them keeps this harness
  protocol-agnostic: corpus packets span v4, v6, ICMP, VLAN-tagged
  and deliberately odd shapes, and any parser here would just be a
  second place for the model to be wrong.
  """

  def __init__(self):
    self.tx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    self.tx.bind((SEND_IF, 0))
    self.rx = socket.socket(
      socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL)
    )
    self.rx.bind((RECV_IF, 0))
    self.rx.setsockopt(
      socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024
    )
    self.rx.setblocking(False)

  def drain(self):
    while True:
      r, _, _ = select.select([self.rx], [], [], 0)
      if not r:
        return
      try:
        self.rx.recv(65535)
      except BlockingIOError:
        return

  def probe(self, timeout=60.0):
    """Wait until frames cross send -> switch -> recv."""
    teach = (b"\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01"
             b"\x88\xb5" + b"CORPUS-PROBE".ljust(50, b"\x00"))
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
      self.drain()
      try:
        self.tx.send(teach)
      except OSError:
        time.sleep(0.5)
        continue
      r, _, _ = select.select([self.rx], [], [], 0.5)
      if r:
        self.drain()
        return True
    return False

  def disposition(self, frame):
    """Return ("allow"|"drop"|"wire-dead", arrived).

    A zero count means one of two very different things: the policy
    dropped the frame, or nothing was crossing the wire at all. The
    first draft of this harness conflated them and reported three
    false divergences — including a program whose entire body is
    `allow`. So a zero is never taken at face value: re-probe the
    wire, and only call it a drop if inert frames still cross.
    """
    seen = self.send_and_count(frame)
    if seen > 0:
      return "allow", seen
    if not self.probe(timeout=20.0):
      return "wire-dead", 0
    seen = self.send_and_count(frame)
    return ("allow" if seen > 0 else "drop"), seen

  def send_and_count(self, frame, repeat=REPEAT, settle=1.0):
    self.drain()
    for _ in range(repeat):
      try:
        self.tx.send(frame)
      except OSError:
        pass
    time.sleep(settle)
    seen = 0
    while True:
      r, _, _ = select.select([self.rx], [], [], 0.05)
      if not r:
        break
      try:
        got, meta = self.rx.recvfrom(65535)
      except BlockingIOError:
        break
      if meta[2] == socket.PACKET_OUTGOING:
        continue
      # The NIC pads short frames; compare only what we sent.
      if got[:len(frame)] == frame:
        seen += 1
    return seen


def main() -> int:
  cases = json.load(open(sys.argv[1]))
  limit = None
  out_path = None
  if "--limit" in sys.argv:
    limit = int(sys.argv[sys.argv.index("--limit") + 1])
  if "--out" in sys.argv:
    out_path = sys.argv[sys.argv.index("--out") + 1]
  if limit:
    cases = cases[:limit]

  # Group by program so each policy is deployed once.
  by_prog = {}
  for path, src, builder, expected in cases:
    by_prog.setdefault(src, []).append((path, builder, expected))

  wire = Wire()
  results = []
  agree = diverge = skipped = 0
  t0 = time.monotonic()

  for i, (src, entries) in enumerate(by_prog.items(), 1):
    if not deploy(src):
      for path, _, _ in entries:
        results.append({"case": path, "verdict": "deploy-failed"})
        skipped += 1
      continue
    if not wire.probe():
      for path, _, _ in entries:
        results.append({"case": path, "verdict": "wire-dead"})
        skipped += 1
      continue

    for path, builder, expected in entries:
      try:
        frame = pkt.build_packet(pkt.parse_builder(builder)).raw
      except Exception as exc:
        results.append({"case": path, "verdict": "build-failed",
                        "detail": str(exc)})
        skipped += 1
        continue
      observed, seen = wire.disposition(frame)
      row = {"case": path, "builder": builder,
             "expected": expected, "observed": observed,
             "arrived": seen, "of": REPEAT}
      if observed == "wire-dead":
        skipped += 1
        row["verdict"] = "wire-dead"
        results.append(row)
        continue
      if observed == expected:
        agree += 1
        row["verdict"] = "agree"
      else:
        diverge += 1
        row["verdict"] = "DIVERGE"
        print(f"DIVERGE {path}\n  {builder}\n  corpus says "
              f"{expected}, wire says {observed} "
              f"({seen}/{REPEAT} arrived)", flush=True)
      results.append(row)

    if i % 20 == 0:
      el = time.monotonic() - t0
      print(f"... {i}/{len(by_prog)} programs, {agree} agree, "
            f"{diverge} diverge, {el:.0f}s", flush=True)

  print(f"\ncorpus replay: {agree} agree, {diverge} DIVERGE, "
        f"{skipped} skipped, {time.monotonic() - t0:.0f}s")
  if out_path:
    json.dump(results, open(out_path, "w"), indent=2)
    print(f"report: {out_path}")
  return 1 if diverge else 0


if __name__ == "__main__":
  sys.exit(main())
