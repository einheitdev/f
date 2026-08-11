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
  cases.json: [[case_path, source_fw, builder, expected_action,
                truncate_to?], ...]
"""
import glob
import json
import os
import subprocess
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
# Minimum Ethernet payload+header on the wire, excluding FCS.
ETH_MIN_FRAME = 60
ETH_P_ALL = 0x0003


SMOKE_POLICY = """\
# Layer-0 smoke policy: attach to all three data-plane ports, count
# every frame, pass everything. Proves load+attach+counters only.
zone data = [enp1s0f0, enp1s0f1, enp1s0f2]

@xdp(data)

count data_total
default allow
"""


def restore_smoke():
  """Put the bench back in its walk-up state.

  Every scenario test restores via hwlib's hw::finish; this harness
  did not, so a completed run left the rig on whichever corpus case
  happened to be last — a single-port policy nobody would recognise.
  That matters more now that hone's --wire mode drives this same
  code: an unattended run would misconfigure the bench every time it
  finished.
  """
  try:
    with open(RULES, "w") as fh:
      fh.write(SMOKE_POLICY)
    subprocess.run(
      ["fwl", "compile", "--bundle", "/usr/share/f/compiled/v-smoke",
       RULES], capture_output=True, timeout=120,
    )
    subprocess.run(["systemctl", "stop", "fd"], capture_output=True)
    pins = glob.glob("/sys/fs/bpf/f/fwl_*")
    pins.append("/sys/fs/bpf/f/conntrack")
    for pin in pins:
      try:
        os.unlink(pin)
      except OSError:
        pass
    if os.path.islink(BUNDLE_CURRENT) or os.path.exists(BUNDLE_CURRENT):
      os.unlink(BUNDLE_CURRENT)
    os.symlink("/usr/share/f/compiled/v-smoke", BUNDLE_CURRENT)
    subprocess.run(["systemctl", "start", "fd"], capture_output=True)
    time.sleep(3)
    print("bench restored to the smoke policy")
  except Exception as exc:
    print(f"WARNING: could not restore the smoke policy ({exc}). "
          f"Run: bash /opt/fwl/tests/system/hw/hw.sh l1_01_proto_port_cidr "
          f"or restore /etc/f/rules.fw by hand.")


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


def flush_conntrack():
  """Empty the pinned conntrack map.

  The conntrack map is shared state that deliberately survives a
  policy swap, so entries created by one corpus case are still there
  for the next one. Three stateful cases "diverged" on the first full
  run purely because an earlier case had already opened a matching
  flow. Corpus cases assume a clean table; give them one.
  """
  pin = "/sys/fs/bpf/f/conntrack"
  if not os.path.exists(pin):
    return
  try:
    import ctypes
    import ctypes.util
    lib = ctypes.CDLL(ctypes.util.find_library("bpf"), use_errno=True)
    lib.bpf_obj_get.argtypes = [ctypes.c_char_p]
    lib.bpf_obj_get.restype = ctypes.c_int
    fd = lib.bpf_obj_get(pin.encode())
    if fd < 0:
      return
    # ConnKey is 16 bytes (two v4 addrs, two ports, proto + pad).
    key = (ctypes.c_ubyte * 32)()
    nxt = (ctypes.c_ubyte * 32)()
    removed = 0
    while lib.bpf_map_get_next_key(fd, None, ctypes.byref(nxt)) == 0:
      ctypes.memmove(key, nxt, 32)
      if lib.bpf_map_delete_elem(fd, ctypes.byref(key)) != 0:
        break
      removed += 1
      if removed > 200000:
        break
  except Exception:
    # Best effort: a stale entry costs a false divergence, not a
    # crash, and the wire verdict is still recorded either way.
    pass


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

  @staticmethod
  def _variants(frame):
    """Byte patterns that count as "this frame arrived".

    The kernel software-untags 802.1Q before delivering to packet
    sockets (which is why sniff.py reads PACKET_AUXDATA), so a frame
    sent tagged comes back 4 bytes shorter with the inner EtherType
    promoted. Matching only the sent bytes counted every VLAN case as
    a drop — one of three artifact classes that made this harness's
    first full run report 7 false divergences.
    """
    out = [frame]
    if len(frame) >= 18 and frame[12:14] == b"\x81\x00":
      out.append(frame[:12] + frame[16:])
    return out

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
      for want in self._variants(frame):
        if got[:len(want)] == want:
          seen += 1
          break
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
  for case in cases:
    path, src, builder, expected = case[:4]
    # The .pkt format can cut a frame short to test what happens
    # when a header the rule needs is simply not there. Ignoring
    # it sends a FULL frame at a case written for a truncated one,
    # which inverts the expected verdict — three of the first
    # run's seven 'divergences' were exactly this.
    truncate = case[4] if len(case) > 4 else None
    by_prog.setdefault(src, []).append(
      (path, builder, expected, truncate))

  wire = Wire()
  results = []
  agree = diverge = skipped = 0
  t0 = time.monotonic()

  for i, (src, entries) in enumerate(by_prog.items(), 1):
    flush_conntrack()
    if not deploy(src):
      for path, _, _, _ in entries:
        results.append({"case": path, "verdict": "deploy-failed"})
        skipped += 1
      continue
    if not wire.probe():
      for path, _, _, _ in entries:
        results.append({"case": path, "verdict": "wire-dead"})
        skipped += 1
      continue

    for path, builder, expected, truncate in entries:
      try:
        frame = pkt.build_packet(pkt.parse_builder(builder)).raw
        if truncate:
          frame = frame[:truncate]
          if len(frame) < ETH_MIN_FRAME:
            # Ethernet has a 60-byte minimum: the NIC pads anything
            # shorter on transmit, so data_end at the receiver
            # reflects 60 bytes, not the truncated length. The
            # bounds check the case exists to exercise therefore
            # PASSES and the field is readable — measured: a
            # 38-byte frame arrives as 60 with dst_port intact, so
            # the rule fires and the wire drops what the corpus
            # expects to pass. That is a property of Ethernet, not
            # a datapath defect, and no attacker can put a short
            # frame on the wire either. BPF_PROG_TEST_RUN can feed
            # arbitrary lengths; hardware cannot, so these cases
            # are simply outside what a wire oracle can decide.
            results.append({"case": path, "builder": builder,
                            "expected": expected,
                            "verdict": "not-wire-testable",
                            "detail": (
                              f"truncate_to={truncate} is below the "
                              f"{ETH_MIN_FRAME}-byte Ethernet "
                              "minimum; the NIC pads it back")})
            skipped += 1
            continue
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
  try:
    rc = main()
  finally:
    # Always: an interrupted run must not leave the bench on a
    # corpus case either.
    restore_smoke()
  sys.exit(rc)
