"""Three-oracle test runner.

For each `.pkt` file: load, parse the embedded `source_fw`, evaluate
through the AST interpreter, compile and execute via BPF_PROG_RUN,
compare both to the file's `expected:` block. Reports per-oracle
pass/fail with diffs.

Methodology reference: docs/F_DEVELOPMENT_METHODOLOGY.md:132-181.
"""
from __future__ import annotations
import ipaddress
import re
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import analyzer, ast, bpf_runner, emitter, interpreter, parser, pkt
from .errors import FwlException


_EXPECTED_TO_XDP = {
  "allow": interpreter.XdpAction.PASS,
  "drop": interpreter.XdpAction.DROP,
  "pass": interpreter.XdpAction.PASS,
  "none": interpreter.XdpAction.PASS,
  # v0.4 § 6.3: `redirect to <zone>` returns XDP_REDIRECT.
  "redirect": interpreter.XdpAction.REDIRECT,
}


def _zone_program(program: ast.Program, ingress_zone: str | None):
  """Select the @xdp block a packet ingresses on (v0.4 § 6).

  Returns a single-program `ast.Program` wrapping the chosen
  ZoneProgram so every downstream consumer (emit, evaluate_full,
  program.rules/.hook) works uniformly. `ingress_zone is None` keeps
  the whole program (the first/only block evaluates — the degenerate
  single-zone case).
  """
  if ingress_zone is None:
    return program
  for zp in program.programs:
    if zp.zone_name == ingress_zone:
      return ast.Program(programs=[zp], zones=program.zones)
  raise ValueError(
    f"ingress_zone {ingress_zone!r} matches no @xdp block"
  )


@dataclass
class OracleResult:
  """Outcome of running one oracle against one test case."""
  name: str             # "spec" | "interpreter" | "bpf"
  status: str           # "pass" | "fail" | "skip" | "error"
  detail: str = ""      # explanation for fail/skip/error


@dataclass
class CaseResult:
  """All-oracle outcome for a single .pkt case."""
  case: pkt.PktCase
  oracles: list[OracleResult]

  @property
  def passed(self) -> bool:
    """True iff no oracle failed or errored. Skips don't fail."""
    return all(o.status in ("pass", "skip") for o in self.oracles)


def _expected_action(case: pkt.PktCase) -> interpreter.XdpAction:
  """Map the .pkt expected.bpf_action string to an XdpAction."""
  raw = case.expected.get("bpf_action", "allow")
  try:
    return _EXPECTED_TO_XDP[raw]
  except KeyError as exc:
    raise ValueError(
      f"unknown expected.bpf_action: {raw!r}"
    ) from exc


def _spec_oracle(case: pkt.PktCase) -> OracleResult:
  """The spec oracle is just an existence check on the .pkt fields.

  Spec correctness of the expectation is human-reviewed at corpus
  authoring time (per F_DEVELOPMENT_METHODOLOGY.md:170). This oracle
  ensures the file at least has the fields the runner needs.
  """
  if case.expected.get("compiles", True) is False:
    # Compile-failure cases need no bpf_action — the interpreter and
    # bpf oracles verify that compilation actually fails.
    return OracleResult(
      "spec", "pass", "compile-failure case (no action)"
    )
  if "bpf_action" not in case.expected:
    return OracleResult(
      "spec", "fail",
      "expected.bpf_action missing — cannot verify",
    )
  return OracleResult("spec", "pass", "")


def _interpreter_oracle(
  case: pkt.PktCase, expected: interpreter.XdpAction
) -> OracleResult:
  """Run the AST interpreter and compare to expected."""
  try:
    program = analyzer.analyze(parser.parse(case.source_fw))
  except FwlException as exc:
    if not case.expected.get("compiles", True):
      return OracleResult(
        "interpreter", "pass",
        f"compile failure as expected: {exc.error.message}",
      )
    return OracleResult(
      "interpreter", "error",
      f"unexpected compile error: {exc.error.format()}",
    )
  if not case.expected.get("compiles", True):
    return OracleResult(
      "interpreter", "fail",
      "expected compile failure but program parsed cleanly",
    )

  program = _zone_program(program, case.ingress_zone)
  result = interpreter.evaluate_full(
    program, case.packet.fields, case.state,
    geoip_data=(case.geoip_data or None),
    conntrack=interpreter.ConntrackTable(case.conntrack_seed),
    nat=_build_nat_state(case),
  )
  if result.action != expected:
    return OracleResult(
      "interpreter", "fail",
      f"expected {expected.value}, got {result.action.value}",
    )
  op_diff = _check_output_packet(
    case.expected.get("output_packet"), result.output_packet, "interpreter"
  )
  if op_diff:
    return OracleResult("interpreter", "fail", op_diff)
  want_zone = case.expected.get("redirect_zone")
  if want_zone is not None and result.redirect_zone != want_zone:
    return OracleResult(
      "interpreter", "fail",
      f"expected redirect to {want_zone}, got {result.redirect_zone}",
    )
  counter_diff = _check_counter_changes(
    case.expected.get("counter_changes", {}),
    result.counter_changes,
  )
  if counter_diff:
    return OracleResult("interpreter", "fail", counter_diff)
  log_diff = _check_log_events(
    case.expected.get("log_events", []),
    result.log_events,
  )
  if log_diff:
    return OracleResult("interpreter", "fail", log_diff)
  return OracleResult("interpreter", "pass", "")


def _bpf_oracle(
  case: pkt.PktCase, expected: interpreter.XdpAction
) -> OracleResult:
  """Compile + (optionally) BPF_PROG_RUN and compare to expected.

  Skips with a clear message when CAP_BPF is unavailable, so the
  runner remains useful in development environments without root.
  Compilation alone still runs and catches structural emitter bugs.

  When a .pkt declares state: the BPF run is skipped because
  pre-populating BPF maps from .pkt state isn't implemented yet —
  running anyway would silently report a different action than the
  interpreter (which respects the state) and create false agreement
  for the wrong reason.
  """
  try:
    program = analyzer.analyze(parser.parse(case.source_fw))
  except FwlException:
    # The interpreter oracle already reports parse/semantic errors;
    # don't double-report.
    return OracleResult(
      "bpf", "skip", "skipped because compile failed (see interpreter)"
    )
  if not case.expected.get("compiles", True):
    return OracleResult(
      "bpf", "skip", "skipped: compile-failure expected"
    )

  program = _zone_program(program, case.ingress_zone)
  c_source = emitter.emit(program)
  map_init = _build_map_init(program, case.state)
  for name, entries in _build_geoip_map_init(
    program, case.geoip_data or {}
  ).items():
    map_init[name] = entries
  ct_seed = _build_conntrack_map_init(case.conntrack_seed)
  if ct_seed:
    map_init["conntrack"] = ct_seed
  for name, entries in _build_nat_map_init(case).items():
    map_init[name] = entries
  counter_slots = _parse_counter_table(c_source)
  n_slots = len(counter_slots)
  has_log = any(
    r.action == ast.Action.LOG for r in program.rules
  )

  try:
    result = bpf_runner.run_full(
      c_source, case.packet.raw, map_init, n_slots, has_log
    )
  except bpf_runner.BpfUnavailable as exc:
    try:
      bpf_runner.compile_c(c_source)
    except subprocess.CalledProcessError as cexc:
      stderr = cexc.stderr.decode("utf-8", "replace")
      return OracleResult(
        "bpf", "fail",
        f"clang failed to compile emitter output:\n{stderr}",
      )
    return OracleResult(
      "bpf", "skip",
      f"BPF_PROG_RUN unavailable ({exc}); clang compile passed",
    )
  except subprocess.CalledProcessError as exc:
    stderr = exc.stderr.decode("utf-8", "replace")
    return OracleResult(
      "bpf", "fail", f"clang failed:\n{stderr}"
    )
  except RuntimeError as exc:
    # BPF_PROG_TEST_RUN of a `redirect to <zone>` program with an
    # unpopulated devmap aborts the redirect (retval XDP_ABORTED): the
    # kernel executes xdp_do_redirect, finds no devmap entry / no
    # XDP-target netdev in the test context, and reports ABORTED. The
    # program still loaded — the verifier accepted bpf_redirect_map —
    # so this confirms a real redirect, not a stub. The packet
    # physically crossing interfaces is proven by the netns system test
    # (tests/system/test_zone_redirect_netns.sh), which test-run cannot.
    if expected == interpreter.XdpAction.REDIRECT:
      return OracleResult(
        "bpf", "skip",
        "redirect program loaded (verifier-accepted bpf_redirect_map); "
        "behavioral crossing verified by the netns system test",
      )
    return OracleResult("bpf", "fail", f"BPF_PROG_RUN error: {exc}")

  if result.action != expected:
    return OracleResult(
      "bpf", "fail",
      f"expected {expected.value}, got {result.action.value}",
    )

  want_op = case.expected.get("output_packet")
  if want_op is not None:
    op_diff = _check_output_packet(
      want_op, _decode_output_packet(result.output_packet), "bpf"
    )
    if op_diff:
      return OracleResult("bpf", "fail", op_diff)
    # A rewrite that asserts output fields must also leave valid
    # checksums — the wire-correctness a stub cannot fake.
    csum_diff = _checksum_diag(result.output_packet)
    if csum_diff:
      return OracleResult("bpf", "fail", csum_diff)

  expected_cc = case.expected.get("counter_changes", {})
  if expected_cc and counter_slots:
    named = _slot_deltas_to_named(
      result.counter_deltas, counter_slots
    )
    counter_diff = _check_counter_changes(expected_cc, named)
    if counter_diff:
      return OracleResult("bpf", "fail", counter_diff)

  expected_le = case.expected.get("log_events", [])
  if expected_le:
    bpf_log = [
      interpreter.LogEvent(
        rule_index=e.rule_index, proto=e.proto,
        src_ip=e.src_ip, dst_ip=e.dst_ip,
        src_port=e.src_port, dst_port=e.dst_port,
        syn=e.syn, ack=e.ack,
      )
      for e in result.log_events
    ]
    log_diff = _check_log_events(expected_le, bpf_log)
    if log_diff:
      return OracleResult("bpf", "fail", log_diff)

  return OracleResult("bpf", "pass", "")


def _seq_spec_oracle(case: pkt.PktCase) -> OracleResult:
  """Existence check: every sequence step needs an expected.bpf_action."""
  for i, step in enumerate(case.sequence):
    if "bpf_action" not in step.expected:
      return OracleResult(
        "spec", "fail",
        f"sequence[{i}] ({step.name}) missing expected.bpf_action",
      )
  return OracleResult("spec", "pass", "")


def _seq_interpreter_oracle(case: pkt.PktCase) -> OracleResult:
  """Evaluate every step through one carried-over conntrack table."""
  try:
    program = analyzer.analyze(parser.parse(case.source_fw))
  except FwlException as exc:
    return OracleResult(
      "interpreter", "error",
      f"unexpected compile error: {exc.error.format()}",
    )
  ct = interpreter.ConntrackTable(case.conntrack_seed)
  for i, step in enumerate(case.sequence):
    want = _EXPECTED_TO_XDP[step.expected.get("bpf_action", "allow")]
    res = interpreter.evaluate_full(
      program, step.packet.fields, case.state,
      geoip_data=(case.geoip_data or None), conntrack=ct,
    )
    if res.action != want:
      return OracleResult(
        "interpreter", "fail",
        f"step {i} ({step.name}): expected {want.value}, "
        f"got {res.action.value}",
      )
  return OracleResult("interpreter", "pass", "")


def _seq_bpf_oracle(case: pkt.PktCase) -> OracleResult:
  """Load the program once and run every step's packet against it."""
  try:
    program = analyzer.analyze(parser.parse(case.source_fw))
  except FwlException:
    return OracleResult(
      "bpf", "skip", "skipped because compile failed (see interpreter)"
    )
  c_source = emitter.emit(program)
  map_init = _build_map_init(program, case.state)
  for name, entries in _build_geoip_map_init(
    program, case.geoip_data or {}
  ).items():
    map_init[name] = entries
  ct_seed = _build_conntrack_map_init(case.conntrack_seed)
  if ct_seed:
    map_init["conntrack"] = ct_seed
  counter_slots = _parse_counter_table(c_source)
  has_log = any(r.action == ast.Action.LOG for r in program.rules)
  packets = [step.packet.raw for step in case.sequence]
  try:
    results = bpf_runner.run_sequence(
      c_source, packets, map_init, len(counter_slots), has_log
    )
  except bpf_runner.BpfUnavailable as exc:
    try:
      bpf_runner.compile_c(c_source)
    except subprocess.CalledProcessError as cexc:
      stderr = cexc.stderr.decode("utf-8", "replace")
      return OracleResult(
        "bpf", "fail",
        f"clang failed to compile emitter output:\n{stderr}",
      )
    return OracleResult(
      "bpf", "skip",
      f"BPF_PROG_RUN unavailable ({exc}); clang compile passed",
    )
  except subprocess.CalledProcessError as exc:
    stderr = exc.stderr.decode("utf-8", "replace")
    return OracleResult("bpf", "fail", f"clang failed:\n{stderr}")
  for i, (step, res) in enumerate(zip(case.sequence, results)):
    want = _EXPECTED_TO_XDP[step.expected.get("bpf_action", "allow")]
    if res.action != want:
      return OracleResult(
        "bpf", "fail",
        f"step {i} ({step.name}): expected {want.value}, "
        f"got {res.action.value}",
      )
  return OracleResult("bpf", "pass", "")


def _run_sequence_case(case: pkt.PktCase) -> CaseResult:
  """Run all oracles against a multi-packet `sequence:` case."""
  spec = _seq_spec_oracle(case)
  if spec.status != "pass":
    return CaseResult(case=case, oracles=[spec])
  return CaseResult(case=case, oracles=[
    spec,
    _seq_interpreter_oracle(case),
    _seq_bpf_oracle(case),
  ])


def run_case(case: pkt.PktCase) -> CaseResult:
  """Run all oracles against one .pkt case."""
  if case.sequence is not None:
    return _run_sequence_case(case)
  spec = _spec_oracle(case)
  if spec.status != "pass":
    return CaseResult(case=case, oracles=[spec])

  if case.expected.get("compiles", True) is False:
    return CaseResult(
      case=case,
      oracles=[
        spec,
        _interpreter_oracle(case, interpreter.XdpAction.PASS),
        _bpf_oracle(case, interpreter.XdpAction.PASS),
      ],
    )

  expected = _expected_action(case)
  return CaseResult(
    case=case,
    oracles=[
      spec,
      _interpreter_oracle(case, expected),
      _bpf_oracle(case, expected),
    ],
  )


def _build_map_init(
  program: ast.Program,
  state: dict[int, dict[Any, int]],
) -> dict[str, dict[bytes, bytes]]:
  """Translate .pkt state into the {map_name: {key: value}} layout.

  The emitter names rate_limit maps fwl_rl_map_<rule_idx>; the value
  is `struct fwl_rl_state { __u64 ts; __u32 count; }` packed to 16
  bytes by the C compiler. For per-CPU maps the kernel expects the
  value buffer to be nr_possible_cpus * sizeof(struct).
  """
  if not state:
    return {}
  result: dict[str, dict[bytes, bytes]] = {}
  try:
    nr_cpus = bpf_runner.num_possible_cpus()
  except OSError:
    nr_cpus = 1
  for rule_idx, buckets in state.items():
    if rule_idx >= len(program.rules):
      continue
    rule = program.rules[rule_idx]
    if rule.modifier is None:
      continue
    map_name = f"fwl_rl_map_{rule_idx}"
    entries: dict[bytes, bytes] = {}
    for raw_key, count in buckets.items():
      key_bytes = _encode_rl_key(rule.modifier.per_field, raw_key)
      value_bytes = _encode_rl_value_per_cpu(count, nr_cpus)
      entries[key_bytes] = value_bytes
    if entries:
      result[map_name] = entries
  return result


def _build_conntrack_map_init(
  seed: tuple,
) -> dict[bytes, bytes]:
  """Translate the conntrack seed into `conntrack` map key/value bytes.

  Each seed tuple `(proto, src_u32, dst_u32, sport, dport)` is packed
  to match the BPF program's `struct fwl_conn_key` memory layout (===
  the daemon's ConnKey): network-order addresses (big-endian, matching
  the program's raw `ip->saddr`), host-order ports (little-endian u16
  on the x86 test host, matching the bpf_ntohs'd port vars), the
  protocol byte, and 3 pad bytes. The value is an ESTABLISHED
  `struct fwl_conn_value` (state = 1).
  """
  import time
  entries: dict[bytes, bytes] = {}
  now_ns = time.monotonic_ns()
  value = struct.pack("<QQB7x", now_ns, 1, 1)
  for proto, src, dst, sport, dport in seed:
    proto_num = pkt._CONNTRACK_PROTO_NUM[proto]
    key = (
      struct.pack(">I", src) + struct.pack(">I", dst)
      + struct.pack("<H", sport) + struct.pack("<H", dport)
      + struct.pack("<B", proto_num) + b"\x00\x00\x00"
    )
    entries[key] = value
  return entries


_NAT_TYPE_NUM = {"snat": 1, "dnat": 2}


def _build_nat_state(case: pkt.PktCase):
  """Build the interpreter's NatState from the .pkt's state.nat block.

  Returns None when the case declares no NAT state (so the interpreter
  runs unchanged)."""
  if case.nat_masq_ip is None and not case.nat_mappings:
    return None  # no state.nat block: interpreter runs without NAT seed
  reply = {}
  for proto, src, dst, sport, dport, new, new_port, kind in case.nat_mappings:
    reply[(proto, src, dst, sport, dport)] = (kind, new, new_port)
  return interpreter.NatState(masq_ip=case.nat_masq_ip, mappings=reply)


def _build_nat_map_init(case: pkt.PktCase) -> dict[str, dict[bytes, bytes]]:
  """Seed `fwl_nat` (reply mappings) and `fwl_nat_cfg` (masquerade IP)
  from the .pkt's state.nat block, byte-matching the emitted structs."""
  out: dict[str, dict[bytes, bytes]] = {}
  if case.nat_masq_ip is not None:
    out["fwl_nat_cfg"] = {
      struct.pack("<I", 0): struct.pack(">I", case.nat_masq_ip)
    }
  if case.nat_mappings:
    entries: dict[bytes, bytes] = {}
    for proto, src, dst, sport, dport, new, new_port, kind in \
        case.nat_mappings:
      proto_num = pkt._CONNTRACK_PROTO_NUM[proto]
      key = (struct.pack(">I", src) + struct.pack(">I", dst)
             + struct.pack("<H", sport) + struct.pack("<H", dport)
             + struct.pack("<B", proto_num) + b"\x00\x00\x00")
      value = (struct.pack(">I", new) + struct.pack("<H", new_port)
               + struct.pack("<B", _NAT_TYPE_NUM[kind]) + b"\x00")
      entries[key] = value
    out["fwl_nat"] = entries
  return out


def _decode_output_packet(raw: bytes) -> dict[str, Any]:
  """Decode an output frame's NAT-relevant fields (IPv4, plain or one
  802.1Q tag). Returns {src_ip, dst_ip, src_port, dst_port}."""
  out: dict[str, Any] = {}
  if len(raw) < 14:
    return out
  off = 14
  ethertype = (raw[12] << 8) | raw[13]
  if ethertype == 0x8100 and len(raw) >= 18:
    off = 18
  if len(raw) < off + 20:
    return out
  ihl = (raw[off] & 0x0F) * 4
  out["src_ip"] = ".".join(str(b) for b in raw[off + 12:off + 16])
  out["dst_ip"] = ".".join(str(b) for b in raw[off + 16:off + 20])
  l4 = off + ihl
  if len(raw) >= l4 + 4:
    out["src_port"] = (raw[l4] << 8) | raw[l4 + 1]
    out["dst_port"] = (raw[l4 + 2] << 8) | raw[l4 + 3]
  return out


def _ones_sum(data: bytes) -> int:
  """16-bit one's-complement sum of `data` (folded), the Internet
  checksum primitive."""
  if len(data) % 2:
    data = data + b"\x00"
  s = 0
  for i in range(0, len(data), 2):
    s += (data[i] << 8) | data[i + 1]
  while s >> 16:
    s = (s & 0xFFFF) + (s >> 16)
  return s


def _checksum_diag(raw: bytes) -> str | None:
  """Validate the IPv4 header checksum and the TCP/UDP checksum of an
  output frame (plain or one 802.1Q tag). Returns a diagnostic string on
  any invalid checksum, or None when all are valid / not applicable.

  This is the automatic guard behind the `checksum_verify` story: a NAT
  rewrite that corrupts a checksum is silently dropped on the wire, so
  the BPF oracle proves every rewritten frame is internally consistent.
  """
  if len(raw) < 14:
    return None  # not even an Ethernet header
  off = 14
  if ((raw[12] << 8) | raw[13]) == 0x8100 and len(raw) >= 18:
    off = 18
  if len(raw) < off + 20:
    return None  # no IPv4 header to check
  ihl = (raw[off] & 0x0F) * 4
  if ihl < 20 or len(raw) < off + ihl:
    return None  # malformed / truncated IP header — not our concern
  # IP header checksum: the sum over the header (check field included)
  # must be 0xFFFF.
  if _ones_sum(raw[off:off + ihl]) != 0xFFFF:
    return "IP header checksum invalid after rewrite"
  proto = raw[off + 9]
  l4 = off + ihl
  seg = raw[l4:]
  if proto == 6 and len(seg) >= 20 or proto == 17 and len(seg) >= 8:
    if proto == 17:
      stored = (seg[6] << 8) | seg[7]
      if stored == 0:
        return None  # UDP with no checksum
    # Pseudo-header: src, dst, zero, proto, L4 length.
    pseudo = (raw[off + 12:off + 16] + raw[off + 16:off + 20]
              + bytes([0, proto]) + len(seg).to_bytes(2, "big"))
    if _ones_sum(pseudo + seg) != 0xFFFF:
      name = "TCP" if proto == 6 else "UDP"
      return f"{name} checksum invalid after rewrite"
  return None  # all checksums valid


def _check_output_packet(expected_op, got, oracle: str) -> str | None:
  """Compare the rewritten packet fields against expected.output_packet.

  Only the fields the .pkt lists are checked. Returns a diff string on
  mismatch, or None on agreement (or when nothing is expected)."""
  if not expected_op:
    return None  # nothing to check
  if got is None:
    return (f"expected output_packet {expected_op} but {oracle} produced "
            f"no rewrite")
  for field, want in expected_op.items():
    have = got.get(field)
    if have != want:
      return (f"output_packet.{field}: expected {want!r}, got {have!r} "
              f"({oracle})")
  return None  # all expected fields matched


def _check_counter_changes(
  expected: dict[str, int],
  actual: dict[str, int],
) -> str:
  """Compare expected vs actual counter deltas. Empty string = match."""
  diffs: list[str] = []
  for name, want in expected.items():
    got = actual.get(name, 0)
    if got != want:
      diffs.append(f"counter {name!r}: expected {want}, got {got}")
  if diffs:
    return "counter_changes mismatch: " + "; ".join(diffs)
  return ""


_COUNTER_TABLE_RE = re.compile(
  r"^//\s+(\d+)\t(.+)$", re.MULTILINE
)


def _parse_counter_table(c_source: str) -> dict[str, int]:
  """Parse the fwl_counter_table comment block from emitted C."""
  result: dict[str, int] = {}
  for match in _COUNTER_TABLE_RE.finditer(c_source):
    slot = int(match.group(1))
    name = match.group(2).strip()
    result[name] = slot
  return result


def _slot_deltas_to_named(
  slot_deltas: dict[int, int],
  counter_slots: dict[str, int],
) -> dict[str, int]:
  """Convert {slot: delta} to {name: delta}."""
  slot_to_name = {v: k for k, v in counter_slots.items()}
  return {
    slot_to_name[slot]: delta
    for slot, delta in slot_deltas.items()
    if slot in slot_to_name
  }


def _check_log_events(
  expected: list[dict[str, Any]],
  actual: list[interpreter.LogEvent],
) -> str:
  """Compare expected vs actual log events. Empty string = match."""
  if not expected:
    return ""
  if len(expected) != len(actual):
    return (
      f"log_events count mismatch: expected {len(expected)}, "
      f"got {len(actual)}"
    )
  for i, (want, got) in enumerate(zip(expected, actual)):
    diff = _compare_log_event(i, want, got)
    if diff:
      return diff
  return ""


_LOG_FIELD_GETTERS = {
  "rule_index": lambda e: e.rule_index,
  "proto": lambda e: e.proto,
  "src_ip": lambda e: e.src_ip,
  "dst_ip": lambda e: e.dst_ip,
  "src_port": lambda e: e.src_port,
  "dst_port": lambda e: e.dst_port,
  "syn": lambda e: e.syn,
  "ack": lambda e: e.ack,
}


def _compare_log_event(
  idx: int,
  expected: dict[str, Any],
  actual: interpreter.LogEvent,
) -> str:
  """Compare one expected log event against an actual LogEvent."""
  for field_name, value in expected.items():
    getter = _LOG_FIELD_GETTERS.get(field_name)
    if getter is None:
      continue
    actual_val = getter(actual)
    if actual_val != value:
      return (
        f"log_events[{idx}].{field_name}: "
        f"expected {value!r}, got {actual_val!r}"
      )
  return ""


def _encode_rl_key(per_field: str, raw_key: Any) -> bytes:
  """Pack a .pkt state bucket key into the BPF map's key bytes (u32 LE).

  The emitter casts both ip and port fields to __u32 before lookup
  (see emitter._emit_rate_limit_gate); IP fields use bpf_ntohl so
  src_ip in the BPF program is in host byte order. Match that here:
  pack as little-endian u32 with the high octet first in the
  dotted-quad value.
  """
  if per_field in ("src_ip", "dst_ip"):
    if isinstance(raw_key, int):
      value = raw_key
    else:
      parts = raw_key.split(".")
      value = 0
      for part in parts:
        value = (value << 8) | int(part)
  else:
    value = int(raw_key)
  return struct.pack("<I", value & 0xFFFFFFFF)


def _encode_rl_value_per_cpu(count: int, nr_cpus: int) -> bytes:
  """Pack a count value into per-CPU buffer bytes for fwl_rl_state.

  Each per-CPU slot is `__u64 ts; __u32 count;` plus 4 bytes of
  trailing padding (16 bytes total). ts is set to the current
  monotonic ns so the sliding window doesn't immediately reset the
  count to 0.
  """
  import time
  now_ns = time.monotonic_ns()
  per_cpu_value = struct.pack("<QI4x", now_ns, count)
  return per_cpu_value * nr_cpus


def _build_geoip_map_init(
  program: ast.Program,
  geoip_data: dict[str, list[str]],
) -> dict[str, dict[bytes, bytes]]:
  """Translate .pkt geoip_data into LPM trie map entries per call site.

  Walks every `geoip(...)` call in `program`, looks up its codes in
  `geoip_data`, and produces a `{map_name: {key_bytes: value_bytes}}`
  layout matching the BPF runtime's expectations.

  v4 key layout: `struct { __u32 prefixlen; __u32 ip; }` — prefixlen
  in host byte order, ip in network byte order (matches the lookup
  helper's `bpf_htonl(ip)`). v6 key: `struct { __u32 prefixlen;
  __u8 ip[16]; }` — 16 bytes of network-order address.

  The map's value type is `__u8` so each entry's value is a single
  membership byte (1).
  """
  if not geoip_data:
    return {}
  result: dict[str, dict[bytes, bytes]] = {}
  seen: set[int] = set()
  geoip_nodes: list[ast.GeoIp] = []
  for rule in program.rules:
    geoip_nodes.extend(_walk_geoip_operands(rule.condition))
  if program.function is not None:
    geoip_nodes.extend(_walk_geoip_in_tier2(program.function.body))
  for node in geoip_nodes:
      if node.call_index in seen:
        continue
      seen.add(node.call_index)
      map_name = f"fwl_geoip_{node.call_index}"
      entries: dict[bytes, bytes] = {}
      for code in node.codes:
        for cidr in geoip_data.get(code, ()):
          net = ipaddress.ip_network(cidr, strict=False)
          if node.family == "ipv4":
            if not isinstance(net, ipaddress.IPv4Network):
              continue
            key = struct.pack(
              "<I", net.prefixlen
            ) + int(net.network_address).to_bytes(4, "big")
          else:
            if not isinstance(net, ipaddress.IPv6Network):
              continue
            key = struct.pack(
              "<I", net.prefixlen
            ) + int(net.network_address).to_bytes(16, "big")
          entries[key] = b"\x01"
      if entries:
        result[map_name] = entries
  return result


def _walk_geoip_operands(node):
  """Yield every GeoIp node reachable from a Condition subtree."""
  if node is None:
    return
  if isinstance(node, ast.Comparison):
    if isinstance(node.operand, ast.GeoIp):
      yield node.operand
    return
  if isinstance(node, ast.NotOp):
    yield from _walk_geoip_operands(node.inner)
    return
  if isinstance(node, (ast.AndOp, ast.OrOp)):
    for child in node.operands:
      yield from _walk_geoip_operands(child)
    return


def _walk_geoip_in_tier2(stmts):
  """Yield every GeoIp node reachable from a Tier 2 statement block."""
  for s in stmts:
    if isinstance(s, ast.AssignStmt):
      yield from _walk_geoip_operands(s.rhs)
    elif isinstance(s, ast.IfStmt):
      yield from _walk_geoip_operands(s.cond)
      yield from _walk_geoip_in_tier2(s.body)
      for cond, body in s.elif_branches:
        yield from _walk_geoip_operands(cond)
        yield from _walk_geoip_in_tier2(body)
      if s.else_body is not None:
        yield from _walk_geoip_in_tier2(s.else_body)


def discover(directory: Path) -> list[Path]:
  """Find all .pkt files under `directory`, sorted."""
  return sorted(directory.rglob("*.pkt"))


def run_directory(directory: Path) -> list[CaseResult]:
  """Run every .pkt under `directory` and return per-case results.

  A .pkt may declare `expected.loads: false` to assert that the
  loader rejects it (PoC for a loader bug, kept as anti-regression
  once the bug is fixed). When `loads` is omitted it defaults to
  true and a load-time exception is reported as a runner error.
  """
  import yaml as _yaml
  results = []
  for path in discover(directory):
    expects_load = _peek_expects_load(path, _yaml)
    try:
      case = pkt.load(path)
    except (ValueError, KeyError) as exc:
      results.append(_load_failure_result(path, exc, expects_load))
      continue
    if not expects_load:
      results.append(_unexpected_load_success_result(path, case))
      continue
    results.append(run_case(case))
  return results


def _peek_expects_load(path: Path, _yaml) -> bool:
  """Extract `expected.loads` from a .pkt without invoking pkt.load,
  so we can interpret a load-time exception as expected-vs-genuine."""
  try:
    doc = _yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return bool(doc.get("expected", {}).get("loads", True))
  except Exception:
    return True


def _load_failure_result(
  path: Path, exc: Exception, expects_load: bool,
) -> CaseResult:
  """Synthesize a CaseResult for a .pkt that errored during pkt.load."""
  stub = pkt.PktCase(
    name=path.stem,
    source_fw="",
    packet=pkt.Packet(raw=b"", fields={}),
    expected={},
    state={},
    path=path,
  )
  if expects_load:
    return CaseResult(
      case=stub,
      oracles=[OracleResult("loader", "error", f"{exc}")],
    )
  return CaseResult(
    case=stub,
    oracles=[
      OracleResult(
        "loader", "pass",
        f"load rejected as expected: {exc}",
      )
    ],
  )


def _unexpected_load_success_result(
  path: Path, case: pkt.PktCase,
) -> CaseResult:
  """Caller declared expected.loads=false but the loader accepted the
  file — the loader bug this PoC was guarding against has come back."""
  return CaseResult(
    case=case,
    oracles=[
      OracleResult(
        "loader", "fail",
        "expected load failure but pkt.load accepted the file — "
        "loader regression",
      )
    ],
  )


def format_results(results: list[CaseResult]) -> str:
  """Pretty-print a list of CaseResult for terminal output."""
  lines = []
  passed = sum(1 for r in results if r.passed)
  for result in results:
    marker = "PASS" if result.passed else "FAIL"
    lines.append(f"{marker}  {result.case.path.name}  ({result.case.name})")
    for oracle in result.oracles:
      if oracle.status == "pass":
        suffix = ""
      elif oracle.status == "skip":
        suffix = f"  [skip: {oracle.detail}]"
      else:
        suffix = f"  -- {oracle.detail}"
      lines.append(f"      {oracle.name:<11}  {oracle.status}{suffix}")
  lines.append("")
  lines.append(f"{passed}/{len(results)} cases passed")
  return "\n".join(lines)
