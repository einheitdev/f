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
}


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

  result = interpreter.evaluate_full(
    program, case.packet.fields, case.state,
    geoip_data=(case.geoip_data or None),
  )
  if result.action != expected:
    return OracleResult(
      "interpreter", "fail",
      f"expected {expected.value}, got {result.action.value}",
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

  c_source = emitter.emit(program)
  map_init = _build_map_init(program, case.state)
  for name, entries in _build_geoip_map_init(
    program, case.geoip_data or {}
  ).items():
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

  if result.action != expected:
    return OracleResult(
      "bpf", "fail",
      f"expected {expected.value}, got {result.action.value}",
    )

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


def run_case(case: pkt.PktCase) -> CaseResult:
  """Run all oracles against one .pkt case."""
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
