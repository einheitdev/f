"""Three-oracle test runner.

For each `.pkt` file: load, parse the embedded `source_fw`, evaluate
through the AST interpreter, compile and execute via BPF_PROG_RUN,
compare both to the file's `expected:` block. Reports per-oracle
pass/fail with diffs.

Methodology reference: docs/F_DEVELOPMENT_METHODOLOGY.md:132-181.
"""
from __future__ import annotations
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

  got = interpreter.evaluate(program, case.packet.fields, case.state)
  if got == expected:
    return OracleResult("interpreter", "pass", "")
  return OracleResult(
    "interpreter", "fail",
    f"expected {expected.value}, got {got.value}",
  )


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

  try:
    got = bpf_runner.run(c_source, case.packet.raw, map_init)
  except bpf_runner.BpfUnavailable as exc:
    # Still try to compile, so we catch structural emitter errors.
    try:
      bpf_runner.compile_c(c_source)
    except subprocess.CalledProcessError as cexc:
      stderr = cexc.stderr.decode("utf-8", "replace")
      return OracleResult(
        "bpf", "fail", f"clang failed to compile emitter output:\n{stderr}"
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

  if got == expected:
    return OracleResult("bpf", "pass", "")
  return OracleResult(
    "bpf", "fail", f"expected {expected.value}, got {got.value}"
  )


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
