"""Three-oracle test runner.

For each `.pkt` file: load, parse the embedded `source_fw`, evaluate
through the AST interpreter, compile and execute via BPF_PROG_RUN,
compare both to the file's `expected:` block. Reports per-oracle
pass/fail with diffs.

Methodology reference: docs/F_DEVELOPMENT_METHODOLOGY.md:132-181.
"""
from __future__ import annotations
import subprocess
from dataclasses import dataclass
from pathlib import Path

from . import analyzer, bpf_runner, emitter, interpreter, parser, pkt
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
  if "bpf_action" not in case.expected:
    return OracleResult(
      "spec", "fail",
      "expected.bpf_action missing — cannot verify",
    )
  if case.expected.get("compiles", True) is False:
    # No expected action when the program is supposed to fail to
    # compile. The interpreter and bpf oracles will then check the
    # compile-fail behavior.
    return OracleResult(
      "spec", "pass", "compile-failure case (no action)"
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

  got = interpreter.evaluate(program, case.packet.fields)
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

  try:
    got = bpf_runner.run(c_source, case.packet.raw)
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


def discover(directory: Path) -> list[Path]:
  """Find all .pkt files under `directory`, sorted."""
  return sorted(directory.rglob("*.pkt"))


def run_directory(directory: Path) -> list[CaseResult]:
  """Run every .pkt under `directory` and return per-case results."""
  results = []
  for path in discover(directory):
    case = pkt.load(path)
    results.append(run_case(case))
  return results


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
