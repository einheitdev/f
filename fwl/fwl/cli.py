"""`fwl` command-line interface.

Subcommands:
  parse <file>             Parse only; print AST.
  check <file>             Parse + semantic check.
  compile <file>           Full compile to .bpf.c (and .bpf.o via clang).
  interpret <file> <pkt>   AST interpreter against a test packet.
  test <dir>               Run a corpus directory through the
                           verification loop.
  version                  Print version.
"""
from __future__ import annotations
import sys
from pathlib import Path

import click

from . import (
  __version__, analyzer, ast, emitter, interpreter, parser, pkt, runner
)
from .errors import FwlException


@click.group()
def main() -> None:
  """FWL — Firewall Language compiler for eBPF/XDP."""


@main.command()
@click.argument("source", type=click.Path(exists=True, path_type=Path))
def parse(source: Path) -> None:
  """Parse SOURCE and print the AST."""
  text = source.read_text(encoding="utf-8")
  try:
    program = parser.parse(text)
  except FwlException as exc:
    click.echo(exc.error.format(), err=True)
    sys.exit(1)
  click.echo(_format_program(program))


def _format_program(p: ast.Program) -> str:
  """One-rule-per-line summary of an AST. Easier to scan than dataclass repr."""
  lines = [f"@xdp({p.hook.interface})"]
  for i, rule in enumerate(p.rules):
    parts = [rule.action.value]
    if rule.action == ast.Action.COUNT and rule.counter_name:
      parts.append(rule.counter_name)
    if rule.condition is not None:
      parts.append(f"if {_format_condition(rule.condition)}")
    if rule.modifier is not None:
      parts.append(
        f"limited by rate_limit({rule.modifier.threshold}, "
        f"per={rule.modifier.per_field})"
      )
    lines.append(f"  [{i}] {' '.join(parts)}")
  if p.default is not None:
    lines.append(f"  default {p.default.action.value}")
  return "\n".join(lines)


def _format_condition(node: ast.Condition) -> str:
  """Pretty-print a condition AST as the source-form expression."""
  if isinstance(node, ast.Comparison):
    return f"{node.field.name} {node.op} {_format_operand(node.operand)}"
  if isinstance(node, ast.BoolField):
    return node.field.name
  if isinstance(node, ast.NotOp):
    return f"not ({_format_condition(node.inner)})"
  if isinstance(node, ast.AndOp):
    return "(" + " and ".join(
      _format_condition(c) for c in node.operands
    ) + ")"
  if isinstance(node, ast.OrOp):
    return "(" + " or ".join(
      _format_condition(c) for c in node.operands
    ) + ")"
  return repr(node)


def _format_operand(op: ast.Operand) -> str:
  """Pretty-print an operand AST as the source-form literal."""
  if isinstance(op, ast.ProtoLiteral):
    return op.proto.value
  if isinstance(op, ast.IntLiteral):
    return str(op.value)
  if isinstance(op, ast.IPv4Literal):
    return _ipv4_str(op.value)
  if isinstance(op, ast.CidrLiteral):
    return f"{_ipv4_str(op.prefix)}/{op.bits}"
  if isinstance(op, ast.RangeLiteral):
    return f"{op.lo}..{op.hi}"
  if isinstance(op, ast.ListLiteral):
    return "[" + ", ".join(_format_operand(i) for i in op.items) + "]"
  if isinstance(op, ast.CidrListLiteral):
    return "[" + ", ".join(_format_operand(i) for i in op.items) + "]"
  return repr(op)


def _ipv4_str(value: int) -> str:
  """32-bit int back to dotted-quad."""
  return ".".join(str((value >> shift) & 0xFF) for shift in (24, 16, 8, 0))


@main.command()
@click.argument("source", type=click.Path(exists=True, path_type=Path))
def check(source: Path) -> None:
  """Parse + semantic check of SOURCE without code generation."""
  text = source.read_text(encoding="utf-8")
  try:
    analyzer.analyze(parser.parse(text))
  except FwlException as exc:
    click.echo(exc.error.format(), err=True)
    sys.exit(1)
  click.echo("ok")


@main.command()
@click.argument("source", type=click.Path(exists=True, path_type=Path))
@click.option(
  "-o", "--output", type=click.Path(path_type=Path), default=None,
  help="Write generated C to this path instead of stdout.",
)
def compile(source: Path, output: Path | None) -> None:
  """Compile SOURCE to BPF C."""
  text = source.read_text(encoding="utf-8")
  try:
    program = analyzer.analyze(parser.parse(text))
  except FwlException as exc:
    click.echo(exc.error.format(), err=True)
    sys.exit(1)
  c_source = emitter.emit(program)
  if output is None:
    click.echo(c_source, nl=False)
  else:
    output.write_text(c_source, encoding="utf-8")


@main.command()
@click.argument("source", type=click.Path(exists=True, path_type=Path))
@click.argument("pkt_file", type=click.Path(exists=True, path_type=Path))
def interpret(source: Path, pkt_file: Path) -> None:
  """Run SOURCE against the packet in PKT_FILE via the AST interpreter."""
  text = source.read_text(encoding="utf-8")
  try:
    program = analyzer.analyze(parser.parse(text))
  except FwlException as exc:
    click.echo(exc.error.format(), err=True)
    sys.exit(1)
  case = pkt.load(pkt_file)
  action = interpreter.evaluate(
    program, case.packet.fields, case.state
  )
  fired = _which_rule_fired(program, case.packet.fields, case.state)
  click.echo(f"{action.value} ({fired})")


def _which_rule_fired(
  program, packet, state
) -> str:
  """Return a human-readable label for which rule produced the action.

  Mirrors the interpreter's match logic — kept separate so the
  interpreter doesn't carry diagnostic responsibilities into its
  oracle role.
  """
  state = state or {}
  for idx, rule in enumerate(program.rules):
    if (rule.condition is not None
        and not interpreter._eval(rule.condition, packet)):
      continue
    if rule.modifier is not None:
      if not interpreter._rate_limit_allows(
        rule.modifier, idx, packet, state
      ):
        continue
    if rule.action in interpreter._TERMINAL_ACTION_TO_XDP:
      return f"rule {idx}: {rule.action.value}"
  if program.default is not None:
    return f"default: {program.default.action.value}"
  return "no rule matched (implicit allow)"


@main.command()
@click.argument(
  "directory", type=click.Path(exists=True, file_okay=False, path_type=Path)
)
def test(directory: Path) -> None:
  """Run all .pkt cases under DIRECTORY through all three oracles."""
  results = runner.run_directory(directory)
  click.echo(runner.format_results(results))
  if not all(r.passed for r in results):
    sys.exit(1)


@main.command()
def version() -> None:
  """Print the FWL compiler version."""
  click.echo(__version__)
