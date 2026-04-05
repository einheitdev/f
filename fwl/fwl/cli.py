"""FWL CLI — fwl compile, fwl parse, fwl check."""

import sys
from pathlib import Path

import click

from fwl.analyzer import analyze
from fwl.emitter import emit
from fwl.parser import parse


@click.group()
@click.version_option()
def main():
  """FWL — Firewall Language compiler for eBPF/XDP."""


@main.command()
@click.argument("source", type=click.Path(exists=True))
@click.option(
  "-o", "--output", type=click.Path(),
  help="Output .bpf.c file (default: stdout).")
def compile(source, output):
  """Compile a .fw file to BPF C."""
  source_path = Path(source)
  text = source_path.read_text()

  try:
    ast = parse(text)
  except Exception as e:
    click.echo(f"Parse error: {e}", err=True)
    sys.exit(1)

  result = analyze(ast)
  if result.errors:
    for err in result.errors:
      click.echo(f"Error: {err}", err=True)
    sys.exit(1)

  code = emit(result, filename=source_path.stem)

  if output:
    Path(output).write_text(code)
    click.echo(f"Wrote {output}")
  else:
    click.echo(code)


@main.command()
@click.argument("source", type=click.Path(exists=True))
def parse_cmd(source):
  """Parse a .fw file and print the AST (for debugging)."""
  text = Path(source).read_text()

  try:
    ast = parse(text)
  except Exception as e:
    click.echo(f"Parse error: {e}", err=True)
    sys.exit(1)

  for stmt in ast.stmts:
    click.echo(stmt)


@main.command()
@click.argument("source", type=click.Path(exists=True))
def check(source):
  """Check a .fw file for errors without emitting C."""
  text = Path(source).read_text()

  try:
    ast = parse(text)
  except Exception as e:
    click.echo(f"Parse error: {e}", err=True)
    sys.exit(1)

  result = analyze(ast)
  if result.errors:
    for err in result.errors:
      click.echo(f"Error: {err}", err=True)
    sys.exit(1)

  n_funcs = len(result.funcs)
  n_rules = len(result.rules)
  n_maps = len(result.maps)
  click.echo(
    f"OK: {n_funcs} functions, {n_rules} rules, "
    f"{n_maps} maps")
