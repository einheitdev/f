"""Semantic analysis: protocol guards, types, default placement.

Walks the AST and rejects programs that parse but violate v0.1
semantics. Per spec FWL_V01_SPEC.md:382-400, errors are fatal — first
error encountered is reported and analysis stops.

Phase 0 surface (hook + bare allow rules) has no semantic constraints
beyond what the grammar already enforces, so analyze() is currently
a pass-through. Checks land per construct.
"""
from __future__ import annotations

from . import ast


def analyze(program: ast.Program) -> ast.Program:
  """Run the semantic pass.

  Returns the same program object on success. Raises FwlException
  with category="semantic" on the first violation.
  """
  return program
