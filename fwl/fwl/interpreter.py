"""AST interpreter — independent oracle for the verification loop.

Walks the AST against a parsed packet (a dict of decoded fields)
and returns the XDP action the program would take. Implementation
must not share any code with the emitter beyond AST node definitions
— the whole point is independent evaluation.

Spec reference: docs/FWL_V01_SPEC.md, methodology reference:
docs/F_DEVELOPMENT_METHODOLOGY.md:307-311.
"""
from __future__ import annotations
from enum import Enum
from typing import Any

from . import ast


class XdpAction(Enum):
  """The XDP return values an FWL program can produce.

  Distinct from ast.Action because XDP_PASS is the implicit default
  that fires when no rule matches (FWL_V01_SPEC.md:70).
  """
  PASS = "XDP_PASS"
  DROP = "XDP_DROP"


_ACTION_TO_XDP = {
  ast.Action.ALLOW: XdpAction.PASS,
  ast.Action.DROP: XdpAction.DROP,
}


def evaluate(program: ast.Program, packet: dict[str, Any]) -> XdpAction:
  """Run `program` against `packet` and return the resulting XDP action.

  `packet` is a decoded-fields dict produced by pkt.parse_packet().
  Phase 0 only handles bare action rules; future phases extend this
  with condition evaluation, modifiers, defaults, etc.
  """
  for rule in program.rules:
    return _ACTION_TO_XDP[rule.action]
  return XdpAction.PASS
