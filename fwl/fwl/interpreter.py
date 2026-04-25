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
  Rules execute top to bottom; first matching rule's action wins.
  No matching rule => implicit XDP_PASS per FWL_V01_SPEC.md:70.
  """
  for rule in program.rules:
    if rule.condition is None or _eval_condition(rule.condition, packet):
      return _ACTION_TO_XDP[rule.action]
  return XdpAction.PASS


def _eval_condition(cond: ast.Condition, packet: dict[str, Any]) -> bool:
  """Evaluate a Phase 1 condition (single comparison) against a packet."""
  return _eval_comparison(cond, packet)


def _eval_comparison(cmp: ast.Comparison, packet: dict[str, Any]) -> bool:
  """Evaluate a `field op operand` comparison.

  Phase 1 only handles `pkt.proto == <proto-keyword>`. If the packet
  dict is missing the field (e.g. a non-IP packet has no proto), the
  comparison is treated as false — the rule does not match.
  """
  if cmp.field.name == ast.FIELD_PROTO:
    actual = packet.get("proto")
    expected = cmp.operand.proto.value
    if cmp.op == "==":
      return actual == expected
  raise NotImplementedError(
    f"interpreter: comparison {cmp.field.name} {cmp.op} not supported yet"
  )
