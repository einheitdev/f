"""Semantic analysis: protocol guards, types, default placement.

Walks the AST and rejects programs that parse but violate v0.1
semantics. Per spec FWL_V01_SPEC.md:382-400, errors are fatal — first
error encountered is reported and analysis stops.

Protocol guard model: at every point in a condition we track the set
of protocols the packet *might* be (`possible`), starting as None
(unconstrained). A `pkt.proto == X` comparison constrains `possible`
to {X} for the rest of the AND chain. AND propagates the constraint
forward; OR unions branch-exit constraints; NOT discards them. When
a port/flag field is accessed, `possible` must be a subset of the
field's allowed protocol set — None (unconstrained) does not satisfy
any guard requirement.
"""
from __future__ import annotations

from . import ast
from .errors import FwlError, FwlException


_ALL_PROTOS = frozenset({ast.Proto.TCP, ast.Proto.UDP, ast.Proto.ICMP})


# Allowed protocols per field. Empty set => no guard required.
_ALLOWED_PROTOS: dict[str, frozenset[ast.Proto]] = {
  ast.FIELD_PROTO: _ALL_PROTOS,
  ast.FIELD_SRC_IP: _ALL_PROTOS,
  ast.FIELD_DST_IP: _ALL_PROTOS,
  ast.FIELD_SRC_PORT: frozenset({ast.Proto.TCP, ast.Proto.UDP}),
  ast.FIELD_DST_PORT: frozenset({ast.Proto.TCP, ast.Proto.UDP}),
  ast.FIELD_TCP_SYN: frozenset({ast.Proto.TCP}),
  ast.FIELD_TCP_ACK: frozenset({ast.Proto.TCP}),
}


# A `Possible` value is either None (no constraint, packet could be
# any protocol) or a frozenset of protos the packet must be one of.
Possible = frozenset[ast.Proto] | None


def analyze(program: ast.Program) -> ast.Program:
  """Run the semantic pass.

  Returns the same program object on success. Raises FwlException
  with category="semantic" on the first violation.
  """
  for rule in program.rules:
    if rule.condition is not None:
      _check(rule.condition, possible=None)
    if rule.modifier is not None:
      _check_modifier(rule.modifier)
  return program


def _check_modifier(mod: ast.RateLimit) -> None:
  """Validate a rate_limit modifier."""
  if mod.threshold <= 0:
    raise FwlException(
      FwlError(
        category="semantic",
        message="rate_limit threshold must be > 0",
        span=mod.span,
      )
    )
  # Grammar already restricts per_field to one of the four valid
  # values, so no field-name check is needed here.


def _check(node: ast.Condition, possible: Possible) -> Possible:
  """Walk a condition node enforcing protocol guards.

  Returns the constraint set after this node evaluates true, for use
  by subsequent siblings in an AND chain.
  """
  if isinstance(node, ast.Comparison):
    _require_guard(node.field, possible)
    if (
      node.field.name == ast.FIELD_PROTO
      and node.op == "=="
      and isinstance(node.operand, ast.ProtoLiteral)
    ):
      return _intersect(possible, frozenset({node.operand.proto}))
    return possible

  if isinstance(node, ast.BoolField):
    _require_guard(node.field, possible)
    return possible

  if isinstance(node, ast.NotOp):
    # `not X` doesn't tell us anything definite about X's
    # constraints. Walk the inner to enforce its required guards
    # but discard its returned constraint set.
    _check(node.inner, possible)
    return possible

  if isinstance(node, ast.AndOp):
    scope = possible
    for child in node.operands:
      scope = _check(child, scope)
    return scope

  if isinstance(node, ast.OrOp):
    # Each branch starts with the outer scope; the branches' exits
    # union into "the packet is one of these alternatives."
    branch_exits: list[Possible] = []
    for child in node.operands:
      branch_exits.append(_check(child, possible))
    return _union_exits(branch_exits)

  raise NotImplementedError(
    f"analyzer: unsupported node {type(node).__name__}"
  )


def _intersect(a: Possible, b: frozenset[ast.Proto]) -> Possible:
  """Intersect a possibility set with a new constraint."""
  if a is None:
    return frozenset(b)
  return a & b


def _union_exits(branches: list[Possible]) -> Possible:
  """Union of branch-exit possibility sets (OR semantics).

  If any branch is unconstrained (None), the union is unconstrained:
  the packet could be anything that branch allows.
  """
  result: frozenset[ast.Proto] = frozenset()
  for b in branches:
    if b is None:
      return None
    result = result | b
  return result


def _require_guard(field: ast.FieldRef, possible: Possible) -> None:
  """Raise FwlException if `field`'s required guard isn't satisfied."""
  allowed = _ALLOWED_PROTOS.get(field.name)
  if allowed is None:
    raise FwlException(
      FwlError(
        category="semantic",
        message=f"unknown field '{field.name}'",
        span=field.span,
      )
    )
  if allowed == _ALL_PROTOS:
    return
  if possible is not None and possible <= allowed:
    return
  options = " or ".join(sorted(p.value for p in allowed))
  raise FwlException(
    FwlError(
      category="semantic",
      message=(
        f"{field.name} requires 'pkt.proto == {options}' guard"
      ),
      span=field.span,
    )
  )
