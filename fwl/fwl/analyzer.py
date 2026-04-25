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


_MAX_COUNTERS = 256  # FWL_V01_SPEC.md:329


def analyze(program: ast.Program) -> ast.Program:
  """Run the semantic pass.

  Returns the same program object on success. Raises FwlException
  with category="semantic" on the first violation.
  """
  counter_names: set[str] = set()
  for rule in program.rules:
    if rule.condition is not None:
      _check(rule.condition, possible=None)
    if rule.modifier is not None:
      _check_modifier(rule.modifier)
    if rule.action == ast.Action.COUNT and rule.counter_name is not None:
      counter_names.add(rule.counter_name)

  if len(counter_names) > _MAX_COUNTERS:
    # Find the rule that pushed us over so we can point at a span.
    span = next(
      (r.span for r in program.rules
       if r.action == ast.Action.COUNT),
      None,
    )
    raise FwlException(
      FwlError(
        category="semantic",
        message=(
          f"program declares {len(counter_names)} counters; "
          f"v0.1 limit is {_MAX_COUNTERS}"
        ),
        span=span,
      )
    )
  return program


_FIELD_TYPE_LABEL = {
  ast.FIELD_PROTO: "proto enum",
  ast.FIELD_SRC_IP: "ipv4",
  ast.FIELD_DST_IP: "ipv4",
  ast.FIELD_SRC_PORT: "port (u16)",
  ast.FIELD_DST_PORT: "port (u16)",
  ast.FIELD_TCP_SYN: "bool",
  ast.FIELD_TCP_ACK: "bool",
}


def _operand_label(operand) -> str:
  """Human-readable type tag for a comparison operand."""
  if isinstance(operand, ast.ProtoLiteral):
    return f"proto keyword '{operand.proto.value}'"
  if isinstance(operand, ast.IntLiteral):
    return f"integer {operand.value}"
  if isinstance(operand, ast.IPv4Literal):
    return "ipv4 literal"
  if isinstance(operand, ast.CidrLiteral):
    return "cidr"
  if isinstance(operand, ast.CidrListLiteral):
    return "cidr list"
  if isinstance(operand, ast.RangeLiteral):
    return "integer range"
  if isinstance(operand, ast.ListLiteral):
    return "list"
  return type(operand).__name__


def _check_port_int(value: int, span) -> None:
  """Spec error #7: port literal must be in 0..65535."""
  if not (0 <= value <= 65535):
    raise FwlException(
      FwlError(
        category="semantic",
        message=(
          f"port value {value} outside valid range 0..65535"
        ),
        span=span,
      )
    )


def _type_error(field_label: str, op: str, operand, span) -> FwlException:
  """Spec error #3: type mismatch in comparison."""
  return FwlException(
    FwlError(
      category="semantic",
      message=(
        f"cannot apply '{op}' to {field_label} with "
        f"{_operand_label(operand)}"
      ),
      span=span,
    )
  )


def _check_comparison_types(cmp: ast.Comparison) -> None:
  """Enforce the spec's comparison-operand type rules.

  Covers spec error #3 (type mismatch), #7 (port literal outside
  0..65535), #8 (range with lo > hi).
  """
  field_name = cmp.field.name
  op = cmp.op
  operand = cmp.operand
  span = cmp.span
  field_label = _FIELD_TYPE_LABEL.get(field_name, field_name)

  if field_name == ast.FIELD_PROTO:
    # Grammar restricts proto comparisons to ProtoLiteral via the
    # enum_eq / enum_neq aliases, so no further type check needed.
    if op not in ("==", "!="):
      raise _type_error(field_label, op, operand, span)
    return

  if field_name in ast.IP_FIELDS:
    if op in ("==", "!="):
      if not isinstance(operand, ast.IPv4Literal):
        raise _type_error(field_label, op, operand, span)
    elif op == "in":
      if not isinstance(
        operand, (ast.CidrLiteral, ast.CidrListLiteral, ast.ListLiteral)
      ):
        raise _type_error(field_label, op, operand, span)
      if isinstance(operand, ast.ListLiteral):
        for item in operand.items:
          if not isinstance(item, ast.IPv4Literal):
            raise _type_error(field_label, op, item, item.span)
    else:
      raise _type_error(field_label, op, operand, span)
    return

  if field_name in ast.PORT_FIELDS:
    if op in ("==", "!=", "<", ">", "<=", ">="):
      if not isinstance(operand, ast.IntLiteral):
        raise _type_error(field_label, op, operand, span)
      _check_port_int(operand.value, operand.span)
    elif op == "in":
      if isinstance(operand, ast.RangeLiteral):
        _check_port_int(operand.lo, operand.span)
        _check_port_int(operand.hi, operand.span)
        if operand.lo > operand.hi:
          raise FwlException(
            FwlError(
              category="semantic",
              message=(
                f"range lower bound ({operand.lo}) exceeds upper "
                f"bound ({operand.hi})"
              ),
              span=operand.span,
            )
          )
      elif isinstance(operand, ast.ListLiteral):
        for item in operand.items:
          if not isinstance(item, ast.IntLiteral):
            raise _type_error(field_label, op, item, item.span)
          _check_port_int(item.value, item.span)
      else:
        raise _type_error(field_label, op, operand, span)
    else:
      raise _type_error(field_label, op, operand, span)
    return

  # Bool fields shouldn't appear in a Comparison node — the grammar
  # routes them through bool_field/primary instead. Defensive check.
  if field_name in ast.TCP_FLAG_FIELDS:
    raise _type_error(field_label, op, operand, span)


_MAX_RL_THRESHOLD = (1 << 32) - 1


def _check_modifier(mod: ast.RateLimit) -> None:
  """Validate a rate_limit modifier.

  Threshold is bounded to u32 max because the emitted BPF C stores
  bucket counts as `__u32` (see emitter.py's fwl_rl_state struct).
  Without this bound, large literals like 10**40 are accepted by the
  analyzer and emitted as bare decimals into the C source, where
  clang rejects them with "integer literal is too large to be
  represented in any integer type" — a soundness gap discovered by
  the explore-mode bug hunter.
  """
  if mod.threshold <= 0:
    raise FwlException(
      FwlError(
        category="semantic",
        message="rate_limit threshold must be > 0",
        span=mod.span,
      )
    )
  if mod.threshold > _MAX_RL_THRESHOLD:
    raise FwlException(
      FwlError(
        category="semantic",
        message=(
          f"rate_limit threshold {mod.threshold} exceeds "
          f"u32 max ({_MAX_RL_THRESHOLD}); the BPF counter is __u32"
        ),
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
    _check_comparison_types(node)
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
