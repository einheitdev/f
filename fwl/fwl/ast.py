"""AST node types for FWL v0.1.

One dataclass per spec production. The shape of these nodes is the
contract between the parser, the analyzer, the interpreter, and the
emitter — change cautiously.

Spec reference: docs/FWL_V01_SPEC.md grammar section.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum

from .errors import Span


class Action(Enum):
  """Terminal and non-terminal action verbs.

  v0.1 actions per FWL_V01_SPEC.md:78. Phase 1 ships ALLOW and DROP;
  LOG and COUNT join in later phases.
  """
  ALLOW = "allow"
  DROP = "drop"


class Proto(Enum):
  """Protocol keywords used as enum operands for pkt.proto.

  Spec: FWL_V01_SPEC.md:140, :577.
  """
  TCP = "tcp"
  UDP = "udp"
  ICMP = "icmp"


# Field identifiers as plain strings keyed off the spec's accessor
# names. Using a string key (rather than an enum) keeps the AST
# extension-friendly: future field additions don't require enum
# updates everywhere that pattern-matches on field type.
FIELD_PROTO = "pkt.proto"


@dataclass(frozen=True)
class FieldRef:
  """A reference to a packet field, e.g. pkt.proto."""
  name: str
  span: Span


@dataclass(frozen=True)
class ProtoLiteral:
  """A bare protocol keyword (tcp, udp, icmp) as an operand."""
  proto: Proto
  span: Span


@dataclass(frozen=True)
class Comparison:
  """A field-vs-operand comparison.

  Phase 1 only models `==`; other operators (`!=`, ordered, `in`) join
  in Phase 3. `op` is a string literal so the same node type can
  carry every comparison operator the spec defines.
  """
  field: FieldRef
  op: str
  operand: ProtoLiteral
  span: Span


# A condition is currently just a Comparison; Phase 4 introduces
# boolean composition (BoolOp, NotOp). Aliasing here keeps signatures
# stable across phases.
Condition = Comparison


@dataclass(frozen=True)
class Rule:
  """A single firewall rule: action with optional condition.

  v0.1 grammar: `<action> [if <condition>] [<modifier>]`. Phase 1
  supports `<action>` and `<action> if <condition>`. The `modifier`
  slot lands in Phase 5 (rate_limit).
  """
  action: Action
  condition: Condition | None
  span: Span


@dataclass(frozen=True)
class Hook:
  """The `@xdp(<interface>)` declaration.

  v0.1 requires exactly one hook declaration per program
  (FWL_V01_SPEC.md:58).
  """
  interface: str
  span: Span


@dataclass(frozen=True)
class DefaultRule:
  """An explicit `default <action>` final rule.

  Spec: FWL_V01_SPEC.md:105-116. Only ALLOW and DROP are valid as
  default actions because LOG/COUNT are non-terminal — falling
  through past them lands at the implicit allow anyway, so calling
  that "the default" makes no sense.
  """
  action: Action
  span: Span


@dataclass(frozen=True)
class Program:
  """A complete FWL program: hook + ordered rules + optional default.

  Per the spec grammar (`program = hook_decl { rule } [ default_rule ]`)
  zero rules are valid when a `default` rule is present.
  """
  hook: Hook
  rules: list[Rule] = field(default_factory=list)
  default: DefaultRule | None = None
