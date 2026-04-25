"""AST node types for FWL v0.1.

One dataclass per spec production. The shape of these nodes is the
contract between the parser, the analyzer, the interpreter, and the
emitter — change cautiously.

Spec reference: docs/FWL_V01_SPEC.md grammar section.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Union

from .errors import Span


class Action(Enum):
  """Terminal action verbs (FWL_V01_SPEC.md:78).

  Phase 3 ships ALLOW and DROP; LOG and COUNT join later.
  """
  ALLOW = "allow"
  DROP = "drop"


class Proto(Enum):
  """Protocol keywords used as enum operands for pkt.proto."""
  TCP = "tcp"
  UDP = "udp"
  ICMP = "icmp"


# Field identifier strings keyed off the spec's accessor names. Using
# strings (not enums) keeps the AST extension-friendly: future fields
# don't require enum updates everywhere that matches on field type.
FIELD_PROTO = "pkt.proto"
FIELD_SRC_IP = "pkt.src_ip"
FIELD_DST_IP = "pkt.dst_ip"
FIELD_SRC_PORT = "pkt.src_port"
FIELD_DST_PORT = "pkt.dst_port"
FIELD_TCP_SYN = "pkt.tcp.syn"
FIELD_TCP_ACK = "pkt.tcp.ack"

IP_FIELDS = frozenset({FIELD_SRC_IP, FIELD_DST_IP})
PORT_FIELDS = frozenset({FIELD_SRC_PORT, FIELD_DST_PORT})
TCP_FLAG_FIELDS = frozenset({FIELD_TCP_SYN, FIELD_TCP_ACK})


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
class IntLiteral:
  """An integer operand (decimal or hex)."""
  value: int
  span: Span


@dataclass(frozen=True)
class IPv4Literal:
  """An IPv4 dotted-quad operand stored as a 32-bit big-endian int."""
  value: int
  span: Span


@dataclass(frozen=True)
class CidrLiteral:
  """An IPv4 CIDR operand: prefix bits + prefix length."""
  prefix: int  # 32-bit, masked
  bits: int    # 0..32
  span: Span


@dataclass(frozen=True)
class ListLiteral:
  """A `[a, b, c]` list operand. Element types must match the field."""
  items: list[Union["IntLiteral", "IPv4Literal"]]
  span: Span


@dataclass(frozen=True)
class CidrListLiteral:
  """A `[cidr1, cidr2]` list operand for IP fields."""
  items: list["CidrLiteral"]
  span: Span


@dataclass(frozen=True)
class RangeLiteral:
  """A `lo..hi` integer range operand (inclusive on both ends)."""
  lo: int
  hi: int
  span: Span


Operand = Union[
  ProtoLiteral, IntLiteral, IPv4Literal, CidrLiteral,
  ListLiteral, CidrListLiteral, RangeLiteral,
]


@dataclass(frozen=True)
class Comparison:
  """A field-vs-operand comparison.

  `op` is one of: '==', '!=', '<', '>', '<=', '>=', 'in'. Type
  compatibility between field and operand is enforced by the
  analyzer, not the parser.
  """
  field: FieldRef
  op: str
  operand: Operand
  span: Span


@dataclass(frozen=True)
class BoolField:
  """A bool field used directly as a condition (e.g. `pkt.tcp.syn`).

  Truthy when the underlying flag bit is set. `not pkt.tcp.syn` is
  modeled as NotOp wrapping a BoolField.
  """
  field: FieldRef
  span: Span


@dataclass(frozen=True)
class NotOp:
  """Logical NOT of a sub-condition."""
  inner: "Condition"
  span: Span


@dataclass(frozen=True)
class AndOp:
  """Left-to-right chain of `and` operands. Short-circuit evaluation."""
  operands: list["Condition"]
  span: Span


@dataclass(frozen=True)
class OrOp:
  """Left-to-right chain of `or` operands. Short-circuit evaluation."""
  operands: list["Condition"]
  span: Span


Condition = Union[Comparison, BoolField, NotOp, AndOp, OrOp]


@dataclass(frozen=True)
class Rule:
  """A single firewall rule: action + optional condition + optional modifier.

  v0.1 grammar: `<action> [if <condition>] [<modifier>]`. The
  modifier slot lands in Phase 5 (rate_limit).
  """
  action: Action
  condition: Condition | None
  span: Span


@dataclass(frozen=True)
class Hook:
  """The `@xdp(<interface>)` declaration."""
  interface: str
  span: Span


@dataclass(frozen=True)
class DefaultRule:
  """An explicit `default <action>` final rule (FWL_V01_SPEC.md:105)."""
  action: Action
  span: Span


@dataclass(frozen=True)
class Program:
  """A complete FWL program: hook + ordered rules + optional default."""
  hook: Hook
  rules: list[Rule] = field(default_factory=list)
  default: DefaultRule | None = None
