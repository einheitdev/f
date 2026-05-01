"""AST node types for FWL v0.2.

One dataclass per spec production. The shape of these nodes is the
contract between the parser, the analyzer, the interpreter, and the
emitter — change cautiously.

Spec reference: docs/FWL_V02_SPEC.md grammar section. v0.2 is a
near-superset of v0.1; nodes added in v0.2 carry "v0.2" in their
docstring. Construct 1 (IPv6 fields) adds Ipv6Literal, Ipv6CidrLiteral,
Ipv6ListLiteral, Ipv6CidrListLiteral, the FIELD_SRC_IP6 / FIELD_DST_IP6
constants, and the ICMP6 proto value.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Union

from .errors import Span


class Action(Enum):
  """Action verbs (FWL_V01_SPEC.md:78).

  ALLOW and DROP are terminal — once a packet matches, evaluation
  stops and the action takes effect.

  LOG and COUNT are non-terminal — they record the event but do not
  affect packet disposition; evaluation continues to the next rule
  (FWL_V01_SPEC.md:92).
  """
  ALLOW = "allow"
  DROP = "drop"
  LOG = "log"
  COUNT = "count"


TERMINAL_ACTIONS = frozenset({Action.ALLOW, Action.DROP})


class Proto(Enum):
  """Protocol keywords used as enum operands for pkt.proto.

  v0.2 adds ICMP6 (next_header == 58 for IPv6 frames). `tcp`, `udp`
  match across both v4 and v6 in v6-active programs per the
  proto-enum table in FWL_V02_SPEC.md; `icmp` is byte 1 (admitted
  on either family in v6-active programs); `icmp6` is byte 58 and
  family-restricted to IPv6.
  """
  TCP = "tcp"
  UDP = "udp"
  ICMP = "icmp"
  ICMP6 = "icmp6"


# Field identifier strings keyed off the spec's accessor names. Using
# strings (not enums) keeps the AST extension-friendly: future fields
# don't require enum updates everywhere that matches on field type.
FIELD_PROTO = "pkt.proto"
FIELD_SRC_IP = "pkt.src_ip"
FIELD_DST_IP = "pkt.dst_ip"
FIELD_SRC_IP6 = "pkt.src_ip6"
FIELD_DST_IP6 = "pkt.dst_ip6"
FIELD_SRC_PORT = "pkt.src_port"
FIELD_DST_PORT = "pkt.dst_port"
FIELD_TCP_SYN = "pkt.tcp.syn"
FIELD_TCP_ACK = "pkt.tcp.ack"

IP_FIELDS = frozenset({FIELD_SRC_IP, FIELD_DST_IP})
IP6_FIELDS = frozenset({FIELD_SRC_IP6, FIELD_DST_IP6})
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
class Ipv6Literal:
  """An IPv6 RFC 5952 canonical address (v0.2).

  Stored as a 128-bit integer in network byte order (high bits in
  the int's high bits — same convention as IPv4Literal). Parser
  validates canonicality before constructing the node; the source
  text that produced this literal is preserved on `.span` for
  error messages.
  """
  value: int  # 128-bit, masked
  span: Span


@dataclass(frozen=True)
class Ipv6CidrLiteral:
  """An IPv6 CIDR operand: prefix bits + prefix length (v0.2).

  prefix is the masked 128-bit value (host bits cleared) — analyser
  emits a warning when the source had non-zero host bits, identical
  to v0.1's IPv4-CIDR rule. bits is 0..128.
  """
  prefix: int  # 128-bit, masked
  bits: int    # 0..128
  span: Span


@dataclass(frozen=True)
class ListLiteral:
  """A `[a, b, c]` list operand. Element types must match the field."""
  items: list[Union["IntLiteral", "IPv4Literal", "Ipv6Literal"]]
  span: Span


@dataclass(frozen=True)
class CidrListLiteral:
  """A `[cidr1, cidr2]` list operand for IPv4 fields."""
  items: list["CidrLiteral"]
  span: Span


@dataclass(frozen=True)
class Ipv6CidrListLiteral:
  """A `[cidr1, cidr2]` list operand for IPv6 fields (v0.2).

  Distinct from CidrListLiteral so the analyser can type-check the
  family of every element uniformly. Mixed-family lists are
  syntactically a `ListLiteral` of mixed operand kinds; the analyser
  rejects them as a type error.
  """
  items: list["Ipv6CidrLiteral"]
  span: Span


@dataclass(frozen=True)
class RangeLiteral:
  """A `lo..hi` integer range operand (inclusive on both ends)."""
  lo: int
  hi: int
  span: Span


# GeoIp is a mutable dataclass (unlike the rest of the AST) because
# call_index and family are filled in by the analyzer pass after
# parsing — the parser doesn't know the call's source-order position
# or its host comparison's LHS family. The other fields (codes, span)
# are immutable in practice; the contract is that only the analyzer
# writes call_index/family, and only once.
@dataclass
class GeoIp:
  """`geoip(<CC>, <CC>, ...)` operand for IP-membership tests (v0.2).

  Codes are always uppercase 2-letter ISO 3166-1 alpha-2 strings;
  the parser enforces shape and the analyzer validates against the
  iso3166 frozen list. `call_index` is the zero-based source-order
  index assigned by the analyzer for the bundle manifest. Per
  FWL_V02_SPEC.md, each textual occurrence is its own call site
  bound to a single family — the family is inferred from the LHS
  of the host comparison and stored once type-checking succeeds.
  Both fields default to sentinel values (-1 / "") at parse time.
  """
  codes: tuple[str, ...]
  call_index: int = -1
  family: str = ""
  span: Span | None = None


Operand = Union[
  ProtoLiteral, IntLiteral, IPv4Literal, CidrLiteral,
  Ipv6Literal, Ipv6CidrLiteral,
  ListLiteral, CidrListLiteral, Ipv6CidrListLiteral,
  RangeLiteral, GeoIp,
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
class RateLimit:
  """`rate_limit(<N>, per=<field>)` modifier (FWL_V01_SPEC.md:266).

  per_field is the bare bucket key name: src_ip, dst_ip, src_port,
  dst_port. The grammar restricts it to those four; the analyzer
  enforces threshold > 0.
  """
  threshold: int
  per_field: str
  span: Span


@dataclass(frozen=True)
class Rule:
  """A single firewall rule: action + optional condition + optional modifier.

  v0.1 grammar: `<action> [if <condition>] [<modifier>]`. The
  `if` clause and the modifier are independently optional, so a rule
  may consist of just `<action>`, `<action> if <cond>`,
  `<action> limited by ...`, or all three together.

  `counter_name` is set only for COUNT actions and names the per-CPU
  counter to bump.
  """
  action: Action
  condition: Condition | None
  modifier: RateLimit | None
  span: Span
  counter_name: str | None = None


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


class LocalType(Enum):
  """Static types for Tier 2 locals (FWL_V02_SPEC.md § Tier 2 / Type rules).

  v0.2 has no list-shaped local types; the type universe is exactly
  the six scalars listed below. The smallest unsigned integer type
  containing an integer literal value (u16 for 0..65535, u32 for
  larger) is selected by the analyzer's literal-typing pass.
  """
  BOOL = "bool"
  U16 = "u16"
  U32 = "u32"
  IPV4 = "ipv4"
  IPV6 = "ipv6"
  PROTO = "proto"


@dataclass(frozen=True)
class LocalRead:
  """A local variable read inside a Tier 2 condition or scalar_expr.

  The grammar admits `identifier` in both `lvalue`/`rvalue` (locals
  on either side of a comparison) and `bool_primary` (a bare `bool`
  local as an `if` primary). The analyzer resolves the name to the
  function's locals, type-checks the use, and emits the
  read-before-assignment error when the name has no preceding
  assignment on every path. Stays as a `LocalRead` in the AST so the
  emitter can emit the C local variable name.
  """
  name: str
  span: Span


# RateLimitCall is mutable to let the analyzer fill `call_index`
# post-parse, mirroring the GeoIp convention.
@dataclass
class RateLimitCall:
  """`rate_limit(<N>, per=<field>)` as a primary inside a Tier 2 condition.

  Distinct from RateLimit (which is a Tier 1 rule modifier). Per
  FWL_V02_SPEC.md, this primary form is bool-valued: true when the
  bucket for the per-field bucket key is at or above the threshold.
  call_index is assigned by the analyzer in source-order, mirroring
  Tier 1 rate_limit's per-rule-idx slot allocation.
  """
  threshold: int
  per_field: str
  span: Span
  call_index: int = -1


@dataclass(frozen=True)
class AssignStmt:
  """A Tier 2 local-variable assignment (`name = scalar_expr`).

  RHS is the `scalar_expr` AST node — one of: Comparison, BoolField,
  NotOp, AndOp, OrOp, LocalRead, FieldRef, IntLiteral, IPv4Literal,
  Ipv6Literal, ProtoLiteral, RateLimitCall (analyzer-rejected here per
  spec), GeoIp (rejected per spec). The analyzer narrows the surface
  and infers the local's type from the first source-order assignment.
  """
  name: str
  rhs: "ScalarExpr"
  span: Span


@dataclass(frozen=True)
class ActionStmt:
  """A Tier 2 action statement: allow / drop / log / count <name>.

  allow and drop are terminal; log and count are non-terminal and
  fall through to the next statement. Mirrors Action+Rule from
  Tier 1 but as a statement form.
  """
  action: Action
  span: Span
  counter_name: str | None = None


@dataclass(frozen=True)
class IfStmt:
  """A Tier 2 `if` / `elif` / `else` chain (FWL_V02_SPEC.md grammar).

  An IfStmt holds the leading `if`'s condition and body, plus an
  ordered list of (cond, body) tuples for `elif` branches and an
  optional final `else` body. Each body is a list of statements.
  """
  cond: "Condition"
  body: list["Stmt"]
  elif_branches: list[tuple["Condition", list["Stmt"]]]
  else_body: list["Stmt"] | None
  span: Span


# A Tier 2 statement is one of these four shapes.
Stmt = Union[IfStmt, AssignStmt, ActionStmt]


# A `scalar_expr` is the RHS of an `AssignStmt`, narrowed at analysis
# time. The grammar admits a broader set; the analyzer rejects
# list/CIDR/range/geoip_call/rate_limit_call RHSs with the spec's
# "scalar RHS" error message.
ScalarExpr = Union[
  Comparison, BoolField, NotOp, AndOp, OrOp,
  LocalRead, FieldRef,
  IntLiteral, IPv4Literal, Ipv6Literal, ProtoLiteral,
]


@dataclass(frozen=True)
class FunctionDef:
  """A Tier 2 `def <name>(pkt):` function (v0.2).

  `name` is the bare identifier; `body` is the ordered statement list
  (at least one statement, per FWL_V02_SPEC.md Edge cases). v0.2
  permits exactly one FunctionDef per Program; mixing with Tier 1
  rules is a compile error caught by the analyzer.
  """
  name: str
  body: list[Stmt]
  span: Span


@dataclass(frozen=True)
class Program:
  """A complete FWL program.

  v0.1 / v0.2 Tier 1: `hook` + `rules` + optional `default`.
  v0.2 Tier 2: `hook` + `function`. The two shapes are mutually
  exclusive — the analyzer reports the spec's "Tier 1 rule sequence
  or a single Tier 2 function, not a mix" error if both fields are
  populated. A Tier 1 program leaves `function` as None; a Tier 2
  program leaves `rules` empty and `default` as None.
  """
  hook: Hook
  rules: list[Rule] = field(default_factory=list)
  default: DefaultRule | None = None
  function: FunctionDef | None = None
