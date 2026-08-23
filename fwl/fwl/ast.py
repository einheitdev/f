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
  # v0.4 Phase 6.3: `redirect to <zone>` — a terminal action that sends
  # the packet out the destination zone's interface(s) via
  # bpf_redirect_map(). The target zone is carried on Rule.redirect_zone
  # / ActionStmt.redirect_zone (FWL_V04_SPEC.md § Zones / Redirect).
  REDIRECT = "redirect"
  # Phase 5 NAT: `masquerade`, `snat to <ip>`, `dnat to <ip>:<port>`.
  # Non-terminal rewrite actions — they translate the packet in place
  # and fall through, so a following terminal (redirect/allow) emits the
  # rewritten frame (FWL_V04_SPEC.md § NAT). masquerade/snat rewrite the
  # source; dnat rewrites the destination. The target address/port are
  # carried on Rule.nat_addr / Rule.nat_port (ActionStmt likewise).
  MASQUERADE = "masquerade"
  SNAT = "snat"
  DNAT = "dnat"


TERMINAL_ACTIONS = frozenset({Action.ALLOW, Action.DROP, Action.REDIRECT})

# NAT rewrite actions — non-terminal: they translate the packet and fall
# through to the next rule/statement (the terminal action emits it).
NAT_ACTIONS = frozenset({Action.MASQUERADE, Action.SNAT, Action.DNAT})


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


class CtState(Enum):
  """Connection-tracking state keywords (FWL_V04_SPEC.md § 4.3).

  The value of `conntrack(pkt).state`. NEW means the packet's 5-tuple
  is absent from the conntrack table; ESTABLISHED means it was found
  (forward or reverse direction); INVALID is a TCP state-machine
  violation (a non-SYN TCP segment for an untracked flow). RELATED is
  an ICMP error whose EMBEDDED datagram names a tracked flow — its own
  5-tuple has no ports and matches nothing, so this is the only way an
  error can be classified at all.

  ESTABLISHED does not include RELATED, exactly as in nftables: a
  policy listing only `established` keeps dropping the ICMP errors its
  own outbound flows provoke, and for a masquerading gateway that
  means path-MTU discovery is dead. `in [established, related]` is the
  idiom.
  """
  NEW = "new"
  ESTABLISHED = "established"
  RELATED = "related"
  INVALID = "invalid"


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
# v0.4 adds the remaining six TCP flag bits. Each is a bool field with
# the same pkt.proto == tcp guard as syn/ack (FWL_V04_SPEC.md § 4.1).
FIELD_TCP_FIN = "pkt.tcp.fin"
FIELD_TCP_RST = "pkt.tcp.rst"
FIELD_TCP_PSH = "pkt.tcp.psh"
FIELD_TCP_URG = "pkt.tcp.urg"
FIELD_TCP_ECE = "pkt.tcp.ece"
FIELD_TCP_CWR = "pkt.tcp.cwr"
# v0.4 ICMP/ICMPv6 type and code (u8 fields, integer comparisons).
# ICMP fields require a pkt.proto == icmp guard; ICMPv6 fields require
# a pkt.proto == icmp6 guard (FWL_V04_SPEC.md § 4.2).
FIELD_ICMP_TYPE = "pkt.icmp.type"
FIELD_ICMP_CODE = "pkt.icmp.code"
FIELD_ICMP6_TYPE = "pkt.icmp6.type"
FIELD_ICMP6_CODE = "pkt.icmp6.code"
# v0.4 VLAN 802.1Q fields. L2 constructs — no protocol guard needed
# (FWL_V04_SPEC.md "VLAN 802.1Q / Type rules").
FIELD_VLAN_ID = "pkt.vlan_id"
FIELD_VLAN_PRIORITY = "pkt.vlan_priority"
# v0.4 conntrack accessor. `conntrack(pkt).state` is a ct_state-typed
# read with no protocol guard — conntrack is evaluated on any frame
# (a non-IP or IPv6 frame reads NEW). Carried as a constant so the
# field tables and walks can name it uniformly (FWL_V04_SPEC.md § 4.3).
FIELD_CT_STATE = "conntrack(pkt).state"
# v0.4 Phase 6.4 zone field. `pkt.zone` is a compile-time constant
# within each @xdp(<zone>) block — the compiler knows which zone the
# program belongs to. Type: zone enum. Comparisons: ==, !=, in [...]
# against declared zone names (FWL_V04_SPEC.md § Zones / pkt.zone).
FIELD_ZONE = "pkt.zone"

IP_FIELDS = frozenset({FIELD_SRC_IP, FIELD_DST_IP})
IP6_FIELDS = frozenset({FIELD_SRC_IP6, FIELD_DST_IP6})
PORT_FIELDS = frozenset({FIELD_SRC_PORT, FIELD_DST_PORT})
TCP_FLAG_FIELDS = frozenset({
  FIELD_TCP_SYN, FIELD_TCP_ACK, FIELD_TCP_FIN, FIELD_TCP_RST,
  FIELD_TCP_PSH, FIELD_TCP_URG, FIELD_TCP_ECE, FIELD_TCP_CWR,
})
ICMP_FIELDS = frozenset({FIELD_ICMP_TYPE, FIELD_ICMP_CODE})
ICMP6_FIELDS = frozenset({FIELD_ICMP6_TYPE, FIELD_ICMP6_CODE})
VLAN_FIELDS = frozenset({FIELD_VLAN_ID, FIELD_VLAN_PRIORITY})

# Per-field valid integer ranges for v0.4 VLAN fields. vlan_id is a
# 12-bit VID (0..4095); vlan_priority is a 3-bit PCP (0..7).
VLAN_FIELD_MAX = {
  FIELD_VLAN_ID: 4095,
  FIELD_VLAN_PRIORITY: 7,
}


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


# TableRef is mutable for the same reason GeoIp is: `table_id`,
# `resolved` and `family` are filled in by the analyzer once the
# reference has been matched against the unit's `table` declarations.
# The parser knows only the name the author wrote, which may be an
# alias.
@dataclass
class TableRef:
  """A named table as the RHS of `in` (TABLES.md).

  `name` is exactly what the source said — possibly an alias. The
  analyzer resolves it against the unit's `table` declarations and
  stamps `resolved` (the canonical table name), `table_id` (the small
  allocated integer the kernel map is named for) and `family`
  ("ipv4"/"ipv6", taken from the declaration's `kind`, not from the
  comparison's LHS: a table's key width exists before any packet
  does). All three default to sentinels at parse time.

  An unresolvable name is a compile error, never an empty map — a
  table that silently holds nothing is a rule that never matches,
  which in a blocklist is an open firewall.
  """
  name: str
  table_id: int = -1
  resolved: str = ""
  family: str = ""
  span: Span | None = None


Operand = Union[
  ProtoLiteral, IntLiteral, IPv4Literal, CidrLiteral,
  Ipv6Literal, Ipv6CidrLiteral,
  ListLiteral, CidrListLiteral, Ipv6CidrListLiteral,
  RangeLiteral, GeoIp, TableRef,
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


@dataclass(frozen=True)
class ConntrackStateCompare:
  """`conntrack(pkt).state` compared against state keyword(s) (v0.4).

  A self-contained Condition (like CountCompare) rather than a
  FieldRef-based Comparison: ct_state is its own type with no Tier 2
  local form, so keeping it off the generic field tables avoids
  polluting the port/IP type machinery.

  `op` is '==', '!=', or 'in'. For ==/!= `states` holds exactly one
  CtState; for `in` it holds the (de-duplicated, source-order) list of
  CtStates on the right of `in [ ... ]`.
  """
  op: str
  states: tuple[CtState, ...]
  span: Span


@dataclass(frozen=True)
class ZoneCompare:
  """`pkt.zone` compared against declared zone name(s) (v0.4 § 6.4).

  A self-contained Condition (like ConntrackStateCompare): pkt.zone is
  its own type (the zone enum) and resolves to a compile-time constant
  — the @xdp(<zone>) block the comparison lives in fixes pkt.zone's
  value, so the emitter folds the comparison to 1 or 0.

  `op` is '==', '!=', or 'in'. For ==/!= `zones` holds exactly one zone
  name; for `in` it holds the (de-duplicated, source-order) list of
  names on the right of `in [ ... ]`. Names are validated against the
  program's zone declarations by the analyzer.
  """
  op: str
  zones: tuple[str, ...]
  span: Span


Condition = Union[
  Comparison, BoolField, NotOp, AndOp, OrOp,
  "CountCompare", ConntrackStateCompare, ZoneCompare,
]


class RlScope(Enum):
  """Zone scope of a `rate_limit` bucket (FWL_V04_SPEC.md § 6.7).

  ZONE — the bucket is private to the zone program that holds the rule.
    N zones carrying the rule each get their own budget.
  GLOBAL — one bucket for the rule across the whole bundle: every zone
    program that holds that rule shares it, so the budget is spent
    once no matter which zone the traffic arrives on.
  """
  ZONE = "zone"
  GLOBAL = "global"


# RateLimit is mutable so the analyzer can fill `global_slot` post-parse,
# mirroring the GeoIp / RateLimitCall call_index convention.
@dataclass
class RateLimit:
  """`rate_limit(<N>, per=<field>[, scope=...])` modifier.

  FWL_V01_SPEC.md:266 for the base form, FWL_V04_SPEC.md § 6.7 for
  `scope=`.

  per_field is the bare bucket key name: src_ip, dst_ip, src_port,
  dst_port. The grammar restricts it to those four; the analyzer
  enforces threshold > 0.

  `scope` defaults to ZONE, which is what every pre-v0.4-§6.7 policy
  meant, so adding the field changes no deployed policy.
  `scope_explicit` records whether the author wrote `scope=` — it drives
  the multi-zone aggregate warning and nothing else, so an author who
  has stated intent is not nagged.
  `global_slot` is the bundle-wide bucket number the analyzer assigns to
  a GLOBAL-scoped rule; -1 for ZONE-scoped ones. Rules that are
  structurally identical share a slot, which is what makes one rule
  written into several zones one bucket.
  """
  threshold: int
  per_field: str
  span: Span
  scope: RlScope = RlScope.ZONE
  scope_explicit: bool = False
  global_slot: int = -1


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
  log_sample: int | None = None
  # Set only for REDIRECT actions: the destination zone name
  # (FWL_V04_SPEC.md § Zones / Redirect).
  redirect_zone: str | None = None
  # Phase 5 NAT. `nat_addr` is the rewrite target IPv4 as a host-order
  # u32: the new source for SNAT, the new destination for DNAT. None for
  # MASQUERADE (the source is the runtime interface address) and every
  # non-NAT action. `nat_port` is the new destination port for DNAT
  # (None otherwise).
  nat_addr: int | None = None
  nat_port: int | None = None


@dataclass(frozen=True)
class CountCall:
  """A `count(name)` function call returning the counter's value."""
  counter_name: str
  span: Span


@dataclass(frozen=True)
class CountCompare:
  """A comparison involving count(name): count(n) op operand."""
  call: CountCall
  op: str
  operand: "Operand"
  span: Span


@dataclass(frozen=True)
class ChainMarker:
  """A `chain <name>` manual pipeline-split boundary (v0.4 § 6.6).

  Placed between Tier 1 rules, it forces the emitter to start a new
  tail-call stage at the following rule. `name` is a human label for
  the stage (surfaced in the emitted stage filename / manifest). The
  parser records the marker's position as a rule-index boundary on
  ZoneProgram.chain_boundaries; the node itself is not retained in the
  rule list.
  """
  name: str
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
  # Set only for REDIRECT actions in a Tier 2 body: destination zone.
  redirect_zone: str | None = None
  # Phase 5 NAT (Tier 2): rewrite target IPv4 (host-order u32) for
  # SNAT/DNAT, and destination port for DNAT. None for MASQUERADE and
  # non-NAT actions. Mirrors Rule.nat_addr / Rule.nat_port.
  nat_addr: int | None = None
  nat_port: int | None = None


@dataclass(frozen=True)
class CallStmt:
  """A Tier 2 `helper(pkt)` call statement (v0.4 § 6.5 multi-def).

  Invokes a top-level helper `def` (resolved by `name` against
  Program.helpers). The helper compiles to a `static __noinline` BPF
  function; the call site checks its return value and propagates a
  terminal verdict (allow/drop/redirect) while falling through on the
  helper's non-terminal fall-out. Non-terminal side effects (count,
  log, NAT rewrite, conntrack create) happen inside the helper.
  """
  name: str
  span: Span


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


# A Tier 2 statement is one of these shapes.
Stmt = Union[IfStmt, AssignStmt, ActionStmt, CallStmt]


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
class ZoneDecl:
  """A `zone <name> = [<iface>, ...]` declaration (v0.4 § 6.1).

  Declared at the top of a .fw file, before any @xdp block. `name` is
  the zone identifier; `interfaces` is the ordered tuple of interface
  names (resolved to ifindexes by the daemon at load time). The
  analyzer rejects empty zones, duplicate zone names, and an interface
  appearing in more than one zone.
  """
  name: str
  interfaces: tuple[str, ...]
  span: Span


# TABLES.md: the kinds a `table` declaration may name. `cidr4` and
# `cidr6` are LPM tries — the shape geoip() already proves end to end
# on the rig. Exact-match (`addr4`/`addr6`) and port tables are a
# different emission strategy (a hash on a scalar, not a prefix trie)
# and are deliberately not admitted yet: an unimplemented kind that
# parses is worse than one that does not.
TABLE_KINDS: tuple[str, ...] = ("cidr4", "cidr6")

# kind -> the address family its entries and its LHS field must have.
TABLE_KIND_FAMILY: dict[str, str] = {
  "cidr4": "ipv4",
  "cidr6": "ipv6",
}


@dataclass(frozen=True)
class TableDecl:
  """A `table <name> { ... }` declaration (TABLES.md).

  A named set whose contents come from outside the rule text. `kind`
  fixes the key width, `max_entries` the capacity the BPF map is
  created with, and `source` the file the contents are read from.

  All three are explicit on purpose. Everywhere else FWL infers
  element types; a table cannot, because the map must be created
  before any element exists and an empty table still has a key size.
  Capacity lives in the policy rather than the config so that it is
  reviewable and diffable beside the rules that depend on it.
  """
  name: str
  kind: str
  max_entries: int
  source: str
  span: Span


@dataclass(frozen=True)
class TableAlias:
  """A `table <alias> = <target>` declaration (TABLES.md).

  One table under a second name so a block of policy pasted from
  elsewhere keeps the vocabulary it was written with. The alias
  resolves at compile time and allocates nothing: alias and target are
  one table, one id, one set of contents.
  """
  name: str
  target: str
  span: Span


@dataclass(frozen=True)
class ZoneProgram:
  """One @xdp(<zone>) block — the policy for a single zone (v0.4 § 6.2).

  Holds exactly what a v0.2 `Program` did: a hook plus either a Tier 1
  rule sequence (`rules` + optional `default`) or a single Tier 2
  `function`. `hook.interface` carries the @xdp argument — a zone name
  when the file declares zones, or a bare interface name in the
  degenerate single-block case (one implicit zone). Each zone compiles
  to its own BPF program.
  """
  hook: Hook
  rules: list[Rule] = field(default_factory=list)
  default: DefaultRule | None = None
  function: FunctionDef | None = None
  # v0.4 § 6.6: rule indices at which a manual `chain` forces a new
  # pipeline stage. Each value b means rules[b:] start a fresh stage.
  # Empty when the source has no `chain` markers.
  chain_boundaries: tuple[int, ...] = ()

  @property
  def zone_name(self) -> str:
    """The zone this program is attached to (the @xdp argument)."""
    return self.hook.interface


@dataclass(frozen=True)
class Program:
  """A complete FWL compilation unit (v0.4 § 6.1-6.2).

  A unit is an ordered list of zone declarations plus one or more
  `ZoneProgram` blocks (one per @xdp). The v0.1-v0.3 single-`@xdp`
  shape is the degenerate case: zero zone declarations and exactly one
  ZoneProgram. The `hook`/`rules`/`default`/`function` properties
  delegate to that single program so the analyzer, emitter, and
  interpreter's per-program code keeps working unchanged on
  single-zone files; multi-zone code iterates `programs` directly.
  """
  programs: list[ZoneProgram] = field(default_factory=list)
  zones: list[ZoneDecl] = field(default_factory=list)
  # TABLES.md: the unit's `table` declarations and the aliases onto
  # them. Bundle-global, not per-zone — a blocklist shared by every
  # zone is the case the feature exists for — so they live on the unit
  # rather than on a ZoneProgram.
  tables: list[TableDecl] = field(default_factory=list)
  table_aliases: list[TableAlias] = field(default_factory=list)
  # v0.4 § 6.5 multi-def: top-level helper `def`s shared across zones.
  # Each compiles to a `static __noinline` BPF function; zone bodies
  # invoke them via CallStmt. Empty in the v0.1-v0.3 shape.
  helpers: list[FunctionDef] = field(default_factory=list)
  # Non-fatal diagnostics collected by the analyzer (errors.FwlWarning).
  # Rebuilt from scratch on every analyze() call, so re-analyzing a
  # program does not accumulate duplicates.
  warnings: list = field(default_factory=list)

  @property
  def hook(self) -> Hook:
    return self.programs[0].hook

  @property
  def rules(self) -> list[Rule]:
    return self.programs[0].rules

  @property
  def default(self) -> DefaultRule | None:
    return self.programs[0].default

  @property
  def function(self) -> FunctionDef | None:
    return self.programs[0].function
