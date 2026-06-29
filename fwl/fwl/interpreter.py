"""AST interpreter — independent oracle for the verification loop.

Walks the AST against a parsed packet (a dict of decoded fields)
and returns the XDP action the program would take. Implementation
must not share any code with the emitter beyond AST node definitions
— the whole point is independent evaluation.

Spec reference: docs/FWL_V02_SPEC.md (with FWL_V01_SPEC.md as the
v0.1 baseline). Methodology: docs/F_DEVELOPMENT_METHODOLOGY.md:307-311.
"""
from __future__ import annotations
import ipaddress
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from . import ast


class XdpAction(Enum):
  """The XDP return values an FWL program can produce."""
  PASS = "XDP_PASS"
  DROP = "XDP_DROP"


@dataclass
class LogEvent:
  """A log event emitted by a `log` rule."""
  rule_index: int
  proto: str
  src_ip: str
  dst_ip: str
  src_port: int
  dst_port: int
  syn: bool
  ack: bool


@dataclass
class EvalResult:
  """Full evaluation result including side effects."""
  action: XdpAction
  counter_changes: dict[str, int] = field(default_factory=dict)
  log_events: list[LogEvent] = field(default_factory=list)


_TERMINAL_ACTION_TO_XDP = {
  ast.Action.ALLOW: XdpAction.PASS,
  ast.Action.DROP: XdpAction.DROP,
}


def evaluate(
  program: ast.Program,
  packet: dict[str, Any],
  state: dict[int, dict[Any, int]] | None = None,
  geoip_data: dict[str, list[str]] | None = None,
) -> XdpAction:
  """Run `program` against `packet` and return the resulting XDP action.

  Rules execute top to bottom; first matching rule's action wins,
  modulo rate-limit gating. The optional `state` argument supplies
  pre-existing rate-limit bucket counts keyed by the rule's index in
  the program; absent buckets are treated as count=0. State is read
  but not mutated — the test harness compares the action only.

  v0.2 `geoip(...)` lookups consult `geoip_data` (a dict mapping
  country code → list of CIDR strings, mirroring the bundle's
  `geoip.json`). When the program references geoip but no data is
  supplied, every lookup returns "miss" — analogous to the daemon
  refusing to attach a bundle without `geoip.json`. Test harnesses
  that exercise geoip programs pass the dict explicitly via the
  `.pkt` `geoip_data:` block.

  After all rules, the explicit default (if present) fires; otherwise
  the implicit XDP_PASS per FWL_V01_SPEC.md:70 / :116.

  v0.2: when the program is v0.1-shaped (does not touch any v6
  surface) and the packet is a v6-builder frame, every v0.1-style
  field read returns "unreadable" per PKT_V02_SPEC.md:122-127. This
  matches the BPF emitter's behaviour: a v0.1-shaped program produces
  no v6 parse path, so v6 frames hit the default action.
  """
  return evaluate_full(program, packet, state, geoip_data).action


def evaluate_full(
  program: ast.Program,
  packet: dict[str, Any],
  state: dict[int, dict[Any, int]] | None = None,
  geoip_data: dict[str, list[str]] | None = None,
) -> EvalResult:
  """Run `program` against `packet` and return full results.

  Like evaluate() but also returns counter_changes and log_events.
  """
  state = state or {}
  geoip_data = geoip_data or {}
  packet = _gate_v6_packet_for_v01_program(program, packet)
  ctx = _Ctx(geoip_data=geoip_data)
  counters: dict[str, int] = {}
  log_events: list[LogEvent] = []
  if program.function is not None:
    result = _exec_tier2(program.function, packet, ctx, state)
    action = result if result is not None else XdpAction.PASS
    return EvalResult(action=action)
  for idx, rule in enumerate(program.rules):
    if rule.condition is not None and not _eval(
      rule.condition, packet, ctx, counters
    ):
      continue
    if rule.modifier is not None:
      if not _rate_limit_allows(rule.modifier, idx, packet, state):
        continue
    if rule.action in _TERMINAL_ACTION_TO_XDP:
      return EvalResult(
        action=_TERMINAL_ACTION_TO_XDP[rule.action],
        counter_changes=counters,
        log_events=log_events,
      )
    if rule.action == ast.Action.COUNT and rule.counter_name:
      counters[rule.counter_name] = (
        counters.get(rule.counter_name, 0) + 1
      )
    if rule.action == ast.Action.LOG:
      sample = getattr(rule, "log_sample", None)
      if sample is not None and sample > 1:
        pass
      else:
        log_events.append(_build_log_event(idx, packet))
  if program.default is not None:
    action = _TERMINAL_ACTION_TO_XDP[program.default.action]
  else:
    action = XdpAction.PASS
  return EvalResult(
    action=action,
    counter_changes=counters,
    log_events=log_events,
  )


def _exec_tier2(
  func: ast.FunctionDef,
  packet: dict[str, Any],
  ctx: "_Ctx",
  state: dict[int, dict[Any, int]],
) -> XdpAction | None:
  """Execute a Tier 2 function body against `packet`.

  Returns the XdpAction reached by a terminal statement, or None
  when the body falls through (caller defaults to PASS per spec).
  """
  locals_: dict[str, Any] = {}
  return _exec_stmts(func.body, packet, ctx, state, locals_)


def _exec_stmts(
  stmts: list[ast.Stmt],
  packet: dict[str, Any],
  ctx: "_Ctx",
  state: dict[int, dict[Any, int]],
  locals_: dict[str, Any],
) -> XdpAction | None:
  """Run a Tier 2 statement block, returning the terminal action if hit."""
  for stmt in stmts:
    if isinstance(stmt, ast.ActionStmt):
      if stmt.action == ast.Action.ALLOW:
        return XdpAction.PASS
      if stmt.action == ast.Action.DROP:
        return XdpAction.DROP
      # LOG and COUNT are non-terminal: side effect omitted in test.
      continue
    if isinstance(stmt, ast.AssignStmt):
      locals_[stmt.name] = _eval_scalar(stmt.rhs, packet, ctx, locals_)
      continue
    if isinstance(stmt, ast.IfStmt):
      cond_value = _eval_scalar(stmt.cond, packet, ctx, locals_)
      if cond_value:
        result = _exec_stmts(stmt.body, packet, ctx, state, locals_)
        if result is not None:
          return result
        continue
      branch_taken = False
      for elif_cond, elif_body in stmt.elif_branches:
        if _eval_scalar(elif_cond, packet, ctx, locals_):
          result = _exec_stmts(elif_body, packet, ctx, state, locals_)
          if result is not None:
            return result
          branch_taken = True
          break
      if not branch_taken and stmt.else_body is not None:
        result = _exec_stmts(stmt.else_body, packet, ctx, state, locals_)
        if result is not None:
          return result
      continue
    raise AssertionError(f"unexpected stmt {type(stmt).__name__}")
  return None


def _eval_scalar(
  expr,
  packet: dict[str, Any],
  ctx: "_Ctx",
  locals_: dict[str, Any],
) -> Any:
  """Evaluate a Tier 2 scalar_expr or condition against the packet."""
  if isinstance(expr, ast.IntLiteral):
    return expr.value
  if isinstance(expr, ast.IPv4Literal):
    return expr.value
  if isinstance(expr, ast.Ipv6Literal):
    return expr.value
  if isinstance(expr, ast.ProtoLiteral):
    return expr.proto
  if isinstance(expr, ast.LocalRead):
    return locals_.get(expr.name)
  if isinstance(expr, ast.FieldRef):
    return _read_field(expr.name, packet)
  if isinstance(expr, ast.BoolField):
    val = _read_field(expr.field.name, packet)
    return bool(val) if val is not None else False
  if isinstance(expr, ast.Comparison):
    return _eval_tier2_comparison(expr, packet, ctx, locals_)
  if isinstance(expr, ast.NotOp):
    return not _eval_scalar(expr.inner, packet, ctx, locals_)
  if isinstance(expr, ast.AndOp):
    for c in expr.operands:
      if not _eval_scalar(c, packet, ctx, locals_):
        return False
    return True
  if isinstance(expr, ast.OrOp):
    for c in expr.operands:
      if _eval_scalar(c, packet, ctx, locals_):
        return True
    return False
  if isinstance(expr, ast.RateLimitCall):
    # Test harness doesn't simulate rate-limit dynamics for Tier 2.
    return False
  raise AssertionError(f"unexpected scalar expr {type(expr).__name__}")


_FIELD_TO_PACKET_KEY = {
  ast.FIELD_PROTO: "proto",
  ast.FIELD_SRC_IP: "src_ip",
  ast.FIELD_DST_IP: "dst_ip",
  ast.FIELD_SRC_IP6: "src_ip6",
  ast.FIELD_DST_IP6: "dst_ip6",
  ast.FIELD_SRC_PORT: "src_port",
  ast.FIELD_DST_PORT: "dst_port",
  ast.FIELD_TCP_SYN: "syn",
  ast.FIELD_TCP_ACK: "ack",
  ast.FIELD_VLAN_ID: "vlan_id",
  ast.FIELD_VLAN_PRIORITY: "vlan_priority",
}


def _read_field(field_name: str, packet: dict[str, Any]) -> Any:
  """Read a packet field for a Tier 2 statement-position read.

  Normalises the wire value to Tier-2-friendly types: `proto` →
  `ast.Proto` enum, IPv4 → integer, IPv6 → integer, ports/booleans
  pass through as-is.
  """
  key = _FIELD_TO_PACKET_KEY[field_name]
  raw = packet.get(key)
  if raw is None:
    return None
  if field_name == ast.FIELD_PROTO:
    return _PROTO_FROM_STRING.get(raw)
  if field_name in ast.IP_FIELDS:
    return _ipv4_to_int(raw)
  if field_name in ast.IP6_FIELDS:
    return _ipv6_to_int(raw)
  return raw


_PROTO_FROM_STRING = {
  "tcp": ast.Proto.TCP,
  "udp": ast.Proto.UDP,
  "icmp": ast.Proto.ICMP,
  "icmp6": ast.Proto.ICMP6,
}


def _eval_tier2_comparison(
  cmp: ast.Comparison,
  packet: dict[str, Any],
  ctx: "_Ctx",
  locals_: dict[str, Any],
) -> bool:
  """Evaluate a Tier 2 comparison whose lvalue may be a local."""
  if isinstance(cmp.field, ast.LocalRead):
    lhs = locals_.get(cmp.field.name)
  else:
    lhs = _read_field(cmp.field.name, packet)
  if cmp.op == "in":
    if lhs is None:
      return False
    return _ip_or_port_or_proto_in(cmp, lhs, ctx)
  if isinstance(cmp.operand, ast.LocalRead):
    rhs = locals_.get(cmp.operand.name)
  elif isinstance(cmp.operand, ast.FieldRef):
    rhs = _read_field(cmp.operand.name, packet)
  elif isinstance(cmp.operand, ast.IntLiteral):
    rhs = cmp.operand.value
  elif isinstance(cmp.operand, ast.IPv4Literal):
    rhs = cmp.operand.value
  elif isinstance(cmp.operand, ast.Ipv6Literal):
    rhs = cmp.operand.value
  elif isinstance(cmp.operand, ast.ProtoLiteral):
    rhs = cmp.operand.proto
  else:
    rhs = None
  if lhs is None or rhs is None:
    return False
  if cmp.op == "==":
    return lhs == rhs
  if cmp.op == "!=":
    return lhs != rhs
  if cmp.op == "<":
    return lhs < rhs
  if cmp.op == ">":
    return lhs > rhs
  if cmp.op == "<=":
    return lhs <= rhs
  if cmp.op == ">=":
    return lhs >= rhs
  return False


def _ip_or_port_or_proto_in(cmp: ast.Comparison, lhs, ctx: "_Ctx") -> bool:
  """Tier 2 'in' membership dispatch."""
  field = cmp.field
  field_name = field.name if isinstance(field, ast.FieldRef) else None
  operand = cmp.operand
  if field_name in ast.IP_FIELDS or (
    isinstance(field, ast.LocalRead) and isinstance(operand, ast.GeoIp)
    and operand.family == "ipv4"
  ) or (
    field_name is None
    and isinstance(operand, (ast.CidrLiteral, ast.CidrListLiteral))
  ):
    return _ip_in_set(lhs, operand, ctx)
  if field_name in ast.IP6_FIELDS or (
    isinstance(operand, (ast.Ipv6CidrLiteral, ast.Ipv6CidrListLiteral))
  ) or (
    isinstance(operand, ast.GeoIp) and operand.family == "ipv6"
  ):
    return _ip6_in_set(lhs, operand, ctx)
  if isinstance(operand, ast.RangeLiteral):
    return operand.lo <= lhs <= operand.hi
  if isinstance(operand, ast.ListLiteral):
    for item in operand.items:
      if isinstance(item, ast.IntLiteral) and item.value == lhs:
        return True
      if isinstance(item, ast.IPv4Literal) and item.value == lhs:
        return True
      if isinstance(item, ast.Ipv6Literal) and item.value == lhs:
        return True
      if isinstance(item, ast.ProtoLiteral) and item.proto == lhs:
        return True
    return False
  if isinstance(operand, ast.GeoIp):
    if operand.family == "ipv4":
      return _ip_in_set(lhs, operand, ctx)
    return _ip6_in_set(lhs, operand, ctx)
  return False


# v0.1-style fields the v6-builder packet exposes but a v0.1-shaped
# program must NOT see. Per PKT_V02_SPEC.md "Interpreter access to
# v6-builder decoded fields is gated by FWL_V02's v6-surface
# activation rule": these reads on a v6 frame from a non-activating
# program have to fall through, identical to the BPF runtime.
_V01_FIELDS_GATED_ON_V6 = (
  "proto", "src_port", "dst_port", "syn", "ack", "src_ip", "dst_ip",
)


def _gate_v6_packet_for_v01_program(
  program: ast.Program, packet: dict[str, Any]
) -> dict[str, Any]:
  """Apply the PKT_V02 v6-builder activation gate to a packet dict.

  No-op when the packet is not a v6 builder (`ether_type != 0x86DD`)
  or when the program touches a v6 surface. Otherwise returns a copy
  of `packet` with the v0.1-style fields removed so subsequent reads
  fall through.
  """
  if packet.get("ether_type") != 0x86DD:
    return packet
  if _program_touches_v6_surface(program):
    return packet
  gated = dict(packet)
  for key in _V01_FIELDS_GATED_ON_V6:
    gated.pop(key, None)
  return gated


def _program_touches_v6_surface(program: ast.Program) -> bool:
  """True when the program activates the v6 parse path.

  Mirrors emitter._is_v6_active. Kept as an interpreter-private
  helper rather than imported across module boundaries because the
  oracle independence rule (F_DEVELOPMENT_METHODOLOGY.md:307-311)
  forbids the interpreter from sharing emission code.

  Walks both Tier 1 rules and Tier 2 function bodies — a Tier 2
  program activates v6 via `if pkt.src_ip6 in ::/0:` (or any other
  v6 surface inside the function), not via Tier 1 rules (the two
  shapes are mutually exclusive in v0.2).
  """
  for rule in program.rules:
    if _condition_touches_v6(rule.condition):
      return True
  if program.function is not None:
    if _stmts_touch_v6(program.function.body):
      return True
  return False


def _stmts_touch_v6(stmts) -> bool:
  """Walk Tier 2 stmts looking for any v6 surface activation."""
  for s in stmts:
    if isinstance(s, ast.IfStmt):
      if _condition_touches_v6(s.cond):
        return True
      if _stmts_touch_v6(s.body):
        return True
      for cond, body in s.elif_branches:
        if _condition_touches_v6(cond):
          return True
        if _stmts_touch_v6(body):
          return True
      if s.else_body is not None and _stmts_touch_v6(s.else_body):
        return True
    elif isinstance(s, ast.AssignStmt):
      if _condition_touches_v6(s.rhs):
        return True
  return False


def _condition_touches_v6(node) -> bool:
  if node is None:
    return False
  if isinstance(node, ast.Comparison):
    if (isinstance(node.field, ast.FieldRef)
        and node.field.name in ast.IP6_FIELDS):
      return True
    if (isinstance(node.operand, ast.FieldRef)
        and node.operand.name in ast.IP6_FIELDS):
      return True
    op = node.operand
    if isinstance(op, (ast.Ipv6Literal, ast.Ipv6CidrLiteral,
                       ast.Ipv6CidrListLiteral)):
      return True
    if isinstance(op, ast.ProtoLiteral) and op.proto == ast.Proto.ICMP6:
      return True
    if isinstance(op, ast.ListLiteral):
      for item in op.items:
        if isinstance(item, ast.Ipv6Literal):
          return True
    return False
  if isinstance(node, ast.FieldRef):
    return node.name in ast.IP6_FIELDS
  if isinstance(node, ast.Ipv6Literal):
    return True
  if isinstance(node, ast.NotOp):
    return _condition_touches_v6(node.inner)
  if isinstance(node, (ast.AndOp, ast.OrOp)):
    return any(_condition_touches_v6(c) for c in node.operands)
  return False


def _build_log_event(
  rule_idx: int, packet: dict[str, Any]
) -> LogEvent:
  """Construct a LogEvent from the current packet fields."""
  return LogEvent(
    rule_index=rule_idx,
    proto=packet.get("proto", ""),
    src_ip=packet.get("src_ip", "0.0.0.0"),
    dst_ip=packet.get("dst_ip", "0.0.0.0"),
    src_port=int(packet.get("src_port", 0)),
    dst_port=int(packet.get("dst_port", 0)),
    syn=bool(packet.get("syn", False)),
    ack=bool(packet.get("ack", False)),
  )


def _rate_limit_allows(
  mod: ast.RateLimit,
  rule_idx: int,
  packet: dict[str, Any],
  state: dict[int, dict[Any, int]],
) -> bool:
  """True iff the rate_limit gate would let the rule fire for this packet.

  The bucket key is the runtime value of mod.per_field. Buckets in
  `state` carry the count "so far" within the current 1-second window;
  the rule fires when count >= threshold (i.e., the rate has been
  exceeded — `drop ... limited by rate_limit(N)` drops once traffic
  passes N/sec).

  Lookups try the raw key first (matching the .pkt spec, which says
  IP buckets are dotted-quad strings and port buckets are integers).
  If that misses, IP keys are renormalized to integer form so the
  interpreter and the BPF runner cannot silently disagree on which
  bucket "1.2.3.4" and 16909060 refer to — surfaced by the
  explore-mode bug hunter (Finding 2).
  """
  bucket_key = packet.get(mod.per_field)
  if bucket_key is None:
    # The per= field isn't available on this packet (e.g. src_port
    # for an ICMP packet). Treat as bucket count = 0.
    bucket_key = 0
  buckets = state.get(rule_idx, {})
  if bucket_key in buckets:
    return buckets[bucket_key] >= mod.threshold
  if mod.per_field in ("src_ip", "dst_ip") and isinstance(bucket_key, str):
    int_key = _ipv4_str_to_int(bucket_key)
    if int_key in buckets:
      return buckets[int_key] >= mod.threshold
  return 0 >= mod.threshold


def _ipv4_str_to_int(addr: str) -> int:
  """Dotted-quad to host-order u32, matching runner._encode_rl_key."""
  value = 0
  for part in addr.split("."):
    value = (value << 8) | int(part)
  return value & 0xFFFFFFFF


class _Ctx:
  """Per-evaluation context carrying ancillary data the v0.2 walks need.

  Currently only `geoip_data` (the country-code → CIDR-list dict from
  the .pkt's geoip_data block, mirroring the bundle's geoip.json). The
  Ctx avoids threading more positional arguments through every node-
  evaluation function.
  """
  def __init__(self, *, geoip_data: dict[str, list[str]]):
    self.geoip_data = geoip_data
    # Per-call resolved prefix lists keyed by the GeoIp call_index.
    # Memoising keeps repeated lookups cheap when a rule fires per
    # packet across a corpus run.
    self._resolved: dict[int, list] = {}


_COUNT_OPS = {
  "==": lambda a, b: a == b,
  "!=": lambda a, b: a != b,
  "<": lambda a, b: a < b,
  ">": lambda a, b: a > b,
  "<=": lambda a, b: a <= b,
  ">=": lambda a, b: a >= b,
}


def _eval(
  node: ast.Condition,
  packet: dict[str, Any],
  ctx: "_Ctx",
  counters: dict[str, int] | None = None,
) -> bool:
  """Evaluate a condition node against a decoded packet."""
  if isinstance(node, ast.Comparison):
    return _eval_comparison(node, packet, ctx)
  if isinstance(node, ast.CountCompare):
    cur = (counters or {}).get(node.call.counter_name, 0)
    val = node.operand.value  # type: ignore[union-attr]
    op_fn = _COUNT_OPS.get(node.op)
    return op_fn(cur, val) if op_fn else False
  if isinstance(node, ast.BoolField):
    return bool(packet.get(_field_key(node.field.name), False))
  if isinstance(node, ast.NotOp):
    return not _eval(node.inner, packet, ctx, counters)
  if isinstance(node, ast.AndOp):
    for child in node.operands:
      if not _eval(child, packet, ctx, counters):
        return False
    return True
  if isinstance(node, ast.OrOp):
    for child in node.operands:
      if _eval(child, packet, ctx, counters):
        return True
    return False
  raise NotImplementedError(
    f"interpreter: unsupported node {type(node).__name__}"
  )


def _field_key(name: str) -> str:
  """Map an AST field name to the packet-dict key that pkt.py emits."""
  return _FIELD_TO_KEY[name]


_FIELD_TO_KEY = {
  ast.FIELD_PROTO: "proto",
  ast.FIELD_SRC_IP: "src_ip",
  ast.FIELD_DST_IP: "dst_ip",
  ast.FIELD_SRC_IP6: "src_ip6",
  ast.FIELD_DST_IP6: "dst_ip6",
  ast.FIELD_SRC_PORT: "src_port",
  ast.FIELD_DST_PORT: "dst_port",
  ast.FIELD_TCP_SYN: "syn",
  ast.FIELD_TCP_ACK: "ack",
  ast.FIELD_VLAN_ID: "vlan_id",
  ast.FIELD_VLAN_PRIORITY: "vlan_priority",
}


def _packet_value(field_name: str, packet: dict[str, Any]) -> Any:
  """Read a field's runtime value from the decoded packet dict."""
  return packet.get(_field_key(field_name))


def _ipv4_to_int(addr: str | int) -> int:
  """Coerce a packet's src_ip/dst_ip to a 32-bit integer."""
  if isinstance(addr, int):
    return addr
  parts = addr.split(".")
  value = 0
  for part in parts:
    value = (value << 8) | int(part)
  return value


def _ipv6_to_int(addr: str | int) -> int:
  """Coerce a packet's src_ip6/dst_ip6 to a 128-bit integer.

  The packet dict carries v6 addresses as strings (the raw spelling
  the .pkt builder used). ipaddress.IPv6Address accepts any
  RFC-4291-valid form; canonicality is enforced at parse time on
  the program side, not the packet side.
  """
  if isinstance(addr, int):
    return addr
  return int(ipaddress.IPv6Address(addr))


def _eval_comparison(
  cmp: ast.Comparison, packet: dict[str, Any], ctx: "_Ctx"
) -> bool:
  """Evaluate a `field op operand` comparison.

  Returns False when the field is absent from the packet (e.g. asking
  for a port on an ICMP packet) — matching the spec's "rule does not
  match" semantics for missing fields.
  """
  actual = _packet_value(cmp.field.name, packet)
  if actual is None:
    return False

  field_name = cmp.field.name
  op = cmp.op
  operand = cmp.operand

  # Protocol enum
  if field_name == ast.FIELD_PROTO:
    if op == "==":
      return actual == operand.proto.value  # type: ignore[union-attr]
    if op == "!=":
      return actual != operand.proto.value  # type: ignore[union-attr]
    if op == "in":
      return _proto_in_set(actual, operand)

  # IP fields
  if field_name in ast.IP_FIELDS:
    actual_int = _ipv4_to_int(actual)
    if op == "==":
      return actual_int == operand.value  # type: ignore[union-attr]
    if op == "!=":
      return actual_int != operand.value  # type: ignore[union-attr]
    if op == "in":
      return _ip_in_set(actual_int, operand, ctx)

  # IPv6 fields
  if field_name in ast.IP6_FIELDS:
    actual_int = _ipv6_to_int(actual)
    if op == "==":
      return actual_int == operand.value  # type: ignore[union-attr]
    if op == "!=":
      return actual_int != operand.value  # type: ignore[union-attr]
    if op == "in":
      return _ip6_in_set(actual_int, operand, ctx)

  # Port fields and VLAN fields — both u16 integers with identical
  # comparison + range/list membership semantics (FWL_V04_SPEC.md
  # "VLAN 802.1Q / Type rules").
  if field_name in ast.PORT_FIELDS or field_name in ast.VLAN_FIELDS:
    actual_int = int(actual)
    if op == "==":
      return actual_int == operand.value  # type: ignore[union-attr]
    if op == "!=":
      return actual_int != operand.value  # type: ignore[union-attr]
    if op == "<":
      return actual_int < operand.value   # type: ignore[union-attr]
    if op == ">":
      return actual_int > operand.value   # type: ignore[union-attr]
    if op == "<=":
      return actual_int <= operand.value  # type: ignore[union-attr]
    if op == ">=":
      return actual_int >= operand.value  # type: ignore[union-attr]
    if op == "in":
      return _port_in_set(actual_int, operand)

  raise NotImplementedError(
    f"interpreter: comparison {field_name} {op} not supported"
  )


def _ip_in_set(ip_value: int, operand: ast.Operand, ctx: "_Ctx") -> bool:
  """Membership test for an IP field's `in` operator."""
  if isinstance(operand, ast.CidrLiteral):
    return _cidr_match(ip_value, operand)
  if isinstance(operand, ast.CidrListLiteral):
    return any(_cidr_match(ip_value, c) for c in operand.items)
  if isinstance(operand, ast.ListLiteral):
    for item in operand.items:
      if isinstance(item, ast.IPv4Literal) and item.value == ip_value:
        return True
    return False
  if isinstance(operand, ast.GeoIp):
    return _geoip_match_v4(ip_value, operand, ctx)
  raise TypeError(f"unexpected operand for ip in: {type(operand).__name__}")


def _cidr_match(ip_value: int, cidr: ast.CidrLiteral) -> bool:
  """True iff `ip_value` falls within the CIDR block."""
  if cidr.bits == 0:
    return True
  mask = ((1 << cidr.bits) - 1) << (32 - cidr.bits)
  return (ip_value & mask) == cidr.prefix


def _ip6_in_set(ip_value: int, operand: ast.Operand, ctx: "_Ctx") -> bool:
  """Membership test for an IPv6 field's `in` operator."""
  if isinstance(operand, ast.Ipv6CidrLiteral):
    return _ipv6_cidr_match(ip_value, operand)
  if isinstance(operand, ast.Ipv6CidrListLiteral):
    return any(_ipv6_cidr_match(ip_value, c) for c in operand.items)
  if isinstance(operand, ast.ListLiteral):
    for item in operand.items:
      if isinstance(item, ast.Ipv6Literal) and item.value == ip_value:
        return True
    return False
  if isinstance(operand, ast.GeoIp):
    return _geoip_match_v6(ip_value, operand, ctx)
  raise TypeError(
    f"unexpected operand for ipv6 in: {type(operand).__name__}"
  )


def _resolve_geoip_v4(node: ast.GeoIp, ctx: "_Ctx") -> list[tuple[int, int]]:
  """Memoised resolution of geoip(...) → list of (prefix, bits) for v4.

  Walks node.codes, looks up each in ctx.geoip_data, parses the
  CIDR strings via ipaddress, retains only IPv4 entries, and stores
  the resolved list keyed by call_index.
  """
  key = ("v4", node.call_index)
  if key in ctx._resolved:
    return ctx._resolved[key]
  prefixes: list[tuple[int, int]] = []
  for code in node.codes:
    for cidr in ctx.geoip_data.get(code, ()):
      net = ipaddress.ip_network(cidr, strict=False)
      if isinstance(net, ipaddress.IPv4Network):
        prefixes.append((int(net.network_address), net.prefixlen))
  ctx._resolved[key] = prefixes
  return prefixes


def _resolve_geoip_v6(node: ast.GeoIp, ctx: "_Ctx") -> list[tuple[int, int]]:
  """Memoised resolution of geoip(...) → list of (prefix, bits) for v6."""
  key = ("v6", node.call_index)
  if key in ctx._resolved:
    return ctx._resolved[key]
  prefixes: list[tuple[int, int]] = []
  for code in node.codes:
    for cidr in ctx.geoip_data.get(code, ()):
      net = ipaddress.ip_network(cidr, strict=False)
      if isinstance(net, ipaddress.IPv6Network):
        prefixes.append((int(net.network_address), net.prefixlen))
  ctx._resolved[key] = prefixes
  return prefixes


def _geoip_match_v4(ip_value: int, node: ast.GeoIp, ctx: "_Ctx") -> bool:
  """LPM lookup over the geoip call's v4 prefix list."""
  for prefix, bits in _resolve_geoip_v4(node, ctx):
    if bits == 0:
      return True
    mask = ((1 << bits) - 1) << (32 - bits)
    if (ip_value & mask) == (prefix & mask):
      return True
  return False


def _geoip_match_v6(ip_value: int, node: ast.GeoIp, ctx: "_Ctx") -> bool:
  """LPM lookup over the geoip call's v6 prefix list."""
  for prefix, bits in _resolve_geoip_v6(node, ctx):
    if bits == 0:
      return True
    mask = ((1 << bits) - 1) << (128 - bits)
    if (ip_value & mask) == (prefix & mask):
      return True
  return False


def _ipv6_cidr_match(ip_value: int, cidr: ast.Ipv6CidrLiteral) -> bool:
  """True iff `ip_value` (128-bit) falls within the IPv6 CIDR block."""
  if cidr.bits == 0:
    return True
  mask = ((1 << cidr.bits) - 1) << (128 - cidr.bits)
  return (ip_value & mask) == cidr.prefix


def _port_in_set(port_value: int, operand: ast.Operand) -> bool:
  """Membership test for a port field's `in` operator."""
  if isinstance(operand, ast.RangeLiteral):
    return operand.lo <= port_value <= operand.hi
  if isinstance(operand, ast.ListLiteral):
    for item in operand.items:
      if isinstance(item, ast.IntLiteral) and item.value == port_value:
        return True
    return False
  raise TypeError(f"unexpected operand for port in: {type(operand).__name__}")


def _proto_in_set(proto_value: int, operand: ast.Operand) -> bool:
  """Membership test for `pkt.proto in [list]`.

  Per the v0.2 spec fix to FWL_V02_SPEC.md:566/:718, a proto-typed LHS
  admits `in` over a list of proto_keyword tokens; the analyzer
  enforces that every list item is a ProtoLiteral, so this only
  needs to handle ListLiteral.
  """
  if isinstance(operand, ast.ListLiteral):
    for item in operand.items:
      if (isinstance(item, ast.ProtoLiteral)
          and item.proto.value == proto_value):
        return True
    return False
  raise TypeError(
    f"unexpected operand for proto in: {type(operand).__name__}"
  )
