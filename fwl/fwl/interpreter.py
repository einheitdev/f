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
  # v0.4 § 6.3: `redirect to <zone>` returns XDP_REDIRECT. The
  # destination zone is reported separately on EvalResult.redirect_zone.
  REDIRECT = "XDP_REDIRECT"


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
  # Set when the resulting action is REDIRECT: the destination zone
  # name (v0.4 § 6.3). None for every other action.
  redirect_zone: str | None = None
  # Phase 5 NAT: the packet's header fields after every NAT rewrite that
  # fired (src_ip/dst_ip as dotted-quad strings, src_port/dst_port as
  # ints), or None when no NAT action rewrote the packet. The .pkt
  # runner compares this against `expected.output_packet` and the BPF
  # oracle's captured frame.
  output_packet: dict[str, Any] | None = None


_TERMINAL_ACTION_TO_XDP = {
  ast.Action.ALLOW: XdpAction.PASS,
  ast.Action.DROP: XdpAction.DROP,
  ast.Action.REDIRECT: XdpAction.REDIRECT,
}


# --- v0.4 conntrack state model -------------------------------------
#
# The interpreter is the conntrack oracle: it carries a table of
# forward 5-tuple keys and decides new/established/invalid the same way
# the emitted BPF program does (FWL_V04_SPEC.md § 4.3 "Semantics"),
# without sharing code with the emitter. v0.4 tracks IPv4 only — the
# daemon's `conntrack` map is keyed on 32-bit addresses — so an IPv6
# or non-IP frame is always NEW and never creates an entry. RELATED is
# never produced (ICMP-error tracking is deferred).


# Sentinel for "this frame is not conntracked" — an IPv6 frame (v0.4
# conntrack is IPv4-only) or a frame with no readable IPv4 5-tuple.
_UNTRACKED = None


def _ct_key(packet: dict[str, Any]) -> tuple | None:
  """Forward 5-tuple key for `packet`, or `_UNTRACKED` when untracked.

  Untracked covers IPv6 frames (v0.4 conntrack is IPv4-only) and frames
  with no readable IPv4 5-tuple (non-IP or truncated below L3). Ports
  default to 0 for ICMP and any frame without an L4 header, mirroring
  the BPF key (where the port fields stay 0).
  """
  src = packet.get("src_ip")
  dst = packet.get("dst_ip")
  proto = packet.get("proto")
  if (packet.get("ether_type") == 0x86DD
      or src is None or dst is None or proto is None):
    return _UNTRACKED
  sport = int(packet.get("src_port") or 0)
  dport = int(packet.get("dst_port") or 0)
  return (proto, _ipv4_to_int(src), _ipv4_to_int(dst), sport, dport)


class ConntrackTable:
  """Mutable set of forward 5-tuple keys, the interpreter's CT state.

  A connection is ESTABLISHED when the packet's forward key or its
  reverse (src/dst and sport/dport swapped) is present — matching the
  BPF lookup's forward-then-reverse probe. `create` adds the forward
  key, the side effect an allowed NEW packet produces.
  """
  def __init__(self, entries=None):
    self._fwd: set[tuple] = set(entries or ())

  def state_for(self, packet: dict[str, Any]) -> ast.CtState:
    """Classify `packet` against the current table."""
    key = _ct_key(packet)
    if key is None:
      return ast.CtState.NEW
    proto, src, dst, sport, dport = key
    rev = (proto, dst, src, dport, sport)
    if key in self._fwd or rev in self._fwd:
      return ast.CtState.ESTABLISHED
    # A TCP segment with no SYN for an untracked flow is a state-machine
    # violation (data/ACK/RST without a handshake we ever saw).
    if proto == "tcp" and not packet.get("syn", False):
      return ast.CtState.INVALID
    return ast.CtState.NEW

  def create(self, packet: dict[str, Any]) -> None:
    """Insert `packet`'s forward key (no-op for untracked frames)."""
    key = _ct_key(packet)
    if key is not None:
      self._fwd.add(key)


class NatState:
  """Interpreter NAT model (Phase 5).

  Carries the masquerade source IP (the runtime WAN address the BPF
  program reads from its `fwl_nat_cfg` map; the .pkt supplies it via
  `state.nat.masq_ip`) and a set of pre-seeded reply-direction mappings
  used to de-NAT return traffic before rule evaluation. Each mapping is
  keyed by the inbound packet's forward 5-tuple
  `(proto, src, dst, sport, dport)` and records what to rewrite:
  `('dnat', new_addr, new_port)` rewrites the destination back to the
  original internal host (the reply of an egress SNAT/masquerade), and
  `('snat', new_addr, new_port)` rewrites the source (the reply of an
  inbound DNAT). Addresses are stored as 32-bit ints (the
  `_ipv4_to_int` convention); ports as ints.
  """
  def __init__(self, masq_ip=None, mappings=None):
    self.masq_ip = masq_ip
    self._reply: dict[tuple, tuple] = dict(mappings or {})

  def denat(self, packet: dict[str, Any]) -> tuple | None:
    """Return the rewrite to apply to a return packet, or None.

    The tuple is `(kind, new_addr_int, new_port_or_None)` where kind is
    'dnat' (rewrite dst) or 'snat' (rewrite src).
    """
    key = _ct_key(packet)
    if not isinstance(key, tuple):
      return None  # untracked frame: no reply mapping can apply
    return self._reply.get(key)

  def install_egress_reply(
    self, packet: dict[str, Any], new_saddr: int
  ) -> None:
    """Record how to de-NAT the reply to an egress SNAT/masquerade.

    Mirrors `fwl_snat_egress` in the emitter, which writes the reply
    mapping into `fwl_nat` before rewriting the frame. Until this
    existed the interpreter modelled only the *lookup* half of NAT: it
    could de-NAT a reply the .pkt pre-seeded via `state.nat.mappings`,
    but nothing it did ever created a mapping. A program whose SNAT
    stopped installing them was therefore indistinguishable from a
    correct one on this oracle.

    Keyed the way the reply arrives: source and destination swapped,
    with the translated address in the destination position. SNAT is
    port-preserving, so the reply's destination port is the original
    source port.
    """
    old_saddr = _ipv4_to_int(packet.get("src_ip"))
    daddr = _ipv4_to_int(packet.get("dst_ip"))
    proto = packet.get("proto")
    if old_saddr is None or daddr is None or proto is None:
      return
    sport = int(packet.get("src_port") or 0)
    dport = int(packet.get("dst_port") or 0)
    self._reply[(proto, daddr, new_saddr, dport, sport)] = (
      "dnat", old_saddr, sport
    )

  def install_ingress_reply(
    self, packet: dict[str, Any], new_daddr: int, new_dport: int | None
  ) -> None:
    """Record how to de-NAT the reply to an ingress DNAT.

    Mirrors `fwl_dnat_ingress`. The reply comes back from the internal
    host, so it is keyed on the translated address/port as source and
    the original client as destination, and rewrites the source back to
    the public address the client believes it is talking to.

    The emitter only rewrites TCP and UDP here (it returns early for
    anything else), so neither does this.
    """
    old_daddr = _ipv4_to_int(packet.get("dst_ip"))
    saddr = _ipv4_to_int(packet.get("src_ip"))
    proto = packet.get("proto")
    if old_daddr is None or saddr is None or proto not in ("tcp", "udp"):
      return
    sport = int(packet.get("src_port") or 0)
    old_dport = int(packet.get("dst_port") or 0)
    reply_sport = old_dport if new_dport is None else int(new_dport)
    self._reply[(proto, new_daddr, saddr, reply_sport, sport)] = (
      "snat", old_daddr, old_dport
    )


def _program_uses_conntrack(program: ast.Program) -> bool:
  """True iff any rule or Tier 2 statement reads conntrack(pkt).state.

  Duplicated from the emitter's equivalent walk rather than imported:
  the oracle-independence rule (F_DEVELOPMENT_METHODOLOGY.md:307-311)
  keeps the interpreter from sharing the emitter's analysis, exactly
  as `_program_touches_v6_surface` mirrors `emitter._is_v6_active`.
  """
  for rule in program.rules:
    if _condition_uses_conntrack(rule.condition):
      return True
  if program.function is not None:
    if _stmts_use_conntrack(program.function.body):
      return True
  return False


def _stmts_use_conntrack(stmts) -> bool:
  for s in stmts:
    if isinstance(s, ast.AssignStmt):
      if _condition_uses_conntrack(s.rhs):
        return True
    elif isinstance(s, ast.IfStmt):
      if _condition_uses_conntrack(s.cond):
        return True
      if _stmts_use_conntrack(s.body):
        return True
      for cond, body in s.elif_branches:
        if _condition_uses_conntrack(cond):
          return True
        if _stmts_use_conntrack(body):
          return True
      if s.else_body is not None and _stmts_use_conntrack(s.else_body):
        return True
  return False


def _condition_uses_conntrack(node) -> bool:
  if isinstance(node, ast.ConntrackStateCompare):
    return True
  if isinstance(node, ast.NotOp):
    return _condition_uses_conntrack(node.inner)
  if isinstance(node, (ast.AndOp, ast.OrOp)):
    return any(_condition_uses_conntrack(c) for c in node.operands)
  return False


def evaluate(
  program: ast.Program,
  packet: dict[str, Any],
  state: dict[int, dict[Any, int]] | None = None,
  geoip_data: dict[str, list[str]] | None = None,
  conntrack: ConntrackTable | None = None,
  nat: "NatState | None" = None,
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
  return evaluate_full(
    program, packet, state, geoip_data, conntrack, nat
  ).action


def evaluate_full(
  program: ast.Program,
  packet: dict[str, Any],
  state: dict[int, dict[Any, int]] | None = None,
  geoip_data: dict[str, list[str]] | None = None,
  conntrack: ConntrackTable | None = None,
  nat: "NatState | None" = None,
) -> EvalResult:
  """Run `program` against `packet` and return full results.

  Like evaluate() but also returns counter_changes and log_events.

  v0.4: when the program reads `conntrack(pkt).state`, the `conntrack`
  table supplies the connection state (built from the .pkt's
  `state.conntrack` seed and/or carried across a multi-packet
  sequence). An explicit `allow` of a NEW IPv4 packet inserts the
  forward 5-tuple into the table — the side effect a later packet in
  the sequence observes as ESTABLISHED. The implicit fall-through
  XDP_PASS does not create an entry (only an explicit allow rule or
  `default allow` does).
  """
  state = state or {}
  geoip_data = geoip_data or {}
  packet = _gate_v6_packet_for_v01_program(program, packet)
  uses_ct = _program_uses_conntrack(program)
  ct = conntrack if conntrack is not None else ConntrackTable()
  ct_state = ct.state_for(packet)
  # pkt.zone's constant value is the @xdp block's zone (the hook
  # argument); works for a Program (delegates to programs[0]) or a
  # ZoneProgram passed directly by the cross-zone runner (v0.4 § 6.4).
  zone_name = program.hook.interface
  ctx = _Ctx(
    geoip_data=geoip_data, ct_state=ct_state, zone_name=zone_name,
    nat=nat,
    helpers={h.name: h for h in getattr(program, "helpers", [])},
  )
  # Seed the NAT working packet with the input header fields, then apply
  # ingress de-NAT (return traffic) before any rule evaluates — the BPF
  # program rewrites the destination of a reply before the rule body
  # runs, so the oracle does too.
  ctx.work = _nat_work_init(packet)
  _apply_ingress_denat(packet, ctx)
  counters: dict[str, int] = {}
  log_events: list[LogEvent] = []
  if program.function is not None:
    result = _exec_tier2(program.function, packet, ctx, state)
    action = result if result is not None else XdpAction.PASS
    # An explicit `allow` statement (result is PASS, not the
    # fall-through None) of a NEW packet creates conntrack state.
    if uses_ct and result is XdpAction.PASS and ct_state == ast.CtState.NEW:
      ct.create(packet)
    return EvalResult(
      action=action, redirect_zone=ctx.redirect_zone,
      output_packet=ctx.work if ctx.nat_fired else None,
    )
  for idx, rule in enumerate(program.rules):
    if rule.condition is not None and not _eval(
      rule.condition, packet, ctx, counters
    ):
      continue
    if rule.modifier is not None:
      if not _rate_limit_allows(rule.modifier, idx, packet, state):
        continue
    if rule.action in _TERMINAL_ACTION_TO_XDP:
      if (uses_ct and rule.action == ast.Action.ALLOW
          and ct_state == ast.CtState.NEW):
        ct.create(packet)
      return EvalResult(
        action=_TERMINAL_ACTION_TO_XDP[rule.action],
        counter_changes=counters,
        log_events=log_events,
        redirect_zone=(
          rule.redirect_zone
          if rule.action == ast.Action.REDIRECT else None
        ),
        output_packet=ctx.work if ctx.nat_fired else None,
      )
    if rule.action in ast.NAT_ACTIONS:
      # Non-terminal rewrite: translate the working packet and fall
      # through to the next rule (the terminal emits the rewrite).
      _apply_nat(rule.action, rule.nat_addr, rule.nat_port,
                 ctx.work, ctx.nat)
      ctx.nat_fired = True
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
    # An explicit `default allow` of a NEW packet creates state, the
    # same as an explicit allow rule. The implicit fall-through PASS
    # (no `default` clause) does not.
    if (uses_ct and program.default.action == ast.Action.ALLOW
        and ct_state == ast.CtState.NEW):
      ct.create(packet)
  else:
    action = XdpAction.PASS
  return EvalResult(
    action=action,
    counter_changes=counters,
    log_events=log_events,
    output_packet=ctx.work if ctx.nat_fired else None,
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
      if stmt.action == ast.Action.REDIRECT:
        ctx.redirect_zone = stmt.redirect_zone
        return XdpAction.REDIRECT
      if stmt.action in ast.NAT_ACTIONS:
        # Non-terminal rewrite: translate and fall through.
        _apply_nat(stmt.action, stmt.nat_addr, stmt.nat_port,
                   ctx.work, ctx.nat)
        ctx.nat_fired = True
        continue
      # LOG and COUNT are non-terminal: side effect omitted in test.
      continue
    if isinstance(stmt, ast.AssignStmt):
      locals_[stmt.name] = _eval_scalar(stmt.rhs, packet, ctx, locals_)
      continue
    if isinstance(stmt, ast.CallStmt):
      # v0.4 § 6.5: execute the helper inline with a FRESH local scope
      # (function-call semantics). A terminal action in the helper is
      # the packet's verdict and propagates; non-terminal side effects
      # (NAT rewrite, redirect_zone) already applied to `ctx`. The
      # analyzer guarantees the target resolves and is non-recursive.
      helper = ctx.helpers[stmt.name]
      result = _exec_stmts(helper.body, packet, ctx, state, {})
      if result is not None:
        return result
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
  if isinstance(expr, ast.ConntrackStateCompare):
    return _eval_ct_state_compare(expr, ctx.ct_state)
  if isinstance(expr, ast.ZoneCompare):
    return _eval_zone_compare(expr, ctx.zone_name)
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
  ast.FIELD_TCP_FIN: "fin",
  ast.FIELD_TCP_RST: "rst",
  ast.FIELD_TCP_PSH: "psh",
  ast.FIELD_TCP_URG: "urg",
  ast.FIELD_TCP_ECE: "ece",
  ast.FIELD_TCP_CWR: "cwr",
  ast.FIELD_ICMP_TYPE: "icmp_type",
  ast.FIELD_ICMP_CODE: "icmp_code",
  ast.FIELD_ICMP6_TYPE: "icmp6_type",
  ast.FIELD_ICMP6_CODE: "icmp6_code",
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
  def __init__(
    self,
    *,
    geoip_data: dict[str, list[str]],
    ct_state: ast.CtState = ast.CtState.NEW,
    zone_name: str | None = None,
    nat: "NatState | None" = None,
    helpers: dict[str, ast.FunctionDef] | None = None,
  ):
    self.geoip_data = geoip_data
    # v0.4 § 6.5 multi-def: name -> helper FunctionDef, so a CallStmt in
    # a Tier 2 body executes the helper inline (the interpreter models
    # the split-invisible single unit).
    self.helpers = helpers or {}
    # Phase 5 NAT model + accumulator. `nat` supplies the masquerade IP
    # and pre-seeded reply mappings. `work` is the packet's header
    # fields as a NAT rewrite leaves them; `nat_fired` records whether
    # any rewrite (ingress de-NAT or an action) touched it.
    self.nat = nat
    self.work: dict[str, Any] = {}
    self.nat_fired = False
    # The conntrack state of the packet under evaluation, computed once
    # from the conntrack table (v0.4). Every conntrack(pkt).state read
    # in this packet's evaluation sees the same value.
    self.ct_state = ct_state
    # The zone this @xdp block is attached to — pkt.zone's constant
    # value for the evaluation (v0.4 § 6.4).
    self.zone_name = zone_name
    # Set by a fired `redirect to <zone>` so evaluate_full can report
    # the destination on EvalResult.redirect_zone (v0.4 § 6.3).
    self.redirect_zone: str | None = None
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
  if isinstance(node, ast.ConntrackStateCompare):
    return _eval_ct_state_compare(node, ctx.ct_state)
  if isinstance(node, ast.ZoneCompare):
    return _eval_zone_compare(node, ctx.zone_name)
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


def _eval_ct_state_compare(
  node: ast.ConntrackStateCompare, ct_state: ast.CtState
) -> bool:
  """Evaluate `conntrack(pkt).state <op> ...` against the packet's state."""
  if node.op == "==":
    return ct_state == node.states[0]
  if node.op == "!=":
    return ct_state != node.states[0]
  if node.op == "in":
    return ct_state in node.states
  raise AssertionError(f"unexpected ct_state op {node.op}")


def _eval_zone_compare(node: ast.ZoneCompare, zone_name: str | None) -> bool:
  """Evaluate `pkt.zone <op> ...` — a compile-time constant (v0.4 § 6.4).

  pkt.zone equals the @xdp block's zone, so the comparison is decided
  by the static zone name alone.
  """
  if node.op == "==":
    return zone_name == node.zones[0]
  if node.op == "!=":
    return zone_name != node.zones[0]
  if node.op == "in":
    return zone_name in node.zones
  raise AssertionError(f"unexpected zone op {node.op}")


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
  ast.FIELD_TCP_FIN: "fin",
  ast.FIELD_TCP_RST: "rst",
  ast.FIELD_TCP_PSH: "psh",
  ast.FIELD_TCP_URG: "urg",
  ast.FIELD_TCP_ECE: "ece",
  ast.FIELD_TCP_CWR: "cwr",
  ast.FIELD_ICMP_TYPE: "icmp_type",
  ast.FIELD_ICMP_CODE: "icmp_code",
  ast.FIELD_ICMP6_TYPE: "icmp6_type",
  ast.FIELD_ICMP6_CODE: "icmp6_code",
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


def _int_to_ipv4(value: int) -> str:
  """Render a 32-bit integer (the `_ipv4_to_int` convention) as a
  dotted-quad string, the form the packet dict / output_packet uses."""
  return (f"{(value >> 24) & 0xff}.{(value >> 16) & 0xff}."
          f"{(value >> 8) & 0xff}.{value & 0xff}")


def _nat_work_init(packet: dict[str, Any]) -> dict[str, Any]:
  """The header fields a NAT rewrite may touch, copied from `packet`.

  Carries the dotted-quad src/dst IPs and src/dst ports (when present)
  so output_packet reports the post-rewrite 5-tuple regardless of which
  fields a given action changes."""
  work: dict[str, Any] = {}
  for k in ("src_ip", "dst_ip", "src_port", "dst_port", "proto"):
    if packet.get(k) is not None:
      work[k] = packet[k]
  return work


def _apply_ingress_denat(packet: dict[str, Any], ctx: "_Ctx") -> None:
  """Rewrite return traffic before rule evaluation (Phase 5).

  A reply to an egress SNAT/masquerade arrives addressed to the
  translated tuple; the seeded reply mapping restores the original
  internal destination. Mirrors the BPF program's pre-rule de-NAT."""
  if ctx.nat is None:
    return
  hit = ctx.nat.denat(packet)
  if hit is None:
    return
  kind, new_addr, new_port = hit
  if kind == "dnat":
    ctx.work["dst_ip"] = _int_to_ipv4(new_addr)
    if new_port is not None:
      ctx.work["dst_port"] = new_port
  elif kind == "snat":
    ctx.work["src_ip"] = _int_to_ipv4(new_addr)
    if new_port is not None:
      ctx.work["src_port"] = new_port
  ctx.nat_fired = True


def _apply_nat(action: ast.Action, nat_addr: int | None,
               nat_port: int | None, work: dict[str, Any],
               nat: "NatState | None") -> None:
  """Apply one NAT rewrite action to the working packet dict `work`.

  Port-preserving (the translated source port equals the original) so
  both oracles agree deterministically; only the address (and, for
  DNAT, the destination port) changes. masquerade rewrites the source
  to the masquerade IP (`state.nat.masq_ip`); snat to the literal
  target; dnat rewrites the destination address and port.

  Each rewrite also records the reply mapping, mirroring the emitter,
  which installs it before touching the frame. The mapping is derived
  from `work` BEFORE the rewrite — the reply is keyed on where the
  packet came from, not where it was translated to.
  """
  if action == ast.Action.SNAT and nat_addr is not None:
    if nat is not None:
      nat.install_egress_reply(work, nat_addr)
    work["src_ip"] = _int_to_ipv4(nat_addr)
  elif action == ast.Action.MASQUERADE:
    masq = nat.masq_ip if nat is not None else None
    if masq is not None:
      nat.install_egress_reply(work, masq)
      work["src_ip"] = _int_to_ipv4(masq)
  elif action == ast.Action.DNAT and nat_addr is not None:
    if nat is not None:
      nat.install_ingress_reply(work, nat_addr, nat_port)
    work["dst_ip"] = _int_to_ipv4(nat_addr)
    if nat_port is not None:
      work["dst_port"] = nat_port


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

  # ICMP/ICMPv6 type and code: u8 integer comparisons (mirror ports).
  if field_name in ast.ICMP_FIELDS or field_name in ast.ICMP6_FIELDS:
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
