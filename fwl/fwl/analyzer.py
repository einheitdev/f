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
from .iso3166 import ALPHA2_CODES


_ALL_PROTOS = frozenset({
  ast.Proto.TCP, ast.Proto.UDP, ast.Proto.ICMP, ast.Proto.ICMP6,
})


# Per-program prefix budget for all geoip() trie maps combined
# (FWL_V02_SPEC.md). Verified at bundle-time when geoip.json is read;
# the analyzer can't enforce it here because it doesn't see the
# data — but the cap is documented at the analyzer layer alongside
# the call-index allocation.
_GEOIP_PREFIX_BUDGET = 65536


# Allowed protocols per field. Empty set => no guard required.
# v0.2 IPv6 fields require no explicit guard — the parse short-
# circuits on EtherType, identical to v0.1's IPv4 L3 fields. Tier 1
# rules touching pkt.src_ip6/pkt.dst_ip6 against a v4 packet fall
# through with no field read happening at runtime.
_ALLOWED_PROTOS: dict[str, frozenset[ast.Proto]] = {
  ast.FIELD_PROTO: _ALL_PROTOS,
  ast.FIELD_SRC_IP: _ALL_PROTOS,
  ast.FIELD_DST_IP: _ALL_PROTOS,
  ast.FIELD_SRC_IP6: _ALL_PROTOS,
  ast.FIELD_DST_IP6: _ALL_PROTOS,
  ast.FIELD_SRC_PORT: frozenset({ast.Proto.TCP, ast.Proto.UDP}),
  ast.FIELD_DST_PORT: frozenset({ast.Proto.TCP, ast.Proto.UDP}),
  ast.FIELD_TCP_SYN: frozenset({ast.Proto.TCP}),
  ast.FIELD_TCP_ACK: frozenset({ast.Proto.TCP}),
  ast.FIELD_TCP_FIN: frozenset({ast.Proto.TCP}),
  ast.FIELD_TCP_RST: frozenset({ast.Proto.TCP}),
  ast.FIELD_TCP_PSH: frozenset({ast.Proto.TCP}),
  ast.FIELD_TCP_URG: frozenset({ast.Proto.TCP}),
  ast.FIELD_TCP_ECE: frozenset({ast.Proto.TCP}),
  ast.FIELD_TCP_CWR: frozenset({ast.Proto.TCP}),
  ast.FIELD_ICMP_TYPE: frozenset({ast.Proto.ICMP}),
  ast.FIELD_ICMP_CODE: frozenset({ast.Proto.ICMP}),
  ast.FIELD_ICMP6_TYPE: frozenset({ast.Proto.ICMP6}),
  ast.FIELD_ICMP6_CODE: frozenset({ast.Proto.ICMP6}),
  # v0.4 VLAN fields are L2 — readable on any frame, no proto guard
  # (FWL_V04_SPEC.md "VLAN 802.1Q / Type rules"). _ALL_PROTOS marks
  # "no guard required", identical to the L3 IP-field treatment.
  ast.FIELD_VLAN_ID: _ALL_PROTOS,
  ast.FIELD_VLAN_PRIORITY: _ALL_PROTOS,
}


# A `Possible` value is either None (no constraint, packet could be
# any protocol) or a frozenset of protos the packet must be one of.
Possible = frozenset[ast.Proto] | None


_MAX_COUNTERS = 256  # FWL_V01_SPEC.md:329


def analyze(program: ast.Program) -> ast.Program:
  """Run the semantic pass.

  Returns the same program object on success. Raises FwlException
  with category="semantic" on the first violation.

  v0.2 mutation contract: GeoIp operand nodes have `call_index` and
  `family` written during this pass; RateLimitCall nodes have
  `call_index` written. Every other AST node stays immutable. See
  ast.GeoIp's docstring for the rationale.

  Tier 1 vs Tier 2 mutual exclusion is enforced here: a program with
  both `rules`/`default` and `function` set raises the spec's
  "Tier 1 rule sequence or a single Tier 2 function, not a mix" error.
  """
  # Mutual exclusion: per FWL_V02_SPEC.md § Tier 2 / Edge cases.
  has_tier1 = bool(program.rules) or program.default is not None
  has_tier2 = program.function is not None
  if has_tier1 and has_tier2:
    raise FwlException(FwlError(
      category="semantic",
      message=(
        "v0.2 program is either a Tier 1 rule sequence or a single "
        "Tier 2 function, not a mix"
      ),
      span=program.function.span if program.function else None,
    ))

  if has_tier2:
    return _analyze_tier2(program)
  return _analyze_tier1(program)


def _analyze_tier1(program: ast.Program) -> ast.Program:
  """Tier 1 analyzer pass — runs on rules + optional default."""
  # Source-order pass to assign geoip call indices. Walking before
  # the type-check pass guarantees the indices match the bundle
  # manifest's source-order convention regardless of which rule's
  # type-check happens to run first.
  _assign_geoip_call_indices(program)

  counter_names: set[str] = set()
  for rule in program.rules:
    if rule.condition is not None:
      _reject_locals_tier1(rule.condition)
      _check(rule.condition, possible=None)
    if rule.modifier is not None:
      _check_modifier(rule.modifier)
    if rule.action == ast.Action.COUNT and rule.counter_name is not None:
      counter_names.add(rule.counter_name)
    if rule.log_sample is not None and rule.log_sample < 1:
      raise FwlException(FwlError(
        category="semantic",
        message=(
          f"log(sample=N) requires N >= 1 "
          f"(got {rule.log_sample})"
        ),
        span=rule.span,
      ))

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


def _analyze_tier2(program: ast.Program) -> ast.Program:
  """Tier 2 analyzer pass — type infer locals + dominator + reachability.

  Implementation detail per FWL_V02_SPEC.md § Tier 2:
  - Locals are typed by source-order first assignment.
  - Reads of unknown locals are read-before-assignment errors.
  - Statement-position pkt.<field> reads must be dominated by an
    appropriate guard.
  - Reachability check: statements after fully-terminating control
    flow are unreachable.
  - Stack budget warn at 256 / error at 450 bytes.
  """
  func = program.function
  assert func is not None
  _assign_geoip_call_indices_tier2(program)
  _assign_rate_limit_call_indices_tier2(program)
  ctx = _Tier2Ctx()
  _check_stmts(func.body, ctx, established_guards=frozenset())
  _check_stack_budget(func, ctx)
  if len(ctx.counter_names) > _MAX_COUNTERS:
    raise FwlException(FwlError(
      category="semantic",
      message=(
        f"program declares {len(ctx.counter_names)} counters; "
        f"v0.1 limit is {_MAX_COUNTERS}"
      ),
      span=func.span,
    ))
  return program


class _Tier2Ctx:
  """Mutable state threaded through the Tier 2 walk."""
  def __init__(self):
    self.locals: dict[str, ast.LocalType] = {}
    self.counter_names: set[str] = set()
    self.next_rate_limit_index = 0


def _check_stmts(
  stmts: list[ast.Stmt],
  ctx: _Tier2Ctx,
  established_guards: frozenset[str],
) -> tuple[bool, frozenset[str]]:
  """Walk a statement block.

  Returns (terminates, guards_at_end). `terminates` is True if every
  control-flow path from the block start hits a terminal action.
  `guards_at_end` is the set of guards still active when statements
  fall through to the parent block.
  """
  guards = established_guards
  terminated = False
  for i, stmt in enumerate(stmts):
    if terminated:
      raise FwlException(FwlError(
        category="semantic",
        message=(
          f"unreachable statement after terminal action "
          f"'{_last_terminal_name(stmts[:i])}'"
        ),
        span=getattr(stmt, "span", None),
      ))
    if isinstance(stmt, ast.ActionStmt):
      if stmt.action == ast.Action.COUNT and stmt.counter_name is not None:
        ctx.counter_names.add(stmt.counter_name)
      if stmt.action in ast.TERMINAL_ACTIONS:
        terminated = True
    elif isinstance(stmt, ast.AssignStmt):
      _check_assign(stmt, ctx, guards)
    elif isinstance(stmt, ast.IfStmt):
      branch_terms = []
      branch_cond_guards = _established_by(stmt.cond)
      _check_condition(stmt.cond, ctx, guards)
      then_terms, _ = _check_stmts(
        stmt.body, ctx, guards | branch_cond_guards
      )
      branch_terms.append(then_terms)
      for elif_cond, elif_body in stmt.elif_branches:
        elif_guards = _established_by(elif_cond)
        _check_condition(elif_cond, ctx, guards)
        elif_terms, _ = _check_stmts(
          elif_body, ctx, guards | elif_guards
        )
        branch_terms.append(elif_terms)
      if stmt.else_body is not None:
        else_terms, _ = _check_stmts(stmt.else_body, ctx, guards)
        branch_terms.append(else_terms)
      else:
        branch_terms.append(False)
      if all(branch_terms):
        terminated = True
    else:
      raise AssertionError(f"unexpected stmt {type(stmt).__name__}")
  return terminated, guards


def _last_terminal_name(prev_stmts: list[ast.Stmt]) -> str:
  """Return 'allow'/'drop' label of the most recent terminal in scope."""
  for s in reversed(prev_stmts):
    if isinstance(s, ast.ActionStmt) and s.action in ast.TERMINAL_ACTIONS:
      return s.action.value
    if isinstance(s, ast.IfStmt):
      return "allow"
  return "allow"


def _check_assign(
  stmt: ast.AssignStmt, ctx: _Tier2Ctx, guards: frozenset[str]
) -> None:
  """Type-infer or type-check a Tier 2 assignment.

  First assignment binds the local's type; subsequent assignments
  must agree on type. Field reads on the RHS that are bare (not
  inside a comparison/in) are dominator-checked.
  """
  if stmt.name == "pkt":
    raise FwlException(FwlError(
      category="semantic",
      message="'pkt' is reserved; cannot be used as a local name",
      span=stmt.span,
    ))
  rhs_type = _infer_scalar_type(stmt.rhs, ctx, guards, bare_field_read=True)
  if stmt.name in ctx.locals:
    existing = ctx.locals[stmt.name]
    if existing != rhs_type:
      raise FwlException(FwlError(
        category="semantic",
        message=(
          f"local '{stmt.name}' was bound as {existing.value}; "
          f"cannot reassign as {rhs_type.value}"
        ),
        span=stmt.span,
      ))
  else:
    ctx.locals[stmt.name] = rhs_type


def _infer_scalar_type(
  expr,
  ctx: _Tier2Ctx,
  guards: frozenset[str],
  *,
  bare_field_read: bool,
) -> ast.LocalType:
  """Infer the type of a scalar expression.

  `bare_field_read` controls whether a top-level FieldRef triggers
  the dominator check (true at assignment-RHS top level, false when
  the field is inside a comparison/in subtree).
  """
  if isinstance(expr, ast.IntLiteral):
    if expr.value > 0xFFFFFFFF:
      raise FwlException(FwlError(
        category="semantic",
        message=f"integer literal {expr.value} exceeds u32 range",
        span=expr.span,
      ))
    return ast.LocalType.U16 if expr.value <= 0xFFFF else ast.LocalType.U32
  if isinstance(expr, ast.IPv4Literal):
    return ast.LocalType.IPV4
  if isinstance(expr, ast.Ipv6Literal):
    return ast.LocalType.IPV6
  if isinstance(expr, ast.ProtoLiteral):
    return ast.LocalType.PROTO
  if isinstance(expr, ast.LocalRead):
    if expr.name not in ctx.locals:
      raise FwlException(FwlError(
        category="semantic",
        message=f"local '{expr.name}' read before assignment",
        span=expr.span,
      ))
    return ctx.locals[expr.name]
  if isinstance(expr, ast.FieldRef):
    if bare_field_read:
      _check_dominator(expr, guards)
    return _FIELD_LOCAL_TYPE[expr.name]
  if isinstance(expr, ast.BoolField):
    if bare_field_read:
      _check_dominator(expr.field, guards)
    return ast.LocalType.BOOL
  if isinstance(expr, ast.Comparison):
    _check_condition(expr, ctx, guards)
    return ast.LocalType.BOOL
  if isinstance(expr, (ast.AndOp, ast.OrOp, ast.NotOp)):
    _check_condition(expr, ctx, guards)
    return ast.LocalType.BOOL
  if isinstance(expr, ast.RateLimitCall):
    raise FwlException(FwlError(
      category="semantic",
      message=(
        "rate_limit(...) is only valid as the condition of an "
        "if-statement in Tier 2 or as the 'limited by' modifier "
        "of a Tier 1 rule"
      ),
      span=expr.span,
    ))
  if isinstance(
    expr,
    (ast.ListLiteral, ast.RangeLiteral, ast.CidrLiteral,
     ast.CidrListLiteral, ast.Ipv6CidrLiteral, ast.Ipv6CidrListLiteral,
     ast.GeoIp),
  ):
    raise FwlException(FwlError(
      category="semantic",
      message=(
        "assignment RHS must be scalar (bool/integer/ipv4/ipv6/proto); "
        "list/range/CIDR literals are only valid on the right of 'in'"
      ),
      span=getattr(expr, "span", None),
    ))
  raise AssertionError(f"unexpected scalar expr {type(expr).__name__}")


_FIELD_LOCAL_TYPE = {
  ast.FIELD_PROTO: ast.LocalType.PROTO,
  ast.FIELD_SRC_IP: ast.LocalType.IPV4,
  ast.FIELD_DST_IP: ast.LocalType.IPV4,
  ast.FIELD_SRC_IP6: ast.LocalType.IPV6,
  ast.FIELD_DST_IP6: ast.LocalType.IPV6,
  ast.FIELD_SRC_PORT: ast.LocalType.U16,
  ast.FIELD_DST_PORT: ast.LocalType.U16,
  ast.FIELD_TCP_SYN: ast.LocalType.BOOL,
  ast.FIELD_TCP_ACK: ast.LocalType.BOOL,
  ast.FIELD_TCP_FIN: ast.LocalType.BOOL,
  ast.FIELD_TCP_RST: ast.LocalType.BOOL,
  ast.FIELD_TCP_PSH: ast.LocalType.BOOL,
  ast.FIELD_TCP_URG: ast.LocalType.BOOL,
  ast.FIELD_TCP_ECE: ast.LocalType.BOOL,
  ast.FIELD_TCP_CWR: ast.LocalType.BOOL,
  # ICMP type/code are u8 on the wire; v0.2 has no u8 LocalType, so
  # they hoist into a u16 local (the smallest unsigned scalar that
  # holds 0..255). Direct field comparisons still range-check 0..255.
  ast.FIELD_ICMP_TYPE: ast.LocalType.U16,
  ast.FIELD_ICMP_CODE: ast.LocalType.U16,
  ast.FIELD_ICMP6_TYPE: ast.LocalType.U16,
  ast.FIELD_ICMP6_CODE: ast.LocalType.U16,
  # VLAN fields are u16-typed for Tier 2 binding; the tighter VID/PCP
  # range checks are applied per-field at comparison time.
  ast.FIELD_VLAN_ID: ast.LocalType.U16,
  ast.FIELD_VLAN_PRIORITY: ast.LocalType.U16,
}


def _check_condition(
  cond, ctx: _Tier2Ctx, guards: frozenset[str]
) -> None:
  """Walk a condition subtree, type-checking comparisons and locals."""
  if isinstance(cond, ast.Comparison):
    _check_tier2_comparison(cond, ctx, guards)
    return
  if isinstance(cond, ast.BoolField):
    return
  if isinstance(cond, ast.LocalRead):
    if cond.name not in ctx.locals:
      raise FwlException(FwlError(
        category="semantic",
        message=f"local '{cond.name}' read before assignment",
        span=cond.span,
      ))
    if ctx.locals[cond.name] != ast.LocalType.BOOL:
      raise FwlException(FwlError(
        category="semantic",
        message=(
          f"'{cond.name}' is type {ctx.locals[cond.name].value}; "
          f"only bool values are valid as a bare 'if' condition"
        ),
        span=cond.span,
      ))
    return
  if isinstance(cond, ast.NotOp):
    _check_condition(cond.inner, ctx, guards)
    return
  if isinstance(cond, (ast.AndOp, ast.OrOp)):
    for c in cond.operands:
      _check_condition(c, ctx, guards)
    return
  if isinstance(cond, ast.RateLimitCall):
    if cond.threshold <= 0:
      raise FwlException(FwlError(
        category="semantic",
        message="rate_limit threshold must be > 0",
        span=cond.span,
      ))
    if cond.threshold > _MAX_RL_THRESHOLD:
      raise FwlException(FwlError(
        category="semantic",
        message=(
          f"rate_limit threshold {cond.threshold} exceeds "
          f"u32 max ({_MAX_RL_THRESHOLD}); the BPF counter is __u32"
        ),
        span=cond.span,
      ))
    needed = _RL_PER_FIELD_DOMINATOR[cond.per_field]
    if needed not in guards:
      raise FwlException(FwlError(
        category="semantic",
        message=(
          f"rate_limit(per={cond.per_field}) call site does not "
          f"dominate the implicit read of pkt.{cond.per_field}"
        ),
        span=cond.span,
      ))
    if cond.call_index < 0:
      cond_call_index = ctx.next_rate_limit_index
      object.__setattr__(cond, "call_index", cond_call_index)
      ctx.next_rate_limit_index += 1
    return
  raise AssertionError(f"unexpected condition node {type(cond).__name__}")


def _check_tier2_comparison(
  cmp: ast.Comparison, ctx: _Tier2Ctx, guards: frozenset[str]
) -> None:
  """Type-check a Tier 2 comparison.

  Resolves both sides to a concrete type. Comparisons with a
  Tier 2 local on the LHS use the local's type; field reads inside
  a comparison are short-circuit-protected and don't trigger the
  dominator check.
  """
  lhs_type, lhs_label = _resolve_lvalue_type(cmp.field, ctx)
  if cmp.op == "in":
    _check_in_operand(lhs_type, lhs_label, cmp.field, cmp.operand, ctx)
    if isinstance(cmp.operand, ast.GeoIp):
      family = "ipv4" if lhs_type == ast.LocalType.IPV4 else "ipv6"
      _bind_geoip(cmp.operand, family=family)
    return
  if cmp.op in ("==", "!="):
    rhs_type, rhs_label = _resolve_rvalue_type(cmp.operand, ctx)
    if lhs_type != rhs_type:
      raise FwlException(FwlError(
        category="semantic",
        message=f"cannot compare {lhs_label} with {rhs_label}",
        span=cmp.span,
      ))
    if (lhs_type == ast.LocalType.U16
        and isinstance(cmp.operand, ast.IntLiteral)):
      _check_u16_field_int(cmp.field, cmp.operand.value, cmp.operand.span)
    return
  if cmp.op in ("<", ">", "<=", ">="):
    rhs_type, rhs_label = _resolve_rvalue_type(cmp.operand, ctx)
    if lhs_type not in (ast.LocalType.U16, ast.LocalType.U32):
      raise FwlException(FwlError(
        category="semantic",
        message=(
          f"cannot compare {lhs_label} with {rhs_label} using {cmp.op}; "
          f"ordered comparisons require matching integer types (u16 or u32)"
        ),
        span=cmp.span,
      ))
    if lhs_type != rhs_type:
      raise FwlException(FwlError(
        category="semantic",
        message=(
          f"cannot compare {lhs_label} with {rhs_label} using {cmp.op}; "
          f"ordered comparisons require matching integer types (u16 or u32)"
        ),
        span=cmp.span,
      ))
    if (lhs_type == ast.LocalType.U16
        and isinstance(cmp.operand, ast.IntLiteral)):
      _check_u16_field_int(cmp.field, cmp.operand.value, cmp.operand.span)
    return
  raise AssertionError(f"unexpected comparison op {cmp.op}")


def _resolve_lvalue_type(
  field, ctx: _Tier2Ctx
) -> tuple[ast.LocalType, str]:
  """Resolve a comparison's LHS to (LocalType, human label)."""
  if isinstance(field, ast.FieldRef):
    return _FIELD_LOCAL_TYPE[field.name], _FIELD_TYPE_LABEL[field.name]
  if isinstance(field, ast.LocalRead):
    if field.name not in ctx.locals:
      raise FwlException(FwlError(
        category="semantic",
        message=f"local '{field.name}' read before assignment",
        span=field.span,
      ))
    t = ctx.locals[field.name]
    return t, t.value
  raise AssertionError(f"unexpected lvalue {type(field).__name__}")


def _resolve_rvalue_type(
  operand, ctx: _Tier2Ctx
) -> tuple[ast.LocalType, str]:
  """Resolve a comparison's RHS scalar to (LocalType, human label)."""
  if isinstance(operand, ast.IntLiteral):
    if operand.value > 0xFFFFFFFF:
      raise FwlException(FwlError(
        category="semantic",
        message=f"integer literal {operand.value} exceeds u32 range",
        span=operand.span,
      ))
    t = ast.LocalType.U16 if operand.value <= 0xFFFF else ast.LocalType.U32
    return t, t.value
  if isinstance(operand, ast.IPv4Literal):
    return ast.LocalType.IPV4, "ipv4"
  if isinstance(operand, ast.Ipv6Literal):
    return ast.LocalType.IPV6, "ipv6"
  if isinstance(operand, ast.ProtoLiteral):
    return ast.LocalType.PROTO, f"proto keyword '{operand.proto.value}'"
  if isinstance(operand, ast.FieldRef):
    return _FIELD_LOCAL_TYPE[operand.name], _FIELD_TYPE_LABEL[operand.name]
  if isinstance(operand, ast.LocalRead):
    if operand.name not in ctx.locals:
      raise FwlException(FwlError(
        category="semantic",
        message=f"local '{operand.name}' read before assignment",
        span=operand.span,
      ))
    t = ctx.locals[operand.name]
    return t, t.value
  raise AssertionError(f"unexpected rvalue {type(operand).__name__}")


def _check_in_operand(
  lhs_type: ast.LocalType,
  lhs_label: str,
  lhs_node,
  operand,
  ctx: _Tier2Ctx,
) -> None:
  """Type-check the RHS of an `in` comparison given the LHS type."""
  if lhs_type == ast.LocalType.IPV4:
    if isinstance(operand, ast.GeoIp):
      return
    if isinstance(operand, (ast.CidrLiteral, ast.CidrListLiteral)):
      return
    if isinstance(operand, ast.ListLiteral):
      for item in operand.items:
        if not isinstance(item, ast.IPv4Literal):
          raise _type_error(lhs_label, "in", item, item.span)
      return
    raise _type_error(lhs_label, "in", operand, getattr(operand, "span", None))
  if lhs_type == ast.LocalType.IPV6:
    if isinstance(operand, ast.GeoIp):
      return
    if isinstance(operand, (ast.Ipv6CidrLiteral, ast.Ipv6CidrListLiteral)):
      return
    if isinstance(operand, ast.ListLiteral):
      for item in operand.items:
        if not isinstance(item, ast.Ipv6Literal):
          raise _type_error(lhs_label, "in", item, item.span)
      return
    raise _type_error(lhs_label, "in", operand, getattr(operand, "span", None))
  if lhs_type == ast.LocalType.U16:
    # VLAN fields carry the tighter VID/PCP range; ports use 0..65535.
    def _range_check(value, span):
      _check_u16_field_int(lhs_node, value, span)
    if isinstance(operand, ast.RangeLiteral):
      _range_check(operand.lo, operand.span)
      _range_check(operand.hi, operand.span)
      if operand.lo > operand.hi:
        raise FwlException(FwlError(
          category="semantic",
          message=(
            f"range lower bound ({operand.lo}) exceeds upper "
            f"bound ({operand.hi})"
          ),
          span=operand.span,
        ))
      return
    if isinstance(operand, ast.ListLiteral):
      for item in operand.items:
        if not isinstance(item, ast.IntLiteral):
          raise _type_error(lhs_label, "in", item, item.span)
        _range_check(item.value, item.span)
      return
    raise _type_error(lhs_label, "in", operand, getattr(operand, "span", None))
  if lhs_type == ast.LocalType.PROTO:
    if isinstance(operand, ast.ListLiteral):
      for item in operand.items:
        if not isinstance(item, ast.ProtoLiteral):
          raise FwlException(FwlError(
            category="semantic",
            message=(
              "'proto' values may only appear with 'in' over a list of "
              f"proto_keyword tokens; got {_operand_label(item)}"
            ),
            span=item.span,
          ))
      return
    raise _type_error(lhs_label, "in", operand, getattr(operand, "span", None))
  raise _type_error(
    lhs_label, "in", operand, getattr(operand, "span", None)
  )


_RL_PER_FIELD_DOMINATOR = {
  "src_ip": "ipv4",
  "dst_ip": "ipv4",
  "src_port": "l4",
  "dst_port": "l4",
}


def _established_by(cond) -> frozenset[str]:
  """Return the guard tags established by entering the then-branch.

  Per FWL_V02_SPEC.md § Tier 2 / Edge cases / dominator semantics —
  polarity-aware, disjunction-aware. Each disjunct of an OR must
  independently establish a tag for that tag to propagate to the
  then-branch.
  """
  if isinstance(cond, ast.Comparison):
    return _comparison_guards(cond)
  if isinstance(cond, ast.AndOp):
    out = set()
    for c in cond.operands:
      out |= _established_by(c)
    return frozenset(out)
  if isinstance(cond, ast.OrOp):
    branch_guards = [_established_by(c) for c in cond.operands]
    if not branch_guards:
      return frozenset()
    common = set(branch_guards[0])
    for g in branch_guards[1:]:
      common &= g
    return frozenset(common)
  return frozenset()


def _comparison_guards(cmp: ast.Comparison) -> frozenset[str]:
  """Single-comparison guard contribution.

  Reading any v4 IP field (in any positive comparison form) gives v4.
  Reading any v6 IP field gives v6. proto == icmp6 (and the
  single-element list form) gives v6 + l3.
  """
  out: set[str] = set()
  field = cmp.field
  if isinstance(field, ast.FieldRef):
    if field.name in ast.IP_FIELDS:
      out.add("ipv4")
      out.add("l3")
    if field.name in ast.IP6_FIELDS:
      out.add("ipv6")
      out.add("l3")
    if field.name in ast.PORT_FIELDS:
      out.add("l4")
    if field.name == ast.FIELD_PROTO:
      if (
        cmp.op in ("==", "!=")
        and isinstance(cmp.operand, ast.ProtoLiteral)
        and cmp.operand.proto == ast.Proto.ICMP6
        and cmp.op == "=="
      ):
        out.add("ipv6")
        out.add("l3")
      if (
        cmp.op == "in"
        and isinstance(cmp.operand, ast.ListLiteral)
        and len(cmp.operand.items) == 1
        and isinstance(cmp.operand.items[0], ast.ProtoLiteral)
        and cmp.operand.items[0].proto == ast.Proto.ICMP6
      ):
        out.add("ipv6")
        out.add("l3")
      if (
        cmp.op in ("==", "!=")
        and isinstance(cmp.operand, ast.ProtoLiteral)
        and cmp.op == "=="
        and cmp.operand.proto in (ast.Proto.TCP, ast.Proto.UDP)
      ):
        out.add("l4")
      # pkt.proto == icmp / icmp6 establish the guard tags that
      # dominate pkt.icmp.* / pkt.icmp6.* reads in Tier 2. The icmp6
      # form also contributes ipv6 + l3 above (it implies the v6 path).
      if (
        cmp.op == "=="
        and isinstance(cmp.operand, ast.ProtoLiteral)
        and cmp.operand.proto == ast.Proto.ICMP
      ):
        out.add("icmp")
      if (
        cmp.op == "=="
        and isinstance(cmp.operand, ast.ProtoLiteral)
        and cmp.operand.proto == ast.Proto.ICMP6
      ):
        out.add("icmp6")
  return frozenset(out)


def _check_dominator(field: ast.FieldRef, guards: frozenset[str]) -> None:
  """Enforce the dominator rule for a bare field read."""
  name = field.name
  if name in ast.PORT_FIELDS:
    if "l4" not in guards:
      raise FwlException(FwlError(
        category="semantic",
        message=(
          f"'{name}' read on a path not guarded by "
          f"'pkt.proto == tcp/udp'"
        ),
        span=field.span,
      ))
    return
  if name in ast.TCP_FLAG_FIELDS:
    if "l4" not in guards:
      raise FwlException(FwlError(
        category="semantic",
        message=(
          f"'{name}' read on a path not guarded by 'pkt.proto == tcp'"
        ),
        span=field.span,
      ))
    return
  if name in ast.ICMP_FIELDS:
    if "icmp" not in guards:
      raise FwlException(FwlError(
        category="semantic",
        message=(
          f"'{name}' read on a path not guarded by 'pkt.proto == icmp'"
        ),
        span=field.span,
      ))
    return
  if name in ast.ICMP6_FIELDS:
    if "icmp6" not in guards:
      raise FwlException(FwlError(
        category="semantic",
        message=(
          f"'{name}' read on a path not guarded by 'pkt.proto == icmp6'"
        ),
        span=field.span,
      ))
    return
  if name in ast.IP_FIELDS:
    if "ipv4" not in guards:
      raise FwlException(FwlError(
        category="semantic",
        message=(
          f"'{name}' read on a path not guarded by an IPv4-establishing "
          f"condition"
        ),
        span=field.span,
      ))
    return
  if name in ast.IP6_FIELDS:
    if "ipv6" not in guards:
      raise FwlException(FwlError(
        category="semantic",
        message=(
          f"'{name}' read on a path not guarded by an IPv6-establishing "
          f"condition"
        ),
        span=field.span,
      ))
    return
  if name == ast.FIELD_PROTO:
    if "l3" not in guards:
      raise FwlException(FwlError(
        category="semantic",
        message=(
          "'pkt.proto' read on a path not guarded by an L3-establishing "
          "condition"
        ),
        span=field.span,
      ))
    return


_LOCAL_WIDTH_BYTES = {
  ast.LocalType.BOOL: 1,
  ast.LocalType.U16: 2,
  ast.LocalType.U32: 4,
  ast.LocalType.IPV4: 4,
  ast.LocalType.IPV6: 16,
  ast.LocalType.PROTO: 1,
}

_STACK_WARN = 256
_STACK_HARD = 450


def _check_stack_budget(func: ast.FunctionDef, ctx: _Tier2Ctx) -> None:
  """Estimate stack usage from declared locals; warn/error per spec."""
  total = 0
  for t in ctx.locals.values():
    width = _LOCAL_WIDTH_BYTES[t]
    total += (width + 7) & ~7
  if total >= _STACK_HARD:
    raise FwlException(FwlError(
      category="semantic",
      message=(
        f"function '{func.name}' estimated stack use is {total} bytes; "
        f"v0.2 limit is {_STACK_HARD} bytes"
      ),
      span=func.span,
    ))


def _assign_geoip_call_indices_tier2(program: ast.Program) -> None:
  """Source-order index assignment for Tier 2 geoip calls."""
  next_index = 0
  func = program.function
  if func is None:
    return
  for op in _walk_geoip_in_stmts(func.body):
    op.call_index = next_index
    next_index += 1


def _walk_geoip_in_stmts(stmts):
  for s in stmts:
    if isinstance(s, ast.AssignStmt):
      yield from _walk_geoip_in_expr(s.rhs)
    elif isinstance(s, ast.IfStmt):
      yield from _walk_geoip_in_expr(s.cond)
      yield from _walk_geoip_in_stmts(s.body)
      for cond, body in s.elif_branches:
        yield from _walk_geoip_in_expr(cond)
        yield from _walk_geoip_in_stmts(body)
      if s.else_body is not None:
        yield from _walk_geoip_in_stmts(s.else_body)


def _walk_geoip_in_expr(expr):
  if isinstance(expr, ast.Comparison) and isinstance(expr.operand, ast.GeoIp):
    yield expr.operand
    return
  if isinstance(expr, ast.NotOp):
    yield from _walk_geoip_in_expr(expr.inner)
  elif isinstance(expr, (ast.AndOp, ast.OrOp)):
    for c in expr.operands:
      yield from _walk_geoip_in_expr(c)


def _assign_rate_limit_call_indices_tier2(program: ast.Program) -> None:
  """Source-order index assignment for Tier 2 rate_limit_call instances."""
  func = program.function
  if func is None:
    return
  next_index = 0
  for call in _walk_rate_limit_in_stmts(func.body):
    object.__setattr__(call, "call_index", next_index)
    next_index += 1


def _walk_rate_limit_in_stmts(stmts):
  for s in stmts:
    if isinstance(s, ast.IfStmt):
      yield from _walk_rate_limit_in_expr(s.cond)
      yield from _walk_rate_limit_in_stmts(s.body)
      for cond, body in s.elif_branches:
        yield from _walk_rate_limit_in_expr(cond)
        yield from _walk_rate_limit_in_stmts(body)
      if s.else_body is not None:
        yield from _walk_rate_limit_in_stmts(s.else_body)


def _walk_rate_limit_in_expr(expr):
  if isinstance(expr, ast.RateLimitCall):
    yield expr
    return
  if isinstance(expr, ast.NotOp):
    yield from _walk_rate_limit_in_expr(expr.inner)
  elif isinstance(expr, (ast.AndOp, ast.OrOp)):
    for c in expr.operands:
      yield from _walk_rate_limit_in_expr(c)


def _reject_locals_tier1(node) -> None:
  """Tier 1 has no locals; any LocalRead is an unknown name."""
  for operand in _walk_operands(node):
    if isinstance(operand, ast.LocalRead):
      raise FwlException(FwlError(
        category="semantic",
        message=f"unknown name '{operand.name}'",
        span=operand.span,
      ))
  # Walk lvalues too — pkt.proto == <local_name> would put a
  # LocalRead on the rvalue side which _walk_operands yields as the
  # operand, but the lvalue side could also be a LocalRead in a Tier 1
  # program if a user mistakenly wrote `foo == 22`. Catch that here.
  for cmp in _walk_comparisons(node):
    if isinstance(cmp.field, ast.LocalRead):
      raise FwlException(FwlError(
        category="semantic",
        message=f"unknown name '{cmp.field.name}'",
        span=cmp.field.span,
      ))


_FIELD_TYPE_LABEL = {
  ast.FIELD_PROTO: "proto enum",
  ast.FIELD_SRC_IP: "ipv4",
  ast.FIELD_DST_IP: "ipv4",
  ast.FIELD_SRC_IP6: "ipv6",
  ast.FIELD_DST_IP6: "ipv6",
  ast.FIELD_SRC_PORT: "port (u16)",
  ast.FIELD_DST_PORT: "port (u16)",
  ast.FIELD_TCP_SYN: "bool",
  ast.FIELD_TCP_ACK: "bool",
  ast.FIELD_TCP_FIN: "bool",
  ast.FIELD_TCP_RST: "bool",
  ast.FIELD_TCP_PSH: "bool",
  ast.FIELD_TCP_URG: "bool",
  ast.FIELD_TCP_ECE: "bool",
  ast.FIELD_TCP_CWR: "bool",
  ast.FIELD_ICMP_TYPE: "icmp type (u8)",
  ast.FIELD_ICMP_CODE: "icmp code (u8)",
  ast.FIELD_ICMP6_TYPE: "icmp6 type (u8)",
  ast.FIELD_ICMP6_CODE: "icmp6 code (u8)",
  ast.FIELD_VLAN_ID: "vlan_id (u16)",
  ast.FIELD_VLAN_PRIORITY: "vlan_priority (u16)",
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
    return "ipv4 cidr"
  if isinstance(operand, ast.CidrListLiteral):
    return "ipv4 cidr list"
  if isinstance(operand, ast.Ipv6Literal):
    return "ipv6 literal"
  if isinstance(operand, ast.Ipv6CidrLiteral):
    return "ipv6 cidr"
  if isinstance(operand, ast.Ipv6CidrListLiteral):
    return "ipv6 cidr list"
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


_VLAN_FIELD_LABEL = {
  ast.FIELD_VLAN_ID: "vlan_id",
  ast.FIELD_VLAN_PRIORITY: "vlan_priority",
}


def _check_vlan_int(field_name: str, value: int, span) -> None:
  """Range-check a VLAN field literal (FWL_V04_SPEC.md compile errors).

  vlan_id must be 0..4095 (12-bit VID); vlan_priority must be 0..7
  (3-bit PCP). Applied to ==/!=/ordered operands and to every member
  of an `in` list/range.
  """
  max_val = ast.VLAN_FIELD_MAX[field_name]
  if not (0 <= value <= max_val):
    raise FwlException(FwlError(
      category="semantic",
      message=(
        f"{_VLAN_FIELD_LABEL[field_name]} value {value} outside "
        f"valid range 0..{max_val}"
      ),
      span=span,
    ))


def _check_u16_field_int(field_node, value: int, span) -> None:
  """Range-check an int literal against a u16 field's domain.

  VLAN fields use their tighter VID/PCP ranges; every other u16
  field (ports, u16 locals) uses the 0..65535 port range.
  """
  if (isinstance(field_node, ast.FieldRef)
      and field_node.name in ast.VLAN_FIELDS):
    _check_vlan_int(field_node.name, value, span)
  else:
    _check_port_int(value, span)


def _check_u8_int(value: int, span) -> None:
  """ICMP type/code literal must be in 0..255 (u8 wire field)."""
  if not (0 <= value <= 255):
    raise FwlException(
      FwlError(
        category="semantic",
        message=(
          f"icmp type/code value {value} outside valid range 0..255"
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
    if op in ("==", "!="):
      if not isinstance(operand, ast.ProtoLiteral):
        raise _type_error(field_label, op, operand, span)
      return
    if op == "in":
      if not isinstance(operand, ast.ListLiteral):
        raise _type_error(field_label, op, operand, span)
      for item in operand.items:
        if not isinstance(item, ast.ProtoLiteral):
          raise FwlException(FwlError(
            category="semantic",
            message=(
              "'proto' values may only appear with 'in' over a list of "
              f"proto_keyword tokens; got {_operand_label(item)}"
            ),
            span=item.span,
          ))
      return
    raise _type_error(field_label, op, operand, span)

  if field_name in ast.IP_FIELDS:
    if op in ("==", "!="):
      if not isinstance(operand, ast.IPv4Literal):
        raise _type_error(field_label, op, operand, span)
    elif op == "in":
      if isinstance(operand, ast.GeoIp):
        _bind_geoip(operand, family="ipv4")
      elif not isinstance(
        operand, (ast.CidrLiteral, ast.CidrListLiteral, ast.ListLiteral)
      ):
        raise _type_error(field_label, op, operand, span)
      elif isinstance(operand, ast.ListLiteral):
        for item in operand.items:
          if not isinstance(item, ast.IPv4Literal):
            raise _type_error(field_label, op, item, item.span)
    else:
      raise _type_error(field_label, op, operand, span)
    return

  if field_name in ast.IP6_FIELDS:
    if op in ("==", "!="):
      if not isinstance(operand, ast.Ipv6Literal):
        raise _type_error(field_label, op, operand, span)
    elif op == "in":
      if isinstance(operand, ast.GeoIp):
        _bind_geoip(operand, family="ipv6")
      elif not isinstance(
        operand,
        (ast.Ipv6CidrLiteral, ast.Ipv6CidrListLiteral, ast.ListLiteral),
      ):
        raise _type_error(field_label, op, operand, span)
      elif isinstance(operand, ast.ListLiteral):
        for item in operand.items:
          if not isinstance(item, ast.Ipv6Literal):
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

  if field_name in ast.VLAN_FIELDS:
    if op in ("==", "!=", "<", ">", "<=", ">="):
      if not isinstance(operand, ast.IntLiteral):
        raise _type_error(field_label, op, operand, span)
      _check_vlan_int(field_name, operand.value, operand.span)
    elif op == "in":
      if isinstance(operand, ast.RangeLiteral):
        _check_vlan_int(field_name, operand.lo, operand.span)
        _check_vlan_int(field_name, operand.hi, operand.span)
        if operand.lo > operand.hi:
          raise FwlException(FwlError(
            category="semantic",
            message=(
              f"range lower bound ({operand.lo}) exceeds upper "
              f"bound ({operand.hi})"
            ),
            span=operand.span,
          ))
      elif isinstance(operand, ast.ListLiteral):
        for item in operand.items:
          if not isinstance(item, ast.IntLiteral):
            raise _type_error(field_label, op, item, item.span)
          _check_vlan_int(field_name, item.value, item.span)
      else:
        raise _type_error(field_label, op, operand, span)
    else:
      raise _type_error(field_label, op, operand, span)
    return

  # ICMP/ICMPv6 type and code are u8 integer fields — same comparison
  # surface as ports (==/!=/ordered/in range or list) but bounded to
  # 0..255 (FWL_V04_SPEC.md § 4.2).
  if field_name in ast.ICMP_FIELDS or field_name in ast.ICMP6_FIELDS:
    if op in ("==", "!=", "<", ">", "<=", ">="):
      if not isinstance(operand, ast.IntLiteral):
        raise _type_error(field_label, op, operand, span)
      _check_u8_int(operand.value, operand.span)
    elif op == "in":
      if isinstance(operand, ast.RangeLiteral):
        _check_u8_int(operand.lo, operand.span)
        _check_u8_int(operand.hi, operand.span)
        if operand.lo > operand.hi:
          raise FwlException(FwlError(
            category="semantic",
            message=(
              f"range lower bound ({operand.lo}) exceeds upper "
              f"bound ({operand.hi})"
            ),
            span=operand.span,
          ))
      elif isinstance(operand, ast.ListLiteral):
        for item in operand.items:
          if not isinstance(item, ast.IntLiteral):
            raise _type_error(field_label, op, item, item.span)
          _check_u8_int(item.value, item.span)
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


def _walk_operands(node):
  """Yield every Operand reachable under `node` (pre-order)."""
  if node is None:
    return
  if isinstance(node, ast.Comparison):
    yield node.operand
    return
  if isinstance(node, ast.NotOp):
    yield from _walk_operands(node.inner)
    return
  if isinstance(node, (ast.AndOp, ast.OrOp)):
    for child in node.operands:
      yield from _walk_operands(child)


def _walk_comparisons(node):
  """Yield every Comparison reachable under `node` (pre-order)."""
  if node is None:
    return
  if isinstance(node, ast.Comparison):
    yield node
    return
  if isinstance(node, ast.NotOp):
    yield from _walk_comparisons(node.inner)
    return
  if isinstance(node, (ast.AndOp, ast.OrOp)):
    for child in node.operands:
      yield from _walk_comparisons(child)


def _assign_geoip_call_indices(program: ast.Program) -> None:
  """Walk the program in source order, numbering each GeoIp call.

  Every textual occurrence of `geoip(...)` is its own call site
  (FWL_V02_SPEC.md). The analyzer numbers them 0, 1, 2, ... in the
  rule-list order, matching the manifest emission order the bundle
  later writes.
  """
  next_index = 0
  for rule in program.rules:
    for operand in _walk_operands(rule.condition):
      if isinstance(operand, ast.GeoIp):
        operand.call_index = next_index
        next_index += 1


def _bind_geoip(node: ast.GeoIp, family: str) -> None:
  """Validate codes and bind family on a geoip() call site.

  - Empty code list → compile error.
  - Codes not in ISO 3166-1 alpha-2 list → compile error.
  - Duplicate codes are silently de-duplicated (FWL_V02_SPEC.md).

  Family ("ipv4" or "ipv6") is stamped on the node so the emitter
  and bundle-manifest writer can pick the right LPM trie key width.
  """
  if not node.codes:
    raise FwlException(FwlError(
      category="semantic",
      message="geoip requires at least one country code",
      span=node.span,
    ))
  for code in node.codes:
    if code not in ALPHA2_CODES:
      raise FwlException(FwlError(
        category="semantic",
        message=(
          f"unknown country code '{code}' "
          f"(not in ISO 3166-1 alpha-2)"
        ),
        span=node.span,
      ))
  # Silent dedup, preserve order of first appearance.
  seen: set[str] = set()
  unique: list[str] = []
  for code in node.codes:
    if code not in seen:
      seen.add(code)
      unique.append(code)
  node.codes = tuple(unique)
  node.family = family


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

  if isinstance(node, ast.CountCompare):
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
