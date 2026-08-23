"""Pipeline-split estimator + split-point calculator (v0.4 § 6.6).

The compiler decides whether a zone's program fits in a single BPF
program or must be split into a `bpf_tail_call()` pipeline. This module
holds that decision, kept separate from the emitter so the analyzer (for
diagnostics), the emitter (for code generation), and the runner (to
chain stages in BPF_PROG_TEST_RUN) all consume one authoritative plan.

Heuristic (roadmap 6.6):
  - Estimate instruction count from per-feature costs: parse ~2K,
    conntrack lookup ~5K, NAT ~8K, 500 per rule, 3K per geoip LPM call.
  - Estimate BPF stack usage from the parsed-field working set.
  - If instructions < 500K AND stack < 400B AND no manual `chain`:
    emit a single program (no pipeline overhead).
  - Otherwise split: a parse stage that writes the per-CPU scratch
    struct, then one or more policy stages (Tier 1 rule groups, or a
    single Tier 2 policy stage). Manual `chain` markers force cuts; the
    auto-splitter additionally cuts a rule group before it would exceed
    the per-stage instruction budget.

Estimates are deliberately approximate — they exist to keep a program
off the verifier's hard limits, and can be tuned as real measurements
accumulate.
"""
from __future__ import annotations
from dataclasses import dataclass

from . import ast

# Per-feature instruction estimates (roadmap 6.6).
PARSE_INSTR = 2000
CONNTRACK_INSTR = 5000
NAT_INSTR = 8000
RULE_INSTR = 500
GEOIP_INSTR = 3000

# Split thresholds. A program strictly under BOTH stays single.
INSTR_BUDGET = 500_000
STACK_BUDGET = 400

# The BPF hard per-program limits the split defends against. A single
# stage is kept under these; they also bound the auto-split group size.
HARD_INSTR = 1_000_000
HARD_STACK = 512

# A stage that unpacks the scratch struct and then evaluates a very long
# rule chain spills more BPF stack than the equivalent inline code (the
# scratch pointer + unpacked locals stay live across the chain), so clang
# can hit the 512-byte stack ceiling well before the instruction ceiling.
# Cap the rules per stage so no group grows into that regime — a hard
# safety bound on top of the instruction budget, tuned from the point
# where a single stage stops compiling on clang 19 / kernel 6.12.
MAX_RULES_PER_STAGE = 64

# The kernel will not follow a tail-call chain deeper than
# MAX_TAIL_CALL_CNT, which has been 33 since 5.10. Past that the tail
# call simply does not happen: `bpf_tail_call` returns, and the calling
# stage falls through to whatever follows it.
#
# For a firewall that is the worst possible failure. Measured on the
# rig with a 2,500-rule policy, which the compiler split into 41
# stages: the program loaded, `fctl status` reported `xdp_attached:
# true` on both interfaces, and not one packet was dropped, redirected
# or forwarded -- because the terminal `redirect to lan` lives in the
# last stage, and stages 34 through 40 never ran. A policy that
# silently stops enforcing while reporting healthy is precisely what
# this compiler exists to refuse.
#
# A chain of N stages performs N-1 tail calls, so 34 stages would fit
# exactly. One is kept in hand rather than sitting on the boundary of
# a kernel constant we do not control.
MAX_TAIL_CALL_CNT = 33
MAX_STAGES = MAX_TAIL_CALL_CNT

# With MAX_RULES_PER_STAGE rules in each policy stage and one parse
# stage ahead of them, this is the largest Tier 1 rule set that can be
# expressed at all. Reported in the error rather than left for the
# reader to multiply.
MAX_TIER1_RULES = (MAX_STAGES - 1) * MAX_RULES_PER_STAGE

# Rough stack costs (bytes), 8-byte aligned working set.
_STACK_BASE = 24
_STACK_PER_FIELD = 8
_STACK_CONNTRACK = 72   # two fwl_conn_key probes + value pointer scratch
_STACK_NAT = 80         # rewrite + checksum locals
_STACK_PER_LOCAL = 8


@dataclass(frozen=True)
class Estimate:
  """Instruction + stack estimate for a zone program (single-program)."""
  instructions: int
  stack: int


@dataclass(frozen=True)
class Stage:
  """One stage of a split pipeline.

  `index` 0 is always the parse stage; 1.. are policy stages. For a
  Tier 1 split, `rule_range` is the [lo, hi) slice of the zone's rules
  this stage evaluates; the last policy stage also applies the default.
  For a Tier 2 split there is exactly one policy stage (`kind` ==
  "policy", `rule_range` None).
  """
  index: int
  kind: str  # "parse" | "rules" | "policy"
  rule_range: tuple[int, int] | None
  label: str
  is_last: bool


@dataclass(frozen=True)
class SplitPlan:
  """The compiler's decision for one zone."""
  split: bool
  stages: tuple[Stage, ...]
  estimate: Estimate
  reason: str

  @property
  def n_stages(self) -> int:
    return len(self.stages)


# --- usage detection (self-contained; oracle-independent) -----------

def _walk_cond(node):
  if node is None:
    return
  yield node
  if isinstance(node, ast.NotOp):
    yield from _walk_cond(node.inner)
  elif isinstance(node, (ast.AndOp, ast.OrOp)):
    for c in node.operands:
      yield from _walk_cond(c)


def _rule_geoip_calls(rule: ast.Rule) -> int:
  n = 0
  for node in _walk_cond(rule.condition):
    if isinstance(node, ast.Comparison) and isinstance(
      node.operand, ast.GeoIp
    ):
      n += 1
  return n


def _cond_uses_ct(node) -> bool:
  return any(
    isinstance(n, ast.ConntrackStateCompare) for n in _walk_cond(node)
  )


def _uses_conntrack(zp: ast.ZoneProgram) -> bool:
  for rule in zp.rules:
    if _cond_uses_ct(rule.condition):
      return True
  if zp.function is not None:
    return _stmts_use_ct(zp.function.body)
  return False


def _stmts_use_ct(stmts) -> bool:
  for s in stmts:
    if isinstance(s, ast.AssignStmt) and _cond_uses_ct(s.rhs):
      return True
    if isinstance(s, ast.IfStmt):
      if _cond_uses_ct(s.cond) or _stmts_use_ct(s.body):
        return True
      for cond, body in s.elif_branches:
        if _cond_uses_ct(cond) or _stmts_use_ct(body):
          return True
      if s.else_body is not None and _stmts_use_ct(s.else_body):
        return True
  return False


def _uses_nat(zp: ast.ZoneProgram) -> bool:
  for rule in zp.rules:
    if rule.action in ast.NAT_ACTIONS:
      return True
  if zp.function is not None:
    return _stmts_use_nat(zp.function.body)
  return False


def _stmts_use_nat(stmts) -> bool:
  for s in stmts:
    if isinstance(s, ast.ActionStmt) and s.action in ast.NAT_ACTIONS:
      return True
    if isinstance(s, ast.IfStmt):
      if _stmts_use_nat(s.body):
        return True
      for _cond, body in s.elif_branches:
        if _stmts_use_nat(body):
          return True
      if s.else_body is not None and _stmts_use_nat(s.else_body):
        return True
  return False


def _distinct_fields(zp: ast.ZoneProgram) -> int:
  names: set[str] = set()
  for rule in zp.rules:
    for node in _walk_cond(rule.condition):
      if isinstance(node, ast.Comparison) and isinstance(
        node.field, ast.FieldRef
      ):
        names.add(node.field.name)
      elif isinstance(node, ast.BoolField):
        names.add(node.field.name)
  # Tier 2 field working set is dominated by the same fixed header set;
  # approximate with a small constant so the estimate stays monotone.
  if zp.function is not None:
    return max(len(names), 6)
  return len(names)


def _tier2_locals(zp: ast.ZoneProgram) -> int:
  if zp.function is None:
    return 0
  seen: set[str] = set()

  def walk(stmts):
    for s in stmts:
      if isinstance(s, ast.AssignStmt):
        seen.add(s.name)
      elif isinstance(s, ast.IfStmt):
        walk(s.body)
        for _c, body in s.elif_branches:
          walk(body)
        if s.else_body is not None:
          walk(s.else_body)

  walk(zp.function.body)
  return len(seen)


# --- estimation -----------------------------------------------------

def estimate(zp: ast.ZoneProgram) -> Estimate:
  """Estimate a zone program's single-program instruction + stack use."""
  instr = PARSE_INSTR
  uses_ct = _uses_conntrack(zp)
  uses_nat = _uses_nat(zp)
  if uses_ct:
    instr += CONNTRACK_INSTR
  if uses_nat:
    instr += NAT_INSTR
  for rule in zp.rules:
    instr += RULE_INSTR + GEOIP_INSTR * _rule_geoip_calls(rule)
  if zp.function is not None:
    # A Tier 2 body's instruction cost tracks its statement/condition
    # count; approximate one "rule" per statement.
    instr += RULE_INSTR * max(_count_stmts(zp.function.body), 1)

  stack = _STACK_BASE + _STACK_PER_FIELD * _distinct_fields(zp)
  if uses_ct:
    stack += _STACK_CONNTRACK
  if uses_nat:
    stack += _STACK_NAT
  stack += _STACK_PER_LOCAL * _tier2_locals(zp)
  return Estimate(instructions=instr, stack=stack)


def _count_stmts(stmts) -> int:
  n = 0
  for s in stmts:
    n += 1
    if isinstance(s, ast.IfStmt):
      n += _count_stmts(s.body)
      for _c, body in s.elif_branches:
        n += _count_stmts(body)
      if s.else_body is not None:
        n += _count_stmts(s.else_body)
  return n


# --- split planning -------------------------------------------------

def plan(
  zp: ast.ZoneProgram,
  *,
  force_split: bool = False,
  max_stage_instr: int = INSTR_BUDGET,
  instr_budget: int = INSTR_BUDGET,
  stack_budget: int = STACK_BUDGET,
) -> SplitPlan:
  """Decide the pipeline shape for one zone.

  `force_split` (used by the pipeline_equivalence harness and by a very
  low `instr_budget`) makes a program that would otherwise stay single
  split anyway, so the split path is exercised on small programs.
  `max_stage_instr` bounds the auto-split rule-group size.
  """
  est = estimate(zp)
  has_manual = bool(_effective_boundaries(zp))
  over = est.instructions >= instr_budget or est.stack >= stack_budget
  if not (over or has_manual or force_split):
    return SplitPlan(
      split=False, stages=(), estimate=est,
      reason=(
        f"single: ~{est.instructions} instr, ~{est.stack}B stack "
        f"(under {instr_budget}/{stack_budget})"
      ),
    )

  if zp.function is not None:
    # Tier 2: parse stage + one policy stage (locals do not survive a
    # tail call, so the body is not split mid-function).
    stages = (
      Stage(0, "parse", None, "parse", is_last=False),
      Stage(1, "policy", None, "policy", is_last=True),
    )
    return SplitPlan(
      split=True, stages=stages, estimate=est,
      reason=_reason(est, has_manual, force_split, over),
    )

  groups = _partition_rules(zp, max_stage_instr)
  stages = [Stage(0, "parse", None, "parse", is_last=False)]
  for i, (lo, hi) in enumerate(groups):
    stages.append(Stage(
      index=i + 1, kind="rules", rule_range=(lo, hi),
      label=f"rules{i}", is_last=(i == len(groups) - 1),
    ))
  return SplitPlan(
    split=True, stages=tuple(stages), estimate=est,
    reason=_reason(est, has_manual, force_split, over),
  )


def _reason(est, has_manual, force_split, over) -> str:
  if has_manual:
    return "split: manual `chain` boundary"
  if force_split:
    return "split: forced (pipeline_equivalence / low budget)"
  if over:
    return (
      f"split: ~{est.instructions} instr / ~{est.stack}B stack over budget"
    )
  return "split"


def _effective_boundaries(zp: ast.ZoneProgram) -> list[int]:
  """Manual `chain` cut points inside the rule list (1..len-1)."""
  n = len(zp.rules)
  return sorted({
    b for b in getattr(zp, "chain_boundaries", ()) if 0 < b < n
  })


def _partition_rules(
  zp: ast.ZoneProgram, max_stage_instr: int
) -> list[tuple[int, int]]:
  """Partition rule indices into contiguous stage groups.

  Honors manual `chain` boundaries as hard cuts, then greedily closes a
  group before its accumulated instruction estimate would exceed
  `max_stage_instr`. Always yields at least one group (possibly empty
  when the zone has no rules — the parse stage still tail-calls a policy
  stage that only applies the default).
  """
  n = len(zp.rules)
  if n == 0:
    return [(0, 0)]
  forced = set(_effective_boundaries(zp))
  groups: list[tuple[int, int]] = []
  start = 0
  acc = 0
  for i, rule in enumerate(zp.rules):
    if i in forced and i > start:
      groups.append((start, i))
      start, acc = i, 0
    cost = RULE_INSTR + GEOIP_INSTR * _rule_geoip_calls(rule)
    # Cut before the group would exceed the instruction budget OR the
    # per-stage rule cap (whichever binds first), so no stage grows into
    # the clang stack-spill regime.
    over_instr = acc + cost > max_stage_instr
    over_rules = (i - start) >= MAX_RULES_PER_STAGE
    if (over_instr or over_rules) and i > start:
      groups.append((start, i))
      start, acc = i, 0
    acc += cost
  groups.append((start, n))
  return groups
