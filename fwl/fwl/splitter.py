"""Pipeline-split estimator + split-point calculator (v0.4 § 6.6).

The compiler decides whether a zone's program fits in a single BPF
program or must be split into a `bpf_tail_call()` pipeline. This module
holds that decision, kept separate from the emitter so the analyzer (for
diagnostics), the emitter (for code generation), and the runner (to
chain stages in BPF_PROG_TEST_RUN) all consume one authoritative plan.

## The numbers here are measured

They were not. The per-feature costs were roadmap estimates — 500
instructions per rule, 2,000 for the parse prelude, 3,000 per geoip
lookup — and every one of them was wrong by between fifteen and fifty
times. The consequence was not academic: a 2,500-rule policy was cut
into 41 stages, the kernel follows at most 33 tail calls, and the stages
holding the terminal verdict never ran. The box loaded it, reported
`xdp_attached: true`, and forwarded nothing. See
`f.planning/rig-evidence/ACL_SCALING_2026-08-23.md`.

Measured with clang 19, `-target bpf -O2 -g`, counting the `xdp`
section of the emitted object, on three-term rules
(`src_ip in <cidr> and proto == tcp and dst_port == N`):

| what                                   | instructions |
|----------------------------------------|--------------|
| a zone program with no rules            | 209          |
| one more rule, single-program form      | 22.0         |
| one more rule, split-stage form         | 10.35        |
| one more entry in an inline `cidr_list` | 3.43         |
| conntrack state lookup                  | 148          |
| one geoip() LPM helper                  | 18           |
| masquerade / NAT rewrite                | 1,169        |

The single-program figure is twice the split-stage one because the
unsplit form re-derives its guards per rule where a stage unpacks them
once from the scratch struct. That is why there are two per-rule
constants below and not an average of them.

## What actually binds

Three limits stack, and only the middle one was ever guarded:

  * **LLVM's signed 16-bit branch offset**, at the default `-mcpu`. A
    program or stage of about 32,767 instructions is where
    `error in backend: Branch target out of insn range` starts.
    Measured: 1,400 unsplit rules (31,066 insns) compiles and 1,500
    does not; 3,200 rules in a single stage (32,305) compiles and
    4,000 does not; 9,000 inline cidr entries (31,097) compiles and
    10,000 does not. Three different shapes, one number, exactly where
    a 16-bit offset predicts it. `-mcpu=v4` adds `gotol`, a 32-bit
    jump, and removes this entirely -- at the cost of needing kernel
    6.6 or newer.

  * **The verifier's jump-sequence limit**,
    `BPF_COMPLEXITY_LIMIT_JMP_SEQ` = 8,192. Measured on the rig: a
    10,000-rule single program compiles to 197,383 instructions under
    `-mcpu=v4` and is then refused with "the sequence of 8193 jumps is
    too complex", after `processed 49163 insns (limit 1000000)`. So the
    million-instruction limit is nowhere near binding and this one is.
    5,000 rules loads.

  * **`MAX_TAIL_CALL_CNT` = 33**, the depth the kernel will follow. Past
    it `bpf_tail_call` simply does not happen and the calling stage
    falls through -- the fail-open above.

The old `MAX_RULES_PER_STAGE = 64` was tuned against `RULE_INSTR = 500`,
and 64 x 500 = 32,000: it was the branch-range limit all along, wearing
a rule count as a disguise. With the real per-rule cost the same limit
allows about 3,200 rules in a stage, and the cap below is set well
under that.

## What this does NOT try to fix

Speed. 10,000 rules cannot be made fast in this form and it was
measured rather than assumed: 2,000 rules in 33 stages ran at 385,826
pps and 2,500 rules as one tail-call-free program under `-mcpu=v4` ran
at 193,116. Removing 32 tail calls made it SLOWER, because tail calls
are nearly free and the cost is the rules themselves at roughly a
nanosecond each. Raising the ceiling is a robustness fix: a policy of a
few thousand rules should work, and one past the ceiling should produce
a sentence rather than an LLVM crash dump. The answer for large rule
sets is a data structure -- 50,000 prefixes in an LPM trie cost 227
instructions and 99% of line rate -- not a longer chain.
"""
from __future__ import annotations
from dataclasses import dataclass

from . import ast

# --- measured costs -------------------------------------------------
#
# These are the raw measurements, kept separate from the constants the
# planner uses so a reader can see the safety factor rather than infer
# it, and so a test can assert the two have not drifted apart.
MEASURED_BASE_INSTR = 209
MEASURED_RULE_INSTR_SINGLE = 22.0
MEASURED_RULE_INSTR_STAGE = 10.35
MEASURED_CIDR_ENTRY_INSTR = 3.43
MEASURED_CONNTRACK_INSTR = 148
MEASURED_GEOIP_INSTR = 18
MEASURED_NAT_INSTR = 1169

# --- what the planner budgets with ----------------------------------
#
# Each is the measurement above rounded up. The margin is small on
# purpose: an estimate that is far too high does not fail safe, it
# splits a policy into stages the kernel will not follow, which is the
# defect this file was rewritten to remove.
PARSE_INSTR = 256
CONNTRACK_INSTR = 192
NAT_INSTR = 1408
GEOIP_INSTR = 32
# One inline `cidr_list` / list entry, expanded by the emitter into one
# more term of an unsplittable `||` chain. It gets a constant of its own
# because it is the only way a SINGLE rule can grow past what a stage
# holds, and a rule cannot be cut in half.
CIDR_ENTRY_INSTR = 4

# Per rule, in each of the two forms. `RULE_INSTR` keeps its name
# because that is what every caller says; it is the split-stage figure,
# which is the one the partitioner uses.
RULE_INSTR = 12
RULE_INSTR_SINGLE = 24

# LLVM emits a signed 16-bit branch offset unless told otherwise, so a
# jump can reach 32,767 instructions and no further. Measured from three
# directions (see the module docstring); they agree.
LLVM_BRANCH_RANGE_INSTR = 32_767

# The verifier's own ceiling on how long a chain of jumps it will
# explore, `BPF_COMPLEXITY_LIMIT_JMP_SEQ`. Unlike the branch range this
# one is per LOADED PROGRAM and cannot be assembled away.
JMP_SEQ_LIMIT = 8_192

# Split thresholds. A program strictly under BOTH stays single.
#
# Three quarters of the branch range, so an estimate that is a third low
# still assembles. At 24 instructions per rule that keeps roughly a
# thousand rules in a single program, and 1,400 was measured to compile.
INSTR_BUDGET = 24_000
STACK_BUDGET = 400

# The same budget for one stage of a pipeline. Stages are separate
# functions, so the branch range applies to each of them independently —
# which is why the split form reaches far higher rule counts than the
# unsplit one, and why splitting is the answer to a program that will
# not assemble rather than `-mcpu=v4`.
STAGE_INSTR_BUDGET = 24_000

# The BPF hard per-program limits the split defends against. A single
# stage is kept under these; they also bound the auto-split group size.
HARD_INSTR = 1_000_000
HARD_STACK = 512

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

# Rules per policy stage.
#
# 1,024 rules is about 10,800 instructions, a third of the branch range
# and three times under the 3,200-rule stage that was measured to be
# where clang stops. It is a cap on the group size, not the ceiling on
# the policy: with 32 policy stages available it would allow 32,768
# rules, and MAX_TIER1_RULES below is what actually stops the compile,
# for a reason that has nothing to do with stage sizing.
MAX_RULES_PER_STAGE = 1024

# The largest Tier 1 rule set this compiler will emit, and the number
# the refusal quotes.
#
# It is the verifier's jump-sequence limit, not a stage arithmetic. A
# policy of this size fits comfortably in nine stages; what it does NOT
# fit inside is `BPF_COMPLEXITY_LIMIT_JMP_SEQ`, measured on the rig at
# roughly 0.82 explored jumps per three-term rule (10,000 rules ->
# "the sequence of 8193 jumps is too complex"). Above this number there
# is no arrangement of the policy that is known to load, so the honest
# ceiling is the same for the split and unsplit forms.
#
# It was 2,048 -- (33 - 1) stages x 64 rules -- which was never a
# property of the kernel at all, only of two compiler constants that
# happened to multiply to the branch range.
MAX_TIER1_RULES = JMP_SEQ_LIMIT

# Where a rule set stops being a sensible way to write a policy, as
# opposed to stopping being expressible. Measured on the rig, IMIX,
# 10 GbE: 1,000 rules is 30% of line and 2,000 is 12%. Past this the
# compile succeeds and the operator is told what it will cost him.
ADVISORY_RULES = 2048

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


def rule_list_entries(rule: ast.Rule) -> int:
  """Inline list entries in this rule's condition, across all operands.

  Every one of them becomes another term of an `||` chain in the
  emitted C. That chain is inside ONE rule, so nothing downstream can
  cut it: a stage either holds the whole rule or the policy does not
  compile. This count is what makes that failure a sentence instead of
  an LLVM backend crash.
  """
  n = 0
  for node in _walk_cond(rule.condition):
    if not isinstance(node, ast.Comparison):
      continue
    items = getattr(node.operand, "items", None)
    if items is not None:
      n += len(items)
  return n


def rule_cost(rule: ast.Rule, *, single: bool = False) -> int:
  """Estimated instructions for one rule, in stage or single form.

  Public because the emitter needs it to name the rule that is too big
  for any stage, and a second copy of this arithmetic there would be a
  second place for it to be wrong.
  """
  per_rule = RULE_INSTR_SINGLE if single else RULE_INSTR
  return (per_rule
          + GEOIP_INSTR * _rule_geoip_calls(rule)
          + CIDR_ENTRY_INSTR * rule_list_entries(rule))


def oversized_rule(zp: ast.ZoneProgram) -> tuple[int, int] | None:
  """The first rule too large for any stage, as `(index, cost)`.

  A rule is the unit the splitter works in; there is no cut point
  inside one. So a rule whose own estimate exceeds a stage's budget is
  not a splitting problem, it is a policy that cannot be expressed in
  this form, and saying so is the whole job. The way to get here in
  practice is a long inline `cidr_list`: 10,000 of them was measured to
  fail as `error in backend: Branch target out of insn range`, which is
  not a message anyone can act on.
  """
  for i, rule in enumerate(zp.rules):
    cost = rule_cost(rule)
    if cost > STAGE_INSTR_BUDGET:
      return (i, cost)
  return None


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
    instr += rule_cost(rule, single=True)
  if zp.function is not None:
    # A Tier 2 body's instruction cost tracks its statement/condition
    # count; approximate one "rule" per statement.
    instr += RULE_INSTR_SINGLE * max(_count_stmts(zp.function.body), 1)

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
  `max_stage_instr` or its rule count would exceed
  `MAX_RULES_PER_STAGE`. Always yields at least one group (possibly
  empty when the zone has no rules — the parse stage still tail-calls a
  policy stage that only applies the default).

  The cut is against the instruction budget first because that is the
  limit that binds: a stage is a function, LLVM's branch offset is
  per function, and 32,767 instructions is where it stops. The rule cap
  is a second, blunter bound for the case where the estimate is wrong.
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
    cost = rule_cost(rule)
    over_instr = acc + cost > max_stage_instr
    over_rules = (i - start) >= MAX_RULES_PER_STAGE
    if (over_instr or over_rules) and i > start:
      groups.append((start, i))
      start, acc = i, 0
    acc += cost
  groups.append((start, n))
  return groups


def advisory(zp: ast.ZoneProgram) -> str | None:
  """What this rule count will cost, said before it is paid.

  Not a refusal. The policy compiles and loads; it is simply slow, and
  the operator has no way to discover that short of measuring the box.
  Measured on the rig, IMIX at 10 GbE: no rules is 98.6% of line, 1,000
  rules is 30.4%, 2,000 is 11.8%. The cost is the rules themselves at
  roughly a nanosecond each, so it is linear and it is not going to be
  optimised away — a longer chain is the wrong shape for a large policy,
  not a slow implementation of the right one.
  """
  n = len(zp.rules)
  if n <= ADVISORY_RULES:
    return None
  return (
    f"{n} rules. Measured on 10 GbE with IMIX traffic, 1,000 rules "
    f"runs at 30% of line rate and 2,000 at 12%, because every packet "
    f"walks the whole chain at about a nanosecond a rule. This will "
    f"compile and load (the ceiling is {MAX_TIER1_RULES}) and it will "
    f"be slow. A prefix table holds 50,000 entries in 227 instructions "
    f"at 99% of line; if most of these rules test the same field, that "
    f"is the shape they want."
  )
