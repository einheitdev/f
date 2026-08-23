"""How much policy fits, and what happens at the edge of it.

Three limits stack on a Tier 1 rule chain, and until 2026-08-23 the
compiler had a wrong estimate of one of them and no knowledge of the
other two:

  * LLVM's signed 16-bit branch offset, about 32,767 instructions per
    function, which arrives as `error in backend: Branch target out of
    insn range` -- a message that names nothing an operator can act on.
  * the verifier's `BPF_COMPLEXITY_LIMIT_JMP_SEQ`, 8,192 explored
    jumps, which is what actually bounds a rule set. The
    million-instruction limit is nowhere near it.
  * `MAX_TAIL_CALL_CNT`, 33, past which the chain silently stops being
    followed. That one is already guarded and its test lives in
    test_pipeline.py; this file is about the two above.

The measurements these tests assert against are in
`f.planning/rig-evidence/ACL_SCALING_2026-08-23.md` and in the module
docstring of `fwl/splitter.py`.
"""
import random

import pytest

from fwl import analyzer, emitter, parser, splitter
from fwl.errors import FwlException


def _rules_policy(count):
  """`count` three-term rules, the shape the rig measured."""
  lines = ["zone wan = [eth0]", "zone lan = [eth1]", "", "@xdp(wan)", ""]
  for i in range(count):
    a, b = (i // 254) % 250 + 1, i % 254 + 1
    lines.append(f"drop if pkt.src_ip in 10.{a}.{b}.0/24 "
                 f"and pkt.proto == tcp and pkt.dst_port == {1024 + i}")
  lines += ["redirect to lan", "", "@xdp(lan)", "", "default drop", ""]
  return "\n".join(lines)


def _cidr_policy(count):
  """One rule holding `count` scattered /24s inline.

  Scattered rather than contiguous on purpose: consecutive prefixes
  collapse into a single range comparison and measure nothing. This is
  the shape an operator produces by pasting a blocklist into a rule.
  """
  rng = random.Random(7)
  seen = set()
  items = []
  while len(items) < count:
    value = rng.randrange(1 << 24) << 8
    if value in seen:
      continue
    seen.add(value)
    items.append(f"{(value >> 24) & 255}.{(value >> 16) & 255}."
                 f"{(value >> 8) & 255}.0/24")
  return "\n".join([
    "zone wan = [eth0]", "zone lan = [eth1]", "", "@xdp(wan)", "",
    f"drop if pkt.src_ip in [{', '.join(items)}]",
    "redirect to lan", "", "@xdp(lan)", "", "default drop", ""])


def _zp(text):
  return analyzer.analyze(parser.parse(text)).programs[0]


# --- an inline list is one rule, and one rule cannot be split --------

def test_a_short_inline_list_is_ordinary():
  # The feature still works. This test exists so the bound below is
  # read as a bound and not as a ban.
  emitter.emit(analyzer.analyze(parser.parse(_cidr_policy(64))))


def test_a_list_that_fits_a_stage_still_compiles():
  entries = (splitter.STAGE_INSTR_BUDGET - splitter.RULE_INSTR) \
      // splitter.CIDR_ENTRY_INSTR - 10
  emitter.emit(analyzer.analyze(parser.parse(_cidr_policy(entries))))


def test_an_oversized_list_is_a_sentence_not_a_backend_crash():
  """Measured: 9,000 inline /24s assemble and 10,000 crash clang.

  The crash is `fatal error: error in backend: Branch target out of insn
  range`, printed by clang, on stderr, with the compiler's own exit
  status -- and `fwl compile` turned it into a failed build with no
  explanation attached to any rule. The refusal has to arrive before
  clang is reached and has to name the rule, the list and the limit.
  """
  with pytest.raises(FwlException) as caught:
    emitter.emit(analyzer.analyze(parser.parse(_cidr_policy(10_000))))
  message = caught.value.error.message
  assert caught.value.error.category == "codegen"
  assert "10000 entries" in message
  # The rule, so the operator knows which line to change.
  assert "rule 1" in message
  assert "line" in message
  # The limit, and why it is where it is.
  assert str(splitter.STAGE_INSTR_BUDGET) in message
  assert "branch offset" in message
  # And what to do instead, which is the whole point of the exercise:
  # a table does not grow the program.
  assert "table" in message


def test_the_oversized_rule_is_found_before_the_plan_is_built():
  """It is a property of one rule, and needs no split plan to see."""
  found = splitter.oversized_rule(_zp(_cidr_policy(10_000)))
  assert found is not None
  index, cost = found
  assert index == 0
  assert cost > splitter.STAGE_INSTR_BUDGET


def test_an_ordinary_policy_has_no_oversized_rule():
  assert splitter.oversized_rule(_zp(_rules_policy(500))) is None


def test_list_entries_are_counted_wherever_they_sit():
  # The count has to walk the whole condition, not just the first
  # comparison: a rule can carry more than one list.
  zp = _zp(
    "@xdp(eth0)\n"
    "drop if pkt.src_ip in [10.0.0.0/24, 10.0.1.0/24, 10.0.2.0/24] "
    "and pkt.dst_ip in [192.0.2.0/24, 198.51.100.0/24]\n"
    "default allow\n")
  assert splitter.rule_list_entries(zp.rules[0]) == 5


# --- the rule ceiling ------------------------------------------------

def test_the_ceiling_is_four_times_what_it_was():
  """2,048 was two wrong constants multiplied together.

  `(MAX_STAGES - 1) x MAX_RULES_PER_STAGE` with `MAX_RULES_PER_STAGE`
  chosen against `RULE_INSTR = 500`. Neither number described the
  kernel. The replacement is the verifier's own limit.
  """
  assert splitter.MAX_TIER1_RULES == 8192
  assert splitter.MAX_TIER1_RULES == 4 * 2048


def test_a_policy_at_the_ceiling_plans_and_emits():
  # 8,191 written rules plus the terminal `redirect to lan` is exactly
  # the ceiling. It must produce C, in a stage count the kernel will
  # follow, without an exception.
  program = analyzer.analyze(parser.parse(_rules_policy(8191)))
  zp = program.programs[0]
  assert len(zp.rules) == splitter.MAX_TIER1_RULES
  plan = splitter.plan(zp)
  assert plan.n_stages <= splitter.MAX_STAGES
  assert emitter.emit(program)


def test_one_rule_past_the_ceiling_is_refused():
  program = analyzer.analyze(parser.parse(_rules_policy(8192)))
  with pytest.raises(FwlException) as caught:
    emitter.emit(program)
  message = caught.value.error.message
  assert str(splitter.MAX_TIER1_RULES + 1) in message
  assert str(splitter.MAX_TIER1_RULES) in message
  assert "BPF_COMPLEXITY_LIMIT_JMP_SEQ" in message


# --- stage sizing ----------------------------------------------------

def test_the_stage_count_tracks_the_rule_count_not_a_bad_estimate():
  """The 41-stage defect, in the numbers it produced.

  A rule was estimated at 500 instructions against a measured 10.35, so
  a stage filled up 48 times too early. 2,500 rules became 41 stages
  against a kernel that follows 33, and the policy loaded and enforced
  nothing.
  """
  counts = {n: splitter.plan(_zp(_rules_policy(n))).n_stages
            for n in (1000, 2500, 5000, 8000)}
  assert counts[2500] <= 5, counts
  # Monotone, and bounded by the rule cap rather than by an estimate.
  assert counts[1000] <= counts[2500] <= counts[5000] <= counts[8000]
  for n, stages in counts.items():
    assert stages <= 2 + n // splitter.MAX_RULES_PER_STAGE, (n, stages)


def test_a_small_policy_still_stays_a_single_program():
  plan = splitter.plan(_zp(_rules_policy(100)))
  assert plan.split is False


def test_a_policy_splits_before_it_can_outrun_the_branch_range():
  """The regression the corrected estimate could have introduced.

  With a per-rule cost of 12 and the OLD half-million budget, a
  2,000-rule policy would have stayed a single program -- and a single
  program of 2,000 rules is 44,000 instructions, which is past LLVM's
  branch range and arrives as a backend crash. The single-vs-split
  budget had to come down with the per-rule cost, not just the
  per-rule cost.
  """
  for count in (1200, 2000, 4000):
    plan = splitter.plan(_zp(_rules_policy(count)))
    assert plan.split, count
  # And the point at which it switches is inside what was measured to
  # assemble unsplit: 1,400 rules is 31,066 instructions and compiles;
  # 1,500 does not.
  largest_single = splitter.INSTR_BUDGET // splitter.RULE_INSTR_SINGLE
  assert (largest_single * splitter.MEASURED_RULE_INSTR_SINGLE
          < splitter.LLVM_BRANCH_RANGE_INSTR)


# --- which instruction set the objects are built for -----------------

def test_an_ordinary_bundle_records_no_kernel_floor(tmp_path):
  """The default ISA loads anywhere, and most policies want it.

  A floor that is stated when it is not needed is a bundle refused on
  boxes that could run it. An estimate-driven version of this sat here
  first and did exactly that: a Tier 2 body of 1,200 branches estimates
  at 29,000 instructions and clang emits 161.
  """
  from fwl import cli
  program = analyzer.analyze(parser.parse(_rules_policy(300)))
  cli._emit_bundle_dir(program, tmp_path / "b")
  import json
  manifest = json.loads(
    (tmp_path / "b" / "manifest.json").read_text(encoding="utf-8"))
  assert manifest["bpf_isa"] is None
  assert manifest["min_kernel"] is None


def test_the_wider_jump_is_used_when_clang_says_it_needs_one(tmp_path):
  """Real clang, real failure, real retry.

  A 2,000-rule policy forced into a single program is about 44,000
  instructions, which is past LLVM's signed 16-bit branch offset. On
  the default ISA clang aborts with `fatal error: error in backend:
  Branch target out of insn range`; on `-mcpu=v4` the same source
  assembles, because v4 has a 32-bit `gotol`. This is the case the
  fallback exists for and the source is the emitter's own output, not
  something hand-written to provoke it.
  """
  from fwl import cli
  program = analyzer.analyze(parser.parse(_rules_policy(2000)))
  source = emitter.emit(program, split=False)
  with pytest.raises(Exception) as caught:
    cli._compile_one(source, tmp_path, "wide.bpf.o", "")
  assert "Branch target out of insn range" in str(
    caught.value.stderr.decode("utf-8", "replace"))
  assert cli._compile_one(source, tmp_path, "wide.bpf.o", "v4")
  assert (tmp_path / "wide.bpf.o").exists()


def test_an_ordinary_compile_failure_is_not_mistaken_for_it(tmp_path):
  """Only the branch range triggers the retry.

  Widening the instruction set in response to any compile error would
  stamp a kernel floor on a bundle whose real problem was a bug in the
  generated C -- and then hide that bug behind a second failed compile.
  """
  from fwl import cli
  assert cli._compile_one("this is not C\n", tmp_path, "x.bpf.o",
                          "") is False


def test_the_kernel_floor_is_stated_rather_than_assumed():
  from fwl import bpf_runner
  assert bpf_runner.BPF_ISA_MIN_KERNEL["v4"] == "6.6"


# --- the advisory ----------------------------------------------------

def test_a_large_but_legal_policy_is_warned_about_not_refused():
  """The number is knowable at compile time and unknowable otherwise.

  An operator who writes 4,000 rules gets a box at a few percent of
  line rate and nothing anywhere tells him why. The compiler knows.
  """
  advice = splitter.advisory(_zp(_rules_policy(4000)))
  assert advice is not None
  assert "4001 rules" in advice
  assert "%" in advice
  assert str(splitter.MAX_TIER1_RULES) in advice
  assert "table" in advice


def test_an_ordinary_policy_is_not_lectured():
  assert splitter.advisory(_zp(_rules_policy(50))) is None
  assert splitter.advisory(_zp(_rules_policy(
    splitter.ADVISORY_RULES - 2))) is None
