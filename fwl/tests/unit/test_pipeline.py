"""Unit tests for v0.4 § 6.6 pipeline splitter.

Covers the estimator + split-point calculator (splitter.py), the `chain`
manual override, the multi-program split emitter (scratch struct,
prog_array, tail calls), and the single-vs-split behavioral-equivalence
engine. The real byte-identical proof runs on the kernel VM; where BPF
load is unavailable these tests assert both forms compile and the plan
is shaped correctly.
"""
import pytest

from fwl import (
  analyzer, bpf_runner, emitter, parser, pkt, runner, splitter,
)
from fwl.errors import FwlException


def _zp(text):
  return analyzer.analyze(parser.parse(text)).programs[0]


# --- estimator ------------------------------------------------------

def test_small_program_stays_single():
  plan = splitter.plan(_zp(
    "@xdp(eth0)\nallow if pkt.src_ip == 1.1.1.1\ndefault drop\n"
  ))
  assert plan.split is False
  assert "single" in plan.reason


def test_estimate_grows_with_features():
  plain = splitter.estimate(_zp("@xdp(eth0)\nallow if pkt.src_ip == 1.1.1.1\n"))
  heavy = splitter.estimate(_zp(
    "@xdp(eth0)\nallow if conntrack(pkt).state == established\n"
    "masquerade if pkt.src_ip == 10.0.0.1\n"
    "drop if pkt.src_ip in geoip(RU)\n"
  ))
  assert heavy.instructions > plain.instructions
  # conntrack + NAT push the stack estimate up.
  assert heavy.stack > plain.stack


def test_over_instruction_budget_splits():
  many = "@xdp(eth0)\n" + "".join(
    f"drop if pkt.src_ip == 10.0.0.{i}\n" for i in range(1, 12)
  ) + "default allow\n"
  # Force the budget low so the estimate exceeds it.
  plan = splitter.plan(_zp(many), instr_budget=1500, max_stage_instr=1500)
  assert plan.split is True
  rule_stages = [s for s in plan.stages if s.kind == "rules"]
  assert len(rule_stages) >= 2
  # Every rule is covered exactly once, in order, no gaps/overlaps.
  covered = []
  for s in rule_stages:
    covered.extend(range(*s.rule_range))
  assert covered == list(range(11))


# --- chain manual override ------------------------------------------

def test_chain_forces_split_at_boundary():
  zp = _zp(
    "@xdp(eth0)\nallow if pkt.src_ip == 1.1.1.1\n"
    "drop if pkt.src_ip == 2.2.2.2\nchain b\n"
    "allow if pkt.src_ip == 3.3.3.3\ndefault drop\n"
  )
  assert zp.chain_boundaries == (2,)
  plan = splitter.plan(zp)
  assert plan.split is True
  ranges = [s.rule_range for s in plan.stages if s.kind == "rules"]
  assert ranges == [(0, 2), (2, 3)]


def test_chain_in_tier2_rejected():
  with pytest.raises(FwlException, match="'chain' is a Tier 1 stage boundary"):
    analyzer.analyze(parser.parse(
      "@xdp(eth0)\nchain x\ndef m(pkt):\n  drop\n"
    ))


# --- split emitter --------------------------------------------------

def test_split_emits_scratch_prog_array_and_stages():
  c = emitter.emit(
    analyzer.analyze(parser.parse(
      "@xdp(eth0)\nallow if pkt.src_ip == 1.1.1.1\n"
      "chain b\ndrop if pkt.src_ip == 2.2.2.2\ndefault drop\n"
    ))
  )
  assert "struct fwl_meta {" in c
  assert "BPF_MAP_TYPE_PERCPU_ARRAY" in c and "fwl_scratch" in c
  assert "BPF_MAP_TYPE_PROG_ARRAY" in c and "fwl_stages" in c
  assert "int fwl_stage_0(struct xdp_md *ctx)" in c
  assert "int fwl_stage_1(struct xdp_md *ctx)" in c
  assert "int fwl_stage_2(struct xdp_md *ctx)" in c
  assert "bpf_tail_call(ctx, &fwl_stages, 1)" in c
  assert "int fwl_prog(" not in c  # split object has no single entry


def test_parse_stage_packs_policy_stage_unpacks():
  c = emitter.emit(
    analyzer.analyze(parser.parse(
      "@xdp(eth0)\nallow if pkt.src_ip == 1.1.1.1\ndefault drop\n"
    )),
    split=True,
  )
  stage0 = c.split("int fwl_stage_1")[0]
  stage1 = "int fwl_stage_1" + c.split("int fwl_stage_1")[1]
  assert "_m->src_ip = src_ip;" in stage0   # parse packs
  assert "__u32 src_ip = _m->src_ip;" in stage1  # policy unpacks


@pytest.mark.parametrize("src,split", [
  ("@xdp(eth0)\nallow if pkt.src_ip == 1.1.1.1\ndefault drop\n", True),
  ("@xdp(eth0)\ndef m(pkt):\n  if pkt.proto == tcp and pkt.dst_port == 22:\n"
   "    drop\n  allow\n", True),
  ("@xdp(eth0)\nallow if conntrack(pkt).state == established\nchain x\n"
   "drop if pkt.src_ip == 2.2.2.2\ndefault drop\n", None),
  ("@xdp(eth0)\nmasquerade if pkt.src_ip == 10.0.0.1\nchain o\n"
   "allow if pkt.proto == tcp and pkt.dst_port == 80\ndefault drop\n", None),
  ("@xdp(eth0)\ndrop if pkt.src_ip6 == 2001:db8::1\ndefault allow\n", True),
])
def test_split_forms_compile(src, split):
  c = emitter.emit(analyzer.analyze(parser.parse(src)), split=split)
  bpf_runner.check_compiles(c)  # raises on clang failure


def test_tier2_split_is_parse_plus_policy():
  plan = splitter.plan(
    _zp("@xdp(eth0)\ndef m(pkt):\n  drop\n"), force_split=True
  )
  kinds = [s.kind for s in plan.stages]
  assert kinds == ["parse", "policy"]


# --- equivalence engine (kernel-gated) ------------------------------

def _mk_case(source_fw, builder, expected="drop"):
  yaml = (
    'name: "t"\n'
    "source_fw: |\n" + "".join(f"  {ln}\n" for ln in source_fw.splitlines())
    + f"test_packet:\n  builder: {builder}\n"
    f"expected:\n  compiles: true\n  bpf_action: {expected}\n"
  )
  import tempfile
  import os
  fd, path = tempfile.mkstemp(suffix=".pkt")
  os.write(fd, yaml.encode())
  os.close(fd)
  return pkt.load(__import__("pathlib").Path(path))


def test_pipeline_equivalence_pass_or_skip():
  case = _mk_case(
    "@xdp(eth0)\nallow if pkt.src_ip == 1.1.1.1\n"
    "chain b\ndrop if pkt.proto == tcp and pkt.dst_port == 22\ndefault drop\n",
    'tcp(src_ip="1.2.3.4", dst_ip="9.9.9.9", dst_port=22)',
  )
  res = runner.pipeline_equivalence(case)
  # On a CAP_BPF kernel this asserts single==split; otherwise it must at
  # least confirm both forms compile (skip, not fail).
  assert res.status in ("pass", "skip"), res.detail
