"""Unit tests for `rate_limit(..., scope=zone|global)` (v0.4 § 6.7).

Covers the parser surface, the bundle-wide slot allocation, the two map
shapes the emitter produces, the interpreter's model of the same
scopes, and the multi-zone aggregate warning.

The property that cannot be tested here is the one that needs several
objects loaded at once under one pin root — that a global bucket really
is one kernel map, and that traffic on one zone spends another zone's
budget. BPF_PROG_RUN loads a single object, so that half lives on
hardware in tests/system/hw/l8_08_rate_limit_scope.sh.
"""
import re

import pytest

from fwl import (
  analyzer, ast, bpf_runner, emitter, interpreter, parser, runner
)
from fwl.errors import FwlException
from fwl.interpreter import XdpAction

ZL = "zone a = [e0]\nzone b = [e1]\n"


# Two zones holding the SAME rule, at DIFFERENT rule indices (zone a's
# is index 0, zone b's index 2). The index difference is deliberate: a
# shared budget that only worked when the indices happened to agree
# would be the aliasing bug wearing a feature's name.
def _two_zone_src(scope: str) -> str:
  suffix = f", scope={scope}" if scope else ""
  return (
    ZL
    + "\n@xdp(a)\n"
    + f"drop if pkt.src_ip in 10.0.0.0/8 "
      f"limited by rate_limit(5, per=src_ip{suffix})\n"
    + "default allow\n"
    + "\n@xdp(b)\n"
    + "count b_one\ncount b_two\n"
    + f"drop if pkt.src_ip in 10.0.0.0/8 "
      f"limited by rate_limit(5, per=src_ip{suffix})\n"
    + "default allow\n"
  )


def _analyze(text):
  return analyzer.analyze(parser.parse(text))


def _zone(program, name):
  """The single-zone Program view the interpreter evaluates."""
  zp = next(z for z in program.programs if z.zone_name == name)
  return ast.Program(programs=[zp], zones=program.zones)


def _pkt(builder):
  from fwl import pkt as pktmod
  return pktmod.build_packet(pktmod.parse_builder(builder)).fields


P_10_0_0_1 = 'udp(src_ip="10.0.0.1", dst_port=9)'


# --------------------------------------------------------------------
class TestParser:
  def test_scope_defaults_to_zone_and_is_not_explicit(self):
    p = parser.parse(
      "@xdp(e0)\ndrop limited by rate_limit(5, per=src_ip)\n"
    )
    mod = p.programs[0].rules[0].modifier
    assert mod.scope is ast.RlScope.ZONE
    assert mod.scope_explicit is False

  def test_scope_zone_explicit(self):
    p = parser.parse(
      "@xdp(e0)\ndrop limited by rate_limit(5, per=src_ip, scope=zone)\n"
    )
    mod = p.programs[0].rules[0].modifier
    assert mod.scope is ast.RlScope.ZONE
    assert mod.scope_explicit is True

  def test_scope_global(self):
    p = parser.parse(
      "@xdp(e0)\n"
      "drop limited by rate_limit(5, per=src_ip, scope=global)\n"
    )
    mod = p.programs[0].rules[0].modifier
    assert mod.scope is ast.RlScope.GLOBAL
    assert mod.scope_explicit is True

  def test_bad_scope_value_names_the_two_valid_ones(self):
    with pytest.raises(FwlException) as e:
      parser.parse(
        "@xdp(e0)\n"
        "drop limited by rate_limit(5, per=src_ip, scope=bundle)\n"
      )
    assert "scope= must be zone or global" in e.value.error.message
    assert e.value.error.span is not None

  def test_global_is_not_a_reserved_word(self):
    # Making `global` a keyword would silently break any policy using
    # it as a name. It is only a scope value.
    p = _analyze(
      "zone global = [e0]\n@xdp(global)\ncount global\nallow\n"
    )
    assert p.programs[0].zone_name == "global"

  def test_scope_is_not_a_reserved_word(self):
    p = _analyze("@xdp(e0)\ncount scope_hits\nallow\n")
    assert p.programs[0].rules[0].counter_name == "scope_hits"

  def test_every_per_field_accepts_scope(self):
    for field in ("src_ip", "dst_ip", "src_port", "dst_port"):
      guard = (
        "pkt.proto == tcp and " if field.endswith("port") else ""
      )
      cond = f"if {guard}pkt.src_ip in 10.0.0.0/8 " if guard else ""
      src = (
        f"@xdp(e0)\ndrop {cond}"
        f"limited by rate_limit(5, per={field}, scope=global)\n"
        "allow\n"
      )
      mod = _analyze(src).programs[0].rules[0].modifier
      assert mod.per_field == field
      assert mod.scope is ast.RlScope.GLOBAL


# --------------------------------------------------------------------
class TestSlotAllocation:
  def test_zone_scope_gets_no_slot(self):
    p = _analyze(_two_zone_src("zone"))
    slots = [r.modifier.global_slot
             for _z, r in analyzer._rate_limit_rules(p)]
    assert slots == [-1, -1]

  def test_same_rule_in_two_zones_shares_one_slot(self):
    p = _analyze(_two_zone_src("global"))
    slots = [r.modifier.global_slot
             for _z, r in analyzer._rate_limit_rules(p)]
    assert slots == [0, 0]

  def test_slot_is_not_the_rule_index(self):
    # zone a's rule is index 0, zone b's is index 2. If the slot were
    # positional they would not share, and if the map were named by the
    # index they would collide with unrelated rules.
    p = _analyze(_two_zone_src("global"))
    a = _zone(p, "a").rules
    b = _zone(p, "b").rules
    assert [i for i, r in enumerate(a) if r.modifier] == [0]
    assert [i for i, r in enumerate(b) if r.modifier] == [2]

  def test_different_rules_get_different_slots(self):
    p = _analyze(
      ZL + "\n@xdp(a)\n"
      "drop if pkt.src_ip in 10.0.0.0/8 "
      "limited by rate_limit(5, per=src_ip, scope=global)\n"
      "drop if pkt.src_ip in 10.0.0.0/8 "
      "limited by rate_limit(6, per=src_ip, scope=global)\n"
      "drop if pkt.src_ip in 192.168.0.0/16 "
      "limited by rate_limit(5, per=src_ip, scope=global)\n"
      "default allow\n"
      "\n@xdp(b)\nallow\n"
    )
    slots = [r.modifier.global_slot
             for _z, r in analyzer._rate_limit_rules(p)]
    # Different threshold and different condition are different rules.
    assert slots == [0, 1, 2]

  def test_scope_zone_and_scope_global_never_share(self):
    p = _analyze(
      ZL + "\n@xdp(a)\n"
      "drop limited by rate_limit(5, per=src_ip, scope=global)\n"
      "default allow\n"
      "\n@xdp(b)\n"
      "drop limited by rate_limit(5, per=src_ip, scope=zone)\n"
      "default allow\n"
    )
    by_zone = {z: r.modifier for z, r in analyzer._rate_limit_rules(p)}
    assert by_zone["a"].global_slot == 0
    assert by_zone["b"].global_slot == -1

  def test_reanalysis_is_stable(self):
    # analyze() mutates the AST; running it twice must not renumber.
    p = _analyze(_two_zone_src("global"))
    first = [r.modifier.global_slot
             for _z, r in analyzer._rate_limit_rules(p)]
    analyzer.analyze(p)
    second = [r.modifier.global_slot
              for _z, r in analyzer._rate_limit_rules(p)]
    assert first == second == [0, 0]


# --------------------------------------------------------------------
class TestWarning:
  def test_implicit_scope_across_zones_warns_with_aggregate(self):
    p = _analyze(
      "zone a = [e0]\nzone b = [e1]\nzone c = [e2]\n"
      "\n@xdp(a)\ndrop limited by rate_limit(1000, per=src_ip)\nallow\n"
      "\n@xdp(b)\ndrop limited by rate_limit(1000, per=src_ip)\nallow\n"
      "\n@xdp(c)\ndrop limited by rate_limit(1000, per=src_ip)\nallow\n"
    )
    assert len(p.warnings) == 1
    text = p.warnings[0].format()
    assert "3 zones" in text
    assert "a, b, c" in text
    assert "3000/s" in text
    assert p.warnings[0].span is not None

  def test_single_zone_does_not_warn(self):
    p = _analyze(
      "@xdp(e0)\ndrop limited by rate_limit(1000, per=src_ip)\nallow\n"
    )
    assert p.warnings == []

  def test_explicit_zone_scope_does_not_warn(self):
    p = _analyze(_two_zone_src("zone"))
    assert p.warnings == []

  def test_global_scope_does_not_warn(self):
    p = _analyze(_two_zone_src("global"))
    assert p.warnings == []

  def test_one_explicit_copy_silences_the_group(self):
    # The author has clearly seen the knob; do not nag about the rule.
    p = _analyze(
      ZL
      + "\n@xdp(a)\ndrop limited by rate_limit(9, per=src_ip)\nallow\n"
      + "\n@xdp(b)\n"
        "drop limited by rate_limit(9, per=src_ip, scope=zone)\nallow\n"
    )
    assert p.warnings == []

  def test_different_rules_in_different_zones_do_not_warn(self):
    # Two DIFFERENT rate limits, one per zone: no single rule reaches
    # more than one zone, so there is no aggregate to report.
    p = _analyze(
      ZL
      + "\n@xdp(a)\ndrop limited by rate_limit(10, per=src_ip)\nallow\n"
      + "\n@xdp(b)\ndrop limited by rate_limit(20, per=src_ip)\nallow\n"
    )
    assert p.warnings == []

  def test_warnings_do_not_accumulate_across_analyses(self):
    p = _analyze(
      ZL
      + "\n@xdp(a)\ndrop limited by rate_limit(4, per=src_ip)\nallow\n"
      + "\n@xdp(b)\ndrop limited by rate_limit(4, per=src_ip)\nallow\n"
    )
    analyzer.analyze(p)
    assert len(p.warnings) == 1

  def test_warning_is_not_fatal(self):
    # A warning must never stop a compile; the bundle still emits.
    p = _analyze(
      ZL
      + "\n@xdp(a)\ndrop limited by rate_limit(4, per=src_ip)\nallow\n"
      + "\n@xdp(b)\ndrop limited by rate_limit(4, per=src_ip)\nallow\n"
    )
    files = emitter.emit_bundle(p)
    assert "a.bpf.c" in files and "b.bpf.c" in files


# --------------------------------------------------------------------
def _map_decls(src: str) -> dict[str, str]:
  """map name -> declaration body, for every map in one zone source."""
  return {
    m.group(2): m.group(1)
    for m in re.finditer(
      r"struct \{(.*?)\}\s*(\w+) SEC\(\"\.maps\"\);", src, re.S)
  }


class TestEmitter:
  def test_zone_scope_map_is_zone_qualified_and_unpinned(self):
    files = emitter.emit_bundle(_analyze(_two_zone_src("zone")))
    a, b = _map_decls(files["a.bpf.c"]), _map_decls(files["b.bpf.c"])
    assert "fwl_rl_a_0" in a
    assert "fwl_rl_b_2" in b
    assert "LIBBPF_PIN_BY_NAME" not in a["fwl_rl_a_0"]
    assert "LIBBPF_PIN_BY_NAME" not in b["fwl_rl_b_2"]

  def test_global_scope_map_is_one_pinned_name_in_both_objects(self):
    files = emitter.emit_bundle(_analyze(_two_zone_src("global")))
    a, b = _map_decls(files["a.bpf.c"]), _map_decls(files["b.bpf.c"])
    assert "fwl_rl_g0" in a and "fwl_rl_g0" in b
    assert "LIBBPF_PIN_BY_NAME" in a["fwl_rl_g0"]
    assert "LIBBPF_PIN_BY_NAME" in b["fwl_rl_g0"]
    # Byte-identical declarations. libbpf validates the definition when
    # it reuses a pin: any difference is -EINVAL at load.
    assert a["fwl_rl_g0"] == b["fwl_rl_g0"]

  def test_global_map_survives_the_private_map_rewriter(self):
    files = emitter.emit_bundle(_analyze(_two_zone_src("global")))
    for name in ("a.bpf.c", "b.bpf.c"):
      assert "fwl_rl_a_" not in files[name]
      assert "fwl_rl_b_" not in files[name]

  def test_max_entries_does_not_come_from_a_zone_rule_count(self):
    # The trap in one assertion: two zones whose rule counts, counter
    # counts and rate-limit-rule counts all differ still declare the
    # shared map identically. A size derived from `len(zone.rules)`
    # would make the second object fail to load with -EINVAL.
    prog = _analyze(
      ZL + "\n@xdp(a)\n"
      "drop limited by rate_limit(5, per=src_ip, scope=global)\n"
      "default allow\n"
      "\n@xdp(b)\n"
      "count b1\ncount b2\ncount b3\n"
      "log(sample=4) if pkt.proto == udp\n"
      "drop if pkt.proto == icmp\n"
      "drop limited by rate_limit(5, per=src_ip, scope=global)\n"
      "default allow\n"
    )
    files = emitter.emit_bundle(prog)
    a, b = _map_decls(files["a.bpf.c"]), _map_decls(files["b.bpf.c"])
    assert len(prog.programs[0].rules) != len(prog.programs[1].rules)
    assert a["fwl_rl_g0"] == b["fwl_rl_g0"]
    assert "max_entries, 4096" in a["fwl_rl_g0"]

  def test_rules_sharing_a_slot_declare_the_map_once(self):
    # Two identical rules inside ONE zone share a slot; emitting the
    # declaration twice would not compile.
    prog = _analyze(
      "@xdp(e0)\n"
      "count seen\n"
      "drop limited by rate_limit(5, per=src_ip, scope=global)\n"
      "count seen2\n"
      "drop limited by rate_limit(5, per=src_ip, scope=global)\n"
      "default allow\n"
    )
    src = emitter.emit(prog)
    assert src.count("} fwl_rl_g0 SEC") == 1
    bpf_runner.check_compiles(src)

  def test_single_object_path_emits_the_global_name_unpinned(self):
    src = emitter.emit(_analyze(
      "@xdp(e0)\n"
      "drop limited by rate_limit(5, per=src_ip, scope=global)\n"
      "default allow\n"
    ))
    decls = _map_decls(src)
    assert "fwl_rl_g0" in decls
    assert "LIBBPF_PIN_BY_NAME" not in decls["fwl_rl_g0"]

  def test_both_scopes_compile(self):
    for scope in ("zone", "global"):
      files = emitter.emit_bundle(_analyze(_two_zone_src(scope)))
      for name, src in files.items():
        if name.endswith(".bpf.c"):
          bpf_runner.check_compiles(src)

  def test_scope_does_not_change_the_gate_arithmetic(self):
    # Scope selects the map and nothing else: the firing predicate,
    # window and update must be untouched, or `scope=` would quietly
    # change the limit as well as its reach.
    z = emitter.emit(_analyze(
      "@xdp(e0)\ndrop limited by rate_limit(5, per=src_ip)\nallow\n"
    ))
    g = emitter.emit(_analyze(
      "@xdp(e0)\n"
      "drop limited by rate_limit(5, per=src_ip, scope=global)\n"
      "allow\n"
    ))
    assert z.replace("fwl_rl_map_0", "X") == g.replace("fwl_rl_g0", "X")


# --------------------------------------------------------------------
class TestInterpreter:
  def test_state_key_follows_scope(self):
    p = _analyze(_two_zone_src("global"))
    mod = _zone(p, "b").rules[2].modifier
    assert interpreter.rl_state_key(mod, 2) == ("global", 0)
    z = _analyze(_two_zone_src("zone"))
    zmod = _zone(z, "b").rules[2].modifier
    assert interpreter.rl_state_key(zmod, 2) == 2

  def test_global_budget_is_shared_by_both_zones(self):
    p = _analyze(_two_zone_src("global"))
    spent = {("global", 0): {"10.0.0.1": 9}}
    for zone in ("a", "b"):
      assert interpreter.evaluate(
        _zone(p, zone), _pkt(P_10_0_0_1), spent
      ) is XdpAction.DROP

  def test_zone_budget_is_not_shared(self):
    p = _analyze(_two_zone_src("zone"))
    # Zone a's rate-limit rule is index 0, zone b's is index 2. A
    # budget spent at zone a's rule leaves zone b's rule untouched.
    spent_a = {0: {"10.0.0.1": 9}}
    assert interpreter.evaluate(
      _zone(p, "a"), _pkt(P_10_0_0_1), spent_a
    ) is XdpAction.DROP
    assert interpreter.evaluate(
      _zone(p, "b"), _pkt(P_10_0_0_1), spent_a
    ) is XdpAction.PASS
    # ...and the converse, so the test is not passing on an index that
    # simply does not exist in zone b.
    spent_b = {2: {"10.0.0.1": 9}}
    assert interpreter.evaluate(
      _zone(p, "b"), _pkt(P_10_0_0_1), spent_b
    ) is XdpAction.DROP
    assert interpreter.evaluate(
      _zone(p, "a"), _pkt(P_10_0_0_1), spent_b
    ) is XdpAction.PASS

  def test_rule_index_seed_reaches_the_global_slot(self):
    # A .pkt can only name a rule index. Under global scope that seed
    # has to land on the shared slot, or the interpreter would ignore
    # a seed the BPF oracle honours.
    p = _analyze(_two_zone_src("global"))
    assert interpreter.evaluate(
      _zone(p, "a"), _pkt(P_10_0_0_1), {0: {"10.0.0.1": 9}}
    ) is XdpAction.DROP
    assert interpreter.evaluate(
      _zone(p, "b"), _pkt(P_10_0_0_1), {2: {"10.0.0.1": 9}}
    ) is XdpAction.DROP

  def test_under_threshold_still_passes_under_both_scopes(self):
    for scope in ("zone", "global"):
      p = _analyze(_two_zone_src(scope))
      key = ("global", 0) if scope == "global" else 0
      assert interpreter.evaluate(
        _zone(p, "a"), _pkt(P_10_0_0_1), {key: {"10.0.0.1": 4}}
      ) is XdpAction.PASS

  def test_per_field_still_selects_the_bucket_under_global_scope(self):
    # scope and per= compose: the slot picks the map, per= picks the
    # key inside it. A different source IP has its own budget.
    p = _analyze(_two_zone_src("global"))
    spent = {("global", 0): {"10.0.0.1": 9}}
    other = 'udp(src_ip="10.0.0.2", dst_port=9)'
    assert interpreter.evaluate(
      _zone(p, "a"), _pkt(other), spent
    ) is XdpAction.PASS

  def test_per_dst_port_composes_with_global_scope(self):
    p = _analyze(
      ZL + "\n@xdp(a)\n"
      "drop if pkt.proto == udp and pkt.dst_port == 9 "
      "limited by rate_limit(5, per=dst_port, scope=global)\n"
      "default allow\n"
      "\n@xdp(b)\n"
      "count b1\n"
      "drop if pkt.proto == udp and pkt.dst_port == 9 "
      "limited by rate_limit(5, per=dst_port, scope=global)\n"
      "default allow\n"
    )
    spent = {("global", 0): {9: 9}}
    for zone in ("a", "b"):
      assert interpreter.evaluate(
        _zone(p, zone), _pkt(P_10_0_0_1), spent
      ) is XdpAction.DROP


# --------------------------------------------------------------------
class TestRunnerSeeding:
  def test_map_init_uses_the_map_the_program_reads(self):
    prog = _analyze(
      "@xdp(e0)\n"
      "count seen\n"
      "drop limited by rate_limit(5, per=src_ip, scope=global)\n"
      "default allow\n"
    )
    init = runner._build_map_init(prog, {1: {"10.0.0.1": 9}})
    assert list(init) == ["fwl_rl_g0"]
    assert "fwl_rl_g0" in emitter.emit(prog)

  def test_zone_scope_seeding_is_unchanged(self):
    prog = _analyze(
      "@xdp(e0)\n"
      "count seen\n"
      "drop limited by rate_limit(5, per=src_ip)\n"
      "default allow\n"
    )
    init = runner._build_map_init(prog, {1: {"10.0.0.1": 9}})
    assert list(init) == ["fwl_rl_map_1"]
