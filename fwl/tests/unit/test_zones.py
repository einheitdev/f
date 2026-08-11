"""Unit tests for v0.4 zones, redirect, and pkt.zone (FWL § 6.1-6.4).

Covers the parser/analyzer/emitter/interpreter surfaces added for zone
declarations, per-zone @xdp blocks, the `redirect to <zone>` action,
and the `pkt.zone` compile-time constant.
"""
import re

import pytest

from fwl import analyzer, ast, bpf_runner, emitter, interpreter, parser, pkt
from fwl.errors import FwlException
from fwl.interpreter import XdpAction

WL = "zone wan = [wan0]\nzone lan = [lan0, lan1]\n"


def _parse(text):
  return parser.parse(text)


def _analyze(text):
  return analyzer.analyze(parser.parse(text))


def _emit(text):
  return emitter.emit(_analyze(text))


def _pkt(builder):
  return pkt.build_packet(pkt.parse_builder(builder)).fields


def _run(text, builder, ingress=None, ct_seed=None):
  prog = _analyze(text)
  if ingress is not None:
    prog = next(
      ast.Program(programs=[zp], zones=prog.zones)
      for zp in prog.programs if zp.zone_name == ingress
    )
  ct = interpreter.ConntrackTable(ct_seed) if ct_seed else None
  return interpreter.evaluate_full(prog, _pkt(builder), conntrack=ct)


# --------------------------------------------------------------------
class TestParser:
  def test_zone_decls_parsed(self):
    p = _parse(WL + "@xdp(lan)\nallow\n")
    assert [(z.name, z.interfaces) for z in p.zones] == [
      ("wan", ("wan0",)), ("lan", ("lan0", "lan1")),
    ]

  def test_multiple_xdp_blocks(self):
    p = _parse(WL + "@xdp(wan)\ndrop\n@xdp(lan)\nallow\n")
    assert len(p.programs) == 2
    assert [zp.zone_name for zp in p.programs] == ["wan", "lan"]

  def test_redirect_tier1_carries_zone(self):
    p = _parse(WL + "@xdp(lan)\nredirect to wan\n")
    rule = p.programs[0].rules[0]
    assert rule.action == ast.Action.REDIRECT
    assert rule.redirect_zone == "wan"

  def test_redirect_tier2_carries_zone(self):
    p = _parse(WL + "@xdp(lan)\ndef f(pkt):\n  redirect to wan\n")
    stmt = p.programs[0].function.body[0]
    assert stmt.action == ast.Action.REDIRECT
    assert stmt.redirect_zone == "wan"

  def test_pkt_zone_eq_parses(self):
    p = _parse(WL + "@xdp(lan)\nallow if pkt.zone == lan\ndrop\n")
    cond = p.programs[0].rules[0].condition
    assert isinstance(cond, ast.ZoneCompare)
    assert cond.op == "==" and cond.zones == ("lan",)

  def test_pkt_zone_in_parses(self):
    p = _parse(WL + "@xdp(lan)\nallow if pkt.zone in [lan, wan]\ndrop\n")
    cond = p.programs[0].rules[0].condition
    assert cond.op == "in" and cond.zones == ("lan", "wan")

  def test_default_redirect_is_syntax_error(self):
    with pytest.raises(FwlException):
      _parse(WL + "@xdp(lan)\nallow\ndefault redirect to wan\n")

  def test_zone_keyword_not_reserved_prefix(self):
    # `zoned` / `redirected` / `tomorrow` still lex as identifiers.
    p = _parse("@xdp(eth0)\ncount zoned\nallow\n")
    assert p.programs[0].rules[0].counter_name == "zoned"

  def test_empty_zone_parses_for_semantic_error(self):
    # Grammar admits []; the analyzer reports the typed error.
    p = _parse("zone wan = []\n@xdp(wan)\nallow\n")
    assert p.zones[0].interfaces == ()


# --------------------------------------------------------------------
class TestAnalyzerZoneDecls:
  def test_empty_zone_rejected(self):
    with pytest.raises(FwlException) as e:
      _analyze("zone wan = []\n@xdp(wan)\nallow\n")
    assert "empty" in e.value.error.message

  def test_duplicate_zone_name_rejected(self):
    with pytest.raises(FwlException) as e:
      _analyze("zone w = [a]\nzone w = [b]\n@xdp(w)\nallow\n")
    assert "duplicate" in e.value.error.message

  def test_overlapping_interface_rejected(self):
    with pytest.raises(FwlException) as e:
      _analyze("zone w = [e0]\nzone l = [e0]\n@xdp(w)\nallow\n")
    assert "one zone" in e.value.error.message

  def test_xdp_undeclared_zone_rejected(self):
    with pytest.raises(FwlException) as e:
      _analyze("zone w = [w0]\n@xdp(dmz)\nallow\n")
    assert "not a declared zone" in e.value.error.message

  def test_duplicate_xdp_for_zone_rejected(self):
    with pytest.raises(FwlException) as e:
      _analyze(WL + "@xdp(lan)\nallow\n@xdp(lan)\ndrop\n")
    assert "more than one @xdp" in e.value.error.message

  def test_zone_declared_without_xdp_is_ok(self):
    # A redirect target need not have its own @xdp block.
    _analyze("zone w=[w0]\nzone l=[l0]\n@xdp(l)\nredirect to w\n")


class TestAnalyzerRedirect:
  def test_redirect_unknown_zone_rejected(self):
    with pytest.raises(FwlException) as e:
      _analyze("zone w=[w0]\n@xdp(w)\nredirect to dmz\n")
    assert "undeclared zone" in e.value.error.message

  def test_redirect_without_zones_rejected(self):
    with pytest.raises(FwlException) as e:
      _analyze("@xdp(eth0)\nredirect to wan\n")
    assert "requires zone declarations" in e.value.error.message

  def test_redirect_tier2_unknown_zone_rejected(self):
    with pytest.raises(FwlException):
      _analyze(WL + "@xdp(lan)\ndef f(pkt):\n  redirect to dmz\n")


class TestAnalyzerPktZone:
  def test_pkt_zone_undeclared_rejected(self):
    with pytest.raises(FwlException) as e:
      _analyze(WL + "@xdp(lan)\nallow if pkt.zone == dmz\ndrop\n")
    assert "undeclared zone" in e.value.error.message

  def test_pkt_zone_ordered_op_rejected(self):
    with pytest.raises(FwlException) as e:
      _analyze(WL + "@xdp(lan)\nallow if pkt.zone < wan\ndrop\n")
    assert "==" in e.value.error.message

  def test_pkt_zone_without_zones_rejected(self):
    with pytest.raises(FwlException) as e:
      _analyze("@xdp(eth0)\nallow if pkt.zone == eth0\ndrop\n")
    assert "no zones" in e.value.error.message

  def test_pkt_zone_in_list_ok(self):
    _analyze("zone w=[w0]\nzone l=[l0]\n@xdp(l)\n"
             "allow if pkt.zone in [l, w]\ndrop\n")


# --------------------------------------------------------------------
class TestEmitter:
  def test_redirect_emits_bpf_redirect_map(self):
    c = _emit(WL + "@xdp(lan)\nredirect to wan\n")
    assert "bpf_redirect_map(&fwl_devmap_wan, 0, 0)" in c
    assert "fwl_devmap_wan SEC(\".maps\")" in c
    assert "BPF_MAP_TYPE_DEVMAP" in c

  def test_redirect_not_a_pass_stub(self):
    # Guard against a regression to a stubbed XDP_PASS return.
    c = _emit(WL + "@xdp(lan)\nredirect to wan if pkt.proto == tcp\ndrop\n")
    assert "bpf_redirect_map" in c

  def test_pkt_zone_folds_true(self):
    c = _emit(WL + "@xdp(lan)\nallow if pkt.zone == lan\ndrop\n")
    assert "if (1)" in c

  def test_pkt_zone_folds_false(self):
    c = _emit(WL + "@xdp(lan)\nallow if pkt.zone == wan\ndrop\n")
    assert "if (0)" in c

  def test_redirect_programs_compile(self):
    for src in (
      WL + "@xdp(lan)\nredirect to wan\n",
      WL + "@xdp(lan)\nredirect to wan if pkt.proto == tcp and "
      "pkt.dst_port == 80\ndrop\n",
      WL + "@xdp(lan)\ndef f(pkt):\n  if pkt.zone == lan:\n"
      "    redirect to wan\n  drop\n",
    ):
      bpf_runner.compile_c(_emit(src))  # raises on failure

  def test_bundle_one_file_per_zone(self):
    prog = _analyze(WL + "@xdp(wan)\ndrop\n@xdp(lan)\nredirect to wan\n")
    files = emitter.emit_bundle(prog)
    assert set(files) == {"wan.bpf.c", "lan.bpf.c", "fwl_shared.h"}

  def test_bundle_pins_conntrack(self):
    prog = _analyze(
      WL + "@xdp(wan)\nallow if conntrack(pkt).state == established\ndrop\n"
      "@xdp(lan)\nredirect to wan\n"
    )
    files = emitter.emit_bundle(prog)
    assert "LIBBPF_PIN_BY_NAME" in files["wan.bpf.c"]
    # The pinned map is the shared conntrack state.
    assert "} conntrack SEC" in files["wan.bpf.c"]

  def test_bundle_zone_private_maps_are_zone_qualified(self):
    # Two zones with DIFFERENT counter sets: a bundle-global pinned
    # `fwl_counters` would fail to load (parameter mismatch reusing
    # the pin) or cross-wire slots. Private maps carry the zone name.
    prog = _analyze(
      WL + "@xdp(wan)\ncount wan_a\ncount wan_b\ndrop\n"
      "@xdp(lan)\ncount lan_only\nredirect to wan\n"
    )
    files = emitter.emit_bundle(prog)
    assert "fwl_counters_wan" in files["wan.bpf.c"]
    assert "fwl_counters_lan" in files["lan.bpf.c"]
    assert "fwl_counters SEC" not in files["wan.bpf.c"]
    assert "fwl_counters SEC" not in files["lan.bpf.c"]

  def test_bundle_log_sample_map_is_zone_qualified(self):
    # `fwl_log_sample` is sized len(zone.rules) and indexed by the
    # zone's own rule index. Sharing it bundle-wide breaks both ways:
    # unequal rule counts fail to load, equal rule counts silently
    # cross-advance each other's sampling phase.
    prog = _analyze(
      WL + "@xdp(wan)\nlog(sample=4) if pkt.proto == udp\n"
      "log(sample=4) if pkt.proto == tcp\ndrop\n"
      "@xdp(lan)\nlog(sample=4) if pkt.proto == udp\nallow\n"
    )
    files = emitter.emit_bundle(prog)
    assert "fwl_log_sample_wan" in files["wan.bpf.c"]
    assert "fwl_log_sample_lan" in files["lan.bpf.c"]
    assert "fwl_log_sample SEC" not in files["wan.bpf.c"]
    assert "fwl_log_sample SEC" not in files["lan.bpf.c"]

  def test_bundle_pinned_maps_agree_on_max_entries(self):
    # The invariant behind every zone-qualified name, stated once and
    # checked structurally so a NEW map cannot reintroduce the bug:
    # any map pinned under a name shared by two zone objects must be
    # declared identically in both. libbpf validates the definition
    # when reusing a pin, so a divergence is either -EINVAL at load
    # (unequal sizes) or silent cross-zone aliasing (equal sizes).
    # Every construct that emits a map appears in at least one zone.
    prog = _analyze(
      "zone wan = [wan0]\nzone lan = [lan0]\n"
      "@xdp(wan)\n"
      "count wan_a\ncount wan_b\n"
      "log(sample=4) if pkt.proto == udp\n"
      "drop if pkt.src_ip in geoip(RU)\n"
      "drop limited by rate_limit(10, per=src_ip)\n"
      "drop limited by rate_limit(7, per=src_ip, scope=global)\n"
      "allow if conntrack(pkt).state == established\n"
      "masquerade\ndrop\n"
      "@xdp(lan)\n"
      "count lan_only\n"
      "log(sample=8) if pkt.proto == tcp\n"
      "drop if pkt.src_ip in geoip(CN)\n"
      "drop limited by rate_limit(7, per=src_ip, scope=global)\n"
      "redirect to wan\n"
    )
    files = emitter.emit_bundle(prog)
    # map name -> set of the distinct declaration bodies seen for it
    pinned: dict[str, set[str]] = {}
    for name, src in files.items():
      if not name.endswith(".bpf.c"):
        continue
      for m in re.finditer(
          r"struct \{(.*?)\}\s*(\w+) SEC\(\"\.maps\"\);", src, re.S):
        body, map_name = m.group(1), m.group(2)
        if "LIBBPF_PIN_BY_NAME" in body:
          pinned.setdefault(map_name, set()).add(body)
    # Sanity: the policy really did emit shared pinned maps to check.
    # The two zones differ in rule count, counter count and geoip call
    # count, so a map whose shape came from a zone's own analysis WOULD
    # diverge here. `fwl_rl_g0` is the v0.4 § 6.7 global bucket: named
    # bundle-wide on purpose, and therefore held to this invariant.
    assert "conntrack" in pinned
    assert "fwl_rl_g0" in pinned
    divergent = {k: v for k, v in pinned.items() if len(v) > 1}
    assert not divergent, (
      f"pinned maps declared differently across zones: "
      f"{sorted(divergent)}"
    )

  def test_bundle_zone_files_compile(self):
    prog = _analyze(
      WL + "@xdp(wan)\nallow if conntrack(pkt).state == established\ndrop\n"
      "@xdp(lan)\nredirect to wan\n"
    )
    files = emitter.emit_bundle(prog)
    for name, src in files.items():
      if name.endswith(".bpf.c"):
        bpf_runner.compile_c(src)


# --------------------------------------------------------------------
class TestInterpreter:
  def test_redirect_returns_redirect_and_zone(self):
    r = _run(WL + "@xdp(lan)\nredirect to wan\n",
             "tcp(src_ip=\"10.0.0.1\", dst_ip=\"1.1.1.1\", dst_port=80)",
             ingress="lan")
    assert r.action == XdpAction.REDIRECT and r.redirect_zone == "wan"

  def test_conditional_redirect_falls_through(self):
    src = (WL + "@xdp(lan)\nredirect to wan if pkt.proto == tcp and "
           "pkt.dst_port == 80\ndrop\n")
    r = _run(src,
             "tcp(src_ip=\"10.0.0.1\", dst_ip=\"1.1.1.1\", dst_port=22)",
             ingress="lan")
    assert r.action == XdpAction.DROP

  def test_pkt_zone_constant_true(self):
    r = _run(WL + "@xdp(lan)\nallow if pkt.zone == lan\ndrop\n",
             "tcp(src_ip=\"10.0.0.1\", dst_ip=\"1.1.1.1\", dst_port=80)",
             ingress="lan")
    assert r.action == XdpAction.PASS

  def test_pkt_zone_constant_false(self):
    r = _run(WL + "@xdp(lan)\nallow if pkt.zone == wan\ndrop\n",
             "tcp(src_ip=\"10.0.0.1\", dst_ip=\"1.1.1.1\", dst_port=80)",
             ingress="lan")
    assert r.action == XdpAction.DROP

  def test_tier2_redirect(self):
    r = _run(WL + "@xdp(lan)\ndef f(pkt):\n  if pkt.zone == lan:\n"
             "    redirect to wan\n  drop\n",
             "tcp(src_ip=\"10.0.0.1\", dst_ip=\"1.1.1.1\", dst_port=80)",
             ingress="lan")
    assert r.action == XdpAction.REDIRECT and r.redirect_zone == "wan"

  def test_different_blocks_per_ingress_zone(self):
    src = WL + "@xdp(wan)\ndrop\n@xdp(lan)\nredirect to wan\n"
    pk = "tcp(src_ip=\"10.0.0.1\", dst_ip=\"1.1.1.1\", dst_port=80)"
    assert _run(src, pk, ingress="wan").action == XdpAction.DROP
    assert _run(src, pk, ingress="lan").action == XdpAction.REDIRECT


# --------------------------------------------------------------------
class TestBackwardCompat:
  def test_single_xdp_no_zones_still_works(self):
    prog = _analyze("@xdp(eth0)\nallow if pkt.proto == tcp\ndefault drop\n")
    assert prog.hook.interface == "eth0"
    assert len(prog.rules) == 1
    c = emitter.emit(prog)
    bpf_runner.compile_c(c)
