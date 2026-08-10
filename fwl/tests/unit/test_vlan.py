"""Unit tests for v0.4 VLAN 802.1Q support.

Covers the parser/analyzer/emitter/pkt-builder/interpreter surfaces
added for `pkt.vlan_id` and `pkt.vlan_priority` (FWL_V04_SPEC.md).
"""
import pytest

from fwl import analyzer, ast, emitter, interpreter, parser, pkt
from fwl.errors import FwlException


def _analyze(text):
  return analyzer.analyze(parser.parse(text))


def _emit(text):
  return emitter.emit(_analyze(text))


def _run(text, builder, truncate_to=None, state=None, geoip_data=None):
  prog = _analyze(text)
  packet = pkt.build_packet(pkt.parse_builder(builder))
  fields = packet.fields
  if truncate_to is not None:
    fields = pkt._strip_truncated_fields(fields, truncate_to)
  return interpreter.evaluate(prog, fields, state, geoip_data)


H = "@xdp(eth0)\n"


class TestParser:
  def test_vlan_fields_parse_to_fieldrefs(self):
    prog = _analyze(
      H + "drop if pkt.vlan_id == 10\n"
      "drop if pkt.vlan_priority == 3\ndefault allow\n"
    )
    names = {r.condition.field.name for r in prog.rules}
    assert names == {ast.FIELD_VLAN_ID, ast.FIELD_VLAN_PRIORITY}

  def test_vlan_priority_longest_match(self):
    # "pkt.vlan_priority" must not lex as "pkt.vlan_id"-adjacent junk.
    prog = _analyze(H + "drop if pkt.vlan_priority == 7\ndefault allow\n")
    assert prog.rules[0].condition.field.name == ast.FIELD_VLAN_PRIORITY


class TestAnalyzerTypeRules:
  def test_no_proto_guard_required(self):
    # VLAN is L2 — readable with no pkt.proto guard.
    _analyze(H + "allow if pkt.vlan_id == 10\ndefault drop\n")
    _analyze(H + "allow if pkt.vlan_priority == 1\ndefault drop\n")

  def test_all_comparison_ops(self):
    for op in ("==", "!=", "<", ">", "<=", ">="):
      _analyze(H + f"drop if pkt.vlan_id {op} 10\ndefault allow\n")
    _analyze(H + "drop if pkt.vlan_id in [1, 2, 3]\ndefault allow\n")
    _analyze(H + "drop if pkt.vlan_id in 100..199\ndefault allow\n")

  def test_vid_boundary_4095_ok(self):
    _analyze(H + "drop if pkt.vlan_id == 4095\ndefault allow\n")

  def test_priority_boundary_7_ok(self):
    _analyze(H + "drop if pkt.vlan_priority == 7\ndefault allow\n")

  def test_vid_above_4095_rejected(self):
    with pytest.raises(FwlException, match="vlan_id value 5000"):
      _analyze(H + "drop if pkt.vlan_id == 5000\ndefault allow\n")

  def test_vid_range_above_4095_rejected(self):
    with pytest.raises(FwlException, match="vlan_id value 9000"):
      _analyze(H + "drop if pkt.vlan_id in 4000..9000\ndefault allow\n")

  def test_vid_list_member_above_4095_rejected(self):
    with pytest.raises(FwlException, match="vlan_id value 9000"):
      _analyze(H + "drop if pkt.vlan_id in [1, 9000]\ndefault allow\n")

  def test_priority_above_7_rejected(self):
    with pytest.raises(FwlException, match="vlan_priority value 8"):
      _analyze(H + "drop if pkt.vlan_priority == 8\ndefault allow\n")

  def test_priority_list_member_above_7_rejected(self):
    with pytest.raises(FwlException, match="vlan_priority value 9"):
      _analyze(H + "drop if pkt.vlan_priority in [1, 9]\ndefault allow\n")

  def test_vlan_vs_non_integer_rejected(self):
    with pytest.raises(FwlException, match="vlan_id"):
      _analyze(H + "drop if pkt.vlan_id == 10.0.0.1\ndefault allow\n")

  def test_tier2_vlan_local_binds_u16(self):
    _analyze(
      H + "def f(pkt):\n  v = pkt.vlan_id\n"
      "  if v == 10:\n    allow\n  drop\n"
    )

  def test_tier2_vlan_range_check(self):
    with pytest.raises(FwlException, match="vlan_id value 5000"):
      _analyze(
        H + "def f(pkt):\n  if pkt.vlan_id in 4090..5000:\n"
        "    drop\n  allow\n"
      )


class TestEmitter:
  def test_vlan_dispatch_always_present(self):
    # Even an IP-only program must skip the tag so IP rules match
    # tagged frames.
    src = _emit(H + "drop if pkt.src_ip in 10.0.0.0/8\ndefault allow\n")
    assert "ETH_P_8021Q" in src
    assert "fwl_vlanhdr" in src
    assert "l3_proto" in src

  def test_vlan_field_read_and_gate(self):
    src = _emit(H + "drop if pkt.vlan_id == 10\ndefault allow\n")
    assert "vlan_ok = 1" in src
    assert "vlan_id = bpf_ntohs(vh->tci) & 0x0FFF" in src
    assert "(vlan_ok && (vlan_id == 10))" in src

  def test_priority_extraction(self):
    src = _emit(H + "drop if pkt.vlan_priority >= 5\ndefault allow\n")
    assert "vlan_priority = (bpf_ntohs(vh->tci) >> 13) & 0x7" in src

  def test_early_out_includes_vlan_ok_when_referenced(self):
    src = _emit(H + "drop if pkt.vlan_id == 10\ndefault allow\n")
    assert "!v4_ok && !v6_ok && !vlan_ok" in src

  def test_early_out_omits_vlan_ok_when_not_referenced(self):
    src = _emit(H + "drop if pkt.src_ip in 10.0.0.0/8\ndefault allow\n")
    assert "if (!v4_ok && !v6_ok && !is_v6_frame) return XDP_PASS;" \
        in src
    assert "vlan_ok" not in src

  def test_l3_derives_from_vlan_aware_pointer(self):
    # The IPv4 header pointer is `l3`, not a hard-coded eth+1.
    src = _emit(H + "drop if pkt.src_ip == 1.2.3.4\ndefault allow\n")
    assert "struct iphdr *ip = l3;" in src


class TestBuilder:
  def test_tagged_frame_inserts_4_byte_tag(self):
    packet = pkt.build_packet(pkt.parse_builder("tcp(vlan_id=10)"))
    # 14 eth + 4 tag + 20 ip + 20 tcp = 58
    assert len(packet.raw) == 58
    # TPID 0x8100 at offset 12, then TCI.
    assert packet.raw[12:14] == bytes([0x81, 0x00])
    assert packet.fields["vlan_id"] == 10
    assert packet.fields["vlan_priority"] == 0

  def test_untagged_frame_has_no_tag(self):
    packet = pkt.build_packet(pkt.parse_builder("tcp()"))
    assert len(packet.raw) == 54
    assert packet.raw[12:14] == bytes([0x08, 0x00])  # straight to IPv4
    assert "vlan_id" not in packet.fields

  def test_priority_only_sets_vid_zero(self):
    packet = pkt.build_packet(
      pkt.parse_builder("tcp(vlan_priority=5)")
    )
    assert packet.fields["vlan_id"] == 0
    assert packet.fields["vlan_priority"] == 5

  def test_tci_packs_pcp_and_vid(self):
    packet = pkt.build_packet(
      pkt.parse_builder("tcp(vlan_id=100, vlan_priority=3)")
    )
    tci = (packet.raw[14] << 8) | packet.raw[15]
    assert tci == (3 << 13) | 100

  def test_tagged_v6_offsets(self):
    packet = pkt.build_packet(
      pkt.parse_builder("tcp6(vlan_id=30, dst_port=443)")
    )
    # 14 + 4 tag + 40 v6 + 20 tcp = 78
    assert len(packet.raw) == 78
    assert packet.raw[12:14] == bytes([0x81, 0x00])
    # inner EtherType 0x86DD at offset 16
    assert packet.raw[16:18] == bytes([0x86, 0xDD])

  def test_qinq_double_tag(self):
    packet = pkt.build_packet(
      pkt.parse_builder("tcp(vlan_id=100, inner_vlan_id=200)")
    )
    # two 4-byte tags
    assert len(packet.raw) == 62
    assert packet.raw[12:14] == bytes([0x81, 0x00])  # outer TPID
    assert packet.raw[16:18] == bytes([0x81, 0x00])  # inner TPID
    # only outer VLAN is exposed; L3/L4 unreachable for v0.4
    assert packet.fields == {"vlan_id": 100, "vlan_priority": 0}

  def test_vid_out_of_range_rejected(self):
    with pytest.raises(ValueError, match="vlan_id out of range"):
      pkt.build_packet(pkt.parse_builder("tcp(vlan_id=5000)"))

  def test_priority_out_of_range_rejected(self):
    with pytest.raises(ValueError, match="vlan_priority out of range"):
      pkt.build_packet(pkt.parse_builder("tcp(vlan_priority=8)"))

  def test_truncation_inside_tag_strips_vlan(self):
    fields = pkt.build_packet(
      pkt.parse_builder("tcp(vlan_id=10)")
    ).fields
    stripped = pkt._strip_truncated_fields(fields, 15)
    assert "vlan_id" not in stripped

  def test_truncation_after_tag_keeps_vlan(self):
    fields = pkt.build_packet(
      pkt.parse_builder("tcp(vlan_id=10)")
    ).fields
    stripped = pkt._strip_truncated_fields(fields, 18)
    assert stripped["vlan_id"] == 10
    # L3 truncated away
    assert "src_ip" not in stripped


class TestInterpreter:
  def test_tagged_match(self):
    res = _run(
      H + "drop if pkt.vlan_id == 10\ndefault allow\n",
      "tcp(vlan_id=10)",
    )
    assert res is interpreter.XdpAction.DROP

  def test_untagged_does_not_match_vlan_rule(self):
    res = _run(
      H + "drop if pkt.vlan_id == 10\ndefault allow\n",
      "tcp()",
    )
    assert res is interpreter.XdpAction.PASS

  def test_native_vlan_distinct_from_untagged(self):
    prog = H + "allow if pkt.vlan_id == 0\ndefault drop\n"
    assert _run(prog, "tcp(vlan_id=0)") is interpreter.XdpAction.PASS
    assert _run(prog, "tcp()") is interpreter.XdpAction.DROP

  def test_vlan_transparent_to_ipv4(self):
    res = _run(
      H + "drop if pkt.src_ip in 10.0.0.0/8\ndefault allow\n",
      "tcp(vlan_id=10, src_ip=\"10.1.2.3\")",
    )
    assert res is interpreter.XdpAction.DROP

  def test_qinq_outer_only(self):
    prog = H + "drop if pkt.vlan_id == 100\ndefault allow\n"
    assert _run(
      prog, "tcp(vlan_id=100, inner_vlan_id=200)"
    ) is interpreter.XdpAction.DROP
    # inner vid is not visible
    prog2 = H + "drop if pkt.vlan_id == 200\ndefault allow\n"
    assert _run(
      prog2, "tcp(vlan_id=100, inner_vlan_id=200)"
    ) is interpreter.XdpAction.PASS
