"""Unit tests for v0.4 conntrack support (conntrack(pkt).state).

Covers the parser/analyzer/interpreter/emitter/pkt surfaces added for
`conntrack(pkt).state` (FWL_V04_SPEC.md § 4.3): the state model,
entry-creation side effect, BPF lookup emission, and the .pkt
`state.conntrack` pre-seed + `sequence:` extensions.
"""
import pytest

from fwl import analyzer, ast, emitter, interpreter, parser, pkt
from fwl.errors import FwlException
from fwl.interpreter import ConntrackTable, XdpAction


def _analyze(text):
  return analyzer.analyze(parser.parse(text))


def _emit(text):
  return emitter.emit(_analyze(text))


H = "@xdp(eth0)\n"


def _pkt(builder):
  return pkt.build_packet(pkt.parse_builder(builder)).fields


class TestParser:
  def test_eq_parses_to_ct_compare(self):
    prog = _analyze(
      H + "allow if conntrack(pkt).state == established\ndefault drop\n"
    )
    cond = prog.rules[0].condition
    assert isinstance(cond, ast.ConntrackStateCompare)
    assert cond.op == "==" and cond.states == (ast.CtState.ESTABLISHED,)

  def test_in_list_parses_states(self):
    prog = _analyze(
      H + "allow if conntrack(pkt).state in [established, related]\n"
      "default drop\n"
    )
    cond = prog.rules[0].condition
    assert cond.op == "in"
    assert cond.states == (ast.CtState.ESTABLISHED, ast.CtState.RELATED)

  def test_internal_whitespace_tolerated(self):
    prog = _analyze(
      H + "allow if conntrack( pkt ).state != new\ndefault drop\n"
    )
    assert prog.rules[0].condition.op == "!="

  def test_state_keyword_is_not_a_reserved_prefix(self):
    # Bare state keywords are reserved (like the proto keywords), but
    # the negative-lookahead keeps `established_flows` an identifier.
    prog = _analyze(H + "count established_flows\nallow\n")
    assert prog.rules[0].counter_name == "established_flows"

  def test_bare_conntrack_without_state_is_error(self):
    with pytest.raises(FwlException):
      parser.parse(H + "allow if conntrack(pkt) == established\ndefault drop\n")

  def test_tier2_conntrack_parses(self):
    prog = _analyze(
      H + "def f(pkt):\n"
      "  if conntrack(pkt).state == established:\n"
      "    allow\n"
      "  drop\n"
    )
    assert prog.function is not None


class TestAnalyzer:
  def test_ordered_op_rejected(self):
    with pytest.raises(FwlException) as e:
      _analyze(
        H + "allow if conntrack(pkt).state < established\ndefault drop\n"
      )
    assert "==" in e.value.error.message

  def test_no_proto_guard_required(self):
    # conntrack reads on any frame — no guard, even before any proto test.
    _analyze(H + "allow if conntrack(pkt).state == new\ndefault drop\n")

  def test_wrong_type_rhs_rejected(self):
    with pytest.raises(FwlException):
      _analyze(H + "allow if conntrack(pkt).state == tcp\ndefault drop\n")


class TestInterpreterModel:
  def test_empty_table_is_new(self):
    t = ConntrackTable()
    assert t.state_for(_pkt("tcp(dst_port=80, syn=true)")) == ast.CtState.NEW

  def test_seeded_forward_is_established(self):
    key = ("tcp", interpreter._ipv4_to_int("1.2.3.4"),
           interpreter._ipv4_to_int("2.2.2.2"), 12345, 80)
    t = ConntrackTable([key])
    p = _pkt("tcp(src_ip=\"1.2.3.4\", dst_ip=\"2.2.2.2\", "
             "src_port=12345, dst_port=80, ack=true)")
    assert t.state_for(p) == ast.CtState.ESTABLISHED

  def test_reverse_direction_is_established(self):
    key = ("tcp", interpreter._ipv4_to_int("1.2.3.4"),
           interpreter._ipv4_to_int("2.2.2.2"), 12345, 80)
    t = ConntrackTable([key])
    reply = _pkt("tcp(src_ip=\"2.2.2.2\", dst_ip=\"1.2.3.4\", "
                 "src_port=80, dst_port=12345, ack=true)")
    assert t.state_for(reply) == ast.CtState.ESTABLISHED

  def test_nonsyn_untracked_tcp_is_invalid(self):
    t = ConntrackTable()
    p = _pkt("tcp(dst_port=80, ack=true)")
    assert t.state_for(p) == ast.CtState.INVALID

  def test_untracked_udp_is_new_not_invalid(self):
    t = ConntrackTable()
    assert t.state_for(_pkt("udp(dst_port=53)")) == ast.CtState.NEW

  def test_ipv6_is_always_new(self):
    t = ConntrackTable()
    assert t.state_for(_pkt("tcp6(dst_port=80, ack=true)")) == ast.CtState.NEW


class TestInterpreterSideEffects:
  PROG = (H + "allow if conntrack(pkt).state == established\n"
          "allow if pkt.proto == tcp and pkt.tcp.syn and pkt.dst_port == 80\n"
          "default drop\n")

  def test_allowed_new_creates_then_reply_established(self):
    prog = _analyze(self.PROG)
    ct = ConntrackTable()
    syn = _pkt("tcp(src_ip=\"1.1.1.1\", dst_ip=\"2.2.2.2\", "
               "src_port=40000, dst_port=80, syn=true)")
    reply = _pkt("tcp(src_ip=\"2.2.2.2\", dst_ip=\"1.1.1.1\", "
                 "src_port=80, dst_port=40000, ack=true)")
    assert interpreter.evaluate(prog, syn, conntrack=ct) == XdpAction.PASS
    assert interpreter.evaluate(prog, reply, conntrack=ct) == XdpAction.PASS

  def test_drop_on_new_creates_no_entry(self):
    prog = _analyze(
      H + "allow if conntrack(pkt).state == established\ndefault drop\n"
    )
    ct = ConntrackTable()
    syn = _pkt("tcp(src_ip=\"1.1.1.1\", dst_ip=\"2.2.2.2\", "
               "src_port=40000, dst_port=80, syn=true)")
    reply = _pkt("tcp(src_ip=\"2.2.2.2\", dst_ip=\"1.1.1.1\", "
                 "src_port=80, dst_port=40000, ack=true)")
    assert interpreter.evaluate(prog, syn, conntrack=ct) == XdpAction.DROP
    # No entry created -> the reply is still new -> dropped.
    assert interpreter.evaluate(prog, reply, conntrack=ct) == XdpAction.DROP

  def test_related_never_matches(self):
    prog = _analyze(
      H + "allow if conntrack(pkt).state == related\ndefault drop\n"
    )
    ct = ConntrackTable()
    p = _pkt("tcp(dst_port=80, syn=true)")
    assert interpreter.evaluate(prog, p, conntrack=ct) == XdpAction.DROP


class TestEmitter:
  def test_emits_conntrack_map_and_lookup(self):
    c = _emit(
      H + "allow if conntrack(pkt).state == established\ndefault drop\n"
    )
    assert "} conntrack SEC(\".maps\");" in c
    assert "bpf_map_lookup_elem(&conntrack, &_ct_f)" in c
    assert "bpf_map_lookup_elem(&conntrack, &_ct_r)" in c
    # forward + reverse 5-tuple derived from the raw (network-order) addrs
    assert ".src_addr = ip->saddr, .dst_addr = ip->daddr," in c
    assert ".src_addr = ip->daddr, .dst_addr = ip->saddr," in c

  def test_allow_creates_entry_drop_does_not(self):
    c = _emit(
      H + "allow if conntrack(pkt).state == new\n"
      "drop if conntrack(pkt).state == invalid\ndefault drop\n"
    )
    # Exactly one creation site: the single `allow` rule. The two drop
    # rules and the default drop emit no BPF_NOEXIST insert.
    assert c.count("BPF_NOEXIST") == 1

  def test_default_allow_creates_entry(self):
    c = _emit(H + "drop if conntrack(pkt).state == invalid\ndefault allow\n")
    assert c.count("BPF_NOEXIST") == 1

  def test_no_conntrack_no_map(self):
    c = _emit(
      H + "allow if pkt.proto == tcp and pkt.dst_port == 80\ndefault drop\n"
    )
    assert "conntrack" not in c

  def test_ct_state_compare_numeric_encoding(self):
    c = _emit(H + "allow if conntrack(pkt).state == invalid\ndefault drop\n")
    assert "(ct_state == 3)" in c

  @pytest.mark.parametrize("src", [
    H + "allow if conntrack(pkt).state == established\ndefault drop\n",
    H + "drop if conntrack(pkt).state in [invalid]\nallow\n",
    H + "def f(pkt):\n  if conntrack(pkt).state == established:\n"
        "    allow\n  drop\n",
  ])
  def test_emitted_c_compiles(self, src):
    from fwl import bpf_runner
    bpf_runner.check_compiles(_emit(src))


class TestPktLoader:
  def test_conntrack_seed_parsed(self, tmp_path):
    f = tmp_path / "c.pkt"
    f.write_text(
      "name: t\n"
      "source_fw: |\n"
      "  @xdp(eth0)\n"
      "  allow if conntrack(pkt).state == established\n"
      "  default drop\n"
      "state:\n"
      "  conntrack:\n"
      "    - { src_ip: \"1.2.3.4\", dst_ip: \"2.2.2.2\", "
      "src_port: 12345, dst_port: 80, proto: tcp }\n"
      "test_packet:\n"
      "  builder: tcp(src_ip=\"1.2.3.4\", dst_ip=\"2.2.2.2\", "
      "src_port=12345, dst_port=80, ack=true)\n"
      "expected:\n"
      "  compiles: true\n"
      "  bpf_action: allow\n"
    )
    case = pkt.load(f)
    assert case.conntrack_seed == (
      ("tcp", 0x01020304, 0x02020202, 12345, 80),
    )

  def test_conntrack_seed_rejects_v6(self, tmp_path):
    f = tmp_path / "c.pkt"
    f.write_text(
      "name: t\n"
      "source_fw: |\n"
      "  @xdp(eth0)\n  allow\n"
      "state:\n"
      "  conntrack:\n"
      "    - { src_ip: \"1.2.3.4\", dst_ip: \"2.2.2.2\", proto: sctp }\n"
      "test_packet:\n  builder: tcp(dst_port=80)\n"
      "expected:\n  compiles: true\n  bpf_action: allow\n"
    )
    with pytest.raises(ValueError):
      pkt.load(f)

  def test_sequence_loads_steps(self, tmp_path):
    f = tmp_path / "s.pkt"
    f.write_text(
      "name: t\n"
      "source_fw: |\n"
      "  @xdp(eth0)\n"
      "  allow if conntrack(pkt).state == established\n"
      "  allow if pkt.proto == tcp and pkt.tcp.syn\n"
      "  default drop\n"
      "sequence:\n"
      "  - name: a\n"
      "    builder: tcp(src_ip=\"1.1.1.1\", dst_ip=\"2.2.2.2\", "
      "src_port=40000, dst_port=80, syn=true)\n"
      "    expected: { bpf_action: allow }\n"
      "  - name: b\n"
      "    builder: tcp(src_ip=\"2.2.2.2\", dst_ip=\"1.1.1.1\", "
      "src_port=80, dst_port=40000, ack=true)\n"
      "    expected: { bpf_action: allow }\n"
    )
    case = pkt.load(f)
    assert case.sequence is not None and len(case.sequence) == 2
    assert case.sequence[0].name == "a"

  def test_sequence_and_test_packet_mutually_exclusive(self, tmp_path):
    f = tmp_path / "x.pkt"
    f.write_text(
      "name: t\n"
      "source_fw: |\n  @xdp(eth0)\n  allow\n"
      "sequence:\n"
      "  - builder: tcp(dst_port=80)\n"
      "    expected: { bpf_action: allow }\n"
      "test_packet:\n  builder: tcp(dst_port=80)\n"
      "expected:\n  bpf_action: allow\n"
    )
    with pytest.raises(ValueError):
      pkt.load(f)
