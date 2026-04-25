"""Unit tests for the parser/transformer."""
import pytest

from fwl import ast, parser
from fwl.errors import FwlException


def parse(text):
  return parser.parse(text)


class TestHook:
  def test_parses_xdp_with_interface(self):
    program = parse("@xdp(eth0)\nallow\n")
    assert program.hook.interface == "eth0"
    assert program.hook.span.line == 1

  def test_interface_can_be_any_identifier(self):
    program = parse("@xdp(wlp3s0)\nallow\n")
    assert program.hook.interface == "wlp3s0"

  def test_missing_hook_is_syntax_error(self):
    with pytest.raises(FwlException):
      parse("allow\n")


class TestActions:
  def test_bare_allow(self):
    program = parse("@xdp(eth0)\nallow\n")
    assert program.rules[0].action == ast.Action.ALLOW
    assert program.rules[0].condition is None

  def test_bare_drop(self):
    program = parse("@xdp(eth0)\ndrop\n")
    assert program.rules[0].action == ast.Action.DROP

  def test_log(self):
    program = parse("@xdp(eth0)\nlog if pkt.proto == tcp\n")
    assert program.rules[0].action == ast.Action.LOG

  def test_count_with_name(self):
    program = parse("@xdp(eth0)\ncount foo if pkt.proto == tcp\n")
    assert program.rules[0].action == ast.Action.COUNT
    assert program.rules[0].counter_name == "foo"


class TestDefault:
  def test_default_drop(self):
    program = parse("@xdp(eth0)\ndefault drop\n")
    assert program.default is not None
    assert program.default.action == ast.Action.DROP

  def test_default_allow_after_rules(self):
    program = parse(
      "@xdp(eth0)\nallow if pkt.proto == tcp\ndefault allow\n"
    )
    assert len(program.rules) == 1
    assert program.default.action == ast.Action.ALLOW

  def test_rule_after_default_fails(self):
    with pytest.raises(FwlException):
      parse("@xdp(eth0)\ndefault drop\nallow\n")

  def test_default_log_fails(self):
    with pytest.raises(FwlException):
      parse("@xdp(eth0)\ndefault log\n")


class TestComparisons:
  def test_proto_eq_keyword(self):
    program = parse("@xdp(eth0)\ndrop if pkt.proto == tcp\n")
    cmp = program.rules[0].condition
    assert cmp.field.name == ast.FIELD_PROTO
    assert cmp.op == "=="
    assert cmp.operand.proto == ast.Proto.TCP

  def test_proto_neq_keyword(self):
    program = parse("@xdp(eth0)\ndrop if pkt.proto != udp\n")
    assert program.rules[0].condition.op == "!="

  def test_port_in_list(self):
    program = parse(
      "@xdp(eth0)\ndrop if pkt.proto == tcp and "
      "pkt.dst_port in [80, 443]\n"
    )
    cmp = program.rules[0].condition.operands[1]
    assert cmp.op == "in"
    assert isinstance(cmp.operand, ast.ListLiteral)
    assert [item.value for item in cmp.operand.items] == [80, 443]

  def test_port_range(self):
    program = parse(
      "@xdp(eth0)\ndrop if pkt.proto == tcp and "
      "pkt.dst_port in 1024..65535\n"
    )
    cmp = program.rules[0].condition.operands[1]
    assert isinstance(cmp.operand, ast.RangeLiteral)
    assert cmp.operand.lo == 1024
    assert cmp.operand.hi == 65535

  def test_cidr(self):
    program = parse(
      "@xdp(eth0)\ndrop if pkt.src_ip in 10.0.0.0/8\n"
    )
    cmp = program.rules[0].condition
    assert isinstance(cmp.operand, ast.CidrLiteral)
    assert cmp.operand.bits == 8
    assert cmp.operand.prefix == 0x0A000000

  def test_cidr_list(self):
    program = parse(
      "@xdp(eth0)\ndrop if pkt.src_ip in "
      "[10.0.0.0/8, 172.16.0.0/12]\n"
    )
    cmp = program.rules[0].condition
    assert isinstance(cmp.operand, ast.CidrListLiteral)
    assert len(cmp.operand.items) == 2

  def test_hex_integer(self):
    program = parse(
      "@xdp(eth0)\ndrop if pkt.proto == tcp and "
      "pkt.dst_port == 0xff\n"
    )
    cmp = program.rules[0].condition.operands[1]
    assert cmp.operand.value == 255


class TestComposition:
  def test_and(self):
    program = parse(
      "@xdp(eth0)\ndrop if pkt.proto == tcp and pkt.dst_port == 22\n"
    )
    assert isinstance(program.rules[0].condition, ast.AndOp)
    assert len(program.rules[0].condition.operands) == 2

  def test_or(self):
    program = parse(
      "@xdp(eth0)\ndrop if pkt.proto == tcp or pkt.proto == udp\n"
    )
    assert isinstance(program.rules[0].condition, ast.OrOp)

  def test_not(self):
    program = parse(
      "@xdp(eth0)\ndrop if pkt.proto == tcp and not pkt.tcp.syn\n"
    )
    inner = program.rules[0].condition.operands[1]
    assert isinstance(inner, ast.NotOp)

  def test_parens_override_precedence(self):
    program = parse(
      "@xdp(eth0)\n"
      "drop if (pkt.proto == tcp or pkt.proto == udp) "
      "and pkt.dst_port == 53\n"
    )
    # With parens, top-level is AND
    assert isinstance(program.rules[0].condition, ast.AndOp)


class TestRateLimit:
  def test_modifier_with_if_clause(self):
    program = parse(
      "@xdp(eth0)\n"
      "drop if pkt.proto == tcp limited by rate_limit(10, per=src_ip)\n"
    )
    rule = program.rules[0]
    assert rule.modifier is not None
    assert rule.modifier.threshold == 10
    assert rule.modifier.per_field == "src_ip"

  def test_modifier_without_if_clause(self):
    program = parse(
      "@xdp(eth0)\n"
      "drop limited by rate_limit(5000, per=dst_ip)\n"
    )
    assert program.rules[0].condition is None
    assert program.rules[0].modifier.per_field == "dst_ip"


class TestComments:
  def test_full_line_comment(self):
    program = parse(
      "@xdp(eth0)\n# this is a comment\nallow\n"
    )
    assert len(program.rules) == 1

  def test_trailing_comment(self):
    program = parse(
      "@xdp(eth0)\nallow if pkt.proto == tcp  # ssh\n"
    )
    assert program.rules[0].condition.field.name == ast.FIELD_PROTO


class TestKeywordsVsIdentifiers:
  def test_identifier_starting_with_keyword_prefix(self):
    """`tcp_traffic` lexes as IDENTIFIER, not PROTO_KEYWORD `tcp`."""
    program = parse(
      "@xdp(eth0)\ncount tcp_traffic if pkt.proto == tcp\n"
    )
    assert program.rules[0].counter_name == "tcp_traffic"
