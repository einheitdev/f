"""Emitter tests — verify generated C is valid."""

from pathlib import Path

from fwl.analyzer import analyze
from fwl.emitter import emit
from fwl.parser import parse

_FIXTURES = Path(__file__).parent / "fixtures"


def _compile_fixture(name: str) -> str:
  text = (_FIXTURES / name).read_text()
  ast = parse(text)
  result = analyze(ast)
  return emit(result, filename=name.replace(".fw", ""))


class TestBlockPortEmit:
  """block_port.fw → .bpf.c"""

  def test_emits(self):
    code = _compile_fixture("block_port.fw")
    assert len(code) > 0

  def test_has_sec_xdp(self):
    code = _compile_fixture("block_port.fw")
    assert 'SEC("xdp")' in code

  def test_has_func_name(self):
    code = _compile_fixture("block_port.fw")
    assert "int block_port(" in code

  def test_has_l2_parse(self):
    code = _compile_fixture("block_port.fw")
    assert "struct ethhdr* eth = data;" in code

  def test_has_l3_parse(self):
    code = _compile_fixture("block_port.fw")
    assert "struct iphdr* ip = (void*)(eth + 1);" in code

  def test_has_l4_parse(self):
    code = _compile_fixture("block_port.fw")
    assert "dst_port = bpf_ntohs(tcp->dest);" in code

  def test_has_bounds_check(self):
    code = _compile_fixture("block_port.fw")
    assert "(void*)(eth + 1) > data_end" in code
    assert "(void*)(ip + 1) > data_end" in code
    assert "(void*)(tcp + 1) > data_end" in code

  def test_has_xdp_drop(self):
    code = _compile_fixture("block_port.fw")
    assert "return XDP_DROP;" in code

  def test_has_license(self):
    code = _compile_fixture("block_port.fw")
    assert 'SEC("license")' in code

  def test_has_port_comparison(self):
    code = _compile_fixture("block_port.fw")
    assert "dst_port == 8080" in code

  def test_has_proto_comparison(self):
    code = _compile_fixture("block_port.fw")
    assert "ip->protocol == 6" in code


class TestMinimalEmit:
  """minimal.fw — should not emit any function (rules only)."""

  def test_emits(self):
    code = _compile_fixture("minimal.fw")
    assert len(code) > 0

  def test_has_license(self):
    code = _compile_fixture("minimal.fw")
    assert 'SEC("license")' in code

  def test_no_func(self):
    code = _compile_fixture("minimal.fw")
    assert 'SEC("xdp")' not in code


class TestInlineCEmit:
  """inline_c.fw — should pass through raw C."""

  def test_emits(self):
    code = _compile_fixture("inline_c.fw")
    assert len(code) > 0

  def test_has_inline_code(self):
    code = _compile_fixture("inline_c.fw")
    assert "dns[2] & 0x80" in code
