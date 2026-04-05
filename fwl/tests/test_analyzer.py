"""Analyzer tests — verify layer resolution and map allocation."""

from pathlib import Path

from fwl.analyzer import analyze
from fwl.ast_nodes import ActionType
from fwl.parser import parse

_FIXTURES = Path(__file__).parent / "fixtures"


def _analyze_fixture(name: str):
  text = (_FIXTURES / name).read_text()
  ast = parse(text)
  return analyze(ast)


class TestBlockPortAnalysis:
  """block_port.fw — needs IP + L4 for dst_port and proto."""

  def test_needs_ip(self):
    result = _analyze_fixture("block_port.fw")
    assert result.funcs[0].needs_ip

  def test_needs_l4(self):
    result = _analyze_fixture("block_port.fw")
    assert result.funcs[0].needs_l4

  def test_no_maps(self):
    result = _analyze_fixture("block_port.fw")
    assert len(result.funcs[0].maps) == 0


class TestAllowlistAnalysis:
  """allowlist.fw — needs geoip map."""

  def test_needs_ip(self):
    result = _analyze_fixture("allowlist.fw")
    assert result.funcs[0].needs_ip

  def test_needs_l4(self):
    result = _analyze_fixture("allowlist.fw")
    assert result.funcs[0].needs_l4

  def test_has_geoip_map(self):
    result = _analyze_fixture("allowlist.fw")
    map_names = [m.name for m in result.funcs[0].maps]
    assert "geoip" in map_names


class TestMinimalAnalysis:
  """minimal.fw — just default drop."""

  def test_default_action(self):
    result = _analyze_fixture("minimal.fw")
    assert result.default_action == ActionType.DROP

  def test_no_funcs(self):
    result = _analyze_fixture("minimal.fw")
    assert len(result.funcs) == 0


class TestPortFilterAnalysis:
  """port_filter.fw — mixed rules + function."""

  def test_has_rules(self):
    result = _analyze_fixture("port_filter.fw")
    assert len(result.rules) == 2

  def test_has_func(self):
    result = _analyze_fixture("port_filter.fw")
    assert len(result.funcs) == 1

  def test_func_needs_l4(self):
    result = _analyze_fixture("port_filter.fw")
    assert result.funcs[0].needs_l4
