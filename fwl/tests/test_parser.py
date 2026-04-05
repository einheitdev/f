"""Parser tests — verify .fw files produce correct AST."""

from pathlib import Path

import pytest

from fwl.ast_nodes import (
  ActionType,
  DefaultStmt,
  FuncDef,
  IfStmt,
  Program,
  RuleStmt,
)
from fwl.parser import parse

_FIXTURES = Path(__file__).parent / "fixtures"


def _parse_fixture(name: str) -> Program:
  return parse((_FIXTURES / name).read_text())


class TestMinimal:
  """Test the simplest possible .fw file."""

  def test_parses(self):
    ast = _parse_fixture("minimal.fw")
    assert isinstance(ast, Program)

  def test_has_default(self):
    ast = _parse_fixture("minimal.fw")
    assert len(ast.stmts) == 1
    assert isinstance(ast.stmts[0], DefaultStmt)
    assert ast.stmts[0].action == ActionType.DROP


class TestBlockPort:
  """Test tier 2 function with if/drop/allow."""

  def test_parses(self):
    ast = _parse_fixture("block_port.fw")
    assert isinstance(ast, Program)

  def test_has_func(self):
    ast = _parse_fixture("block_port.fw")
    funcs = [s for s in ast.stmts if isinstance(s, FuncDef)]
    assert len(funcs) == 1

  def test_func_name(self):
    ast = _parse_fixture("block_port.fw")
    func = ast.stmts[0]
    assert func.name == "block_port"

  def test_func_hook(self):
    ast = _parse_fixture("block_port.fw")
    func = ast.stmts[0]
    assert func.hook == "xdp"

  def test_func_has_if(self):
    ast = _parse_fixture("block_port.fw")
    func = ast.stmts[0]
    ifs = [s for s in func.body if isinstance(s, IfStmt)]
    assert len(ifs) == 1


class TestPortFilter:
  """Test mixed tier 1 rules + tier 2 function."""

  def test_parses(self):
    ast = _parse_fixture("port_filter.fw")
    assert isinstance(ast, Program)

  def test_has_rules_and_func(self):
    ast = _parse_fixture("port_filter.fw")
    rules = [s for s in ast.stmts if isinstance(s, RuleStmt)]
    funcs = [s for s in ast.stmts if isinstance(s, FuncDef)]
    assert len(rules) == 2
    assert len(funcs) == 1

  def test_rule_action(self):
    ast = _parse_fixture("port_filter.fw")
    rules = [s for s in ast.stmts if isinstance(s, RuleStmt)]
    assert rules[0].action == ActionType.ALLOW
    assert rules[1].action == ActionType.ALLOW

  def test_rule_matches(self):
    ast = _parse_fixture("port_filter.fw")
    rules = [s for s in ast.stmts if isinstance(s, RuleStmt)]
    # First rule: allow dst_port 80, 443 proto tcp
    assert len(rules[0].matches) == 2
    assert rules[0].matches[0].field == "dst_port"


class TestInlineC:
  """Test tier 3 inline C escape."""

  def test_parses(self):
    ast = _parse_fixture("inline_c.fw")
    assert isinstance(ast, Program)

  def test_has_func_with_inline_c(self):
    ast = _parse_fixture("inline_c.fw")
    func = ast.stmts[0]
    assert isinstance(func, FuncDef)
    assert func.name == "dpi"
