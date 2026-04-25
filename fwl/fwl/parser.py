"""Lark parser + transformer: .fw source -> typed AST.

Produces ast.Program; raises FwlException on syntax errors with
source spans.
"""
from __future__ import annotations
import importlib.resources

from lark import Lark, Transformer, Token, UnexpectedInput

from . import ast
from .errors import FwlError, FwlException, Span


def _grammar_text() -> str:
  """Read the Lark grammar from the package."""
  return (
    importlib.resources.files("fwl")
    .joinpath("grammar.lark")
    .read_text(encoding="utf-8")
  )


_PARSER = Lark(
  _grammar_text(),
  parser="lalr",
  start="program",
  propagate_positions=True,
)


def _span(token_or_tree) -> Span:
  """Extract a (line, column) span from a Lark token or tree."""
  line = getattr(token_or_tree, "line", None) or 1
  column = getattr(token_or_tree, "column", None) or 1
  return Span(line=line, column=column)


class _ToAst(Transformer):
  """Lark Transformer: parse tree -> AST nodes."""

  def IDENTIFIER(self, tok: Token) -> Token:
    return tok

  def ALLOW(self, tok: Token) -> Token:
    return tok

  def DROP(self, tok: Token) -> Token:
    return tok

  def hook_decl(self, children) -> ast.Hook:
    (iface_tok,) = children
    return ast.Hook(interface=str(iface_tok), span=_span(iface_tok))

  def action(self, children) -> tuple[ast.Action, Span]:
    (tok,) = children
    if tok.type == "ALLOW":
      return ast.Action.ALLOW, _span(tok)
    if tok.type == "DROP":
      return ast.Action.DROP, _span(tok)
    # Grammar restricts action to ALLOW | DROP, so this is unreachable.
    raise AssertionError(f"unexpected action token {tok.type}")

  def rule(self, children) -> ast.Rule:
    (action_tuple,) = children
    action, span = action_tuple
    return ast.Rule(action=action, span=span)

  def program(self, children) -> ast.Program:
    hook = children[0]
    rules = list(children[1:])
    return ast.Program(hook=hook, rules=rules)


def parse(source: str) -> ast.Program:
  """Parse FWL source into an AST.

  Raises FwlException with category="syntax" on any parse error.
  """
  try:
    tree = _PARSER.parse(source)
  except UnexpectedInput as exc:
    span = Span(line=exc.line, column=exc.column)
    raise FwlException(
      FwlError(category="syntax", message=str(exc), span=span)
    ) from exc
  return _ToAst().transform(tree)
