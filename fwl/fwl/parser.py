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


_PROTO_FROM_KEYWORD = {
  "tcp": ast.Proto.TCP,
  "udp": ast.Proto.UDP,
  "icmp": ast.Proto.ICMP,
}


class _ToAst(Transformer):
  """Lark Transformer: parse tree -> AST nodes."""

  def IDENTIFIER(self, tok: Token) -> Token:
    return tok

  def ALLOW(self, tok: Token) -> Token:
    return tok

  def DROP(self, tok: Token) -> Token:
    return tok

  def PROTO_FIELD(self, tok: Token) -> Token:
    return tok

  def PROTO_KEYWORD(self, tok: Token) -> Token:
    return tok

  def hook_decl(self, children) -> ast.Hook:
    (iface_tok,) = children
    return ast.Hook(interface=str(iface_tok), span=_span(iface_tok))

  def field(self, children) -> ast.FieldRef:
    (tok,) = children
    return ast.FieldRef(name=str(tok), span=_span(tok))

  def operand(self, children) -> ast.ProtoLiteral:
    (tok,) = children
    return ast.ProtoLiteral(
      proto=_PROTO_FROM_KEYWORD[str(tok)], span=_span(tok)
    )

  def comparison(self, children) -> ast.Comparison:
    field, operand = children
    return ast.Comparison(
      field=field, op="==", operand=operand, span=field.span
    )

  def condition(self, children) -> ast.Condition:
    (cmp_node,) = children
    return cmp_node

  def terminal_action(self, children) -> tuple[ast.Action, Span]:
    (tok,) = children
    if tok.type == "ALLOW":
      return ast.Action.ALLOW, _span(tok)
    if tok.type == "DROP":
      return ast.Action.DROP, _span(tok)
    raise AssertionError(f"unexpected terminal_action token {tok.type}")

  def action(self, children) -> tuple[ast.Action, Span]:
    (action_tuple,) = children
    return action_tuple

  def default_rule(self, children) -> ast.DefaultRule:
    (action_tuple,) = children
    action, span = action_tuple
    return ast.DefaultRule(action=action, span=span)

  def rule(self, children) -> ast.Rule:
    action_tuple = children[0]
    action, action_span = action_tuple
    condition = children[1] if len(children) > 1 else None
    return ast.Rule(action=action, condition=condition, span=action_span)

  def program(self, children) -> ast.Program:
    hook = children[0]
    default = None
    rules: list[ast.Rule] = []
    for child in children[1:]:
      if isinstance(child, ast.DefaultRule):
        default = child
      else:
        rules.append(child)
    return ast.Program(hook=hook, rules=rules, default=default)


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
