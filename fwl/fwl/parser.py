"""Lark parser + transformer: .fw source -> typed AST.

Produces ast.Program; raises FwlException on syntax errors with
source spans.
"""
from __future__ import annotations
import importlib.resources

from lark import Lark, Transformer, UnexpectedInput
from lark.exceptions import VisitError

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
  lexer="basic",
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


def _parse_int(text: str) -> int:
  """Decimal or hex int literal."""
  if text.startswith("0x") or text.startswith("0X"):
    return int(text, 16)
  return int(text)


def _parse_ipv4(text: str) -> int:
  """Dotted-quad IPv4 -> 32-bit integer (network-order packed left-to-right).

  Returns the address as a 32-bit unsigned integer with the leftmost
  octet in the high byte (e.g. 192.168.0.1 -> 0xC0A80001).
  """
  parts = text.split(".")
  value = 0
  for part in parts:
    n = int(part)
    if not (0 <= n <= 255):
      raise ValueError(f"IPv4 octet out of range: {part}")
    value = (value << 8) | n
  return value


def _parse_cidr(text: str, span: Span) -> tuple[int, int]:
  """Dotted-quad/prefix -> (masked_prefix_int, prefix_bits).

  Raises FwlException with the spec's wording for invalid prefix
  lengths instead of a Python ValueError so the analyzer/runner
  surface a clean compile error.
  """
  ip_text, _, bits_text = text.partition("/")
  bits = int(bits_text)
  if not (0 <= bits <= 32):
    raise FwlException(
      FwlError(
        category="semantic",
        message=f"CIDR prefix must be 0..32 for IPv4 (got {bits})",
        span=span,
      )
    )
  ip_value = _parse_ipv4(ip_text)
  if bits == 0:
    mask = 0
  else:
    mask = ((1 << bits) - 1) << (32 - bits)
  return ip_value & mask, bits


class _ToAst(Transformer):
  """Lark Transformer: parse tree -> AST nodes."""

  # --- terminals: pass through so children-lists carry tokens. ---
  def IDENTIFIER(self, tok): return tok
  def ALLOW(self, tok): return tok
  def DROP(self, tok): return tok
  def LOG(self, tok): return tok
  def COUNT(self, tok): return tok
  def NOT(self, tok): return tok
  def EQ(self, tok): return tok
  def NEQ(self, tok): return tok
  def LT(self, tok): return tok
  def GT(self, tok): return tok
  def LE(self, tok): return tok
  def GE(self, tok): return tok
  def PROTO_FIELD(self, tok): return tok
  def IP_FIELD(self, tok): return tok
  def PORT_FIELD(self, tok): return tok
  def TCP_FLAG_FIELD(self, tok): return tok
  def PROTO_KEYWORD(self, tok): return tok
  def IPV4(self, tok): return tok
  def CIDR(self, tok): return tok
  def INTEGER(self, tok): return tok

  # --- top-level structure ---

  def hook_decl(self, children) -> ast.Hook:
    (iface_tok,) = children
    return ast.Hook(interface=str(iface_tok), span=_span(iface_tok))

  def terminal_action(
    self, children
  ) -> tuple[ast.Action, Span, str | None]:
    (tok,) = children
    if tok.type == "ALLOW":
      return ast.Action.ALLOW, _span(tok), None
    return ast.Action.DROP, _span(tok), None

  def nonterminal_action(
    self, children
  ) -> tuple[ast.Action, Span, str | None]:
    if children[0].type == "LOG":
      return ast.Action.LOG, _span(children[0]), None
    # COUNT IDENTIFIER
    count_tok, name_tok = children
    return ast.Action.COUNT, _span(count_tok), str(name_tok)

  def action(
    self, children
  ) -> tuple[ast.Action, Span, str | None]:
    (action_tuple,) = children
    return action_tuple

  def default_rule(self, children) -> ast.DefaultRule:
    (action_tuple,) = children
    action, span, _ = action_tuple
    return ast.DefaultRule(action=action, span=span)

  def rule(self, children) -> ast.Rule:
    action, action_span, counter_name = children[0]
    condition: ast.Condition | None = None
    modifier: ast.RateLimit | None = None
    for child in children[1:]:
      if isinstance(child, ast.RateLimit):
        modifier = child
      else:
        condition = child
    return ast.Rule(
      action=action,
      condition=condition,
      modifier=modifier,
      span=action_span,
      counter_name=counter_name,
    )

  def modifier(self, children) -> ast.RateLimit:
    threshold_tok, field_tok = children
    return ast.RateLimit(
      threshold=_parse_int(str(threshold_tok)),
      per_field=str(field_tok),
      span=_span(threshold_tok),
    )

  def RL_FIELD(self, tok):
    return tok

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

  # --- conditions ---

  def condition(self, children) -> ast.Condition:
    (node,) = children
    return node

  def or_expr(self, children) -> ast.Condition:
    if len(children) == 1:
      return children[0]
    return ast.OrOp(operands=list(children), span=children[0].span)

  def and_expr(self, children) -> ast.Condition:
    if len(children) == 1:
      return children[0]
    return ast.AndOp(operands=list(children), span=children[0].span)

  def not_expr(self, children) -> ast.Condition:
    if len(children) == 1:
      return children[0]
    not_tok, inner = children
    return ast.NotOp(inner=inner, span=_span(not_tok))

  def primary(self, children) -> ast.Condition:
    (node,) = children
    return node

  def bool_field(self, children) -> ast.BoolField:
    (tok,) = children
    return ast.BoolField(
      field=ast.FieldRef(name=str(tok), span=_span(tok)),
      span=_span(tok),
    )

  # --- comparisons + operands ---

  def comp_op(self, children) -> str:
    (tok,) = children
    return str(tok)

  def value_field(self, children) -> ast.FieldRef:
    (tok,) = children
    return ast.FieldRef(name=str(tok), span=_span(tok))

  def enum_field(self, children) -> ast.FieldRef:
    (tok,) = children
    return ast.FieldRef(name=str(tok), span=_span(tok))

  def value_compare(self, children) -> ast.Comparison:
    """value_field comp_op operand."""
    field, op, operand = children
    return ast.Comparison(
      field=field, op=op, operand=operand, span=field.span
    )

  def value_in(self, children) -> ast.Comparison:
    """value_field 'in' set_or_range."""
    field, operand = children
    return ast.Comparison(
      field=field, op="in", operand=operand, span=field.span
    )

  def enum_eq(self, children) -> ast.Comparison:
    """enum_field '==' PROTO_KEYWORD."""
    field, kw_tok = children
    return ast.Comparison(
      field=field,
      op="==",
      operand=ast.ProtoLiteral(
        proto=_PROTO_FROM_KEYWORD[str(kw_tok)], span=_span(kw_tok)
      ),
      span=field.span,
    )

  def enum_neq(self, children) -> ast.Comparison:
    """enum_field '!=' PROTO_KEYWORD."""
    field, kw_tok = children
    return ast.Comparison(
      field=field,
      op="!=",
      operand=ast.ProtoLiteral(
        proto=_PROTO_FROM_KEYWORD[str(kw_tok)], span=_span(kw_tok)
      ),
      span=field.span,
    )

  def operand(self, children) -> ast.Operand:
    (tok,) = children
    if tok.type == "INTEGER":
      return ast.IntLiteral(value=_parse_int(str(tok)), span=_span(tok))
    if tok.type == "IPV4":
      return ast.IPv4Literal(value=_parse_ipv4(str(tok)), span=_span(tok))
    raise AssertionError(f"unexpected operand token {tok.type}")

  def set_or_range(self, children) -> ast.Operand:
    (node,) = children
    return node

  def list(self, children) -> ast.ListLiteral:
    items = list(children)
    return ast.ListLiteral(items=items, span=items[0].span)

  def cidr(self, children) -> ast.CidrLiteral:
    (tok,) = children
    span = _span(tok)
    prefix, bits = _parse_cidr(str(tok), span)
    return ast.CidrLiteral(prefix=prefix, bits=bits, span=span)

  def cidr_list(self, children) -> ast.CidrListLiteral:
    items = []
    for tok in children:
      span = _span(tok)
      prefix, bits = _parse_cidr(str(tok), span)
      items.append(ast.CidrLiteral(prefix=prefix, bits=bits, span=span))
    return ast.CidrListLiteral(items=items, span=items[0].span)

  def range(self, children) -> ast.RangeLiteral:
    lo_tok, hi_tok = children
    lo = _parse_int(str(lo_tok))
    hi = _parse_int(str(hi_tok))
    return ast.RangeLiteral(lo=lo, hi=hi, span=_span(lo_tok))


def parse(source: str) -> ast.Program:
  """Parse FWL source into an AST.

  Raises FwlException on any parse error. Lark's VisitError wrapper
  is unwrapped so structural-validation failures from the
  transformer (out-of-range CIDR prefix, malformed IPv4 octet, etc.)
  surface as clean compile errors instead of crashing the runner.
  """
  try:
    tree = _PARSER.parse(source)
  except UnexpectedInput as exc:
    span = Span(line=exc.line, column=exc.column)
    raise FwlException(
      FwlError(category="syntax", message=str(exc), span=span)
    ) from exc
  try:
    return _ToAst().transform(tree)
  except VisitError as exc:
    inner = exc.orig_exc
    if isinstance(inner, FwlException):
      raise inner from exc
    raise FwlException(
      FwlError(category="semantic", message=str(inner), span=None)
    ) from exc
