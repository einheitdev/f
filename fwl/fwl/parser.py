"""Lark parser + transformer: .fw source -> typed AST.

Produces ast.Program; raises FwlException on syntax errors with
source spans.
"""
from __future__ import annotations
import importlib.resources
import ipaddress

from lark import Lark, Transformer, UnexpectedInput
from lark.exceptions import VisitError
from lark.indenter import Indenter

from . import ast
from .errors import FwlError, FwlException, Span


def _grammar_text() -> str:
  """Read the Lark grammar from the package."""
  return (
    importlib.resources.files("fwl")
    .joinpath("grammar.lark")
    .read_text(encoding="utf-8")
  )


class FwlIndenter(Indenter):
  """Postlex that produces _INDENT/_DEDENT tokens for Tier 2 blocks.

  Indentation tracking is *gated* on having seen the `def` keyword
  — Tier 1 programs are line-oriented but allow continuation
  whitespace (e.g. a `limited by rate_limit(...)` modifier indented
  on the next line), and Lark's stock Indenter would emit spurious
  _INDENT/_DEDENT for every such continuation. Activating the
  tracker only inside the `def`'s body keeps Tier 1's whitespace
  semantics unchanged while still emitting the indent/dedent pair
  the Tier 2 grammar needs.

  Tab-len=8 matches Python's pre-PEP 8 convention. Mixing tabs and
  spaces within one indentation level is allowed by the base class
  but banned at the analyzer level (FWL_V02_SPEC.md).
  """
  NL_type = "_NL"
  OPEN_PAREN_types = ["LPAR", "LSQB"]
  CLOSE_PAREN_types = ["RPAR", "RSQB"]
  INDENT_type = "_INDENT"
  DEDENT_type = "_DEDENT"
  tab_len = 8

  def _process(self, stream):
    """Override the base process to gate indentation on `def`.

    Tier 1 programs are line-oriented but allow `limited by ...`
    continuation on a separately-indented line, where the stock
    Indenter would emit spurious INDENT tokens. To keep the LALR(1)
    grammar simple, we treat `_NL` as whitespace (drop it entirely)
    until we hit the `DEF` keyword. Once inside a `def` block,
    `_NL` is honoured by the standard tracker so INDENT/DEDENT
    emerge for the function body.
    """
    in_def = False
    token = None
    for token in stream:
      if not in_def and token.type == "DEF":
        in_def = True
      if token.type == self.NL_type:
        if in_def:
          yield from self.handle_NL(token)
        # else: drop the newline silently — Tier 1 doesn't need it.
      else:
        yield token
      if token.type in self.OPEN_PAREN_types:
        self.paren_level += 1
      elif token.type in self.CLOSE_PAREN_types:
        self.paren_level -= 1
        assert self.paren_level >= 0
    while len(self.indent_level) > 1:
      self.indent_level.pop()
      from lark.lexer import Token
      yield (
        Token.new_borrow_pos(self.DEDENT_type, "", token)
        if token else Token(self.DEDENT_type, "", 0, 0, 0, 0, 0, 0)
      )
    assert self.indent_level == [0], self.indent_level


_PARSER = Lark(
  _grammar_text(),
  parser="lalr",
  lexer="basic",
  start="program",
  propagate_positions=True,
  postlex=FwlIndenter(),
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
  "icmp6": ast.Proto.ICMP6,
}

# RFC 4291 §2.5.5.2: IPv4-mapped IPv6 addresses occupy ::ffff:0:0/96.
# RFC 5952 §5 mandates the dotted-quad form for that block. Other
# special blocks (the deprecated IPv4-compatible ::/96 block, link-
# local fe80::/10, etc.) follow rules 1-3 only.
_IPV4_MAPPED_BLOCK = ipaddress.IPv6Network("::ffff:0:0/96")


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


def _canonical_ipv6(text: str, addr: ipaddress.IPv6Address) -> str:
  """Compute the RFC 5952 canonical form per FWL_V02_SPEC.md.

  Python's IPv6Address.compressed is RFC 5952-compliant for rules 1-3
  (lowercase hex, suppressed leading zeros, single longest-`::`).
  RFC 5952 §5 (rule 4 in the spec) mandates dotted-quad for the
  IPv4-mapped block (::ffff:0:0/96); Python doesn't apply that rule
  by default, so we override.
  """
  if addr in _IPV4_MAPPED_BLOCK:
    v4_int = int(addr) & 0xFFFFFFFF
    v4 = ipaddress.IPv4Address(v4_int)
    return f"::ffff:{v4}"
  return addr.compressed


def _parse_ipv6(text: str, span: Span) -> int:
  """Parse and canonicality-check an IPv6 literal.

  Returns the address as a 128-bit integer in network byte order
  (the leftmost hextet is in the high 16 bits — same convention as
  IPv4Literal). Raises FwlException with the spec's wording when
  the source text is not in RFC 5952 canonical form (rules 1-4).
  """
  try:
    addr = ipaddress.IPv6Address(text)
  except ValueError as exc:
    raise FwlException(
      FwlError(
        category="semantic",
        message=f"invalid IPv6 literal '{text}': {exc}",
        span=span,
      )
    ) from exc
  expected = _canonical_ipv6(text, addr)
  if text != expected:
    if addr in _IPV4_MAPPED_BLOCK and "." not in text:
      msg = (
        "IPv4-mapped IPv6 literal must use dotted-quad form per "
        f"RFC 5952 §5; expected '{expected}'"
      )
    else:
      msg = (
        "IPv6 literal must be in canonical (RFC 5952) form; "
        f"expected '{expected}'"
      )
    raise FwlException(
      FwlError(category="semantic", message=msg, span=span)
    )
  return int(addr)


def _parse_ipv6_cidr(text: str, span: Span) -> tuple[int, int]:
  """IPv6 CIDR -> (masked_prefix_int, prefix_bits).

  The address half is canonicalized identically to a literal
  (FWL_V02_SPEC.md "CIDR with non-canonical address" edge case).
  Prefix length must be 0..128 inclusive.
  """
  addr_text, _, bits_text = text.rpartition("/")
  bits = int(bits_text)
  if not (0 <= bits <= 128):
    raise FwlException(
      FwlError(
        category="semantic",
        message=f"CIDR prefix must be 0..128 for IPv6 (got {bits})",
        span=span,
      )
    )
  addr_value = _parse_ipv6(addr_text, span)
  if bits == 0:
    mask = 0
  else:
    mask = ((1 << bits) - 1) << (128 - bits)
  return addr_value & mask, bits


class _ToAst(Transformer):
  """Lark Transformer: parse tree -> AST nodes."""

  # --- terminals: pass through so children-lists carry tokens. ---
  def IDENTIFIER(self, tok): return tok
  def ALLOW(self, tok): return tok
  def DROP(self, tok): return tok
  def LOG(self, tok): return tok
  def COUNT(self, tok): return tok
  def GEOIP(self, tok): return tok
  def CC_CODE(self, tok): return tok
  def NOT(self, tok): return tok
  def EQ(self, tok): return tok
  def NEQ(self, tok): return tok
  def LT(self, tok): return tok
  def GT(self, tok): return tok
  def LE(self, tok): return tok
  def GE(self, tok): return tok
  def PROTO_FIELD(self, tok): return tok
  def IP_FIELD(self, tok): return tok
  def IP6_FIELD(self, tok): return tok
  def PORT_FIELD(self, tok): return tok
  def TCP_FLAG_FIELD(self, tok): return tok
  def VLAN_FIELD(self, tok): return tok
  def PROTO_KEYWORD(self, tok): return tok
  def IPV4(self, tok): return tok
  def IPV6(self, tok): return tok
  def CIDR(self, tok): return tok
  def IPV6_CIDR(self, tok): return tok
  def INTEGER(self, tok): return tok

  # --- top-level structure ---

  def hook_decl(self, children) -> ast.Hook:
    (iface_tok,) = children
    return ast.Hook(interface=str(iface_tok), span=_span(iface_tok))

  def terminal_action(self, children):
    (tok,) = children
    if tok.type == "ALLOW":
      return ast.Action.ALLOW, _span(tok), None, None
    return ast.Action.DROP, _span(tok), None, None

  def log_action(self, children):
    log_tok = children[0]
    sample = None
    if len(children) > 1:
      sample = _parse_int(str(children[1]))
    return ast.Action.LOG, _span(log_tok), None, sample

  def nonterminal_action(self, children):
    if isinstance(children[0], tuple):
      return children[0]
    count_tok, name_tok = children
    return ast.Action.COUNT, _span(count_tok), str(name_tok), None

  def action(self, children):
    (action_tuple,) = children
    return action_tuple

  def default_rule(self, children) -> ast.DefaultRule:
    (action_tuple,) = children
    action, span, _, _ = action_tuple
    return ast.DefaultRule(action=action, span=span)

  def rule(self, children) -> ast.Rule:
    action, action_span, counter_name, log_sample = children[0]
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
      log_sample=log_sample,
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

  def body_item(self, children) -> ast.Rule | ast.DefaultRule | ast.FunctionDef:
    (item,) = children
    return item

  def program(self, children) -> ast.Program:
    hook = children[0]
    default: ast.DefaultRule | None = None
    function: ast.FunctionDef | None = None
    rules: list[ast.Rule] = []
    for child in children[1:]:
      if isinstance(child, ast.DefaultRule):
        if default is not None:
          raise FwlException(FwlError(
            category="syntax",
            message="program has multiple 'default' rules; only one is allowed",
            span=child.span,
          ))
        default = child
      elif isinstance(child, ast.FunctionDef):
        function = child
      elif isinstance(child, ast.Rule):
        if default is not None:
          raise FwlException(FwlError(
            category="syntax",
            message="rule placed after 'default'; default must be last",
            span=child.span,
          ))
        rules.append(child)
    return ast.Program(
      hook=hook, rules=rules, default=default, function=function
    )

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

  def bare_field(self, children) -> ast.FieldRef:
    """A bare value_field used as a primary — analyzer narrows."""
    (field,) = children
    return field

  def bool_flag(self, children) -> ast.BoolField:
    """`pkt.tcp.syn` / `pkt.tcp.ack` as a bare condition primary."""
    (tok,) = children
    return ast.BoolField(
      field=ast.FieldRef(name=str(tok), span=_span(tok)),
      span=_span(tok),
    )

  def bool_local(self, children) -> ast.LocalRead:
    """A bare identifier as a condition primary — a `bool` Tier 2 local."""
    (tok,) = children
    return ast.LocalRead(name=str(tok), span=_span(tok))

  # --- comparisons + operands ---

  def comp_op(self, children) -> str:
    (tok,) = children
    return str(tok)

  def value_field(self, children) -> ast.FieldRef:
    (tok,) = children
    return ast.FieldRef(name=str(tok), span=_span(tok))

  def lvalue_field(self, children) -> ast.FieldRef:
    """value_field on the LHS of a comparison."""
    (field,) = children
    return field

  def lvalue_local(self, children) -> ast.LocalRead:
    """A Tier 2 local name on the LHS of a comparison."""
    (tok,) = children
    return ast.LocalRead(name=str(tok), span=_span(tok))

  def rvalue_operand(self, children) -> ast.Operand:
    """A scalar operand (int / ipv4 / ipv6 / proto_keyword) on the RHS."""
    (operand,) = children
    return operand

  def rvalue_field(self, children) -> ast.FieldRef:
    """A packet field read on the RHS of a comparison (Tier 2)."""
    (field,) = children
    return field

  def rvalue_local(self, children) -> ast.LocalRead:
    """A Tier 2 local on the RHS of a comparison."""
    (tok,) = children
    return ast.LocalRead(name=str(tok), span=_span(tok))

  def value_compare(self, children) -> ast.Comparison:
    """lvalue comp_op rvalue."""
    lvalue, op, rvalue = children
    span = getattr(lvalue, "span", None) or _span(lvalue)
    return ast.Comparison(
      field=lvalue, op=op, operand=rvalue, span=span
    )

  def value_in(self, children) -> ast.Comparison:
    """lvalue 'in' set_or_range."""
    lvalue, operand = children
    span = getattr(lvalue, "span", None) or _span(lvalue)
    return ast.Comparison(
      field=lvalue, op="in", operand=operand, span=span
    )

  def count_call(self, children) -> ast.CountCall:
    count_tok, name_tok = children
    return ast.CountCall(
      counter_name=str(name_tok), span=_span(count_tok)
    )

  def count_compare(self, children) -> ast.CountCompare:
    call, op, rvalue = children
    return ast.CountCompare(
      call=call, op=op, operand=rvalue, span=call.span
    )

  def operand(self, children) -> ast.Operand:
    (tok,) = children
    if tok.type == "INTEGER":
      return ast.IntLiteral(value=_parse_int(str(tok)), span=_span(tok))
    if tok.type == "IPV4":
      return ast.IPv4Literal(value=_parse_ipv4(str(tok)), span=_span(tok))
    if tok.type == "IPV6":
      span = _span(tok)
      value = _parse_ipv6(str(tok), span)
      return ast.Ipv6Literal(value=value, span=span)
    if tok.type == "PROTO_KEYWORD":
      return ast.ProtoLiteral(
        proto=_PROTO_FROM_KEYWORD[str(tok)], span=_span(tok)
      )
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

  def ipv6_cidr(self, children) -> ast.Ipv6CidrLiteral:
    (tok,) = children
    span = _span(tok)
    prefix, bits = _parse_ipv6_cidr(str(tok), span)
    return ast.Ipv6CidrLiteral(prefix=prefix, bits=bits, span=span)

  def ipv6_cidr_list(self, children) -> ast.Ipv6CidrListLiteral:
    items = []
    for tok in children:
      span = _span(tok)
      prefix, bits = _parse_ipv6_cidr(str(tok), span)
      items.append(
        ast.Ipv6CidrLiteral(prefix=prefix, bits=bits, span=span)
      )
    return ast.Ipv6CidrListLiteral(items=items, span=items[0].span)

  def geoip_call(self, children) -> ast.GeoIp:
    """geoip(CC_CODE [, CC_CODE]*)."""
    geoip_tok = children[0]
    code_toks = children[1:]
    codes = tuple(str(tok) for tok in code_toks)
    return ast.GeoIp(
      codes=codes, call_index=-1, family="", span=_span(geoip_tok),
    )

  def range(self, children) -> ast.RangeLiteral:
    lo_tok, hi_tok = children
    lo = _parse_int(str(lo_tok))
    hi = _parse_int(str(hi_tok))
    return ast.RangeLiteral(lo=lo, hi=hi, span=_span(lo_tok))

  def proto_list(self, children) -> ast.ListLiteral:
    """`[tcp, icmp6]` proto-keyword list (Tier 2 enum_in)."""
    items = [
      ast.ProtoLiteral(
        proto=_PROTO_FROM_KEYWORD[str(tok)], span=_span(tok),
      )
      for tok in children
    ]
    return ast.ListLiteral(items=items, span=items[0].span)

  def rate_limit_call(self, children) -> ast.RateLimitCall:
    """`rate_limit(N, per=<field>)` as a Tier 2 condition primary."""
    threshold_tok, field_tok = children
    return ast.RateLimitCall(
      threshold=_parse_int(str(threshold_tok)),
      per_field=str(field_tok),
      span=_span(threshold_tok),
    )

  # --- Tier 2 statements ---

  def scalar_expr(self, children) -> ast.ScalarExpr:
    """Pass-through wrapper — the analyzer narrows the surface."""
    (node,) = children
    return node

  def assign_stmt(self, children) -> ast.AssignStmt:
    name_tok, rhs = children
    return ast.AssignStmt(
      name=str(name_tok), rhs=rhs, span=_span(name_tok)
    )

  def action_allow(self, children) -> ast.ActionStmt:
    (tok,) = children
    return ast.ActionStmt(action=ast.Action.ALLOW, span=_span(tok))

  def action_drop(self, children) -> ast.ActionStmt:
    (tok,) = children
    return ast.ActionStmt(action=ast.Action.DROP, span=_span(tok))

  def action_log(self, children) -> ast.ActionStmt:
    (tok,) = children
    return ast.ActionStmt(action=ast.Action.LOG, span=_span(tok))

  def action_count(self, children) -> ast.ActionStmt:
    count_tok, name_tok = children
    return ast.ActionStmt(
      action=ast.Action.COUNT,
      counter_name=str(name_tok),
      span=_span(count_tok),
    )

  def action_stmt(self, children) -> ast.ActionStmt:
    (stmt,) = children
    return stmt

  def statement(self, children) -> ast.Stmt:
    (stmt,) = children
    return stmt

  def elif_clause(self, children) -> tuple[ast.Condition, list[ast.Stmt]]:
    cond, body_block = children
    return cond, body_block

  def else_clause(self, children) -> list[ast.Stmt]:
    (body_block,) = children
    return body_block

  def if_stmt(self, children) -> ast.IfStmt:
    cond = children[0]
    body = children[1]
    elif_branches: list[tuple[ast.Condition, list[ast.Stmt]]] = []
    else_body: list[ast.Stmt] | None = None
    for child in children[2:]:
      if isinstance(child, tuple) and len(child) == 2:
        elif_branches.append(child)
      elif isinstance(child, list):
        else_body = child
    span = getattr(cond, "span", Span(line=1, column=1))
    return ast.IfStmt(
      cond=cond,
      body=body,
      elif_branches=elif_branches,
      else_body=else_body,
      span=span,
    )

  def block(self, children) -> list[ast.Stmt]:
    """A statement block — children are pre-transformed Stmt nodes."""
    return list(children)

  def function_def(self, children) -> ast.FunctionDef:
    """`def IDENTIFIER ( pkt ) : <block>` — the leading `def` keyword
    is a real Token in the children list (not filtered) since DEF was
    promoted to a named token to gate the FwlIndenter."""
    def_tok, name_tok, body_block = children
    return ast.FunctionDef(
      name=str(name_tok), body=body_block, span=_span(def_tok)
    )


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
