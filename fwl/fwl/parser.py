"""FWL parser — Lark grammar to typed AST."""

from pathlib import Path

from lark import Lark, Transformer, v_args

from fwl.ast_nodes import (
  Action,
  ActionType,
  AssignStmt,
  BinOp,
  BuiltinCall,
  ChainStmt,
  Cidr,
  Compare,
  CompOp,
  DefaultStmt,
  FieldAccess,
  FuncDef,
  IfStmt,
  InlineC,
  ListLit,
  MatchClause,
  NameRef,
  NumberLit,
  Program,
  RuleOption,
  RuleStmt,
  StringLit,
  UnaryOp,
)
from fwl.indent import FwlIndenter

_GRAMMAR_PATH = Path(__file__).parent / "grammar.lark"

_COMP_OPS = {
  "eq": CompOp.EQ,
  "neq": CompOp.NEQ,
  "gt": CompOp.GT,
  "lt": CompOp.LT,
  "gte": CompOp.GTE,
  "lte": CompOp.LTE,
  "in_op": CompOp.IN,
  "not_in": CompOp.NOT_IN,
}


@v_args(meta=True)
class FwlTransformer(Transformer):
  """Transform Lark parse tree into FWL AST nodes."""

  def start(self, meta, items):
    stmts = [i for i in items if i is not None]
    return Program(stmts=stmts)

  # Actions.
  def action_word(self, meta, items):
    return items[0]

  def drop(self, meta, _):
    return Action(ActionType.DROP, line=meta.line)

  def allow(self, meta, _):
    return Action(ActionType.ALLOW, line=meta.line)

  def pass_action(self, meta, _):
    return Action(ActionType.PASS, line=meta.line)

  # Tier 1 — declarative rules.
  def rule_stmt(self, meta, items):
    action = items[0].action
    matches = [i for i in items[1:] if isinstance(i, MatchClause)]
    return RuleStmt(action, matches, line=meta.line)

  def default_stmt(self, meta, items):
    return DefaultStmt(items[0].action, line=meta.line)

  def match_clause(self, meta, items):
    field_name = items[0].name if isinstance(items[0], NameRef) else str(items[0])
    values = items[1]
    return MatchClause(field_name, CompOp.EQ, values, line=meta.line)

  def match_values(self, meta, items):
    return list(items)

  def match_value(self, meta, items):
    return items[0]

  # Tier 2 — function definitions.
  def _name_str(self, item):
    """Extract plain string from a NameRef or Token."""
    if isinstance(item, NameRef):
      return item.name
    return str(item)

  def func_def(self, meta, items):
    decorator = items[0]
    name = self._name_str(items[1])
    param = self._name_str(items[2])
    body = items[3]
    hook = decorator[0]
    hook_args = decorator[1] if len(decorator) > 1 else []
    return FuncDef(
      name=name,
      param=param,
      hook=hook,
      hook_args=hook_args,
      body=body,
      line=meta.line,
    )

  def decorator(self, meta, items):
    name = self._name_str(items[0])
    args = items[1] if len(items) > 1 else []
    return (name, args)

  def func_args(self, meta, items):
    return [self._name_str(i) for i in items]

  def body(self, meta, items):
    # Flatten — if_stmt returns directly, simple_stmt may be
    # wrapped, filter out None and _NL artifacts.
    return [i for i in items if i is not None]

  def simple_stmt(self, meta, items):
    return items[0]

  # If/elif/else.
  def if_stmt(self, meta, items):
    condition = items[0]
    body = items[1]
    elifs = []
    else_body = None
    for item in items[2:]:
      if isinstance(item, tuple) and item[0] == "elif":
        elifs.append((item[1], item[2]))
      elif isinstance(item, list):
        else_body = item
    return IfStmt(condition, body, elifs, else_body, line=meta.line)

  def elif_clause(self, meta, items):
    return ("elif", items[0], items[1])

  def else_clause(self, meta, items):
    return items[0]

  def assign_stmt(self, meta, items):
    return AssignStmt(str(items[0]), items[1], line=meta.line)

  # Tier 3 — inline C.
  def inline_c(self, meta, items):
    raw = str(items[0])
    # Strip triple quotes.
    code = raw[3:-3]
    return InlineC(code, line=meta.line)

  # Chain.
  def chain_stmt(self, meta, items):
    return ChainStmt(self._name_str(items[0]), line=meta.line)

  # Built-in calls.
  def builtin_call(self, meta, items):
    name = self._name_str(items[0])
    args = []
    kwargs = {}
    if len(items) > 1 and items[1] is not None:
      for item in items[1]:
        if isinstance(item, tuple):
          kwargs[item[0]] = item[1]
        else:
          args.append(item)
    return BuiltinCall(name, args, kwargs, line=meta.line)

  def builtin_stmt(self, meta, items):
    return items[0]

  def call_args(self, meta, items):
    return list(items)

  def kwarg(self, meta, items):
    return (str(items[0]), items[1])

  def posarg(self, meta, items):
    return items[0]

  # Expressions.
  def or_expr(self, meta, items):
    result = items[0]
    for item in items[1:]:
      result = BinOp("or", result, item, line=meta.line)
    return result

  def and_expr(self, meta, items):
    result = items[0]
    for item in items[1:]:
      result = BinOp("and", result, item, line=meta.line)
    return result

  def not_expr(self, meta, items):
    return UnaryOp("not", items[0], line=meta.line)

  def cmp_expr(self, meta, items):
    if len(items) == 1:
      return items[0]
    left, op, right = items[0], items[1], items[2]
    return Compare(op, left, right, line=meta.line)

  def comp_op(self, meta, items):
    return _COMP_OPS[items[0].data]

  def eq(self, meta, _):
    return CompOp.EQ

  def neq(self, meta, _):
    return CompOp.NEQ

  def gt(self, meta, _):
    return CompOp.GT

  def lt(self, meta, _):
    return CompOp.LT

  def gte(self, meta, _):
    return CompOp.GTE

  def lte(self, meta, _):
    return CompOp.LTE

  def in_op(self, meta, _):
    return CompOp.IN

  def not_in(self, meta, _):
    return CompOp.NOT_IN

  # Atoms.
  def field_access(self, meta, items):
    parts = [self._name_str(i) for i in items]
    return FieldAccess(parts, line=meta.line)

  def list_literal(self, meta, items):
    return ListLit(list(items), line=meta.line)

  def cidr(self, meta, items):
    return Cidr(str(items[0]), int(items[1]), line=meta.line)

  def NUMBER(self, token):
    return NumberLit(int(token), line=token.line)

  def ESCAPED_STRING(self, token):
    return StringLit(str(token)[1:-1], line=token.line)

  def NAME(self, token):
    return NameRef(str(token), line=token.line)

  def IP_ADDR(self, token):
    return str(token)

  def RATIO(self, token):
    return str(token)


def _build_parser() -> Lark:
  """Build the Lark parser from the grammar file."""
  grammar_text = _GRAMMAR_PATH.read_text()
  return Lark(
    grammar_text,
    parser="earley",
    postlex=FwlIndenter(),
    propagate_positions=True,
    ambiguity="resolve",
  )


_parser = None


def parse(source: str) -> Program:
  """Parse FWL source code into an AST.

  Args:
    source: FWL source code string.

  Returns:
    Program AST node.
  """
  global _parser
  if _parser is None:
    _parser = _build_parser()
  # Ensure trailing newline for indenter.
  if not source.endswith("\n"):
    source += "\n"
  tree = _parser.parse(source)
  return FwlTransformer().transform(tree)
