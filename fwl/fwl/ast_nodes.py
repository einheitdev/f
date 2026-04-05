"""AST node definitions for FWL."""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional


class ActionType(Enum):
  """Firewall verdict."""
  DROP = auto()
  ALLOW = auto()
  PASS = auto()


class CompOp(Enum):
  """Comparison operators."""
  EQ = auto()
  NEQ = auto()
  GT = auto()
  LT = auto()
  GTE = auto()
  LTE = auto()
  IN = auto()
  NOT_IN = auto()


class Proto(Enum):
  """Known protocol names."""
  TCP = 6
  UDP = 17
  ICMP = 1
  ANY = 0


# ================================================================
# Expression nodes
# ================================================================

@dataclass
class NumberLit:
  """Integer literal."""
  value: int
  line: int = 0


@dataclass
class StringLit:
  """String literal."""
  value: str
  line: int = 0


@dataclass
class NameRef:
  """Bare name reference (variable, protocol name, etc.)."""
  name: str
  line: int = 0


@dataclass
class FieldAccess:
  """Dotted field access: pkt.dst_port, pkt.tcp.syn."""
  parts: list[str]
  line: int = 0

  @property
  def root(self) -> str:
    """First element (usually 'pkt')."""
    return self.parts[0]

  @property
  def chain(self) -> list[str]:
    """Everything after the root."""
    return self.parts[1:]


@dataclass
class Cidr:
  """CIDR notation: 10.0.0.0/8."""
  addr: str
  prefix: int
  line: int = 0


@dataclass
class ListLit:
  """List literal: ["RU", "CN"]."""
  items: list
  line: int = 0


@dataclass
class BinOp:
  """Binary logical: and, or."""
  op: str
  left: object
  right: object
  line: int = 0


@dataclass
class UnaryOp:
  """Unary logical: not."""
  op: str
  operand: object
  line: int = 0


@dataclass
class Compare:
  """Comparison: pkt.dst_port == 80."""
  op: CompOp
  left: object
  right: object
  line: int = 0


@dataclass
class BuiltinCall:
  """Built-in function call: rate_limit(10, per=src_ip)."""
  name: str
  args: list = field(default_factory=list)
  kwargs: dict = field(default_factory=dict)
  line: int = 0


# ================================================================
# Statement nodes
# ================================================================

@dataclass
class Action:
  """Firewall verdict: drop, allow, pass."""
  action: ActionType
  line: int = 0


@dataclass
class MatchClause:
  """Single match condition in a declarative rule."""
  field: str
  op: CompOp
  values: list
  line: int = 0


@dataclass
class RuleOption:
  """Rule option: count, log."""
  kind: str
  args: list = field(default_factory=list)
  line: int = 0


@dataclass
class RuleStmt:
  """Tier 1 declarative rule: allow dst_port 80 proto tcp."""
  action: ActionType
  matches: list[MatchClause]
  options: list[RuleOption] = field(default_factory=list)
  line: int = 0


@dataclass
class DefaultStmt:
  """Default action: default drop."""
  action: ActionType
  line: int = 0


@dataclass
class IfStmt:
  """If/elif/else block."""
  condition: object
  body: list
  elifs: list[tuple] = field(default_factory=list)
  else_body: Optional[list] = None
  line: int = 0


@dataclass
class AssignStmt:
  """Variable assignment: x = expr."""
  name: str
  value: object
  line: int = 0


@dataclass
class InlineC:
  """Tier 3 raw C escape: inline_c triple-quoted string."""
  code: str
  line: int = 0


@dataclass
class ChainStmt:
  """Tail call to another stage: chain dpi."""
  target: str
  line: int = 0


# ================================================================
# Top-level nodes
# ================================================================

@dataclass
class FuncDef:
  """Tier 2 function: @xdp(eth0) def firewall(pkt): ..."""
  name: str
  param: str
  hook: str
  hook_args: list[str] = field(default_factory=list)
  body: list = field(default_factory=list)
  line: int = 0


@dataclass
class Program:
  """Root AST node — a complete .fw file."""
  stmts: list = field(default_factory=list)
