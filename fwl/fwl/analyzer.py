"""Semantic analyzer for FWL AST.

Resolves which protocol layers each function needs, checks
protocol guard correctness, and allocates BPF maps.
"""

from dataclasses import dataclass, field

from fwl.ast_nodes import (
  Action,
  ActionType,
  AssignStmt,
  BuiltinCall,
  ChainStmt,
  Compare,
  BinOp,
  DefaultStmt,
  FieldAccess,
  FuncDef,
  IfStmt,
  InlineC,
  NameRef,
  Program,
  RuleStmt,
  UnaryOp,
)


# Which protocol layer each pkt field requires.
_FIELD_LAYERS = {
  # L3 fields — need Ethernet + IP parse.
  "src_ip": "ip",
  "dst_ip": "ip",
  "proto": "ip",
  "ttl": "ip",
  # L4 fields — need Ethernet + IP + TCP/UDP parse.
  "src_port": "l4",
  "dst_port": "l4",
  # TCP-specific — need full TCP parse.
  "tcp": "tcp",
  # UDP-specific.
  "udp": "udp",
}

# Protocol names mapped to IP protocol numbers.
PROTO_NUMBERS = {
  "tcp": 6,
  "udp": 17,
  "icmp": 1,
}


class AnalysisError(Exception):
  """Raised on semantic errors in FWL source."""

  def __init__(self, message: str, line: int = 0):
    self.line = line
    super().__init__(f"line {line}: {message}" if line else message)


@dataclass
class MapInfo:
  """Metadata for a BPF map the compiler needs to generate."""
  name: str
  map_type: str
  key_type: str
  value_type: str
  max_entries: int = 1024


@dataclass
class CounterInfo:
  """Named counter allocated in the counters array."""
  name: str
  index: int


@dataclass
class AnalyzedFunc:
  """Analysis result for a single @xdp / @tc function."""
  func: FuncDef
  needs_eth: bool = True
  needs_ip: bool = False
  needs_l4: bool = False
  needs_tcp: bool = False
  needs_udp: bool = False
  needs_inline_c: bool = False
  maps: list[MapInfo] = field(default_factory=list)
  counters: list[CounterInfo] = field(default_factory=list)
  tail_calls: list[str] = field(default_factory=list)

  @property
  def needs_any_l4(self) -> bool:
    """True if any L4 parsing is needed."""
    return self.needs_l4 or self.needs_tcp or self.needs_udp


@dataclass
class AnalysisResult:
  """Full analysis result for a .fw file."""
  funcs: list[AnalyzedFunc] = field(default_factory=list)
  rules: list[RuleStmt] = field(default_factory=list)
  default_action: ActionType = ActionType.PASS
  maps: list[MapInfo] = field(default_factory=list)
  errors: list[str] = field(default_factory=list)


def _collect_field_accesses(node, accesses: list[FieldAccess]):
  """Walk an expression tree collecting FieldAccess nodes."""
  if isinstance(node, FieldAccess):
    accesses.append(node)
  elif isinstance(node, Compare):
    _collect_field_accesses(node.left, accesses)
    _collect_field_accesses(node.right, accesses)
  elif isinstance(node, BinOp):
    _collect_field_accesses(node.left, accesses)
    _collect_field_accesses(node.right, accesses)
  elif isinstance(node, UnaryOp):
    _collect_field_accesses(node.operand, accesses)
  elif isinstance(node, BuiltinCall):
    for arg in node.args:
      _collect_field_accesses(arg, accesses)
    for val in node.kwargs.values():
      _collect_field_accesses(val, accesses)


def _collect_from_body(body: list, accesses: list[FieldAccess]):
  """Walk a function body collecting all field accesses."""
  for stmt in body:
    if isinstance(stmt, IfStmt):
      _collect_field_accesses(stmt.condition, accesses)
      _collect_from_body(stmt.body, accesses)
      for elif_cond, elif_body in stmt.elifs:
        _collect_field_accesses(elif_cond, accesses)
        _collect_from_body(elif_body, accesses)
      if stmt.else_body:
        _collect_from_body(stmt.else_body, accesses)
    elif isinstance(stmt, BuiltinCall):
      _collect_field_accesses(stmt, accesses)
    elif isinstance(stmt, Action):
      pass
    elif isinstance(stmt, AssignStmt):
      _collect_field_accesses(stmt.value, accesses)


def _resolve_layers(accesses: list[FieldAccess], af: AnalyzedFunc):
  """Determine which protocol layers to parse from field accesses."""
  for fa in accesses:
    if fa.root != "pkt" and fa.root != "msg":
      continue
    for part in fa.chain:
      layer = _FIELD_LAYERS.get(part)
      if layer == "ip":
        af.needs_ip = True
      elif layer == "l4":
        af.needs_ip = True
        af.needs_l4 = True
      elif layer == "tcp":
        af.needs_ip = True
        af.needs_l4 = True
        af.needs_tcp = True
      elif layer == "udp":
        af.needs_ip = True
        af.needs_l4 = True
        af.needs_udp = True


def _collect_builtins_from_expr(node, af: AnalyzedFunc,
                               counter_idx: list[int]):
  """Walk an expression tree collecting built-in calls."""
  if isinstance(node, BuiltinCall):
    _handle_builtin(node, af, counter_idx)
  elif isinstance(node, Compare):
    _collect_builtins_from_expr(node.left, af, counter_idx)
    _collect_builtins_from_expr(node.right, af, counter_idx)
  elif isinstance(node, BinOp):
    _collect_builtins_from_expr(node.left, af, counter_idx)
    _collect_builtins_from_expr(node.right, af, counter_idx)
  elif isinstance(node, UnaryOp):
    _collect_builtins_from_expr(node.operand, af, counter_idx)


def _collect_builtins(body: list, af: AnalyzedFunc, counter_idx: list[int]):
  """Walk body collecting built-in calls and allocating maps."""
  for stmt in body:
    if isinstance(stmt, BuiltinCall):
      _handle_builtin(stmt, af, counter_idx)
    elif isinstance(stmt, IfStmt):
      _collect_builtins_from_expr(stmt.condition, af, counter_idx)
      _collect_builtins(stmt.body, af, counter_idx)
      for elif_cond, elif_body in stmt.elifs:
        _collect_builtins_from_expr(elif_cond, af, counter_idx)
        _collect_builtins(elif_body, af, counter_idx)
      if stmt.else_body:
        _collect_builtins(stmt.else_body, af, counter_idx)
    elif isinstance(stmt, InlineC):
      af.needs_inline_c = True
    elif isinstance(stmt, ChainStmt):
      af.tail_calls.append(stmt.target)
    elif isinstance(stmt, RuleStmt):
      for opt in stmt.options:
        if opt.kind == "count" and opt.args:
          name = opt.args[0]
          af.counters.append(CounterInfo(name, counter_idx[0]))
          counter_idx[0] += 1


def _handle_builtin(call: BuiltinCall, af: AnalyzedFunc,
                    counter_idx: list[int]):
  """Process a built-in function call, allocating maps as needed."""
  if call.name == "rate_limit":
    per_field = call.kwargs.get("per")
    key_type = "__u32"
    if isinstance(per_field, NameRef) and per_field.name == "src_ip":
      key_type = "__u32"
    af.maps.append(MapInfo(
      name=f"rate_{call.name}_{len(af.maps)}",
      map_type="BPF_MAP_TYPE_HASH",
      key_type=key_type,
      value_type="struct RateState",
      max_entries=65536,
    ))
  elif call.name == "count":
    if call.args and isinstance(call.args[0], NameRef):
      name = call.args[0].name
    else:
      name = f"counter_{counter_idx[0]}"
    af.counters.append(CounterInfo(name, counter_idx[0]))
    counter_idx[0] += 1
  elif call.name == "geoip":
    af.maps.append(MapInfo(
      name="geoip",
      map_type="BPF_MAP_TYPE_HASH",
      key_type="__u32",
      value_type="struct GeoValue",
      max_entries=1000000,
    ))
  elif call.name == "conntrack":
    af.maps.append(MapInfo(
      name="conntrack",
      map_type="BPF_MAP_TYPE_HASH",
      key_type="struct ConnKey",
      value_type="struct ConnValue",
      max_entries=65536,
    ))


def _analyze_func(func: FuncDef) -> AnalyzedFunc:
  """Analyze a single function definition."""
  af = AnalyzedFunc(func=func)

  # Collect all pkt field accesses.
  accesses: list[FieldAccess] = []
  _collect_from_body(func.body, accesses)
  # Also check conditions for field accesses.
  _resolve_layers(accesses, af)

  # Collect built-in calls and allocate maps/counters.
  counter_idx = [1]  # 0 reserved for total.
  _collect_builtins(func.body, af, counter_idx)

  # If any tail calls, need a prog array map.
  if af.tail_calls:
    af.maps.append(MapInfo(
      name="prog_array",
      map_type="BPF_MAP_TYPE_PROG_ARRAY",
      key_type="__u32",
      value_type="__u32",
      max_entries=32,
    ))

  return af


def analyze(program: Program) -> AnalysisResult:
  """Run semantic analysis on a parsed FWL program.

  Args:
    program: Parsed AST.

  Returns:
    AnalysisResult with resolved layers, maps, and counters.
  """
  result = AnalysisResult()

  for stmt in program.stmts:
    if isinstance(stmt, FuncDef):
      af = _analyze_func(stmt)
      result.funcs.append(af)
      result.maps.extend(af.maps)
    elif isinstance(stmt, RuleStmt):
      result.rules.append(stmt)
    elif isinstance(stmt, DefaultStmt):
      result.default_action = stmt.action

  return result
