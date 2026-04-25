"""AST interpreter — independent oracle for the verification loop.

Walks the AST against a parsed packet (a dict of decoded fields)
and returns the XDP action the program would take. Implementation
must not share any code with the emitter beyond AST node definitions
— the whole point is independent evaluation.

Spec reference: docs/FWL_V01_SPEC.md, methodology reference:
docs/F_DEVELOPMENT_METHODOLOGY.md:307-311.
"""
from __future__ import annotations
from enum import Enum
from typing import Any

from . import ast


class XdpAction(Enum):
  """The XDP return values an FWL program can produce."""
  PASS = "XDP_PASS"
  DROP = "XDP_DROP"


_ACTION_TO_XDP = {
  ast.Action.ALLOW: XdpAction.PASS,
  ast.Action.DROP: XdpAction.DROP,
}


def evaluate(program: ast.Program, packet: dict[str, Any]) -> XdpAction:
  """Run `program` against `packet` and return the resulting XDP action.

  Rules execute top to bottom; first matching rule's action wins.
  After all rules, the explicit default (if present) fires; otherwise
  the implicit XDP_PASS per FWL_V01_SPEC.md:70 / :116.
  """
  for rule in program.rules:
    if rule.condition is None or _eval(rule.condition, packet):
      return _ACTION_TO_XDP[rule.action]
  if program.default is not None:
    return _ACTION_TO_XDP[program.default.action]
  return XdpAction.PASS


def _eval(node: ast.Condition, packet: dict[str, Any]) -> bool:
  """Evaluate a condition node against a decoded packet."""
  if isinstance(node, ast.Comparison):
    return _eval_comparison(node, packet)
  if isinstance(node, ast.BoolField):
    return bool(packet.get(_field_key(node.field.name), False))
  if isinstance(node, ast.NotOp):
    return not _eval(node.inner, packet)
  if isinstance(node, ast.AndOp):
    for child in node.operands:
      if not _eval(child, packet):
        return False
    return True
  if isinstance(node, ast.OrOp):
    for child in node.operands:
      if _eval(child, packet):
        return True
    return False
  raise NotImplementedError(
    f"interpreter: unsupported node {type(node).__name__}"
  )


def _field_key(name: str) -> str:
  """Map an AST field name to the packet-dict key that pkt.py emits."""
  return _FIELD_TO_KEY[name]


_FIELD_TO_KEY = {
  ast.FIELD_PROTO: "proto",
  ast.FIELD_SRC_IP: "src_ip",
  ast.FIELD_DST_IP: "dst_ip",
  ast.FIELD_SRC_PORT: "src_port",
  ast.FIELD_DST_PORT: "dst_port",
  ast.FIELD_TCP_SYN: "syn",
  ast.FIELD_TCP_ACK: "ack",
}


def _packet_value(field_name: str, packet: dict[str, Any]) -> Any:
  """Read a field's runtime value from the decoded packet dict."""
  return packet.get(_field_key(field_name))


def _ipv4_to_int(addr: str | int) -> int:
  """Coerce a packet's src_ip/dst_ip to a 32-bit integer."""
  if isinstance(addr, int):
    return addr
  parts = addr.split(".")
  value = 0
  for part in parts:
    value = (value << 8) | int(part)
  return value


def _eval_comparison(cmp: ast.Comparison, packet: dict[str, Any]) -> bool:
  """Evaluate a `field op operand` comparison.

  Returns False when the field is absent from the packet (e.g. asking
  for a port on an ICMP packet) — matching the spec's "rule does not
  match" semantics for missing fields.
  """
  actual = _packet_value(cmp.field.name, packet)
  if actual is None:
    return False

  field_name = cmp.field.name
  op = cmp.op
  operand = cmp.operand

  # Protocol enum
  if field_name == ast.FIELD_PROTO:
    expected = operand.proto.value  # type: ignore[union-attr]
    if op == "==":
      return actual == expected
    if op == "!=":
      return actual != expected

  # IP fields
  if field_name in ast.IP_FIELDS:
    actual_int = _ipv4_to_int(actual)
    if op == "==":
      return actual_int == operand.value  # type: ignore[union-attr]
    if op == "!=":
      return actual_int != operand.value  # type: ignore[union-attr]
    if op == "in":
      return _ip_in_set(actual_int, operand)

  # Port fields
  if field_name in ast.PORT_FIELDS:
    actual_int = int(actual)
    if op == "==":
      return actual_int == operand.value  # type: ignore[union-attr]
    if op == "!=":
      return actual_int != operand.value  # type: ignore[union-attr]
    if op == "<":
      return actual_int < operand.value   # type: ignore[union-attr]
    if op == ">":
      return actual_int > operand.value   # type: ignore[union-attr]
    if op == "<=":
      return actual_int <= operand.value  # type: ignore[union-attr]
    if op == ">=":
      return actual_int >= operand.value  # type: ignore[union-attr]
    if op == "in":
      return _port_in_set(actual_int, operand)

  raise NotImplementedError(
    f"interpreter: comparison {field_name} {op} not supported"
  )


def _ip_in_set(ip_value: int, operand: ast.Operand) -> bool:
  """Membership test for an IP field's `in` operator."""
  if isinstance(operand, ast.CidrLiteral):
    return _cidr_match(ip_value, operand)
  if isinstance(operand, ast.CidrListLiteral):
    return any(_cidr_match(ip_value, c) for c in operand.items)
  if isinstance(operand, ast.ListLiteral):
    for item in operand.items:
      if isinstance(item, ast.IPv4Literal) and item.value == ip_value:
        return True
    return False
  raise TypeError(f"unexpected operand for ip in: {type(operand).__name__}")


def _cidr_match(ip_value: int, cidr: ast.CidrLiteral) -> bool:
  """True iff `ip_value` falls within the CIDR block."""
  if cidr.bits == 0:
    return True
  mask = ((1 << cidr.bits) - 1) << (32 - cidr.bits)
  return (ip_value & mask) == cidr.prefix


def _port_in_set(port_value: int, operand: ast.Operand) -> bool:
  """Membership test for a port field's `in` operator."""
  if isinstance(operand, ast.RangeLiteral):
    return operand.lo <= port_value <= operand.hi
  if isinstance(operand, ast.ListLiteral):
    for item in operand.items:
      if isinstance(item, ast.IntLiteral) and item.value == port_value:
        return True
    return False
  raise TypeError(f"unexpected operand for port in: {type(operand).__name__}")
