"""Per-zone rule metadata for the bundle manifest.

An operator asking "what is this box enforcing right now" has, until
now, had to read the `.fw` file and hope it matches. `fd` holds
compiled BPF objects; the bundle manifest carried per-zone topology and
no rule metadata; the daemon has never seen the policy text. Anything a
rule table could have shown was re-derived from the bundle directory,
which is a claim about the disk.

This module is the compiler half of closing that. It turns each `@xdp`
block's analyzed rule list into a JSON-serialisable description that
goes into `manifest.json` beside the zone's `object`, so the loader
captures it in the same call that opens the object — exactly the way
the `// fwl_counter_table:` block is captured beside the counter map.

**The renderer is total, and where it is not, it says so.** Every AST
node this module knows how to write is written; anything it does not
know produces a rule marked unrenderable with a named reason, never a
`repr()` and never a silently shortened match. A partial answer that
states what it omits is a usable answer; one that looks complete and is
not is the defect this project keeps finding. `test_rulemeta.py` walks
the AST's own type unions and fails when a node type is added without a
rendering, so the omission is caught at build time rather than on a
box.

**What is deliberately not here.**

- **Tier 2 zones.** A zone whose policy is `def policy(pkt): ...` has
  no rule list at all — `ZoneProgram.rules` is empty and the policy is
  a statement tree. Such a zone is reported as `form: "function"` with
  no rules, which is a different answer from "this zone has no rules".
- **`chain` stage names.** The parser keeps a `chain` marker's position
  (as a rule-index boundary) and discards its name before anything
  downstream can see it, so a stage label cannot be recovered here.
  The rules themselves are all present and in order; only the stage
  headings are missing.
- **Helper bodies.** Tier 1 conditions cannot call a helper, so a Tier
  1 rule list is self-contained. A Tier 2 zone's `CallStmt` can, and
  that is part of why Tier 2 gets no rule list rather than a partial
  one.
"""
from __future__ import annotations

import hashlib
from typing import Any

from . import ast


class Unrenderable(Exception):
  """An AST node this module has no source form for.

  Carries the node's type name so the manifest can say what it could
  not write rather than writing something that looks like FWL and is
  not.
  """
  def __init__(self, node: Any) -> None:
    self.node_type = type(node).__name__
    super().__init__(f"no rendering for {self.node_type}")


def _ipv4_str(value: int) -> str:
  """32-bit int back to dotted-quad."""
  return ".".join(str((value >> shift) & 0xFF)
                  for shift in (24, 16, 8, 0))


def _ipv6_str(value: int) -> str:
  """128-bit int back to an RFC 5952-shaped address.

  Not the canonical compressor — the longest run of zero groups is
  collapsed, which is what RFC 5952 asks for and is enough to
  recognise an address by.
  """
  groups = [(value >> shift) & 0xFFFF
            for shift in range(112, -1, -16)]
  best_start, best_len = -1, 0
  run_start, run_len = -1, 0
  for i, g in enumerate(groups):
    if g == 0:
      if run_start < 0:
        run_start, run_len = i, 0
      run_len += 1
      if run_len > best_len:
        best_start, best_len = run_start, run_len
    else:
      run_start, run_len = -1, 0
  parts = [format(g, "x") for g in groups]
  if best_len < 2:
    return ":".join(parts)
  head = ":".join(parts[:best_start])
  tail = ":".join(parts[best_start + best_len:])
  return f"{head}::{tail}"


def render_operand(op: ast.Operand) -> str:
  """The source form of an operand.

  Raises Unrenderable for any operand kind this build has no form for.
  """
  if isinstance(op, ast.ProtoLiteral):
    return op.proto.value
  if isinstance(op, ast.IntLiteral):
    return str(op.value)
  if isinstance(op, ast.IPv4Literal):
    return _ipv4_str(op.value)
  if isinstance(op, ast.CidrLiteral):
    return f"{_ipv4_str(op.prefix)}/{op.bits}"
  if isinstance(op, ast.Ipv6Literal):
    return _ipv6_str(op.value)
  if isinstance(op, ast.Ipv6CidrLiteral):
    return f"{_ipv6_str(op.prefix)}/{op.bits}"
  if isinstance(op, ast.RangeLiteral):
    return f"{op.lo}..{op.hi}"
  if isinstance(op, (ast.ListLiteral, ast.CidrListLiteral,
                     ast.Ipv6CidrListLiteral)):
    inner = ", ".join(render_operand(i) for i in op.items)
    return f"[{inner}]"
  if isinstance(op, ast.GeoIp):
    return f"geoip({', '.join(op.codes)})"
  raise Unrenderable(op)


def render_condition(node: ast.Condition) -> str:
  """The source form of a condition tree.

  Raises Unrenderable for any node kind this build has no form for.
  """
  if isinstance(node, ast.Comparison):
    return (f"{node.field.name} {node.op} "
            f"{render_operand(node.operand)}")
  if isinstance(node, ast.BoolField):
    return node.field.name
  if isinstance(node, ast.NotOp):
    return f"not ({render_condition(node.inner)})"
  if isinstance(node, ast.AndOp):
    return "(" + " and ".join(
      render_condition(c) for c in node.operands) + ")"
  if isinstance(node, ast.OrOp):
    return "(" + " or ".join(
      render_condition(c) for c in node.operands) + ")"
  if isinstance(node, ast.ConntrackStateCompare):
    states = [s.value for s in node.states]
    if node.op == "in":
      return f"{ast.FIELD_CT_STATE} in [{', '.join(states)}]"
    return f"{ast.FIELD_CT_STATE} {node.op} {states[0]}"
  if isinstance(node, ast.ZoneCompare):
    if node.op == "in":
      return f"{ast.FIELD_ZONE} in [{', '.join(node.zones)}]"
    return f"{ast.FIELD_ZONE} {node.op} {node.zones[0]}"
  if isinstance(node, ast.CountCompare):
    return (f"count({node.call.counter_name}) {node.op} "
            f"{render_operand(node.operand)}")
  raise Unrenderable(node)


def unwrap(text: str) -> str:
  """Drop one fully-enclosing pair of parentheses.

  `render_condition` parenthesises every `and`/`or` so nesting is
  unambiguous, which leaves a whole-rule guard wrapped in a pair that
  says nothing: `drop if (a and b)`. The outermost pair is dropped
  only when it really does enclose the whole expression — `(a) and
  (b)` keeps both, because removing the first `(` there would change
  what the text means.
  """
  if len(text) < 2 or text[0] != "(" or text[-1] != ")":
    return text
  depth = 0
  for i, c in enumerate(text):
    if c == "(":
      depth += 1
    elif c == ")":
      depth -= 1
      if depth == 0 and i != len(text) - 1:
        return text
  return text[1:-1]


def render_modifier(mod: ast.RateLimit) -> str:
  """The source form of a `limited by rate_limit(...)` modifier."""
  scope = ""
  if mod.scope is not ast.RlScope.ZONE:
    scope = f", scope={mod.scope.value}"
  return (f"rate_limit({mod.threshold}, per={mod.per_field}"
          f"{scope})")


def render_action(rule: ast.Rule) -> str:
  """The source form of a rule's action, target included.

  `redirect to wan` and `dnat to 10.0.0.5:8080` are one thing to an
  operator; splitting the verb from its target across two columns is
  how a redirect to the wrong zone stops being visible.
  """
  action = rule.action
  if action is ast.Action.COUNT and rule.counter_name:
    return f"count {rule.counter_name}"
  if action is ast.Action.LOG:
    if rule.log_sample:
      return f"log(sample={rule.log_sample})"
    return "log"
  if action is ast.Action.REDIRECT and rule.redirect_zone:
    return f"redirect to {rule.redirect_zone}"
  if action is ast.Action.SNAT and rule.nat_addr is not None:
    return f"snat to {_ipv4_str(rule.nat_addr)}"
  if action is ast.Action.DNAT and rule.nat_addr is not None:
    target = _ipv4_str(rule.nat_addr)
    if rule.nat_port is not None:
      return f"dnat to {target}:{rule.nat_port}"
    return f"dnat to {target}"
  return action.value


def rule_entry(index: int, rule: ast.Rule) -> dict:
  """One rule as the manifest carries it.

  `log_rule_index` is named for what it is: the index the emitter
  stamps into this rule's log events, which is the only thing it may
  legitimately be joined against. It is deliberately not called
  `index`, because a bare index next to a list of counters is how the
  retired `kGetRules` came to pair every value with the wrong rule.
  """
  entry: dict[str, Any] = {
    "log_rule_index": index,
    "line": rule.span.line,
    "action": render_action(rule),
    "terminal": rule.action in ast.TERMINAL_ACTIONS,
    "renderable": True,
  }
  omitted = []
  match = ""
  if rule.condition is not None:
    try:
      match = unwrap(render_condition(rule.condition))
    except Unrenderable as exc:
      entry["renderable"] = False
      omitted.append(
        f"this build cannot write the source form of a "
        f"{exc.node_type} condition node")
  entry["match"] = match
  entry["guarded"] = rule.condition is not None
  limit = ""
  if rule.modifier is not None:
    limit = render_modifier(rule.modifier)
  entry["rate_limit"] = limit
  if omitted:
    entry["omitted"] = omitted
  # The whole statement on one line, which is what an operator scans.
  text = entry["action"]
  if entry["guarded"]:
    text += f" if {match}" if entry["renderable"] else " if <?>"
  if limit:
    text += f" limited by {limit}"
  entry["text"] = text
  return entry


def zone_rules(zp: ast.ZoneProgram) -> dict:
  """The `rules` object for one `@xdp` block's manifest entry.

  `form` is the honest discriminator. `rules` means the list below is
  this zone's whole policy in order. `function` means the zone is
  Tier 2 and has no rule list to give — which is a different finding
  from a zone whose rule list is empty, and a consumer that renders
  them the same way is back to one blank screen for two states.
  """
  if zp.function is not None:
    return {
      "form": "function",
      "detail": (
        f"this zone's policy is the Tier 2 function "
        f"`{zp.function.name}`, a statement tree rather than a rule "
        f"list; the compiler emits no per-rule metadata for it"),
      "rules": [],
      "default": None,
    }
  entries = [rule_entry(i, r) for i, r in enumerate(zp.rules)]
  # A zone with no `default` line falls through to XDP_PASS — it
  # ALLOWS whatever reaches the end of the block. Reporting that as
  # "no default" would put the most consequential line of a policy on
  # the screen as a blank, so the effective action is always named and
  # `explicit` says whether the author wrote it.
  if zp.default is not None:
    default = {
      "action": zp.default.action.value,
      "line": zp.default.span.line,
      "explicit": True,
    }
  else:
    default = {
      "action": "allow",
      "line": 0,
      "explicit": False,
    }
  out: dict[str, Any] = {
    "form": "rules",
    "detail": "",
    "rules": entries,
    "default": default,
  }
  # `chain` boundaries survive as rule indices; the marker's NAME does
  # not survive parsing, so the stage headings cannot be rebuilt here.
  # Said out loud rather than left as a gap in the table.
  if zp.chain_boundaries:
    out["stage_boundaries"] = list(zp.chain_boundaries)
    out["detail"] = (
      "this zone is split into tail-call stages at the rule indices "
      "in stage_boundaries; the `chain` labels are not retained by "
      "the parser and are not reported")
  return out


def source_identity(source_path: str, text: str) -> dict:
  """The identity of the policy text this bundle was compiled from.

  The digest is over the source bytes as compiled. A box can then be
  asked whether the file on disk is still the one in the packet path,
  and answer with a fact rather than with a hope — a `.fw` edited and
  never reloaded reads exactly like one that is live, and that is the
  state an operator most needs told.
  """
  digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
  name = source_path.rsplit("/", 1)[-1]
  return {
    "path": source_path,
    "name": name,
    "sha256": digest,
    "bytes": len(text.encode("utf-8")),
  }
