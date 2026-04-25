"""AST node types for FWL v0.1.

One dataclass per spec production. The shape of these nodes is the
contract between the parser, the analyzer, the interpreter, and the
emitter — change cautiously.

Spec reference: docs/FWL_V01_SPEC.md grammar section.

Phase 0 covers only the smallest possible surface: a hook declaration
followed by a single unconditional `allow` rule. New node types and
fields land per construct as the language grows.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum

from .errors import Span


class Action(Enum):
  """Terminal and non-terminal action verbs.

  v0.1 actions per FWL_V01_SPEC.md:78. Phase 0 ships only ALLOW and
  DROP; LOG and COUNT are reserved enum members but not yet wired
  through parser/interpreter/emitter.
  """
  ALLOW = "allow"
  DROP = "drop"


@dataclass(frozen=True)
class Rule:
  """A single firewall rule.

  v0.1 grammar: `<action> [if <condition>] [<modifier>]`. Phase 0
  supports only the bare `<action>` form — no condition, no modifier.
  """
  action: Action
  span: Span


@dataclass(frozen=True)
class Hook:
  """The `@xdp(<interface>)` declaration.

  v0.1 requires exactly one hook declaration per program
  (FWL_V01_SPEC.md:58).
  """
  interface: str
  span: Span


@dataclass(frozen=True)
class Program:
  """A complete FWL program: hook + ordered rules.

  Per the spec grammar (`program = hook_decl { rule } [ default_rule ]`)
  zero rules are valid when a `default` rule is present; Phase 0
  doesn't model default rules yet.
  """
  hook: Hook
  rules: list[Rule] = field(default_factory=list)
