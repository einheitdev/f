#!/usr/bin/env python3
"""FWL test corpus generator via Claude Code.

Generates `.pkt` test files by calling Claude through the
claude-code-sdk, which authenticates via the user's existing
Claude Code session (subscription) — no API key required.

Each category targets a specific area of the FWL v0.1 spec.

Usage examples:
  fwl-test-agent --list-categories
  fwl-test-agent --category field_operators --count 20
  fwl-test-agent --category all --count 10
  fwl-test-agent --category compile_errors --count 15 --output tests/generated/
  fwl-test-agent --category protocol_guards --count 12 --auto-test

Generated cases land in --output (default tests/generated/) for
human review per the methodology — they do NOT go straight into
the regression corpus.
"""
from __future__ import annotations
import argparse
import asyncio
import re
import subprocess
import sys
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

try:
  from claude_code_sdk import (
    AssistantMessage,
    ClaudeCodeOptions,
    ResultMessage,
    TextBlock,
    query,
  )
  from claude_code_sdk._internal import client as _sdk_client
  from claude_code_sdk._internal import message_parser
  from claude_code_sdk._internal.message_parser import MessageParseError
  from claude_code_sdk.types import StreamEvent
except ImportError:
  print(
    "claude-code-sdk not installed. Run: pip install claude-code-sdk",
    file=sys.stderr,
  )
  sys.exit(1)


# Patch the SDK message parser to swallow unknown event types
# (rate_limit_event, etc.) instead of crashing the stream. Same
# workaround takt uses — these informational events leak from the
# claude CLI's protocol but the SDK doesn't model them. Only catches
# MessageParseError so real bugs still propagate.
_original_parse = message_parser.parse_message


def _patched_parse(data):
  """Wrap parse_message to return StreamEvent for unknown types."""
  try:
    return _original_parse(data)
  except MessageParseError:
    return StreamEvent(
      uuid=data.get("uuid", ""),
      session_id=data.get("session_id", ""),
      event=data,
      parent_tool_use_id=data.get("parent_tool_use_id"),
    )


message_parser.parse_message = _patched_parse
_sdk_client.parse_message = _patched_parse

try:
  import yaml
except ImportError:
  print("pyyaml not installed. Run: pip install pyyaml", file=sys.stderr)
  sys.exit(1)


# Default to Opus for intelligence-sensitive work — generating
# spec-conforming cases that exercise subtle protocol-guard semantics
# and compute correct expected.bpf_action values requires the strongest
# model the user's subscription provides. Override with --model if you
# want to trade quality for quota.
DEFAULT_MODEL = "claude-opus-4-7"


# Path defaults resolved from this script's location so the agent works
# regardless of the user's CWD.
_SCRIPT_DIR = Path(__file__).resolve().parent
_FWL_DIR = _SCRIPT_DIR.parent.parent           # fwl/ (package repo)
_REPO_ROOT = _FWL_DIR.parent                   # f/ (project root)

DEFAULT_FWL_SPEC_PATH = _REPO_ROOT / "docs" / "FWL_V01_SPEC.md"
DEFAULT_PKT_SPEC_PATH = _REPO_ROOT / "docs" / "PKT_V01_SPEC.md"
DEFAULT_CORPUS_DIR = _FWL_DIR / "tests" / "corpus"
DEFAULT_OUTPUT_DIR = _FWL_DIR / "tests" / "generated"


# Brief format reminder injected into every prompt. The authoritative
# .pkt spec is the system prompt; this block summarizes the surface
# for the model and pins the v0.1 implementation defaults.
PKT_FORMAT_REMINDER = textwrap.dedent("""\
  Each test case is a YAML document in a .pkt file. Required fields:
    name (string), source_fw (string), test_packet (mapping with
    `builder`), expected (mapping). Optional: state (mapping with
    `rate_limit`).

  Builder mini-language — exactly three constructors:
    tcp(src_ip="x.x.x.x", dst_ip="x.x.x.x", src_port=N, dst_port=N,
        syn=true|false, ack=true|false)
    udp(src_ip="x.x.x.x", dst_ip="x.x.x.x", src_port=N, dst_port=N)
    icmp(src_ip="x.x.x.x", dst_ip="x.x.x.x")

  All builder fields are optional. Defaults the loader fills in:
    src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=12345,
    dst_port=80 (tcp) or 53 (udp), syn=false, ack=false.

  No raw_ip(), no truncate_to, no counter_changes, no log_events —
  these are spec-defined but not yet implemented in the loader, so
  cases using them will fail to load. Stick to the shipped surface.

  expected.bpf_action: "allow" | "drop" (omit when compiles: false)
  expected.compiles: true (default) | false

  state block (only for rate_limit cases):
    state:
      rate_limit:
        <rule_index>:        # 0-based position of the rate_limit rule
          "<bucket_key>": N  # IP as dotted-quad string for src_ip/dst_ip
                             # integer for src_port/dst_port

  Output ONLY the YAML documents, separated by `---` on its own line.
  No markdown fences, no commentary, no preamble.
""")


CATEGORIES: dict[str, dict] = {}


def category(name: str, description: str):
  """Decorator to register a prompt-building function under `name`."""
  def decorator(fn: Callable):
    CATEGORIES[name] = {"description": description, "build_prompt": fn}
    return fn
  return decorator


# ---------------------------------------------------------------------
# Prompt builders — one per category. Each returns the user-message
# string only; the system prompt (FWL spec + PKT spec) is added by
# call_claude().
# ---------------------------------------------------------------------


@category(
  "field_operators",
  "Every pkt field x every valid operator x boundary values",
)
def prompt_field_operators(examples: str, count: int) -> str:
  return f"""Generate exactly {count} .pkt test cases covering the
FIELD x OPERATOR matrix for FWL v0.1.

Fields: pkt.proto, pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port,
pkt.tcp.syn, pkt.tcp.ack.

Operators: ==, !=, >, <, >=, <= (ordered ops only valid on numeric
fields per the spec — don't pair > with IP addresses), in.

Focus on:
- Boundary values: port 0, port 65535, 0.0.0.0, 255.255.255.255
- Each operator with each compatible field type
- At least one matching and one non-matching case per field
- Boolean fields used bare as conditions (no `== true`)
- Proto enum comparisons with each keyword (tcp, udp, icmp)
- Cases where the packet falls through to default

Every program must include @xdp(eth0) and a default rule. Every case
must have a correct expected.bpf_action — derive it from the spec
semantics, not a guess. Ensure protocol guards are present where
required (pkt.{{src,dst}}_port needs `pkt.proto == tcp|udp` guard;
pkt.tcp.* needs `pkt.proto == tcp` guard).

EXISTING EXAMPLES (style reference, do not duplicate):
{examples}

{PKT_FORMAT_REMINDER}"""


@category(
  "in_operator",
  "in with lists, ranges, CIDRs — boundary values and edge shapes",
)
def prompt_in_operator(examples: str, count: int) -> str:
  return f"""Generate exactly {count} .pkt test cases for the `in`
operator in all its forms.

Cover:
- Port lists: [22], [80, 443], longer mixed lists
- Port ranges: 1..1023, 1024..65535, 80..80, 0..65535
- CIDR: /0, /8, /16, /24, /32, common private ranges
  (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- CIDR lists with multiple CIDRs
- Match and non-match for each variant (packet inside vs. outside)
- Boundary values: IP at exact CIDR boundary, port at exact range
  boundary (first, last, one-beyond)
- Single-element list vs equality (should behave identically)

Every program must include @xdp(eth0) and a default rule.
Ensure protocol guards where required.

EXISTING EXAMPLES:
{examples}

{PKT_FORMAT_REMINDER}"""


@category(
  "boolean_composition",
  "and/or/not precedence, nesting, short-circuit, parentheses",
)
def prompt_boolean_composition(examples: str, count: int) -> str:
  return f"""Generate exactly {count} .pkt test cases for boolean
composition (and, or, not, parentheses).

Cover:
- Precedence: `a or b and c` (and binds tighter) vs `(a or b) and c`
- Packets that match one branch of an `or` but not the other
- `not` applied to: a comparison, a bool field, a parenthesized
  expression
- Deep nesting: 3+ levels of parens
- Short-circuit: proto guard via `and` followed by field access
- Mixed: `(proto == tcp and dst_port == 22) or (proto == udp and
  dst_port == 53)`

For each test, include a packet that exercises the specific branch
path you're testing. Think carefully about which branch the packet
takes and what the expected action is.

EXISTING EXAMPLES:
{examples}

{PKT_FORMAT_REMINDER}"""


@category(
  "protocol_guards",
  "Protocol guard enforcement — valid and invalid field access",
)
def prompt_protocol_guards(examples: str, count: int) -> str:
  return f"""Generate exactly {count} .pkt test cases for protocol
guard enforcement.

FWL v0.1 requires:
- pkt.{{src,dst}}_port need `pkt.proto == tcp` or `pkt.proto == udp`
  guard
- pkt.tcp.{{syn,ack}} need `pkt.proto == tcp` guard

Generate a mix of compile-failure and compile-success cases:

COMPILE-FAILURE (expected.compiles: false):
- dst_port access with no proto guard at all
- tcp.syn access inside a `pkt.proto == udp` guard
- tcp.ack access with no guard
- src_port access with only icmp guard

COMPILE-SUCCESS (expected.compiles: true):
- Properly guarded tcp + tcp field
- UDP guard + port access
- TCP guard + both syn and ack
- (tcp or udp) and dst_port == ... — guard via OR-union of branches
- Multiple rules: each with its own independent guard

For compile-failure cases the test packet doesn't matter; use
`builder: tcp()` as a placeholder. For compile-success cases
provide a packet that exercises the guarded path.

EXISTING EXAMPLES:
{examples}

{PKT_FORMAT_REMINDER}"""


@category(
  "multi_rule",
  "Rule ordering, first-match semantics, non-terminal fall-through",
)
def prompt_multi_rule(examples: str, count: int) -> str:
  return f"""Generate exactly {count} .pkt test cases for multi-rule
programs.

Cover:
- First-match semantics: earlier rule shadows later rule for same
  packet
- Non-terminal actions: log and `count <name>` fall through to the
  next rule
- Count action followed by terminal action: count fires, terminal
  decides fate
- Multiple counts before a terminal
- Log followed by drop: packet is logged AND dropped
- Rules that don't match: packet falls through
- Default rule: `default allow` and `default drop` as final catch-all
- Zero regular rules + default only: `@xdp(eth0)\\ndefault drop`
- Unreachable rules: unconditional allow followed by drop
- Ordering matters: same rules in different order, different outcomes
- Mix of protocols: TCP rule followed by UDP rule

Think carefully about which rule fires for each test packet.

EXISTING EXAMPLES:
{examples}

{PKT_FORMAT_REMINDER}"""


@category(
  "rate_limit",
  "rate_limit modifier — thresholds, per-fields, state, interactions",
)
def prompt_rate_limit(examples: str, count: int) -> str:
  return f"""Generate exactly {count} .pkt test cases for the
rate_limit modifier.

Cover:
- Every per= field: src_ip, dst_ip, src_port, dst_port
- Threshold boundaries: count=0 (fires), count=N-1 (fires),
  count=N (does NOT fire), count=N+1 (does not fire)
- No prior state (empty bucket -> treated as count=0 -> fires)
- Rate limit without if clause:
  `drop limited by rate_limit(N, per=src_ip)`
- Rate limit WITH if clause: condition must match first, then gate
- Packet doesn't match condition -> rate limit gate is never consulted
- Fall-through when gate blocks: rule doesn't fire, evaluation
  continues to next rule
- Multiple rate_limits in same program (different rule indices)
- Rate limit on allow action (not just drop)
- Different buckets are independent (different src_ip values)

For stateful tests, include the state: block with the correct rule
index (0-based position of the rate_limit rule in the program).

EXISTING EXAMPLES:
{examples}

{PKT_FORMAT_REMINDER}"""


@category(
  "compile_errors",
  "Errors from the spec's error table, plus variations",
)
def prompt_compile_errors(examples: str, count: int) -> str:
  return f"""Generate exactly {count} .pkt test cases that should
FAIL to compile.

The spec defines these compile errors:
1. Missing @xdp declaration
2. pkt field access outside required protocol guard
3. Type mismatch in comparison
4. Rate limit threshold non-positive (0 or negative)
5. Rate limit per= field is not valid
6. CIDR with invalid prefix length (>32, negative)
7. Port literal outside 0..65535 (e.g., 70000)
8. Range with lo > hi (e.g., 1000..500)
9. Unknown identifier
10. Rule following a default rule
11. Non-terminal action as default (default count x, default log)
12. Use of v0.2+ features (def, inline_c, chain, etc.)

Generate at least one case per error category — vary the shape where
possible (protocol guard violations have many forms: no guard, wrong
guard, etc.).

Every case must have expected.compiles: false. Use `builder: tcp()`
as the test packet placeholder.

EXISTING EXAMPLES:
{examples}

{PKT_FORMAT_REMINDER}"""


@category(
  "interactions",
  "Combinations across categories — where real bugs hide",
)
def prompt_interactions(examples: str, count: int) -> str:
  return f"""Generate exactly {count} .pkt test cases that combine
multiple FWL v0.1 features. These are the cases where real bugs
hide — feature interactions.

Combinations to draw from:
- Rate limit + boolean composition + multiple rules
- Count action + log action + rate-limited drop in the same program
- CIDR match + port range + protocol guard + default drop
- Nested boolean with rate_limit modifier
- Multiple rate_limits with different per= fields in same program
- in-operator with CIDR list + fallthrough to rate-limited rule
- Not operator on a proto check combined with port access
- Program with 5+ rules mixing all action types
- Rate limit on allow (not just drop) with a subsequent default drop
- Real-world firewall: SSH brute-force + web allow + DNS allow +
  rate limit + default deny

Each test should be a realistic or adversarial combination, not just
two features side-by-side. Think about what the compiler has to do
to get each case right.

EXISTING EXAMPLES:
{examples}

{PKT_FORMAT_REMINDER}"""


@category(
  "count_log",
  "count and log non-terminal actions — fall-through semantics",
)
def prompt_count_log(examples: str, count: int) -> str:
  return f"""Generate exactly {count} .pkt test cases for count and
log actions.

Key semantics:
- `count <name>` is non-terminal: increments counter, evaluation
  continues
- `log` is non-terminal: writes ringbuf event, evaluation continues
- Both fall through to subsequent rules
- Final disposition is determined by the first terminal action
  (allow/drop) or default

Cover:
- count + allow: counter fires, packet allowed
- count + drop: counter fires, packet dropped
- log + allow: logged, packet allowed
- log + drop: logged, packet dropped
- Multiple counts before terminal: all counters fire
- log + count + terminal: all three happen
- count with condition that doesn't match: counter NOT incremented,
  falls through
- Multiple named counters in same program
- count + rate_limit interaction: rate-limited rule blocked, falls to
  count, then to next terminal
- Default after only non-terminal rules: count + count + default drop

EXISTING EXAMPLES:
{examples}

{PKT_FORMAT_REMINDER}"""


@category(
  "implementation_adversary",
  "Read parser/analyzer/interpreter/emitter and try to break them",
)
def prompt_implementation_adversary(examples: str, count: int) -> str:
  return f"""You are doing adversarial review of the FWL v0.1
compiler. The implementation source is in your system prompt
(fwl/parser.py, analyzer.py, interpreter.py, emitter.py,
grammar.lark). Your job is to generate {count} .pkt test cases
that maximize the chance of catching real bugs.

For each case, pick a target — one of:

A. **Interpreter / emitter disagreement.** Find a packet shape and
   program where _eval(condition, packet) and the emitted BPF C
   could plausibly produce different XDP actions. Look at what each
   path does and where the abstractions are thin. Especially look at
   short-circuit evaluation in conditions, integer-vs-string keys in
   rate_limit state, fall-through behavior on bounds-check failure,
   and casting (e.g. CIDR mask shifts at boundary widths).

B. **Spec/analyzer drift.** The spec defines compile errors in its
   error table. Find one the analyzer doesn't enforce, or a check
   the analyzer makes that the spec doesn't authorize. Generate a
   case that exercises the gap. (We just fixed type-mismatch, port
   range, range order, and CIDR prefix — but there may be more.)

C. **Parser/grammar corner.** Find a syntactic construct that the
   spec's EBNF allows but the Lark grammar rejects (or vice versa).
   Look at lexer ambiguities (identifiers that share prefixes with
   keywords, e.g. tcp_traffic), comment placement, hex literals in
   unusual positions, deeply nested expressions, repeated empty
   structures.

D. **Constraint-set guard analysis.** The analyzer tracks `Possible`
   protocol constraints through AND/OR/NOT trees. The model has
   explicit rules — find a tree shape where the actual constraint
   propagation differs from what a careful reader of the spec would
   compute.

E. **Per-CPU + sliding-window rate_limit edge.** The state encoding
   is tied to specific BPF map types and value layouts. Look for
   places where the interpreter's view of state could differ from
   what the BPF runtime computes given the same `state:` block.

For each case:
- Include a one-sentence rationale in the `name` (e.g.
  "tcp_traffic identifier should not lex as keyword tcp + _traffic").
- Make expected.bpf_action correct per the spec — if you think the
  implementation produces a different result, that IS the bug; the
  spec wins.

EXISTING EXAMPLES (style reference):
{examples}

{PKT_FORMAT_REMINDER}"""


@category(
  "spec_ambiguity",
  "Cases where the spec text is ambiguous or under-specified",
)
def prompt_spec_ambiguity(examples: str, count: int) -> str:
  return f"""You are auditing the FWL v0.1 spec
(docs/FWL_V01_SPEC.md) for ambiguity. Generate exactly {count} .pkt
test cases at points where the spec text is unclear, contradictory,
or leaves behavior up to the implementer.

For each case, the value comes from the act of writing it down: if
the spec is genuinely ambiguous, two compliant implementations could
disagree on this packet, and the spec needs a clarifying edit.

Look for:
- Operator behavior on edge cases the spec doesn't explicitly enumerate
  (e.g. != on a CIDR list — does it mean "in none of these"?)
- Default rule semantics when log/count appear before it
- Rate_limit semantics at exact-threshold boundaries (the spec uses
  both "at or below" and "below" wording in different paragraphs)
- Protocol guard analysis through OR composition (spec example at
  FWL_V01_SPEC.md:179-183 has internally inconsistent rationale)
- Lexer ambiguity around `not in` vs `in` with negation
- The interaction of truncated packets with rate_limit state

For each case:
- Pick the interpretation that matches the *spec's semantics
  section* (not a stray example).
- Add a comment in the `name` describing the ambiguity.
- If the implementation happens to behave differently, that
  surfaces the spec gap.

EXISTING EXAMPLES:
{examples}

{PKT_FORMAT_REMINDER}"""


@category(
  "emitter_edges",
  "BPF emission edge cases — verifier challenges, layout corners",
)
def prompt_emitter_edges(examples: str, count: int) -> str:
  return f"""Generate exactly {count} .pkt test cases that target
edge cases in BPF emission (the C generator in emitter.py and the
verifier-accepted output it produces).

Cover:
- Programs with many rules (10+) that stress the verifier's
  instruction count limit
- Deeply nested conditions (5+ levels of and/or/not) that produce
  long boolean expressions in C
- Rate_limit gates that allocate per-CPU maps — multiple in the
  same program, all four per= field types
- Bounds-check fall-through: packets where the bounds check fails
  AND the program has an explicit default — the default MUST fire,
  not the implicit allow (we just fixed this; verify it stays fixed)
- IPv4 packets with IHL options (the emitter computes ip_hlen
  dynamically, but the test packet builder always emits IHL=5; this
  category surfaces cases where IHL=5 is actually load-bearing)
- The emitter reads CIDR masks at specific bit widths — test /1,
  /7, /15, /23, /31 (off-by-one boundary widths)
- Programs with only non-terminal rules + default — log+log+default
- count + log + rate_limit + condition all stacked on one rule

For each case, walk through what BPF C the emitter would produce
(the source is in your system prompt), then write the .pkt that
exercises that path.

EXISTING EXAMPLES:
{examples}

{PKT_FORMAT_REMINDER}"""


# ---------------------------------------------------------------------
# Agent runner
# ---------------------------------------------------------------------


def load_text(path: Path, label: str) -> str:
  """Load a text file from disk; exit with a helpful error if missing."""
  if not path.exists():
    flag = "--" + label.lower().replace(" ", "-")
    print(
      f"{label} not found at {path}. Pass {flag} to override.",
      file=sys.stderr,
    )
    sys.exit(1)
  return path.read_text(encoding="utf-8")


def load_examples(corpus_dir: Path, max_examples: int = 6) -> str:
  """Load a few existing .pkt files as style references."""
  if not corpus_dir.exists():
    return "(no existing examples found)"
  files = sorted(corpus_dir.rglob("*.pkt"))[:max_examples]
  if not files:
    return "(no existing examples found)"
  parts = []
  for f in files:
    parts.append(f"# --- {f.relative_to(corpus_dir)} ---")
    parts.append(f.read_text(encoding="utf-8").strip())
  return "\n\n".join(parts)


# Source files injected into the system prompt so adversarial
# categories can target spec/implementation drift directly.
_SOURCE_MODULES = (
  "parser.py",
  "analyzer.py",
  "interpreter.py",
  "emitter.py",
  "grammar.lark",
)


def _load_source_modules() -> str:
  """Read the implementation modules verbatim from the package dir."""
  pkg_dir = _SCRIPT_DIR.parent
  parts: list[str] = []
  for name in _SOURCE_MODULES:
    path = pkg_dir / name
    if not path.exists():
      continue
    parts.append(f"--- fwl/{name} ---\n")
    parts.append(path.read_text(encoding="utf-8"))
    parts.append("\n")
  return "".join(parts)


def build_system_prompt(fwl_spec: str, pkt_spec: str) -> str:
  """Assemble the system prompt that's reused across categories.

  Includes both authoritative specs AND the implementation source
  modules, so adversarial categories can spot spec/code drift
  directly. Cost is higher per call (~80K tokens of context vs ~50K
  spec-only) but the user has prioritized bug-finding over budget.
  """
  source = _load_source_modules()
  return f"""You are generating .pkt test cases for FWL v0.1, a
firewall DSL that compiles to eBPF/XDP. The authoritative specs and
the current implementation source follow. Anything not in the specs
is out of scope; the implementation source is provided so adversarial
categories can spot places where the code might disagree with the
spec, with itself (interpreter vs emitter), or with reasonable
expectations.

================================================================
FWL v0.1 LANGUAGE SPECIFICATION (docs/FWL_V01_SPEC.md)
================================================================

{fwl_spec}

================================================================
.pkt v0.1 TEST CASE FORMAT SPECIFICATION (docs/PKT_V01_SPEC.md)
================================================================

{pkt_spec}

================================================================
IMPLEMENTATION SOURCE (fwl/fwl/*.py + grammar.lark)
================================================================

{source}

================================================================

Stick to the shipped subset of the .pkt format — the specs flag
which fields are already implemented and which are spec-only.
Generated cases that use spec-only fields (truncate_to,
counter_changes, log_events) will fail to load.

For each test case you generate:
1. The expected.bpf_action MUST be derivable from the spec semantics,
   not a guess. Walk through the rules in order, evaluate the
   condition for the test packet, and pick the first matching rule's
   action (or the default).
2. Protocol guards are required exactly as the spec defines. Do not
   add stray guards; do not omit required ones.
3. Names should be descriptive (slug-able). Snake_case.
4. Output ONLY the YAML documents, separated by a `---` line. No
   markdown fences, no commentary.

When generating adversarial cases against the implementation:
- The interpreter (interpreter.py) and the emitter (emitter.py) MUST
  agree on every packet. If you find a case where the spec is silent
  but the interpreter and emitter could plausibly disagree, generate
  it — disagreement is a real bug.
- The analyzer (analyzer.py) enforces compile errors. Any spec error
  not enforced is a real bug. Any compile error the analyzer raises
  that the spec doesn't authorize is also a bug.
- The parser (parser.py) and grammar.lark together define the
  surface. Look for edge cases in lexing (keywords vs identifiers
  with shared prefixes, hex literals, comment placement) and parsing
  (precedence corners, empty constructs, max-rule programs)."""


@dataclass
class _GenResult:
  """Outcome of one category generation request."""
  category: str
  raw: str
  cost_usd: float


async def call_claude(
  system_prompt: str,
  user_prompt: str,
  category: str,
  model: str,
  dry_run: bool,
) -> _GenResult:
  """Run one query() call and collect the assistant's text response.

  Authentication piggybacks on the user's existing Claude Code
  session — no API key needed. Each call spawns a `claude` subprocess
  via the SDK; we collect AssistantMessage TextBlocks until
  ResultMessage signals completion.

  Tools are disabled (max_turns=1, allowed_tools=[]) — the agent
  should produce text only, no file edits or shell calls.
  """
  if dry_run:
    print("=" * 70)
    print(f"PROMPT for category: {category}")
    print("=" * 70)
    print(f"[system_prompt, ~{len(system_prompt)} chars]")
    print(user_prompt[:2000])
    if len(user_prompt) > 2000:
      print("... (truncated)")
    return _GenResult(category=category, raw="", cost_usd=0.0)

  options = ClaudeCodeOptions(
    system_prompt=system_prompt,
    model=model,
    max_turns=1,
    allowed_tools=[],
    permission_mode="bypassPermissions",
    settings='{"sandbox":{"enabled":false}}',
  )

  text_parts: list[str] = []
  cost: float = 0.0
  async for msg in query(prompt=user_prompt, options=options):
    if isinstance(msg, AssistantMessage):
      for block in msg.content:
        if isinstance(block, TextBlock):
          text_parts.append(block.text)
    elif isinstance(msg, ResultMessage):
      if msg.total_cost_usd is not None:
        cost = msg.total_cost_usd

  return _GenResult(
    category=category, raw="".join(text_parts), cost_usd=cost
  )


def parse_pkt_documents(raw: str) -> list[tuple[str, dict]]:
  """Split the raw response into individual YAML documents."""
  chunks = re.split(r"^---\s*$", raw, flags=re.MULTILINE)
  docs: list[tuple[str, dict]] = []
  for chunk in chunks:
    chunk = chunk.strip()
    if not chunk:
      continue
    # Strip stray markdown fences the model might emit despite
    # explicit instructions to omit them.
    chunk = re.sub(r"^```ya?ml\s*", "", chunk)
    chunk = re.sub(r"\s*```\s*$", "", chunk)
    chunk = chunk.strip()
    if not chunk:
      continue
    try:
      doc = yaml.safe_load(chunk)
      if isinstance(doc, dict) and "name" in doc:
        docs.append((chunk, doc))
    except yaml.YAMLError as exc:
      print(
        f"  WARN: skipping unparseable YAML chunk: {exc}",
        file=sys.stderr,
      )
  return docs


def slugify(name: str) -> str:
  """Turn a test name into a safe filename slug, capped at 80 chars."""
  s = name.lower()
  s = re.sub(r"[^a-z0-9]+", "_", s)
  return s.strip("_")[:80]


def write_pkt_files(
  docs: list[tuple[str, dict]],
  output_dir: Path,
  category: str,
) -> list[Path]:
  """Write parsed .pkt documents to disk under output_dir/<category>/."""
  out = output_dir / category
  out.mkdir(parents=True, exist_ok=True)
  written: list[Path] = []
  for i, (raw_yaml, doc) in enumerate(docs):
    name = doc.get("name", f"case_{i}")
    slug = slugify(name)
    path = out / f"{slug}.pkt"
    if path.exists():
      path = out / f"{slug}_{i}.pkt"
    path.write_text(raw_yaml + "\n", encoding="utf-8")
    written.append(path)
  return written


def validate_pkt_doc(doc: dict) -> list[str]:
  """Quick structural sanity check before writing to disk.

  Catches obvious agent mistakes (missing fields, bpf_action present
  on a compile-failure case) before they hit the runner. Detailed
  validation against the .pkt spec is the runner's job.
  """
  warnings: list[str] = []
  for required in ("name", "source_fw", "test_packet", "expected"):
    if required not in doc:
      warnings.append(f"missing '{required}'")
  if "test_packet" in doc and "builder" not in doc.get("test_packet", {}):
    warnings.append("missing 'test_packet.builder'")
  exp = doc.get("expected", {})
  compiles = exp.get("compiles", True)
  if compiles and "bpf_action" not in exp:
    warnings.append("compiles: true but missing 'expected.bpf_action'")
  if not compiles and "bpf_action" in exp:
    warnings.append("compiles: false but 'expected.bpf_action' set")
  fw = doc.get("source_fw", "")
  if "@xdp" not in fw and compiles:
    warnings.append("source_fw missing @xdp but expected.compiles is true")
  return warnings


def run_auto_test(output_dir: Path) -> None:
  """Run `fwl test` against the generated directory and print the result."""
  print("\n" + "=" * 70)
  print(f"Running fwl test {output_dir} ...")
  print("=" * 70)
  result = subprocess.run(
    ["fwl", "test", str(output_dir)],
    capture_output=False,
  )
  if result.returncode == 0:
    print("\nAll generated cases pass. Review them by hand before "
          "moving to tests/corpus/.")
  else:
    print("\nSome generated cases failed. For each failure:")
    print("  - Read the .pkt file and the runner's diff")
    print("  - Decide: bad test (discard) or real bug (file an issue)")


# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------


async def _run(args: argparse.Namespace) -> None:
  """Async core of main(): builds prompts and dispatches to call_claude."""
  fwl_spec = load_text(args.fwl_spec, "FWL spec")
  pkt_spec = load_text(args.pkt_spec, "PKT spec")
  examples = load_examples(args.corpus, args.max_examples)
  system_prompt = build_system_prompt(fwl_spec, pkt_spec)

  cats = (
    list(CATEGORIES.keys()) if args.category == "all" else [args.category]
  )

  total_generated = 0
  total_warnings = 0
  total_cost_usd = 0.0

  for cat_name in cats:
    cat = CATEGORIES[cat_name]
    print(f"\n{'=' * 70}")
    print(f"Category: {cat_name}")
    print(f"  {cat['description']}")
    print(f"  Requesting {args.count} cases...")

    user_prompt = cat["build_prompt"](examples, args.count)

    result = await call_claude(
      system_prompt, user_prompt, cat_name, args.model, args.dry_run
    )
    if args.dry_run:
      continue

    total_cost_usd += result.cost_usd

    docs = parse_pkt_documents(result.raw)
    print(f"  Parsed {len(docs)} cases from response")
    if result.cost_usd:
      print(f"  Cost: ${result.cost_usd:.4f}")

    if not docs:
      print("  WARN: no valid test cases parsed", file=sys.stderr)
      continue

    for raw_yaml, doc in docs:
      warns = validate_pkt_doc(doc)
      if warns:
        name = doc.get("name", "(unnamed)")
        for w in warns:
          print(f"  WARN [{name}]: {w}", file=sys.stderr)
          total_warnings += 1

    written = write_pkt_files(docs, args.output, cat_name)
    print(f"  Wrote {len(written)} files to {args.output}/{cat_name}/")
    total_generated += len(written)

  if args.dry_run:
    return

  print(f"\n{'=' * 70}")
  print(
    f"Total: {total_generated} test cases generated, "
    f"{total_warnings} warnings"
  )
  if total_cost_usd:
    print(f"Total cost: ${total_cost_usd:.4f}")

  if args.auto_test and total_generated > 0:
    run_auto_test(args.output)
  else:
    print("\nNext steps:")
    print(f"  1. Review generated files in {args.output}/")
    print(f"  2. fwl test {args.output}/  (or rerun with --auto-test)")
    print(f"  3. For passing cases: move to {args.corpus}/<phase>/")
    print("  4. For failures: investigate spec/compiler/test bug")


def main() -> None:
  """CLI entry point. Run `fwl-test-agent --help` for usage."""
  parser = argparse.ArgumentParser(
    prog="fwl-test-agent",
    description=(
      "Generate FWL test corpus cases via Claude Code "
      "(uses your existing Claude session, no API key required)."
    ),
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=__doc__,
  )
  parser.add_argument(
    "--category", "-c",
    choices=list(CATEGORIES.keys()) + ["all"],
    help="Which category to generate (or 'all' for every category)",
  )
  parser.add_argument(
    "--count", "-n", type=int, default=15,
    help="Number of test cases per category (default: 15)",
  )
  parser.add_argument(
    "--fwl-spec", type=Path, default=DEFAULT_FWL_SPEC_PATH,
    help=f"Path to FWL spec (default: {DEFAULT_FWL_SPEC_PATH})",
  )
  parser.add_argument(
    "--pkt-spec", type=Path, default=DEFAULT_PKT_SPEC_PATH,
    help=f"Path to .pkt spec (default: {DEFAULT_PKT_SPEC_PATH})",
  )
  parser.add_argument(
    "--corpus", type=Path, default=DEFAULT_CORPUS_DIR,
    help=(
      f"Existing corpus dir for style examples "
      f"(default: {DEFAULT_CORPUS_DIR})"
    ),
  )
  parser.add_argument(
    "--output", "-o", type=Path, default=DEFAULT_OUTPUT_DIR,
    help=(
      f"Output dir for generated .pkt files "
      f"(default: {DEFAULT_OUTPUT_DIR})"
    ),
  )
  parser.add_argument(
    "--model", default=DEFAULT_MODEL,
    help=(
      f"Claude model to use (default: {DEFAULT_MODEL}). Override with "
      "e.g. claude-sonnet-4-6 to trade quality for quota."
    ),
  )
  parser.add_argument(
    "--list-categories", "-l", action="store_true",
    help="List available categories and exit",
  )
  parser.add_argument(
    "--dry-run", action="store_true",
    help="Print prompts without calling Claude",
  )
  parser.add_argument(
    "--max-examples", type=int, default=6,
    help="Number of corpus examples to inject as style refs (default: 6)",
  )
  parser.add_argument(
    "--auto-test", action="store_true",
    help=(
      "After generation, run `fwl test` on the output dir to surface "
      "which agent-generated cases all three oracles agree on"
    ),
  )

  args = parser.parse_args()

  if args.list_categories:
    print("Available categories:\n")
    for name, info in CATEGORIES.items():
      print(f"  {name:25s} {info['description']}")
    print(f"\n  {'all':25s} Run all categories sequentially")
    return

  if not args.category:
    parser.print_help()
    sys.exit(1)

  asyncio.run(_run(args))


if __name__ == "__main__":
  main()
