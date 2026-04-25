#!/usr/bin/env python3
"""FWL test corpus generator via Claude.

Generates `.pkt` test files by calling Claude with structured prompts.
Each category targets a specific area of the FWL v0.1 spec.

Usage examples:
  fwl-test-agent --list-categories
  fwl-test-agent --category field_operators --count 20
  fwl-test-agent --category all --count 10
  fwl-test-agent --category compile_errors --count 15 --output tests/generated/
  fwl-test-agent --category protocol_guards --count 12 --auto-test

Cost note: each --category run sends ~50K tokens of spec + examples to
Claude. The spec injection is prompt-cached (5-minute TTL), so a
--category all run pays the cache write once and reads on the
remaining 8 categories. Generated cases land in --output (default
tests/generated/) for human review per the methodology — they do NOT
go straight into the regression corpus.
"""
from __future__ import annotations
import argparse
import os
import re
import subprocess
import sys
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

try:
  import anthropic
except ImportError:
  print(
    "anthropic package not installed. Run: pip install anthropic",
    file=sys.stderr,
  )
  sys.exit(1)

try:
  import yaml
except ImportError:
  print("pyyaml not installed. Run: pip install pyyaml", file=sys.stderr)
  sys.exit(1)


# Use Opus 4.7 with adaptive thinking + high effort. This is intelligence-
# sensitive work — generating spec-conforming test cases that exercise
# subtle protocol-guard semantics, edge cases, and correct expected
# actions. A weaker model produces cases that look right but have wrong
# bpf_action values or invalid syntax, which the user then has to triage.
MODEL = "claude-opus-4-7"
MAX_TOKENS = 64000


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
# .pkt spec is also included in full as part of the cached system
# prompt; this block summarizes the surface for the model and pins
# the v0.1 implementation defaults.
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
# string only; the cached system prompt (FWL spec + PKT spec) is added
# by call_claude().
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


# ---------------------------------------------------------------------
# Agent runner
# ---------------------------------------------------------------------


def load_text(path: Path, label: str) -> str:
  """Load a text file from disk; exit with a helpful error if missing."""
  if not path.exists():
    print(
      f"{label} not found at {path}. Pass --{label.lower().replace(' ', '-')} "
      f"to override.",
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


def build_system_prompt(fwl_spec: str, pkt_spec: str) -> str:
  """Assemble the cached system prompt that's reused across categories."""
  return f"""You are generating .pkt test cases for FWL v0.1, a
firewall DSL that compiles to eBPF/XDP. The two authoritative
specifications follow. Anything not in these specs is out of scope —
do not reference language features marked deferred to v0.2+.

================================================================
FWL v0.1 LANGUAGE SPECIFICATION (docs/FWL_V01_SPEC.md)
================================================================

{fwl_spec}

================================================================
.pkt v0.1 TEST CASE FORMAT SPECIFICATION (docs/PKT_V01_SPEC.md)
================================================================

{pkt_spec}

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
   markdown fences, no commentary."""


@dataclass
class _GenResult:
  """Outcome of one category generation request."""
  category: str
  raw: str
  cache_creation: int
  cache_read: int


def call_claude(
  client: anthropic.Anthropic,
  system_prompt: str,
  user_prompt: str,
  category: str,
  dry_run: bool,
) -> _GenResult:
  """Send the prompt to Claude and return the raw text response.

  Streaming is used because the response can be 20K+ tokens; the SDK
  refuses non-streaming requests it estimates will exceed ~10 minutes
  of wall time.

  The system prompt carries cache_control so the spec injection is
  reused across category requests within a single run (5-minute TTL).
  """
  if dry_run:
    print("=" * 70)
    print(f"PROMPT for category: {category}")
    print("=" * 70)
    print("[system, ~", len(system_prompt), "chars, cached]")
    print(user_prompt[:2000])
    if len(user_prompt) > 2000:
      print("... (truncated)")
    return _GenResult(
      category=category, raw="", cache_creation=0, cache_read=0
    )

  with client.messages.stream(
    model=MODEL,
    max_tokens=MAX_TOKENS,
    thinking={"type": "adaptive"},
    output_config={"effort": "high"},
    system=[
      {
        "type": "text",
        "text": system_prompt,
        "cache_control": {"type": "ephemeral"},
      }
    ],
    messages=[{"role": "user", "content": user_prompt}],
  ) as stream:
    final = stream.get_final_message()

  text_parts = [b.text for b in final.content if b.type == "text"]
  raw = "".join(text_parts)
  return _GenResult(
    category=category,
    raw=raw,
    cache_creation=final.usage.cache_creation_input_tokens or 0,
    cache_read=final.usage.cache_read_input_tokens or 0,
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


def main() -> None:
  """CLI entry point. Run `fwl-test-agent --help` for usage."""
  parser = argparse.ArgumentParser(
    prog="fwl-test-agent",
    description="Generate FWL test corpus cases via Claude.",
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
    "--list-categories", "-l", action="store_true",
    help="List available categories and exit",
  )
  parser.add_argument(
    "--dry-run", action="store_true",
    help="Print prompts without calling the API",
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

  if not args.dry_run and not os.environ.get("ANTHROPIC_API_KEY"):
    print(
      "ANTHROPIC_API_KEY not set. Use --dry-run to preview prompts "
      "without calling the API.",
      file=sys.stderr,
    )
    sys.exit(1)

  fwl_spec = load_text(args.fwl_spec, "FWL spec")
  pkt_spec = load_text(args.pkt_spec, "PKT spec")
  examples = load_examples(args.corpus, args.max_examples)
  system_prompt = build_system_prompt(fwl_spec, pkt_spec)

  cats = (
    list(CATEGORIES.keys()) if args.category == "all" else [args.category]
  )

  client = None if args.dry_run else anthropic.Anthropic()

  total_generated = 0
  total_warnings = 0
  cache_writes_total = 0
  cache_reads_total = 0

  for cat_name in cats:
    cat = CATEGORIES[cat_name]
    print(f"\n{'=' * 70}")
    print(f"Category: {cat_name}")
    print(f"  {cat['description']}")
    print(f"  Requesting {args.count} cases...")

    user_prompt = cat["build_prompt"](examples, args.count)

    result = call_claude(
      client, system_prompt, user_prompt, cat_name, args.dry_run
    )
    if args.dry_run:
      continue

    cache_writes_total += result.cache_creation
    cache_reads_total += result.cache_read

    docs = parse_pkt_documents(result.raw)
    print(f"  Parsed {len(docs)} cases from response")
    print(
      f"  Cache: {result.cache_creation} written, "
      f"{result.cache_read} read"
    )

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
  print(
    f"Cache totals: {cache_writes_total} written, "
    f"{cache_reads_total} read"
  )

  if args.auto_test and total_generated > 0:
    run_auto_test(args.output)
  else:
    print("\nNext steps:")
    print(f"  1. Review generated files in {args.output}/")
    print(f"  2. fwl test {args.output}/  (or rerun with --auto-test)")
    print(f"  3. For passing cases: move to {args.corpus}/<phase>/")
    print("  4. For failures: investigate spec/compiler/test bug")


if __name__ == "__main__":
  main()
