# FWL Development Methodology

## Overview

This document specifies how FWL — the Firewall Language at the heart of f — gets built. It is not the language spec. It is the methodology for getting from "no FWL" to "FWL v0.1 is shipped, tested, and dogfooded."

The core risk: FWL is a programming language. Languages with broken or inconsistent semantics are very hard to fix later because users depend on existing behavior. Every built-in function shipped, every edge case in `pkt` field access, every interaction between language tiers — once it's released and people are using it, the bug becomes the spec.

The methodology has to:

1. Build the language incrementally, smallest viable surface first.
2. Verify every construct works correctly before moving on.
3. Use AI agents (via the Claude API) as quality multipliers for test generation and spec review, not as substitutes for design judgment.
4. Produce a shippable v0.1 with a small but rock-solid vocabulary that supports real firewalls.

This document is the contract that prevents scope creep and methodology drift during development.

## Three Activities, Three Artifacts

Language development has three distinct activities. Mixing them costs time and produces worse output. Sequence them, but cycle tightly.

| Activity | Artifact | Cycle time |
|---|---|---|
| Language design | `FWL_SPEC.md` (the language spec) | Per-construct, days |
| Compiler implementation | Python compiler source under `fwl/` | Per-construct, hours to days |
| Verification | `.pkt` test corpus + spec-checking tools | Continuous after each construct |

A construct is the unit of progress: one language feature (`pkt.dst_port`, `rate_limit()`, `if/and/or` composition, etc.). For each construct, you go through all three activities before moving to the next. Don't try to spec the whole language up front. Don't try to implement broadly. Depth beats breadth.

## v0.1 Scope (Frozen)

This is the explicit, frozen scope for FWL v0.1. Anything not in this list is deferred to v0.2 or later. Resist the urge to add anything until v0.1 is shipped and dogfooded.

### Language constructs

- **Tier 1 declarative rules only.** No Tier 2 functions. No Tier 3 `inline_c`.
- **`pkt.proto`** — TCP, UDP, ICMP only.
- **`pkt.src_ip`, `pkt.dst_ip`** — IPv4 only.
- **`pkt.src_port`, `pkt.dst_port`** — TCP and UDP.
- **`pkt.tcp.syn`, `pkt.tcp.ack`** — only these two flags.
- **One built-in: `rate_limit(N, per=field)`** — nothing else.
- **Actions:** `allow`, `drop`, `log`, `count <n>` (logs are unconditional in v0.1; no `sampled` modifier; `count <n>` is the action form, not the function-call form).
- **Default rule:** `default <action>` as explicit final rule (where `<action>` is `allow` or `drop`; `log` and `count` are non-terminal and not valid as defaults).
- **Comparisons:** `==`, `!=`, `>`, `<`, `>=`, `<=`, `in` (set/range membership).
- **Composition:** `and`, `or`, `not`, parentheses.
- **Hook point:** `@xdp(<interface>)`. Single attach point per program.

### Explicitly deferred to v0.2+

- IPv6 (`pkt.src_ip6`, `pkt.dst_ip6`)
- Tier 2 programmable functions (`def`, control flow, locals)
- Tier 3 `inline_c` and `.bpf.c` stage loading
- `geoip()`, `conntrack()`, `chain`, `wg_*` built-ins
- `count(name)` function-call form (the `count <n>` action is in v0.1; the function-call form usable inside expressions is deferred)
- Stateful primitives beyond `rate_limit`
- Custom `pkt.<protocol>` layers (`pkt.wg.*`, `pkt.icmp.*`, etc.)
- Tail-call composition between programs
- Multi-interface attach
- `sampled` modifiers on log
- Map-level operations
- Schema generation for tab completion
- LSP server

This list is the scope freeze. Adding to it requires either shipping v0.1 first or explicit re-scoping.

## Spec-First Development

For each construct, before writing any compiler code, write a spec entry. Not a sentence. A real specification.

Required sections:

- **Construct** — what the syntax looks like, with examples
- **Type rules** — what types are valid in what positions
- **Semantics** — what it means at runtime (what the BPF program does)
- **Edge cases** — explicit decisions about degenerate inputs (truncated packets, zero values, overflow, undefined-behavior cases)
- **Compile errors** — what kinds of programs are rejected at compile time, with exact error messages
- **Examples** — at least three programs using the construct, with expected behavior

### Example spec entry

```markdown
## pkt.dst_port

**Construct.** Field access on the packet object yielding the destination
L4 port number.

**Type.** u16 (0..=65535)

**Semantics.**
- For TCP and UDP packets, the destination port from the L4 header,
  converted from network byte order to host byte order.
- The compiler emits the appropriate parse chain (Ethernet + IPv4 +
  TCP/UDP) with bounds checks at each layer.

**Edge cases.**
- Truncated packet (less than full TCP/UDP header): rule does not match.
  Packet returns XDP_PASS by default. Compiler must emit the bounds check.
- IPv4 with options extending the IP header beyond 20 bytes: L4 offset is
  computed as `ihl * 4`. Bounds checked.
- Non-TCP/UDP packets: accessing `pkt.dst_port` outside an `if pkt.proto ==
  tcp` or `if pkt.proto == udp` guard is a compile-time error.
- Fragmented IP packets where the fragment does not contain the L4 header:
  rule does not match. Packet returns XDP_PASS.

**Compile errors.**
- Access without protocol guard:
  `error: pkt.dst_port requires 'pkt.proto == tcp' or 'pkt.proto == udp' guard`
- Comparison with non-integer:
  `error: pkt.dst_port (u16) cannot be compared with string "foo"`

**Examples.**

1. Allow HTTP and HTTPS:
   ```
   allow if pkt.proto == tcp and pkt.dst_port in [80, 443]
   ```

2. Drop DNS amplification candidates:
   ```
   drop if pkt.proto == udp and pkt.dst_port in [53, 5353, 11211]
   ```

3. SSH SYN flood protection:
   ```
   drop if pkt.proto == tcp and pkt.dst_port == 22
       and pkt.tcp.syn and not pkt.tcp.ack
       limited by rate_limit(10, per=src_ip)
   ```
```

That level of detail is what's needed. Write one of these for every v0.1 construct. The spec is what you verify against. If the spec is vague, the verification is vague.

## The Verification Loop

Once you have a spec entry, the verification loop runs:

```
┌──────────────────────────────────────────────────────────────┐
│                                                              │
│  Spec entry (FWL_SPEC.md)                                    │
│         │                                                    │
│         ▼                                                    │
│  Agent generates test corpus  ◀──────┐                       │
│   (Claude API, structured prompt)    │                       │
│         │                            │                       │
│         ▼                            │ refine spec /         │
│  Human review of generated tests     │ correct agent         │
│         │                            │ misunderstanding      │
│         ▼                            │                       │
│  Compiler runs corpus                │                       │
│         │                            │                       │
│         ▼                            │                       │
│  AST interpreter runs corpus  ──────▶│                       │
│         │                            │                       │
│         ▼                            │                       │
│  BPF_PROG_RUN runs corpus  ─────────▶│                       │
│         │                            │                       │
│         ▼                            │                       │
│  Discrepancy?  ────── yes ───────────┤                       │
│         │                                                    │
│         no                                                   │
│         │                                                    │
│         ▼                                                    │
│  Construct verified, corpus added to regression suite        │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

Three oracles independently verify each test case:

1. **The spec** — does the test's expected outcome match what the spec says? (Human-checked at review time.)
2. **The AST interpreter** — does evaluating the program against the test packet at the AST level produce the expected outcome?
3. **The BPF compiler + BPF_PROG_RUN** — does the compiled BPF, executed in the kernel, produce the expected outcome?

All three must agree. If they disagree:

- AST interpreter and BPF disagree → compiler bug. Fix the compiler.
- AST interpreter agrees with spec, BPF disagrees with both → compiler bug.
- AST interpreter and BPF agree but disagree with spec → either the spec is wrong or both implementations have the same bug. Investigate.
- AST interpreter and spec disagree → spec ambiguity or interpreter bug.

The point is that having three independent oracles catches the bugs that a single oracle would miss. This is the same pattern from F_SECURITY_HARNESS, applied to language development rather than security testing.

## The AI Agent's Role

This methodology uses Claude via the Python API. The agent is a quality multiplier on the parts of language development that scale poorly with one human's attention.

### What the agent does

**Spec review.** Given a spec entry, the agent identifies ambiguities, missing edge cases, and contradictions. The agent does not write the spec; it stress-tests it.

**Test corpus generation.** Given a spec entry, the agent produces `.pkt` test files exercising the construct. Pass cases, fail cases, edge cases. The corpus is the regression suite.

**Edge case spotting.** Given an existing corpus, the agent suggests cases that aren't covered yet. ("You have tests for valid TCP packets but no test for a TCP header that claims a length less than 20 bytes.")

**Generated-code review.** Given a `.fw` source and the BPF C the compiler emits, the agent compares against the spec's semantics and flags discrepancies.

**Documentation maintenance.** When the spec changes, the agent flags places in the docs (tutorials, examples, READMEs) that need to be updated to match.

### What the agent does NOT do

**The agent does not write the compiler.** Compiler design — AST shapes, semantic analysis passes, code generation strategy — is yours. An agent producing 5,000 lines of compiler code with subtle bugs is far worse than you producing 1,500 lines you fully understand.

**The agent does not make design decisions.** When the spec is ambiguous, the agent flags the ambiguity. The decision about how to resolve it is yours. Don't ask the agent "what should this language do" — ask it "what cases does my spec leave undefined."

**The agent does not approve its own work.** Every test case the agent generates gets human review before it joins the regression corpus. Otherwise the corpus is full of agent hallucinations and the verification loop produces noise instead of signal.

### Agent prompt patterns

For test generation:

```
You are reviewing a specification for a single language construct in FWL,
a Python-syntax DSL that compiles to eBPF.

Spec:
[paste the spec entry]

Generate 15 test cases that exercise this construct. Format each as a YAML
document with the structure:

  name: short descriptive name
  source_fw: |
    [the .fw program]
  test_packet: [hex bytes or a builder syntax description]
  state: [optional pre-loaded state for stateful primitives]
  expected:
    compiles: true | false
    compile_error: [exact expected error string, if applicable]
    bpf_action: allow | drop | log | none
    counter_changes:
      [counter_name]: [delta]

Include:
- 5 cases that should compile and run normally
- 3 cases that should cause compile errors (different errors)
- 4 edge cases (boundary values, truncated packets, fragmentation)
- 3 cases that test interaction with other constructs

For each, briefly explain why this case matters.
```

For spec review:

```
You are reviewing a specification for a language construct in FWL.

Spec:
[paste the spec entry]

Your job is to find ambiguities, contradictions, or missing cases. For
each, output:

  - The ambiguity in plain language.
  - A specific test case that two implementations could handle differently
    while both claiming to follow this spec.
  - A suggested clarification.

Do not propose new features. Do not suggest the spec should cover more.
Find only the cases where the existing spec is unclear about behavior
that is in scope.
```

These prompts are deliberately structured. The agent gets a single, well-scoped task. The output format is parseable. The human reviews structured output, not free-form prose.

### A word on agent hallucinations

The agent will occasionally claim a test case proves a bug when it doesn't, or claim a spec is unambiguous when it isn't. This is unavoidable. The mitigation is human review. The cost of agent hallucinations in this workflow is bounded — a hallucinated test gets dropped during review, a missed ambiguity gets caught at the next review. Neither is catastrophic. Trust the agent for breadth, not for correctness.

## Tooling

The development environment for FWL needs the following tools, built early:

### `.pkt` test format

Already specified in F_PRODUCT_VISION's testing section. Use that format. Don't invent a new one. Stick to it.

A `.pkt` file is a YAML document with:

```yaml
name: "SSH SYN allowed under rate limit"
source_fw: |
  @xdp(eth0)
  drop if pkt.proto == tcp and pkt.dst_port == 22
      and pkt.tcp.syn and not pkt.tcp.ack
      limited by rate_limit(10, per=src_ip)

state:
  rate_limit:
    "1.2.3.4": 5  # current count for this src_ip

test_packet:
  builder: tcp(src_ip="1.2.3.4", dst_port=22, syn=true, ack=false)

expected:
  compiles: true
  bpf_action: allow  # under rate limit, not yet at threshold
  counter_changes:
    rate_limit__src_ip__1.2.3.4: 1
```

### Test runner

`fwl test path/to/tests/` walks a directory of `.pkt` files, runs each through the compiler, the AST interpreter, and BPF_PROG_RUN, and reports pass/fail with diffs.

Estimated size: 500-800 lines of Python. Output is a clear, scannable summary. Failures show what went wrong and where. CI-friendly.

### AST interpreter

Walks the parsed AST against a test packet. Same Python codebase as the compiler. Built early because it's the cheapest oracle to run and finds the most spec/compiler discrepancies fast.

Estimated size: 300-500 lines on top of the existing AST.

### BPF_PROG_RUN harness

Loads the compiled BPF program via `bpf(BPF_PROG_LOAD)`, runs it against the test packet via `bpf(BPF_PROG_RUN)`, captures the action and any state changes. Requires `CAP_BPF` (or root) on a Linux test machine.

Estimated size: 200-400 lines. The kernel does the work; this is just orchestration.

### Golden file management

When the compiler changes, generated BPF C changes. Use snapshot tests so you can review diffs without manually inspecting every generated file. `pytest-snapshot` or similar.

### CI

Even if it's just a Makefile target that runs every test on every commit, this is non-optional. The verification loop only works if regressions are caught instantly.

```makefile
test: parser-tests interpreter-tests compiler-tests bpf-tests corpus-tests
	@echo "All tests passed."

corpus-tests:
	fwl test corpus/
```

A pre-commit hook that runs `make test` and refuses the commit on failure prevents bad commits from accumulating. Standard practice but worth stating explicitly.

## Roadmap

Realistic estimates for solo development alongside other work. Expect actual to be 1.5-2x these numbers.

### Weeks 1-2: Foundation

- Write the v0.1 spec for every construct in scope.
- Set up project layout: parser, AST, semantic, codegen, tests.
- Build the test runner and `.pkt` format support.
- Build the AST interpreter.
- Get a `.fw` file parsing into an AST. No code generation yet.

Deliverable: `fwl parse foo.fw` prints the AST. `fwl interpret foo.fw foo.pkt` runs the AST against a test packet and reports the action.

### Weeks 3-4: First construct end-to-end

- Pick the simplest construct: `allow if pkt.proto == tcp` (no fields, just protocol match).
- Take it all the way: parser → AST → semantic check → BPF C emission → BPF compilation via clang → load via bpftool → BPF_PROG_RUN against test packets.
- Most of the compiler infrastructure gets built here.
- Use the agent to generate 20-30 test cases for this construct alone.

Deliverable: end-to-end pipeline works for one construct. The verification loop is operational.

### Weeks 5-6: Field access and protocol guards

- Add `pkt.src_ip`, `pkt.dst_ip`, `pkt.src_port`, `pkt.dst_port`.
- Add `pkt.tcp.syn`, `pkt.tcp.ack`.
- Implement protocol guard checking.
- Implement bounds checks at every parse layer.
- Handle IPv4 with options correctly (variable IHL).

Deliverable: programs that read packet fields work correctly across edge cases.

### Weeks 7-8: Built-in and composition

- Add `rate_limit(N, per=field)` with per-CPU sliding window map.
- Add boolean composition (`and`, `or`, `not`, parens).
- Add the action verbs (`allow`, `drop`, `log`).
- Test programs combining everything.

Deliverable: SSH brute force protection program works correctly. SYN flood protection works correctly. Real-ish firewalls become expressible.

### Weeks 9-10: Hardening

- Generate large test corpus with agent help (target: 200+ cases across all constructs).
- Find and fix bugs revealed by the corpus.
- Document everything.
- Write a README, a tutorial, three example programs that real operators would use.
- Polish error messages.

Deliverable: a corpus that reliably passes, a tutorial that walks through writing a real firewall, error messages that are actually useful.

### Weeks 11-12: Beta dogfood

- Use FWL v0.1 to write the firewall for one machine you actually operate. Your home server. Your dev VM. Optris infrastructure if appropriate. Doesn't matter which — the requirement is that it's a real machine you care about.
- Notice every place where v0.1 is painful, missing something, or confusing.
- File issues for v0.2 — do not fix them in v0.1.
- Tag v0.1, write release notes, ship.

Deliverable: FWL v0.1, used in production by at least one real user (you), with a clear backlog for v0.2.

## The Dogfood Requirement

v0.1 is not done until you have written a real firewall in FWL and deployed it on a machine you operate.

This forces the language design to confront real-world use cases instead of toy examples. Every limitation discovered during dogfooding becomes either a v0.1 fix (if it's a bug) or a v0.2 backlog item (if it's missing functionality). The dogfood firewall stays running on your machine after v0.1 ships, becoming the first reference deployment.

The first user is you. The first program is real. This is the failure mode prevention against "shipped a language nobody can write programs in."

## After v0.1

The v0.2 scope is determined by what dogfooding reveals, not by what was deferred from v0.1. Likely candidates:

- **`geoip()` built-in** — high practical value, reasonable scope
- **`count` action** — natural extension, useful for metrics
- **IPv6 support** — important but doubles the testing surface
- **Tier 2 functions** — significant scope expansion, do this only when v0.1 is solid

Each v0.2 item gets its own spec entry, its own test corpus, its own verification loop. Same methodology, expanded scope.

By v0.5, the language should cover everything in F_PRODUCT_VISION's "What Exists" list and a substantial portion of "What Needs Building." By v1.0, FWL is a stable language that real operators write programs in and ship to production. The path from v0.1 to v1.0 is tens of constructs, hundreds of corpus tests, and continuous dogfooding — all driven by the methodology this document specifies.

## Summary

Build FWL incrementally. Spec each construct before implementing it. Use Claude via the API to multiply your test coverage and stress-test the spec, not to write the compiler. Every construct passes through three oracles (spec, AST interpreter, BPF runtime) before it's considered done. v0.1 is small, frozen, and dogfooded by you on a real machine before shipping.

The language design and compiler implementation are yours. The test corpus and the spec review process are where the agent earns its keep. The result is FWL v0.1: small enough to ship in three months, solid enough to build everything else on.
