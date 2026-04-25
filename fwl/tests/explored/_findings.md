# FWL v0.1 Adversarial Bug-Hunt Findings

Findings from a focused adversarial pass against the v0.1 compiler
(parser / analyzer / interpreter / emitter / loader). All cases were
authored by computing the expected outcome from the spec and only
then running the three-oracle harness.

> Note: BPF_PROG_RUN was unavailable in this environment
> (`unprivileged_bpf_disabled=2`, no root). The "bpf" oracle therefore
> degenerated to a clang-compile-only check; runtime divergence
> between the BPF kernel program and the AST interpreter was not
> directly observable. Findings below report what was reachable.

## Finding 1: huge `rate_limit` threshold emits uncompilable BPF C
**Case:** `tests/explored/rate_limit_threshold_overflow.pkt`
**Spec ref:** docs/FWL_V01_SPEC.md:271-273, 393 (error table entry
"Rate limit threshold non-positive")
**What the spec says:** `<N>` is a "positive integer" threshold. The
spec lists exactly one error for the threshold (`<= 0`); it does not
upper-bound `<N>`.
**What the implementation does:** The analyzer accepts any positive
Python int (Python ints are unbounded). The emitter writes the
threshold as a bare decimal literal: `if (cur < {mod.threshold})`. With
a threshold above the largest C integer type (`unsigned long long`,
2^64-1), clang fails:
```
error: integer literal is too large to be represented in any integer type
   if (cur < 99999999999999999999999999999999) {
```
The interpreter still evaluates correctly (Python int compare).
**Hypothesis:** The analyzer should reject thresholds that don't fit
in `__u32` (the type of `cur` in the emitted C and the type of
`fwl_rl_state.count`), or the emitter should clamp / cast at emit
time. A second-best fix would just bound it to `2^32 - 1`.
**Severity:** medium — a malformed input (oversized literal) takes
the compiler offline; emitter output is structurally invalid C, not
just a verifier rejection. Easy to trigger by a fuzzer.

## Finding 2: integer keys in `state.rate_limit` for IP buckets cause silent interpreter / BPF divergence
**Case:** `tests/explored/state_int_key_for_ip.pkt`
**Spec ref:** docs/PKT_V01_SPEC.md:91-95
**What the spec says:** "for `per=src_ip` / `per=dst_ip` the key is a
dotted-quad string (`"10.0.0.1"`)".
**What the implementation does:** `pkt.py:259-263` accepts whatever
YAML key type the user wrote. The interpreter looks up
`state[idx][packet["src_ip"]]` where `packet["src_ip"]` is the dotted
quad string the builder emitted, so an integer key never matches and
the bucket appears as count=0. The runner's
`_encode_rl_key` (`runner.py:233-252`) DOES convert ints to the same
4-byte LE u32 the emitter expects, so the BPF map gets a populated
bucket. With BPF_PROG_RUN available, BPF would see the bucket at the
configured count while the interpreter sees count=0 → opposite
verdicts.
**Hypothesis:** Either reject non-string keys for `per=src_ip`/`dst_ip`
in the loader, or have the interpreter normalize bucket keys the same
way the runner does.
**Severity:** low — requires malformed input the spec already
disallows; the loader status table notes "partial validation."

## Finding 3: builder accepts but mishandles non-string IPv4 args
**Case:** transient (no .pkt kept; reproduced inline below)
**Spec ref:** docs/PKT_V01_SPEC.md:204-228 (per-constructor field
table — `src_ip`/`dst_ip` declared "dotted quad")
**What the spec says:** IP fields in the builder mini-language take
dotted-quad string values.
**What the implementation does:** `_parse_value` in `pkt.py:74-87`
returns int for unquoted numerics, then `build_packet` passes that
int into `_ipv4_to_bytes`, which crashes with
`AttributeError: 'int' object has no attribute 'split'`. The PKT spec
table at line 251 promises a clear "out of range" error in the loader
but no value-shape error.
**Reproducer:**
```yaml
test_packet:
  builder: tcp(src_ip=16909060, dst_port=80)
```
**Hypothesis:** `_parse_value` / `build_packet` should produce a
loader error of the form `error: src_ip: 16909060 not a dotted quad`
before reaching `_ipv4_to_bytes`.
**Severity:** low — operator-error class; the spec marks loader
validation as "partial — some are Python exceptions."

## Finding 4: spec-reserved-word leakage — bare keywords cannot be used as identifiers despite spec lexical class
**Cases:** transient (verified inline; not retained as .pkt because
both oracles agree they fail to parse, just disagreeing with spec)
**Spec ref:** docs/FWL_V01_SPEC.md:36-39, 543-561 (Identifiers and
the `identifier` production)
**What the spec says:** "Identifiers match `[a-z_][a-z0-9_]*`." The
spec explicitly enumerates only `rate_limit`, `tcp`, `udp`, `icmp` as
"built-in names". `default`, `if`, `or`, `and`, `not`, `xdp`,
`limited`, `by`, `per`, `src_ip`, `dst_ip`, `src_port`, `dst_port`,
`allow`, `drop`, `log`, `count` are **not** declared reserved.
**What the implementation does:** All of the above are inline
literals or higher-priority terminals (`RL_FIELD.10`, etc.) in
`grammar.lark`, so writing `count default if ...`,
`count src_ip if ...`, or `@xdp(default)` produces a generic Lark
"Unexpected token" error. The spec table contains no error message
for "identifier collides with keyword" because the spec doesn't
recognize the collision class.
**Hypothesis:** Either tighten the spec to enumerate the full
reserved-word list, or relax the lexer (e.g. parse contextually so
counter-name and interface-name positions accept keywords). The
former is cheap; the latter would require a less terminal-driven
lexer.
**Severity:** low — a Linux interface or counter named `default` is
plausible but uncommon; mostly a spec/impl wording mismatch.

## Finding 5: spec error-message wording diverges in many places (status-table-acknowledged)
**Cases:** Confirmed for: missing `@xdp` (`error: program must declare
a hook ...` not produced); rule-after-default (`error: 'default' must
be the last rule in the program` not produced — generic Lark
"Unexpected token ALLOW" instead); rate_limit `per=foo` (`error:
rate_limit per= must be src_ip, dst_ip, ...` not produced — generic
"Unexpected token IDENTIFIER" instead); type mismatch wording
(`cannot apply '==' to port (u16) with ipv4 literal` vs spec
`cannot compare <field> (<type>) with <literal> (<type>)`); IPv4
octet >255 produces `IPv4 octet out of range: 999` with no source
span.
**Spec ref:** docs/FWL_V01_SPEC.md:391-400 error table, plus the
loader-side table at PKT_V01_SPEC.md:241-261.
**What the implementation does:** Many of these errors fall through
to Lark's default `UnexpectedInput.__str__` rather than the spec's
templated wording. Acknowledged in PKT_V01_SPEC.md:397
("partial — some are Python exceptions").
**Severity:** low — error wording divergence; doesn't affect oracle
agreement on accept/reject, but operator-facing messages will mislead
when they hit the spec table.

## Areas explored without finding new disagreements
- All 62 corpus + 300 generated cases pass three-oracle (with bpf
  oracle skipped because of CAP_BPF unavailability).
- Protocol-guard analyzer: union-of-OR, intersection-of-AND, no
  narrowing for `!=`, no narrowing through `not`, impossible `AND`
  paths. Behavior is conservative-but-consistent across all three
  oracles.
- CIDR boundaries (/0, /1, /15, /23, /31, /32) and non-canonical host
  bits — both interpreter and emitter compute the same masked prefix
  and emit / accept the same bit pattern.
- Port boundaries (0, 65535) and ranges (`lo..lo`, `0..65535`,
  `lo > hi`) — analyzer + interpreter + emitter all aligned.
- Hex literals in port comparisons, port lists, ranges, rate_limit
  thresholds (within u32) — consistent representation.
- Rate-limit semantics at threshold boundary (`cur < N` fires,
  `cur >= N` blocks) — interpreter and emitter use the same arithmetic.
- Log-event flag bit packing (`bit 0 = SYN`, `bit 1 = ACK`) and
  layout match the spec.
- Counter slot allocation (one slot per unique name, dedup correct,
  256-slot limit enforced) — consistent.
- Bare and no-condition rate_limit modifiers; non-terminal actions
  with rate_limit (count/log gated) — interpreter and emitter agree.
- ICMP packets falling through TCP/UDP-guarded port reads — all
  oracles return 0 for ports and short-circuit at proto guard.
- All 25 spec_ambiguity .pkt cases (including the
  recently-fixed OR-precedence example, `not` constraint discard,
  `at_threshold_does_not_fire`) confirm interpreter behavior matches
  what the spec ultimately settled on.
