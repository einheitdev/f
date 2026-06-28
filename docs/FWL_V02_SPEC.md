# FWL v0.2 — Language Specification

## What FWL Is

FWL is a small declarative language for writing firewall rules. A `.fw`
file declares a sequence of rules; the compiler turns it into an
XDP/eBPF program that runs at line rate in the kernel.

This document specifies FWL v0.2. v0.2 is a near-superset of [v0.1](FWL_V01_SPEC.md): every v0.1 program is a valid v0.2 program with identical packet semantics, **except** v0.1 programs that use one of the four new v0.2 reserved words (`def`, `elif`, `else`, `icmp6`) in an identifier position (counter name, interface name, etc.). Such programs require a one-time rename of the offending identifier — a syntactic adjustment, not a semantic change. The first three are reserved because Tier 2 grammar needs them as statement-leading tokens; `icmp6` is reserved because v0.2 promotes it to a proto keyword (v0.1 had no `icmp6` keyword and admitted it freely as an identifier). No other v0.2 reservation breaks v0.1 backward compatibility. v0.2 adds three constructs to the v0.1 surface:

1. **IPv6 fields** — `pkt.src_ip6`, `pkt.dst_ip6` and IPv6 literals,
   CIDRs, and CIDR lists for matching.
2. **`geoip()` built-in** — variadic two-letter country codes that
   resolve at load time to an LPM trie of prefixes. Valid only on the
   right-hand side of `in`.
3. **Tier 2 programmable functions** — `def fn(pkt):` with
   `if/elif/else`, local variables, and statement-position actions.
   The single Tier 2 function replaces the rule sequence; mixing
   Tier 1 and Tier 2 is not allowed in v0.2.

Everything else from v0.1 is preserved. The deferral list at the end
of this document restates what stays out of v0.2.

The same rigour as v0.1 applies: every construct here has a
[spec](#) entry covering syntax, types, runtime semantics, edge cases,
compile errors, and worked examples. The corpus under
`f/fwl/tests/corpus/` exercises every entry against three independent
oracles (the spec, the AST interpreter, and `BPF_PROG_TEST_RUN`).

## Surface deltas relative to v0.1

Quick map for readers familiar with v0.1:

| Area | v0.1 | v0.2 |
|---|---|---|
| `pkt` fields | `proto`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `tcp.syn`, `tcp.ack` | adds `src_ip6`, `dst_ip6` |
| `pkt.proto` enum values | `tcp`, `udp`, `icmp` | adds `icmp6` |
| Literals | int, ipv4, ipv4 CIDR, port range, list | adds ipv6 (RFC 5952), ipv6 CIDR, ipv6 CIDR list |
| Built-ins | `rate_limit(N, per=...)` | adds `geoip(<cc>, ...)` |
| Program shape | one hook + flat rule sequence | hook + (flat rule sequence **xor** one Tier 2 `def`) |
| Composition | `and`, `or`, `not`, parens | unchanged |
| Comparisons | `==`, `!=`, `<`, `<=`, `>`, `>=`, `in` | unchanged operators; `in` accepts `geoip(...)` and v6 set/CIDR forms |
| Actions | `allow`, `drop`, `log`, `count <n>` | unchanged; available as Tier 2 statements |
| Default rule | `default allow|drop` | unchanged (Tier 1 only) |

A v0.1 program runs unchanged under the v0.2 compiler — modulo the `def`/`elif`/`else`/`icmp6`-as-identifier carve-out described above. The [Phase 1 corpus](../../f-knowlege-base/corpus/) is the regression oracle for this guarantee; any corpus case that uses one of those four words in a v0.1 identifier position (counter name, interface name) requires a one-time rename when the corpus is migrated to v0.2.

## Lexical Structure (delta from v0.1)

v0.1's lexical rules — comments (`#`), identifier shape (`[a-z_][a-z0-9_]*`), decimal/hex integer literals, IPv4 dotted-quad, IPv4 CIDR — carry forward unchanged. v0.2 adds three new literal kinds and one new lexical concern.

**New literal kinds.**

| Kind | Syntax | Example |
|---|---|---|
| IPv6 literal | RFC 5952 canonical form | `2001:db8::1`, `::1`, `::`, `::ffff:1.2.3.4` |
| IPv6 CIDR | IPv6 literal + `/` + prefix | `2001:db8::/32`, `::/0`, `fc00::/7` |
| Country-code token | exactly two uppercase ASCII letters | `RU`, `CN`, `US`, `DE` |

Country-code tokens lexically tokenize as `[A-Z][A-Z]` and are valid only inside a `geoip(...)` argument list. They do not collide with the lowercase-only identifier production. Lowercase or mixed-case spellings (`ru`, `Ru`) are not country-code tokens — they tokenize as identifiers and are rejected by the `geoip(...)` analyser pass.

**IPv6-literal termination.** The lexer reads an IPv6 literal as the longest sequence of characters in the IPv6 character class `[0-9a-fA-F:.]` that is a valid RFC 5952 form. A trailing `:` that would make the sequence invalid (a hextet with no following digits, more than one `::`, or a non-canonical placement) is **not** consumed by the literal — it is returned to the parser as a separate `:` token. So in a Tier 2 line like `if c == 2001:db8::1:`, the lexer produces `IF`, `IDENTIFIER(c)`, `EQ`, `IPV6(2001:db8::1)`, `COLON`, `NEWLINE` — the trailing `:` is the `if`-suffix, not part of the literal. Implementations should use a longest-match-then-validate-with-backtrack strategy (Lark's `priority` + `backtrack` combination, ANTLR's predicates, or a hand-rolled lexer with a final-state RFC-5952 validator).

**Reserved words.** v0.2 introduces the first user-definable identifiers (Tier 2 function names, Tier 2 locals, and counter names — though counter names already existed in v0.1). The following identifiers are reserved and may not appear as a Tier 2 function name, a Tier 2 local name, or a counter name. Lexically they tokenize as their respective keyword classes regardless of context.

- *Statement keywords:* `def`, `if`, `elif`, `else`, `default`.
- *Boolean operators (word-form):* `not`, `and`, `or`.
- *Membership operator (word-form):* `in`.
- *Action keywords:* `allow`, `drop`, `log`, `count`.
- *Modifier keywords:* `limited`, `by`, `per`.
- *Built-in function names:* `rate_limit`, `geoip`.
- *Field-root reserved name:* `pkt`.
- *Proto keywords:* `tcp`, `udp`, `icmp`, `icmp6`.

`for`, `while`, `pass`, `return` are **not** reserved in v0.2 — they are valid identifiers (counter names, locals, function names). v0.3 may introduce loops/`return`, in which case those programs would need a one-time rename. v0.2 trades forward-compat tidiness for backward-compat with v0.1 (which admits the same identifiers as counter names). The three new reservations relative to v0.1 — `def`, `elif`, `else` — are unavoidable: Tier 2 grammar treats them as syntactic keywords, and the parser cannot accept them as identifiers without an LL(*) lookahead the spec doesn't require.

Field-segment names that follow `pkt.` (`proto`, `src_ip`, `dst_ip`, `src_ip6`, `dst_ip6`, `src_port`, `dst_port`, `tcp`, `syn`, `ack`) are recognized as field segments only in field-accessor position and are not globally reserved. A Tier 2 local named `proto` (no `pkt.` prefix) is permitted; a counter named `src_port` is permitted; the reserved-word ban applies only to the bare keyword forms above.

Using a reserved word in a forbidden position is a compile error: `error: '<word>' is reserved and may not be used as a <function|local|counter> name`.

## IPv6 Fields

**Construct.** Two new fields on the `pkt` object:

```
pkt.src_ip6              # IPv6 source address (128 bits)
pkt.dst_ip6              # IPv6 destination address (128 bits)
```

Operands they accept:

| Operand kind | Syntax | Example |
|---|---|---|
| IPv6 literal | RFC 5952 canonical form | `2001:db8::1`, `::1`, `::` |
| IPv6 CIDR | literal `/` prefix | `2001:db8::/32`, `::/0` |
| IPv6 CIDR list | `[ cidr, ... ]` | `[2001:db8::/32, fc00::/7]` |
| IPv6 literal list | `[ literal, ... ]` | `[::1, 2001:db8::1]` |

Operators: `==`, `!=`, `in`. There is no IPv6 range form
(`a..b`) in v0.2 — ranges are deferred to v0.3. Ordered comparisons
(`<`, `<=`, `>`, `>=`) on `pkt.src_ip6` / `pkt.dst_ip6` are not valid
(no useful semantics; matches the v0.1 rule that ordered comparisons
are restricted to numeric port fields).

**Type rules.**

- `pkt.src_ip6` and `pkt.dst_ip6` have type `ipv6`.
- `ipv4` and `ipv6` are distinct types and not comparable. Comparing
  `pkt.src_ip6` against an IPv4 literal — or `pkt.src_ip` against an
  IPv6 literal — is a compile error (see Compile errors below).
- IPv6 literals must be in RFC 5952 canonical form. The four canonicalization rules v0.2 enforces:
  1. Lowercase hex digits.
  2. Suppressed leading zeros within each 16-bit group.
  3. A single `::` collapsing the longest run of all-zero groups (or the first such run if multiple runs tie); `::` may not be used for a run of fewer than two groups.
  4. *RFC 5952 §5 — IPv4-mapped IPv6 addresses.* When the address is an IPv4-mapped IPv6 address (high 80 bits zero, next 16 bits `0xFFFF`, low 32 bits the embedded IPv4 address — the `::ffff:0:0/96` block, RFC 4291 §2.5.5.2), the trailing 32 bits **must** be expressed as a dotted quad. Hex form (`::ffff:0102:0304`) is non-canonical; the canonical form is the dotted-quad form (`::ffff:1.2.3.4`). The deprecated *IPv4-compatible* IPv6 address form (`::a.b.c.d`, RFC 4291 §2.5.5.1, deprecated by that same RFC) is **not** specially canonicalized in v0.2 — addresses in `::/96` outside the IPv4-mapped block follow rules 1–3 only. So `::`, `::1`, `::a`, `::ff`, `::feed`, `::ffff`, and `::ffff:1.2.3.4` are all canonical.

  Non-canonical input — `2001:DB8::1`, `2001:db8:0:0::1`, `2001:db8:0000::1`, `::ffff:0102:0304` — is a compile error. The compiler does not silently canonicalize; the source has to be canonical so diffs and grep are well-behaved.
- An IPv6 CIDR `<addr>/<prefix>` requires `0 <= prefix <= 128`.
- The element type of a CIDR list or literal list must be uniformly
  `ipv6`. Mixing `ipv4` and `ipv6` elements in one list is a compile
  error.
- The element type of the right operand of `in` must match the type
  of the left operand. `pkt.src_ip in [2001:db8::/32]` and
  `pkt.src_ip6 in [10.0.0.0/8]` are both compile errors.

**Semantics.**

- The compiler emits a parse prelude that distinguishes IPv4 from
  IPv6 by the Ethernet `EtherType` field: `0x0800` (IPv4) and
  `0x86DD` (IPv6). Other EtherType values fall through every rule
  (no match), reaching the default action.
- For IPv6 packets, the IPv6 fixed header is 40 bytes. The parser
  bounds-checks the read of the source and destination addresses
  before any access; truncated frames (less than 14 + 40 = 54 bytes)
  cause `pkt.src_ip6` and `pkt.dst_ip6` accesses not to match (the
  rule falls through, identical to truncated-IPv4 behaviour in v0.1).
- **Extension headers.** v0.2 reads only the IPv6 fixed header. If
  the IPv6 next-header field is anything other than `IPPROTO_TCP`
  (6), `IPPROTO_UDP` (17), or `IPPROTO_ICMPV6` (58), the packet is
  treated as having no readable L4. Specifically: if the next header
  is one of the recognized extension headers (Hop-by-Hop, Routing,
  Fragment, ESP, AH, Destination Options, Mobility, HIP, Shim6) the
  parser does **not** chase the extension chain; rules referencing
  `pkt.src_port`, `pkt.dst_port`, `pkt.tcp.syn`, `pkt.tcp.ack`, or
  `pkt.proto` (when used to test `tcp`/`udp`/`icmp6`) **do not match**
  on such packets. The v0.2 compiler rejects no programs on this
  ground; the runtime simply falls through.
  - This is a deliberate conservatism: extension-header chasing
    requires either a bounded loop (verifier-hostile) or a tail-call
    chain (out of scope for v0.2). The behaviour is documented and
    testable, and the corpus must include a Hop-by-Hop case to lock
    it down.
  - L3 fields (`pkt.src_ip6`, `pkt.dst_ip6`) are still readable on
    packets with extension headers — the addresses live in the
    fixed header, which is always at offset 14.
- **`pkt.proto` on IPv6.** The `pkt.proto` field reads the IPv6 fixed
  header's `next_header` byte when the packet is IPv6 (subject to the
  extension-header rule above). The proto enum gains one new value:

  | Keyword | `pkt.proto` byte | Family allowed |
  |---|---|---|
  | `tcp`   | 6  | IPv4 always; IPv6 (no ext hdrs) only when the program activates the v6 parse path (see Compilation) |
  | `udp`   | 17 | IPv4 always; IPv6 (no ext hdrs) only when the program activates the v6 parse path |
  | `icmp`  | 1  | IPv4 always; IPv6 (no ext hdrs) only when the program activates the v6 parse path |
  | `icmp6` | 58 | IPv6 (no ext hdrs) only when the program activates the v6 parse path |

  *Equality semantics.* `pkt.proto == <kw>` evaluates true exactly when **(i)** the L3 read of `pkt.proto` succeeded for the packet's family (the EtherType matched, the parse short-circuited correctly, no extension header chain truncated the next-header byte), **(ii)** the packet's family is in the keyword's "Family allowed" column, and **(iii)** the byte read equals the keyword's IPPROTO. Any of those three failing makes the comparison false — the rule falls through, identical to v0.1's "field unreadable" semantics. `pkt.proto != <kw>` is the negation: true when the read succeeded and the byte differs, *false* when the read failed (so `not (pkt.proto == tcp)` is not the same as `pkt.proto != tcp` on a non-IP frame; the negation rule still requires the read to succeed).

  *Refactor invariance.* Hoisting `pkt.proto` into a Tier 2 local does not change behaviour. `p = pkt.proto; if p == <kw>: …` is exactly equivalent to `if pkt.proto == <kw>: …` *when* the assignment's L3-establishing guard dominates the comparison (per the dominator rule in the Tier 2 section). Inside the dominated region, `p` holds the byte value of the read, and the equality `p == <kw>` is the same byte-and-family check the inline form uses. The "Family allowed" column applies symmetrically to both forms.

  *No cross-family `not` confusion.* A v0.1-shaped program (no v6 surface touched) sees `icmp` and `icmp6` differently: `icmp` matches v4 (IPPROTO 1) only; `icmp6` matches no packet (the v6 parse path is inactive). A v0.2 program that activates the v6 parse path can use either keyword, but each carries its byte-and-family check. This conditionality is what preserves the v0.1 strict-superset guarantee at the start of this spec — a v0.1-shaped program gets v0.1 behaviour on every packet, including v6 packets, exactly as in v0.1.
- **Cross-family rules.** A rule whose condition references
  `pkt.src_ip6` or `pkt.dst_ip6` does not match IPv4 packets (the
  parse for IPv6 fields fails on EtherType `0x0800`). Symmetrically,
  a rule whose condition references `pkt.src_ip` or `pkt.dst_ip` does
  not match IPv6 packets. There is no compile error for accessing v6
  fields without an explicit guard — the parse fall-through is the
  guard.
- **CIDR matching.** v0.2 matches IPv6 CIDRs via two 64-bit masked
  compares against the address halves. Programs reaching the
  hard CIDR map limit may still hit the v0.1 LPM-trie cap (`v0.1`
  used scalar bit-math; v0.2 may continue to do so until LPM is
  wired). The behaviour is identical to v0.1's IPv4 CIDR matcher.
- **`limited by rate_limit(...) per=` field.** The v0.1
  `rate_limit` modifier accepts `per=src_ip|dst_ip|src_port|dst_port`.
  The bucket key is whichever field's runtime value is current at the
  packet. v0.2 keeps the same field list — `per=src_ip` continues to
  bucket on the IPv4 source address only. **Buckets are not shared
  between v4 and v6**: an IPv6 packet has no IPv4 source, and a rule
  with `per=src_ip` does not match IPv6 packets (the field is
  unreadable, so the per-bucket key is undefined and the rule falls
  through). v0.3 will introduce `per=src_ip6` (and a unified
  `per=src_addr` form). Specifying `per=src_ip6` in v0.2 is a compile
  error: `rate_limit per= must be src_ip, dst_ip, src_port, or
  dst_port`.

**Edge cases.**

- *Truncated IPv6.* A frame whose total length is less than 14 + 40
  bytes cannot satisfy any v6 field access — rules touching
  `pkt.src_ip6`, `pkt.dst_ip6`, or any L4 field on a v6 packet fall
  through.
- *Valid v6, no extension headers.* TCP/UDP/ICMPv6 next_header is
  read; L4 fields are accessible; rules behave as expected.
- *v6 with one Hop-by-Hop ext header.* Per the rule above:
  `pkt.src_ip6` / `pkt.dst_ip6` rules still match; rules referencing
  L4 fields or `pkt.proto == tcp|udp|icmp6` do **not** match.
- *IPv4 packet against a v6 rule.* The v6 parse fails on EtherType `0x0800`. The rule falls through.
- *Adversarial cross-family `pkt.proto` byte.* A v6 frame whose `next_header` byte is `1` (the IPv4 IPPROTO for ICMP) does **not** match `pkt.proto == icmp` in a v0.1-shaped program — the v6 parse path is inactive, so the read of `pkt.proto` against a v6 frame fails. In a program that activates the v6 parse path, the comparison evaluates true (per the byte-and-family rule in the proto-enum table). Symmetrically, a v4 frame whose `proto` byte is `58` (the v6 IPPROTO for ICMPv6) matches `pkt.proto == icmp6` only when the v6 parse path is active. Operators who want to gate on family explicitly write the v6 guard alongside the proto check: `if pkt.src_ip6 in ::/0 and pkt.proto == icmp:` is v6-only by construction.
- *Zero address (`::`) and all-ones address
  (`ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff`).* Both are valid
  literals and matchable. `::/0` matches every IPv6 packet; it is the
  v6 equivalent of `0.0.0.0/0`.
- *IPv4-mapped IPv6 addresses (`::ffff:1.2.3.4`).* Treated as IPv6
  literals; they match `pkt.src_ip6` only when the actual frame is
  IPv6 carrying a v4-mapped address. They do **not** match an IPv4
  packet whose source is `1.2.3.4`. (Cross-family equivalence is a
  v0.3 question.)
- *List of mixed-prefix CIDRs.* `[2001:db8::/32, fc00::/7]` is valid;
  each CIDR is matched independently and the rule fires if any
  matches.
- *CIDR with non-canonical address.* `2001:DB8::/32` is a compile
  error per the canonicalization rule; `2001:db8:0::/32` is also a
  compile error. The CIDR's address half is canonicalized
  identically to a literal.
- *Non-zero host bits in a CIDR.* `2001:db8::1/32` is permitted
  (the host bits are masked off at compile time). The compiler
  emits a warning: `warning: CIDR 2001:db8::1/32 has non-zero host
  bits; matching as 2001:db8::/32`. Behaviour matches the v0.1
  IPv4-CIDR rule.

**Compile errors.**

| Condition | Error |
|---|---|
| `pkt.src_ip6 == 1.2.3.4` (or any v4 literal/CIDR/list) | `error: cannot compare pkt.src_ip6 (ipv6) with 1.2.3.4 (ipv4)` |
| `pkt.src_ip == 2001:db8::1` (or any v6 literal/CIDR/list) | `error: cannot compare pkt.src_ip (ipv4) with 2001:db8::1 (ipv6)` |
| IPv6 CIDR with prefix outside 0..128 | `error: CIDR prefix must be 0..128 for IPv6` |
| Non-canonical IPv6 literal (case, leading zeros, or `::` placement) | `error: IPv6 literal must be in canonical (RFC 5952) form; expected '<canonical>'` |
| Hex form of an IPv4-mapped IPv6 address (`::ffff:0102:0304`) | `error: IPv4-mapped IPv6 literal must use dotted-quad form per RFC 5952 §5; expected '<canonical>'` |
| Mixed-family list | `error: list elements must share a type; found ipv4 and ipv6` |
| Ordered comparison on `pkt.src_ip6`/`pkt.dst_ip6` | `error: ordered comparison <op> not valid on pkt.<field> (ipv6)` |
| `per=src_ip6` in `rate_limit` | `error: rate_limit per= must be src_ip, dst_ip, src_port, or dst_port` |
| `rate_limit(..., per=<field>)` whose call site is not dominated by a guard establishing that `pkt.<field>` is readable (the implicit-read dominator rule under Tier 2) | `error: rate_limit(per=<field>) call site does not dominate the implicit read of pkt.<field>` |
| IPv6 range syntax `a..b` | parser-level syntax error — `..` is the port-range operator and the parser does not accept an IPv6 literal on either side. The user-visible message is the parser's normal "unexpected token `..`" form. |

**Examples.**

Drop one specific host (a /128):

```python
@xdp(eth0)

drop if pkt.src_ip6 == 2001:db8:dead:beef::1
default allow
```

Allow only a single /48 prefix and deny the rest:

```python
@xdp(eth0)

allow if pkt.src_ip6 in 2001:db8:cafe::/48
default drop
```

Log all IPv6 traffic, irrespective of L4:

```python
@xdp(eth0)

log if pkt.src_ip6 in ::/0
default allow
```

Cross-family allow-list with a Tier 1 rule that already exists for v4:

```python
@xdp(eth0)

allow if pkt.src_ip in [10.0.0.0/8, 192.168.0.0/16]
allow if pkt.src_ip6 in [2001:db8::/32, fc00::/7]
log   if pkt.proto == tcp and pkt.tcp.syn and not pkt.tcp.ack
default drop
```

## `geoip()` built-in

**Construct.** A built-in function callable only as the right-hand
side of `in`:

```
geoip(<cc> [, <cc> ... ])
```

- `<cc>` is an unquoted (bare) two-letter ISO 3166-1 alpha-2 country
  code in **uppercase** (e.g. `RU`, `CN`, `US`, `DE`).
- Variadic: at least one code, no upper bound on how many can be
  named in one call (subject to the 65 536-prefix cap below).
- The result is an opaque set of IP prefixes. Any LHS of type `ipv4` or `ipv6` accepts it as the right operand of `in`; the LHS's *type* (not its specific name) selects which underlying trie is queried. In Tier 1 the only `ipv4`/`ipv6`-typed LHSes are the four pkt fields (`pkt.src_ip`, `pkt.dst_ip`, `pkt.src_ip6`, `pkt.dst_ip6`); in Tier 2 the same four pkt fields plus any local of type `ipv4` or `ipv6` are admitted.

```python
drop if pkt.src_ip in geoip(RU, CN)
allow if pkt.src_ip6 in geoip(US)
```

Codes are bare identifiers, not strings. v0.1 has no string literals,
so this stays consistent with the language's lexical rules — country
codes are tokens of the form `[A-Z][A-Z]` and only valid inside a
`geoip(...)` argument list.

**Type rules.**

- `geoip(...)` produces an opaque value of type `set<ipv4 | ipv6>`.
  The compiler picks which underlying index is queried based on the
  type of the left operand of `in`:
  - `pkt.src_ip in geoip(...)` and `pkt.dst_ip in geoip(...)` query
    the IPv4 LPM trie for this call site.
  - `pkt.src_ip6 in geoip(...)` and `pkt.dst_ip6 in geoip(...)` query
    the IPv6 LPM trie for this call site.
- *Map allocation is per call site, one family per call site.* Each textual `geoip(...)` occurrence is the right-hand side of exactly one `... in geoip(...)` comparison, and that comparison's left-hand operand binds the call site to a single address family. The analyser allocates one BPF map per call site of the key size matching its bound family — `BPF_MAP_TYPE_LPM_TRIE` with a 32-bit key for IPv4 LHSes (`pkt.src_ip`/`pkt.dst_ip`, or, per the type-based rule, any `ipv4`-typed local), and a 128-bit key for IPv6 LHSes. A program that needs both v4 and v6 coverage of the same country list writes two `geoip(...)` calls, one per family — the analyser does not deduplicate by argument list (v0.3 may).
- Country codes are validated at compile time against a frozen
  ISO 3166-1 alpha-2 list embedded in the compiler
  (`f/fwl/fwl/iso3166.py`). Unknown codes are a compile error.
  Reserved (`AA`, `OO`, `QM`–`QZ`, `XA`–`XZ`, `ZZ`) and
  user-assigned codes are not in the alpha-2 list and are rejected.
- Lowercase codes are a compile error. Mixed case
  (`Ru`, `rU`) is a compile error. The error message points the user
  at the canonical form.
- A `geoip(...)` call may not appear as an argument to another
  function: `geoip(geoip(RU))` and `f(geoip(RU))` are syntactically
  rejected (the grammar limits the form to RHS of `in` only).
- A `geoip(...)` call may not appear in any context other than RHS of
  `in`. `pkt.src_ip == geoip(RU)` is a compile error.
- Duplicate codes inside one call are deduplicated silently (no
  warning). `geoip(RU, RU)` is the same as `geoip(RU)`.

**Semantics.**

- *Compile time.* Each textual occurrence of `geoip(...)` is a distinct call site. By the grammar, a `geoip(...)` call appears only as the right-hand side of an `... in geoip(...)` comparison, and a comparison has exactly one left-hand operand — so each call site is bound to exactly one address family (IPv4 if the LHS is `pkt.src_ip`/`pkt.dst_ip`; IPv6 if the LHS is `pkt.src_ip6`/`pkt.dst_ip6`). The analyser allocates one map ID per call site and emits one `BPF_MAP_TYPE_LPM_TRIE`. Two different textual occurrences of `geoip(RU)` — for example one bound to a v4 LHS and one bound to a v6 LHS — produce two manifest entries with two distinct map IDs (the analyser does not deduplicate by argument list; v0.3 may). The list of country codes is recorded in the bundle's `manifest.json` under the `geoip` section. A program that geo-blocks both v4 and v6 traffic from RU and CN — for example:

  ```python
  drop if pkt.src_ip  in geoip(RU, CN)
  drop if pkt.src_ip6 in geoip(RU, CN)
  default allow
  ```

  produces two manifest entries:

  ```json
  "geoip": [
    {"call_index": 0,
     "codes": ["RU", "CN"],
     "family": "ipv4",
     "map_id": 1,
     "prefix_count": 12345},
    {"call_index": 1,
     "codes": ["RU", "CN"],
     "family": "ipv6",
     "map_id": 2,
     "prefix_count": 2345}
  ]
  ```

  `call_index` is the zero-based source-order index of the `geoip(...)` call. `family` is the single address family the call site is bound to (`"ipv4"` or `"ipv6"`). `map_id` is the unique-across-the-program identifier of the BPF LPM trie populated for this call. `prefix_count` is the number of prefixes loaded for `family` from the listed `codes`. There is exactly one `map_id` per manifest entry — the v0.2 grammar has no syntactic surface that can bind one call site to two families.
- *Bundle-time.* `fwl compile --bundle` reads a static
  `geoip.json` from the path passed via `--geoip-source`
  (default `<cwd>/geoip.json`). The file maps each
  ISO 3166-1 alpha-2 code to an array of CIDRs:

  ```json
  {
    "RU": ["5.8.0.0/16", "2a00:1370::/32", ...],
    "CN": ["1.0.1.0/24", "240e::/20", ...]
  }
  ```

  Codes referenced by the program but absent from the
  `geoip.json` cause `fwl compile --bundle` to fail with
  `error: geoip code 'XX' not present in geoip.json`. The bundle's
  `geoip.json` is copied into the bundle directory verbatim so
  the daemon can re-read it during a hot reload.
- *Load time.* On bundle attach, `fd` parses the bundle's `geoip.json` and, for each `geoip` manifest entry, calls `bpf_map_create` exactly once (the entry's `family` decides the trie's key size — 32 bits for `ipv4`, 128 bits for `ipv6`), then populates the trie via `bpf_map_update_elem` calls before the XDP swap. Only prefixes of the entry's `family` are loaded — IPv4 prefixes from the listed `codes` are skipped on `family: ipv6` entries, and vice versa. Population is atomic with respect to traffic: every map is filled, then the swap happens. The previous bundle's tries are released as part of the bundle's lifecycle.
- *Packet time.* For a packet, the emitter performs an LPM lookup on
  the packet's `src_ip` (or `dst_ip` / `src_ip6` / `dst_ip6`,
  matching the left operand). A non-zero hit value means the address
  is in one of the country prefixes; a miss means it isn't. The rule
  containing the `in geoip(...)` test fires accordingly.
- *Compile-time prefix budget.* The total number of prefixes loaded
  into all `geoip` tries combined (across all call sites and across
  both families) is capped at 65 536 in v0.2. The compiler checks
  the prefix count from `geoip.json` at bundle time; programs that
  exceed the cap fail with `error: geoip prefix budget exceeded:
  <N>; v0.2 limit is 65536`. The cap is per-program, not global.
- *Hot reload.* In v0.2 the bundle's `geoip.json` is captured at
  bundle time. Editing the source `geoip.json` after the bundle is
  built has no effect until the user runs `fwl compile --bundle`
  again, producing a new bundle the watcher will swap in. Live DB
  refresh (re-reading `geoip.json` without rebuilding) is a v0.3
  feature.

**Edge cases.**

- *Unknown country code.* `geoip(XQ)` (XQ is unassigned) is a compile
  error. The error names the alpha-2 standard, not just "invalid".
- *Lowercase or mixed case.* `geoip(ru)` → compile error: `error:
  geoip codes are ISO 3166-1 alpha-2 (two uppercase letters); got
  'ru'`. Same for `geoip(Ru)`.
- *Three-letter code.* `geoip(RUS)` → compile error: `error: geoip
  codes are ISO 3166-1 alpha-2 (two uppercase letters); got 'RUS'`.
  ISO 3166-1 alpha-3 is not supported in v0.2.
- *Empty argument list.* `geoip()` → compile error: `error: geoip
  requires at least one country code`.
- *`geoip(...)` outside `in`.* `pkt.src_ip == geoip(RU)`,
  `if geoip(RU):`, `not geoip(RU)` → compile error: `error: geoip()
  is only valid as the right-hand side of 'in'`.
- *Missing `geoip.json` at compile time.* The bundle build fails with
  `error: --geoip-source path '<path>' does not exist`.
- *Code referenced by program but missing from `geoip.json`.* Bundle
  build fails: `error: geoip code 'XX' not present in geoip.json`.
- *Code present in `geoip.json` but not referenced by program.* The
  daemon does not load it; the bundle is not enriched with prefixes
  the program never queries.
- *Missing `geoip.json` at load time.* `fd` refuses to attach the
  bundle: `fd: refuse to attach: bundle missing required geoip.json`.
  This is a runtime test marked with `expected.compiles: true` and
  `expected.load_action: refuse` (a v0.2 addition to the `.pkt` spec —
  see PKT_V02_SPEC.md).
- *Very-large prefix in source data (a /1).* Permitted; the LPM trie
  handles it the same as any other prefix. A `/1` will match roughly
  half of v4 address space; that is the user's choice.
- *Same code referenced twice in one program.* `if pkt.src_ip in
  geoip(RU)` and `if pkt.dst_ip in geoip(RU)` — the analyser
  allocates **two** map IDs (one per call site). The daemon
  populates both tries with the same prefix data. This is wasteful
  but correct; per-call-site maps are simpler than a global cache
  and avoid cross-rule lifetime issues. v0.3 may de-dupe.
- *Bundle-time refresh between calls.* `fwl compile --bundle` is
  deterministic given the same source `.fw` and the same
  `geoip.json` — running it twice produces identical bundle output
  (modulo the `current` symlink rotation). Hot-swapping a fresh
  bundle into a running `fd` updates the LPM trie atomically; the
  daemon does not allow live updates of the LPM trie of an
  already-loaded bundle (the `current` symlink must change).

**Compile errors.**

| Condition | Error |
|---|---|
| Code is not 2 uppercase letters | `error: geoip codes are ISO 3166-1 alpha-2 (two uppercase letters); got '<seen>'` |
| Code is a quoted string (`geoip("RU")`) | `error: geoip codes are bare identifiers, not strings; got '"RU"'` |
| Code not in the alpha-2 list | `error: unknown country code '<XX>' (not in ISO 3166-1 alpha-2)` |
| Empty argument list | `error: geoip requires at least one country code` |
| `geoip(...)` not in RHS of `in` | `error: geoip() is only valid as the right-hand side of 'in'` |
| Mixed-family `geoip(...)` against a wrong-family operand | falls under the existing type rule of `in` (e.g. `pkt.src_ip in geoip(RU)` is fine; the operand types decide which trie is queried) |
| Prefix budget exceeded | `error: geoip prefix budget exceeded: <N>; v0.2 limit is 65536` |
| Bundle source missing required code | `error: geoip code '<XX>' not present in geoip.json` |
| `--geoip-source` missing | `error: --geoip-source path '<path>' does not exist` |

**Examples.**

Drop one country, allow everything else:

```python
@xdp(eth0)

drop if pkt.src_ip in geoip(RU)
default allow
```

Allow only two countries (and the loopback range), drop the rest:

```python
@xdp(eth0)

allow if pkt.src_ip in 127.0.0.0/8
allow if pkt.src_ip in geoip(US, DE)
default drop
```

Log traffic from a country without affecting routing:

```python
@xdp(eth0)

log if pkt.src_ip in geoip(CN)
default allow
```

Cross-family geoip:

```python
@xdp(eth0)

drop if pkt.src_ip  in geoip(RU, CN)
drop if pkt.src_ip6 in geoip(RU, CN)
default allow
```

## Tier 2 Functions

**Construct.** A v0.2 program may take one of two shapes:

1. **Tier 1 (v0.1-compatible).** `@xdp(<iface>)` followed by a
   sequence of declarative rules and an optional `default` rule, as
   in v0.1.
2. **Tier 2.** `@xdp(<iface>)` followed by exactly one function
   definition `def <name>(pkt):`. The function's body is the entire
   firewall logic for the program.

A program may not mix the two shapes in v0.2. `@xdp` followed by both
declarative rules and a `def` — in either order — is a compile error.
The mix is deferred to v0.3 (where the rules-prelude form will be
spec'd).

The Tier 2 function's syntax:

```
def <name>(pkt):
    <stmt>
    <stmt>
    ...
```

Each statement is one of:

- `if <cond>:` … (with optional `elif <cond>:` blocks and one
  optional `else:` block at the end)
- `<local> = <expr>` — local-variable assignment
- `allow` — terminal: returns `XDP_PASS` immediately
- `drop` — terminal: returns `XDP_DROP` immediately
- `log` — non-terminal: emits one `log_event` and falls through to
  the next statement
- `count <n>` — non-terminal: increments named counter `<n>` by 1
  and falls through to the next statement

Indentation rules: the function body is indented by exactly one level relative to the `def` line. `if`, `elif`, `else` blocks introduce one further level of indentation. The compiler infers the indentation step from the first indented line of the function body — any positive number of spaces, or any positive number of tabs, is accepted. Once chosen, the same step must be applied uniformly at every depth (mismatched indentation is a compile error). Tabs and spaces may not be mixed within a single indentation level. The intent is to accept the user's editor preferences without a step-size whitelist; the spec's worked examples use 2-space indentation purely for readability.

The function name is a bare identifier (`[a-z_][a-z0-9_]*`). The name
is informational — the compiler embeds it in the BPF program name and
the bundle manifest — and not callable from anywhere else. There is
no recursion; calling the function from within itself is a compile
error.

`pkt` is the sole parameter. It is the same `pkt` object as in
Tier 1 (a compile-time symbol). No other parameters are valid.

**Type rules.**

Locals are statically typed. Their type is the type of the right-hand side of the **first** assignment to the name within the function. "First" means first in **source order** — the lexically earliest assignment to the name in the function body. Source-order binding is independent of which control-flow path actually reaches the assignment at runtime; the analyser walks the AST top-to-bottom, depth-first, and the first `<name> = <rhs>` it visits sets the type. Branched assignments (`if cond: x = a else: x = b`) must agree on type; the source-order-first one binds the local, and any subsequent assignment with a different type triggers `error: local '<name>' was bound as <T1>; cannot reassign as <T2>`.

| Type | Width | Examples of values |
|---|---|---|
| `bool` | 1 bit (stored as u8) | `pkt.tcp.syn`, `pkt.tcp.ack`, `pkt.dst_port == 80`, `pkt.src_ip in geoip(RU)` |
| `u16` | 16 bits | `pkt.src_port`, `pkt.dst_port`, integer literals in `0..65535` |
| `u32` | 32 bits | integer literals in `65536..4294967295` |
| `ipv4` | 32 bits | `pkt.src_ip`, `pkt.dst_ip`, IPv4 literals |
| `ipv6` | 128 bits | `pkt.src_ip6`, `pkt.dst_ip6`, IPv6 literals |
| `proto` | 8 bits | `pkt.proto`, `proto_keyword` literals (`tcp`, `udp`, `icmp`, `icmp6`) |

An integer literal's type is the smallest unsigned integer type from `{u16, u32}` that contains its value. So `5`, `0xff`, `65535`, `0x10`, `22` are `u16`; `65536`, `0x10000`, `4294967295` are `u32`. Literals exceeding u32 are a compile error: `error: integer literal <N> exceeds u32 range`. There is no implicit widening or narrowing in v0.2 — a comparison between a `u16` operand and a `u32` operand is a type error.

The `proto` type is opaque. `proto`-typed values (the `pkt.proto` field, a Tier 2 `proto`-typed local, or a `proto_keyword` token) may participate in: equality and inequality (`==`, `!=`) against any other `proto`-typed value, and `in` over a list of `proto_keyword` tokens (e.g. `pkt.proto in [tcp, icmp6]`). The single-element form `pkt.proto in [tcp]` is equivalent to `pkt.proto == tcp` per v0.1's `in [N] ≡ == N` rule. Arithmetic, ordered comparisons (`<`, `<=`, `>`, `>=`), `in` over a non-proto-keyword RHS (CIDR, range, `geoip(...)`), and comparisons against any non-`proto`-typed value are all type errors. The motivation for the ordered-comparison ban: `pkt.proto` is an enum on the wire (an 8-bit IPPROTO value) that the user thinks of by name; `pkt.proto < udp` happens to be defined by the byte values `1, 6, 17, 58` but means nothing operationally. Equality and proto-keyword-list membership both have obvious operational meanings.

A local that is **read** before it is **assigned** is a compile error:
`error: local '<name>' read before assignment`. Reachability matters
— see the example under Edge cases.

Reassigning a local with a value of a different type is a compile
error: `error: local '<name>' was bound as <T1>; cannot reassign as
<T2>`. Re-assigning a local with the same type is permitted.

There are no user-defined functions other than the entry point in
v0.2. There are no closures: the function's locals are all local to
the function body and disappear at exit.

A local's name shadows nothing — the function is the only scope. The reserved-word set defined in [Lexical Structure](#lexical-structure-delta-from-v01) is not available as a local name (this is the same set that is unavailable as a function name or counter name). Locals, function names, and counter names share one global pool of "non-reserved identifiers"; a counter named the same as a local is permitted but discouraged, and the compiler emits a stylistic warning.

**Semantics.**

- The function executes statement-by-statement, top to bottom.
- `allow` and `drop` are terminal: control returns to the verifier
  with `XDP_PASS` (allow) or `XDP_DROP` (drop) and no further
  statements execute.
- `log` and `count <n>` execute their side effect and fall through to
  the next statement.
- `if <cond>:` evaluates `<cond>` (with the same boolean semantics
  and short-circuit behaviour as Tier 1). If true, the if-body
  executes and falls through to the statement after the entire
  `if/elif/else` chain. If false, the next `elif` (if any) is tried;
  failing all `elif`s, the `else` block runs (if present); failing
  all of them, control falls through to the statement after the
  chain.
- A function body that ends without reaching a terminal (`allow` or
  `drop`) on every path is **not** a compile error. The implicit
  fall-through is `allow`. (This matches the v0.1 default-action
  rule. Authors who want a deny-by-default end with an explicit
  `drop` line.)
- *Locals on the BPF stack.* Each declared local consumes a stack
  slot of `ceil(width/8)` bytes, rounded up to 8-byte alignment to
  match the BPF verifier's stack model. The analyser estimates the
  total stack consumption per function. The XDP verifier reserves a
  hard cap of 512 bytes; the analyser warns at **256 bytes** and
  errors at **450 bytes** of estimated stack use to leave headroom
  for the verifier's own internal frames. (See "Compile errors"
  below for the exact message.)
- *Short-circuit and protocol guards within a single condition.* All v0.1 short-circuit and protocol-guard rules apply unchanged inside a single Tier 2 `if`/`elif` condition: a condition like `if pkt.proto == tcp and pkt.dst_port == 22:` reads `pkt.dst_port` only when the proto check passes, exactly as in Tier 1. Across nested `if`s — where the proto guard sits in an outer `if`'s condition and the field access sits in an inner `if`'s condition (or in a statement inside the outer branch) — the rule generalises to a control-flow dominator check, described next.
- *Cross-statement `pkt` reads — guard dominator rule.* Tier 2 introduces two new contexts where a protocol-specific or family-specific `pkt` field can be read outside the same-predicate short-circuit form:
  - **Bare-field statement position** — the RHS of a local assignment is *just* a field read, with no surrounding comparison or `in`: `port = pkt.dst_port`, `addr = pkt.src_ip`, `p = pkt.proto`, `s = pkt.tcp.syn`. The field is read directly into the local; there is no fall-through path to make the read safe on the wrong family/protocol.
  - **Inner-condition position** — an `if`/`elif` condition that lacks the proto guard locally but sits inside an enclosing `if` whose condition has already established it, e.g. `if pkt.proto == tcp:\n  if pkt.dst_port == 22:`.

  *Reads of a `pkt` field that sit inside a comparison or `in` expression — whether the comparison is the whole condition of an `if`, the RHS of an assignment (`is_ssh = pkt.dst_port == 22`, `internal = pkt.src_ip in [10.0.0.0/8]`), or a sub-condition under `not`/`and`/`or` — are governed by v0.1's short-circuit semantics, not by the dominator rule.* The comparison itself reads the field only when the parse succeeded (EtherType match plus protocol-guard satisfied per the v0.1 short-circuit rules); on a non-matching packet, the comparison evaluates to false and the surrounding `if` or assignment-RHS sees `false`/no-match. The dominator rule does not need to fire on these reads because there is no garbage-byte hazard — the comparison's fall-through behaviour already protects the program.

  Both bare-field statement-position reads and inner-condition position reads are governed by the same control-flow dominator check:
  - A read of `pkt.src_port`, `pkt.dst_port` is valid only at program points dominated by a `pkt.proto == tcp` or `pkt.proto == udp` guard (or a disjunction whose branches together cover both, per the v0.1 union-of-branches rule).
  - A read of `pkt.tcp.syn`, `pkt.tcp.ack` is valid only at program points dominated by a `pkt.proto == tcp` guard.
  - A read of `pkt.src_ip6`, `pkt.dst_ip6` is valid only at program points dominated by a guard that establishes the packet is IPv6. Two ways to satisfy that guard:
    - A condition that reads `pkt.src_ip6` or `pkt.dst_ip6` directly (e.g. `if pkt.src_ip6 == ::1:` or `if pkt.src_ip6 in ::/0:`). Reaching the inside of such a branch implies the v6 parse succeeded.
    - A condition that reads `pkt.proto == icmp6` (icmp6 only exists on v6 packets). `pkt.proto == tcp` and `pkt.proto == udp` do **not** satisfy the v6 guard, since both proto values exist on both families.
  - A read of `pkt.proto` itself is valid only at program points dominated by an L3-establishing guard. Two ways to satisfy that guard:
    - A condition that reads any of `pkt.src_ip`, `pkt.dst_ip`, `pkt.src_ip6`, or `pkt.dst_ip6` directly (the parse short-circuits on EtherType, so reaching the inside implies the L3 parse succeeded for the relevant family).
    - A condition that uses a *family-restricted* proto keyword on a `pkt.proto` comparison — `pkt.proto == icmp6` or its semantically-equivalent single-element list form `pkt.proto in [icmp6]` (icmp6 is the only family-restricted keyword in v0.2; it matches IPv6 only). Reaching such a comparison's then-branch implies (a) the `pkt.proto` read succeeded — i.e. the L3 parse for the inferred family succeeded — and (b) the family is the keyword's family. A statement-position `p = pkt.proto` inside such a branch is therefore safe by transitivity. *Cross-family proto keywords* (`tcp`, `udp`, `icmp`) do **not** satisfy the L3 guard, because they accept both families in v6-active programs and neither family alone is established by the comparison. *Multi-element `in`-lists* like `pkt.proto in [icmp6, tcp]` fall under the disjunction rule below: every list element must independently establish the guard, so a list mixing `icmp6` with a cross-family keyword does **not** establish v6 (the `tcp` arm fails the v6 condition).

    The "two reads of `pkt.proto` is fine; one read of `pkt.proto` requires a separate L3 guard" asymmetry is intentional: the same byte is read once in the comparison and once in the assignment, but the comparison's short-circuit semantics already protects its own read, whereas the assignment's bare read needs the dominator. On a non-IP frame (ARP, LLDP, raw 802.1Q with non-IP inner, etc.) `pkt.proto` is unreadable; the dominator rule prevents the bare read from ever happening.
  - *`rate_limit(N, per=<field>)` performs an implicit `pkt.<field>` read at the call site to compute its bucket key. The dominator check applies to that implicit read identically to a bare-field read — `per=src_port`/`per=dst_port` requires a `pkt.proto == tcp` or `pkt.proto == udp` dominator; `per=src_ip`/`per=dst_ip` requires an IPv4-establishing dominator; the four `per=` fields all require their respective field be readable on every packet that can reach the call site. A `rate_limit` whose `per=` field is not dominated is a compile error: `error: rate_limit(per=<field>) call site does not dominate the implicit read of pkt.<field>`. This generalises the cross-family dead-rule check (now subsumed) and applies symmetrically to Tier 1 `limited by rate_limit(...)` modifiers and Tier 2 `if rate_limit(...):` conditions.
  - **Dominator semantics — polarity- and disjunction-aware.** A guard is *established along a control-flow path* only when entering the **then-branch** of an `if` or `elif` whose condition was *positively* established by reading the guarding field. Specifically:
    - The then-branch of `if <field> == ...:`, `if <field> != ...:`, `if <field> in <set>:`, or analogous comparisons that read the guarding field is dominated. Reaching the inside means the comparison evaluated true, which (per v0.1's short-circuit rule) implies the field's parse succeeded.
    - The `else` branch of such an `if` and the body of `if not (...):` are **not** dominated, even if the original `if` mentioned the guarding field. Reaching them means the comparison evaluated false, and that can happen for two distinct reasons — either the parse succeeded but the test failed, or the parse failed (EtherType mismatch, truncation). The two reasons cannot be distinguished, so the spec treats negation/`else`/`elif` paths as not-guarded.
    - The body of an `elif` clause is not dominated by the *preceding* `if`/`elif` conditions (they evaluated false, which carries no guarantee about the guard). It is dominated by its own condition, on the same positive-then-branch rule.
    - A disjunction `cond_a or cond_b` establishes a guard for the then-branch only when **every** disjunct independently establishes the guard (the v0.1 union-of-branches rule). `pkt.src_ip6 == ::1 or pkt.proto == tcp` does not establish the v6 guard, because the right disjunct can be true on a v4 TCP packet without the v6 parse succeeding. `pkt.proto == tcp or pkt.proto == udp` does establish the L4-readable guard, because both disjuncts independently provide one.
    - Statements after the `if`/`elif`/`else` block are not dominated, because the false branches reach the same code without the guard.

    Reads on non-establishing paths fail the dominator check with the existing "'<field>' read on a path not guarded by ..." error. The analyser implements this as a polarity-aware control-flow walk: it tracks the set of established guards entering each statement, adds guards on entry to a positively-establishing then-branch, and clears guards on entry to a non-establishing path (`else`, `elif` body, `not`-wrapped, statements after the block).

  A read that fails the dominator check is a compile error: `error: '<field>' read on a path not guarded by 'pkt.proto == <required>'` (for L4 fields), or `error: 'pkt.src_ip6'/'pkt.dst_ip6' read on a path not guarded by an IPv6-establishing condition` (for L3 v6 fields). This is the strict resolution of two related spec holes (`finding/2026-05-01-v02-spec-tier2-stmt-level-pkt-read-on-wrong-protocol` and `finding/2026-05-01-v02-spec-tier2-stmt-level-ipv6-l3-read-undefined-value`). The analyser already needs control-flow analysis for the local-read-before-assignment check; the dominator check is the same pass.

  *IPv4 L3 reads in statement position obey the same dominator rule.* A bare `addr = pkt.src_ip` (or `pkt.dst_ip`) on a non-IPv4 frame reads garbage bytes from the Ethernet payload at the v4-source-address offset; that is no different from the v6 case. v0.1 dodged the question because v0.1 only reads L3 fields inside rule predicates, which short-circuit on EtherType. v0.2 Tier 2 statement reads do not have that short-circuit, so the dominator rule applies here too: `pkt.src_ip`/`pkt.dst_ip` in statement position must be dominated by a guard that establishes the packet is IPv4. The only v4-establishing guards in v0.2 are conditions that read `pkt.src_ip` or `pkt.dst_ip` directly (the parse short-circuits on EtherType `0x0800` and reaching the inside implies success). `pkt.proto == tcp`, `pkt.proto == udp`, and `pkt.proto == icmp` do **not** satisfy the v4 guard, because every one of those proto keywords matches v6 frames in v6-active programs (per the proto-enum table). There is no proto-only IPv4 guard in v0.2; users who want one must include an `pkt.src_ip in [0.0.0.0/0]` or similar v4-only L3 read in the condition. (The asymmetry with the v6 guard list, which admits `pkt.proto == icmp6`, comes from `icmp6` being family-restricted to IPv6 — there is no v0.2 keyword that is symmetrically v4-restricted.)

  Example 4 of this section (`internal = pkt.src_ip in [10.0.0.0/8, 192.168.0.0/16]`) is governed by short-circuit semantics, not by the dominator rule, because the read sits inside an `in` expression. On a v6 packet, the `in` evaluates to `false` and `internal` takes value `false`. Same for `is_ssh = pkt.dst_port == 22` — the `==` is short-circuit-protected; the bare form `port = pkt.dst_port` is not, and triggers the dominator check.
- *`rate_limit(...)` and `geoip(...)` inside Tier 2.* Both built-ins
  are valid inside Tier 2, but only inside the contexts that v0.2
  permits:
  - `rate_limit(N, per=<field>)` is valid only inside an `if`
    condition. It evaluates to `bool` (true when the bucket is at or
    above the threshold). A bare statement form (`rate_limit(10,
    per=src_ip)` on its own line) is a compile error.
  - `geoip(...)` is valid only as the right-hand side of an `in`
    expression, exactly as in Tier 1.
- *Counter names.* The same per-program 256-counter cap as in v0.1
  applies. Counter names declared inside a Tier 2 function share the
  program-level namespace.

**Edge cases.**

- *Empty function body.* The grammar's `function_def` requires at least one `statement` after the `INDENT` (`function_def = "def" identifier "(" "pkt" ")" ":" NEWLINE INDENT statement { statement } DEDENT`), so `def f(pkt):` followed by no indented statement is a parser-level error (no production matches the missing statement). `pass` is **not** a workaround either: `pass` is a non-reserved identifier per Lexical Structure, so `def f(pkt):\n    pass` parses `pass` as an `IDENTIFIER` at statement position. Statement productions require `pass = <scalar_expr>` (an `assign_stmt`) or `pass(...)` (a function call — none exists in v0.2) to consume the identifier; with no `=` and no `(` following, the parser fails with a generic "unexpected token" diagnostic. There is no analyser-level "empty body" message in v0.2 because the grammar already rules out empty bodies.
- *Single statement.* `def f(pkt):\n    allow` is the minimal valid
  Tier 2 program. Equivalent to `@xdp(eth0)\nallow`.
- *Deeply nested if.* Nesting depth is limited only by the stack
  budget; there is no syntactic cap. The corpus locks behaviour at 5
  levels.
- *Local declared but never read.* Compile warning: `warning: local
  '<name>' declared but never read`. Not an error — useful for
  logging-only intermediates the user may add for clarity.
- *Local read before assigned.* Hard compile error: `error: local '<name>' read before assignment`. The check is path-sensitive: reading the local in a branch where it has not been assigned on every preceding path is the trigger.
- *Unguarded statement-level L4 read.* `port = pkt.dst_port` at the top of the function (no preceding proto guard) is a compile error per the dominator rule above. Wrapping the read in an `if pkt.proto == tcp or pkt.proto == udp:` block makes it valid. The dogfood example at the end of this spec respects this rule: every L4 read sits inside an `if pkt.proto == tcp` (or `udp`) block.
- *Unreachable statements (semantic, per-branch).* A statement is **unreachable** if every control-flow path from the function entry that could reach it terminates first. The check is the same control-flow walk the dominator rule uses, with terminal actions (`allow`, `drop`) marking path termination. Three concrete cases the rule covers:

  *Reachable.* A statement after an `if` whose body terminates but whose else-branch (or implicit fall-through when no `else` is written) does not:
  ```python
  if pkt.proto == tcp:
    if pkt.tcp.syn:
      drop
  allow
  ```
  The trailing `allow` is reachable whenever either `if` does not match.

  *Unreachable — bare terminal.*
  ```python
  drop
  allow
  ```
  Compile error: `error: unreachable statement after terminal action 'drop'`.

  *Unreachable — fully-terminating if/elif/else.* When every branch of an `if`/`elif`/`else` chain (including the implicit fall-through if no `else` is written — but here every branch is written and every branch terminates) ends in a terminal action, the next statement is unreachable:
  ```python
  if pkt.proto == tcp:
    drop
  else:
    drop
  allow                                   # error: unreachable
  ```
  Same error message as the bare-terminal case. The analyser walks the same branch-state it tracks for the dominator check; a chain whose every branch's terminal flag is set propagates "terminated" to the statement after the chain.
- *Single `def` with no `@xdp`.* A bare `def f(pkt):` block without a preceding `@xdp(...)` is a compile error: `error: 'def' must be preceded by an @xdp(<iface>) hook declaration`.
- *Two `def`s.* Two function definitions in one file → compile
  error: `error: v0.2 supports only one Tier 2 function per program;
  found '<n1>' and '<n2>'`.
- *`for`, `while`, `return`, `pass` as statement leaders.* These tokens lex as `IDENTIFIER` per Lexical Structure (they are non-reserved; `for`/`while`/`pass`/`return` are valid v0.2 identifiers). Used as a bare statement leader they fail to match any of `if_stmt`, `assign_stmt`, or `action_stmt` (no `=` follows, no production consumes them) and produce a parser-level "unexpected token" error. There is no dedicated analyser message — the diagnostic is the parser's normal form. (BPF verifier loops are out of scope for v0.2; if a future v0.3 adds them as statement keywords, that's a forward-compatibility break documented in the strict-superset carve-out.)
- *General function calls.* The grammar admits no general function-call form. The only function-shaped surfaces are `geoip(...)` (only as the RHS of `in`) and `rate_limit(...)` (only as a `primary` inside an `if`/`elif` condition). A bare `firewall(pkt)` statement, `f(x)` expression, `geoip(geoip(RU))` nested call, or any other form that puts an `identifier "(" ... ")"` outside the two whitelisted positions is a *parser* error (the parser has no production that consumes the `(`). User-defined function calls — including recursion of the entry function on itself — are therefore structurally impossible to write, not analyser-rejected. The deferral list at the end of this spec restates "user-defined functions other than the entry point" as a v0.3 item; v0.2 simply doesn't have the grammar surface.
- *Mixing Tier 1 and Tier 2.* `allow if pkt.proto == tcp\ndef
  f(pkt): drop` → compile error: `error: v0.2 program is either a
  Tier 1 rule sequence or a single Tier 2 function, not a mix`.
- *Stack budget.* A function whose locals are estimated to exceed
  450 bytes of stack causes `error: function '<name>' estimated
  stack use is <N> bytes; v0.2 limit is 450 bytes`. At 256–449
  bytes, a `warning: function '<name>' estimated stack use is <N>
  bytes; v0.2 soft limit is 256 bytes` is emitted.
- *Boolean in non-bool context.* Locals of type `bool` are not numerically convertible. Inside a Tier 2 `if` condition, a bare bool local is a valid `primary` (`if my_bool:`). Inside a comparison, both sides of `==`/`!=` may be a `bool` local or a `bool` packet field, but mixing types is a type error: `pkt.dst_port == my_bool` — type error (`u16` vs `bool`); `my_bool == pkt.tcp.syn` — fine (both `bool`). Symmetrically, a non-`bool` local or non-`bool` packet field used as a *bare* condition primary is a type error — `if my_u16:`, `if pkt.dst_port:`, `if my_proto:`, `if my_ipv4:`, `if my_ipv6:` are all rejected. The only bare-condition forms are `bool` locals, the two `bool` packet fields `pkt.tcp.syn` and `pkt.tcp.ack`, and (parenthesized) sub-conditions. There is no implicit truthiness coercion in v0.2. Note that Tier 1 rules cannot reference Tier 2 locals — `count <n> if my_bool` is a *Tier 1 rule* form, and a Tier 1 rule cannot mention a local that exists only inside a Tier 2 function (and v0.2 already disallows mixing the two shapes in one program).
- *`elif` without `if`.* Syntactically rejected by the grammar.
- *`else` without preceding `if`.* Syntactically rejected by the
  grammar.

**Compile errors.**

| Condition | Error |
|---|---|
| `def` without preceding `@xdp` | `error: 'def' must be preceded by an @xdp(<iface>) hook declaration` |
| Two `def`s in one file | `error: v0.2 supports only one Tier 2 function per program; found '<n1>' and '<n2>'` |
| Mixing Tier 1 rules and a `def` | `error: v0.2 program is either a Tier 1 rule sequence or a single Tier 2 function, not a mix` |
| Local read before assigned | `error: local '<name>' read before assignment` |
| Local re-assigned with different type | `error: local '<name>' was bound as <T1>; cannot reassign as <T2>` |
| Bare `pkt.<L4 field>` read (RHS of assignment with no surrounding comparison/`in`, or inner-condition position) at a point not dominated by a proto guard | `error: '<field>' read on a path not guarded by 'pkt.proto == <required>'` |
| Bare `pkt.src_ip6`/`pkt.dst_ip6` read at a point not dominated by an IPv6-establishing guard | `error: '<field>' read on a path not guarded by an IPv6-establishing condition` |
| Bare `pkt.src_ip`/`pkt.dst_ip` read at a point not dominated by an IPv4-establishing guard | `error: '<field>' read on a path not guarded by an IPv4-establishing condition` |
| Bare `pkt.proto` read at a point not dominated by an L3-establishing guard | `error: 'pkt.proto' read on a path not guarded by an L3-establishing condition` |
| RHS of local assignment is a list, range, or CIDR literal | `error: '<name>' assignment RHS must be scalar (bool/integer/ipv4/ipv6/proto); list/range/CIDR literals are only valid on the right of 'in'` |
| `proto`-typed value used with `<`, `<=`, `>`, `>=`, or arithmetic | `error: 'proto' values support only equality (==, !=) and 'in' over proto-keyword lists; got '<op>'` |
| `proto`-typed LHS with `in` over a non-proto-keyword RHS (CIDR, range, geoip, mixed-type list) | `error: 'proto' values may only appear with 'in' over a list of proto_keyword tokens; got <T>` |
| `proto`-typed value compared against a non-`proto`-typed value | `error: cannot compare proto value with <T> value` |
| Non-`bool` local or non-`bool` packet field used as a bare condition primary | `error: '<name>' is type <T>; only bool values are valid as a bare 'if' condition` |
| Integer literal exceeds u32 range | `error: integer literal <N> exceeds u32 range` |
| Ordered comparison with mismatched integer types or non-integer operand | `error: cannot compare <T1> with <T2> using <op>; ordered comparisons require matching integer types (u16 or u32)` |
| Local named `pkt` | `error: 'pkt' is reserved; cannot be used as a local name` |
| Bare `rate_limit(...)` statement, or as the RHS of a comparison or assignment, or in a Tier 1 `if` condition | `error: rate_limit(...) is only valid as the condition of an if-statement in Tier 2 or as the 'limited by' modifier of a Tier 1 rule` |
| Unreachable statement — every control-flow path that could reach it terminates first (bare-terminal predecessor, or `if`/`elif`/`else` chain where every branch terminates) | `error: unreachable statement after terminal action '<allow|drop>'` |
| Stack budget exceeded (estimate ≥ 450 B) | `error: function '<name>' estimated stack use is <N> bytes; v0.2 limit is 450 bytes` |
| Inconsistent indentation | `error: inconsistent indentation in function '<name>'` |
| Tabs and spaces mixed in one indentation level | `error: tabs and spaces mixed in indentation` |

**Examples.**

1. SSH brute-force protection as a Tier 2 function:

   ```python
   @xdp(eth0)

   def firewall(pkt):
     if pkt.proto == tcp and pkt.dst_port == 22:
       if pkt.src_ip in [0.0.0.0/0]:                # v4-establishing guard
         if pkt.tcp.syn and not pkt.tcp.ack:
           if rate_limit(10, per=src_ip):
             drop
         allow
     allow
   ```

   The outer `if` enters the SSH branch only when the proto + port guard passes. The inner `if pkt.src_ip in [0.0.0.0/0]:` is the IPv4-establishing guard required by the dominator rule for the implicit `pkt.src_ip` read inside `rate_limit(per=src_ip)`. Inside, a new SSH SYN that exceeds the per-source rate is dropped; everything else falls through to the trailing `allow`. Non-SSH traffic and non-v4 traffic fall through the outer/inner `if` to the final `allow`. v6 SSH traffic is allowed unconditionally here — see the dogfood example for the bifurcated v4/v6 form that protects both.

2. geoip + port allow-list:

   ```python
   @xdp(eth0)

   def firewall(pkt):
     if pkt.src_ip in geoip(RU, CN):
       drop
     if pkt.src_ip6 in geoip(RU, CN):
       drop
     if pkt.proto == tcp and pkt.dst_port in [80, 443]:
       allow
     drop
   ```

   Reads: drop traffic from RU or CN (v4 and v6); else allow only
   80/443; else drop.

3. Nested if/elif/else demonstrating the chain semantics:

   ```python
   @xdp(eth0)

   def firewall(pkt):
     if pkt.proto == tcp:
       if pkt.dst_port == 22:
         log
         allow
       elif pkt.dst_port in [80, 443]:
         count web
         allow
       else:
         drop
     elif pkt.proto == udp:
       allow
     else:
       drop
   ```

4. Locals computing once, reused later:

   ```python
   @xdp(eth0)

   def firewall(pkt):
     internal = pkt.src_ip in [10.0.0.0/8, 192.168.0.0/16]
     if internal:
       allow
     if pkt.proto == tcp and pkt.dst_port in [80, 443]:
       allow
     drop
   ```

   `internal` is a `bool` local, assigned once, read once.

5. Stack-budget stress-test (the corpus locks the analyser's
   estimator against the verifier's reported usage):

   ```python
   @xdp(eth0)

   def firewall(pkt):
     if pkt.src_ip in [0.0.0.0/0]:
       a = pkt.src_ip
       b = pkt.dst_ip
       if a == 10.0.0.1:
         allow
       if b == 10.0.0.2:
         drop
     if pkt.src_ip6 in [::/0]:
       c = pkt.src_ip6
       d = pkt.dst_ip6
       if c == 2001:db8::1:
         allow
       if d == 2001:db8::2:
         drop
     if pkt.proto == tcp or pkt.proto == udp:
       e = pkt.src_port
       f = pkt.dst_port
       if e == 22:
         log
       if f == 22:
         count ssh
     drop
   ```

   Six locals total. Each family's L3 reads sit inside an "always-true for that family" guard (`pkt.src_ip in [0.0.0.0/0]` is true on every IPv4 packet and false on every non-IPv4 packet; the analogous v6 form covers IPv6). The L4 reads sit inside a `pkt.proto == tcp or pkt.proto == udp` block. The estimator should report ~64 bytes of stack (the two ipv6 locals dominate the budget; the two ipv4 and two u16 locals share the rest) — well under the 256-byte soft limit. The example demonstrates the simultaneous-stack-occupancy assumption: locals declared in disjoint blocks still share the function's stack frame.

## Bundle additions for v0.2

`fwl compile --bundle <dir>` extends the v0.1 bundle layout with
two pieces:

1. **`manifest.json`'s `geoip` section.** A list of objects, one per `geoip(...)` call site, in source order. Each entry binds one call site to exactly one address family (per the geoip Semantics: each call site has a single LHS family from its host comparison). The shape:
   ```json
   "geoip": [
     {"call_index": 0,
      "codes": ["RU", "CN"],
      "family": "ipv4",
      "map_id": 1,
      "prefix_count": 12345},
     {"call_index": 1,
      "codes": ["RU", "CN"],
      "family": "ipv6",
      "map_id": 2,
      "prefix_count": 2345}
   ]
   ```
   `call_index` is zero-based source order. `family` is `"ipv4"` or `"ipv6"` and determines the LPM trie's key width. `map_id` is a single integer unique across the whole program. `prefix_count` is the number of prefixes loaded for this entry from the listed `codes` (filtered to the entry's `family`). A program with only IPv4 geoip uses produces only `family: "ipv4"` entries; the v6 keys never appear unless the program also references `pkt.src_ip6`/`pkt.dst_ip6` against a geoip call.
2. **`geoip.json`** in the bundle directory. A verbatim copy of the `--geoip-source` file. The bundler does not subset, prune, or canonicalize. Two motivations: (a) the daemon must be able to re-read the file during a hot reload that may add new country codes, and (b) bundle output must be deterministic given the source `.fw` and the source `geoip.json`. The reproducibility claim under "Hot reload" in the geoip section is contingent on this rule.

`fd` reads the manifest, then for each entry calls `bpf_map_create` exactly once (`BPF_MAP_TYPE_LPM_TRIE` with key size 32 or 128 bits matching the entry's `family`) and populates it from `geoip.json` before the XDP swap. A bundle attach is refused with one of two distinct error strings depending on the failure mode:

- **`geoip.json` file missing from the bundle.** `fd: refuse to attach: bundle missing required geoip.json`. (This is the same string the geoip section's Edge cases paragraph specifies for the load-time test.)
- **`geoip.json` present but does not contain every code the manifest requires.** `fd: refuse to attach: bundle's geoip.json is missing required codes: <CC>, <CC>, ...`. The `<CC>` list is sorted, comma-separated, and includes only the codes the program references that are absent from the file.

A `.pkt` test that asserts one of these failure modes via `expected.load_action: refuse` matches the wording string above exactly (or via the `load_error_pattern` regex described in `PKT_V02_SPEC.md`).

The IPv6 bundle work is invisible to the bundle layout — the
emitter's IPv6 parse code is part of `main.bpf.c` like any other
code.

## Operators (delta from v0.1)

The set of operators is unchanged. The right operand of `in` accepts
two new forms in v0.2:

- An IPv6 literal, IPv6 CIDR, IPv6 literal list, or IPv6 CIDR list
  (when the left operand is `pkt.src_ip6` or `pkt.dst_ip6`).
- A `geoip(...)` call (when the left operand has type `ipv4` or `ipv6` — i.e. any of the four pkt IP fields, or in Tier 2 any local of type `ipv4` or `ipv6`).

Comparison operators (`==`, `!=`) accept IPv6 literals on the right when the left is an `ipv6` field. Ordered comparisons (`<`, `<=`, `>`, `>=`) require both operands to share an integer type (`u16` or `u32`). The valid LHS forms are `pkt.src_port`, `pkt.dst_port` (both `u16`), or — in Tier 2 — any local of type `u16` or `u32`. The valid RHS forms are integer literals (whose type is inferred per the integer-literal-typing rule in the Tier 2 type-rules section), `pkt.src_port`/`pkt.dst_port`, or Tier 2 locals of the same integer type as the LHS. Ordered comparisons on `ipv4`, `ipv6`, `bool`, or `proto` operands are type errors. The Tier 1 surface is unchanged: with no locals available, the only valid LHS forms in Tier 1 are the two port fields, so the v0.1 wording continues to hold.

`and`, `or`, `not`, parens are unchanged — and apply identically
inside Tier 2 `if` conditions.

## Compilation

The pipeline is unchanged from v0.1:

```
foo.fw  ──parse──▶  AST  ──semantic──▶  Typed AST  ──emit──▶  foo.bpf.c
```

For a Tier 2 program the analyser additionally:

- Performs local-type inference (first-assignment rule) and
  type-checks every read.
- Performs reachability analysis (terminal action ⇒ subsequent
  statements unreachable).
- Estimates the BPF stack footprint per function and emits the
  256/450-byte warning/error described under "Tier 2 Functions".

For a program containing `geoip(...)`:

- The analyser allocates one map ID per call site and emits a
  manifest entry under the `geoip` section.
- The bundle phase reads `--geoip-source` and validates every
  referenced country code resolves to at least one prefix. Codes
  with zero prefixes are not an error (some countries lack
  allocations in particular families) but emit a warning.

A program **touches an IPv6 surface** if its source mentions any of the following anywhere — in a condition, an assignment RHS, an `in`-list, or a comparison operand on either side:

- `pkt.src_ip6` or `pkt.dst_ip6` (the v6 address fields).
- An IPv6 literal (`::`, `::1`, `2001:db8::1`, `::ffff:1.2.3.4`, etc.) or an IPv6 CIDR (`::/0`, `2001:db8::/32`, etc.).
- The `icmp6` proto keyword — in **any** position: `pkt.proto == icmp6`, `pkt.proto != icmp6`, `pkt.proto in [tcp, icmp6]`, `if p == icmp6:` against a Tier 2 `proto` local, etc.
- A `geoip(...)` call whose host comparison's LHS has type `ipv6` (per the type-based geoip LHS rule).

The activation check is *semantic*, not textual: the analyser runs after parsing and type inference, when the type of every operand is known. Refactors that preserve the program's semantics (e.g. hoisting `pkt.proto` into a Tier 2 local — see the Refactor invariance paragraph in the IPv6 Fields section — or expanding a list-membership `in` into an `or`-chain) preserve activation. *Note that swapping `==` for `!=` with an outer `not` is **not** semantics-preserving in v0.2:* `pkt.proto != tcp` and `not (pkt.proto == tcp)` differ on non-IP frames per the proto-equality rule in the IPv6 Fields section (`!=` requires the read to have succeeded; the outer `not` does not). Applying that rewrite changes both the runtime behaviour and the activation-relevant surface, so it is not in the equivalence list.

For a program **touching an IPv6 surface**:

- The analyser activates the IPv6 parse path in the emitter.
- The IPv6 bounds-check prelude is generated in `main.bpf.c` alongside the IPv4 prelude; the program runs both, branching on EtherType.
- `pkt.proto == tcp|udp` matches both v4 and v6 frames per the proto-enum table in the IPv6 Fields section.

For a program **not touching any IPv6 surface** (every condition, assignment, and operand uses only v0.1-shaped surfaces — no IPv6 literals, CIDRs, address fields, `icmp6`, or v6-typed geoip):

- The v6 parse path is **not** generated. Frames with EtherType `0x86DD` (IPv6) fall through every rule, exactly as in v0.1, and reach the default action.
- `pkt.proto == tcp|udp` matches v4 frames only — same semantics as v0.1.
- This is the strict-superset guarantee: any v0.1 program compiled by the v0.2 toolchain has identical packet behaviour to v0.1.

The full Compile-Time Errors table from v0.1 §"Compile-Time Errors"
is augmented with the per-construct tables above. Where v0.2 adds an
error class to a v0.1 message, the new condition is listed and the
v0.1 row remains unchanged.

## Examples (consolidated)

In addition to the per-construct examples above, three end-to-end
v0.2 programs:

### v6-aware internal network

```python
@xdp(eth0)

# Trust IPv4 internal traffic
allow if pkt.src_ip in [10.0.0.0/8, 192.168.0.0/16]
# Trust IPv6 internal traffic (RFC 4193 unique-local)
allow if pkt.src_ip6 in fc00::/7
# Standard inbound services for both v4 and v6 origins
allow if pkt.proto == tcp and pkt.dst_port in [80, 443, 22]
allow if pkt.proto == udp and pkt.dst_port == 53
# Visibility into unsolicited SYNs from outside
log if pkt.proto == tcp and pkt.tcp.syn and not pkt.tcp.ack
default drop
```

### Geoip block list

```python
@xdp(eth0)

# Drop traffic from a known bad-actor country list (v4 + v6)
drop if pkt.src_ip  in geoip(RU, CN, KP)
drop if pkt.src_ip6 in geoip(RU, CN, KP)

# Allow only common inbound services
allow if pkt.proto == tcp and pkt.dst_port in [80, 443]
allow if pkt.proto == udp and pkt.dst_port == 53

default drop
```

### Tier 2 dogfood

```python
@xdp(eth0)

def firewall(pkt):
  # Trust internal and ULA address space
  if pkt.src_ip in [10.0.0.0/8, 192.168.0.0/16]:
    allow
  if pkt.src_ip6 in fc00::/7:
    allow

  # Geo-block at the v4 and v6 layer
  if pkt.src_ip in geoip(RU, CN, KP):
    drop
  if pkt.src_ip6 in geoip(RU, CN, KP):
    drop

  # Rate-limit new SSH SYNs. v4 buckets per source IP; v6 buckets
  # per destination port (per=src_ip6 is a v0.3 feature). The two
  # sub-branches must stay disjoint to avoid the cross-family
  # rate_limit-per-bucket error.
  if pkt.proto == tcp and pkt.dst_port == 22:
    if pkt.src_ip in [0.0.0.0/0]:               # v4-establishing guard
      if pkt.tcp.syn and not pkt.tcp.ack:
        if rate_limit(10, per=src_ip):
          drop
      count ssh_seen
      allow
    if pkt.src_ip6 in [::/0]:                   # v6-establishing guard
      if pkt.tcp.syn and not pkt.tcp.ack:
        if rate_limit(100, per=dst_port):       # 100 SYNs/sec/port cap
          drop
      count ssh_seen
      allow

  # Allow public services
  if pkt.proto == tcp and pkt.dst_port in [80, 443]:
    count web
    allow
  if pkt.proto == udp and pkt.dst_port == 53:
    allow

  # Visibility on everything else before dropping
  log
  drop
```

## What Is Not in v0.2

Restating the deferral list. None of the following are valid in v0.2;
all produce compile errors with the message `<feature> not supported
in v0.2`.

- **Tier 3** — `inline_c` blocks, `.bpf.c` stage loading.
- **`conntrack(pkt)`** — depends on the dotted-call form.
- **`wg_*` built-ins** — WireGuard parsers.
- **Custom `pkt.<protocol>.*` layers beyond TCP** — `pkt.icmp.*`,
  `pkt.dns.*`, `pkt.wg.*`, etc.
- **`chain` / tail-call composition** between programs.
- **Multi-interface attach** — one `@xdp(...)` per program stays.
- **`sampled` modifiers on `log`**.
- **`count(name)` function-call form** — the `count <n>` action stays.
- **`geoip()` live DB refresh** — bundle's `geoip.json` is
  captured at compile time.
- **`per=src_ip6`, `per=dst_ip6`** for `rate_limit` — v0.3.
- **`per=src_addr`** unifying v4/v6 buckets for `rate_limit` — v0.3.
- **IPv6 ranges (`a..b`)** — use a CIDR or list.
- **IPv6 extension-header chasing** — frames with extension headers
  do not match L4 rules, but the parser does not walk the chain.
- **IPv4-mapped equivalence** — `::ffff:1.2.3.4` matches only IPv6
  packets carrying that mapped address; it does not match an IPv4
  packet from `1.2.3.4`.
- **Multiple `def`s per program**.
- **Mixing Tier 1 rules with a Tier 2 `def`** in one program.
- **Loops**, **recursion**, **closures**, **list/dict mutation**,
  **user-defined functions other than the entry point**.
- **Dotted-call form** (`conntrack(pkt).state == established`,
  `rate_limit(...).exceeded`) — Tier 2 uses bare-bool
  `rate_limit(...)` inside `if` instead.
- **Mesh / `@deploy` / `@api` decorators**.

## Grammar (Reference, delta from v0.1)

The v0.2 grammar extends the v0.1 grammar with the following
productions. Productions not listed are unchanged.

```ebnf
program       = hook_decl ( tier1_body | tier2_body ) ;

tier1_body    = { rule } [ default_rule ] ;
tier2_body    = function_def ;

function_def  = "def" identifier "(" "pkt" ")" ":" NEWLINE
                INDENT statement { statement } DEDENT ;

statement     = if_stmt
              | assign_stmt
              | action_stmt ;

action_stmt   = "allow"            NEWLINE
              | "drop"             NEWLINE
              | "log"              NEWLINE
              | "count" identifier NEWLINE ;

assign_stmt   = identifier "=" scalar_expr NEWLINE ;

if_stmt       = "if" condition ":" NEWLINE
                INDENT statement { statement } DEDENT
                { elif_clause }
                [ else_clause ] ;

elif_clause   = "elif" condition ":" NEWLINE
                INDENT statement { statement } DEDENT ;

else_clause   = "else" ":" NEWLINE
                INDENT statement { statement } DEDENT ;

(* v0.2 redefines `condition` explicitly. It extends the v0.1 grammar
   with three sets of additions:
     - `value_field` is broader (now includes IPv6 address fields,
       `pkt.proto`, `pkt.tcp.syn`, `pkt.tcp.ack` — see the
       `value_field` production below).
     - `lvalue` and `rvalue` admit `identifier` so Tier 2 locals can
       appear on either side of a comparison.
     - `primary` admits `identifier` (a bool local read as a bare
       condition) and `rate_limit_call` (a Tier 2 if-condition
       primary, see below).
     - `operand` admits `ipv6` literals.
   Tier 1 programs are unaffected: a Tier 1 source has no `identifier`
   reads in conditions (no locals exist) and the analyser rejects
   `rate_limit_call` outside Tier 2 if/elif conditions. The grammar
   below is the authoritative parser surface for both tiers. *)

condition       = or_expr ;
or_expr         = and_expr { "or" and_expr } ;
and_expr        = not_expr { "and" not_expr } ;
not_expr        = [ "not" ] primary ;

primary         = comparison
                | bool_primary
                | rate_limit_call
                | "(" condition ")" ;

bool_primary    = "pkt.tcp.syn"
                | "pkt.tcp.ack"
                | identifier ;

comparison      = lvalue comp_op rvalue
                | lvalue "in" set_or_range ;

comp_op         = "==" | "!=" | "<" | ">" | "<=" | ">=" ;

lvalue          = value_field
                | identifier ;

rvalue          = operand
                | identifier
                | value_field ;             (* a comparison may read *)
                                            (* a packet field on    *)
                                            (* either side; analyser *)
                                            (* still type-checks    *)

rate_limit_call = "rate_limit" "(" integer "," "per" "=" rl_field ")" ;

rl_field        = identifier ;
(* the parser admits any `identifier`; the analyser narrows it to
   `src_ip`, `dst_ip`, `src_port`, `dst_port`, and emits the
   "rate_limit per= must be ..." error for any other value (so the
   diagnostic for `per=src_ip6`, `per=src_addr`, `per=foo`, etc.
   is the prescribed analyser-level message rather than a parser
   "unexpected token" error). *)

scalar_expr   = condition
              | identifier                        (* local read *)
              | value_field                       (* packet field read *)
              | integer | ipv4 | ipv6
              | proto_keyword ;                   (* tcp/udp/icmp/icmp6 *)

(* The RHS of a Tier 2 local assignment is `scalar_expr`, not the
   broader `expression`. Lists, CIDRs, ranges, `geoip_call`, and
   `rate_limit_call` are NOT admissible as the RHS of an assignment
   in v0.2. Their valid positions are:
     - `list`, `range`, `cidr`, `cidr_list`, `geoip_call` —
       only as `set_or_range` (RHS of `in`).
     - `rate_limit_call` — only as a `primary` inside a Tier 2
       `if`/`elif` condition.
   v0.2 has no list-shaped local types — `bool`, `u16`, `u32`,
   `ipv4`, `ipv6`, `proto` are the entire local-type universe. *)

value_field   = "pkt.src_ip"   | "pkt.dst_ip"
              | "pkt.src_ip6"  | "pkt.dst_ip6"
              | "pkt.src_port" | "pkt.dst_port"
              | "pkt.proto"
              | "pkt.tcp.syn"  | "pkt.tcp.ack" ;

(* `pkt.proto`, `pkt.tcp.syn`, `pkt.tcp.ack` were `enum_field` /
   `bool_field` in v0.1's grammar. v0.2 lifts them into the
   common `value_field` production so Tier 2 assignments
   (`syn = pkt.tcp.syn`) parse uniformly. The v0.1 distinction
   between `value_field`/`enum_field`/`bool_field` is preserved
   in the analyser as a type-rules concern, not as a parser
   concern. *)

operand       = integer | ipv4 | ipv6 | proto_keyword ;

proto_keyword = "tcp" | "udp" | "icmp" | "icmp6" ;

(* `proto_keyword` is grammar-legal as a generic operand but is
   only meaningful when the LHS of the comparison is `pkt.proto`.
   Field/operand type compatibility is enforced by the analyser,
   not the parser. *)

set_or_range  = list | range | cidr | cidr_list | geoip_call ;
list          = "[" operand { "," operand } "]" ;
range         = port ".." port ;        (* inherited from v0.1; *)
                                        (* port-only — IPv4 and *)
                                        (* IPv6 ranges are not  *)
                                        (* a syntactic surface  *)
                                        (* in v0.2.             *)
port          = integer ;               (* semantic check: 0..65535 *)
cidr          = ipv4 "/" integer
              | ipv6 "/" integer ;
cidr_list     = "[" cidr { "," cidr } "]" ;

geoip_call    = "geoip" "(" cc_code { "," cc_code } ")" ;
cc_code       = upper_letter , upper_letter ;       (* exactly two *)

ipv6          = (* RFC 5952 canonical form *) ;
upper_letter  = "A" | "B" | "C" | "D" | "E" | "F" | "G" | "H"
              | "I" | "J" | "K" | "L" | "M" | "N" | "O" | "P"
              | "Q" | "R" | "S" | "T" | "U" | "V" | "W" | "X"
              | "Y" | "Z" ;
```

`geoip_call` may appear only in the `set_or_range` production (RHS of `in`); the parser rejects it elsewhere with the "`geoip() is only valid as the right-hand side of 'in'`" error.

`rate_limit_call` is grammar-legal anywhere a `primary` is, but the analyser narrows the surface to two valid uses:

- As an `if`/`elif` condition `primary` inside a Tier 2 function body. `if rate_limit(10, per=src_ip):` and `if not rate_limit(10, per=src_ip):` are valid; `if rate_limit(10, per=src_ip) and pkt.tcp.syn:` is valid (the call is one conjunct of the condition).
- As the `modifier` of a Tier 1 `<rule> limited by rate_limit(...)`, exactly as in v0.1.

Every other position is rejected at the analyser pass — including the RHS of a comparison (`x == rate_limit(...)`), inside a Tier 1 `if` clause (`drop if rate_limit(...)` is not valid; the v0.1 form is the modifier `limited by`), as a bare statement (`rate_limit(10, per=src_ip)` on its own line), or as the RHS of a Tier 2 assignment (`x = rate_limit(...)`). The error is `error: rate_limit(...) is only valid as the condition of an if-statement in Tier 2 or as the 'limited by' modifier of a Tier 1 rule`.

`function_def` may appear only as the `tier2_body` of a `program`; nested `def`s and `def`s without a preceding `@xdp` hook are syntactically rejected.

## Summary

v0.2 adds three constructs to FWL — IPv6 fields, `geoip()`, and a
single Tier 2 `def`-style entry point — without disturbing the v0.1
surface. Every v0.1 program runs unchanged under v0.2. The new
constructs are framed conservatively: IPv6 stops at the fixed header,
`geoip()` is a static bundle-time map, and Tier 2 has neither loops
nor recursion. The deferral list is the explicit path to v0.3.

The methodology is unchanged from v0.1: each construct here ships
through the spec → impl → corpus → hone three-oracle loop. The corpus
under `f/fwl/tests/corpus/` and the regression run via
`hone regress` are the verification authority. A construct is not
done until hone signs off.
