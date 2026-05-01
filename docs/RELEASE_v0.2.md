# FWL v0.2 Release Notes

This release evolves the FWL firewall language from v0.1 to v0.2. v0.2 is a strict superset of v0.1: every v0.1 program runs unchanged with v0.1-equivalent semantics. Three new constructs land:

1. **IPv6 fields** — `pkt.src_ip6`, `pkt.dst_ip6`, IPv6 literals (RFC 5952 canonical), IPv6 CIDR blocks (`/0..128`), and the `icmp6` proto keyword.
2. **`geoip()` built-in** — a variadic ISO 3166-1 alpha-2 country-code call that resolves at bundle-time to a BPF LPM trie, valid as the right-hand side of `in` against any IPv4 or IPv6 field.
3. **Tier 2 programmable functions** — a single `def firewall(pkt):` body with `if/elif/else`, locals (bool / u16 / u32 / ipv4 / ipv6 / proto), action statements (`allow`, `drop`, `log`, `count <name>`), and `rate_limit(...)` as an if-condition primary.

Spec: `docs/FWL_V02_SPEC.md` (constructs) and `docs/PKT_V02_SPEC.md` (test packet format additions).

## Strict-superset preservation

A v0.1-shaped program (no Tier 2 function, no v6 surface mentioned) executes under v0.2 with bit-for-bit equivalent BPF parsing logic to v0.1, with one observable improvement: a v6 frame arriving at a v0.1-shaped program now correctly fails every v4-field comparison (previously it could spuriously match `pkt.src_ip == 0.0.0.0` and similar zero-default patterns). The interpreter side already had this gating since Phase 1; the BPF emitter caught up in this release via the new `v4_ok` / `l4_ok` prelude flags.

The Tier 1 / Tier 2 mutual exclusion is enforced at analysis: a single program file may carry either rules + optional default OR exactly one `def firewall(pkt):` function — not both. The mix is deferred to v0.3.

## IPv6 fields

```
@xdp(eth0)
drop if pkt.src_ip6 in 2001:db8::/32
allow if pkt.src_ip6 == ::1
allow if pkt.proto == icmp6 and pkt.src_ip6 in [fe80::/10, ::/128]
default drop
```

- Literals must be in RFC 5952 canonical form (lowercase hex, suppressed leading zeros, single longest-`::`, dotted-quad for the IPv4-mapped block).
- CIDR prefix is `0..128`; a `/0` matches every IPv6 address (analogous to v4 `0.0.0.0/0`).
- The v6 parse path is *activated* by any v6 surface in the program: `pkt.src_ip6` / `pkt.dst_ip6`, an IPv6 literal, an IPv6 CIDR, or the `icmp6` proto keyword. Without activation, v6 frames fall through every rule (preserving v0.1 behaviour). With activation, both v4 and v6 frames are parsed and proto comparisons (`tcp`, `udp`, `icmp`) match across both families per the proto-enum table in the spec.
- `icmp6` is family-restricted: it matches IPv6 frames only (next_header=58).

## `geoip()` built-in

```
@xdp(eth0)
drop if pkt.src_ip  in geoip(RU, CN, KP)
drop if pkt.src_ip6 in geoip(RU, CN, KP)
allow if pkt.src_ip in geoip(US, DE)
default drop
```

- Variadic ISO 3166-1 alpha-2 codes; the analyzer rejects unknown codes against the 249-entry list in `iso3166.py`.
- Each textual occurrence of `geoip(...)` is its own call site, bound to a single address family inferred from the LHS field type. The bundler emits one BPF_MAP_TYPE_LPM_TRIE per call site, populated at attach time from `geoip.json`.
- The `.pkt` test-runner now writes the geoip prefixes into the trie before running BPF_PROG_TEST_RUN, so `fwl test ...` returns true positives under root.
- Per-program prefix budget: 65 536 entries combined across all call sites.

## Tier 2 programmable functions

```
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

- Body is indentation-aware. The compiler infers the indentation step from the first indented line; the same step must be applied uniformly within a function. Mixed tabs and spaces in one indentation level is a compile error.
- Locals are statically typed (`bool`, `u16`, `u32`, `ipv4`, `ipv6`, `proto`). Type is bound by the source-order first assignment; reassignment with a different type is a compile error.
- **Dominator rule.** Statement-position `pkt.<field>` reads (the RHS of an assignment, or an inner-condition position) must be dominated by a guard that establishes the field is readable on every path that reaches the read. Polarity-aware: only the then-branches of positive comparisons establish guards. `else`, `elif`, and `not` paths don't.
- Reads inside short-circuit-protected expressions (the LHS of `==`/`!=`/`<`/`in`, or sub-conditions under `and`/`or`/`not`) are governed by short-circuit semantics, not by the dominator rule.
- Reachability check: a statement after a fully-terminating control-flow chain (every branch ends in `allow`/`drop`) is a compile error.
- Stack budget: the analyser warns at 256 B and errors at 450 B of estimated stack use.

## Migration from v0.1

None required. v0.1 programs compile and run unchanged. The strict-superset guarantee is locked in at every gate and verified by the regression run on every PR.

## Verification

- `f/fwl/tests/corpus/`: 133/133 cases pass under `sudo hone regress` (BPF oracle live). 70 v0.1 cases + 22 IPv6 + 24 geoip + 17 Tier 2 + reproducers from each construct's hunt.
- `pytest`: 457/457 cases (parser + analyzer + emitter + bundle + clang-compile regression).
- `flake8`: clean.

## Known deferrals to v0.3

- Mixed Tier 1 + Tier 2 in one program (rules-prelude + function body).
- IPv6 extension headers (Hop-by-Hop, Fragment, etc.).
- General user-defined functions and recursion.
- Loops (`for`, `while`).
- ICMPv6 type/code parametrisation in test builders.
- Direct `for` / `while` / `pass` / `return` as Tier 2 statement leaders.

## Hunt findings during Phase 2 (all fixed before release)

Five real bugs surfaced and fixed across the three constructs:

1. **IPv6 — interpreter v6-surface activation gate**. `_program_touches_v6_surface` walked Tier 1 only; oracle disagreement on Tier 2 v6 programs. Fixed.
2. **IPv6 — NDP DAD/RS dropped against stated intent in `v6_internal.fw`**. User-rule bug; fixed by adjusting the example's allowlist CIDRs.
3. **PKT loader — non-canonical IPv6 silently accepted**. Loader accepted non-RFC-5952 forms for builder fields; rejected as anti-regression.
4. **geoip — bpf-runner skipped LPM trie population**. The `.pkt` runner only populated rate-limit maps; geoip lookups always missed in BPF. Fixed by extending `_build_map_init` with a geoip-aware sibling.
5. **Tier 2 — interpreter v6 activation skipped function body**. Same shape as (1) but the helper hadn't been extended for Tier 2. Fixed.
6. **Tier 2 — emitter `count` slot KeyError**. `_allocate_counter_slots` walked rules only; Tier 2 `count <name>` crashed the emitter. Fixed.
7. **Tier 2 — emitter cross-family `v4_ok` gate missing**. v6 frames hitting v4-field comparisons spuriously matched against zero-defaults; the interpreter correctly returned false. Fixed by adding `v4_ok` / `l4_ok` BPF prelude flags and gating every v4-field comparison.
