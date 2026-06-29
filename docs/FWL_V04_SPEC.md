# FWL v0.4 — Language Specification

## What FWL Is

FWL is a small declarative language for writing firewall rules. A `.fw`
file declares a sequence of rules; the compiler turns it into an
XDP/eBPF program that runs at line rate in the kernel.

This document specifies the v0.4 protocol-field additions. v0.4 is a
strict superset of [v0.2](FWL_V02_SPEC.md): every v0.2 program is a
valid v0.4 program with identical packet semantics. v0.4 adds two
protocol-field constructs to the v0.2 surface:

1. **All eight TCP flags** — `pkt.tcp.fin`, `pkt.tcp.rst`,
   `pkt.tcp.psh`, `pkt.tcp.urg`, `pkt.tcp.ece`, `pkt.tcp.cwr` join the
   existing `pkt.tcp.syn` and `pkt.tcp.ack`.
2. **ICMP and ICMPv6 type/code** — `pkt.icmp.type`, `pkt.icmp.code`,
   `pkt.icmp6.type`, `pkt.icmp6.code`.

Everything else from v0.2 is preserved. Both constructs follow the
same pattern as the existing `pkt.tcp.syn`/`pkt.tcp.ack` fields: a
typed packet accessor with a protocol guard requirement, evaluated by
three independent oracles (the spec, the AST interpreter, and
`BPF_PROG_TEST_RUN`).

## Surface deltas relative to v0.2

| Area | v0.2 | v0.4 |
|---|---|---|
| TCP flag fields | `pkt.tcp.syn`, `pkt.tcp.ack` | adds `fin`, `rst`, `psh`, `urg`, `ece`, `cwr` |
| ICMP fields | none | adds `pkt.icmp.type`, `pkt.icmp.code` |
| ICMPv6 fields | none | adds `pkt.icmp6.type`, `pkt.icmp6.code` |
| `pkt.proto` enum values | `tcp`, `udp`, `icmp`, `icmp6` | unchanged |
| Operators | `==`, `!=`, `<`, `<=`, `>`, `>=`, `in` | unchanged |
| Program shape | Tier 1 rule sequence **xor** one Tier 2 `def` | unchanged |

No v0.4 reservation breaks v0.2 backward compatibility: the new field
spellings (`fin`, `rst`, `psh`, `urg`, `ece`, `cwr`, `type`, `code`)
are recognized only as field segments after `pkt.tcp.` / `pkt.icmp.` /
`pkt.icmp6.`, not as globally reserved words. A Tier 2 local named
`type` or a counter named `code` remains permitted.

## TCP Flags (all 8)

**Construct.** Six new bool fields on the `pkt` object, completing the
TCP flag set:

```
pkt.tcp.fin              # FIN flag — sender finished sending
pkt.tcp.rst              # RST flag — reset the connection
pkt.tcp.psh              # PSH flag — push buffered data to the app
pkt.tcp.urg              # URG flag — urgent pointer is significant
pkt.tcp.ece              # ECE flag — ECN-Echo
pkt.tcp.cwr              # CWR flag — Congestion Window Reduced
```

These join the v0.1 `pkt.tcp.syn` and `pkt.tcp.ack`. All eight are
single bits in the TCP header flags byte (offset 13).

**Type rules.**

- Every TCP flag field has type `bool`. Boolean fields appear directly
  as conditions; there are no boolean literals (`true`, `false`), so
  write `pkt.tcp.fin` to test whether the FIN flag is set and
  `not pkt.tcp.fin` to test whether it is clear. `pkt.tcp.fin == true`
  is not valid (no `true` literal), identical to the v0.1 rule for
  syn/ack.
- A TCP flag read is valid only on a path guarded by `pkt.proto == tcp`
  (see Compile errors). Accessing a flag without the guard is a compile
  error, exactly as for syn/ack.
- A `bool` flag is a valid bare `if` condition primary in Tier 2; both
  sides of `==`/`!=` may be `bool` flags or `bool` locals, but mixing a
  `bool` flag with a non-`bool` value is a type error. There is no
  implicit truthiness coercion: `if pkt.dst_port:` stays a type error,
  while `if pkt.tcp.rst:` is fine.

**Semantics.**

- Single-bit extraction from the TCP header flags byte (offset 13).
  Bit positions, low to high: FIN `0x01`, SYN `0x02`, RST `0x04`,
  PSH `0x08`, ACK `0x10`, URG `0x20`, ECE `0x40`, CWR `0x80`.
- The compiler emits the TCP L4 parse only when a flag (or port) field
  is referenced. The flag byte is read after the parser bounds-checks
  the full TCP header; on a truncated TCP header, or any non-TCP frame,
  the flag reads do not happen and conditions touching them fall
  through (the rule does not match).
- Flags compose like any other bool: `pkt.tcp.syn and not pkt.tcp.ack`
  matches a bare SYN; `pkt.tcp.fin and pkt.tcp.psh and pkt.tcp.urg`
  matches the "XMAS" flag combination.
- Flags are readable on both IPv4 TCP (`tcp(...)`) and IPv6 TCP
  (`tcp6(...)`) frames — the dual-stack prelude extracts them on both
  paths into the same variables.

**Edge cases.**

- *Flag on a non-TCP packet.* A rule referencing `pkt.tcp.rst` does not
  match a UDP, ICMP, or ICMPv6 packet — the L4 TCP parse never runs, so
  the flag stays unread and the condition is false.
- *Truncated TCP header.* A frame whose TCP header is cut short (less
  than the full 20-byte `struct tcphdr`) does not satisfy any flag
  read; the rule falls through, identical to truncated-port behaviour.
- *All flags clear.* A TCP segment with a zero flags byte matches
  `not pkt.tcp.fin and not pkt.tcp.syn and ...` for every flag.
- *Flag combinations.* `pkt.tcp.fin and pkt.tcp.syn` (an illegal but
  observable combination) is matchable — FWL reports what the bits say,
  it does not validate TCP state.
- *Interaction with `not`.* `not pkt.tcp.ece` is true on a non-TCP
  frame only if the surrounding condition's other terms already
  established that the field is unreadable — by itself `not pkt.tcp.ece`
  evaluates the unread (false) bit, so `not pkt.tcp.ece` is true. This
  matches the existing syn/ack `not` semantics.

**Compile errors.**

| Condition | Error |
|---|---|
| `drop if pkt.tcp.fin` (no guard) | `error: pkt.tcp.fin requires 'pkt.proto == tcp' guard` |
| `drop if pkt.proto == udp and pkt.tcp.rst` | `error: pkt.tcp.rst requires 'pkt.proto == tcp' guard` |
| `pkt.tcp.psh == 1` (bool vs int) | `error: cannot apply '==' to bool with integer 1` |

**Examples.**

```
# Drop bare-SYN scans, allow established.
@xdp(eth0)
drop if pkt.proto == tcp and pkt.tcp.syn and not pkt.tcp.ack
allow

# Drop the XMAS-scan flag combination.
@xdp(eth0)
drop if pkt.proto == tcp and pkt.tcp.fin and pkt.tcp.psh and pkt.tcp.urg
allow

# Log connection teardown (FIN or RST).
@xdp(eth0)
log if pkt.proto == tcp and pkt.tcp.fin
log if pkt.proto == tcp and pkt.tcp.rst
allow
```

## ICMP and ICMPv6 type/code

**Construct.** Four new `u8` fields on the `pkt` object:

```
pkt.icmp.type            # ICMPv4 type byte   (e.g. 8 = echo request)
pkt.icmp.code            # ICMPv4 code byte
pkt.icmp6.type           # ICMPv6 type byte   (e.g. 128 = echo request)
pkt.icmp6.code           # ICMPv6 code byte
```

`pkt.icmp.*` reads the ICMPv4 header; `pkt.icmp6.*` reads the ICMPv6
header. They are distinct fields with distinct guards — the wire
protocols, EtherTypes, and type-number spaces differ.

Operands they accept:

| Operand kind | Syntax | Example |
|---|---|---|
| integer literal | decimal or hex, 0..255 | `pkt.icmp.type == 8` |
| integer range | `lo..hi` | `pkt.icmp6.type in 133..137` |
| integer list | `[ n, ... ]` | `pkt.icmp.type in [0, 3, 11]` |

Operators: `==`, `!=`, `<`, `<=`, `>`, `>=`, `in` — the same surface as
port fields. There is no boolean form (these are numeric u8 fields, not
flags).

**Type rules.**

- `pkt.icmp.type`, `pkt.icmp.code`, `pkt.icmp6.type`, `pkt.icmp6.code`
  all have type `u8` (an unsigned byte, value range 0..255).
- An integer literal compared against any of these fields must be in
  `0..255`. A literal outside that range is a compile error (the wire
  field is a single byte; a larger constant can never match and almost
  always signals a mistake).
- A range `lo..hi` requires `0 <= lo <= hi <= 255`.
- `pkt.icmp.*` reads require a `pkt.proto == icmp` guard on the path.
  `pkt.icmp6.*` reads require a `pkt.proto == icmp6` guard. Crossing
  them — `pkt.icmp.type` under an `icmp6` guard, or vice versa — is a
  compile error (the guard table treats `icmp` and `icmp6` as distinct
  protocols).
- When hoisted into a Tier 2 local (`t = pkt.icmp.type`), the local
  takes the smallest unsigned scalar that holds a byte: `u16` (v0.4 has
  no `u8` local type). The strict `0..255` literal check applies to
  direct field comparisons; once a value lives in a `u16` local the
  ordinary `u16` comparison rules apply, and a literal in `256..65535`
  simply never matches the byte.

**Semantics.**

- **ICMPv4.** When the program references a `pkt.icmp.*` field, the
  compiler emits an ICMP parse branch inside the IPv4 L4 region: after
  the variable-IHL IPv4 header, if `pkt.proto == icmp` (IP protocol 1)
  and the first two header bytes are in-bounds, `type` (offset 0) and
  `code` (offset 1) are read. The branch is gated by an `icmp_ok` flag
  set only when those bytes are present.
- **ICMPv6.** When the program references a `pkt.icmp6.*` field, the
  compiler emits an ICMPv6 branch in the IPv6 path: at the fixed offset
  after the 40-byte IPv6 header, if `next_header == IPPROTO_ICMPV6`
  (58) and the two bytes are in-bounds, `type` and `code` are read,
  gated by an `icmp6_ok` flag. No extension-header chasing — an ICMPv6
  packet behind a Hop-by-Hop or any other extension header has no
  readable `pkt.icmp6.*` (the field reads fall through), identical to
  the v0.2 rule for L4 fields behind extension headers.
- A read on the wrong family does not match: `pkt.icmp.type` never
  matches an IPv6 frame (the v4 ICMP parse runs only on EtherType
  `0x0800`), and `pkt.icmp6.type` never matches an IPv4 frame.
- Byte semantics: `type` is the ICMP message type, `code` is the
  subtype. The values are protocol-defined integers; FWL does not name
  them. Common ICMPv4 types: 0 (echo reply), 3 (destination
  unreachable), 8 (echo request), 11 (time exceeded). Common ICMPv6
  types: 1 (destination unreachable), 128 (echo request), 129 (echo
  reply), 133–137 (NDP: router/neighbor solicitation/advertisement,
  redirect).

**Edge cases.**

- *Echo vs unreachable vs redirect.* `pkt.icmp.type == 8` matches a
  ping request; `pkt.icmp.type == 3` matches destination-unreachable;
  `pkt.icmp.type == 5` matches a redirect. Distinct type values are
  independently matchable.
- *ICMPv6 NDP range.* `pkt.icmp6.type in 133..137` matches the
  Neighbor Discovery message types (router solicitation 133, router
  advertisement 134, neighbor solicitation 135, neighbor advertisement
  136, redirect 137) — the canonical "allow NDP" rule.
- *Truncated ICMP.* A frame cut before the 2-byte type/code pair does
  not satisfy any `pkt.icmp.*` / `pkt.icmp6.*` read; the rule falls
  through (`icmp_ok` / `icmp6_ok` stays 0).
- *v4 vs v6 ICMP.* An ICMPv4 echo request (`icmp(type=8)`) does not
  match `pkt.icmp6.type == 8`, and an ICMPv6 echo request
  (`icmp6(type=128)`) does not match `pkt.icmp.type == 128`. The two
  protocols' type spaces are independent (echo request is 8 in v4, 128
  in v6).
- *Code on a type with no codes.* `pkt.icmp.code` reads byte 1
  regardless of type; for an echo request (code always 0) it reads 0,
  matchable by `pkt.icmp.code == 0`.
- *Boundary type values.* `pkt.icmp.type == 0` (echo reply) and
  `pkt.icmp.type == 255` (the maximum u8) are both valid; `== 256` is a
  compile error.

**Compile errors.**

| Condition | Error |
|---|---|
| `drop if pkt.icmp.type == 8` (no guard) | `error: pkt.icmp.type requires 'pkt.proto == icmp' guard` |
| `drop if pkt.proto == tcp and pkt.icmp.type == 8` | `error: pkt.icmp.type requires 'pkt.proto == icmp' guard` |
| `drop if pkt.proto == icmp6 and pkt.icmp.type == 8` | `error: pkt.icmp.type requires 'pkt.proto == icmp' guard` |
| `drop if pkt.proto == icmp and pkt.icmp.type == 300` | `error: icmp type/code value 300 outside valid range 0..255` |
| `pkt.icmp.type == tcp` (proto vs u8) | `error: cannot apply '==' to icmp type (u8) with proto keyword 'tcp'` |

**Examples.**

```
# Allow ping (echo request), block everything else ICMP.
@xdp(eth0)
allow if pkt.proto == icmp and pkt.icmp.type == 8
drop if pkt.proto == icmp
allow

# Block ICMP destination-unreachable floods.
@xdp(eth0)
drop if pkt.proto == icmp and pkt.icmp.type == 3
allow

# Allow ICMPv6 Neighbor Discovery (types 133–137) — required for IPv6.
@xdp(eth0)
allow if pkt.proto == icmp6 and pkt.icmp6.type in 133..137
drop if pkt.proto == icmp6
allow

# Tier 2: branch on ICMP type after a single guard.
@xdp(eth0)
def filter(pkt):
  if pkt.proto == icmp:
    if pkt.icmp.type == 8:
      allow
    drop
  allow
```

## Compilation

The two constructs activate parse paths the same way v0.2 fields do:

- **TCP flags** extend the existing TCP L4 parse. Each referenced flag
  adds one byte-field read (`tcp->{flag}`) inside the bounds-checked
  TCP branch, on both the IPv4 and IPv6 paths. No flag read happens
  unless the program references that flag.
- **ICMP type/code** add a new protocol branch. `pkt.icmp.*` emits an
  ICMPv4 branch in the IPv4 L4 region (after the variable-IHL header);
  `pkt.icmp6.*` emits an ICMPv6 branch at the fixed offset in the IPv6
  path and activates the v6 parse path (EtherType dispatch on
  `0x86DD`). The type/code bytes are read through a minimal two-byte
  header struct, gated by `icmp_ok` / `icmp6_ok` so a truncated or
  wrong-protocol frame falls through.

The strict-superset guarantee holds: a v0.2-shaped program emits
exactly the v0.2 code (no ICMP branch, no extra flag reads), so its
behaviour on every packet is unchanged.

## What Is Not in v0.4

- No symbolic names for ICMP types/codes (`echo_request`, `unreachable`)
  — v0.4 matches on the numeric byte only. Named constants are a future
  ergonomics item.
- No ICMP `id`/`sequence` field matching — only `type` and `code`.
- No `related` conntrack state keyed on the ICMP error's embedded
  5-tuple (deferred to Phase 4.3 conntrack, which builds on this
  construct).
- No extension-header chasing for ICMPv6 — a packet behind an extension
  header has no readable `pkt.icmp6.*` (same conservatism as v0.2 L4
  fields).
- No `per=` rate-limit bucket keyed on ICMP type/code.
