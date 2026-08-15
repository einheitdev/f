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

v0.4 also adds two larger surfaces documented in their own sections
below: **VLAN 802.1Q** matching (`pkt.vlan_id`, `pkt.vlan_priority`)
and **stateful conntrack** (`conntrack(pkt).state`). Conntrack is the
first construct with a side effect — an allowed `new` packet creates
the connection-tracking entry a later packet reads as `established`.

## Surface deltas relative to v0.2

| Area | v0.2 | v0.4 |
|---|---|---|
| TCP flag fields | `pkt.tcp.syn`, `pkt.tcp.ack` | adds `fin`, `rst`, `psh`, `urg`, `ece`, `cwr` |
| ICMP fields | none | adds `pkt.icmp.type`, `pkt.icmp.code` |
| ICMPv6 fields | none | adds `pkt.icmp6.type`, `pkt.icmp6.code` |
| `pkt.proto` enum values | `tcp`, `udp`, `icmp`, `icmp6` | unchanged |
| Operators | `==`, `!=`, `<`, `<=`, `>`, `>=`, `in` | unchanged |
| Program shape | Tier 1 rule sequence **xor** one Tier 2 `def` | unchanged |
| `rate_limit` | `rate_limit(N, per=<field>)` | adds optional `scope=zone\|global` (§ 6.7), default `zone` |

No v0.4 reservation breaks v0.2 backward compatibility: the new field
spellings (`fin`, `rst`, `psh`, `urg`, `ece`, `cwr`, `type`, `code`)
are recognized only as field segments after `pkt.tcp.` / `pkt.icmp.` /
`pkt.icmp6.`, not as globally reserved words. A Tier 2 local named
`type` or a counter named `code` remains permitted. `global` is
likewise not a reserved word — it is recognized only as the value of a
`rate_limit` `scope=` field, so an interface, zone, or counter named
`global` keeps working.

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

## VLAN 802.1Q

### Construct

Two new read-only packet fields, available on every program (Tier 1
rules and Tier 2 function bodies):

| Field | Width | Range | Meaning |
|-------|-------|-------|---------|
| `pkt.vlan_id` | u16 | 0–4095 | 802.1Q VLAN identifier (VID, 12 bits) |
| `pkt.vlan_priority` | u8 | 0–7 | 802.1p priority code point (PCP, 3 bits) |

Both are integer-valued. The 1-bit DEI (drop-eligible indicator) is
parsed past but not exposed in v0.4.

### Type rules

- `pkt.vlan_id` and `pkt.vlan_priority` are integer fields. They
  behave like port fields for comparison purposes: the operators
  `==`, `!=`, `<`, `>`, `<=`, `>=`, and `in` (over an integer list
  or `lo..hi` range) all apply.
- **No protocol guard is required.** VLAN is an L2 construct, parsed
  before any L3/L4 dispatch. Unlike `pkt.src_port` (which needs
  `pkt.proto == tcp/udp`) or `pkt.tcp.syn` (which needs
  `pkt.proto == tcp`), a VLAN field read is legal in any context,
  exactly like `pkt.src_ip` is legal without a guard. This mirrors
  the `_ALL_PROTOS` (empty-guard) treatment the analyzer already
  gives the L3 IP fields.
- In Tier 2, `pkt.vlan_id` and `pkt.vlan_priority` are typed `u16`
  and bind to `u16` locals. Ordered comparisons (`<`, `>`, `<=`,
  `>=`) follow the same matching-integer-type rule as ports.
- Comparison operands must be integer literals (or integer lists /
  ranges for `in`). Comparing a VLAN field against an IP, proto, or
  IPv6 literal is a type error, identical to the port-field rule.

### Semantics

The Ethernet parse prelude dispatches on EtherType at offset 12:

1. If EtherType is `0x8100` (802.1Q), a 4-byte VLAN tag follows:
   - bits 15–13: PCP → `pkt.vlan_priority`
   - bit 12: DEI (parsed, not exposed)
   - bits 11–0: VID → `pkt.vlan_id`
   - The *real* EtherType follows the tag (offset 16).
   - L3 starts at **offset 18** (14 + 4).
2. If EtherType is not `0x8100`, there is no tag. L3 starts at the
   usual **offset 14**, and the VLAN fields are not readable.

The compiler computes the L3 offset once (14 untagged, 18 tagged)
and derives every downstream offset — IPv4 fixed header, IPv6 fixed
header, TCP/UDP/ICMP — from it. The VLAN tag is **transparent to IP
rules**: an existing IPv4 or IPv6 program matches a VLAN-tagged frame
exactly as it would the untagged equivalent, because the parser
re-reads the real EtherType after the tag.

A VLAN field read on a frame with no VLAN tag yields "unreadable":
the field comparison evaluates false (the rule does not match) and
the program falls through, identical to reading `pkt.dst_port` on an
ICMP packet. The emitter gates VLAN field comparisons on a `vlan_ok`
flag set to 1 only inside the tagged branch after the 4-byte tag's
bounds check succeeds — the same pattern as `v4_ok`/`v6_ok`/`l4_ok`.

### Edge cases

- **Untagged frames.** `pkt.vlan_id` / `pkt.vlan_priority` are not
  readable; rules using them do not match. IP rules still match
  normally. No regression for any pre-v0.4 program.
- **Double-tagged (QinQ).** A frame whose outer EtherType is
  `0x88A8` (or a second `0x8100` after the first tag) is a stacked
  VLAN. v0.4 parses the **outer tag only**: for an `0x8100` outer
  tag, the outer VID/PCP are exposed and L3 is parsed after the
  single 4-byte tag — if the real frame carried a second tag, the
  bytes the parser reads as the real EtherType are actually the
  inner tag's TPID, so an IP rule will not match (the inner tag is
  not skipped). For an `0x88A8` outer TPID, v0.4 does not recognize
  the tag at all (only `0x8100` triggers VLAN parsing); the frame is
  treated as non-IP and falls through. QinQ inner-tag parsing is
  deferred to a later version.
- **Native VLAN (VID = 0).** A priority-tagged frame (tag present,
  VID = 0) is a valid tagged frame: `pkt.vlan_id == 0` matches,
  `pkt.vlan_priority` carries the PCP. This is distinct from an
  untagged frame, where `pkt.vlan_id` is unreadable and
  `pkt.vlan_id == 0` does **not** match.
- **Tagged + truncated.** A frame truncated inside the 4-byte tag,
  or after the tag but before the L3 header fits, leaves the
  affected fields unreadable (VLAN, then L3, then L4 gates fall in
  that order).
- **Tagged + IPv6 + extension header.** The VLAN shift composes with
  the v0.2 IPv6 rules: L3 starts at offset 18, the IPv6 fixed header
  is read there, and a non-TCP/UDP next-header (extension header)
  leaves the L4 fields at zero, exactly as in the untagged v6 path.

### Compile errors

- `pkt.vlan_id` compared against a literal **above 4095** (e.g.
  `pkt.vlan_id == 5000`, `pkt.vlan_id > 9000`, or a range/list member
  such as `pkt.vlan_id in [1, 9000]`) is a compile error:
  *"vlan_id value N outside valid range 0..4095"*. The boundary
  value 4095 is itself valid, so `pkt.vlan_id == 4095` compiles;
  this mirrors the established port rule, where `pkt.dst_port ==
  65535` compiles but `pkt.dst_port == 70000` does not.
- `pkt.vlan_priority` compared against a literal **above 7** (e.g.
  `pkt.vlan_priority == 8`) is a compile error:
  *"vlan_priority value N outside valid range 0..7"*.
- Comparing a VLAN field against a non-integer operand (IP, IPv6, or
  proto literal) is the usual type-mismatch error.

### Examples

```python
@xdp(eth0)
# Allow management VLAN 10 over SSH.
allow if pkt.vlan_id == 10 and pkt.proto == tcp and pkt.dst_port == 22
# Drop the guest VLAN range entirely.
drop if pkt.vlan_id in 100..199
# High-priority voice traffic on VLAN 20.
allow if pkt.vlan_id == 20 and pkt.vlan_priority >= 5
default drop
```

### Builder additions (PKT format)

All packet builders — `tcp()`, `udp()`, `icmp()`, `tcp6()`,
`udp6()`, `icmp6()` — gain two optional parameters: `vlan_id` and
`vlan_priority`. When either is set, the builder inserts a 4-byte
802.1Q tag (TPID `0x8100`, PCP/DEI/VID) immediately after the
Ethernet source MAC, shifting the L3 header by 4 bytes. The decoded
fields dict gains `vlan_id` and `vlan_priority` keys so the
interpreter oracle reads the same values the BPF parser sees. A
builder call with neither parameter produces an untagged frame
(unchanged from v0.2).

A seventh builder, `icmperr()`, produces an ICMP **error**: the 8-byte
ICMP header (whose "unused" word carries the RFC 1191 next-hop MTU for
type 3 code 4) followed by the embedded datagram — a full 20-byte IP
header plus the first 8 bytes of its transport header. Nothing else in
the builder language can produce one: `icmp()` emits an 8-byte header
over a zero body, which no router has ever sent and which carries no
flow identity at all.

| Field | Default | Meaning |
|---|---|---|
| `src_ip`, `dst_ip` | `1.1.1.1`, `2.2.2.2` | the error's own addresses |
| `type`, `code` | `3`, `4` | fragmentation needed |
| `mtu` | `1400` | next-hop MTU (RFC 1191) |
| `inner_proto` | `tcp` | `tcp`, `udp` or `icmp` |
| `inner_src_ip` | the error's `dst_ip` | embedded source — an error comes back from the peer a packet went to, so its datagram was addressed *from* the error's destination |
| `inner_dst_ip` | `2.2.2.2` | embedded destination |
| `inner_src_port`, `inner_dst_port` | `0` | embedded ports (ignored when `inner_proto` is `icmp`) |
| `inner_len` | `1500` | the ORIGINAL datagram's total length — the router copies the header it could not forward, and that length is why the error exists |

`vlan_id`, `vlan_priority` and `ihl` apply as to every other v4
builder. The decoded-fields dict reports `proto: icmp` with
`icmp_type` / `icmp_code` (an error IS an ICMP packet, and
`pkt.proto == icmp` matches it), no `src_port` / `dst_port` (an error
has none), and the embedded tuple under `_inner_proto`,
`_inner_src_ip`, `_inner_dst_ip`, `_inner_src_port`, `_inner_dst_port`
— underscored, like `_ihl`, because no rule can name them.

`expected.output_packet` gains `inner_src_ip`, `inner_dst_ip`,
`inner_src_port` and `inner_dst_port` so a case can assert the
embedded rewrite. A case that asserted only the outer header would
pass on a NAT that steered an error to the right host and left it
describing the wrong connection.

All ICMP frames the builder produces now carry a **correct** checksum
(they carried a zero placeholder until ICMP-error NAT existed), and the
BPF oracle validates the ICMP and embedded-IP checksums of every
asserted `output_packet` alongside the outer IP and L4 ones.

## Conntrack — `conntrack(pkt).state`

### Construct

A single new accessor exposes the daemon's connection-tracking table
to the language:

```
conntrack(pkt).state
```

`conntrack(pkt)` denotes the connection-tracking view of the packet;
`.state` reads its state as a `ct_state`-typed value compared against
state keywords. A bare `conntrack(pkt)` (without `.state`) is not a
valid expression.

The four states:

| State | Meaning |
|-------|---------|
| `new` | the packet's 5-tuple is absent from the conntrack table |
| `established` | the 5-tuple was found (forward **or** reverse direction) |
| `related` | an ICMP error whose **embedded datagram** names a tracked flow |
| `invalid` | a TCP state-machine violation: a non-SYN segment for an untracked flow |

### Type rules

- `conntrack(pkt).state` has type `ct_state`. The only operators are
  `==`, `!=`, and `in` over a list of state keywords:
  ```
  allow if conntrack(pkt).state == established
  drop  if conntrack(pkt).state == invalid
  allow if conntrack(pkt).state in [established, related]
  ```
  Ordered comparisons (`<`, `>`, `<=`, `>=`) are a compile error.
- The right-hand side must be a state keyword (`new`, `established`,
  `related`, `invalid`). Comparing against a proto keyword, integer, or
  any other operand is a compile error.
- **No protocol guard is required.** Conntrack is evaluated on every
  frame; a non-IP or IPv6 frame simply reads `new` (see Semantics).
  Like the L3 IP fields and the VLAN fields, `conntrack(pkt).state` is
  legal in any context, including before any `pkt.proto ==` test.
- The state keywords (`new`, `established`, `related`, `invalid`) are
  reserved words, like the proto keywords (`tcp`, `udp`, ...). An
  identifier that merely starts with one (e.g. a counter named
  `established_flows`) is unaffected.
- There is no `ct_state` Tier 2 local: `conntrack(pkt).state` cannot be
  hoisted into a variable (`x = conntrack(pkt).state` is invalid). It
  may be compared directly inside Tier 2 `if` conditions.

### Semantics

- **5-tuple.** The lookup key is `(src addr, dst addr, src port, dst
  port, protocol)`, extracted from the variable `l3` pointer so it is
  correct on VLAN-tagged frames. Addresses are network byte order, ports
  host byte order — byte-matching the daemon's `conntrack` map
  (`struct ConnKey` in `include/f/types.h`). For ICMP (and any frame
  with no L4 header) the ports are 0.
- **Lookup.** A single hash-map probe on the forward key; on a miss, a
  second probe on the reverse key (src/dst addresses and ports swapped).
  A hit in **either** direction is `established` — this is what lets a
  reply match the entry its initiating packet created.
- **Refresh.** A hit stamps the entry's `last_seen_ns` and bumps its
  packet count. This is what makes the daemon's `timeout_s` an *idle*
  timeout rather than a lifetime cap: without it an entry was collected
  `timeout_s` after the flow's FIRST packet, so a busy connection lost
  its state mid-flight and a stateful policy began dropping it.
- **Classification.** Forward-or-reverse hit → `established`. Otherwise a
  TCP segment with no SYN flag → `invalid` (data/ACK/RST for a flow whose
  handshake was never seen). Everything else → `new`. `established` takes
  precedence over `invalid`.
- **Entry creation (side effect).** Two constructs insert a forward
  5-tuple into the conntrack table (via `BPF_NOEXIST`):
  1. An explicit `allow` rule (or an explicit `default allow`) that
     permits a packet reading `new` — the packet's own 5-tuple.
  2. A **source-NAT** action (`masquerade`/`snat`) that actually rewrites
     the source — the **post-NAT** 5-tuple (the rewritten source, the
     unchanged destination, and the preserved ports). A NAT'd flow is a
     tracked connection: inserting the post-NAT tuple is what lets the
     reply — which arrives with that tuple reversed — read `established`,
     so a stateful gateway can redirect return traffic back in. Without
     it the canonical `masquerade` + `redirect to wan` / `redirect to lan
     if established` gateway would be outbound-only.
  3. A **destination-NAT** action (`dnat`) that actually rewrites the
     destination — likewise the post-NAT 5-tuple, so the internal
     server's reply reads `established` on its way back out. Same
     argument as (2), same failure without it: a port forward that
     admits the client and drops every reply.

  These post-NAT entries are also what gives each `fwl_nat` mapping an
  anchor the daemon can age it against (see § NAT, mapping lifetime).

  A `drop` on a `new` packet creates **nothing**, the implicit
  fall-through `XDP_PASS` (no matching rule and no `default`) does
  **not** create an entry, and `redirect` alone creates none. This is the
  first family of constructs whose evaluation of one packet changes the
  state a later packet sees.
- **IPv4 only.** v0.4 conntrack tracks IPv4 flows (the daemon's `ConnKey`
  is keyed on 32-bit addresses). On an IPv6 frame `conntrack(pkt).state`
  is always `new`, and an allowed IPv6 packet creates no entry. A program
  may freely mix conntrack rules with IPv6 rules; the IPv6 packets simply
  read `new`.

### Edge cases

- *Non-IP / IPv6 frame.* Reads `new`; creates no entry.
- *ICMP packet.* Tracked as a 5-tuple with ports 0; an untracked ICMP
  packet is `new` (never `invalid` — `invalid` is TCP-only).
- *UDP.* An untracked UDP datagram is `new`; its reply matches via the
  reverse key once the query created the entry.
- *Truncated TCP.* A frame cut before the flags byte cannot prove a SYN,
  so an untracked truncated-TCP segment reads `invalid` (the `l4_ok` /
  flag reads never happen).
- *`established` vs `invalid`.* A non-SYN packet that matches an existing
  entry is `established`, not `invalid` — the table lookup wins.
- *`related`.* An ICMP **error** — types 3, 4, 5, 11 and 12, the five
  RFC 792 messages that carry the datagram that provoked them — reads
  `related` when the 5-tuple of that embedded datagram matches a
  tracked flow in either direction. Nothing else is ever `related`: an
  ICMP **query** (echo, timestamp, …) carries nobody's packet and reads
  `new`, however closely its payload resembles one.
- *`related` creates nothing and refreshes nothing.* An error is
  evidence ABOUT a flow, not traffic belonging to one, so an allowed
  `related` packet adds no conntrack entry and does not stop an idle
  flow from being collected.
- *`established` does not include `related`.* This is the migration
  every policy written against v0.4 must make, and it is the same one
  nftables and iptables require: `allow if conntrack(pkt).state ==
  established` does **not** admit the ICMP errors your own outbound
  flows provoke, which for a masquerading gateway means path-MTU
  discovery is dead and large transfers hang with nothing logged. The
  idiom is `allow if conntrack(pkt).state in [established, related]`.
- *Classification is a property of the packet, not of NAT.* A policy
  with no NAT rule anywhere still classifies errors, because the flows
  it is protecting still provoke them.
- *5-tuple specificity.* A packet to a different port (or address, or
  protocol) than a tracked flow does not match it — it reads `new`.

### Compile errors

| Condition | Error |
|---|---|
| `conntrack(pkt).state < established` | ordered comparison rejected: only `==`, `!=`, `in` |
| `conntrack(pkt).state == tcp` | wrong RHS type (a state keyword is required) |
| `conntrack(pkt).state == 1` | wrong RHS type (a state keyword is required) |
| `conntrack(pkt) == established` | `conntrack(pkt)` is not an expression — access `.state` |
| `conntrack(pkt).state == bogus` | unknown state keyword |

### Examples

```
# Stateful allow: established flows pass; new SSH connections are
# rate-limited; everything else is dropped.
@xdp(eth0)
allow if conntrack(pkt).state == established
drop  if pkt.proto == tcp and pkt.dst_port == 22 limited by rate_limit(5, per=src_ip)
allow if pkt.proto == tcp and pkt.tcp.syn and pkt.dst_port in [80, 443]
default drop

# Drop state-machine violations early.
@xdp(eth0)
drop if conntrack(pkt).state == invalid
allow if conntrack(pkt).state in [established, related]
allow if pkt.proto == tcp and pkt.tcp.syn
default drop

# Tier 2.
@xdp(eth0)
def filter(pkt):
  if conntrack(pkt).state == established:
    allow
  if pkt.proto == tcp and pkt.tcp.syn and pkt.dst_port == 80:
    allow
  drop
```

### PKT format additions

The `.pkt` test format gains two v0.4 extensions for conntrack, both
exercised by the three-oracle runner:

- **`state.conntrack`** — a list of pre-seeded forward 5-tuple entries
  (analogous to `state.rate_limit`). Each entry has `src_ip`, `dst_ip`,
  `proto` (required) and optional `src_port`/`dst_port` (default 0). The
  interpreter starts its conntrack table with these entries; the BPF
  oracle seeds the `conntrack` map. v0.4 entries are IPv4 only.
  ```yaml
  state:
    conntrack:
      - { src_ip: "1.2.3.4", dst_ip: "2.2.2.2", src_port: 12345, dst_port: 80, proto: tcp }
  ```
- **`sequence`** — an ordered list of packets sharing one conntrack
  table, replacing the single `test_packet`/`expected` pair. The runner
  loads the BPF program **once** and runs each step against it, so an
  allowed `new` packet's created entry is visible to a later step. Each
  step carries its own `expected`.
  ```yaml
  sequence:
    - name: client SYN out
      builder: tcp(src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=40000, dst_port=80, syn=true)
      expected: { bpf_action: allow }
    - name: server reply (established via reverse 5-tuple)
      builder: tcp(src_ip="2.2.2.2", dst_ip="1.1.1.1", src_port=80, dst_port=40000, syn=true, ack=true)
      expected: { bpf_action: allow }
  ```

## Zones, Per-Zone @xdp, Redirect & `pkt.zone`

The zone model abstracts policy over physical interfaces. The operator
declares named zones (`wan`, `lan`, `dmz`) bound to interface lists,
writes one `@xdp(<zone>)` block per zone, and forwards traffic between
zones with `redirect to <zone>`. This is the first construct where one
`.fw` file compiles to **multiple** BPF programs — one per zone —
cooperating through bpffs-pinned shared maps.

### 6.1 Zone declarations

#### Construct

```
zone wan = [wan0]
zone lan = [lan0, lan1, lan2, lan3]
zone dmz = [dmz0]
```

Zero or more `zone` declarations appear at the top of the file, before
any `@xdp` block. A zone names a set of one or more interfaces; every
interface in a zone gets the same program attached. Interface names are
resolved to ifindexes by the daemon at load time (a missing interface is
a load-time error, not a compile error — interfaces may appear after
boot).

#### Type rules

A zone name is a compile-time identifier, not a runtime value. It
appears only in `@xdp(<zone>)` declarations, `redirect to <zone>`
actions, and `pkt.zone` comparisons — never as a packet-field operand.

#### Compile errors

- **Empty zone**: `zone wan = []` — a zone needs ≥ 1 interface.
- **Duplicate zone name**: two `zone <name> = ...` with the same name.
- **Overlapping interface**: one interface listed in two zones.

### 6.2 Per-zone `@xdp` blocks

#### Construct

```
zone wan = [wan0]
zone lan = [lan0, lan1, lan2, lan3]

@xdp(wan)
def from_wan(pkt):
  if conntrack(pkt).state == established:
    allow
  drop

@xdp(lan)
redirect to wan
```

Each `@xdp(<zone>)` block defines the policy for traffic arriving on
that zone's interfaces. A block is either a Tier 1 rule sequence
(optionally with `default`) or a single Tier 2 `def`, exactly as in
v0.2 — the two tiers stay mutually exclusive **per block**. The
single-`@xdp` file with no zone declarations is the degenerate case: one
implicit zone whose name is the `@xdp` argument.

#### Compilation model

- Each zone compiles to its own BPF program (its own `<zone>.bpf.c` →
  `<zone>.bpf.o`), named `fwl_prog` within its object. The daemon
  attaches each object to every interface in its zone.
- Shared state is held in bpffs-**pinned** maps (`LIBBPF_PIN_BY_NAME`):
  above all the `conntrack` map, so a flow established on one zone is
  `established` for every other zone — the requirement that makes a
  stateful gateway work. Loading every zone object under a common pin
  root resolves the pinned maps to one kernel map each. `fwl compile
  --bundle <dir>` emits the per-zone sources, objects, a shared header,
  and a `manifest.json` describing zones, objects, redirect topology,
  the pinned maps, each zone's RULES in policy order, and the identity
  (path, name, SHA-256) of the policy text the bundle was compiled
  from. The rule metadata and the source digest exist so a box can
  answer "what am I enforcing right now" without reading a file: the
  loader captures both in the same call that opens the objects, and
  serves them over the control socket. A zone whose policy is a Tier 2
  function has no rule list and its entry says so — `"form":
  "function"` — rather than reporting an empty one.

#### Compile errors

- `@xdp(<name>)` naming an undeclared zone (when the file declares
  zones).
- More than one `@xdp` block targeting the same zone.

A declared zone need not have its own `@xdp` block — it may exist only
as a redirect destination.

### 6.3 Redirect action

#### Construct

```
redirect to <zone>
```

A terminal action (like `allow`/`drop`) that forwards the packet out one
of the destination zone's interfaces and returns `XDP_REDIRECT`. Valid
as a Tier 1 rule action (`redirect to wan if <cond>`) and as a Tier 2
action statement. **Not** valid as a `default` action — `default` admits
only `allow`/`drop` — so `default redirect to <zone>` is a syntax error.

#### Semantics

The emitter declares one `BPF_MAP_TYPE_DEVMAP` per destination zone
(`fwl_devmap_<zone>`). The daemon populates it with the destination
zone's egress ifindex(es) at load time; for a multi-interface zone the
switch chip's FDB/MAC learning picks the physical egress port.
`redirect` does not open a conntrack entry in v0.4 (NAT-driven flow
creation is Phase 5).

**A devmap is never pinned**, and every zone object that redirects to `<dest>` therefore carries its own copy of `fwl_devmap_<dest>`, which the daemon fills from that object's own `redirects_to`. This is not a choice: a devmap **cannot** be reused from a bpffs pin. The kernel sets `BPF_F_RDONLY_PROG` inside `dev_map_alloc` — so the verifier cannot let a program write through a devmap lookup — while the object declares `map_flags 0`, and libbpf's pin-reuse check compares the two (0 against 128, which can never agree). Under the old bundle-global pin the SECOND zone object to declare `fwl_devmap_<dest>` failed to load with `couldn't reuse pinned map ...: parameter mismatch`, which made a gateway with two inside zones behind one uplink unloadable — the shape `deploy/firstboot` generates for every box with more than two ports. Declaring the flag in the emitter does not work either: `DEV_CREATE_FLAG_MASK` excludes it and map creation returns `-EINVAL`. Per-object copies cost nothing, because the contents are re-derived from the manifest at every load rather than carried between them.

In the map registry (`emitter._MAP_KINDS`) this is `MapScope.PRIVATE` with no zone-qualified name — the same shape as `fwl_scratch` and `fwl_stages`, where the object boundary does the isolating — and `MapLifetime.POLICY`, which is now a statement that nothing of it reaches bpffs to be adopted rather than a rule about what may be. The two axes stay orthogonal: PRIVATE here is not "the contents belong to one zone" (they do not — every copy holds the same ifindexes) but "two zone objects must not land on one kernel map", which is the question `MapScope` actually asks.

**`f` routes.** A redirect is not only an egress decision, it is a
next-hop decision, and the two are not the same question. Through v0.4
the emitted code was one `bpf_redirect_map()`, which forwards the frame
with the Ethernet header it arrived carrying. For a zone-to-zone hop on
one L2 segment that is correct. For a hop across a subnet boundary it
is not, and **masquerade is that second case by construction**: you
cannot translate the source to your own address and then hand the frame
to a MAC you never addressed. The next hop's NIC reports the frame as
`PACKET_OTHERHOST` and its stack discards it before any socket exists.

So a redirect now resolves the next hop through the kernel's own
routing table (`bpf_fib_lookup`) and re-addresses the frame to it:

1. Read the destination zone's ifindex from devmap slot 0. If the slot
   is empty, nothing is known about this zone and the frame is
   forwarded L2-adjacent (this is also what makes an unpopulated devmap
   behave exactly as before, which is what the `.pkt` corpus sees).
2. `bpf_fib_lookup` with the packet's post-NAT addresses and the
   ingress ifindex.
3. On `BPF_FIB_LKUP_RET_SUCCESS`, **the egress ifindex the FIB returns
   must be the zone's own**. A box with a default route resolves every
   destination, so without this check a zone hop on an unrouted segment
   would be stamped with the default gateway's MAC, which lives on a
   different interface. A mismatch is counted (`off_zone`) and the
   frame is forwarded L2-adjacent.
4. Otherwise: the destination MAC and source MAC are written from the
   lookup, the TTL is decremented, and the IP checksum updated. Egress
   is still the zone's devmap — the policy named a zone and the frame
   leaves through it.

The failure outcomes follow the kernel's own classification:

| FIB result | Outcome |
|---|---|
| `SUCCESS`, ifindex matches | routed (MACs rewritten, TTL decremented) |
| `SUCCESS`, ifindex differs | forwarded L2-adjacent, counted `off_zone` |
| `BLACKHOLE` / `UNREACHABLE` / `PROHIBIT` | `XDP_DROP`, counted `no_route` |
| `NO_NEIGH` | `XDP_PASS` so the stack can ARP, counted `no_neigh` |
| anything else (incl. `FWD_DISABLED`, no route) | forwarded L2-adjacent |
| TTL ≤ 1 | `XDP_PASS`; the stack owns the ICMP time-exceeded |

`NO_NEIGH` is the one that does not fully recover: handing the packet to
the stack is what triggers the ARP, but a **source-translated** packet
does not survive that trip, because its source is one of this box's own
addresses and `fib_validate_source` rejects it as a martian. The
resolution happens; that packet does not. It is counted and logged for
exactly that reason.

`net.ipv4.ip_forward` is therefore load-bearing rather than advisory:
with it at 0 the lookup returns `FWD_DISABLED`, no next hop is
resolved, and every forward degrades to the L2-adjacent behaviour. It is
generated as part of the appliance system configuration
(`f-sysconf render sysctl`), not documented as a manual step.

Which of the two a forward took is **not observable on the wire**. Both
put the same frame on the same cable; only the far side's stack tells
them apart, and only by dropping one of them. `fwl_route_stats` (one
per-CPU array per bundle, surfaced as the `route` section of
`fctl status`) is where the difference is written down.

Routing is IPv4-and-untagged only in v0.4, the same boundary as
conntrack and NAT. A tagged frame or an IPv6 frame keeps the
L2-adjacent behaviour, because re-addressing a tagged frame without
touching its tag addresses the right host on the wrong segment.

#### Edge cases

- **Hairpin** (`redirect to <ingress zone>`) is permitted — it forwards
  back out the arriving zone (an unusual but valid configuration).
- **Redirect destination down**: the kernel drops the frame at
  `xdp_do_redirect`; no crash.
- **Redirect without prior NAT** is valid — pure L2/L3 forwarding.
- **Redirect on a segment the box has no route to** keeps working: the
  lookup fails, the frame is forwarded unchanged, and `bridged` counts
  it. A bridge does not need a routing table.
- **A multi-interface zone routes only through devmap slot 0** — the
  zone's first declared interface. A route whose egress is one of the
  zone's OTHER interfaces reads as `off_zone` and is forwarded
  L2-adjacent. That is the safe degradation (it never stamps a next hop
  from another segment onto a frame leaving the wrong port), but it is a
  real limitation and it is untested: every zone on the bench has one
  interface. Lifting it means matching the FIB's egress ifindex against
  every populated devmap slot and redirecting to the slot that matches,
  which is a small change and should not be made without a two-port
  zone to prove it on.

#### Compile errors

- `redirect to <unknown_zone>` — destination not a declared zone.
- `redirect to <zone>` in a file that declares no zones.

### 6.4 `pkt.zone` field

#### Construct

```
@xdp(lan)
allow if pkt.zone == lan      # constant-true in this block
drop
```

`pkt.zone` is a **compile-time constant** within an `@xdp` block — the
compiler knows the block's zone, so the comparison folds to `1`/`0` in
the emitted C and to a fixed boolean in the interpreter. Useful in
shared helpers (future multi-def, § 6.5) that branch on ingress zone.

#### Type rules

Type: zone enum. Operators: `==`, `!=`, and `in [<zone>, ...]`. The RHS
zone names must be declared. Ordered operators (`<`, `>`, `<=`, `>=`)
are a compile error.

#### Compile errors

- `pkt.zone` compared against an undeclared zone.
- `pkt.zone` with an ordered operator.
- `pkt.zone` in a file that declares no zones.

### 6.7 `rate_limit` zone scope — `scope=`

v0.1 defined `rate_limit(N, per=<field>)` for a world with one program.
v0.4 compiles one program per zone, which raises a question v0.1 could
not ask: when a policy carries that rule in more than one zone, is `N`
a budget per zone or a budget for the bundle? Through v0.4 the answer
was per zone, by implementation and not by statement. `scope=` states
it.

#### Construct

```
<rule> limited by rate_limit(<N>, per=<field>[, scope=<zone|global>])
```

`scope` is optional and its **default is `zone`** — the behaviour every
policy written before this section already had, so adding the field
changes no deployed policy's meaning.

#### Semantics

- **`scope=zone`** (default) — the bucket belongs to the zone program
  that holds the rule. A rule written into three zones is three
  independent budgets: each zone admits `N` per second per bucket key,
  so the bundle admits up to `3N`.
- **`scope=global`** — one bucket for the rule across the whole
  bundle. Every zone program that holds the rule spends the same
  budget, so the bundle admits `N` per second per bucket key no matter
  which zone the traffic arrives on.

Everything else about the primitive is unchanged: the one-second
window, the pre-increment comparison, and the "fires once the bucket
already holds `N`" reading of v0.1 § *The rate_limit Modifier* all
apply identically under both scopes.

**`scope` does not change the per-CPU nature of the count.** v0.1 chose
a per-CPU map for `rate_limit`, and that is still the map a global
bucket shares: `scope=global` makes two zones read the same *map*, and
each CPU still keeps its own counter within it. So a global budget is
`N` per second per bucket key **per CPU** — the same multiplier
`scope=zone` has always carried, and the same one a single-zone v0.1
policy has. Two zones' traffic therefore shares a budget when it is
processed on the same CPU, which for one flow (one RSS bucket) it
normally is, and does not when the kernel spreads it. Removing that
multiplier is a change to `rate_limit` itself, not to `scope`, and is
not in v0.4.

**Which rules share a global bucket.** A `scope=global` bucket is one
bucket *per rule*, and "the same rule" means structurally the same
rule: same action, same condition, same threshold, same `per=` field,
same scope. That is what makes the common multi-zone shape work — one
rule written once per `@xdp` block is one rule, so it gets one bucket.
Two rules that differ anywhere in that list are two rules and get two
buckets, even when both say `scope=global`. Source position is not part
of the identity; a rule's line number and its index within its zone are
not.

#### Composition with `per=`

`scope` and `per=` are independent and orthogonal, and both are needed
to describe a bucket: `per=` chooses **how the traffic is divided into
buckets**, `scope` chooses **how far each bucket reaches**.

| | `scope=zone` (default) | `scope=global` |
|---|---|---|
| `per=src_ip` | each source IP gets `N`/s **in each zone** | each source IP gets `N`/s **across the bundle** |
| `per=dst_port` | each destination port gets `N`/s in each zone | each destination port gets `N`/s across the bundle |

`per=src_ip, scope=global` is the meaningful combination for a DoS
control: one attacking source cannot get a fresh budget by moving to
another zone's interface. `per=src_ip, scope=zone` is the meaningful
combination for a fairness control within a zone.

#### Composition with the v0.2 dominator rule

Unchanged. `scope` does not alter what `rate_limit` reads, only where
the resulting count is kept, so the implicit `pkt.<field>` read at the
call site is exactly the read v0.2 already governs: `per=src_port` /
`per=dst_port` still require a `pkt.proto == tcp`/`udp` dominator,
`per=src_ip` / `per=dst_ip` still require an IPv4-establishing
dominator, and the same
`error: rate_limit(per=<field>) call site does not dominate the
implicit read of pkt.<field>` applies. Dominance is a property of the
control-flow path to the call site within one program; a scope is a
property of the state behind the call. Adding `scope=global` neither
satisfies nor weakens a guard, and a rule shared across zones must
still be individually dominated **in every zone that holds it** — each
zone program is analysed on its own.

#### Compilation model

- A `scope=zone` bucket compiles to a map private to the zone object,
  named for the zone and the rule's index within it
  (`fwl_rl_<zone>_<idx>`), and is **not** pinned. Two zones cannot
  reach each other's buckets even when their rate-limit rules sit at
  the same index.
- A `scope=global` bucket compiles to a map named for its **bundle**
  slot (`fwl_rl_g<slot>`) and pinned `LIBBPF_PIN_BY_NAME`, so every
  zone object that declares it resolves to one kernel map under the
  bundle's common pin root.
- The slot number is allocated over the whole compilation unit from the
  rule's structure, never from its index inside a zone, and
  `max_entries` is a constant. Both are required, not incidental: a map
  wearing a bundle-global name whose shape or index meaning came from
  one zone's own analysis fails to load with `-EINVAL` when two zones
  disagree, and silently aliases their slots when they agree. A global
  bucket is on the shared side of that line precisely because the
  author declared the state bundle-wide; per-zone counters, geoip
  tries, log-sample accumulators and `scope=zone` buckets are not.

#### Diagnostic

When a `rate_limit` rule appears in **more than one zone** and the
author did **not** write `scope=`, the compiler warns and names the
effective aggregate:

```
warning: 6:58: rate_limit(1000, per=src_ip) appears in 3 zones
(wan, dmz, lan) with no scope=; scope defaults to zone, so each zone
keeps its own bucket and the bundle-wide aggregate is 3000/s. Write
scope=global for one shared bucket, or scope=zone to say per-zone is
what you meant
```

The warning is not a deprecation of the default — per-zone stays the
default and stays correct. It exists because per-zone is *more
permissive* than the naive reading of a single `rate_limit(N)`, and for
a rule used as a DoS control that gap is security-relevant. It fires
only for the implicit default: once any copy of the rule states a
scope, the author has declared intent and is not warned again.

#### Compile errors

- `scope=` with any value other than `zone` or `global`:
  `error: rate_limit scope= must be zone or global, not '<value>'`

#### Examples

```
# One SSH-flood budget for the whole appliance. A source that exhausts
# its 10/s on the WAN gets nothing more by arriving on the DMZ.
zone wan = [wan0]
zone dmz = [dmz0]

@xdp(wan)
drop if pkt.proto == tcp and pkt.dst_port == 22
       limited by rate_limit(10, per=src_ip, scope=global)
allow

@xdp(dmz)
drop if pkt.proto == tcp and pkt.dst_port == 22
       limited by rate_limit(10, per=src_ip, scope=global)
allow
```

```
# Per-zone fairness, stated rather than inherited: each zone admits
# 1000/s per source independently. Identical in behaviour to omitting
# scope, but it silences the multi-zone aggregate warning because the
# author has said the 2000/s bundle total is intended.
@xdp(wan)
drop limited by rate_limit(1000, per=src_ip, scope=zone)
allow

@xdp(lan)
drop limited by rate_limit(1000, per=src_ip, scope=zone)
allow
```

### 6.8 Log-event record ABI

`log` submits one record to `fwl_log_events`, a `BPF_MAP_TYPE_RINGBUF`
that is **bundle-wide**: every zone object in a unit pins it by name
and writes into one kernel ring. That is deliberate — the ring is fixed
size and genuinely unit-wide, and splitting it per zone would push
multiplexing onto every consumer for no gain.

It does mean a record is only meaningful *with* its zone. `rule_index`
is numbered within a zone, so zone `wan`'s rule 2 and zone `lan`'s rule
2 write the same number into the same ring. **A logged rule is
identified by the pair `(zone_id, rule_index)`, never by `rule_index`
alone.**

#### Record layout (v1)

```c
#define FWL_LOG_EVENT_MAGIC 0x464C4745u   /* "FLGE" */
#define FWL_LOG_EVENT_VERSION 1u

struct fwl_log_event {
  __u32 magic;          /* offset  0 */
  __u16 version;        /*         4 */
  __u16 event_size;     /*         6 — sizeof(struct fwl_log_event) */
  __u64 timestamp_ns;   /*         8 */
  __u32 zone_id;        /*        16 */
  __u32 rule_index;     /*        20 */
  __u32 src_ip;         /*        24 */
  __u32 dst_ip;         /*        28 */
  __u16 src_port;       /*        32 */
  __u16 dst_port;       /*        34 */
  __u8  proto;          /*        36 */
  __u8  flags;          /*        37 — bit 0 SYN, bit 1 ACK */
  __u8  pad[2];         /*        38 */
};                      /* 40 bytes */
```

The layout is defined once, in `fwl/log_abi.py`: both the C the
emitter stamps into every object and the `struct` format its consumers
unpack come from that module, and a unit test compiles the struct and
asserts each offset against the format. Two copies of a record layout
is how a reader and a datapath drift apart without either reporting an
error.

#### Header fields

A consumer **must** validate `magic`, `version` and `event_size`
before reading any other field, and **must** treat a mismatch as an
error rather than skipping the record. The failure this guards against
is not a crash: a changed layout unpacks into values that all look
legal — a rule index that names a real rule, a port in range — so
without the header a mismatch produces plausible wrong data and no
diagnostic anywhere.

#### `zone_id`

`zone_id` is FNV-1a 32 over the UTF-8 zone name (offset basis
`0x811C9DC5`, prime `0x01000193`).

It is a hash of the name and not an ordinal assigned at emit time,
because an ordinal is a property of a zone's *position* in the unit:
inserting a zone renumbers every zone after it, and a table read back
against a previous compilation then names the wrong zone — silently.
The name is what every other artifact already keys on
(`fwl_counters_<zone>`, the manifest, `pkt.zone`), so the id follows
the name.

A hash's one failure mode is a collision, and a collision restores
exactly the ambiguity this field removes. It is therefore a **compile
error**, checked across the whole unit's zone set:

```
error: zones 'wan' and 'lan' share log-event zone id 0x0BADC0DE. Log
events identify their zone by a hash of its name, so a collision makes
the two zones' events indistinguishable — the ambiguity the zone tag
removes. Rename one of them.
```

`zone_id == 0` is reserved to mean "unattributed" and no zone may
compile to it.

#### The lookup table

A numeric id a consumer cannot resolve to a name is no improvement on
no id at all, so the table ships **with the bundle**. Every bundle's
`manifest.json` carries a `zone_ids` object mapping name to id, over
every zone the unit can emit an event from (including the degenerate
`@xdp(eth0)` case, which declares no zones and still tags its records
`eth0`):

```json
"zone_ids": {
  "lan": 1449164816,
  "wan": 736289537
}
```

`fwl_shared.h` repeats the table as a comment for a human reading the
bundle; `manifest.json` is the machine-readable copy.

#### Rejected alternatives

- **Bundle-global rule numbering.** Would couple every zone object to
  whole-unit knowledge at emit time — the same coupling that made the
  shared-counter-map defect possible.
- **Packing the zone into the high bits of `rule_index`.** Saves four
  bytes, costs clarity, and caps the rule count.
- **One ring buffer per zone.** The shared ring is correct; splitting
  it moves multiplexing into every consumer and buys nothing.

### 6.9 Egress conntrack tracking — flows the box originates

Conntrack in v0.4 is built by the XDP programs, and XDP only ever sees
INGRESS. A flow the appliance itself starts therefore creates no
conntrack entry at all: the DNS query its forwarder sends upstream, the
NTP exchange that sets its clock, the package update it fetches. Each
one leaves through the local stack, which no XDP program is attached
to. Its reply arrives on the WAN port, is looked up, reads `new`, and a
`default drop` policy — the one this whole section teaches — eats it.

Measured on hardware before the fix
(`fwl/tests/system/hw/l12_01_box_originated_flows.sh`): the box sent 5
UDP requests from its own WAN address, the datapath counter recorded 5
replies arriving at the port, 0 survived, conntrack went 0 -> 0. A
policy drop, not an empty wire. **A firewall that cannot resolve a name
or set its own clock is not deployable**, so this is not an edge case
of the language; it is the language's default policy being unusable on
the box that runs it.

#### The mechanism

Every bundle whose policy reads `conntrack(pkt).state` anywhere also
carries **one** extra object, `fwl_egress.bpf.c`, holding a single
`SEC("tc")` program. `fd` attaches it at the **clsact egress** hook of
every interface the bundle attaches XDP to — those are exactly the
ports on which a reply to a locally-originated flow would be judged.

Per packet it:

1. returns immediately unless `skb->sk` is set. A packet the local
   stack SENT carries the socket that sent it; a packet this box merely
   FORWARDED has none. This gate is what keeps the tracker an observer:
   without it, a forwarded flow would get an entry and its replies
   would be admitted, which is a policy change made by a component that
   has no business making one;
2. parses IPv4 / first fragment / TCP, UDP or ICMP, and builds the
   5-tuple exactly as the XDP prelude does (ICMP keyed on ports 0);
3. probes conntrack in **both** directions. A hit is refreshed
   (`last_seen_ns`, `packets`), not replaced;
4. only on a double miss inserts the forward tuple with state
   `established`, via `BPF_NOEXIST`.

An 802.1Q tag is skipped exactly as the prelude skips it, so the key is
built from the same inner header on a tagged segment as on an untagged
one; and every protocol other than TCP and UDP is keyed on ports 0,
again exactly as the prelude keys it, so a box-originated GRE or IPsec
flow is tracked rather than left for the two sides to disagree about.

Step 3 is what bounds the cost. A reply the box sends to a client that
queried it is egress traffic too, and its forward key is the reverse of
the entry the client's own query already created at ingress; probing
one direction would insert a second entry for every served flow and
double conntrack's fill rate. With both, the table grows by **exactly
one entry per flow the box originates**, and by nothing for the flows
it serves or forwards.

#### Why the qdisc layer

Measured, not argued. The same hook saw 5/5 of what the local stack
sent and **0 of 13** frames the XDP datapath forwarded out the same
port, because `bpf_redirect_map()` leaves through `ndo_xdp_xmit`, below
the qdisc layer entirely. It therefore covers precisely the gap and
costs the forwarding fast path nothing — it cannot even see it.

#### Rejected alternative

`bpf_sk_lookup_udp()` from XDP would need no second copy of the state
at all: ask the kernel's own socket table whether an arriving packet
belongs to a socket this box has open. It is refuted by measurement.
The lookup can only tell a reply from an unsolicited arrival when the
socket carries a **peer**, and a real DNS forwarder's upstream sockets
do not: dnsmasq's were unconnected 2/2 on the bench. Admitting on an
unconnected match would open every bound port to the WAN.

#### Visibility

`fwl_egress_stats` is a bundle-wide per-CPU array with six slots:
`seen`, `not_local`, `untracked`, `tracked`, `refreshed`, `refused`.
It is `MapScope.SHARED` and `MapLifetime.POLICY` — the entries the
tracker creates are flow-keyed and inherited across a reload; the tally
of how they got there is not.

`refused` is the one that matters. It means an insert failed, which in
practice means conntrack is at its cap: the query still goes out, the
reply still arrives, and `default drop` eats it — the original symptom,
restored, by a mechanism working exactly as designed. `fd` logs an
error naming the count whenever it moves, and `fctl status`'s `egress`
section reports it alongside a **live** count of the interfaces that
carry the filter right now.

#### Manifest

```json
"egress_tracker": {
  "source": "fwl_egress.bpf.c",
  "object": "fwl_egress.bpf.o",
  "program": "fwl_egress_ct"
}
```

**Known residual.** A locally-originated datagram large enough to be
fragmented loses `skb->sk` on the fragments (`ip_copy_metadata` does not
carry it), so such a flow is counted `not_local` and goes untracked. It
is narrow — DNS keeps itself under the MTU and TCP does not fragment —
and it is recorded rather than worked around because the workaround
(tracking socketless packets) is the policy change the gate exists to
prevent.

`null` means this policy reads no conntrack and needs no tracker. The
field being **absent** means something different — a bundle compiled
before the tracker existed — and `fd` warns about that case, because a
box running one looks healthy from every other line while dropping the
replies to its own DNS.

#### Failure policy

A bundle that declares a tracker and cannot attach it is a **failed
load**, on the same grounds as a bundle attached to zero interfaces:
loading is not attaching, and a second attach point must never report
success having attached to nothing. An attach that fails on any one of
the interfaces is rolled back rather than left partial — every one of
them demonstrably exists, since XDP just attached to it, so there is no
benign reason for a strict subset and a strict subset is a box whose
DNS works through one port and not another.

### Examples

```
# Stateful gateway: the LAN forwards everything to the WAN; the WAN
# only lets established return traffic back in.
zone wan = [wan0]
zone lan = [lan0, lan1, lan2, lan3]

@xdp(wan)
allow if conntrack(pkt).state == established
drop

@xdp(lan)
redirect to wan
```

```
# Port-forward-style steering with a per-zone branch.
zone wan = [wan0]
zone lan = [lan0]
zone dmz = [dmz0]

@xdp(wan)
redirect to dmz if pkt.proto == tcp and pkt.dst_port in [80, 443]
drop

@xdp(dmz)
def from_dmz(pkt):
  if pkt.zone == dmz:
    redirect to wan
  drop
```

## NAT — `masquerade`, `snat to <ip>`, `dnat to <ip>:<port>` (Phase 5)

NAT rewrites packets in flight: the source for outbound traffic
(`snat`/`masquerade`), the destination for inbound port forwarding
(`dnat`), and the matching reverse rewrite on the return path. NAT
builds on zones — `masquerade` + `redirect to wan` is the core gateway
pattern.

### Construct

```
masquerade                  # rewrite source -> the WAN interface address
snat to <ip>                # rewrite source -> a fixed IPv4 literal
dnat to <ip>:<port>         # rewrite destination -> a fixed IPv4:port
```

All three are **non-terminal rewrite actions**: they translate the
packet in place and fall through, so the *following* terminal action
(`redirect to <zone>` or `allow`) emits the rewritten frame. They are
valid as Tier 1 rule actions (`snat to 203.0.113.1 if pkt.proto == tcp`)
and as Tier 2 action statements. They are **not** valid `default`
actions — `default masquerade` is a syntax error.

### Type rules

`masquerade` takes no operand. `snat to` takes an IPv4 literal. `dnat
to` takes an IPv4 literal and a port (`1`–`65535`). A `dnat` port
outside that range is a compile error.

### Semantics

- **Source NAT (`snat`/`masquerade`).** When the action fires, the emitter rewrites the source address (to the literal, or — for `masquerade` — to the address the daemon wrote into this zone's own `fwl_nat_cfg_<zone>` map: the first IPv4 address on the zone THIS zone redirects to, resolved per masquerading zone because two masquerading zones need not name the same uplink), fixes the IPv4 header checksum and the TCP/UDP checksum, and installs a **reply mapping** in the shared `fwl_nat` map so the return packet is de-NAT'd.
- **Port allocation.** Source NAT **prefers to preserve** the source
  port: when the mapping key that port names is free, the translated
  port equals the original. When a **different flow already holds that
  key** — two guests picking the same ephemeral port toward the same
  destination — the mapping is moved to a port in the NAT-owned range
  `49152`–`65535`, chosen by a hash of the flow with a bounded probe
  (8 attempts), and the source port is rewritten to match. The claim is
  a `BPF_NOEXIST` insert, so a collision is always *detected*: a
  mapping is never overwritten.
- **Refusal is terminal.** If no mapping can be claimed — every probe
  taken, no port to move (a frame with no L4 ports), or `fwl_nat` at
  its `max_entries` cap — the packet is **dropped**, the frame is left
  untouched, and the event is counted in `fwl_nat_stats`. This is the
  one case where a NAT action, normally non-terminal, terminates
  evaluation. A translated packet without a mapping has nowhere for its
  reply to go: it is delivered either to the firewall's own address or
  into another guest's socket, and both used to happen silently.
- **Destination NAT (`dnat`).** Rewrites the destination address **and**
  port, fixes both checksums, and installs the reply mapping that
  restores the original (public) destination on return traffic. A
  `dnat` port is the operator's choice, so a `dnat` mapping is **never
  reallocated** — a collision is refused.
- **Return traffic (automatic de-NAT).** Before any rule evaluates,
  each NAT-carrying program probes `fwl_nat` with the packet's forward
  5-tuple; on a hit it rewrites the recorded side (destination for an
  SNAT/masquerade reply, source for a DNAT reply) back to the original
  endpoint, fixing checksums. In a bundle, **every** zone program emits
  this de-NAT pass and the shared `fwl_nat` map, so the egress zone
  installs the mapping and the ingress zone consumes it.
- **Mapping lifetime.** A mapping lives exactly as long as its flow.
  Every translated flow gets a conntrack entry carrying its **post-NAT**
  5-tuple (see § Conntrack, entry creation), and that entry is the
  mapping's own key with both endpoints swapped — so the daemon can ask
  conntrack, one lookup per mapping, whether the flow is still there.
  `fd` sweeps `fwl_nat` immediately after each conntrack sweep and frees
  every mapping whose entry is gone **and** which has itself carried no
  traffic for a grace window (default 30 s). The second condition exists
  because the anchor can be missing without the flow being over — a
  conntrack table at its own cap refuses the insert silently — and a
  mapping that is carrying traffic is never freed whatever conntrack
  says. Nothing evicts a live mapping to make room: at the cap, new
  allocations are refused and logged.
- **Occupancy is observable.** `fctl status` carries a `nat` section:
  live mappings, the cap, occupancy percentage, high-water mark, total
  reclaimed, and the datapath's own tally (`installed`,
  `port_reallocated`, `refused`, `table_full`, `denat`,
  `icmp_error`). `fd` logs a
  warning as the table crosses 80 % and an error naming the count
  whenever refusals move.
- **Checksums.** XDP has no `bpf_l3/l4_csum_replace` (skb-only), so the
  IPv4 header checksum is recomputed with `bpf_csum_diff` and the L4
  checksum is updated incrementally (RFC 1624) in native byte order.
  A wrong checksum compiles and passes the interpreter but is silently
  dropped on the wire — the BPF oracle therefore recomputes both
  checksums of every asserted `expected.output_packet`.
- **Conditions read the original packet.** A NAT rewrite affects the
  emitted frame and the reply mapping only; rule conditions evaluated
  after a `snat`/`dnat` still read the pre-NAT parsed fields (the
  emitter captures them into locals up front, and the interpreter
  mirrors this).
- **IPv4 only.** v0.4 NAT translates IPv4 only (the `fwl_nat` key is
  32-bit, like conntrack). An IPv6 frame is never rewritten and creates
  no mapping. Only the no-IP-options common case (`ihl == 5`) is
  rewritten.

### ICMP-error translation (RFC 5508 § 4.2)

An ICMP error carries no ports, so its own 5-tuple identifies nothing.
The flow it is about is named in the datagram it **carries** — the IP
header of the packet that provoked it plus the first 8 bytes of that
packet's transport header. For a translated flow, that embedded packet
is the one this NAT put on the wire, so reversing its tuple yields the
reply mapping's own key. No new state and no second table: the mapping
that de-NATs a flow's replies de-NATs the errors about it.

- **Which errors.** Types 3, 4, 5, 11 and 12 — the five RFC 792
  messages that carry an embedded datagram. A query type carries
  nobody's packet and is never treated as an error, whatever its
  payload contains.
- **Two rewrites, and either alone is useless.** The outer header is
  re-addressed to the host behind the NAT (destination for a
  masquerade reply, source for a port-forward reply); the embedded
  header is put back the way that host sent it, address and port. An
  error left addressed to the firewall never reaches the host; an error
  delivered to the host still describing the translated connection is
  discarded by that host's own stack — the same black hole, reached the
  quiet way.
- **Three checksums.** The embedded IP header's checksum is updated for
  its changed address; the ICMP checksum, which covers the embedded
  datagram, is updated for every word changed inside it (including that
  embedded checksum); the outer IP checksum is recomputed. Note that
  the embedded IP checksum absorbs an address change **exactly**, so an
  address-only translation leaves the ICMP checksum unmoved — only a
  changed embedded PORT makes that update observable.
- **The embedded tuple wins.** It is consulted before the error's own
  5-tuple, which is `(error-sender, us, 0, 0, icmp)` — a key that a
  ports-0 ICMP mapping (a guest's ping to that same router) can hold.
  Reading the outer header first delivers one host's path-MTU error to
  whichever host last pinged the sender.
- **Bounds.** The whole 8-byte ICMP header, 20-byte embedded IP header
  and 8 embedded transport bytes must be present, and the embedded
  header must have `ihl == 5`. Anything less names no flow: the error
  is neither `related` nor translated.
- **Counted.** `icmp_error` in the `nat` section of `fctl status`, a
  subset of `denat`. It is reported even at zero: a masquerading
  gateway carrying return traffic and translating no ICMP errors is a
  path-MTU black hole, and that failure produces no drop, no log, and
  no other counter movement.

### Edge cases

- *Guard miss.* `snat to <ip> if pkt.proto == tcp` leaves a UDP frame
  unrewritten (the action never fires).
- *IPv6 frame.* No rewrite, no mapping (NAT is IPv4-only).
- *UDP with checksum 0.* Left as 0 ("no checksum"); a computed checksum
  that folds to 0 is stored as `0xffff`.
- *Same flow, later packet.* Finds its own mapping, not a collision:
  the port does not move and the mapping's lifetime stamp is refreshed.
- *ICMP.* A source NAT translates an ICMP frame's address and installs a
  mapping keyed on **ports 0**, and de-NAT consumes it, so a masqueraded
  host's echo replies come home. Because the key has no port field to
  move, two hosts pinging the same peer collide, and the second is
  **refused and dropped** rather than silently taking over the first's
  mapping. `dnat` does not touch ICMP at all (there is no port to
  rewrite).
- *ICMP error.* An ICMP error (types 3, 4, 5, 11, 12) is translated
  off the datagram **embedded** in it, per RFC 5508 § 4.2 — see
  § ICMP-error translation below. The embedded tuple is consulted
  **before** the error's own 5-tuple, because that tuple is
  (error-sender, us, 0, 0, icmp) and can belong to an unrelated ping.
- *Table at its cap.* Refused and dropped, never evicted. Freeing is
  driven by flow end, so reaching the cap means flows are genuinely
  live, not that the table failed to drain.

### Compile errors

| Condition | Error |
|---|---|
| `default masquerade` | `default` admits only `allow`/`drop` (syntax error) |
| `dnat to 10.0.0.5:70000` | dnat target port out of range 1-65535 |
| `snat to 999.0.0.1` | invalid IPv4 octet |

### Examples

```
# Outbound gateway: the LAN masquerades behind the WAN address and
# redirects out; return traffic is de-NAT'd automatically before the
# WAN program redirects it back.
zone wan = [wan0]
zone lan = [lan0, lan1]

@xdp(lan)
allow if pkt.proto == udp and pkt.dst_port == 67   # DHCP, to us
allow if pkt.dst_ip == 10.0.0.1                    # our own address
masquerade
redirect to wan

@xdp(wan)
redirect to lan if conntrack(pkt).state in [established, related]
drop
```

**`masquerade` + `redirect` swallows traffic addressed to the box itself.** Both are unconditional, so anything reaching them is source-NATed and emitted on the other port — including packets that were never going anywhere, because their destination was the appliance. The case that finds this is DHCP: a client with no lease addresses its DISCOVER to `255.255.255.255`, since it has neither an address of its own nor yours. Without a terminal `allow` ahead of the rewrite the request is masqueraded onto the uplink and arrives on the far side as `<gateway>.68 > 255.255.255.255.67`, while the appliance's own DHCP server — correctly bound, correctly contained — never sees it. `allow` is terminal, so a rule that matches it never reaches `masquerade`.

The same reasoning covers the segment's own broadcast and multicast (`224.0.0.0/4`, `255.255.255.255`, the directed broadcast, NetBIOS): none of it is routable, and all of it would otherwise be masqueraded onto the uplink one frame at a time. `fwl/examples/storm_shield.fw` is the worked example.

```
# Port forward TCP/80 on the WAN address to an internal web server.
@xdp(wan)
dnat to 10.0.0.5:8080 if pkt.proto == tcp and pkt.dst_port == 80
redirect to lan
```

### PKT format additions

The `.pkt` test format gains two Phase 5 extensions:

- **`expected.output_packet`** — the packet header fields after the
  program's NAT rewrite (`src_ip`, `dst_ip`, `src_port`, `dst_port`;
  only the listed keys are checked). Verified by both oracles; when set,
  the BPF oracle also recomputes the IPv4 + TCP/UDP checksums of the
  rewritten frame and fails on any invalid checksum.
  ```yaml
  expected:
    bpf_action: allow
    output_packet:
      src_ip: "198.51.100.9"
      dst_ip: "93.184.216.34"
      src_port: 12345
  ```
- **`state.nat`** — the masquerade source IP and pre-seeded reply
  mappings for return-traffic de-NAT (analogous to `state.conntrack`).
  Each mapping carries the forward 5-tuple the return packet presents,
  the address+port to restore, and `nat_type` (`snat` rewrites source,
  `dnat` rewrites destination).
  ```yaml
  state:
    nat:
      masq_ip: "203.0.113.7"
      mappings:
        - { proto: tcp, src_ip: "93.184.216.34", dst_ip: "198.51.100.9",
            src_port: 80, dst_port: 12345, new_ip: "10.0.0.5",
            new_port: 12345, nat_type: dnat }
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
- No extension-header chasing for ICMPv6 — a packet behind an extension
  header has no readable `pkt.icmp6.*` (same conservatism as v0.2 L4
  fields).
- No `per=` rate-limit bucket keyed on ICMP type/code.
- QinQ inner-tag parsing (only the outer tag is exposed).
- The DEI bit as a readable field.
- VLAN rewriting / pushing / popping (read-only matching only).
- `0x88A8` TPID recognition (only `0x8100` triggers VLAN parsing).
- **IPv6 conntrack** — v0.4 tracks IPv4 flows only (the daemon's
  `ConnKey` is 32-bit). IPv6 packets read `new` and create no entry.
- **Conntrack on fragments** — no special handling; only the first
  fragment carries the L4 header that the 5-tuple needs.
- **Configurable UDP/TCP conntrack timeouts in the language** — timeouts
  live in the daemon (`fd.yaml`) and its GC, not the `.fw` surface.
- **ICMP-error translation for IPv6 / ICMPv6** — RFC 5508 covers IPv4
  only here, as all of v0.4's NAT and conntrack do.
- **Rewriting the embedded transport checksum.** An ICMP error carries
  8 bytes of the transport header, so that header's checksum covers a
  payload the error does not carry: no receiver can validate it and no
  oracle can check it, and for TCP the checksum field is not even among
  the 8 bytes. Linux's `nf_nat` skips it for the same reason.
- **Errors about a flow whose outer header carries IP options.** Every
  NAT rewrite in v0.4 bails on `ihl != 5`; an ICMP error is no
  exception. It is still classified `related` (classification walks a
  variable IHL) and so is admitted, but it stops at the firewall's own
  address.
