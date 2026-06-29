# FWL v0.4 — Language Specification (delta from v0.2)

## What v0.4 Adds

v0.4 is the stateful-foundation release. This document specifies the
v0.4 language deltas one construct at a time; each section is a
strict superset of v0.2 (docs/FWL_V02_SPEC.md). Programs written for
v0.1/v0.2/v0.3 compile unchanged.

Constructs landed in this document:

- **VLAN 802.1Q** — `pkt.vlan_id`, `pkt.vlan_priority` (this file).

Other Phase 4 constructs (TCP flags, ICMP type/code, conntrack in
the language) are tracked in `f.planning/FIREWALL_ROADMAP.md` and get
their own sections here as they land.

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

## What Is Not in v0.4 (VLAN scope)

- QinQ inner-tag parsing (only the outer tag is exposed).
- The DEI bit as a readable field.
- VLAN rewriting / pushing / popping (read-only matching only).
- `0x88A8` TPID recognition (only `0x8100` triggers VLAN parsing).
