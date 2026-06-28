# .pkt v0.2 — Test Case Format Specification

## What .pkt v0.2 Is

A `.pkt` v0.2 file is one test case for the FWL v0.2 verification
loop. It is a strict superset of [v0.1](PKT_V01_SPEC.md) — every v0.1
case is a valid v0.2 case with identical semantics — plus three
additions for the three v0.2 constructs:

1. **`tcp6(...)`, `udp6(...)`, `icmp6(...)` builders** — IPv6
   counterparts of the v0.1 `tcp/udp/icmp` builders, producing
   Ethernet (EtherType `0x86DD`) + IPv6 fixed header + L4 frames.
2. **`truncate_to` table extended for IPv6.** The bookkeeping table
   in v0.1 §"`truncate_to`" is augmented with the 14 + 40 = 54-byte
   L3 boundary for IPv6 frames.
3. **`expected.load_action`** — a new sub-field that asserts the
   daemon's behaviour at bundle-attach time, used to test the
   `geoip.json`-missing path that's specific to v0.2.

All other surface (the `name`/`source_fw`/`test_packet`/`expected`/
`state` shape, the `state.rate_limit` decoding, the `expected
.compiles`/`bpf_action`/`counter_changes`/`log_events` fields)
remains identical to v0.1.

This document specifies only the deltas. For every field not
mentioned here, the v0.1 spec is authoritative.

## Hello World (v0.2)

A v0.2 case targeting an IPv6 program:

```yaml
name: "v6 internal /48 allows traffic from 2001:db8:cafe::1"
source_fw: |
  @xdp(eth0)
  allow if pkt.src_ip6 in 2001:db8:cafe::/48
  default drop

test_packet:
  builder: tcp6(src_ip="2001:db8:cafe::1", dst_port=80)

expected:
  compiles: true
  bpf_action: allow
```

## Builder Mini-Language Reference (delta)

The grammar of a builder expression is unchanged: `<proto>(<arg>,
<arg>, ...)`. v0.2 adds three new constructors:

### `tcp6(...)`

Produces an Ethernet (EtherType `0x86DD`) + IPv6 fixed header + TCP
frame. No extension headers in the default output (see
"Output invariants" below).

| Field | Type | Default | Notes |
|---|---|---|---|
| `src_ip` | RFC 5952 ipv6 string | `"2001:db8::1"` | The address half of the IPv6 source field. |
| `dst_ip` | RFC 5952 ipv6 string | `"2001:db8::2"` | The address half of the IPv6 destination field. |
| `src_port` | int 0..65535 | `12345` | TCP source port. |
| `dst_port` | int 0..65535 | `80` | TCP destination port. |
| `syn` | bool | `false` | TCP SYN flag. |
| `ack` | bool | `false` | TCP ACK flag. |

Note: the `src_ip`/`dst_ip` field names are reused for symmetry with
the IPv4 builders; the values are IPv6 strings, so the type is
unambiguous to the loader. `src_ip6` and `dst_ip6` are not separate
fields on the IPv6 builders — using either spelling on a `tcp6`
builder is a load error.

### `udp6(...)`

Produces an Ethernet + IPv6 + UDP frame.

| Field | Type | Default | Notes |
|---|---|---|---|
| `src_ip` | RFC 5952 ipv6 string | `"2001:db8::1"` | |
| `dst_ip` | RFC 5952 ipv6 string | `"2001:db8::2"` | |
| `src_port` | int 0..65535 | `12345` | |
| `dst_port` | int 0..65535 | `53` | |

### `icmp6(...)`

Produces an Ethernet + IPv6 + ICMPv6 frame. ICMPv6 uses Next-Header
`58` (not `1` like IPv4 ICMP).

| Field | Type | Default | Notes |
|---|---|---|---|
| `src_ip` | RFC 5952 ipv6 string | `"2001:db8::1"` | |
| `dst_ip` | RFC 5952 ipv6 string | `"2001:db8::2"` | |

ICMPv6 type/code/sequence are fixed (Echo Request, type 128, code 0,
id 0, sequence 0) in v0.2 and not exposed as builder fields. v0.3 may
parameterise them.

### Decoded fields produced

The builder produces the same two artifacts as in v0.1: raw bytes for
`BPF_PROG_TEST_RUN` and a decoded fields dict for the AST
interpreter. For IPv6 builders, the decoded dict is keyed under
the new `src_ip6`/`dst_ip6` names so the interpreter never confuses
v4 and v6 addresses:

```python
# tcp6(src_ip="2001:db8::1", dst_port=80, syn=true) decodes to:
{
  "ether_type": 0x86DD,
  "proto": "tcp",          # wire-level next_header == 6
  "src_ip6": "2001:db8::1",
  "dst_ip6": "2001:db8::2",
  "src_port": 12345,
  "dst_port": 80,
  "syn": True,
  "ack": False,
}
```

The IPv4 builders' decoded dict is unchanged (`src_ip` / `dst_ip` remain the v4 keys). Two builders never produce the same v4-key set — so a rule referencing `pkt.src_ip` against an IPv6-builder packet finds the field absent and falls through, matching the spec's cross-family rule.

**Interpreter access to v6-builder decoded fields is gated by FWL_V02's v6-surface activation rule** (`FWL_V02_SPEC.md` §"Compilation"). The decoded dict above is the *wire-level truth* of the packet — `proto: "tcp"` correctly reflects the IPv6 fixed header's `next_header` byte, the `src_port`/`dst_port` keys correctly reflect the TCP header — but reading those fields through `pkt.<field>` from the AST interpreter must follow the same activation rule the BPF emitter uses:

- For a program **touching IPv6 fields** (any of `pkt.src_ip6`, `pkt.dst_ip6`, `pkt.proto == icmp6`, or a `geoip(...)` whose LHS has type `ipv6`), the interpreter reads the v6-builder decoded dict directly and `pkt.proto == tcp` matches v6 TCP packets.
- For a program **not touching IPv6 fields** (a v0.1-shaped program), the interpreter must treat every read of `pkt.proto`, `pkt.src_port`, `pkt.dst_port`, `pkt.tcp.syn`, `pkt.tcp.ack`, `pkt.src_ip`, `pkt.dst_ip` against a v6-builder packet as **unreadable** (the v6 parse path is inactive in the BPF emitter; the rule falls through, identical to BPF behaviour). The v6-only keys `src_ip6`/`dst_ip6` are already absent from the v0.1 surface, so the interpreter naturally falls through any rule referencing them — but the v0.1-shaped fields above need explicit gating so the AST interpreter and BPF runtime stay in agreement.

This rule is what preserves the v0.1 strict-superset guarantee at the language level: an unmodified v0.1 program produces identical interpreter and BPF verdicts on every test packet, including v6 packets, exactly as in v0.1.

### Output invariants

A v0.2 IPv6 builder always produces:

- Ethernet frame with EtherType `0x86DD` (IPv6) and fixed source /
  destination MAC addresses (the same fixed MACs the v0.1 IPv4
  builders use).
- IPv6 fixed header with version 6, traffic class 0, flow label 0,
  payload length set from the L4 length, hop limit 64, and the
  Next-Header field set to the L4 protocol (`6` TCP, `17` UDP,
  `58` ICMPv6). **No extension headers** in the default output.
- L4 header sized according to the constructor (TCP = 20, UDP = 8,
  ICMPv6 = 8).

Total default frame size: 14 (Ethernet) + 40 (IPv6) + L4 = 74
(`tcp6`), 62 (`udp6`), 62 (`icmp6`). These are the lengths
`truncate_to` reasons against (next section).

These invariants hold *before* `truncate_to` is applied.

The v0.1 IPv4 builders are unchanged.

## `truncate_to` (delta)

The v0.1 `truncate_to` table assumed IPv4 (14-byte L2 + 20-byte L3).
For v0.2 it must distinguish v4 from v6 because the L3 header sizes
differ. The runner inspects the builder constructor to decide which
table applies:

### IPv4 builders (unchanged from v0.1)

| `truncate_to` | Decoded fields kept |
|---|---|
| 0..13 | none (Ethernet incomplete) |
| 14..33 | none (Ethernet only — L3 unreadable) |
| 34..(34 + L4 hdr - 1) | `proto`, `src_ip`, `dst_ip` only |
| ≥ 34 + L4 hdr | all decoded fields |

### IPv6 builders (new in v0.2)

| `truncate_to` | Decoded fields kept |
|---|---|
| 0..13 | none (Ethernet incomplete) |
| 14..53 | none (Ethernet only — IPv6 fixed header unreadable) |
| 54..(54 + L4 hdr - 1) | `proto`, `src_ip6`, `dst_ip6` only |
| ≥ 54 + L4 hdr | all decoded fields |

L4 header sizes for v6: 20 (TCP), 8 (UDP), 8 (ICMPv6).

The model assumes no IPv6 extension headers (matching the default
builder output). A v0.3 may extend the table for `--with-ext-hdr`
builder modes.

### Worked examples

```yaml
name: "tcp6 truncated to 40 bytes (Ethernet only) — no L3 readable"
source_fw: |
  @xdp(eth0)
  drop if pkt.src_ip6 in ::/0
  default allow

test_packet:
  builder: tcp6(src_ip="2001:db8::1")
  truncate_to: 40

expected:
  compiles: true
  bpf_action: allow   # 40 < 54: src_ip6 unreadable; rule falls through
```

```yaml
name: "tcp6 truncated to 54 bytes — L3 readable, L4 not"
source_fw: |
  @xdp(eth0)
  drop if pkt.src_ip6 == 2001:db8::1
  default allow

test_packet:
  builder: tcp6(src_ip="2001:db8::1", dst_port=22)
  truncate_to: 54

expected:
  compiles: true
  bpf_action: drop   # src_ip6 readable; matches /128
```

```yaml
name: "tcp6 truncated to 54 bytes — L4 not readable"
source_fw: |
  @xdp(eth0)
  drop if pkt.proto == tcp and pkt.dst_port == 22
  default allow

test_packet:
  builder: tcp6(src_ip="2001:db8::1", dst_port=22)
  truncate_to: 54

expected:
  compiles: true
  bpf_action: allow   # dst_port unreadable -> rule falls through
```

> Status (2026-05-01): `truncate_to` was spec-only at the v0.1
> snapshot per `f/docs/PKT_V01_SPEC.md`'s status table. The IPv6
> additions inherit that status — v0.2 work in `pkt.py`/`runner.py`
> implements both at once.

## `expected.load_action` (new in v0.2)

The `geoip.json`-missing case requires asserting the daemon's
load-time behaviour, not the BPF action. v0.2 adds an optional
`load_action` field inside `expected`:

| Field | Type | Default | Purpose |
|---|---|---|---|
| `load_action` | string | `attach` | Expected daemon behaviour when attaching the bundle |

Values:

| Value | Meaning |
|---|---|
| `attach` | Daemon attaches the bundle; XDP swap succeeds. (Default; matches v0.1 behaviour.) |
| `refuse` | Daemon refuses the bundle; XDP swap does not happen. The bundle's `manifest.json` is consulted but the program is not loaded. |

When `load_action: refuse`, `bpf_action` and `counter_changes` and
`log_events` must not be present (the program never runs).
`compiles: true` is still required — the source compiles cleanly; the
failure is at attach time, not compile time.

The runner enforces:

- For `attach` (or default): exactly the v0.1 semantics. The runner
  loads the bundle, runs `BPF_PROG_TEST_RUN`, and compares the
  result to `bpf_action`.
- For `refuse`: the runner loads the bundle and asserts the load
  fails. The exact error text is matched against an optional
  `load_error_pattern` regex; if not given, any non-empty error text
  satisfies the assertion.

Example:

```yaml
name: "geoip.json missing -> daemon refuses bundle"
source_fw: |
  @xdp(eth0)
  drop if pkt.src_ip in geoip(RU)
  default allow

test_packet:
  builder: tcp(src_ip="5.8.0.1", dst_port=80)

expected:
  compiles: true
  load_action: refuse
  load_error_pattern: "missing required geoip\\.json"

# Note: no bpf_action, no counter_changes — program never runs.
```

> Status (2026-05-01): the load-time refusal path requires
> `fd`/runner co-operation that lands during the geoip
> implementation. Cases marked `load_action: refuse` will not run
> until the runner gains the field; mark them
> `pattern_tags: [v0.2-pending]` until then so the regression run
> doesn't trip on them.

## Validation Errors (delta)

The v0.1 error table extends with v0.2 entries:

| Condition | Error |
|---|---|
| Builder `tcp6`/`udp6`/`icmp6` field name unknown | `error: unknown <proto> field '<name>'` (same shape as v0.1) |
| IPv6 builder field with non-canonical RFC 5952 form | `error: builder <field>: '<value>' must be RFC 5952 canonical IPv6` |
| Mixing `src_ip`/`dst_ip` with `src_ip6`/`dst_ip6` keywords on the same constructor | `error: builder field '<name>' is not in <proto>'s field table` |
| `truncate_to` value applied to an IPv6 builder using the v4 table boundaries | (no error; the runner picks the right table by the builder type) |
| `expected.load_action` with an unknown value | `error: unknown load_action '<value>'` |
| `expected.bpf_action` present alongside `load_action: refuse` | `error: bpf_action must not appear when load_action: refuse` |
| `expected.load_error_pattern` not a valid regex | `error: load_error_pattern is not a valid Python regex: <text>` |
| `expected.load_error_pattern` present without `load_action: refuse` | `error: load_error_pattern requires load_action: refuse` |

The v0.1 error rows remain unchanged.

## Schema (delta from v0.1)

The JSON-schema sketch from v0.1 grows two additions inside the
`expected` object:

```yaml
expected:
  type: object
  additionalProperties: false
  properties:
    compiles: {type: boolean, default: true}
    bpf_action: {type: string, enum: [allow, drop, pass, none]}
    load_action: {type: string, enum: [attach, refuse], default: attach}
    load_error_pattern: {type: string}
    counter_changes:
      type: object
      additionalProperties: {type: integer}
    log_events:
      type: array
      # ...same as v0.1...
```

The `test_packet.builder` regex extends to accept the new
constructor names:

```yaml
builder:
  type: string
  pattern: '^\s*(tcp|udp|icmp|tcp6|udp6|icmp6)\s*\(.*\)\s*$'
```

All other top-level/sub-object keys keep their v0.1 shape.

## What Is Not in v0.2 (delta)

Restating the .pkt deferral list with v0.2 additions:

- **Multi-packet sequences** — still one packet per case.
- **Raw-byte packets** — still deferred. Truncation covers the
  bounds-check fall-through cases for both v4 and v6.
- **IPv6 extension headers in builder output** — fixed-header only
  in v0.2; v0.3 may add `tcp6_with_ext(...)` or a generic
  `extensions=[hop_by_hop, fragment]` parameter. Cases that need to
  test the spec's "ext-hdr packet has unreadable L4" rule must
  hand-craft the bytes via raw-byte support, deferred to v0.3.
- **ICMPv6 type/code customization** — fixed Echo Request in v0.2.
- **IPv4-mapped IPv6 addresses in v4 builders** — `src_ip` on a
  `tcp(...)` builder must be a dotted quad; an IPv6-mapped quad is
  not valid input. Use `tcp6(...)` with an IPv6-mapped address
  (`::ffff:1.2.3.4`) when testing IPv4-mapped semantics.
- **Custom Ethernet headers, VLAN tags, double-tagging** — fixed
  MACs and EtherType.
- **`load_action: <other>`** — only `attach` and `refuse` exist in
  v0.2. v0.3 may add `partial_attach` for split bundles.

## Implementation Status (delta)

| Area | Status (2026-05-01) |
|---|---|
| `tcp6`, `udp6`, `icmp6` builder constructors | spec-only — implementation lands during Construct 1 |
| IPv6 `truncate_to` table | spec-only — co-implements with `tcp6/udp6/icmp6` |
| `expected.load_action` `attach` (default) | spec-only — runner already attaches; the field merely makes the assertion explicit |
| `expected.load_action` `refuse` | spec-only — implementation lands during Construct 2 (`geoip()`) |
| `expected.load_error_pattern` | spec-only — same dependency as `load_action: refuse` |

Cases that exercise unimplemented rows above must carry a
`pattern_tags: [v0.2-pending]` annotation so `hone regress` can
quarantine them until the row flips to "shipped." When a row ships,
the corresponding cases lose the annotation in the same PR.

## Summary

`.pkt` v0.2 keeps the v0.1 surface and adds three new builders, an
extended `truncate_to` table for IPv6 frames, and a `load_action`
field for asserting bundle-attach behaviour. Every v0.1 case loads
and runs unchanged; v0.2 cases that exercise IPv6 or geoip use the
new pieces. The verification methodology — three oracles, all must
agree — is unchanged.
