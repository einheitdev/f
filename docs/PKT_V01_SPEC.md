# .pkt v0.1 — Test Case Format Specification

## What .pkt Is

A `.pkt` file is one test case for the FWL verification loop. It bundles a complete FWL program, an input packet, optional pre-state, and the expected outcome into a single self-contained YAML document so the test runner and the three oracles (spec, AST interpreter, BPF runtime) can execute it independently and agree.

This document specifies `.pkt` v0.1. The format is a frozen surface in the same sense as [FWL v0.1](FWL_V01_SPEC.md) — it gates the verification methodology in [F_DEVELOPMENT_METHODOLOGY.md](F_DEVELOPMENT_METHODOLOGY.md), so it cannot drift or accept ambiguous content. Future versions extend the surface; v0.1 is what's described here.

## Hello World

```yaml
name: "always-allow program returns XDP_PASS"
source_fw: |
  @xdp(eth0)
  allow

test_packet:
  builder: tcp(src_ip="1.2.3.4", dst_port=80)

expected:
  compiles: true
  bpf_action: allow
```

That's a complete v0.1 case. The runner parses `source_fw`, feeds the packet through the AST interpreter and through `BPF_PROG_TEST_RUN` (when privileges allow), and asserts both produce `XDP_PASS`.

## Document Structure

A `.pkt` file is a single YAML 1.2 document. The top-level mapping has these fields:

| Field | Type | Required | Purpose |
|---|---|---|---|
| `name` | string | yes | Short human-readable label |
| `source_fw` | string | yes | The FWL program under test |
| `test_packet` | mapping | yes | The packet input (see below) |
| `expected` | mapping | yes | What outcomes to assert |
| `state` | mapping | no | Pre-existing kernel state (e.g. rate_limit buckets) |

Unknown top-level keys are a validation error. Extra keys inside `test_packet`, `expected`, or `state` are also errors — the runner refuses to silently ignore typos.

The file extension `.pkt` is conventional, not enforced. The corpus runner discovers cases by `*.pkt` glob.

## The `test_packet` Block

Describes the packet that BPF_PROG_TEST_RUN sees and that the interpreter is evaluated against. v0.1 supports two compatible specifiers:

| Field | Type | Required | Purpose |
|---|---|---|---|
| `builder` | string | yes | Mini-language expression producing the packet |
| `truncate_to` | integer | no | If set, truncate the built packet to N bytes |

Exactly one of (`builder`) is required. `truncate_to` modifies the result of `builder` and is only valid alongside it.

### `builder`

A small expression language — **not** eval'd Python — describing how to assemble the packet. The grammar is in the [Builder Mini-Language Reference](#builder-mini-language-reference) section. Three constructors exist: `tcp(...)`, `udp(...)`, `icmp(...)`. Each accepts named arguments for IP and L4 fields; missing fields take sensible defaults (see the reference) so a corpus author only writes what matters for the test.

The output is two parallel artifacts the runner uses:

1. **Raw bytes** — a complete Ethernet + IPv4 + L4 frame, used as input to `BPF_PROG_TEST_RUN`.
2. **Decoded fields** — a dict like `{proto: "tcp", src_ip: "1.2.3.4", dst_port: 80, syn: false}`, used as input to the AST interpreter.

The two are derived from the same builder call so the oracles cannot diverge on what packet they're seeing.

### `truncate_to`

A non-negative integer N. When present, the runner cuts the raw bytes to the first N bytes after the builder produces them, and removes any decoded fields that wouldn't be readable from a packet of that length:

| `truncate_to` | Decoded fields kept |
|---|---|
| 0 | none |
| 1..13 | none (incomplete Ethernet) |
| 14..33 | none (Ethernet only — no L3 fields) |
| 34..(34 + L4 hdr - 1) | `proto`, `src_ip`, `dst_ip` only |
| ≥ 34 + L4 hdr | all fields the builder produced |

L4 header sizes: 20 (TCP), 8 (UDP), 8 (ICMP). The model assumes IHL = 5 (no IP options) in v0.1.

This exists so the corpus can verify the bounds-check fall-through paths the emitter generates without forcing corpus authors to hand-write hex.

> Status (2026-05-01): builder + truncate_to both shipped. The interpreter mirrors the BPF parser's bounds-check semantics by stripping decoded fields whose underlying bytes lie past the truncation point (see `pkt.py:_strip_truncated_fields`). The two oracles agree on every truncated frame.

## The `state` Block

Optional. Carries pre-existing kernel state the program would normally accumulate during prior packets. v0.1 has one stateful primitive (`rate_limit`), so `state` has one sub-block:

```yaml
state:
  rate_limit:
    <rule_index>:
      <bucket_key>: <count>
```

- `<rule_index>` — zero-based position of the rule in `source_fw` whose `rate_limit` modifier this state belongs to. Rules without a `rate_limit` modifier may not appear.
- `<bucket_key>` — runtime value of the modifier's `per=` field. For `per=src_ip` / `per=dst_ip` the key is a dotted-quad string (`"10.0.0.1"`); for `per=src_port` / `per=dst_port` the key is an integer.
- `<count>` — non-negative integer, the bucket's current count at the start of the test (within the 1-second window).

The runner translates this into byte-packed `bpf_map_update_elem` calls into the per-CPU rate_limit hash maps before `BPF_PROG_TEST_RUN`, so the BPF oracle and the interpreter both see the same starting bucket counts. Buckets not listed are treated as count=0.

State is consumed read-only by the test — successive runs of the same `.pkt` always start from the same state.

## The `expected` Block

Required. Describes what the runner asserts after the test executes.

| Field | Type | Default | Purpose |
|---|---|---|---|
| `compiles` | bool | `true` | Whether the program is expected to compile |
| `bpf_action` | string | — | Expected XDP action; required when `compiles: true` |
| `counter_changes` | mapping | `{}` | Per-counter expected delta after the run |
| `log_events` | sequence | `[]` | Expected log_event records, in order |

### `compiles`

When `false`, the program is expected to be rejected by the parser, the analyzer, or (rarely) the BPF verifier. The interpreter and BPF oracles both verify that compilation fails; the rest of the `expected` block is ignored. `bpf_action`, `counter_changes`, and `log_events` must not be present when `compiles: false`.

### `bpf_action`

Required when `compiles: true`. One of:

| Value | Meaning |
|---|---|
| `allow` | XDP returns `XDP_PASS` |
| `drop` | XDP returns `XDP_DROP` |
| `pass` | Synonym for `allow` |
| `none` | Synonym for `allow` (used when no rule matches) |

The interpreter and BPF oracles must both produce the same action; otherwise the case fails with both oracles' results in the diff.

### `counter_changes`

A mapping of counter name (the `<n>` in `count <n>`) to the expected delta after the test. Counters not listed are not checked. Negative deltas, missing counters, and counters whose final value differs from `start + delta` are all failures.

```yaml
expected:
  bpf_action: allow
  counter_changes:
    ssh_allowed: 1
    http_traffic: 0   # explicitly assert no increment
```

The interpreter tracks counter increments as it walks; the BPF oracle reads the per-CPU counters array before and after the test run and compares the deltas (summed across all CPUs).

> Status (2026-05-01): **deferred to v0.3** per the pre-soak hardening audit. The interpreter and emitter both produce counters; the runner does not yet read the per-CPU counter map after `BPF_PROG_TEST_RUN`. `expected.counter_changes` is silently ignored — the runner does not fail a case for missing the assertion. v0.3 ships a `_read_counter_deltas` helper alongside the existing `_build_geoip_map_init`. Until then, a `count <n>` rule's effect is verified by inspection of the emitted C and via the existing `bpf_action` agreement check.

### `log_events`

A sequence of expected log_event records emitted by `log` rules, in the order the program would emit them. Each entry is a mapping with one or more of these fields; unspecified fields are not checked:

| Field | Type | Meaning |
|---|---|---|
| `zone` | string | Name of the `@xdp` block that emitted the record (v0.4 § 6.8) |
| `rule_index` | integer | Zero-based index of the `log` rule that emitted the record, **within its zone** |
| `proto` | string | `"tcp"`, `"udp"`, or `"icmp"` |
| `src_ip` | string | Dotted quad |
| `dst_ip` | string | Dotted quad |
| `src_port` | integer | 0 if not TCP/UDP |
| `dst_port` | integer | 0 if not TCP/UDP |
| `syn` | bool | True if the SYN flag was set |
| `ack` | bool | True if the ACK flag was set |

`timestamp_ns` is intentionally excluded from comparison — it changes every run.

`rule_index` alone does not identify a rule: `fwl_log_events` is one ring buffer for a whole bundle and indices are numbered per zone, so `zone` + `rule_index` is the pair that does (v0.4 § 6.8). A field name the runner does not recognise is a failure, not a skipped assertion — a typo'd log-event field used to pass silently.

```yaml
expected:
  bpf_action: allow
  log_events:
    - rule_index: 0
      proto: tcp
      dst_port: 22
      syn: true
```

Mismatch in count (more or fewer events than expected), order, or any specified field is a failure.

> Status (2026-05-01): **deferred to v0.3** per the pre-soak hardening audit. The emitter generates ringbuf submissions; the runner does not yet drain the ringbuf after `BPF_PROG_TEST_RUN`. `expected.log_events` is silently ignored. The defer note in `counter_changes` above applies equally here: the runner needs a ringbuf-drain helper paired with `bpf_runner.run` before this assertion can fire.

## Builder Mini-Language Reference

A builder expression is one constructor call:

```
<proto>(<arg>, <arg>, ...)
```

Where `<proto>` is `tcp`, `udp`, or `icmp`, and each `<arg>` is `<name>=<value>`.

### Values

| Kind | Syntax | Example |
|---|---|---|
| Decimal integer | `[0-9]+` | `80`, `65535` |
| Hex integer | `0x[0-9a-fA-F]+` | `0xff` |
| Boolean | `true` \| `false` | `syn=true` |
| Quoted string | `"..."` | `src_ip="1.2.3.4"` |

No nested calls, no expressions, no unquoted strings. Whitespace around `=`, `,`, and `(`/`)` is ignored.

### Field tables

Per constructor, the accepted fields and their defaults:

**`tcp(...)`**

| Field | Type | Default | Notes |
|---|---|---|---|
| `src_ip` | dotted quad | `"1.1.1.1"` | |
| `dst_ip` | dotted quad | `"2.2.2.2"` | |
| `src_port` | int 0..65535 | `12345` | |
| `dst_port` | int 0..65535 | `80` | |
| `syn` | bool | `false` | |
| `ack` | bool | `false` | |

**`udp(...)`**

| Field | Type | Default | Notes |
|---|---|---|---|
| `src_ip` | dotted quad | `"1.1.1.1"` | |
| `dst_ip` | dotted quad | `"2.2.2.2"` | |
| `src_port` | int 0..65535 | `12345` | |
| `dst_port` | int 0..65535 | `53` | |

**`icmp(...)`**

| Field | Type | Default | Notes |
|---|---|---|---|
| `src_ip` | dotted quad | `"1.1.1.1"` | |
| `dst_ip` | dotted quad | `"2.2.2.2"` | |

ICMP type/code/sequence are fixed (echo request, code 0, id/seq 0) in v0.1 and not exposed as builder fields.

### Output invariants

The builder always produces:

- Ethernet frame with EtherType `0x0800` (IPv4) and fixed source/destination MAC addresses.
- IPv4 header with version 4, IHL 5, TTL 64, computed checksum, no fragmentation, no options.
- L4 header sized according to the constructor.

These invariants hold *before* `truncate_to` is applied.

## Validation Errors

The loader rejects malformed `.pkt` files with a clear error. v0.1 errors:

| Condition | Error |
|---|---|
| Top-level YAML is not a mapping | `error: .pkt root must be a YAML mapping` |
| Required field missing | `error: missing required field '<name>'` |
| Unknown top-level field | `error: unknown field '<name>' at top level` |
| Builder syntax invalid | `error: unrecognized builder expression: <text>` |
| Builder argument missing `=` | `error: builder argument missing '=': <text>` |
| Builder value not int/bool/string | `error: unrecognized builder value: <text>` |
| Builder field not in the constructor's table | `error: unknown <proto> field '<name>'` |
| Builder field value out of range | `error: <field>: <value> out of range` |
| `truncate_to` negative | `error: truncate_to must be ≥ 0` |
| `state.rate_limit` references rule index without a modifier | `error: rule <idx> has no rate_limit modifier` |
| `expected.bpf_action` unknown value | `error: unknown bpf_action '<value>'` |
| `expected.bpf_action` present with `compiles: false` | `error: bpf_action must not appear when compiles: false` |
| `expected.counter_changes` references unknown counter | `error: counter '<name>' not declared in source_fw` |

> Status (2026-04-25): the loader currently produces ad-hoc Python exceptions for some of these. Spec-conformance work in `pkt.py` is open.

## Examples

### Pass case with a guard

```yaml
name: "allow tcp dst_port 22 (with proto guard) matches ssh"
source_fw: |
  @xdp(eth0)
  allow if pkt.proto == tcp and pkt.dst_port == 22
  default drop

test_packet:
  builder: tcp(src_port=12345, dst_port=22)

expected:
  compiles: true
  bpf_action: allow
```

### Compile-failure case

```yaml
name: "pkt.dst_port without proto guard is rejected"
source_fw: |
  @xdp(eth0)
  allow if pkt.dst_port == 80

test_packet:
  builder: tcp(dst_port=80)

expected:
  compiles: false
```

### Rate-limit with pre-state

```yaml
name: "rate_limit fires while bucket is below threshold"
source_fw: |
  @xdp(eth0)
  drop if pkt.proto == tcp and pkt.dst_port == 22
       limited by rate_limit(10, per=src_ip)
  default allow

state:
  rate_limit:
    0:
      "1.2.3.4": 5

test_packet:
  builder: tcp(src_ip="1.2.3.4", dst_port=22)

expected:
  compiles: true
  bpf_action: drop
```

### Counter delta assertion

```yaml
name: "count ssh_allowed increments on a TCP/22 packet"
source_fw: |
  @xdp(eth0)
  count ssh_allowed if pkt.proto == tcp and pkt.dst_port == 22
  allow if pkt.proto == tcp and pkt.dst_port == 22
  default drop

test_packet:
  builder: tcp(dst_port=22)

expected:
  compiles: true
  bpf_action: allow
  counter_changes:
    ssh_allowed: 1
```

### Log event assertion

```yaml
name: "log fires once per matching SYN"
source_fw: |
  @xdp(eth0)
  log if pkt.proto == tcp and pkt.tcp.syn
  allow if pkt.proto == tcp
  default drop

test_packet:
  builder: tcp(src_ip="1.2.3.4", dst_port=22, syn=true)

expected:
  compiles: true
  bpf_action: allow
  log_events:
    - rule_index: 0
      proto: tcp
      src_ip: "1.2.3.4"
      dst_port: 22
      syn: true
      ack: false
```

### Truncated packet falling through to default

```yaml
name: "truncated TCP packet doesn't match dst_port rule"
source_fw: |
  @xdp(eth0)
  drop if pkt.proto == tcp and pkt.dst_port == 22
  default allow

test_packet:
  builder: tcp(dst_port=22)
  truncate_to: 34   # cut at end of IP header

expected:
  compiles: true
  bpf_action: allow   # bounds check fails => rule doesn't match => default
```

## Implementation Status

| Area | Status (2026-04-25) |
|---|---|
| YAML loader, `name`/`source_fw`/`test_packet`/`expected`/`state` parsing | shipped (`fwl/pkt.py`) |
| Builder mini-language: `tcp`, `udp`, `icmp` with int/bool/string args | shipped |
| Builder defaults | shipped |
| `state.rate_limit` decoding | shipped |
| Per-CPU map pre-population from state | shipped (`fwl/bpf_runner.py`) |
| `expected.compiles` semantics | shipped |
| `expected.bpf_action` semantics | shipped |
| `truncate_to` | spec-only — not yet in loader |
| `expected.counter_changes` | spec-only — runner does not read counters yet |
| `expected.log_events` | spec-only — runner does not drain ringbuf yet |
| Strict validation errors per the table above | partial — some are Python exceptions |

This table is the source of truth for what works today. Anything marked spec-only-pending will fail with a load-time error or be silently ignored by the current runner; do not write corpus cases relying on it until those rows flip to "shipped."

## What Is Not in v0.1

Restating the deferred list for clarity:

- **Multi-packet sequences** — only one packet per case in v0.1. Testing rate_limit accumulation across many packets requires running multiple `.pkt` cases or stateful chaining, both deferred.
- **Raw-byte packets** — `raw_bytes:` for fully custom (non-IPv4, IPv6, ARP, malformed) packets. Truncation covers most needs; full raw bytes deferred to v0.2.
- **Verifier expectations** — assertions on the kernel BPF verifier's behavior beyond accept/reject (e.g., max instruction count, register pressure).
- **IPv6 builders** — out of scope until FWL has IPv6 fields.
- **TCP options, IP options** — fixed IHL=5, no TCP options in builder output.
- **TCP flags beyond syn/ack** — match FWL v0.1 surface.
- **ICMP type/code customization** — fixed echo-request in v0.1.
- **Custom Ethernet headers** — fixed source/destination MAC addresses.
- **Per-CPU breakdown of counter_changes** — counter_changes asserts the summed-across-all-CPUs delta only.
- **Ordering tolerance for log_events** — the spec requires exact order.
- **Numeric/regex matching in expected** — only exact equality for action/counter/log fields.

## Schema (Reference)

A YAML/JSON schema sketch for the v0.1 surface, for tooling. The grammar is informal; the spec text above is authoritative.

```yaml
type: object
required: [name, source_fw, test_packet, expected]
additionalProperties: false
properties:
  name:
    type: string
  source_fw:
    type: string
  test_packet:
    type: object
    required: [builder]
    additionalProperties: false
    properties:
      builder:
        type: string
        pattern: '^\s*(tcp|udp|icmp)\s*\(.*\)\s*$'
      truncate_to:
        type: integer
        minimum: 0
  state:
    type: object
    additionalProperties: false
    properties:
      rate_limit:
        type: object
        # Keys are rule indices (integers serialized as YAML keys)
        additionalProperties:
          type: object
          # Keys are bucket values (string for IP, integer for port)
          additionalProperties:
            type: integer
            minimum: 0
  expected:
    type: object
    additionalProperties: false
    properties:
      compiles:
        type: boolean
        default: true
      bpf_action:
        type: string
        enum: [allow, drop, pass, none]
      counter_changes:
        type: object
        additionalProperties:
          type: integer
      log_events:
        type: array
        items:
          type: object
          additionalProperties: false
          properties:
            zone: {type: string}
            rule_index: {type: integer, minimum: 0}
            proto: {type: string, enum: [tcp, udp, icmp]}
            src_ip: {type: string}
            dst_ip: {type: string}
            src_port: {type: integer, minimum: 0, maximum: 65535}
            dst_port: {type: integer, minimum: 0, maximum: 65535}
            syn: {type: boolean}
            ack: {type: boolean}
```

## Summary

A `.pkt` file is one self-contained test case: the FWL program, an input packet, optional pre-state, and the expected outcome. v0.1 supports the YAML structure shipped today plus three planned additions — `truncate_to`, `counter_changes`, and `log_events` — that close the verification gaps the current runner can't yet assert. The builder mini-language stays parsed-not-eval'd so AI-generated corpus content is safe to load.

The bar for accepting a `.pkt` into the corpus is that all three oracles (spec, AST interpreter, BPF runtime) agree on the outcome the file declares. Anything else is a bug in the spec, the loader, the interpreter, or the emitter — and the verification methodology says to find out which.
