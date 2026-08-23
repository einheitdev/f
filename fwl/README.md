# FWL — Firewall Language

`fwl` is the compiler for the Firewall Language at the heart of `f`. It takes a `.fw` source file describing policy and produces verifier-accepted XDP/eBPF programs that run at line rate in the kernel.

The language reference is [`docs/FWL_V04_SPEC.md`](../docs/FWL_V04_SPEC.md); the build methodology is [`docs/F_DEVELOPMENT_METHODOLOGY.md`](../docs/F_DEVELOPMENT_METHODOLOGY.md). For using the language rather than working on it, start at [`docs/fwl/`](../docs/fwl/).

**Status: v0.4 surface complete.** 2238 unit tests and 1291 corpus cases pass. On a host with `CAP_BPF` (or root) every behavioral corpus case runs through `BPF_PROG_TEST_RUN`; unprivileged, the BPF oracle skips cleanly while spec, interpreter and clang-compile still gate regressions. That skip matters — see "Verification model".

## Install

```sh
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
```

Requires Python 3.11+, clang (for BPF compilation), and libbpf 1.x (only when loading programs into the kernel via `fwl test` on a real host).

## Quick start

```sh
cat > my.fw <<'POLICY'
zone lan = [lan0]
zone wan = [wan0]

@xdp(wan)

count wan_total
allow if conntrack(pkt).state == established
drop limited by rate_limit(2000, per=src_ip)
default drop

@xdp(lan)

masquerade
redirect to wan
POLICY

fwl parse my.fw        # print the AST
fwl check my.fw        # parse + semantic check, no codegen
fwl compile my.fw      # emit BPF C to stdout
fwl compile --bundle out/ my.fw   # per-zone objects + manifest
fwl test tests/corpus/ # run the corpus
```

## What v0.4 supports

- **Zones** — `zone <name> = [iface, ...]`, one `@xdp(<zone>)` block per zone, `redirect to <zone>` via devmap, `pkt.zone` readable in a condition.
- **Actions** — `allow`, `drop` (terminal); `log`, `count <name>` (non-terminal); `masquerade`, `snat to <ip>`, `dnat to <ip>:<port>`.
- **Fields** — `pkt.proto`, `pkt.{src,dst}_ip`, `pkt.{src,dst}_ip6`, `pkt.{src,dst}_port`, all eight TCP flags, `pkt.icmp.{type,code}`, `pkt.icmp6.{type,code}`, VLAN, `pkt.zone`.
- **Stateful** — `conntrack(pkt).state`, and `rate_limit(N, per=<field>[, scope=zone|global])` as a Tier 1 `limited by` modifier or a Tier 2 condition.
- **`geoip(CC, ...)`** — country matching against a compiled LPM trie shipped in the bundle.
- **Tables** — `table <name> { kind = cidr4|cidr6  max = <n>  source = "<path>" }`, matched with the ordinary `in`. One LPM lookup whatever the prefix count, so a 50,000-entry blocklist costs what an empty policy costs; the same list as rules is a linear chain that runs at 12% of line rate by 2,000 of them. `table <alias> = <target>` gives one table a second name so a pasted block keeps its own vocabulary. Disk-authoritative: `source` is a path on the **appliance**, the bundle carries the declaration and not one prefix, and `fd` reads the file at load — refusing the load rather than arming a datapath whose blocklist is empty. The map is `MapLifetime.EXTERNAL`, so a policy edit does not discard it, and every load reconciles it against the file by diff rather than by clear-and-refill.
- **Tier 2** — a `def <name>(pkt):` body replacing the rule sequence, with locals, `if`/`elif`/`else` and early exit, plus helper `def`s callable from more than one zone as real BPF-to-BPF calls.

A zone is *either* a Tier 1 rule sequence or a Tier 2 body, never both. Tier 3 raw-C `inline_c` is excluded by design, not merely unbuilt.

## Three things the compiler does that the language does not show

**Pipeline splitting** (`splitter.py`). A program that would exceed the verifier's instruction budget is split into a tail-call chain inside one object. The author never sees it, and the interpreter models the un-split program — so a split that changed behaviour surfaces as an oracle disagreement rather than a silent difference in the kernel.

**Map scope and lifetime, which are orthogonal.** *Scope* asks whether two zones may share a map; *lifetime* asks whether a previous compilation's contents may be inherited. Conntrack is SHARED and FLOW — an established connection is a fact about the wire, not about the policy that admitted it, so discarding it on reload drops every live connection. Counters, log-sampling phases and rate-limit buckets are PRIVATE and POLICY — sized or indexed by one compilation's analysis, so an adopted pin reports a dead policy's numbers against live rules. This is a typed registry (`_MAP_KINDS`), and the emitter **refuses to emit a map nobody classified**: silence used to mean "share it", which is how a per-zone map ended up pinned under a bundle-global name three separate times.

**Rule metadata and the log ABI** (`rulemeta.py`, `log_abi.py`). The daemon never sees policy text, so each zone's analyzed rule list goes into `manifest.json` beside its object — that is what lets an operator ask what the box is enforcing without reading a file and hoping it matches. And because one ring buffer is shared bundle-wide while rule indices are numbered per zone, every log record carries its emitting zone: `(zone_id, rule_index)` is the identity of a logged rule, and both halves of that ABI are stated once in `log_abi.py`.

## Verification model

Every construct is verified against three independent oracles before it ships:

1. **Spec** — the `.pkt` case's declared expectation, reviewed at authoring time.
2. **AST interpreter** — `interpreter.py` walks the parsed AST against a decoded packet. It shares only the AST node definitions with the emitter, so a disagreement diagnoses a real compiler bug.
3. **BPF runtime** — `bpf_runner.py` compiles via `clang -target bpf`, loads via libbpf, pre-populates rate-limit, conntrack, NAT and geoip maps from the case's `state:` block, and runs `BPF_PROG_TEST_RUN`.

**Three oracles agreeing is weaker evidence than it looks, and it has failed here.** Until 2026-08-19 a Tier 2 `rate_limit(...)` emitted a constant false — and the interpreter modelled it the same way. Both were wrong in the same direction, so every differential test agreed with itself and passed, and no corpus case combined `def` with `rate_limit` at all. It took a 96-hour gateway soak on real hardware, flooding the Tier 1 and Tier 2 forms side by side, to see it.

Three consequences worth carrying:

- Agreement proves the oracles are not *independently* wrong. A shared assumption survives it. When adding a construct, ask what case would exist only if the feature were genuinely absent — and write that one.
- **Sequences beat single packets for anything stateful.** One packet cannot distinguish a limiter from a lookup; it only proves the seeded value was read. The interpreter therefore *writes* buckets and conntrack entries as it goes, modelling the emitted program's per-packet update, because an oracle that only reads is structurally incapable of noticing that a counter never climbed.
- **The BPF oracle skips silently without root**, and it is the only one that catches a verifier rejection or a map-layout mismatch. A green corpus run unprivileged is materially weaker than one with `sudo`.

The corpus under `tests/corpus/` is organized by construct and by lifecycle:

```
00_smoke  01_proto_match  02_multi_rule_default  03_fields_composition
05_rate_limit  06_log_count  07_edge_cases  08_ipv6_fields  09_geoip
10_tier2_functions  11_counter_changes  11_tcp_flags  11_zones
12_icmp_fields  12_log_events  13_conntrack  14_nat  15_pipeline
16_multidef  17_nat_lifecycle  18_conntrack_lifecycle
19_rate_limit_lifecycle  20_zone_dispatch  21_truncation
22_rate_limit_overflow  23_nat_edges  24_nat_conntrack  25_ethertype
25_local_delivery  26_near_miss  27_tables
```

The `*_lifecycle` groups are multi-packet sequences; `26_near_miss` holds cases that should *not* match, which is the half a corpus of positive examples never covers.

```sh
fwl test tests/corpus/                # interpreter + clang-compile
sudo .venv/bin/fwl test tests/corpus/ # add live BPF_PROG_TEST_RUN
.venv/bin/python -m pytest tests/unit/
```

**One known flake.** The emitted limiter forgets a bucket older than one second. A multi-packet rate-limit sequence that straddles that boundary resets mid-case, and only the BPF oracle sees it — the interpreter models no window expiry, because `BPF_PROG_TEST_RUN` normally replays a sequence in microseconds. On a loaded machine that assumption can break. A red `19_rate_limit_lifecycle` case that passes on a retry is this, not a compiler bug.

## .pkt format

A test case is a YAML document; the grammar is [`docs/PKT_V02_SPEC.md`](../docs/PKT_V02_SPEC.md).

```yaml
name: "rate_limit fires once the bucket reaches the threshold"
source_fw: |
  @xdp(eth0)
  drop if pkt.proto == tcp and pkt.dst_port == 22
       limited by rate_limit(10, per=src_ip)
  default allow

# Keyed by rule index for a Tier 1 modifier, by rate_limit call index
# for a Tier 2 condition.
state:
  rate_limit:
    0:
      "1.2.3.4": 10

test_packet:
  builder: tcp(src_ip="1.2.3.4", dst_port=22)

expected:
  compiles: true
  bpf_action: drop
```

Top-level keys: `name`, `source_fw`, `test_packet`, `expected`, `state`, `geoip_data`, `table_data` (a table name to its CIDR list, mirroring the bundle payload), `ingress_zone` (which `@xdp` block the packet arrives on), and `sequence` for a multi-packet case — mutually exclusive with the single `test_packet`/`expected` pair.

`state:` carries `rate_limit` buckets, a `conntrack` seed, and `nat` (masquerade address plus pre-seeded reply mappings). `expected:` carries `compiles`, `bpf_action`, `counter_changes`, `log_events`, `redirect_zone`, `output_packet` (header fields after a NAT rewrite, checked by both oracles), and the load-time `loads`/`load_action`/`load_error_pattern`.

Builders: `tcp`, `udp`, `icmp` and the v6 forms `tcp6`, `udp6`, `icmp6`, each accepting an optional VLAN tag, plus `truncate_to` for short frames. The builder mini-language is parsed, not `eval`'d — corpus content can be generated by an agent without RCE risk.

## Directory layout

```
fwl/fwl/
  ast.py              AST dataclasses
  parser.py           Lark LALR + transformer
  analyzer.py         Semantic passes: protocol guards, Tier 2 dominance,
                        stack budget, call-index assignment
  interpreter.py      AST oracle, including the stateful models
  emitter.py          BPF C generation, map scope/lifetime registry
  splitter.py         Verifier-budget estimation and pipeline planning
  rulemeta.py         Per-zone rule metadata for the bundle manifest
  log_abi.py          The fwl_log_events record layout, C and Python
  iso3166.py          Country-code table for geoip()
  pkt.py              .pkt loader + packet builder mini-language
  bpf_runner.py       clang + libbpf BPF_PROG_TEST_RUN harness
  runner.py           Three-oracle test harness
  cli.py              Click CLI
  errors.py           Source-spanned error types
  grammar.lark        Grammar reference
fwl/examples/         ssh_brute_force, web_server_ddos, internal_network,
                      v6_internal, geoip_block, blocklist_table,
                      storm_shield, dogfood_v02, dogfood_v03
  feeds/              Sample table source files the examples read
fwl/tests/
  corpus/             1291 .pkt cases
  unit/               2238 pytest tests
```
