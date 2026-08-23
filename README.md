# f

An eBPF/XDP firewall built around a small declarative language. Policy is written in FWL, compiled to verifier-accepted BPF, and loaded into the kernel without dropping a packet or an established connection. A daemon owns the datapath, a Junos-style CLI owns the configuration, and a web dashboard reads both.

On a 200 EUR SoC board it forwards 10 GbE at line rate in both directions at once and keeps the management plane responsive while doing it — 19.4 Gb/s bidirectional, more than a $899 appliance running pfSense on the same test. Measured against RFC 2544, not estimated. See [Performance](#performance).

## How It Works

`f` runs as a userspace daemon (`fd`) that loads an XDP program onto network interfaces. Packets are filtered at the earliest point in the kernel networking stack — before socket allocation, before iptables, before the kernel builds an `sk_buff`.

Policy does not live in a rule table that userspace edits. A `.fw` source file is compiled to a bundle — one BPF object per zone plus a manifest — and reloading means loading the new objects and replacing the running ones interface by interface with `XDP_FLAGS_REPLACE`. A policy change is therefore a compile step with real diagnostics, not a sequence of map writes that can half-apply.

Maps are classified by whether their contents outlive the policy that created them. Flow-keyed state (conntrack, NAT) is inherited across the swap, because an established connection is a fact about the wire rather than about the policy that admitted it. Anything sized or indexed by one compilation's analysis (counters, rate-limit buckets, log sampling) is replaced with it.

The path a packet takes is short and fixed: parse, de-NAT, the zone's rules, NAT, verdict. Everything else — the operator CLI, the dashboard, the file watcher that recompiles on change — talks to the daemon over its control socket and never touches a BPF map.

## Features

- **XDP packet filtering** — one compiled BPF program per zone, connection tracking, NAT, per-source rate limiting
- **Zero-loss hot reload** — a new bundle replaces the running one interface by interface (`XDP_FLAGS_REPLACE`); flow-keyed state survives the policy change
- **Refuses rather than pretends** — a bundle that attaches to no interface, and a box with no bundle staged, are both a daemon that does not start
- **ZMQ control protocol** — `[1B Cmd][payload]`, JSON reply, at `ipc:///run/f/control.sock`
- **Operator CLI and web dashboard** — `einheit-f` and `einheit-f-ui`, both reading the daemon
- **FWL compiler** — small declarative language that compiles to verifier-accepted BPF C, verified construct-by-construct against three independent oracles

## Performance

Measured on the bench against **RFC 2544 — the highest offered rate at which nothing is lost**, not the packets that survived an overload. Rig is an Orange Pi 5 Plus (RK3588: 4x A76 @ 2.4 GHz + 4x A55 @ 1.8 GHz), ConnectX 10 GbE, DACs straight into the generator. Figures are at 0.01% loss.

The policy under test is a single `redirect to <zone>` with no rule set, no conntrack and no NAT — but it is real L3 forwarding, not an L2 bounce: every packet gets a FIB lookup against this box's routing table, a MAC rewrite and a TTL decrement.

IMIX is the mix appliance datasheets quote: 7 x 64, 4 x 594 and 1 x 1518 byte frames, average 361.8 bytes.

| workload | 64 B | IMIX | 1518 B |
|---|---|---|---|
| **drop** — storm shield, blocklists | 6,433,444 pps | 3,240,759 pps (**99.0% of line**) | line-limited |
| **forward** — one direction | 3,865,457 pps | 3,230,294 pps (**98.7% of line**) | 9.73 Gb/s (98.5%) |
| **bidirectional** — both directions, aggregate | 3,513,116 pps | **10.83 Gb/s** | **19.39 Gb/s (98.2% of line)** |

**At IMIX and above, the ports are the limit — not the box.** 98.7% of line one way, 98.2% both ways at 1518 bytes. Only 64-byte traffic still finds a ceiling inside the SoC.

**The firewall is a twentieth of the cost.** Under `bpf_stats` the compiled FWL program measures 411 ns per packet, under 5% of the machine while it forwards. Rules are cheap relative to the fixed cost of moving a packet, which is the property that decides whether a real policy costs anything a customer notices.

**The management plane is unaffected by a full-rate flood.** Under a 3 Mpps flood, ssh round-trip measured 165 ms median against 214 ms idle — *faster*, because the governor parks the big cores when idle and a flood pins them at maximum. An operator can log in and fix the box while every port is being hammered, which is exactly when they need to.

### For scale: the same test on appliances that cost more

Netgate publishes these for pfSense Plus, measured bidirectionally across all ports — the same thing the bidirectional row above measures.

| appliance | price | L3 forwarding, iPerf3 | L3 forwarding, IMIX |
|---|---|---|---|
| Netgate 4200 | $599 | 8.75 Gb/s | 9.28 Gb/s |
| Netgate 6100 | $899 | 18.50 Gb/s | 6.08 Gb/s |
| Netgate 8200 MAX | $1,749 | 18.60 Gb/s | 11.76 Gb/s |
| **`f` on the rig** | ~200 EUR + NIC | **19.39 Gb/s** | **10.83 Gb/s** |

### Through a 10,000-entry blocklist

Netgate publishes a second figure for the same traffic through 10,000 ACLs. Measured the same way, bidirectionally, with 10,000 prefixes loaded on both zones:

| | price | iPerf3 frames | IMIX |
|---|---|---|---|
| Netgate 6100, 10k ACLs | $899 | 9.93 Gb/s | 2.73 Gb/s |
| Netgate 8200 MAX, 10k ACLs | $1,749 | 18.55 Gb/s | 5.10 Gb/s |
| **`f`, 10k prefixes** | ~200 EUR | **19.60 Gb/s** | **10.70 Gb/s** |

The blocklist costs 1.2% against the same test with no policy at all, and the program stays 227 instructions whether it holds 1,000 prefixes or 50,000 — the size is in a map, not in the code.

Read all of it with its caveats or it misleads. The forms are not identical: Netgate's 10,000 ACLs are 10,000 independent rules that may each test different fields, while this is one rule against a 10,000-entry prefix table. For blocklists, customer prefixes and threat feeds they express the same intent; for 10,000 genuinely heterogeneous rules `f` falls back to a linear chain and cannot express them at all. Their aggregate also spans more ports than this rig has, `f` has no IPsec where every Netgate row has a VPN number, and an appliance buys a case, redundant power and support that a dev board does not.

### Four tuning changes worth 3.4x, none of them a default

Untuned, this box forwards 955,429 pps. Tuned, 3,230,294. Every one of these was invisible until it was measured.

- **The IOMMU was half the machine.** `XDP_REDIRECT` DMA-maps a frame on the transmit device per packet, and the kernel's default strict mode makes every unmap wait for an SMMU invalidation. `perf` found 37% of the big cores in `arm_smmu_cmdq_issue_cmdlist`. `iommu.strict=0` is worth **+80%** and keeps DMA isolation; `iommu.passthrough=1` is worth **+180%** and removes it — a security decision, not a tuning one.
- **Disable deep cpuidle and pin the governor to `performance`.** `cpu-sleep` on this SoC has a 220 us exit latency; at 1.4 Mpps that is 300 packets against a 1024-entry ring. Worth **31-43%**, and it turns a loss threshold that moved 40% between identical runs into one that does not.
- **Weight the RSS indirection table toward the fast cores.** big.LITTLE plus a flat table feeds 1.8 GHz cores exactly as hard as 2.4 GHz ones. `ethtool -X <iface> weight 1 1 1 1 3 3 3 3`, matched to the queue-to-CPU map, is worth **25-32%** — confirmed independently on igb and mlx5. Pinning everything to the big cores instead *halves* throughput; the little cores carry real work.
- **Ring size does nothing.** Tested 256 to 4096 on igb and 1024 to 8192 on mlx5. No effect either time. It is the obvious knob and it is the wrong one.

`deploy/f_datapath_tune.py` applies the ones that are runtime-settable and reports the IOMMU, which is not.

### Before quoting any of this

- **Always state the frame size.** 10 GbE is 14,880,952 pps at 64 bytes and 812,743 at 1518. The same box does 26% of line at one and 98% at the other, and a number without its frame size is not a measurement.
- **Written as rules, a policy costs dearly; written as data, it costs nothing.** 1,000 rules drops forwarding to 994,638 pps and 2,000 to 385,826, because every packet walks the whole chain at about a nanosecond a rule. The ceiling is **8,192 rules** — the verifier's jump-sequence limit, past which no arrangement of the policy loads — and the compiler warns above 2,048 that the throughput is what it is. The same policy as one lookup against a **50,000-entry** trie runs at 99% of line in 227 instructions. Both measured: `f.planning/rig-evidence/ACL_SCALING_2026-08-23.md`.

Harness and full results, including how two earlier conclusions here turned out to be artifacts: `tests/system/hw/l13_02_rfc2544_throughput.py` and `f.planning/rig-evidence/RFC2544_10G_2026-08-23.md`.

## Requirements

- Linux 5.10+ with BPF support
- CMake 3.20+, Ninja
- Clang/GCC with C++23 support
- libbpf (system)
- cppzmq (system)
- Python 3.11+ (for FWL compiler)

## Building

```bash
cmake --preset default
cmake --build --preset default
```

Debug build:

```bash
cmake --preset debug
cmake --build --preset debug
```

## Running

Start the daemon. It attaches to the interfaces the bundle's zones name — there is no interface flag, because a list that disagreed with the policy was a box enforcing something nobody wrote:

```bash
sudo ./build/fd run --bundle-dir /usr/share/f/compiled
```

Start the web dashboard:

```bash
sudo ./build/einheit-f-ui --port 8080
```

Use the CLI to control the engine:

```bash
./build/fctl status
./build/einheit-f show zones
```

## Testing

```bash
ctest --preset default
```

Run a single test:

```bash
./build/tests/test_types --gtest_filter='TypesTest.RuleKey*'
```

**Load and throughput** live in `tests/system/hw/` and need a rig, a traffic generator and root, so they do not run in CI:

```bash
./l13_02_rfc2544_throughput.py --dut-host f-rig --rx-iface eth1 \
    --tx-iface eth2 --gen-iface <generator NIC> --dst-mac <rx MAC>
```

It binary-searches for the highest lossless rate per frame size and refuses to report a trial the generator could not actually deliver. `l13_01_policy_cost_ladder.py` measures per-construct cost with a sampler that records every thermal sensor, per-cluster clocks, per-core softirq and NIC drop counters twice a second.

## FWL — Firewall Language

FWL is a small declarative language that compiles to XDP/eBPF. A policy declares zones and gives each an `@xdp` block — either a sequence of rules or a single `def` body:

```fwl
zone lan = [lan0, lan1]
zone wan = [wan0]

@xdp(wan)

count wan_total
count wan_noise if pkt.dst_ip in 224.0.0.0/4

# The plant-floor broadcast firehose dies at the driver.
drop if pkt.dst_ip in 224.0.0.0/4
drop if pkt.dst_ip == 255.255.255.255

# Keep the DHCP lease alive, then admit only replies to flows we started.
allow if pkt.proto == udp and pkt.src_port == 67 and pkt.dst_port == 68
allow if conntrack(pkt).state == established
drop limited by rate_limit(2000, per=src_ip)

default drop

@xdp(lan)

count lan_out
masquerade
redirect to wan
```

That is a working NAT gateway: the testnet on `lan0`/`lan1` reaches the internet through `wan0`, hidden behind its address, and nothing unsolicited comes back.

**What v0.4 covers.** Actions `allow`, `drop`, `log`, `count <name>`, `redirect to <zone>`, `masquerade`, `snat to <ip>`, `dnat to <ip>:<port>`. All eight TCP flags, ICMP and ICMPv6 type/code, IPv4 and IPv6 addresses, ports, protocol, VLAN, and `pkt.zone`. `conntrack(pkt).state` and `rate_limit(N, per=<field>)` — the latter as a Tier 1 modifier or a Tier 2 condition, with `scope=zone|global`. `geoip(...)` against a compiled country trie. Tier 2 `def` bodies with locals and control flow, plus helper defs callable from several zones. Programs that would exceed the verifier's budget are split into a tail-call pipeline automatically, invisibly to the author.

Tier 3 raw-C `inline_c` is excluded by design, not merely unbuilt. The spec's "What Is Not in v0.4" section is the authoritative list of everything else.

Install and use:

```bash
cd fwl
pip install -e ".[dev]"
fwl check rules.fw                    # parse + semantic check
fwl compile --bundle out/ rules.fw    # per-zone objects + manifest
fwl test tests/corpus/                # interpreter + clang-compile
sudo .venv/bin/fwl test tests/corpus/ # add live BPF_PROG_TEST_RUN
```

See [`fwl/README.md`](fwl/README.md) for the compiler architecture and the `.pkt` test format; the language reference is in [`docs/FWL_V04_SPEC.md`](docs/FWL_V04_SPEC.md); the methodology that gates each construct on three-oracle agreement is in [`docs/F_DEVELOPMENT_METHODOLOGY.md`](docs/F_DEVELOPMENT_METHODOLOGY.md).

## Control surface

There is no REST API. A table of `/api/v1/...` endpoints stood here, served by an `f-api` binary that read the pinned maps of the v0.1 single-program datapath — `rules_a`, `counters`, `config` — none of which a compiled bundle pins. On every deployed box it answered `[]` for rules, one all-zero counter row, and `{"rules_installed": 0}` with HTTP 200 for a `PUT` in which every map write failed `EBADF`. It was removed with that datapath.

The daemon speaks one protocol: ZMQ REQ/REP at `ipc:///run/f/control.sock`, a request of `[1B Cmd][payload]`, a JSON reply. `include/f/protocol.h` lists the opcodes, and records which numbers are retired so they are never reused against an older client. `einheit-f`, `einheit-f-ui` and `fctl` are the three clients.

## Documentation

- [Documentation index](docs/README.md) — which page answers what
- [The first hour](docs/first-hour.md) — box to a working testnet, one path
- [Concepts](docs/concepts.md) — ports, interfaces, zones, services, and what the datapath does
- [FWL guide](docs/fwl/README.md) — a learning path from `allow`/`drop` to NAT and helpers
- [Recovery](docs/recovery.md) — the ways this has actually gone wrong
- [CLI reference](docs/reference/cli.md) · [`system.yaml` reference](docs/reference/system-yaml.md) · [Error codes](docs/reference/error-codes.md)
- [FWL v0.4 language reference](docs/FWL_V04_SPEC.md) — current; [v0.2](docs/FWL_V02_SPEC.md) and [v0.1](docs/FWL_V01_SPEC.md) are superseded, kept for their reasoning
- [FWL development methodology](docs/F_DEVELOPMENT_METHODOLOGY.md)
- [FWL compiler README](fwl/README.md)
