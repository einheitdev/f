# f

An eBPF/XDP firewall built around a small declarative language. Policy is written in FWL, compiled to verifier-accepted BPF, and loaded into the kernel without dropping a packet or an established connection. A daemon owns the datapath, a Junos-style CLI owns the configuration, and a web dashboard reads both.

On a 200 EUR SoC board it forwards a 10 GbE link at 98% of line rate, absorbs a full-rate IMIX flood at 98.9% of line, and keeps the management plane responsive throughout — measured against RFC 2544, not estimated. See [Performance](#performance).

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

Measured on the bench against **RFC 2544 — the highest offered rate at which nothing is lost**, not the packets that survived an overload. Rig is an Orange Pi 5 Plus (RK3588: 4x A76 @ 2.4 GHz + 4x A55 @ 1.8 GHz), ConnectX 10 GbE, DACs straight into the generator. The policy under test is a bare `redirect to <zone>` — no rules, no conntrack, no NAT — so these are the datapath floor and an upper bound on what a real policy does.

IMIX below is the mix appliance datasheets quote: 7 x 64, 4 x 594 and 1 x 1518 byte frames, average 361.8 bytes. Figures are at 0.01% loss; the strict zero-loss column is in the evidence file, and differs by under 3% once the box is tuned.

| workload | 64 B | IMIX | 1518 B |
|---|---|---|---|
| **drop** — storm shield, blocklists | 3,387,811 pps | 3,237,542 pps (**9.37 Gb/s, 98.9% of line**) | 799,803 pps (line-limited) |
| **forward** — one direction | 1,378,641 pps | 1,392,633 pps | 799,919 pps (**9.71 Gb/s, 98.4% of line**) |
| **bidirectional** — both directions, aggregate | 1,419,420 pps | 1,366,340 pps | 1,168,694 pps (**14.19 Gb/s**) |

**The datapath is packet-limited, not byte-limited.** Forwarding tops out at 1.38-1.39 Mpps at every frame size where the link is not the binding constraint, and running both directions at once reaches the same aggregate — one direction or two, the box moves the same number of packets. Bytes are close to free; packets are what cost.

**Dropping costs 2.4x less than forwarding.** At IMIX the box absorbs a full 10 GbE line-rate flood, while a policy that has to put the packets back on the wire manages 42% of line. For a blocklist or a plant-floor broadcast storm there is room to spare; for a gateway the transmit path is the constraint.

**The firewall itself is about an eighth of the cost.** Under `bpf_stats`, the compiled FWL program measures 411 ns per packet — 6.6% of eight cores while the system is 56% busy. The rest is driver, page pool and redirect plumbing. Rules are cheap relative to the fixed cost of moving a packet.

**The management plane is unaffected by a full-rate flood.** Under a 3 Mpps flood, ssh round-trip measured 165 ms median against 214 ms idle — *faster*, because the governor parks the big cores when idle and a flood pins them at maximum. An operator can log in and fix the box while every port is being hammered, which is exactly when they need to.

### Three tuning changes worth 40%, none of them a default

- **Disable deep cpuidle and pin the governor to `performance`.** `cpu-sleep` on this SoC has a 220 us exit latency; at 1.4 Mpps that is 300 packets against a 1024-entry ring. Worth **31-43%**, and it turns a noisy loss threshold into a sharp one. The box had been losing packets with 45% of its CPU idle.
- **Weight the RSS indirection table toward the fast cores.** big.LITTLE plus a flat table feeds 1.8 GHz cores exactly as hard as 2.4 GHz ones. `ethtool -X <iface> weight 1 1 1 1 3 3 3 3`, matched to the queue-to-CPU map, is worth **25-32%** — confirmed independently on igb and mlx5. Pinning everything to the big cores instead *halves* throughput; the little cores carry real work.
- **Ring size does nothing.** Tested 256 to 4096 on igb and 1024 to 8192 on mlx5. No effect either time. It is the obvious knob and it is the wrong one.

### Before quoting any of this

- **Always state the frame size.** 10 GbE is 14,880,952 pps at 64 bytes and 812,743 at 1518. The same box does 9% of line at one and 98% at the other, and a number without its frame size is not a measurement.
- **The 1518-byte bidirectional figure is PCIe-limited, not SoC-limited.** 14.19 Gb/s forwarded is 28.4 Gb/s across the bus, because every forwarded byte crosses it twice, and the card is an x8 in an x4 slot. That number is a property of the rig.
- **No rule set has been measured yet.** Netgate publishes a 10,000-ACL figure; `f` does not have one, and the numbers above are for an empty policy.

Harness and full results, including the side-by-side against Netgate's published figures: `tests/system/hw/l13_02_rfc2544_throughput.py` and `f.planning/rig-evidence/RFC2544_10G_2026-08-23.md`.

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
