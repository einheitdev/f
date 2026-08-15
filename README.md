# f

An eBPF/XDP firewall with zero-downtime rule updates, a REST API, a web dashboard, and a domain-specific language compiler.

## How It Works

`f` runs as a userspace daemon (`fd`) that loads an XDP program onto network interfaces. Packets are filtered at the earliest point in the kernel networking stack — before socket allocation, before iptables, before the kernel builds an `sk_buff`.

Rules live in BPF maps. Updates go to a standby table while the active table continues serving traffic. A single-byte atomic flip switches to the new table. Zero packets are dropped during updates.

```
                    ┌──────────────┐
                    │   Browser    │
                    │  (HTMX UI)   │
                    └──────┬───────┘
                           │ HTTP
                           ▼
┌─────────┐      ┌────────────────────────┐
│  fctl   │──────│  fd (daemon)           │
│  (CLI)  │ unix │  ┌──────────────────┐  │
└─────────┘ sock │  │ Crow (REST API)  │  │
                 │  └────────┬─────────┘  │
                 │  ┌────────┴─────────┐  │
                 │  │ Engine (BPF ops) │  │
                 │  └────────┬─────────┘  │
                 └───────────┼────────────┘
                             │ bpf() syscalls
                             ▼
                 ┌───────────────────────┐
                 │  Kernel (XDP)         │
                 │  ┌─────────────────┐  │
                 │  │ Packet filter   │  │
                 │  │ Conntrack       │  │
                 │  │ Rate limiter    │  │
                 │  │ Counters        │  │
                 │  └─────────────────┘  │
                 └───────────────────────┘
```

## Features

- **XDP packet filtering** — one compiled BPF program per zone, connection tracking, NAT, per-source rate limiting
- **Zero-loss hot reload** — a new bundle replaces the running one interface by interface (`XDP_FLAGS_REPLACE`); flow-keyed state survives the policy change
- **Refuses rather than pretends** — a bundle that attaches to no interface, and a box with no bundle staged, are both a daemon that does not start
- **ZMQ control protocol** — `[1B Cmd][payload]`, JSON reply, at `ipc:///run/f/control.sock`
- **Operator CLI and web dashboard** — `einheit-f` and `einheit-f-ui`, both reading the daemon
- **FWL compiler** — small declarative language that compiles to verifier-accepted BPF C, verified construct-by-construct against three independent oracles

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

Start the daemon and attach to an interface:

```bash
sudo ./build/fd --iface eth0
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

## FWL — Firewall Language

FWL is a small declarative language that compiles to XDP/eBPF. The v0.1 surface is one hook + a sequence of rules + an optional default:

```
@xdp(eth0)

# Drop new SSH connections beyond 3 per second per source IP.
drop if pkt.proto == tcp
       and pkt.dst_port == 22
       and pkt.tcp.syn and not pkt.tcp.ack
       limited by rate_limit(3, per=src_ip)

# Track allowed SSH attempts so userspace can chart them.
count ssh_allowed if pkt.proto == tcp and pkt.dst_port == 22

allow if pkt.proto == tcp and pkt.dst_port in [22, 80, 443]
allow if pkt.proto == udp and pkt.dst_port == 53

default drop
```

What v0.1 covers: `allow|drop|log|count <name>` actions, `default allow|drop`, the seven `pkt.*` fields above plus `pkt.{src,dst}_ip`, all the usual comparison operators including `in` (lists, port ranges, CIDR, CIDR lists), `and`/`or`/`not`/parens with correct precedence and short-circuit, and the `rate_limit(N, per=<field>)` modifier as the one stateful primitive. Tier 2 functions, Tier 3 inline C, IPv6, geoip, and conntrack are explicitly deferred — see the spec for the full list.

Install and use:

```bash
cd fwl
pip install -e ".[dev]"
fwl compile rules.fw -o rules.bpf.c
fwl test tests/corpus/                # interpreter + clang-compile
sudo .venv/bin/fwl test tests/corpus/ # add live BPF_PROG_TEST_RUN
```

See [`fwl/README.md`](fwl/README.md) for the compiler architecture and the `.pkt` test format; the language reference is in [`docs/FWL_V01_SPEC.md`](docs/FWL_V01_SPEC.md); the methodology that gates each construct on three-oracle agreement is in [`docs/F_DEVELOPMENT_METHODOLOGY.md`](docs/F_DEVELOPMENT_METHODOLOGY.md).

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
- [FWL v0.1 language reference](docs/FWL_V01_SPEC.md)
- [FWL development methodology](docs/F_DEVELOPMENT_METHODOLOGY.md)
- [FWL compiler README](fwl/README.md)
