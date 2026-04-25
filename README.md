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

- **XDP packet filtering** — exact 5-tuple and CIDR matching, connection tracking, per-source rate limiting
- **A/B table swap** — atomic rule replacement with no packet loss
- **Per-CPU counters** — packet and byte stats per rule, aggregated in userspace
- **Ring buffer slow path** — kernel-to-userspace event stream for new connections, rate exceeded, unknown protocols
- **Binary control protocol** — flat struct serialization over Unix socket, no parsing overhead
- **REST API** — JSON and HTMX fragment endpoints for rules, counters, conntrack, interfaces
- **Web dashboard** — HTMX + Tailwind CSS + Plotly.js, no build tooling required
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
sudo ./build/f-api --port 8080
```

Use the CLI to control the engine:

```bash
./build/fctl status
./build/fctl counters
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

FWL is a small declarative language that compiles to XDP/eBPF. The v0.1
surface is one hook + a sequence of rules + an optional default:

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

What v0.1 covers: `allow|drop|log|count <name>` actions, `default
allow|drop`, the seven `pkt.*` fields above plus `pkt.{src,dst}_ip`, all
the usual comparison operators including `in` (lists, port ranges, CIDR,
CIDR lists), `and`/`or`/`not`/parens with correct precedence and
short-circuit, and the `rate_limit(N, per=<field>)` modifier as the one
stateful primitive. Tier 2 functions, Tier 3 inline C, IPv6, geoip, and
conntrack are explicitly deferred — see the spec for the full list.

Install and use:

```bash
cd fwl
pip install -e ".[dev]"
fwl compile rules.fw -o rules.bpf.c
fwl test tests/corpus/                # interpreter + clang-compile
sudo .venv/bin/fwl test tests/corpus/ # add live BPF_PROG_TEST_RUN
```

See [`fwl/README.md`](fwl/README.md) for the compiler architecture and
the `.pkt` test format; the language reference is in
[`docs/FWL_V01_SPEC.md`](docs/FWL_V01_SPEC.md); the methodology that
gates each construct on three-oracle agreement is in
[`docs/F_DEVELOPMENT_METHODOLOGY.md`](docs/F_DEVELOPMENT_METHODOLOGY.md).

## REST API

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/status` | Daemon state, uptime, attached interfaces |
| GET | `/api/v1/rules` | Current rule set |
| PUT | `/api/v1/rules` | Replace full rule set (A/B swap) |
| POST | `/api/v1/rules` | Add single rule |
| DELETE | `/api/v1/rules/:id` | Remove single rule |
| GET | `/api/v1/counters` | Per-rule packet/byte counters |
| GET | `/api/v1/conntrack` | Active connection table |
| GET | `/api/v1/interfaces` | Attached interfaces |
| POST | `/api/v1/interfaces/:name/attach` | Attach XDP to interface |
| POST | `/api/v1/interfaces/:name/detach` | Detach XDP from interface |
| GET | `/api/v1/log` | Recent log entries |

All endpoints return JSON by default. When called with `HX-Request: true`, they return HTML fragments for the HTMX dashboard.

## Documentation

- [FWL v0.1 language reference](docs/FWL_V01_SPEC.md)
- [FWL development methodology](docs/F_DEVELOPMENT_METHODOLOGY.md)
- [FWL compiler README](fwl/README.md)
