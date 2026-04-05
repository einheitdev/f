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
- **FWL compiler** — domain-specific language that compiles declarative rules and Python-syntax logic to BPF C

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

FWL compiles firewall rules to BPF. It has three tiers:

**Tier 1** — declarative rules that compile to map entries:

```python
allow dst_port 80, 443 proto tcp
  count web_traffic

block src_net 10.0.0.0/8

default drop
```

**Tier 2** — Python-syntax functions that compile to BPF C:

```python
@xdp(eth0)
def firewall(pkt):
  if pkt.proto == tcp and pkt.dst_port == 22:
    if pkt.tcp.syn and not pkt.tcp.ack:
      rate_limit(10, per=src_ip)
    allow

  if conntrack(pkt).state == established:
    allow

  drop
```

**Tier 3** — raw C escape hatch for custom protocol parsing:

```python
@xdp(eth0)
def deep_inspect(pkt):
  if pkt.dst_port == 53:
    inline_c """
      __u8* dns = pkt->l4_payload;
      if (dns[2] & 0x80) {
        return XDP_DROP;
      }
    """
  allow
```

Install and use:

```bash
cd fwl
pip install -e ".[dev]"
fwl compile rules.fw -o rules.bpf.c
```

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

- [Architecture and design](doc/design.md)
- [FWL language reference](doc/fwl.md)
