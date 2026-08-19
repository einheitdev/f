> **SUPERSEDED — April 2026 design sketch, kept for its reasoning.**
>
> This is the document that argued FWL into existence, and the motivation section still reads true. The surface it describes does not.
>
> Most importantly, **Tier 3 (`inline_c`, the raw-C escape hatch) does not exist and is not coming.** It appears throughout below as though it were part of the design; it was cut deliberately, and `f.planning/DATA_SOURCES.md` records why. Nothing in the compiler has ever implemented it.
>
> For the language as shipped, read [`docs/FWL_V04_SPEC.md`](../docs/FWL_V04_SPEC.md). For using it, [`docs/fwl/`](../docs/fwl/). For the compiler's internals, [`fwl/README.md`](../fwl/README.md).

# FWL — Firewall Language

A Python-syntax domain-specific language that compiles to eBPF/XDP
programs.  Absorbs the complexity of BPF C programming while
preserving full escape-hatch access to raw C when needed.

## Motivation

eBPF/XDP is a programmable kernel runtime — Turing-complete packet
processing at line rate.  But writing BPF C is painful:

- Manual bounds checks on every packet field access (verifier rejects
  without them)
- Explicit byte-order conversions (`bpf_ntohs` everywhere)
- Struct padding mismatches between BPF and userspace
- 512-byte stack limit, manual spills to maps
- Verifier complexity limit on deeply nested code
- Inline protocol header definitions (can't use libc)
- No abstractions — every program re-implements the same parse chain

Meanwhile, `pf` (OpenBSD/FreeBSD) gives users a 20-line config file
that just works — but can't do custom protocol parsing, per-flow
state machines, or any logic beyond match/action rules.

FWL sits between these extremes: pf's accessibility as the floor,
eBPF's power as the ceiling, with a smooth ramp between them.

## Design Principle

All tiers compile down to the same thing: BPF maps + XDP/TC programs.
A declarative rule and a custom `.bpf.c` both end up as verified
bytecode running at line rate.  The tiers are different frontends
for the same backend.

The core analogy is GPU shaders:

| GPU pipeline | FWL pipeline |
|---|---|
| GLSL/HLSL source | `.fw` source |
| SPIR-V / DXIL bytecode | BPF bytecode |
| Driver validation | BPF verifier |
| Runs on GPU per-fragment | Runs in kernel per-packet |
| Uniforms / UBOs | BPF maps |
| Shader compiler | FWL compiler |
| Raw SPIR-V escape hatch | Raw C escape hatch |

## Three Tiers

### Tier 1 — Declarative Rules

Plain-text firewall rules.  No programming knowledge required.
The compiler turns each rule into a BPF map entry that the
orchestrator (`fd`) loads.

```python
# Simple allow/deny rules — compiles to map entries.
allow dst_port 80, 443 proto tcp
  count web_traffic

block src_net 192.168.0.0/16 rate > 100pps
  log sampled 1/100

block src_net 10.0.0.0/8

default drop
```

What the compiler does:
- Parses rules into `RuleKey`/`RuleValue` structs.
- Emits a config blob that `fd` loads via `kApplyConfig`.
- No BPF C generated — rules go directly into existing maps.

### Tier 2 — Programmable Logic

Python-syntax hooks with control flow, built-in functions, and
composable pipeline stages.

```python
@xdp(eth0)
def firewall(pkt):
  # GeoIP lookup — compiler generates a hash map,
  # orchestrator populates it from a GeoIP database.
  if pkt.src_ip in geoip("RU", "CN"):
    drop

  # Port-based rules with nested logic.
  if pkt.proto == tcp and pkt.dst_port == 22:
    if pkt.tcp.syn and not pkt.tcp.ack:
      rate_limit(10, per=src_ip)
    allow

  # Stateful filtering — compiler links in the
  # conntrack BPF library via tail call.
  if conntrack(pkt).state == established:
    allow

  drop
```

What the compiler does:
- Tracks which `pkt` fields are accessed → emits only the
  parse chain needed (touch `pkt.dst_port` → get Ethernet +
  IP + TCP/UDP parsing; touch only `pkt.src_ip` → get
  Ethernet + IP, no L4).
- Inserts bounds checks automatically at every layer.
- Handles byte-order conversions transparently.
- Generates padded structs with matching C++ userspace types.
- `rate_limit(10, per=src_ip)` → generates a per-CPU hash map
  + sliding window counter, wires it up.
- `geoip(...)` → generates a hash map, emits a loader hook
  for the orchestrator to populate from MaxMind/IP2Location.
- `conntrack(pkt)` → tail-calls into the pre-built conntrack
  BPF program.

### Tier 3 — Raw C Escape Hatch

For when the DSL isn't enough.  Drop into C for custom protocol
parsing, payload inspection, or anything the language doesn't
cover yet.

```python
@xdp(eth0)
def deep_inspect(pkt):
  if pkt.dst_port == 53:
    # Raw C block.  The compiler injects bounds-checked
    # pointers: pkt->l4_payload, pkt->l4_len.
    inline_c """
      __u8* dns = pkt->l4_payload;
      // QR bit (bit 7 of byte 2) = 1 means response.
      if (dns[2] & 0x80) {
        return XDP_DROP;  // Block inbound DNS responses.
      }
    """
  allow
```

Users can also drop in a full `.bpf.c` file and register it
as a pipeline stage:

```python
# Load a hand-written BPF program as a tail-call stage.
stage "dpi" from "custom/dpi.bpf.c"

@xdp(eth0)
def firewall(pkt):
  if pkt.dst_port == 443:
    # Jump to the custom stage.
    chain dpi
  allow
```

## Compilation Pipeline

```
 source.fw
     │
     ▼
 ┌──────────────────────────┐
 │ 1. Parser                │  Python-syntax tokenizer + AST.
 │    (Python, PLY or Lark) │  Handles indentation-as-structure.
 └──────────┬───────────────┘
            │ AST
            ▼
 ┌──────────────────────────┐
 │ 2. Semantic analysis     │  Resolves pkt field access chains.
 │                          │  Type-checks: pkt.tcp.syn on a UDP
 │                          │  packet → compile-time error.
 │                          │  Computes minimal parse set.
 └──────────┬───────────────┘
            │ Typed IR
            ▼
 ┌──────────────────────────┐
 │ 3. Lowering              │  Inserts bounds checks at each
 │                          │  protocol layer.  Inserts byte-order
 │                          │  conversions.  Generates struct
 │                          │  padding.  Splits long programs into
 │                          │  tail-call stages to stay under
 │                          │  verifier complexity limit.  Spills
 │                          │  locals to per-CPU map if stack
 │                          │  would exceed 512 bytes.
 └──────────┬───────────────┘
            │ Lowered IR
            ▼
 ┌──────────────────────────┐
 │ 4. C emitter             │  Produces valid, readable .bpf.c.
 │                          │  inline_c blocks paste through
 │                          │  verbatim.  Output is inspectable
 │                          │  for learning and debugging.
 └──────────┬───────────────┘
            │ .bpf.c + types.h
            ▼
 ┌──────────────────────────┐
 │ 5. clang -target bpf     │  Standard BPF compilation.
 │    bpftool gen skeleton   │  Existing cmake/bpf.cmake pipeline.
 └──────────┬───────────────┘
            │ .skel.h
            ▼
    fd orchestrator loads it
```

Emitting C (not raw BPF bytecode) is a deliberate choice:
- Users can read the generated `.bpf.c` to learn or debug.
- Piggybacks on clang's BPF optimizer and BTF generation.
- Verifier errors reference C line numbers, not bytecode offsets.
- `inline_c` blocks paste through with no special handling.

## The `pkt` Object

`pkt` is not a runtime Python object.  It's a compiler-tracked
symbol that records which fields the program accesses.  At emit
time, the compiler generates exactly the parse code needed.

```
pkt.src_ip      → emits: Ethernet + IP parse + bounds checks
pkt.dst_port    → emits: Ethernet + IP + TCP/UDP parse
pkt.tcp.syn     → emits: Ethernet + IP + TCP parse + flag extract
pkt.l4_payload  → emits: full L2-L4 parse, pointer to L4 payload
```

Field access on the wrong protocol is a compile-time error:

```python
if pkt.proto == udp:
  if pkt.tcp.syn:  # ERROR: tcp field access inside udp branch
    drop
```

The compiler knows the protocol context from the enclosing `if`
and rejects the access.

## Built-in Functions

Each built-in compiles to a map + BPF helper code.  The
orchestrator handles populating data-driven maps (geoip, etc.)
at load time.

| Function | What it generates |
|---|---|
| `rate_limit(N, per=field)` | Per-CPU hash map + sliding window token bucket.  Key is the `per` field (e.g., src_ip). |
| `conntrack(pkt)` | Tail call into pre-built conntrack BPF program.  Returns flow state (new, established, related). |
| `geoip(codes...)` | Hash map (IP → country code).  Orchestrator populates from MaxMind DB at load/reload time. |
| `log(msg, sampled=N)` | Ring buffer event with optional 1-in-N sampling.  Stats daemon reads via `bpf_ringbuf_poll`. |
| `count(name)` | Named per-CPU counter.  Compiler allocates a slot in the counters array map. |
| `chain(stage)` | Tail call into another BPF program (from a `.fw` file or a raw `.bpf.c`). |

## Chaining / Pipeline Composition

Programs compose via tail calls (`BPF_MAP_TYPE_PROG_ARRAY`).
Each stage is a separate BPF program.  The compiler wires them
together:

```python
# Define pipeline stages.
@xdp(eth0, order=1)
def geoip_filter(pkt):
  if pkt.src_ip in geoip("RU", "CN"):
    drop
  # Implicit: fall through to next stage.

@xdp(eth0, order=2)
def rate_limiter(pkt):
  if pkt.proto == tcp and pkt.dst_port == 80:
    rate_limit(1000, per=src_ip)
  # Fall through.

@xdp(eth0, order=3)
def policy(pkt):
  allow dst_port 80, 443 proto tcp
  allow dst_port 53 proto udp
  default drop
```

Compiles to:
1. An entry-point XDP program that tail-calls stage 1.
2. Each stage tail-calls the next via `bpf_tail_call()`.
3. The prog array map is populated by the orchestrator.
4. Stages can be hot-swapped individually (update one slot
   in the prog array) without disrupting the others.

## XDP + TC Pipeline

For operations that need sk_buff (header rewriting, NAT,
redirect), the compiler can emit TC programs in addition to
XDP programs:

```python
@xdp(eth0)
def fast_path(pkt):
  # XDP: cheap reject at line rate.
  if pkt.src_ip in blacklist:
    drop

@tc_ingress(eth0)
def rewrite(pkt):
  # TC: has sk_buff, can modify headers.
  if pkt.dst_port == 8080:
    pkt.dst_port = 80   # Port rewrite (NAT).
```

This maps to the GPU analogy: XDP is the vertex shader (fast,
early reject), TC is the fragment shader (full processing).

## Compiler Implementation

The compiler is written in Python.  It's a transpiler that runs
once at config time, not per-packet — performance is irrelevant.

### Parser

Lark or PLY for the grammar.  Python-style indentation handled
by a lexer pre-pass that emits INDENT/DEDENT tokens (same
approach as CPython's tokenizer).

### Key data structures

```
ASTNode
├── RuleNode        (tier 1: "allow dst_port 80 proto tcp")
├── FunctionDef     (tier 2: "@xdp def firewall(pkt): ...")
├── IfNode          (conditional: "if pkt.proto == tcp: ...")
├── FieldAccess     (pkt.dst_port, pkt.tcp.syn)
├── BuiltinCall     (rate_limit, conntrack, geoip, log, count)
├── InlineCBlock    (tier 3: inline_c """ ... """)
├── ChainCall       (tail call to another stage)
├── Action          (drop, allow, pass)
└── PipelineDecl    (stage ordering + hook point)
```

### Semantic passes

1. **Field resolution** — walk all `FieldAccess` nodes, build
   the set of protocol layers needed.  `{pkt.dst_port}` →
   needs Ethernet, IP, TCP/UDP.

2. **Protocol guard checking** — verify every `FieldAccess` is
   inside an appropriate protocol guard (`if pkt.proto == tcp`
   before accessing `pkt.tcp.syn`).

3. **Stack estimation** — sum local variable sizes.  If > 512
   bytes, insert spills to a per-CPU array map.

4. **Complexity estimation** — count branch paths.  If over the
   verifier limit (~1M instructions), split into tail-call
   stages.

5. **Map allocation** — collect all maps needed (rule tables,
   counters, rate limiters, geoip, conntrack, prog arrays).
   Assign map names and counter indices.

### C emission

Each AST node has an `emit()` method that writes C code to a
string buffer.  The emitter tracks indentation and inserts
comments referencing the original `.fw` line numbers for
debugging.

Example input:
```python
@xdp(eth0)
def firewall(pkt):
  if pkt.dst_port == 80 and pkt.proto == tcp:
    allow
  drop
```

Generated C (simplified):
```c
// Generated from firewall.fw:2
SEC("xdp")
int firewall(struct xdp_md* ctx) {
  void* data = (void*)(long)ctx->data;
  void* data_end = (void*)(long)ctx->data_end;

  // --- L2: Ethernet ---
  struct ethhdr* eth = data;
  if ((void*)(eth + 1) > data_end) return XDP_PASS;
  if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

  // --- L3: IPv4 ---
  struct iphdr* ip = (void*)(eth + 1);
  if ((void*)(ip + 1) > data_end) return XDP_PASS;

  // --- L4: TCP (needed for dst_port) ---
  __u16 dst_port = 0;
  if (ip->protocol == 6) {  // IPPROTO_TCP
    __u32 l4_off = sizeof(*eth) + (ip->ihl * 4);
    struct tcphdr* tcp = data + l4_off;
    if ((void*)(tcp + 1) > data_end) return XDP_PASS;
    dst_port = bpf_ntohs(tcp->dest);
  }

  // firewall.fw:3 — if pkt.dst_port == 80 and pkt.proto == tcp:
  if (dst_port == 80 && ip->protocol == 6) {
    return XDP_PASS;  // allow
  }

  // firewall.fw:5 — drop
  return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
```

## Integration with `fd`

FWL is a compile-time tool.  It produces artifacts that `fd`
consumes:

```
fwl compile firewall.fw
  → firewall.bpf.c        (generated BPF C)
  → firewall_types.h       (generated shared types)
  → firewall.skel.h        (bpftool skeleton)
  → firewall_maps.json     (map metadata for orchestrator)

fd --program firewall.skel.h --maps firewall_maps.json
```

Or integrated into the build:

```cmake
# In CMakeLists.txt
add_fwl_program(firewall fw/firewall.fw)
# Runs: fwl compile → clang -target bpf → bpftool gen skeleton
```

The `firewall_maps.json` tells `fd` which maps to create and
how to populate them (e.g., geoip map needs MaxMind data,
rate_limit map needs initial token counts).

## Git-Based Deployment

The web UI can pull firewall configs and custom BPF programs
directly from git repos.  Point it at a repo, it clones,
compiles `.fw` + `.bpf.c` files, and hot-loads them into the
running firewall.  GitOps for packet processing.

### How it works

```
┌─────────────────────────────────────────────────┐
│  UI: Sources page                               │
│                                                 │
│  ┌──────────────────────────────────────────┐   │
│  │ + Add source                             │   │
│  │                                          │   │
│  │ ● github.com/acme/fw-rules     main  ✓  │   │
│  │   last sync: 2m ago  3 rules  1 stage    │   │
│  │   [Sync] [Diff] [Rollback]               │   │
│  │                                          │   │
│  │ ● git.internal/team/custom-dpi  v2.1  ✓  │   │
│  │   last sync: 1h ago  1 stage (.bpf.c)    │   │
│  │   [Sync] [Diff] [Rollback]               │   │
│  │                                          │   │
│  │ ● local: /etc/f/rules.fw           ✓     │   │
│  │   last modified: 5m ago                   │   │
│  │   [Reload]                               │   │
│  └──────────────────────────────────────────┘   │
└─────────────────────────────────────────────────┘
```

### Pipeline

```
git repo
    │
    ├─ clone / pull (shallow, sparse — only fw/ dir)
    │
    ├─ diff against currently loaded version
    │  (show in UI before applying)
    │
    ├─ fwl compile *.fw → .bpf.c → .skel.h
    │  compile *.bpf.c → .skel.h (raw C stages)
    │
    ├─ verify (BPF_PROG_TEST_RUN with sample packets)
    │
    ├─ hot-load into fd
    │  ├─ map entries → kApplyConfig
    │  ├─ new stages → tail-call slot update
    │  └─ full program → freplace or XDP_FLAGS_REPLACE
    │
    └─ record deployed commit SHA + timestamp
```

### Repo structure convention

```
acme/fw-rules/
├── fw/
│   ├── main.fw           # Tier 1/2 rules
│   ├── dpi.fw            # Custom inspection stage
│   └── stages/
│       └── quic.bpf.c    # Tier 3 raw C stage
├── data/
│   └── blocklists.csv    # IP/CIDR lists → loaded into maps
├── tests/
│   └── test_main.pkt     # Packet fixtures for BPF_PROG_RUN
└── f.yaml                # Source config
```

`f.yaml`:
```yaml
source:
  name: acme-fw-rules
  entry: fw/main.fw
  # Stages loaded in order, wired via tail calls.
  stages:
    - fw/main.fw
    - fw/dpi.fw
    - fw/stages/quic.bpf.c

data:
  # Maps populated from files at load time.
  blocklist:
    file: data/blocklists.csv
    map: blacklist
    format: cidr

sync:
  # Auto-pull interval.  "off" = manual only.
  interval: 5m
  branch: main
  # Only deploy if tests pass.
  require_tests: true
```

### REST API additions

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/sources` | List configured git sources |
| `POST` | `/api/v1/sources` | Add a git source (URL, branch, auth) |
| `DELETE` | `/api/v1/sources/:id` | Remove a source |
| `POST` | `/api/v1/sources/:id/sync` | Pull + compile + verify + load |
| `GET` | `/api/v1/sources/:id/diff` | Show diff between deployed and latest |
| `POST` | `/api/v1/sources/:id/rollback` | Revert to previous commit |
| `GET` | `/api/v1/sources/:id/log` | Deployment history (commit, time, status) |

### Auth

Git sources support:
- **SSH key** — stored in `fd` config, used for `git clone`.
- **HTTPS + token** — for GitHub/GitLab API access.
- **Local path** — `file:///etc/f/rules.fw`, no auth needed.
  `fd` watches with inotify for auto-reload.

### Safety model

1. **Diff before apply** — UI shows what changed (rules added/
   removed, stages modified) before deploying.
2. **BPF_PROG_TEST_RUN** — compile and run against test packets
   from the repo's `tests/` dir.  Reject if any test fails.
3. **Atomic rollback** — every deployment records the previous
   state.  One-click revert via A/B table swap (rules) or
   prog array slot swap (stages).
4. **Canary deploy** — attach new program to one interface first,
   watch error counters for N seconds, then roll out to all
   interfaces.
5. **Commit pinning** — lock a source to a specific commit SHA
   or tag.  Auto-sync pulls but won't deploy past the pin.

### Multi-source composition

Multiple repos compose into a single pipeline.  The orchestrator
merges them by `order` / stage slot:

```
Source: acme/fw-rules      → stages 1-3 (geoip, rate-limit, policy)
Source: team/custom-dpi    → stage 4    (QUIC inspection)
Source: local rules.fw     → stage 0    (emergency overrides, highest priority)
```

Conflict resolution: lower stage number wins.  If two sources
claim the same slot, the UI shows a conflict and refuses to
deploy until resolved.

## Mesh Control Plane

Every node in the fleet runs `fd`.  Nodes peer directly over
ZMQ, sharing JSON state.  No central controller — log into any
node's UI, see the entire mesh, apply changes, they propagate.

### Architecture

```
┌─────────┐     ZMQ/mTLS    ┌─────────┐    ZMQ/mTLS    ┌─────────┐
│  fd     │◄───────────────►│  fd     │◄──────────────►│  fd     │
│  node-a │  JSON state      │  node-b │  JSON state     │  node-c │
│  UI ●   │                  │  UI ●   │                 │  UI ●   │
│  XDP    │                  │  XDP    │                 │  XDP    │
└─────────┘                  └─────────┘                 └─────────┘
     ▲                            ▲                           ▲
     │            same state, visible from any node's UI      │
     │                            │                           │
     └────────────────────────────┴───────────────────────────┘
                                  │
                            optionally
                                  │
                                  ▼
                          ┌──────────────┐
                          │  git repo    │
                          │  (journal /  │
                          │  audit trail)│
                          └──────────────┘
```

No hub.  No single point of failure.  Every node is a full
peer with the same view of the mesh.  If a node dies, the
others don't notice beyond one fewer peer.

### How nodes join

```yaml
# /etc/f/fd.yaml
mesh:
  # Peers to connect to on startup.  ZMQ handles reconnect.
  peers:
    - tcp://node-b.internal:9443
    - tcp://node-c.internal:9443
  # Or use multicast/DNS-SD for auto-discovery.
  discovery: mdns

  # mTLS identity.
  cert: /etc/f/node.crt
  key: /etc/f/node.key
  ca: /etc/f/ca.crt

  # Node metadata — used for topology-aware propagation.
  labels:
    env: production
    region: eu-west-1
    role: edge
    layer: 0
```

ZMQ topology: PUB/SUB for state broadcast, REQ/REP for the
existing control socket.  Each node publishes its state on
change; all peers receive it.

### State flow

```
User opens UI on any node
     │
     ▼
Makes a change (add rule, block IP, etc.)
     │
     ▼
fd applies locally to standby table (A/B)
     │
     ├─ self-test passes → flip A/B, publish via ZMQ
     │
     └─ self-test fails  → rollback, don't publish
     │
     ▼
All peers receive update via ZMQ
     │
     ▼
Each peer applies to its own standby table
     │
     ├─ self-test passes → flip, ACK
     │
     └─ self-test fails  → rollback, NACK
        → originating node sees NACK in UI
        → propagation halts for remaining nodes
     │
     ▼
Optionally: fd commits accepted state to git
(audit trail, rollback reference, CI entrypoint)
```

Git becomes the journal, not the deployment mechanism.  CI can
also push via git → pull deploys for planned changes, but
operational changes (emergency block, live tuning) go
UI → ZMQ → mesh → git.  Both directions work.

### Topology-aware propagation

Nodes know their layer from config or auto-discovery (who is
my upstream? who is behind me?).  Changes propagate outside-in:

```
                    internet
                       │
              ┌────────┴────────┐
              ▼                 ▼
         ┌─────────┐     ┌─────────┐
Layer 0  │ edge-a  │     │ edge-b  │   ← apply first
         └────┬────┘     └────┬────┘
              │               │
              ▼               ▼
         ┌─────────┐     ┌─────────┐
Layer 1  │ core-a  │     │ core-b  │   ← apply second
         └────┬────┘     └────┬────┘
              │               │
         ┌────┴────┬──────────┘
         ▼         ▼
    ┌─────────┐ ┌─────────┐
Layer 2 │ app-a   │ │ app-b   │        ← apply last
    └─────────┘ └─────────┘
```

Outer layers fail safe.  If edge-a NACKs, nothing behind it
is touched.  The damage from a bad rule is zero — it only
ever hit one node's standby table.

Propagation with self-test at each hop:

```
edge-a (origin): apply + self-test ✓ → ACK
     │
     ├──► core-a: apply + self-test ✓ → ACK
     │         │
     │         └──► app-a: apply + self-test ✓ → ACK
     │
     ├──► edge-b: apply + self-test ✗ → NACK
     │         "lost gateway 10.0.0.1 after apply"
     │         ← rollback, propagation halted on this branch
     │
     ╳  core-b: never received update
     ╳  app-b:  never received update
```

Each layer tests what matters to its position:

| Layer | Self-test after apply |
|---|---|
| Edge | Can I reach upstream ISP? BGP sessions alive? |
| Core | Can I reach the edges? Routing peers up? |
| App | Can I reach services behind me? Health endpoints? |

### NACK message

```json
{
  "node": "edge-b",
  "status": "rejected",
  "version": "a1b2c3d",
  "reason": "health_check_failed",
  "detail": "gateway 10.0.0.1 unreachable after apply",
  "rollback": "ok",
  "layer": 0
}
```

The UI on any node shows the rollout in real time:

```
┌────────────────────────────────────────────┐
│  Deploy: v2.3.1 → v2.4.0                  │
│                                            │
│  Layer 0 (edge)   [■□] 1/2  ✗  stopped    │
│  Layer 1 (core)   [■ ] 1/2  ◷  partial    │
│  Layer 2 (app)    [■ ] 1/2  ·  partial    │
│                                            │
│  ┌──────────────────────────────────────┐  │
│  │         ● edge-a ✓                  │  │
│  │         ✗ edge-b NACK: lost gateway │  │
│  │            │                         │  │
│  │      ● core-a ✓   · core-b (halted) │  │
│  │            │          │              │  │
│  │      ● app-a ✓    · app-b (halted)  │  │
│  └──────────────────────────────────────┘  │
│                                            │
│  [Retry edge-b]  [Rollback All]            │
└────────────────────────────────────────────┘
```

### State sharing between nodes

Nodes share map data directly over ZMQ:

```
Node A detects port scan from 1.2.3.4
  → publishes to mesh via ZMQ
  → all peers add 1.2.3.4 to blocklist map
  → fleet-wide block in < 1 second
```

Shared map types:

| Map | Direction | Use case |
|---|---|---|
| **Blocklist** | Any node → all peers | Fleet-wide IP/CIDR blocks |
| **Threat intel** | Any node → all peers | Aggregated detections |
| **Rate limit state** | Peer ↔ peer | Distributed rate limiting |
| **GeoIP** | Origin node → all peers | Pushed on DB update |

### CI/CD integration

`f` is a first-class deployment target.  CI pushes to any node
(or to git, and nodes pull).  No SSH, no Ansible, no drift.

**GitHub Actions example:**

```yaml
name: Deploy firewall
on:
  push:
    branches: [main]
    paths: [fw/**]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Compile FWL
        run: |
          fwl compile fw/main.fw -o build/
          fwl test fw/main.fw --packets tests/

      - name: Push to mesh
        run: |
          fctl deploy build/ \
            --node edge-a.internal:9443 \
            --canary 1 --watch 30s
```

Push to any single node.  The mesh propagates it.

**`fctl` CLI for fleet operations:**

```bash
# Deploy via any node — mesh handles propagation.
fctl deploy build/ --node edge-a.internal:9443

# Check fleet status (query any node, sees the whole mesh).
fctl status --node edge-a.internal:9443
# node-a  production/eu-west-1/edge  v2.3.1  4 ifaces  12k rules/s
# node-b  production/us-east-1/edge  v2.3.1  2 ifaces   8k rules/s
# node-c  staging/eu-west-1/edge     v2.2.0  1 iface    1k rules/s

# Rollback entire mesh via any node.
fctl rollback --node edge-a.internal:9443

# Live fleet-wide counter aggregation.
fctl counters --node edge-a.internal:9443
# total:     142M pkts   89 GB
# dropped:    12M pkts    3 GB
# web (80):   98M pkts   71 GB

# Push an emergency block across the fleet.
fctl block 1.2.3.4 --node edge-a.internal:9443

# Pull a specific node's full state.
fctl inspect node-a --node edge-a.internal:9443
```

### Fleet UI

Open the UI on any node, see the entire mesh:

```
┌────────────────────────────────────────────────────┐
│  f — Mesh Overview (via node-a)                    │
│                                                    │
│  Nodes: 47 online  2 degraded  0 offline           │
│  Policy: v2.3.1 (commit a1b2c3d, deployed 12m ago) │
│  Total throughput: 2.4M pps / 1.8 Gbps             │
│                                                    │
│  ┌──────────────────────────────────────────────┐  │
│  │  [Topology view]  [Table view]  [Timeline]   │  │
│  │                                              │  │
│  │  L0 edge     (12 nodes)  1.1M pps   v2.3.1  │  │
│  │  L1 core     (8 nodes)   0.8M pps   v2.3.1  │  │
│  │  L2 app      (4 nodes)   0.3M pps   v2.3.1  │  │
│  │  -- staging  (2 nodes)   12k pps    v2.4.0   │  │
│  │                                              │  │
│  │  Recent deployments:                         │  │
│  │  12m  v2.3.1  production  47/47 nodes  ✓     │  │
│  │  2h   v2.3.0  production  47/47 nodes  ✓     │  │
│  │  3h   v2.4.0  staging      2/2 nodes  ✓      │  │
│  └──────────────────────────────────────────────┘  │
│                                                    │
│  ┌──────────────────────────────────────────────┐  │
│  │  Threat feed (last 5m):                      │  │
│  │  1.2.3.4     → blocked on 47 nodes (scan)    │  │
│  │  5.6.7.0/24  → rate-limited on 12 nodes      │  │
│  │  9.8.7.6     → new, seen on 3 nodes          │  │
│  └──────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────┘
```

Drill into any node → single-node UI (rules, conntrack,
counters, interfaces) for that specific `fd`.

### What this replaces

| Traditional stack | f mesh equivalent |
|---|---|
| iptables/nftables + Ansible | `.fw` rules in git, auto-deployed via mesh |
| Cloudflare / AWS WAF | Self-hosted, same capability at edge |
| SIEM + manual IP blocks | Automatic fleet-wide threat propagation |
| Prometheus + Grafana for fw metrics | Built-in counters + mesh-aggregated dashboard |
| pfsense CARP/pfsync HA | Mesh peers, all identical from git, no state sync |
| Terraform for firewall rules | `fctl deploy` in CI, mesh propagates |
| PagerDuty alert → SSH → add rule | UI on any node, or `fctl block`, instant fleet-wide |

## Mesh Security — Self-Describing Rules

The mesh's own security policy is written in FWL — the same
language used for packet filtering.  The firewall secures
itself.

### The principle

Every boundary in the system is expressible in the same
language the user already knows.  One syntax, one mental model:

| What you're protecting | FWL decorator |
|---|---|
| Network traffic | `@xdp` |
| Mesh propagation | `@mesh` |
| Who can deploy changes | `@deploy` |
| Who can access the UI/API | `@api` |

A network engineer who learned FWL for packet filtering
already knows how to write mesh security policy, deploy
permissions, and API access control.

### Mesh propagation rules

```python
# mesh.fw — rules for the mesh itself

@mesh
def mesh_policy(msg):
  # Only signed messages propagate.
  if not msg.signed:
    drop

  # Operator keys can originate from anywhere.
  if msg.signer in operators:
    allow

  # CI pipeline can push, but only to staging first.
  if msg.signer == "ci" and msg.target.layer != staging:
    drop

  # Nodes can only propagate downstream (outside-in).
  if msg.origin.layer >= msg.target.layer:
    drop

  # Edge nodes can't push to other edges (no lateral).
  if msg.origin.role == edge and msg.target.role == edge:
    drop

  # Rate limit propagation — no update storms.
  rate_limit(10, per=msg.origin)

  # Default: don't propagate.
  drop
```

### Deploy permissions

```python
@deploy
def deploy_policy(req):
  # Only CI and ops team can deploy to production.
  if req.target.env == production:
    if req.signer not in [operators, "ci"]:
      drop

  # Anyone can deploy to staging.
  if req.target.env == staging:
    allow

  # Canary required for production deploys.
  if req.target.env == production and not req.canary:
    drop

  drop
```

### API access control

```python
@api
def api_policy(req):
  # Read-only from monitoring.
  if req.signer == "monitoring" and req.method in [GET]:
    allow

  # Full access from operator keys.
  if req.signer in operators:
    allow

  # UI accessible from management network only.
  if req.src_net == 10.0.0.0/24:
    allow

  drop
```

### Security layers

All three layers stack.  A compromised node can't escalate:

| Attacker has | What they can do |
|---|---|
| Root on one node | Modify local XDP only. Can't publish unsigned changes to mesh. Mesh detects state divergence, alerts, auto-isolates |
| Stolen node mTLS cert | Join mesh as a peer, read state. Can't sign changes (no operator key). Mesh sees unknown peer, `@mesh` rules reject unsigned messages |
| Stolen operator key | Full control (game over — same as any system). Mitigate with key rotation, HSM, short-lived certs |
| Network position (MITM) | Nothing — mTLS on all ZMQ connections |

### State divergence detection

The mesh continuously compares config hashes across peers:

```
node-c config hash: ABC123
all other nodes:    DEF456
node-c didn't receive an update
  → alert: state divergence on node-c
  → auto-isolate: peers stop accepting from node-c
  → UI shows node-c as "diverged / isolated"
```

### Choose your own adventure

The defaults are locked down.  Every boundary is configurable
in FWL:

| Posture | mesh.fw |
|---|---|
| Single box, no mesh | Don't configure `mesh:` in fd.yaml. Done |
| Flat mesh, everyone can push | `@mesh def policy(msg): allow` — 1 line |
| Signed-only propagation | Add `if not msg.signed: drop` — 2 lines |
| Full layered topology with signing + roles + canary | ~20 lines (the full example above) |
| Air-gapped, git-only deploy | Disable ZMQ mesh, each node pulls from git on a timer. No node-to-node traffic at all |

Same tool, same language, same deploy mechanism at every
level of paranoia.

## AI Agent Integration

The entire system is text-in, text-out at every layer.  No
GUIs to click through, no wizards, no interactive prompts.
Every interface is something an AI agent can drive natively.

### Why this matters

An agent can go from a natural language request to a running
fleet deployment in a single pass:

```
Human: "I need 50 edge firewalls across 3 regions.
        Block everything except HTTPS, DNS, and SSH.
        Geo-block Russia and China.  Rate limit SSH
        to 10 connections per source IP.  Canary deploys.
        Layered propagation.  Signed changes only."

Agent:
  1. Writes main.fw          (~15 lines of FWL)
  2. Writes mesh.fw           (~20 lines — propagation + signing)
  3. Writes f.yaml            (3 regions, layer assignments)
  4. Writes deploy.yaml       (canary config, selectors)
  5. Commits to git
  6. CI compiles + tests
  7. Mesh deploys

Time: seconds.  Manual equivalent: days.
```

### Agent-friendly surfaces

Every layer of the system is a text interface:

| Layer | Interface | Agent action |
|---|---|---|
| Policy | `.fw` files | Write FWL (simpler than C, simpler than iptables) |
| Mesh config | `f.yaml` | Write YAML |
| Fleet deploy | `deploy.yaml` | Write YAML (selectors, canary, rollout) |
| Operations | `fctl` CLI | Run commands, parse JSON output |
| Monitoring | REST API | GET endpoints, structured JSON responses |
| Deployment | `git push` | Standard git workflow |
| Debugging | `fctl inspect` | Read node state as JSON |
| Emergency | `fctl block` | One command, fleet-wide effect |

No interface requires a browser, a mouse, or interactive
input.  An agent with shell access and a git credential can
manage the entire fleet.

### Agent-in-the-loop operations

Beyond initial deployment, agents can run continuously:

```
Agent monitors /api/v1/counters on the mesh
     │
     ├─ Sees spike in dropped packets from 5.6.7.0/24
     │  → Queries threat intel API
     │  → Confirms botnet
     │  → Writes updated blocklist, commits, mesh deploys
     │
     ├─ Sees new service on port 8443
     │  → Asks operator: "node-c is receiving traffic on
     │     8443/tcp, not in policy.  Allow or block?"
     │  → Operator says "allow"
     │  → Agent adds rule, commits, mesh deploys
     │
     ├─ Notices node-b latency increasing
     │  → Reads node-b counters, sees rate-limit map full
     │  → Increases rate-limit threshold for that node
     │  → Commits with reason, mesh deploys
     │
     └─ Detects config drift (node diverged from git)
        → Alerts operator
        → Auto-remediates if policy allows
```

### FWL is the key enabler

The reason this works is FWL, not the mesh or the API.  An
agent that has to write BPF C will produce bugs — wrong bounds
checks, padding mismatches, byte-order errors.  An agent that
writes FWL gets:

- Bounds checks generated automatically
- Byte order handled by the compiler
- Protocol guards enforced at compile time
- Struct padding computed, not hand-written
- Verifier errors eliminated by construction

The language is simple enough that an agent can produce
correct policy on the first try, and the compiler catches
the rest.  Same reason humans benefit from FWL over C, but
amplified — agents make more mechanical errors and fewer
conceptual errors.

### Infrastructure as conversation

The end state: you describe your network security posture in
natural language.  An agent translates it to FWL.  The
compiler translates FWL to BPF.  The mesh deploys it across
your fleet.  The agent monitors the result and adjusts.

```
 "block scanners" ──► FWL ──► BPF ──► XDP ──► wire speed
       ▲                                          │
       │          agent monitors + adapts          │
       └───────────────────────────────────────────┘
```

Every layer is deterministic and auditable.  The agent writes
`.fw` files that humans can read.  The compiler emits `.bpf.c`
that engineers can inspect.  Git records every change with
context.  The mesh shows exactly which nodes have which
version.  Nothing is opaque.

## Future Directions

- **LSP server** — syntax highlighting, autocomplete, hover
  docs for `pkt` fields.  The parser already has full type
  info.
- **Live reload** — `fwl watch firewall.fw` recompiles on save
  and signals `fd` to hot-swap via `freplace`.
- **Testing** — `fwl test firewall.fw` runs the generated BPF
  program against crafted packets using `BPF_PROG_RUN`, no
  root required.
- **Visualization** — `fwl graph firewall.fw` emits a pipeline
  diagram (Graphviz DOT) showing stages, maps, and data flow.
- **Import system** — `from fwl.stdlib import syn_proxy` pulls
  in pre-built BPF libraries as pipeline stages.
