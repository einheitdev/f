# f — eBPF Firewall Design

## Overview

`f` is a data-plane eBPF firewall managed by a userspace daemon (`fd`).
The layer above (orchestrator, API, CLI) never touches BPF directly — it
speaks to `fd` over a Unix domain socket using a simple binary protocol.

## Architecture

```
┌──────────────────────────────────────────────┐
│  Browser                                     │
│  HTMX + minimal CSS — no build step          │
└──────────┬───────────────────────────────────┘
           │  HTTP (HTML fragments + JSON)
           ▼
┌──────────────────────────────────────────────┐
│  fd (single daemon process)                  │
│                                              │
│  ┌─── Crow thread ──────────────────────┐    │
│  │  REST API   (/api/v1/...)            │    │
│  │  Web UI     (/ serves static + HTMX) │    │
│  └──────────────┬───────────────────────┘    │
│                 │ direct function calls       │
│  ┌─── Main thread ─────────────────────┐     │
│  │  BPF lifecycle (load/attach/detach) │     │
│  │  Map operations (rule swap, reads)  │     │
│  │  Control socket (layer-above IPC)   │     │
│  └──────────────┬──────────────────────┘     │
└─────────────────┼────────────────────────────┘
                  │  bpf() syscalls
                  ▼
┌──────────────────────────────────────────────┐
│  Kernel                                      │
│  ┌────────────────────────────────────────┐  │
│  │ XDP program (per-NIC)                 │  │
│  │ reads rule table + state              │  │
│  └────────────────────────────────────────┘  │
│  ┌────────────────────────────────────────┐  │
│  │ BPF maps                              │  │
│  │ - rules (LPM trie + hash)            │  │
│  │ - conntrack (hash)                    │  │
│  │ - counters (per-CPU array)            │  │
│  │ - config (array, 1 entry)             │  │
│  └────────────────────────────────────────┘  │
└──────────────────────────────────────────────┘
```

The layer above and the web UI are two independent consumers of the
same daemon.  Layer above uses the Unix socket (binary protocol).
Web UI uses the Crow REST API (JSON).  Both call the same underlying
functions — no duplication of logic.

## Data Structures (Userspace)

All shared between BPF and userspace via `#include` from a common header.

```cpp
// Shared BPF/userspace types.  Packed, no padding.
// Keep hot fields first for cache-friendly map lookups.

enum class Action : uint8_t {
  kDrop = 0,
  kAllow = 1,
  kRateLimit = 2,
};

enum class Proto : uint8_t {
  kAny = 0,
  kTcp = 6,
  kUdp = 17,
  kIcmp = 1,
};

// LPM trie key — variable-length prefix.
struct LpmKey {
  uint32_t prefixlen;
  uint32_t addr;
};

// Hash map key — exact 5-tuple match.
struct RuleKey {
  uint32_t src_addr;
  uint32_t dst_addr;
  uint16_t src_port;
  uint16_t dst_port;
  Proto proto;
  uint8_t pad[3];
};

struct RuleValue {
  Action action;
  uint8_t pad[3];
  uint32_t rate_pps;  // Only meaningful when action == kRateLimit.
};

// Per-rule counters.  Per-CPU array, indexed by rule_id.
struct RuleCounter {
  uint64_t packets;
  uint64_t bytes;
};

// Connection tracking entry (BPF hash map).
struct ConnKey {
  uint32_t src_addr;
  uint32_t dst_addr;
  uint16_t src_port;
  uint16_t dst_port;
  Proto proto;
  uint8_t pad[3];
};

struct ConnValue {
  uint64_t last_seen_ns;
  uint64_t packets;
  uint8_t state;  // SYN_SENT, ESTABLISHED, FIN_WAIT, ...
  uint8_t pad[7];
};

// Global config (array map, 1 entry).
struct FwConfig {
  Action default_action;
  uint8_t active_table;  // 0 or 1 — indexes A/B rule tables.
  uint8_t conntrack_enabled;
  uint8_t pad[1];
  uint32_t conntrack_timeout_s;
};
```

## Control Interface

### Protocol

Layer above connects to `fd` via a Unix stream socket
(default: `/run/f/fd.sock`).

Message framing: `[4B little-endian length][payload]`.
Payload is a flat struct, not JSON — no parsing overhead,
trivial to generate from any language with a struct pack.

### Commands

```cpp
enum class Cmd : uint8_t {
  kApplyConfig = 1,  // Full rule set replacement (A/B swap).
  kGetCounters = 2,  // Read per-rule packet/byte counters.
  kGetStatus   = 3,  // Daemon + program state.
  kReloadProg  = 4,  // Detach/re-attach XDP program.
  kStop        = 5,  // Graceful shutdown.
};
```

### How each command works

**kApplyConfig** — atomic rule replacement

1. Layer above sends a `ConfigMsg`:
   ```cpp
   struct ConfigMsg {
     Cmd cmd;              // kApplyConfig
     uint8_t pad[3];
     Action default_action;
     uint8_t conntrack_enabled;
     uint8_t pad2[2];
     uint32_t conntrack_timeout_s;
     uint32_t rule_count;
     // Followed by rule_count × {RuleKey, RuleValue} pairs.
   };
   ```
2. `fd` populates the *standby* rule table (whichever of A/B is
   not currently active).
3. `fd` flushes the standby table, inserts all new rules.
4. `fd` flips `FwConfig.active_table` (single 1-byte map update).
5. XDP program reads `active_table` on next packet — atomic cutover.
6. `fd` responds with success/failure + rule count installed.

Zero packet loss.  The old table stays valid until the flip.

**kGetCounters**

1. `fd` reads per-CPU counter arrays, aggregates across CPUs.
2. Returns array of `RuleCounter` structs indexed by rule ID.

**kGetStatus**

1. Returns daemon PID, uptime, attached interfaces, active table
   index, program load time, rule count.

**kReloadProg**

1. `fd` compiles (or loads pre-compiled) BPF object.
2. Calls `bpf_xdp_attach` with `XDP_FLAGS_REPLACE` for atomic swap.
3. Pinned maps survive — rules and conntrack state preserved.

**kStop**

1. Detaches XDP programs from all interfaces.
2. Unpins maps from bpffs.
3. Daemon exits.

## BPF Map Layout

| Map | Type | Key | Value | Notes |
|-----|------|-----|-------|-------|
| `rules_a` | `BPF_MAP_TYPE_HASH` | `RuleKey` | `RuleValue` | Table A |
| `rules_b` | `BPF_MAP_TYPE_HASH` | `RuleKey` | `RuleValue` | Table B |
| `cidr_a` | `BPF_MAP_TYPE_LPM_TRIE` | `LpmKey` | `RuleValue` | CIDR table A |
| `cidr_b` | `BPF_MAP_TYPE_LPM_TRIE` | `LpmKey` | `RuleValue` | CIDR table B |
| `conntrack` | `BPF_MAP_TYPE_HASH` | `ConnKey` | `ConnValue` | Connection state |
| `counters` | `BPF_MAP_TYPE_PERCPU_ARRAY` | `uint32_t` | `RuleCounter` | Per-rule stats |
| `config` | `BPF_MAP_TYPE_ARRAY` | `uint32_t` | `FwConfig` | 1 entry, index 0 |

All maps pinned to `/sys/fs/bpf/f/` so they survive daemon restart.

## XDP Program Flow

```
packet in
    │
    ├─ parse eth/ip/tcp/udp headers
    │
    ├─ read config.active_table
    │
    ├─ lookup exact match in rules_{a|b}
    │  found? → apply action → update counter → XDP_DROP / XDP_PASS
    │
    ├─ lookup CIDR in cidr_{a|b}
    │  found? → apply action → update counter → XDP_DROP / XDP_PASS
    │
    ├─ if conntrack_enabled:
    │    lookup ConnKey in conntrack
    │    established? → XDP_PASS
    │    reply direction? → create entry, XDP_PASS
    │
    └─ apply default_action → XDP_DROP / XDP_PASS
```

## Daemon (`fd`) Internals

```cpp
// Core daemon state — single struct, no classes.
struct Daemon {
  int listen_fd;               // Unix control socket.
  int epoll_fd;                // Main thread event loop.

  // BPF handles.
  int prog_fd;
  int rules_a_fd, rules_b_fd;
  int cidr_a_fd, cidr_b_fd;
  int conntrack_fd;
  int counters_fd;
  int config_fd;

  // Attached interfaces.
  struct IfAttach {
    int ifindex;
    char name[16];
  };
  IfAttach interfaces[16];
  uint32_t iface_count;

  FwConfig current_config;

  // Crow runs on its own jthread.
  std::jthread api_thread;
  uint16_t api_port;
  std::string static_dir;  // Path to ui/.

  // Shared log ring buffer for /api/v1/log.
  std::shared_ptr<RingBufferSink_mt> log_sink;
};
```

Two threads total:

| Thread | Role |
|--------|------|
| Main | epoll loop: control socket + BPF map ops |
| Crow | HTTP server: REST API + static files |

Crow handlers call BPF map functions directly (map ops are
thread-safe).  For operations that touch daemon state (attach,
detach, reload), the Crow handler posts a command to the main
thread's epoll via an eventfd.

Follows the OTC.Relay/Hyper-DERP pattern of plain structs + free
functions:

```cpp
auto DaemonInit(std::string_view sock_path,
                std::span<const std::string> ifaces)
    -> std::expected<Daemon, Error<DaemonError>>;

auto DaemonRun(Daemon& d, std::stop_token stop)
    -> std::expected<void, Error<DaemonError>>;

auto DaemonStop(Daemon& d) -> void;

auto ApplyConfig(Daemon& d, const ConfigMsg& msg,
                 std::span<const std::byte> rule_data)
    -> std::expected<uint32_t, Error<DaemonError>>;

auto GetCounters(const Daemon& d, uint32_t rule_count)
    -> std::expected<std::vector<RuleCounter>, Error<DaemonError>>;
```

## REST API (Crow)

Crow runs on a `std::jthread` inside `fd`.  Same process, no IPC
overhead — API handlers call BPF map functions directly.

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/status` | Daemon state, uptime, attached interfaces |
| `GET` | `/api/v1/rules` | Current rule set (JSON) |
| `PUT` | `/api/v1/rules` | Replace full rule set (A/B swap) |
| `POST` | `/api/v1/rules` | Add single rule |
| `DELETE` | `/api/v1/rules/:id` | Remove single rule |
| `GET` | `/api/v1/counters` | Per-rule packet/byte counters |
| `GET` | `/api/v1/conntrack` | Active connection table |
| `GET` | `/api/v1/interfaces` | Attached interfaces + XDP status |
| `POST` | `/api/v1/interfaces/:name/attach` | Attach XDP to interface |
| `POST` | `/api/v1/interfaces/:name/detach` | Detach XDP from interface |
| `GET` | `/api/v1/log` | Recent log entries (ring buffer) |

### HTMX fragments

The same endpoints serve HTML when `Accept: text/html` or when
called with HTMX headers (`HX-Request: true`).  Crow checks the
header and returns JSON or an HTML fragment accordingly:

```cpp
CROW_ROUTE(app, "/api/v1/rules")
([&](const crow::request& req) {
  auto rules = GetRules(daemon);
  if (req.get_header_value("HX-Request") == "true") {
    return RenderRulesFragment(rules);
  }
  return crow::response(RulesToJson(rules));
});
```

No template engine needed.  Fragments are built with a small
`Html` helper that writes directly to a `std::string`:

```cpp
// Inline HTML builder — no dependencies.
struct Html {
  std::string buf;
  auto Tag(std::string_view t, std::string_view attrs,
           std::string_view body) -> Html& {
    std::format_to(std::back_inserter(buf),
                   "<{} {}>{}</{}>", t, attrs, body, t);
    return *this;
  }
};
```

## Web UI (HTMX)

Single-page feel, zero JavaScript build tooling.  Crow is the
only server — serves static assets, HTML fragments, JSON, and
optionally WebSocket for live push.

### Stack

- **HTMX** (~14 KB) — DOM swaps from server HTML fragments
- **Tailwind CSS** (standalone CLI, build-time) — utility
  classes, only emits CSS for classes actually used (~8 KB)
- **Plotly.js** (~1 MB) — full-featured charting: time-series,
  heatmaps, geo maps, sankey flow diagrams.  Worth the size
  for an admin dashboard that loads once.
- No bundler, no transpiler, no node_modules

### Build-time CSS

Tailwind standalone is a single binary, no npm.  CMake runs it
at build time:

```cmake
add_custom_command(
  OUTPUT ${CMAKE_BINARY_DIR}/ui/style.css
  COMMAND tailwindcss -i ui/input.css -o ui/style.css
          --minify
  DEPENDS ui/input.css ui/index.html
  COMMENT "Tailwind CSS"
)
```

`input.css` contains only the Tailwind directives:

```css
@tailwind base;
@tailwind components;
@tailwind utilities;
```

Output is ~8 KB because it tree-shakes to only the classes
referenced in the HTML files.

### Pages

| Page | URL | What it shows |
|------|-----|---------------|
| Dashboard | `/` | Status, traffic graph (uPlot), top talkers |
| Rules | `/rules` | Rule table with add/edit/delete |
| Conntrack | `/conntrack` | Live connection table |
| Interfaces | `/interfaces` | NIC list, attach/detach |
| Log | `/log` | Scrolling log tail |

### How it works

```html
<!-- rules page: load rules table on page load -->
<div hx-get="/api/v1/rules" hx-trigger="load"
     hx-swap="innerHTML">
</div>

<!-- delete a rule, re-render table -->
<button hx-delete="/api/v1/rules/3"
        hx-target="#rules-table"
        hx-swap="outerHTML"
        class="px-3 py-1 bg-red-600 text-white rounded
               hover:bg-red-700">
  Delete
</button>

<!-- live counters: poll every 2s -->
<div hx-get="/api/v1/counters" hx-trigger="every 2s"
     hx-swap="innerHTML">
</div>

<!-- traffic chart: JSON endpoint, Plotly renders -->
<div id="traffic-chart" class="h-48 w-full"></div>
<script>
  // Poll /api/v1/counters (JSON), feed to Plotly.
  // ~20 lines of vanilla JS, no framework.
</script>
```

### Live updates

Two options, both supported:

1. **HTMX polling** — `hx-trigger="every 2s"` on counter/
   conntrack divs.  Simple, no extra code.
2. **WebSocket** (Crow native) — daemon pushes counter
   snapshots.  Lower latency, less overhead at scale.
   HTMX has built-in WebSocket support via `hx-ws`.

### Static file serving

Crow serves `/static/*` from the `ui/` directory.

```
ui/
├── index.html         # Shell page + nav
├── htmx.min.js        # Vendored, ~14 KB
├── plotly.min.js      # Vendored, ~1 MB
├── input.css          # Tailwind directives (source)
└── style.css          # Tailwind output (built, ~8 KB)
```

Total UI payload: **~1 MB**.  Dominated by Plotly, which loads
once and caches.  No CDN dependency.

## Error Handling

Same pattern as OTC.Relay and Hyper-DERP:

```cpp
enum class DaemonError : uint8_t {
  kBpfLoadFailed,
  kBpfAttachFailed,
  kMapUpdateFailed,
  kSocketError,
  kInvalidConfig,
  kAlreadyAttached,
};

template <typename E>
struct Error {
  E code;
  std::string message;
};
```

All public functions return `std::expected<T, Error<DaemonError>>`.
No exceptions on the control path.

## Build & Dependencies

- **C++23**, Clang preferred, CMake + Ninja
- **libbpf** — BPF program loading, map management
- **clang** (BPF target) — compile `.bpf.c` → `.bpf.o`
- **Crow** (FetchContent) — HTTP/REST + static file serving
- **spdlog** — logging
- **CLI11** — CLI argument parsing
- **Google Test** — unit tests
- **HTMX + Pico CSS** — vendored static files, no npm

## Project Layout

```
f/
├── doc/
│   └── design.md
├── include/f/
│   ├── types.h          # Shared BPF/userspace structs
│   ├── daemon.h         # Daemon state + free functions
│   ├── error.h          # Error<E> template
│   ├── protocol.h       # Control socket message types
│   ├── api.h            # Crow REST API setup + handlers
│   ├── html.h           # Html fragment builder
│   └── bpf_skel.h       # Generated BPF skeleton header
├── src/
│   ├── main.cc          # CLI parsing, daemon lifecycle
│   ├── daemon.cc        # epoll loop, command dispatch
│   ├── api.cc           # REST endpoints + HTMX fragments
│   ├── html.cc          # Html rendering helpers
│   ├── bpf_loader.cc   # libbpf program load/attach
│   └── config.cc       # ConfigMsg → map operations
├── bpf/
│   ├── fw.bpf.c         # XDP firewall program
│   └── vmlinux.h        # Kernel type definitions
├── ui/
│   ├── index.html       # Shell page
│   ├── htmx.min.js      # Vendored HTMX (~14 KB)
│   └── pico.min.css     # Vendored Pico CSS (~10 KB)
├── tests/
│   ├── test_protocol.cc
│   ├── test_config.cc
│   ├── test_api.cc
│   └── test_daemon.cc
├── cmake/
│   └── bpf.cmake        # BPF compile rules
├── CMakeLists.txt
├── CMakePresets.json
├── .clang-format
├── .clang-tidy
└── CPPLINT.cfg
```

## Integration Example

Layer above (e.g., orchestrator) applies a new firewall config:

```cpp
// 1. Connect to daemon.
int fd = socket(AF_UNIX, SOCK_STREAM, 0);
connect(fd, "/run/f/fd.sock");

// 2. Build message.
ConfigMsg msg{
    .cmd = Cmd::kApplyConfig,
    .default_action = Action::kDrop,
    .conntrack_enabled = 1,
    .conntrack_timeout_s = 300,
    .rule_count = 2,
};
RuleKey k1{.dst_port = 443, .proto = Proto::kTcp};
RuleValue v1{.action = Action::kAllow};
RuleKey k2{.dst_port = 22, .proto = Proto::kTcp};
RuleValue v2{.action = Action::kDrop};

// 3. Send: header + rules.
send_msg(fd, msg, {{k1, v1}, {k2, v2}});

// 4. Read response.
auto resp = recv_response(fd);
// resp.success == true, resp.rules_installed == 2
```

No BPF knowledge needed.  The layer above packs structs and sends
them over a socket.  `fd` handles everything else.
