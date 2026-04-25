# f — Current State

Snapshot of what exists in the repo today (2026-04-14). Companion to `doc/design.md` and `doc/fwl.md`, which describe the vision. This doc describes reality.

## What f is today

A Linux XDP firewall with a C++23 userspace daemon, a REST/HTMX API server, and a Python compiler for a custom firewall DSL. The full reload story works end-to-end and was demonstrated live: edit a `.fw` file → file watcher fires → `fd` invokes `fwl compile --bundle` → bundle artifacts on disk → BPF program loaded into kernel → atomic XDP swap on the live interface via `XDP_FLAGS_REPLACE` → packet behavior changes on the very next packet without restarting the daemon. Verified with `ping localhost` flipping from 100% drop to 0% drop on a Tier 2 program swap on `lo`. The control plane is partially built and the web UI is vaporware.

## Component status

| Component | Status | Notes |
|-----------|--------|-------|
| `bpf/fw.bpf.c` | working | 5-tuple + CIDR match, conntrack, counters, ring buffer events |
| `libf-engine` (engine.cc, bpf_loader.cc, components.cc, slow_path.cc, watcher.cc, reload.cc, config.cc) | working | BPF lifecycle, A/B swap, ZMQ control, per-CPU counter aggregation, file watcher, reload pipeline, YAML config |
| `libf-api` (api.cc, html.cc) | mostly working | REST JSON + HTMX fragments; attach/detach endpoints missing |
| `fd` daemon | working | runs XDP, accepts Unix-socket commands, watches FWL source for hot reload |
| `fctl` CLI | minimal | `status`, `stop` — no rule-apply command yet |
| `f-api` daemon | working | serves REST on pinned maps via `OpenPinnedMaps()` |
| `ui/` static files | **vaporware** | no `index.html`, no CSS, no JS — API handlers render HTMX fragments that have no page to be swapped into |
| FWL parser | working | Lark grammar, indentation-aware, all three tiers |
| FWL analyzer | working | layer resolution, map allocation, semantic validation, instruction-count estimation with soft/hard warnings |
| FWL BPF C emitter | working | 8 fixtures verified: clang -target bpf clean, BPF verifier accepts, BPF_PROG_TEST_RUN verdicts correct. Covers in/not in, CIDR, TCP flags (scalar extraction), rate_limit (token bucket), geoip (map lookup), conntrack (forward+reverse 5-tuple) |
| FWL config emitter | working | Tier 1 rules → JSON matching engine's RuleKey/RuleValue |
| FWL bundle mode | working | `fwl compile --bundle <dir>` emits manifest.json, rules.json, maps.json, main.bpf.c, main.bpf.o (clang-compiled). JSON envelope on stdout for the daemon to consume |
| `fd` watcher thread | working | poll-based mtime detection, configurable interval, atomic flag for main-thread consumption |
| Reload pipeline | working | spawn fwl via posix_spawnp (no shell) → parse manifest → A/B swap rules → load new BPF object → atomic XDP swap via `XDP_FLAGS_REPLACE` → update `current` symlink. Rolls back on failure |
| `fd.yaml` config | working | YAML schema with engine + watcher sections, sensible defaults, CLI flags override file values |
| Rule persistence | partial | bundle directories (`/usr/share/f/compiled/<version>/`) preserve every successful reload; `current` symlink names the live one. The starting state on cold boot is still whatever's in `current` |
| Rate limiting in XDP | not started | `kRateLimit` action exists but no logic in `fw.bpf.c` (FWL programs implement their own via `rate_limit()` builtin) |
| Conntrack GC | missing | `conntrack_timeout_s` config field unused |
| `kReloadProg` ZMQ command | stubbed | enum value exists, handler empty (the watcher path obsoletes most of its use) |
| C++ tests | working | 72 tests across types, html, protocol, watcher, reload, reload_integration, bpf_loader, config, xdp (xdp suite skips without root). 100% pass |
| FWL tests | working | 111 pytest cases (parser, analyzer, emitter, bundle, config_emitter, clang_compile regression). 100% pass, flake8 clean |
| FWL kernel smoke test | working (manual) | `/tmp/test_fwl_xdp` — 19 test cases across 8 fixtures via BPF_PROG_TEST_RUN. Not yet integrated into the build |

## End-to-end stories that work

### Static rule engine via fctl/socket

```
sudo ./build/fd -i eth0 run                  # load XDP, attach
./build/fctl status                          # confirm attached
# Send a ConfigMsg over /tmp/fd-control.sock  (no fctl wrapper yet)
./build/f-api --port 8080                    # REST on pinned maps
curl localhost:8080/api/v1/counters
```

### Live FWL hot-reload via watcher (new)

```yaml
# /etc/f/fd.yaml
interfaces: [eth0]
watch:
  enabled: true
  interval: 5s
  source: /etc/f/rules.fw
  compiled_dir: /usr/share/f/compiled
  fwl: /usr/local/bin/fwl
```

```
sudo ./build/fd -c /etc/f/fd.yaml run        # starts daemon + watcher

# Edit /etc/f/rules.fw — within `interval` seconds:
#   watcher: change detected
#   reload: compiling … -> /usr/share/f/compiled/<version>
#   reload: ok version=… rules_installed=…
# Tier 2 programs are atomically swapped on every attached interface.
```

Verified live on `lo` (2026-04-14): swap from built-in `fw.bpf.o` (id 290) → FWL `gateway` (id 292) → FWL `allow_all` (id 294); ICMP behavior changed accordingly on each transition.

## Gaps by component

### Engine
- No rule-apply path exposed via `fctl` — only via direct ConfigMsg socket write.
- `kReloadProg` ZMQ command does nothing; the watcher path covers most use cases.
- No persistence beyond the bundle directories — on cold boot, fd loads the built-in `fw.bpf.o` regardless of what `current` points at. The watcher fires on the first source touch after start, but the daemon has no auto-load-on-boot for the latest bundle.

### BPF program
- Rate limiting action returns `XDP_DROP` unconditionally; no token bucket in `fw.bpf.c` (FWL programs do this themselves).
- Conntrack entries never expire.
- No tail-call map — can't compose programs.
- IPv4-only; no IPv6, VLAN, or tunneling.

### API
- `POST /api/v1/interfaces/:name/attach` and `/detach` not wired.
- No WebSocket endpoint (polling via `hx-trigger` is the only live-update path).
- Log ring buffer exists but no downgrade when full.

### UI
- Doesn't exist. API returns HTML fragments but there's no shell page.

### FWL
- Output compiles, loads, and filters correctly for all 8 fixtures. Two verifier-compliance bugs found and fixed during in-kernel testing (double-brace leakage in struct templates; clang rematerializing packet pointer reads after bounds checks, fixed with `asm volatile` barrier after L4 parse + eager scalar extraction for TCP flags).
- `chain stage_name` parses but emits a `bpf_tail_call` with a hash-based slot number — no prog array map is created or populated.
- `conntrack(pkt).state` grammar doesn't exist; conntrack is statement-only.
- Stack budget (512 B) and instruction count (1M) are not modeled.
- BPF_PROG_TEST_RUN harness lives in `/tmp/test_fwl_xdp.c`, not in the project build tree.

### Reload pipeline
- Tier 1 config update applies to engine's rule tables but the active program (if it's an FWL Tier 2 binary) doesn't read those tables — confirmed empirically during the spin (see Q3 below).
- `fd` needs root to traverse `/sys/fs/bpf/` because the mount is `mode=700`. CAP_BPF alone is insufficient. Running fd as root or remounting bpffs are the workarounds; not a code fix.
- On startup `fd` always loads `fw.bpf.o` first, then the watcher's first reload may swap it. There's a brief window where the built-in is the active program. Not a problem for safe defaults (built-in defaults to ALLOW), but worth knowing.

## Cross-cutting open design questions

These are the decisions that shape the next phase. Each has multiple valid answers.

### 1. Config persistence format

When `fd` restarts, how does the last config come back?

**Options:**
- Binary `ConfigMsg` file on disk, reloaded on startup
- YAML/JSON config file, parsed into `ConfigMsg`
- FWL source file (`.fw`), compiled on startup — implicitly chosen by the watcher pattern
- Read `current` symlink at startup, load that bundle directly

The watcher pattern (Q2) implies `.fw` source as the canonical state. But fd doesn't yet do an initial reload at boot — it relies on a mtime change after start. Closing this gap means fd should load `<compiled_dir>/current` on startup if it exists, falling back to `fw.bpf.o`.

### 2. FWL → running daemon bridge (resolved)

**Decision:** `fd` watches a single FWL source file (path from `fd.yaml`) and invokes `fwl compile --bundle` as a subprocess on change. Implemented in `src/watcher.cc` + `src/reload.cc`. The compiler is invoked via `posix_spawnp`, not a shell.

### 3. Tier 1 config vs Tier 2 BPF coexistence (resolved)

**Decision:** unified compilation. Every non-empty `.fw` file produces a single BPF program. Top-level Tier 1 rules are lifted into the program as a prelude, in source order. Pure Tier 1 files synthesize an `@xdp` wrapper named `policy`; mixed files prepend rules to the user's first Tier 2 function. The engine's `rules_a/b` and `cidr_a/b` maps remain in use only by the built-in `fw.bpf.o` (which runs when no FWL source is configured).

**Implications:**
- No runtime coexistence problem: all rules are code in the same program, evaluated in source order with the default action as the trailing fall-through.
- Rule changes require a program recompile and atomic XDP swap (already proven; ~80 ms end-to-end). For huge dynamic blocklists, lift the data into a map via `geoip()` or similar — that pattern remains.
- `rules.json` is still emitted in the bundle for audit, but no longer load-bearing for FWL-driven policy.
- Counter IDs and named counters are allocated by the analyzer at compile time; no negotiation with the engine needed.

### 4. Rule ID allocation

Counters are indexed by rule ID. Currently the engine allocates IDs as rules are inserted. FWL wants to reference rules by name (`count web_traffic`). How do the two spaces reconcile?

**Options:**
- Compiler produces a manifest: `{"web_traffic": 3}`; engine imports it
- Compiler emits IDs directly; engine accepts them
- Names only; engine hashes at load time

### 5. Hot reload for generated programs (resolved)

**Decision:** Yes, atomic via `XDP_FLAGS_REPLACE` with the expected old fd. Implemented in `bpf_loader.cc::ReplaceXdp`. Verified live on `lo` — three swaps within seconds, no traffic loss between swaps. On partial failure across multiple interfaces, `SwapXdpEverywhere` rolls back interfaces that already flipped.

### 6. Combined vs separate daemon

`fd` and `f-api` can run together (one process, two threads) or separate (f-api reads pinned maps). The current code supports both. When do you pick which?

**Status quo (implicit):**
- Single-host deployments → combined (`fd --api`)
- Multi-reader setups → separate
- Not documented anywhere

Should we pick one and delete the other path, or document the trade-off?

### 7. Web UI

The HTMX fragments have nowhere to land. Two paths:

**Options:**
- Build a real SPA shell (`ui/index.html`, Tailwind build, etc.) per `doc/design.md` — 2-3 days
- Drop the UI entirely, lean on REST + a separate frontend project
- Keep the API as-is and ship a minimal `ui/index.html` that just hosts the fragments

### 8. Conntrack GC

Entries never expire. Options:

- Userspace sweeper: periodic iterate + delete in `fd` main loop
- BPF timer hooks (kernel 5.15+): per-entry timers in-kernel
- Passive expiry: check timestamp on lookup, lazy-delete

Userspace sweep is portable and simple; BPF timers are elegant but kernel-dependent.

### 9. FWL verifier compliance (resolved)

All 8 fixtures pass the BPF verifier and filter packets correctly (verified via BPF_PROG_TEST_RUN and confirmed live with ping on `lo`). Remaining latent risks that haven't been stress-tested:
- CIDR match uses scalar bit math, not actual LPM trie lookup — the LPM map is allocated but unused. Works for single CIDRs; won't scale to a populated trie.
- Rate-limit program state tests only the first-packet path (each test reload resets the map). Sustained-rate behavior unverified.

Instruction-count detection now lands in the analyzer (heuristic estimator, soft warning at 5000 insns, hard warning at 50000). Surfaced via `fwl check` per-function output, the bundle envelope's `warnings` field, and the manifest's `estimates` array. All current fixtures estimate at 5–99 insns, well under threshold. Splitting (auto or via explicit `chain`) deferred to a future task — see Q13 below.

### 10. Test harness for FWL

C++ tests use GoogleTest + `BPF_PROG_RUN`. FWL tests use pytest and only check generated text.

**Options:**
- FWL test command that compiles the `.fw`, runs clang, loads via libbpf, injects test packets — full integration
- Unit-only, leave integration testing to users
- Golden-file tests: `.fw` → expected `.bpf.c`, diff against checked-in fixtures

### 11. Mesh / multi-source composition

`doc/fwl.md` describes `@mesh`, `@deploy`, `@api` decorators and git-based multi-source composition. None of this exists. Is it in scope for the next phase, or deferred indefinitely?

### 12. bpffs perms / running as root

CAP_BPF is enough to load BPF programs but not to traverse `/sys/fs/bpf/` (default mount is `mode=700 root:root`). For non-root operation we'd need to either remount bpffs with looser perms, or pin maps to a user-owned bpffs mount under a different path.

**Options:**
- Document "fd must run as root" — simplest, matches operational reality of most kernel-tied tools
- Ship a systemd unit with proper Caps + a private bpffs mount namespace
- Pin to a user-mount of bpffs at `/var/lib/f/bpf` or similar; sidesteps `/sys/fs/bpf` entirely

### 13. Program splitting via tail-call chains (deferred)

The verifier accepts up to ~1M analyzed instructions per program. Detection (Q9) warns when an estimate approaches the limit; splitting is the actual remediation.

**Mechanism design (when needed):**
- `split` instruction (or completing the existing `chain stage_name` grammar) marks where the compiler emits a `bpf_tail_call`.
- Each split section becomes a separate BPF program with its own packet parse prelude — state doesn't survive tail calls.
- Programs are linked via `BPF_MAP_TYPE_PROG_ARRAY` populated at load time. fd allocates slots.
- The bundle manifest grows from one program to many; the engine's hot-swap path must update the prog_array atomically alongside the entry program swap.
- Maps shared across split programs need consistent FDs — extend `LoadProgramFromPath` to share maps within a bundle, or pin and re-open by path.

**Open subquestions:**
- Auto-split (compiler decides) vs explicit (user puts `split` between sections)? Recommend explicit first; auto-split has unpredictable failure modes mid-rule.
- Per-CPU "scratch" map for state across tail calls? Verifier-sensitive; defer.
- Tail call depth limit (33) — surface as another estimate.

**Trigger to do this work:** a real `.fw` file fails the verifier with a complexity rejection. Until then, the warning suffices.
