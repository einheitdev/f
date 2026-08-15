# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`f` is an eBPF/XDP firewall with a userspace daemon, REST API, web dashboard, and a custom firewall language compiler (FWL).

## Build Commands

```bash
# Configure + build (release)
cmake --preset default && cmake --build --preset default

# Configure + build (debug)
cmake --preset debug && cmake --build --preset debug

# Run all tests
ctest --preset default

# Run a single C++ test binary
./build/tests/test_types

# Run a single GoogleTest case
./build/tests/test_types --gtest_filter='TypesTest.RuleKey*'

# FWL compiler (Python)
cd fwl && pip install -e ".[dev]"
fwl compile <source.fw> -o <output.bpf.c>
pytest tests/              # FWL unit tests
flake8 fwl/                # FWL lint
```

Requires: CMake 3.20+, Ninja, libbpf (system), cppzmq (system). Dependencies fetched via CMake FetchContent: spdlog, Crow, nlohmann_json, CLI11, GoogleTest.

## Lint

C++ uses `.clang-format` (Google style, 80-col) and `.clang-tidy` for static analysis. Python (FWL) uses flake8.

## Architecture

Two static libraries compose the system:

- **libf-engine** — BPF lifecycle, ZMQ control socket, map operations. No HTTP.
- **libf-api** — Crow REST API, HTMX fragment serving. Reads pinned BPF maps; no BPF loading.

Three executables link against them:

- **fd** — main daemon (engine + optional API, epoll loop on main thread, Crow on separate thread)
- **fctl** — CLI client, sends binary commands over Unix socket
- **f-api** — standalone REST/web server (reads existing pinned maps via `OpenPinnedMaps()`)

### Key design patterns

**A/B table swapping**: Two sets of rule maps (rules_a/rules_b, cidr_a/cidr_b). New rules populate the standby table; a single-byte atomic flip in `FwConfig.active_table` activates them. Zero packet loss during updates.

**Binary control protocol**: Unix socket at `/tmp/fd-control.sock`. Framing: `[4B LE length][payload]`. Flat struct serialization — see `include/f/protocol.h`.

**Component pattern**: Stateful subsystems (RuleTable, IfaceMgr, ConntrackMgr) inherit `Component` with uniform `GetState()`/`SetState()` JSON interface.

**Ring buffer slow path**: XDP emits events (new connections, rate exceeded) to a BPF ring buffer consumed by `SlowPath` in userspace.

**Shared C/C++ types**: `include/f/types.h` compiles for both BPF (C) and userspace (C++23) via `#ifdef __cplusplus` guards. Explicit padding to prevent struct layout mismatches.

**Error handling**: `std::expected<T, Error<E>>` throughout — no exceptions on control paths.

### FWL Compiler (fwl/)

Python 3.11+ compiler: Lark grammar parser -> typed AST -> BPF C emitter. Three tiers: declarative rules (Tier 1), Python-syntax functions compiling to BPF C (Tier 2), raw C escape hatch (Tier 3). Design doc: `doc/fwl.md`.

### Web UI (ui/)

Zero-build HTMX + Tailwind CSS (standalone CLI, no npm) + Plotly.js. Crow serves static files and HTMX fragments.

## Key Files

- `include/f/types.h` — shared BPF/userspace data structures
- `include/f/engine.h` — core daemon interface (EngineInit, EngineRun, ApplyConfig, etc.)
- `include/f/protocol.h` — wire protocol types and serialization
- `bpf/fw.bpf.c` — XDP program (packet parsing, rule lookup, conntrack, counters)
- `src/engine.cc` — main epoll loop and command dispatch
- `doc/design.md` — full architecture documentation

## Deployment

`deploy/manifest.yaml` is the single enumeration of what an appliance
needs — every file, where it goes, and one sentence on what breaks
without it. Add a binary to `CMakeLists.txt:351` and
`deploy/tests/test_manifest_covers_build.py:40` fails until it is in the
manifest or in `not_deployed`.

- `deploy/f_install.py` — the manifest's only consumer:
  `list` / `stage` / `install` / `verify`. Exit code is the verdict
  (`deploy/f_install.py:20`).
- `deploy/firstboot/firstboot.py` — runs once per device and decides
  what a new box is. Zones, MAC-pinned interface names, a `default drop`
  starting policy, a compiled bundle, and the units the model implies.
- `deploy/image/build_image.py` — debootstrap plus the manifest.
  Unwalked; no aarch64 board on the bench.
- `docs/install.md` — the operator path, walked on a real target.
- `einheit-f show install` runs `f-install verify` rather than keeping a
  second list (`adapters/cli/src/transport.cc` `HandleShowInstall`).

```bash
deploy/f_install.py verify          # what this box has of the set
sudo deploy/f_install.py install --build-dir build
pytest -q deploy/tests              # 72 tests, no build needed
```
