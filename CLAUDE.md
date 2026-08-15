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
./build/tests/test_types --gtest_filter='TypesTest.ConnKey*'

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

**There is one datapath: the compiled bundle.** `fwl compile --bundle` emits one `<zone>.bpf.o` per `@xdp` block plus a `manifest.json`; `fd` loads `<bundle-dir>/current` and attaches each program to its zone's interfaces. A second, v0.1 single-program datapath (`bpf/fw.bpf.c`, `libf-api`, `f-api`, the `rules_a`/`counters`/`config` maps, the ring-buffer slow path, opcodes 1/2/6/7/8) sat beside it until `f-appliance` removed it — see `include/f/bpf_loader.h` for what its fallback did on a real box. **Nothing is loaded when no bundle is staged: `fd` refuses to start.**

- **libf-engine** — bundle lifecycle, ZMQ control socket, map operations. The only library the daemons share.

Executables:

- **fd** — the daemon: loads and attaches the bundle, serves the ZMQ control socket, runs conntrack/NAT GC and the source watcher
- **fctl** — minimal control client (status, stop); what you have left when the CLI is what is broken
- **einheit-f** — the operator CLI; **einheit-f-ui** — the dashboard, which reads everything from `fd` over the control socket
- **f-confd** — commit-confirmed revert timer; **f-sysconf** — `system.yaml` to networkd/dnsmasq/chrony

### Key design patterns

**Control protocol**: ZMQ REQ/REP at `ipc:///run/f/control.sock`. A request is `[1B Cmd][payload]`, the reply is JSON — see `include/f/protocol.h`, which also records which opcode numbers are retired and why they must not be reused.

**Component pattern**: Stateful subsystems (IfaceMgr, ConntrackMgr, NatMgr, RouteMgr, EgressMgr) inherit `Component` with uniform `GetState()`/`SetState()` JSON interface. Each reports what it read from the kernel, never what the model implies.

**Shared types**: `include/f/types.h` holds the structs the daemon reads the emitter's maps through. A layout change there is a compiler/daemon disagreement; `tests/test_types.cc` pins the offsets.

**Error handling**: `std::expected<T, Error<E>>` throughout — no exceptions on control paths.

### FWL Compiler (fwl/)

Python 3.11+ compiler: Lark grammar parser -> typed AST -> BPF C emitter. Three tiers: declarative rules (Tier 1), Python-syntax functions compiling to BPF C (Tier 2), raw C escape hatch (Tier 3). Design doc: `doc/fwl.md`.

### Web UI

`adapters/ui/` is the firewall adapter for the sibling `einheit-ui` framework, built as `einheit-f-ui`. Templates in `adapters/ui/templates/fw/`; every page reads `fd` over the control socket and **the UI opens no BPF map** — the pages that did opened v0.1 names no bundle pins and were blank on every box ever deployed. Seven pages: dashboard, interfaces, policy, counters, zones, NAT, conntrack.

The judgement each page makes about fd's answer lives in `adapters/ui/src/views.cc` (`CountersView`, `PolicyView`, `PolicyFeatures`, `CountersSummary`), not inside the Crow handlers, because a decision inside a handler is not reachable from a test — `tests/test_ui_views.cc` covers the view models and `tests/test_ui_pages.cc` renders the real templates, since a view model that keeps the four counter-availability states apart and a template that draws all four as one blank row is still a blank screen.

## Key Files

- `include/f/types.h` — the structs the daemon reads the emitter's maps through
- `include/f/engine.h` — core daemon interface (EngineInit, EngineRun, GetFullState)
- `include/f/bpf_loader.h` — bundle loading, pin reconciliation, attach plan
- `include/f/protocol.h` — control opcodes, live and retired
- `src/engine.cc` — control loop and command dispatch
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
- `deploy/image/build_image.py` — debootstrap plus the manifest. Must be root (`build_image.py:main`); refuses a rootfs whose binaries do not load (`check_binaries_load`).
- `deploy/image/vm.py` — boots the image under `qemu-system-aarch64`, with a namespace host on each side of it and no address on the host bridges, so "nothing was forwarded" is a measurement. No board needed.
- `deploy/image/firstboot_walk.py` — the acceptance walk: factory boot, gateway boot with traffic through it, and the same disk with its bundle removed.
- `docs/install.md` — the operator path, walked on a real target.
- `einheit-f show install` runs `f-install verify` rather than keeping a
  second list (`adapters/cli/src/transport.cc` `HandleShowInstall`).

```bash
deploy/f_install.py verify          # what this box has of the set
sudo deploy/f_install.py install --build-dir build
pytest -q deploy/tests              # 78 tests, no build needed
deploy/image/vm.py check            # emulation prerequisites
```

**The image boots and firstboot is proven on one** (2026-08-15, `f-rig`): seven defects between `build_image.py` and a provisioned box, none of them previously reachable, the worst a permanent deadlock between `f-firstboot.service` and `fd.service`. `fd` refuses a missing and a corrupt bundle and attaches nothing — **and the box forwards anyway**, because `ip_forward` stays 1 and the kernel has connected routes on both zones. Measured both ways on real sockets. The evidence, and two open findings, are in `~/dev/workspaces/f-rig/context/image-boot-2026-08-15.md`.
