# `f` deployment guide

**If you are installing an appliance, read [`docs/install.md`](../docs/install.md) instead.** That page is the operator's path from a board with an image on it to a box passing traffic, walked end to end. This page is the reference behind it: what each piece is for, and how to do by hand what the installer does for you.

How to install and run `fd` (the eBPF firewall daemon) on a Linux host. Targets Debian 13 / Ubuntu 24.04 with kernel ≥ 6.6 and `libbpf` ≥ 1.4.

## One-time host setup

### 1. Mount `bpffs`

`fd` pins its BPF maps to `bpffs` so the userspace REST/HTMX server (`f-api`) and external tools can read them without re-loading the program. The mount point must exist before `fd` starts.

```sh
sudo mkdir -p /sys/fs/bpf
mount | grep -q '^bpf on /sys/fs/bpf ' || sudo mount -t bpf -o nosuid,nodev bpf /sys/fs/bpf
```

To make the mount persist across reboots, add to `/etc/fstab`:

```
bpf  /sys/fs/bpf  bpf  nosuid,nodev  0  0
```

The systemd unit shipped under `deploy/systemd/fd.service` declares `After=sys-fs-bpf.mount` and `ConditionPathIsMountPoint=/sys/fs/bpf`, so it will refuse to start if the mount is missing.

### 2. Bundle directory layout

`fd` cold-boots into the most recently compiled FWL bundle by reading `<bundle_dir>/current` (the symlink the reload pipeline maintains). Default:

```
/usr/share/f/compiled/
├── current -> v-2026-05-01T12:00:00Z/
├── v-2026-05-01T12:00:00Z/
│   ├── manifest.json
│   ├── rules.json
│   ├── maps.json
│   ├── geoip.json          # optional, only when the program uses geoip()
│   ├── main.bpf.c
│   └── main.bpf.o
└── v-2026-04-30T18:42:11Z/
    └── ...
```

Bootstrap — but do not do it by hand. `f-install` creates every directory the deployable set names, and `f-install verify` tells you which ones are missing:

```sh
sudo deploy/f_install.py install --build-dir build
f-install verify
```

**There is no `fd` user.** Earlier versions of this page told you to `chown fd:fd` and to `sudo -u fd`, and all three of those commands fail with "invalid user" on every box that has ever been built. `fd.service` runs as root with a capability bounding set of `CAP_BPF CAP_NET_ADMIN CAP_PERFMON CAP_SYS_RESOURCE` and the sandbox described under [Capabilities](#capabilities) below; a separate uid would not remove any of those capabilities, because loading a BPF program and attaching XDP is the whole job.

The first time `fd` runs without a `current` symlink, it falls back to the built-in `fw.bpf.o` (the v0.1 search list under `fw.bpf.o`, `build/fw.bpf.o`, `../bpf/fw.bpf.o`, `/usr/lib/f/fw.bpf.o`). Compile a starter bundle with:

```sh
fwl compile /etc/f/rules.fw --bundle /usr/share/f/compiled/v-init
sudo ln -sfT v-init /usr/share/f/compiled/current
```

On a box provisioned by `firstboot.py` this has already happened: it compiles the starting policy and links `current` before it lets `fd` start, precisely so that the fallback above is never what a new box runs.

### 3. Service install

`f-install` puts every unit in place; enabling them is the separate decision, because which ones a box needs follows from its own `system.yaml`.

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now fd.service f-confd.service einheit-f-ui.service
```

Status:

```sh
systemctl status fd.service
sudo journalctl -u fd.service -f
```

### 4. `f-confd` — the configuration daemon

`f-confd` owns the appliance's system configuration lifecycle: candidate, commit, revision history, rollback, and the **commit-confirmed revert timer**.

The timer is the reason it is a daemon. Changing an interface, an address or a zone can sever the session you are changing it from, and the protection against that is a countdown that keeps running after the session dies. A timer inside the CLI would die with the SSH connection it exists to protect — so it lives here, and survives a restart of `f-confd` itself (an expired window fires as soon as the daemon is back).

```sh
sudo systemctl enable --now f-confd.service
```

With it running:

```
f# apply system confirmed 5          # applied, 5 minutes to confirm
f# confirm system                    # keep it
```

If nobody confirms, the previous configuration — the exact document, not a re-derivation — is put back and the derived networkd/dnsmasq artifacts are regenerated from it.

Without `f-confd`, `apply system` still works as a direct apply, and says so: no revision is recorded, no revert timer is armed, and nothing is reloaded. `apply system confirmed` is *refused* rather than performed, because a confirmed apply with no timer behind it is the one thing worse than no timer at all.

### 5. Forwarding — generated, not a step you perform

`f` routes. A policy that sends a packet from one zone to another sends it to a next hop, and Linux will not resolve one with `net.ipv4.ip_forward` at 0 — the XDP datapath asks the same kernel, so `bpf_fib_lookup` answers `FWD_DISABLED`, the redirect falls back to forwarding the frame with the destination MAC it arrived carrying, and the far side discards it as `PACKET_OTHERHOST`. Nothing on the wire says so.

So it is **not** a line in this guide that you are expected to remember. It is derived from the system configuration model like the networkd units, installed as `/etc/sysctl.d/10-f-forwarding.conf`, and written to the running kernel in the same apply — because a drop-in nobody has read is a box that forwards after the next reboot and not now.

```sh
f-sysconf render sysctl     # what it generates
f-sysconf apply             # install it and apply it now
f-sysconf status            # says NOT-APPLIED when the kernel disagrees
```

`einheit-f apply system` (and f-confd's commit path) do the same thing as part of applying the configuration. `fctl status` reports the live value in its `route` section, and `fd` logs an error at policy load when a policy that redirects meets a kernel that will not forward.

## Capabilities

The unit grants `fd` the smallest cap set that supports the BPF program lifecycle:

| Capability | Why |
|---|---|
| `CAP_BPF` | `bpf()` syscall — load programs, create/update maps |
| `CAP_NET_ADMIN` | `XDP_ATTACH` to a NIC, pinning into `bpffs` |
| `CAP_PERFMON` | Helper-call permissions on kernels that gate them |
| `CAP_SYS_RESOURCE` | Older kernels (≤ 5.10) need this to uplift `RLIMIT_MEMLOCK`; newer kernels ignore it |

`NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `PrivateDevices`, and `RestrictAddressFamilies` are enabled — the daemon runs in a hardened sandbox. `ReadWritePaths` whitelists the three locations it must write to: `/sys/fs/bpf`, `/usr/share/f/compiled`, and `/var/log/f`.

## Troubleshooting cold-boot

`fd` logs the BPF object path it loaded from at INFO level on every start:

```
[INFO] Loaded BPF object from /usr/share/f/compiled/current/main.bpf.o
```

If you see the fall-back path (`/usr/lib/f/fw.bpf.o` or `fw.bpf.o`), the cold-boot bundle is missing. Check:

```sh
ls -l /usr/share/f/compiled/current
# Should print: current -> v-<timestamp>
ls -l /usr/share/f/compiled/current/
# Should hold a manifest.json and one .bpf.o per zone. A manifest
# with no .bpf.o beside it is what a compile without clang produces.
```

A broken symlink is logged at INFO ("not found, falling through to built-in") and the daemon proceeds with the built-in program. The usual cause is that nothing has compiled a bundle yet — `einheit-f reload firewall`, or `fwl compile` as above, produces one.

## Logs and metrics

- `journalctl -u fd.service` — daemon log.
- `sudo cat /sys/fs/bpf/f/counters` is not directly readable; use `f-api` or `bpftool map dump pinned /sys/fs/bpf/f/counters`.
- Per-CPU rule counters: `f-api` exposes them at `GET /api/v1/counters`.
- `__rate_limit_overflow` is a reserved counter that ticks when the per-CPU rate-limit map's bucket key space is exhausted (post-Phase-2 hardening). Watch this during soak; non-zero readings mean the operator should consider a larger `max_entries` or a different `per=` field.

## Soak procedure

For Phase 2 dogfood soak (`dogfood_v02.fw`, ≥ 48h on a dev VM), follow the runbook in `f-hone/deploy/staging/SOAK_RUNBOOK.md`. The runbook handles bundle staging, unit install, and the 1-hour smoke watch before walking away.
