# `f` deployment guide

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

Bootstrap:

```sh
sudo install -d -m 0755 -o fd -g fd /usr/share/f/compiled
sudo install -d -m 0755 -o fd -g fd /var/log/f
```

The first time `fd` runs without a `current` symlink, it falls back to the built-in `fw.bpf.o` (the v0.1 search list under `fw.bpf.o`, `build/fw.bpf.o`, `../bpf/fw.bpf.o`, `/usr/lib/f/fw.bpf.o`). Compile a starter bundle with:

```sh
fwl compile --bundle /usr/share/f/compiled/v-init /etc/f/rules.fw
sudo ln -sfT /usr/share/f/compiled/v-init /usr/share/f/compiled/current
```

### 3. Service install

```sh
sudo cp deploy/systemd/fd.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now fd.service
```

Status:

```sh
systemctl status fd.service
sudo journalctl -u fd.service -f
```

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
sudo -u fd test -r /usr/share/f/compiled/current/main.bpf.o
```

A broken symlink is logged at INFO ("not found, falling through to built-in") and the daemon proceeds with the built-in program. The most common cause is the directory permissions blocking the daemon's uid — fix with:

```sh
sudo chown -R fd:fd /usr/share/f/compiled
```

## Logs and metrics

- `journalctl -u fd.service` — daemon log.
- `sudo cat /sys/fs/bpf/f/counters` is not directly readable; use `f-api` or `bpftool map dump pinned /sys/fs/bpf/f/counters`.
- Per-CPU rule counters: `f-api` exposes them at `GET /api/v1/counters`.
- `__rate_limit_overflow` is a reserved counter that ticks when the per-CPU rate-limit map's bucket key space is exhausted (post-Phase-2 hardening). Watch this during soak; non-zero readings mean the operator should consider a larger `max_entries` or a different `per=` field.

## Soak procedure

For Phase 2 dogfood soak (`dogfood_v02.fw`, ≥ 48h on a dev VM), follow the runbook in `f-hone/deploy/staging/SOAK_RUNBOOK.md`. The runbook handles bundle staging, unit install, and the 1-hour smoke watch before walking away.
