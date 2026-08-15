# `f` deployment guide

**If you are installing an appliance, read [`docs/install.md`](../docs/install.md) instead.** That page is the operator's path from a board with an image on it to a box passing traffic, walked end to end. This page is the reference behind it: what each piece is for, and how to do by hand what the installer does for you.

How to install and run `fd` (the eBPF firewall daemon) on a Linux host. Targets Debian 13 / Ubuntu 24.04 with kernel ≥ 6.6 and `libbpf` ≥ 1.4.

## One-time host setup

### 1. Mount `bpffs`

`fd` pins the bundle's shared maps to `bpffs` so that every zone program resolves `conntrack` and `fwl_nat` to one kernel map, and so that flow state survives a restart of the daemon. The mount point must exist before `fd` starts.

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

**`fd` will not start without a compiled bundle at `/usr/share/f/compiled/current`.** Compile one:

```sh
fwl compile /etc/f/rules.fw --bundle /usr/share/f/compiled/v-init
sudo ln -sfT v-init /usr/share/f/compiled/current
```

On a box provisioned by `firstboot.py` this has already happened: it compiles the starting policy and links `current` before it lets `fd` start.

This page used to describe a fallback here instead — a built-in `fw.bpf.o` that `fd` searched for under `fw.bpf.o`, `build/fw.bpf.o`, `../bpf/fw.bpf.o` and `/usr/lib/f/fw.bpf.o` when no bundle was staged, with instructions to put one at the last of those. **If you followed them, delete `/usr/lib/f/fw.bpf.o`.** It is the v0.1 single-program firewall, unrelated to anything `fwl` compiles, and its config map was seeded `default_action = allow` on load — so a box that lost its `current` symlink came up attached, READY, green in `systemctl` and in `show zones`, and passing every packet. Refusing to start is the replacement, and it is the better failure: an appliance that is down is visibly down.

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

### 5. Forwarding — the box fails CLOSED, and nothing here is a step you perform

`f` routes. A policy that sends a packet from one zone to another sends it to a next hop, and Linux will not resolve one with `net.ipv4.ip_forward` at 0 — the XDP datapath asks the same kernel, so `bpf_fib_lookup` answers `FWD_DISABLED`, the redirect falls back to forwarding the frame with the destination MAC it arrived carrying, and the far side discards it as `PACKET_OTHERHOST`. Nothing on the wire says so.

**It routes only while it is filtering.** `fd` owns the running value of `net.ipv4.ip_forward`: it lowers it on the way in, raises it once a compiled bundle is attached to at least one interface, and lowers it again when it stops, when an attach leaves nothing in the packet path, and — via `ExecStopPost` — when it is killed. `/etc/sysctl.d/10-f-forwarding.conf` sets it to **0** and is only the boot-time floor, for the window before `fd` has spoken and for a box on which it never starts.

This reverses an earlier decision, and the measurement that reversed it is worth knowing before you meet it. A provisioned box with its compiled bundle removed refused to start `fd` — correctly, loudly, `activating/auto-restart`, no XDP program anywhere — and **went on routing**, because the drop-in had set forwarding once at provisioning time and `systemd-sysctl` reapplied it every boot. An unsolicited inbound TCP connection the healthy box refused with zero frames on the inside wire completed with four, and outbound traffic left un-masqueraded carrying inside addresses, because the NAT lived in the XDP program that was not there. A box that does not forward is a fault you can see; a box that forwards unfiltered is one you cannot.

**So do not "fix" a box that is passing no traffic by setting the sysctl.** It will be back at 0 within seconds, and the reason is written down in two places:

```sh
fctl status | grep forwarding      # the row, and why it reads what it reads
journalctl -u fd | grep forwarding # every raise and every lower, with its reason
```

The `forwarding` row is rendered on every `fctl status`, in every state, and reads one of four ways:

| Row | What it means | What to do |
|-----|---------------|------------|
| `on (cold boot: datapath armed on N interface(s))` | Healthy. | — |
| `OFF — this box is not routing (…)` | `fd` closed it: nothing is in the packet path. | Fix the reason it names — usually a bundle that will not load or a zone interface that does not exist. `journalctl -u fd`. |
| `OFF, and fd did not do it` | The datapath IS armed and something else set the knob to 0. `fd` reports this and deliberately does not override it. | `sysctl -w net.ipv4.ip_forward=1`, then find what set it. |
| `ON WITHOUT A DATAPATH` | Seen only in the seconds before `fd` closes it. | Nothing; it closes itself. If it persists, `fd` is not running. |

`f-sysconf` still generates and installs the drop-in, and no longer writes the running kernel at all — `apply system` is what you run to change a DNS server and must not be able to take the office offline as a side effect:

```sh
f-sysconf render sysctl     # what it generates (the floor: 0)
f-sysconf apply             # install it; touches no running knob
f-sysconf status            # reports the live value as `owned-by-fd`
```

**Recovery: "it stopped forwarding, now what".** Read the `forwarding` row first. If it says `OFF — this box is not routing`, the firewall is not in the packet path and that is the fault to chase; `fctl status` above the row says how many interfaces are attached, and `journalctl -u fd` says why the load or the attach failed. Restoring forwarding by hand fixes nothing and hides the fault: an armed box is one `systemctl restart fd` away, and an unarmed one must not forward.

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

`fd` names the bundle it loaded, how many zone programs it holds, and — the number that matters — how many interfaces it actually attached to:

```
[INFO] Cold-boot: loading multi-zone bundle from /usr/share/f/compiled/current...
[INFO] Multi-zone bundle loaded: 2 zone program(s), attached to 2 interface(s).
```

If instead the unit fails with `is not a compiled bundle`, the cold-boot bundle is missing. Check:

```sh
ls -l /usr/share/f/compiled/current
# Should print: current -> v-<timestamp>
ls -l /usr/share/f/compiled/current/
# Should hold a manifest.json and one .bpf.o per zone. A manifest
# with no .bpf.o beside it is what a compile without clang produces.
```

A broken symlink, a directory with no `manifest.json`, and a manifest naming no `@xdp` programs are all the same answer: the unit does not start and says which directory it looked in. The usual cause is that nothing has compiled a bundle yet — `einheit-f reload firewall`, or `fwl compile` as above, produces one.

## Logs and metrics

- `journalctl -u fd.service` — daemon log.
- `einheit-f show counters` — a policy's `count` statements write into that zone's own `fwl_counters_<zone>` map, and this reads it, resolving each slot to the name the policy gave it from the `// fwl_counter_table:` block the compiler wrote into the zone's generated C. `sudo bpftool map dump pinned /sys/fs/bpf/f/fwl_counters_<zone>` is still the raw view; it gives slot numbers and no names. `show firewall rules` remains removed — it read a different, v0.1 map. What replaced the question it was asked for is `einheit-f show policy`, which reports the rules `fd` has LOADED (opcode 13, captured at load beside the objects) beside the `.fw` on disk, and says whether the two still agree.
- `__rate_limit_overflow` is a reserved counter that ticks when the per-CPU rate-limit map's bucket key space is exhausted (post-Phase-2 hardening). It is listed by `show counters` like any other. Watch this during soak; non-zero readings mean the operator should consider a larger `max_entries` or a different `per=` field.

## Soak procedure

For Phase 2 dogfood soak (`dogfood_v02.fw`, ≥ 48h on a dev VM), follow the runbook in `f-hone/deploy/staging/SOAK_RUNBOOK.md`. The runbook handles bundle staging, unit install, and the 1-hour smoke watch before walking away.

## Building an image, and booting one without a board

`deploy/image/build_image.py` debootstraps a Debian arm64 rootfs, installs the packages the appliance needs, and hands the question of *what f consists of* to the manifest. It must be run as root — everything it writes lives in a root-owned rootfs — and it will not write an archive for a rootfs whose binaries cannot load, which it establishes by running `ldd` inside the chroot rather than trusting the package list.

```sh
sudo apt-get install -y debootstrap qemu-user-static binfmt-support qemu-system-arm
cmake --preset aarch64 && cmake --build --preset aarch64
deploy/image/vm.py check     # names any missing prerequisite at once
sudo deploy/image/build_image.py --build-dir build-aarch64 --out /tmp/img
```

`--mirror` exists because the default is not always reachable: debootstrap fetches with `wget`, which has no happy-eyeballs fallback, so it takes the AAAA of `deb.debian.org`'s anycast address and waits out its timeout per package if that POP is unreachable over IPv6.

You do not need an aarch64 board to boot the result. `deploy/image/vm.py` turns the rootfs into a disk (adding a generic Debian kernel, which the appliance image does not carry — on the product board it comes from the vendor BSP), boots it under `qemu-system-aarch64`, and builds a bench around it: three NICs, two of them on host taps whose bridges carry **no address on the host**, each reaching a real Linux host in its own namespace. The only path from one side to the other is through the appliance, which is what makes "nothing was forwarded" a measurement rather than a hope.

```sh
deploy/image/firstboot_walk.py --rootfs /tmp/img/rootfs --out /tmp/vm
```

That walks three boots: the factory shape with no provisioning file, a gateway with traffic put through it both ways, and the same disk with its bundle removed — where `fd` must refuse and the traffic the healthy box carried must stop. Every check in the third boot is paired with a control that must still pass, because an image that failed to boot produces the same silence on the wire as an appliance refusing correctly.

Emulation is TCG. A boot takes about a minute and a `fwl compile` about seven seconds; do not measure throughput on it.
