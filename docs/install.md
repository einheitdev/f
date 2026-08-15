# Installing f

From a board with a Debian image on it to a box passing traffic. One path, no options. When you reach the end, [first-hour.md](first-hour.md) takes over and turns the box into a testnet gateway you can browse from.

Every command on this page was run on a real target before the page shipped, and the output shown is what came back. Five defects were found doing that; they are named in the margins where they still shape a step.

**Two ways to do this, and the difference matters:**

| | You are here |
|---|---|
| **A factory board.** Nothing configured, nothing connected, you are at a console or a serial cable. | [The short path](#the-short-path-a-factory-board) — put the image on it and turn it on. |
| **A Debian box you already have.** Reachable over the network, possibly with an address you care about. | [The long path](#the-long-path-a-box-you-already-have) — install by hand, then provision. |

---

## What has to be on the box

Not a list to check by hand. `deploy/manifest.yaml` is the enumeration — every file, where it goes, and one sentence saying what breaks without it — and two commands read it:

```
$ f-install list        # what the set is
$ f-install verify      # what this box has of it
```

There was no such list until recently, and the cost of not having one was this: `build-aarch64/staging/` was a directory somebody maintained by hand, holding `fd`, `fctl` and `einheit-f-ui`. It had never heard of `einheit-f`, `f-confd` or `f-sysconf`. A box built from it started, logged nothing unusual, and had no anti-lockout timer and no way to turn a configuration into a networkd unit. Nobody found out until a service failed to start.

`f-install verify` exits with the answer, so a script does not have to read English:

| exit | verdict | means |
|---|---|---|
| 0 | `complete` | everything in scope is present |
| 1 | `incomplete` | a required item is missing, or is there and will not run |
| 2 | `degraded` | only optional items are missing, or a file that must **not** be present is |
| 3 | `indeterminate` | something in scope could not be checked — not the same as nothing being wrong |

---

## The short path: a factory board

### 1. Put the provisioning file on the boot partition

Optional, and skipping it is a real choice rather than a mistake. Without it the box comes up in the safe default shape described in [step 4](#4-what-you-get) — every port pinned to the MAC it was found on, all in one zone, each asking for a DHCP address, and a policy that drops what it was not asked for. That box filters and does not route, and the `system.yaml` it writes says so in its own comments.

With it, the box comes up as the gateway you described. Copy `/usr/local/share/f/f-provision.yaml.example` to the boot partition as `f-provision.yaml` and edit it:

```yaml
hostname: fw-edge-01
ssh_keys:
  - ssh-ed25519 AAAA... operator@workstation

system:            # this block is /etc/f/system.yaml, verbatim
  zones:
    wan:
      ipv6: off
    testnet:
      ipv6: off
  interfaces:
    wan0:
      mac: "52:54:00:aa:bb:01"
      address: dhcp
      zone: wan
    lan0:
      mac: "52:54:00:aa:bb:02"
      address: 10.10.0.1/24
      zone: testnet
  services:
    dhcp:
      - zone: testnet
        range: 10.10.0.100-10.10.0.200
        lease: 12h
    dns:
      - zone: testnet
        upstream: [9.9.9.9]

policy:
  uplink_zone: wan          # what makes it a gateway rather than a filter
  management_ports: [22, 443]
```

The `system:` block is the system configuration document itself, not a second format that has to be kept in step with it. `f-sysconf check` validates it before the box is provisioned with it, so a typo stops the first boot instead of producing a box that is not the one you described.

If you have a policy of your own, put it beside the provisioning file and name it:

```yaml
policy:
  source: rules.fw
```

It is run through `fwl check` before anything is compiled. A policy that does not compile stops the first boot rather than leaving the box running something else.

> **The v0.1 provisioning format is refused, not ignored.** If your file has `management:`, a top-level `interfaces:`, or `dns:`, firstboot stops and names each key with what replaced it. Those keys described a box that no longer exists; honouring them silently would produce a box that is not the one the file describes.

### 2. Turn it on, with a console attached

`f-firstboot.service` runs once, before `fd`, `f-confd`, `einheit-f-ui` and `f-dnsmasq`, and its output goes to the console as well as the journal. Watch it. This is the one moment where the box tells you everything at once:

```
=== f appliance first boot ===
[    done] verify install: 42 items present
[    done] session: local console; nothing to cut
[    done] read provisioning: read /boot/f-provision.yaml
[    done] hostname: fw-edge-01
[    done] ssh keys: 1 added, 0 already present
[    done] fd.yaml: from /usr/local/share/f/fd.yaml
[    done] system.yaml: from /boot/f-provision.yaml
[    done] apply system: 7 artifact(s) written
[    done] network: networkd reloaded
[    done] policy: generated from the zones in system.yaml
[    done] compile: 2 program(s) in v-20260815T073403Z, current -> v-20260815T073403Z
[    done] plan services: fd.service, f-confd.service, einheit-f-ui.service, f-dnsmasq.service
[    done] start services: 4 unit(s) enabled and running

=== first boot complete ===
    Full report: /var/lib/f/firstboot.json
```

Three things about that transcript are load-bearing:

- **`verify install` runs first.** A board missing `f-confd` has no anti-lockout timer, and finding that out during the change that locks you out is too late. A missing required item stops the run before anything is written, and names the item and the unit it breaks.
- **`start services: 4 unit(s) enabled and running`** is a claim about what systemd reports, not about what `systemctl enable --now` returned. That command exits 0 for a service that started, crashed, and entered auto-restart — and a unit in auto-restart reports `activating`, not `failed`. On the first box this provisioner built, the dashboard had restarted sixty-seven times and every line up to that point said it had started.
- **The marker is written last.** If the run stops, `/etc/f/.provisioned` is not written, so the next boot runs it again. A half-provisioned box that skips its own repair is worse than one that retries.

Exit codes: `0` provisioned, `2` provisioned with something degraded (each degraded step is repeated at the end), `1` stopped — with the step it stopped at, and the box left unprovisioned.

### 3. Check it

```
$ einheit-f show install
every item in the deployable set is present.

verdict: complete (checked /, scope target)

$ einheit-f show zones
 ZONE    │ INTERFACES │ ATTACHED   │ MODE        │ REDIRECTS TO │ MASQ
 wan     │ wan0       │ [OK] wan0  │ [OK] native │ -            │ [--] no
 testnet │ lan0       │ [OK] lan0  │ [OK] native │ wan          │ [OK] yes
```

`ATTACHED` is the column that matters. A bundle that loads and attaches to nothing used to report one zone program and inspect not one packet; the loader refuses that now, and this column is where you see the result.

### 4. What you get

**With a provisioning file**, a gateway: the uplink zone admits replies to flows the inside started, the box's own client traffic, your management ports and ICMP, and drops the rest. The inside zone delivers to the box first — DHCP by port, the gateway address, the management ports — then drops its own broadcast, then masquerades what is left out of the uplink. That ordering is the policy; it is [the storm-shield ordering](../fwl/examples/storm_shield.fw) and it exists because a testnet's DHCP DISCOVER once got masqueraded onto an office network by a policy that had the two verbs in the wrong place.

**Without one**, a filtering box that does not route: every port in zone `mgmt`, each on DHCP, `default drop`, and SSH, HTTPS and ICMP admitted so you can reach it. `/etc/f/system.yaml` says `THIS BOX FILTERS AND DOES NOT ROUTE` in its own header, with what to change.

Either way the starting policy is `default drop`. The provisioner this replaces wrote an allow-everything default, which is a box that passes every packet while every counter, every dashboard and every status line says the firewall is up.

> **One hole in the default policy is deliberate and is named in the file.** XDP sees ingress only, so a DNS query *this box* sent was never entered into conntrack and its answer is not `established`. The generated policy therefore admits answers by source port — udp 67→68, udp 53, udp 123. That is a real hole and a narrow one, and it closes when host-originated flows are tracked on egress.

Now go to [first-hour.md](first-hour.md) §5 onwards, or start changing things with [howto/change-something-safely.md](howto/change-something-safely.md).

---

## The long path: a box you already have

Debian 13 or Ubuntu 24.04, kernel ≥ 6.6.

### 1. Install what f does not ship

```
$ sudo apt install clang llvm libbpf1 bpftool dnsmasq chrony \
    python3 python3-pip python3-yaml systemd-resolved
```

`clang` is not optional even though nothing on the box calls it directly: `fwl` emits BPF C and needs clang to turn it into the `.bpf.o` that `fd` loads. Without it a compile still succeeds and writes a bundle with no objects in it. `f-install verify` names clang for exactly that reason, and firstboot refuses a bundle that has a manifest and no `.bpf.o` beside it.

`dnsmasq` and `chrony` are only needed if a zone binds `dhcp`, `dns` or `ntp`. `f-install verify` reports them as optional with the condition attached.

### 2. Mount bpffs

`fd` pins its maps there, and its unit has `ConditionPathIsMountPoint=/sys/fs/bpf` — so a missing mount is a unit that is *skipped*, which reads as `inactive` in `systemctl` and as nothing at all in the journal.

```
$ sudo mkdir -p /sys/fs/bpf
$ mount | grep -q '^bpf on /sys/fs/bpf ' || \
    sudo mount -t bpf -o nosuid,nodev bpf /sys/fs/bpf
$ echo 'bpf /sys/fs/bpf bpf nosuid,nodev 0 0' | sudo tee -a /etc/fstab
```

### 3. Build

```
$ cmake --preset default && cmake --build --preset default
```

For a board, cross-build instead:

```
$ cmake --preset aarch64 && cmake --build --preset aarch64
```

### 4. Install

```
$ sudo deploy/f_install.py install --build-dir build
```

It does four things in this order, and the order is the point:

1. **Pre-flight.** Every source the manifest names is checked before anything is written. If a *required* one is missing, nothing is installed at all and the message lists every one of them — you get the whole list once instead of one failure per run.
2. **Install.** Each file is put in place by writing a temporary name beside it and renaming over the destination, so upgrading a box whose daemons are running works. Writing through a running binary gets `ETXTBSY` from the kernel, and the install that hit it stopped in the middle with some of the new binaries in place and some not.
3. **Report.** Every item, one line, done or not. An item that could not be installed is named and the rest still are.
4. **Verify.** The same check `f-install verify` runs, straight afterwards, so the install's last word is about the box rather than about itself.

The exit status is the verify verdict, not the install's own.

> **Upgrading a box that predates the installer?** You will see this, and it is not a false positive:
>
> ```
> SKIP shadowed-unit-fd   present and must not be:
>                         /etc/systemd/system/fd.service — pass --remove-stale
> ```
>
> A copy of our own unit in `/etc/systemd/system` outranks the one in `/lib/systemd/system` for the rest of the box's life. An upgrade that changes `fd.service` then changes nothing, and `systemctl cat fd` is the only place the box says so. The same applies to the v0.1 `10-eth0.network` and `20-lan.network` examples if anything ever put them in `/etc/systemd/network`: they sort ahead of the model's own `10-f-eth0.network` and silently win, so the uplink is configured by an example instead of by `/etc/f/system.yaml`.
>
> `f-install` reports these and does not delete them. Pass `--remove-stale` when you have read what they are.

### 5. Check the install before you provision it

```
$ f-install verify
f install — this box

all 42 items present.

verdict: complete (scope: target)
```

On a box that is missing something, every gap is printed with the unit it breaks and the sentence saying what that costs:

```
BINARIES
  MISSING            f-confd                /usr/local/bin/f-confd
                     needed by: f-confd.service
                     Owns the commit-confirmed revert timer, which is the only
                     thing standing between a wrong address and a box you
                     cannot reach. Without it `apply system confirmed` is
                     refused outright.
```

`WILL NOT RUN` is a separate state from `MISSING`, and you want it: the check runs `ldd` on each installed binary, because the question is not whether the file is there but whether it will start. `fd` once shipped linked against a `libspdlog.so.1.16` that lived in the build tree and was on no list — installed, executable, the right size, and dead at exec with status 127.

### 6. Provision

**From the console:**

```
$ sudo /usr/local/share/f/firstboot.py
```

**Over SSH, it refuses:**

```
[  failed] session: this is an SSH session, and provisioning assigns
                    every port an address
           Nothing was written. Run it from the console, or pass --force
           if you can reach the box another way. A first boot on a factory
           board has no session to lose, which is why there is no revert
           timer here — `apply system confirmed` is the command that has one.
```

That is not caution, it is a measurement. A run over SSH on a box with a static management address wrote `address: dhcp` for the port that address was on, reloaded networkd, and the session died in the middle of the run. The box came back on a different address because a DHCP server happened to exist on that segment; on a bench with no DHCP it would have needed a console.

If you can reach the box another way — a second port, a serial console, a hypervisor — `--force` provisions anyway and says what it is risking. If you are provisioning a box you reach over the port being configured, put a provisioning file on it that gives that port the address it already has.

From here it is the same as [step 2 of the short path](#2-turn-it-on-with-a-console-attached).

---

## Building an image

```
$ cmake --preset aarch64 && cmake --build --preset aarch64
$ deploy/image/build_image.py --build-dir build-aarch64
```

It debootstraps a Debian rootfs, installs the packages above into it, and then hands the question of what `f` consists of to the same manifest. It pre-flights *before* debootstrap — half an hour of bootstrapping followed by "f-confd is missing" is the same defect this whole page exists to remove, only slower — and it verifies the staged rootfs before it writes the archive, so an image that is missing something never becomes a board that is.

**This one has not been walked.** There is no aarch64 board on this bench at the moment, so the script's logic is exercised only by the same manifest and staging code that the rest of this page uses on x86-64. Treat the debootstrap and chroot steps as unproven.

---

## When it goes wrong

| symptom | look at |
|---|---|
| `fd.service` is `inactive` and the journal is empty | bpffs is not mounted; the unit was skipped, not started |
| `fd` exits 127 | `f-install verify` — a shared library it needs is not on the box |
| a unit is `activating` and never `active` | `systemctl show <unit> -p NRestarts` — it is flapping, not starting |
| `fwl` raises `FileNotFoundError` on `grammar.lark` | the compiler was installed from a wheel built outside a git checkout; reinstall from a current build |
| firstboot stopped | `/var/lib/f/firstboot.json` has every step and its outcome |
| the box is provisioned and filters nothing | `einheit-f show zones` — check the `ATTACHED` column |

[recovery.md](recovery.md) is the page for a box that was working and stopped.
