# CLI reference

`einheit-f` is both a one-shot command and an interactive shell. Run it with a command as arguments to get one answer and exit; run it with no arguments to get a prompt with completion, history and a status bar.

```
$ einheit-f show system
$ einheit-f
karl@f> show system
```

## Global options

| Option | Meaning |
|---|---|
| `--format table\|json\|yaml\|set` | Output form. Under a machine-readable format the prose goes to stderr, so `\| jq` gets clean JSON and you still see the warnings. |
| `--color always\|never\|auto` | |
| `--ascii` | Force ASCII table borders. |
| `--width N` | Override the detected terminal width. |
| `--locked` | Restricted mode: no shell escapes. |
| `--socket <endpoint>` | `fd` control socket. |
| `--confd-socket <endpoint>` | `f-confd` control socket — the daemon that owns the commit-confirm revert timer. |
| `--system-config <path>` | The system configuration. Default `/etc/f/system.yaml`. |
| `--dnsmasq-conf <path>` | Where the generated dnsmasq config is installed. |
| `--networkd-dir <path>` | Where generated networkd units are installed. |
| `--source <path>` | The main `.fw` policy file. |
| `--lease-file <path>` | dnsmasq's lease database. |
| `--device-journal <path>` | Where device arrival history is recorded. |
| `--pin-path <path>` | BPF map pin directory. |

## The system configuration

| Command | Question it answers |
|---|---|
| `check system` | Does the configuration validate, without applying it? |
| `apply system [force]` | Make it live. `force` discards a hand-edit of a generated file. |
| `apply system confirmed <minutes> [force]` | Make it live with an automatic undo if you do not confirm. See [howto/change-something-safely.md](../howto/change-something-safely.md). |
| `confirm system` | Keep a confirmed apply; cancel the undo. |
| `show system` | What ports, zones and services are declared; whether the ports are physically here; where services will answer. |
| `show services` | Are the backing daemons running, where are they actually bound, and does that match what was asked for? |
| `set address <iface> <cidr\|dhcp>` | Edit an interface's address in `system.yaml` and apply. |
| `no address <iface> [cidr]` | Remove one. |
| `set reservation <mac> <ip> [name]` | Pin a board to an address. |
| `no reservation <mac>` | Unpin it. Removing one that is not there is an error. |
| `set mtu <iface> <bytes>` | Live only — MTU is not in the model, and the command says so. |
| `set link <iface> up\|down` | Live only. |

## Devices on the segment

| Command | |
|---|---|
| `show leases [new\|all]` | What has taken an address, when it appeared, when it was last seen. |
| `watch show leases [window]` | Arrivals as they happen; repaints only on change. |
| `show device <mac\|ip\|name>` | One device, including the connections it has open — joined through NAT, so it works behind a masquerade. |

## The firewall

| Command | |
|---|---|
| `show status` | Daemon status, uptime, attach state. |
| `show firewall` | Program overview. |
| `show firewall rules` | Per-rule detail with hit counts. |
| `show counters` | Named counters from the BPF program. |
| `show zones` | Zones, their interfaces, attach state and XDP mode. |
| `show nat` | Active translations and the masquerade source. |
| `show conntrack` | Connection-tracking table entries. |
| `show interfaces` | Interfaces, addresses, counters. |
| `reload firewall` | Recompile the policy and hot-reload it. A policy that does not compile is never loaded. |
| `clear counters` | Reset per-rule counters. |
| `show log` | Recent daemon log entries. |
| `logs [--follow]` | Daemon logs from the journal. |

## The box itself

| Command | |
|---|---|
| `show ipv6` | Per-zone stance: how many router advertisements arrived, and whether anything autoconfigured anyway. |
| `show time` | The clock, whether it is synchronised, and whether this board can keep time across a power cut. |
| `show storage` | Disk, compiled bundles, and whether log events have been dropped. |
| `daemon start` / `daemon status` | The `fd` unit, via systemd. |
| `doctor` | Framework health checks: transport, schema, theme, keys. |

## Policy files

| Command | |
|---|---|
| `show files` | List `.fw` files. |
| `new file <name>` | Create one. |
| `rename file <old> <new>` | |
| `delete file <name>` | |
| `edit [file]` | Open one in `$EDITOR`. |
| `set editor <name>` | Persist a preferred editor. |

## Candidate configuration

The framework's generic configuration surface — a candidate that is edited, then committed or discarded — sits alongside the `system.yaml` commands above. `configure`, `set`, `delete`, `show diff`, `commit`, `commit confirmed`, `confirm`, `rollback candidate|previous|rescue|to`, `save`, `load factory|merge|replace`, `show config`, `show configs`, `show commits`, `show commit`, `show schema`.

## Shell conveniences

`help`, `explain <command>`, `history`, `alias`, `macro record|end|list|show|run|delete`, `theme list|use`, `statusbar on|off`, `show env`, `shell`, `exit`, `quit`.

`explain` is the one worth knowing: it prints the wire representation, the role required and the session requirement for a command, which answers "why was I refused" without guessing.

---

## Gaps in the command surface

Recorded here because a reader looking for one of these should find out it does not exist rather than conclude they are searching badly.

- **`einheit-f --help` lists no commands.** It prints global options only. The command list exists in the interactive shell (`help`) and in this page. A one-shot user with no terminal has no way to discover the surface.
- **No verb creates a zone or moves an interface into one.** `set address` is the only `system.yaml` mutation besides `set reservation`. Zones, interface pinning, service bindings and the IPv6 stance are edited with an editor.
- **No verb puts content into a policy file.** `new file` creates an empty one and `edit` opens it. Nothing composes a rule.
- **`show firewall rules` is not zone-scoped.** The bundle does not yet carry per-zone rule metadata, so rules are listed flat even when the policy has several zones.
- **The UI has no view for `show leases`, `show device`, `show ipv6`, `show time`, `show storage`, or a pending confirm window.** Those exist only on the CLI.
