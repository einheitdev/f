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

## Two documents, two lifecycles

Read this before the tables, because the single most confusing thing about this CLI used to be that it looked like it had two rival configuration systems. It has two, they are not rivals, and the reason there are two is that there are two documents:

| The document | What is in it | How a change is made live |
|---|---|---|
| `/etc/f/system.yaml` | Ports, zones, addresses, DHCP, DNS, NTP, the IPv6 stance. What the box *is*. | `apply system`, `apply system confirmed <minutes>`, `confirm system` |
| `/etc/f/*.fw` | The firewall policy. What the box *does to packets*. | `configure` … `commit` / `rollback candidate`, or a single `set rule` / `set forward` which applies on the spot |

Every `set`/`no` verb below edits one of those two documents in place — comments, ordering and formatting preserved — and then takes that document's own path to becoming live. There is no third place a setting can live.

The two lifecycles are not symmetric, and it is worth knowing how. The **system configuration** has recorded revisions (`show commits`, `rollback system`) and an anti-lockout timer (`apply system confirmed`), because the changes in it are the ones that can cut your access to the box. The **policy** has a candidate you snapshot and put back (`configure` … `rollback candidate`), and no revision history: a bad policy is recovered from the console or by `fctl`, and [recovery.md](../recovery.md) is written around that.

**What used to be here and is now gone.** The framework ships a generic candidate-config family (`set <path> <value>`, `delete <path>`, `save`, `load factory|merge|replace`, `rollback previous|rescue|to`, `commit confirmed`, `confirm`, `show configs`, `show commit`). This product implements none of it. `set <path> <value>` in particular parsed its arguments, answered `status: set`, and wrote nothing anywhere — `show diff` said "no changes" on the very next line. Those verbs are no longer registered, and `set`/`delete` on the wire are refused with a message naming the verb you wanted instead.

## The system configuration

`/etc/f/system.yaml`. Every verb here edits that file and applies it: through `f-confd` when it is running, which means the change gets a recorded revision you can return to with `rollback system` — and directly onto the generated artifacts when it is not, in which case the files are written and nothing is reloaded. The reply always says which of the two happened, and the direct case says in as many words what did not.

**These verbs apply on the spot; there is no confirm window on any of them.** For a change that could sever your own session, edit the file and use `apply system confirmed <minutes>`, which is what has the timer. See [howto/change-something-safely.md](../howto/change-something-safely.md).

| Command | Question it answers |
|---|---|
| `check system` | Does the configuration validate, without applying it? |
| `apply system [force]` | Make it live. `force` discards a hand-edit of a generated file. |
| `apply system confirmed <minutes> [force]` | Make it live with an automatic undo if you do not confirm. See [howto/change-something-safely.md](../howto/change-something-safely.md). |
| `confirm system` | Keep a confirmed apply; cancel the undo. |
| `show system` | What ports, zones and services are declared; whether the ports are physically here; where services will answer. |
| `show services` | Are the backing daemons running, where are they actually bound, and does that match what was asked for? |
| `show commits` | The revisions `f-confd` has recorded: who applied what, and when. Says so when `f-confd` is not running rather than printing an empty history. |
| `rollback system [<revision>]` | Restore a recorded revision — the previous one, or an id from `show commits`. This is the way back from a `set` verb, which applies on the spot. It does not touch the policy. |

### Zones and ports

| Command | |
|---|---|
| `set zone <name> [off\|ra]` | Declare a zone, or change its IPv6 stance. A new zone may be empty; the reply says it is, because a zone with no port attaches no program. |
| `no zone <name>` | Remove one. Refused while an interface is still in it or a service is still bound to it, and the refusal names them. |
| `set interface zone <iface> <zone>` | Put a port in a zone. Declares the port, pinned to its MAC, if the configuration does not mention it yet. An interface is in exactly one zone — the model has no way to say otherwise. |
| `no interface zone <iface>` | Take it out, leaving it declared and in no zone. |
| `set address <iface> <cidr\|dhcp>` | Set the port's address. |
| `no address <iface> [cidr]` | Remove it. |
| `set mtu <iface> <bytes>` | Live only — MTU is not in the model, and the command says so. |
| `set link <iface> up\|down` | Live only. |

A zone name is not created by being referenced: `set interface zone lan0 dmzz` is refused and lists the zones that do exist. That is the whole value of a declared zone list.

### Services

| Command | |
|---|---|
| `set dhcp <zone> <first>-<last> [lease]` | Serve DHCP on a zone. |
| `no dhcp <zone>` | Stop. Reservations on that zone go with it. |
| `set dns <zone> [<upstream> …]` | Forward DNS for a zone. With no upstream named it inherits the system resolver, which on a DHCP uplink is whatever the upstream handed us. |
| `no dns <zone>` | Stop. |
| `set reservation <mac> <ip> [name]` | Pin a board to an address. The zone is derived from which DHCP subnet the address falls in. |
| `no reservation <mac>` | Unpin it. Removing one that is not there is an error. |

**No service verb takes an interface, and none can.** A service binds to a zone and the ports it answers on are derived from zone membership every time the config is generated — so "DHCP answers on the uplink" is not a mistake you can make at this prompt any more than you can make it in the file.

NTP has no verb yet; see the gaps at the bottom of this page.

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
| `show zones` | Zones, their interfaces, attach state and XDP mode. |
| `show nat` | Active translations and the masquerade source. |
| `show conntrack` | Connection-tracking table entries. |
| `show interfaces` | Interfaces, addresses, counters. |
| `reload firewall` | Recompile the policy and hot-reload it. A policy that does not compile is never loaded. |
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

## The policy

`/etc/f/*.fw`. These verbs read and edit the source, and the compiler has the last word before anything is written: an edit is compiled on a copy, and only a policy that compiles replaces one that does. A rule that is saved but that `fd` would not load reports both halves — the file it reached, and the fact that the running policy is unchanged.

| Command | |
|---|---|
| `show policy [zone]` | The source, block by block, numbered. The numbers are what `no rule` takes; they restart in each `@xdp` block. The `MATCHES` column marks the statements that act on **every** packet, because nothing below one of those can ever match. |
| `set rule <zone> allow\|drop [tcp\|udp\|icmp] [<port>] [from <cidr>] [to <cidr>]` | Add a filter rule. |
| `no rule <zone> <position>` | Remove a statement by the position `show policy` gives it. |
| `set forward <zone> tcp\|udp <port> <ip>:<port> [from <cidr>]` | Forward a port to a machine inside. |
| `no forward <zone> tcp\|udp <port>` | Remove both halves of one. |
| `show files` | List `.fw` files. |
| `new file <name>` | Create one. |
| `rename file <old> <new>` | |
| `delete file <name>` | |
| `edit [file]` | Open one in an editor. |
| `set editor <name>` | Persist a preferred editor. Refuses a name that is not on the box. |

Three things about these are decisions rather than details.

**Placement is computed, not chosen.** `allow` is terminal and `masquerade` / `redirect` / `default` are unconditional, so a rule appended to the end of a block is usually a rule that can never match — and it would look identical, in the file and in every listing, to one that works. `set rule` therefore lands at the end of the *guarded* region, after the last rule carrying an `if`, and the reply says which statement it went in front of.

**A port needs a protocol.** `set rule lan allow 443` is refused. FWL does not infer the guard, and the reason is better than the guess: without it the program reads whatever bytes sit at the port offset of a packet that has no ports.

**A forward is one edit, not two.** `dnat` rewrites the destination and falls through; `redirect` is what emits the frame into the inside zone. A `redirect` whose guard is wider than its `dnat`'s sends untranslated frames inside, so the pair is always written together with one guard, character for character. The inside zone is derived from `system.yaml` — the model knows which segment an address is in, so you are not asked and cannot get it wrong.

`show policy` reads the file on disk. That is the source, not necessarily what is loaded; `show zones` reports what `fd` has attached, and the page says so under every listing.

For anything these verbs cannot express — a helper, a rate limit, a chain, a condition with an `or` in it — the language is [fwl/](../fwl/README.md) and the file is still a file. The verbs are the changes you make weekly, not a front end for the language.

## The policy candidate

`configure` opens a candidate over the `.fw` files: it snapshots them, and holds your edits until `commit`. `commit` compiles every source and, only if they all pass, asks `fd` to hot-reload. `rollback candidate` puts the snapshots back.

| Command | |
|---|---|
| `configure` | Open a candidate over the policy files. |
| `commit` | Compile them all, then hot-reload. A policy that does not compile is never loaded, and a commit `fd` did not apply keeps the session open so `rollback` still works. |
| `rollback candidate` | Restore the snapshots and discard the session. |
| `show diff` | What the candidate changed. |
| `show config` | The policy files as text. |
| `show schema` | The keys of `/etc/f/fd.yaml` — the daemon's own paths and log level. Not the system configuration and not the policy. |

`set rule` and `set forward` work with or without a session. Inside one they join the candidate and wait for `commit`; outside one they compile, write and reload on the spot, and say so. `new file`, `rename file`, `delete file` and `edit` require a session, because a snapshot is the only way back from an editor.

**This is not the system configuration.** `commit` will not apply `system.yaml`, and `apply system` will not load a policy. If you want an anti-lockout window it is `apply system confirmed <minutes>`, and it covers addressing, zones and services — the changes that can actually cut your access. A policy that drops your own SSH is recovered with `rollback candidate`, or with [recovery.md](../recovery.md).

## Finding a command

| | |
|---|---|
| `einheit-f --help` | Global options **and every command**, with one line each. |
| `help` | The same index, inside the shell. |
| `?` | The same thing. In an interactive terminal `?` mid-line opens the completion overlay instead; typed on its own line it prints the index. |
| `help <command>` | What one command takes. |
| `explain <command>` | Its wire representation, the role it needs and whether it needs a session — which answers "why was I refused" without guessing. |

Tab completes command paths at any depth.

## Shell conveniences

`help`, `?`, `explain <command>`, `history`, `alias`, `macro record|end|list|show|run|delete`, `theme list|use`, `statusbar on|off`, `show env`, `shell`, `exit`, `quit`.

---

## Gaps in the command surface

Recorded here because a reader looking for one of these should find out it does not exist rather than conclude they are searching badly.

- **NTP has no verb.** `services.ntp` — the upstreams and whether the box answers NTP for a zone — is the one service block still edited with an editor. `show time` reads it; nothing writes it.
- **`gateway:` and `address6:` have no verb.** A default route on a static interface and the v6 prefix a `ra` zone advertises are both editor-only. `set zone <name> ra` is therefore refused on a zone with no v6 prefix (`SC031`) and there is no verb that adds one — the message is correct and the way out of it is the file.
- **`set rule` covers a conjunction and nothing else.** Every term it takes is `and`-ed together. An `or`, a rate limit, a helper, a chain, a `log`, a `count`, a conntrack state or a rule at a chosen position all need the language and the file. This is a deliberate boundary, not a stub: `set rule` is for the changes that happen weekly.
- **Nothing reads the loaded program's counters.** `count` in a policy compiles to a slot in that zone's `fwl_counters_<zone>` map, and no verb prints it; `bpftool map dump pinned /sys/fs/bpf/f/fwl_counters_<zone>` is the only way, and it gives slot numbers rather than the names you wrote. Four verbs used to sit here — `show firewall`, `show firewall rules`, `show counters`, `clear counters` — and every one of them addressed the v0.1 single-program datapath instead: a separate `counters` map, keyed by match tier rather than by rule, that no v0.4 bundle has. On a real box `show firewall` printed a fixed `default_action drop / active_table 0 / conntrack disabled / rule_count 0` regardless of the policy, and the other three were refused by the daemon. They are removed rather than left answering. `show policy` reads the source and is zone-scoped; `show zones` reads the loaded bundle.
- **`no rule` on one half of a port forward is allowed.** It names the survivor in a warning — a `redirect` without its `dnat` sends untranslated frames into the inside zone — but it does not refuse. Use `no forward` for the pair.
- **The UI has no view for `show leases`, `show device`, `show ipv6`, `show time`, `show storage`, `show policy`, or a pending confirm window.** Those exist only on the CLI.
- **An unrecognised `--option` becomes a command token.** The CLI accepts extra arguments so that command words can reach the shell, so `einheit-f --no-such-flag show system` reports `no matching command` rather than an unknown option.
