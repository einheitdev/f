# f appliance — operator handbook

First edition. Covers commissioning a box, the day-to-day loop of
plugging something in and finding out what it is, and the four ways
this thing has actually gone wrong so far.

It is deliberately not exhaustive. Everything in it has been run
against a real box; where a procedure has a sharp edge, the sharp edge
is written down rather than smoothed over.

---

## 0. The one convention worth learning first

**An empty table always says which kind of empty it is.**

There are two completely different reasons a screen shows nothing:
there is nothing there, or nobody could ask. Confusing them costs
hours, so every view that can come back empty prints a reason next to
the emptiness. If you ever see a blank table with no explanation,
that is a bug — report it.

The same rule shows up in three smaller conventions:

| You see | It means |
|---|---|
| `>=3h` in a time column | *at least* that long. We did not watch it happen; this is a bound derived from the lease, not a measurement. |
| `3h` with no `>=` | We watched it happen. This is a measurement. |
| `NEW` | This device was absent the last time anything looked, and is here now. Only ever set from a watched transition. |
| `(clipped: 96 columns needed, 80 available)` | The table did not fit. Widen the terminal or add `--format json`. Nothing is silently cut. |

---

## 1. First setup

### 1.1 Name the ports

The whole appliance hangs off one chain:

```
physical port  ->  interface  ->  zone  ->  services bind here
```

Everything is declared in `/etc/f/system.yaml`. Start from
`deploy/system.yaml.example`.

An interface is pinned to a **hardware identity**, not to a probe
order. `ip -o link` gives you the MACs:

```yaml
zones:
  wan:
  testnet:

interfaces:
  wan0:
    mac: "52:54:00:aa:bb:01"
    address: dhcp
    zone: wan
  lan0:
    mac: "52:54:00:aa:bb:02"
    address: 10.10.0.1/24
    zone: testnet
```

This is not tidiness. udev renumbering a port repoints the policy
underneath itself, and a firewall pointing at the wrong port is a
bypass, not an outage.

### 1.2 Bind the services

Services bind to a **zone**, and there is no key anywhere in the file
that names an interface. That is what makes "DHCP answers on the
uplink" a sentence the configuration cannot express:

```yaml
services:
  dhcp:
    - zone: testnet
      range: 10.10.0.100-10.10.0.200
      lease: 12h
  dns:
    - zone: testnet
      upstream: [9.9.9.9, 1.1.1.1]
```

### 1.3 Check it, then apply it

```
$ einheit-f check system
ok — /etc/f/system.yaml

$ einheit-f apply system
applied via f-confd, revision 1
applied without a confirm window — use `apply system confirmed
<minutes>` when the change could cut your own access
```

`apply system` generates the dnsmasq config from the model, has
dnsmasq validate it, installs it and reloads the service. The
generated file is a **derived artifact**: it carries a digest of its
own body, it is never hand-edited, and an edit to it is reported as
drift rather than quietly overwritten.

### 1.4 Confirm it came up

```
$ einheit-f show system
 ZONE    │ INTERFACES │ SERVICES │ IPV6
 wan     │ wan0       │ -        │ off
 testnet │ lan0       │ dhcp+dns │ off

 DERIVED            │ INTERFACES
 services listen on │ lan0
 dhcp answers on    │ lan0
 excluded           │ wan0

$ einheit-f show services
 SERVICE            │ STATE   │ ZONES   │ ANSWERS ON │ UNIT
 dhcp+dns (dnsmasq) │ RUNNING │ testnet │ lan0       │ f-dnsmasq.service
```

Read the **excluded** line. It is the containment stated out loud: the
uplink is named as a port DHCP will not answer on, rather than merely
left out of a list.

---

## 2. Normal operation

### 2.1 Plug something in and find out what it is

```
$ einheit-f show leases
 NEW │ MAC               │ ADDRESS     │ HOSTNAME  │ ZONE    │ FIRST SEEN │ LAST SEEN │ EXPIRES
 NEW │ 52:54:00:f1:00:aa │ 10.10.0.132 │ bench-3   │ testnet │        14s │        0s │      2m
     │ aa:bb:cc:dd:ee:02 │ 10.10.0.102 │ (none)    │ testnet │      >=11m │        0s │     11h
     │ aa:bb:cc:dd:ee:01 │ 10.10.0.101 │ board-a   │ testnet │       >=1h │        0s │     11h
```

Most recent arrival first, always. The board you just plugged in is
row one; you do not have to diff anything by eye.

Variants:

- `show leases new` — only devices that turned up in the last 15
  minutes.
- `show leases all` — includes devices that have no current lease.
  Their last known address is still shown.
- `--format json` — machine-readable. Explanatory prose goes to
  stderr in this mode, so `| jq` gets clean JSON and you still see the
  warnings.

A `*` after the MAC means the device has a static reservation.

### 2.2 Watch for arrivals

```
$ einheit-f watch show leases
watching `show leases` — no time limit. Ctrl-C to stop.
```

The screen paints immediately, then repaints **only when something
changes** — an arrival, a departure, or an address change — with a
banner naming what happened:

```
 ARRIVED
 52:54:00:f1:00:bb
4 device(s) leased  ▁▁▂▃▄
```

A quiet segment stays quiet, so the one line that matters is not
buried under a repaint every two seconds. The sparkline is the count
of leased devices, one sample per poll.

`watch` takes an optional window: `watch show leases 5m`, `watch show
leases 30s`. With no window and a terminal attached it runs until
Ctrl-C; run from a script (no tty) it stops after 30 seconds so it
cannot hang a pipeline.

It works as a one-shot too, which is how you use it over SSH:

```
$ ssh box einheit-f watch show leases 5m
```

### 2.3 Find out what it is talking to

```
$ einheit-f show device 10.10.0.132
 FIELD       │ VALUE
 mac         │ 52:54:00:f1:00:aa
 address     │ 10.10.0.132
 hostname    │ bench-3
 zone        │ testnet
 lease       │ holds a lease, 1m left
 first seen  │ 14s ago
 last seen   │ 0s ago
 reservation │ none — the address may change

 DIR │ PROTO │ PEER           │ LOCAL PORT │ VIA    │ STATE       │ PACKETS │ IDLE
 out │ tcp   │ 1.1.1.1:443    │      40001 │ nat    │ established │       9 │   1s
 out │ tcp   │ 203.0.113.9:80 │      40000 │ nat    │ established │       4 │   1s

 TALKING TO  │ PACKETS │ SHARE
 1.1.1.1     │       9 │ ############## 69%
 203.0.113.9 │       4 │ ###### 31%

 NAT  │ ORIGINAL                            │ TRANSLATED
 snat │ 1.1.1.1:443 -> 203.0.113.1:40001    │ 10.10.0.132:40001
 snat │ 203.0.113.9:80 -> 203.0.113.1:40000 │ 10.10.0.132:40000
```

`show device` takes a MAC in any spelling, an IPv4 address, or a
hostname. An ambiguous name is reported as ambiguous with every match
listed — it is never silently resolved to whichever row sorted first.

**Read the VIA column.** Behind a masquerade the connection table is
keyed on the addresses that are *on the wire* — the gateway's, not the
device's — so the device's own flows do not appear under its own
address at all. `VIA nat` means the row was found by joining through
the NAT table, and `LOCAL PORT` is the device's real port rather than
whatever conntrack happens to show. `VIA direct` means conntrack named
the device itself.

This is worth knowing because it is also the shape of the wrong
answer: a tool that filters the connection table by the device's
address finds nothing on a masquerading gateway and cheerfully reports
that the board is talking to nobody.

The flow half comes from `fd`. If `fd` is not running you get

```
 FLOWS
 unknown — fd could not be asked
fd is not running (no socket at ipc:///run/f/control.sock). This is not
the same as a device that is talking to nobody: with fd down there is
no connection table to read.
```

which is the point. A device with no traffic and a daemon that cannot
be asked look identical on every tool that does not bother to
distinguish them. When `fd` *is* up and genuinely has nothing, it says
that instead:

```
 FLOWS
 fd is tracking no connections for this device
fd answered. Its conntrack table has no entry for this device's
address, nor for any of the translated endpoints NAT says belong to it.
```

### 2.4 Pin a board to an address

```
$ einheit-f set reservation 52:54:00:f1:00:aa 10.10.0.55 bench-3
 FIELD      │ VALUE
 action     │ set reservation
 mac        │ 52:54:00:f1:00:aa
 address    │ 10.10.0.55
 zone       │ testnet
 written to │ /etc/f/system.yaml
 state      │ written and live (f-confd)
the client keeps its current address until its lease is renewed
```

The reservation goes into `system.yaml`, next to the range it comes
out of, with your comments intact. You do not have to say which zone:
the address is matched against the subnets of the zones that serve
DHCP, and an address that matches none — or more than one — is
refused with the candidates named.

**It takes effect on the client's next DHCP renewal, not immediately.**
Wait out the lease, or bounce the port. `show device` will say
`10.10.0.55 (not in effect yet — the client keeps 10.10.0.132 until it
renews)` until it lands.

If `f-confd` is not running, the state line reads `written, not yet
live` and tells you to run `apply system` — because writing the model
and regenerating dnsmasq's config are two different events, and only
one of them happened.

`no reservation <mac>` removes it. Removing one that is not there is
an error, not a no-op: a MAC typed by hand that matches nothing is
something you want to know about.

---

## 3. When it goes wrong

### 3.1 You are about to change something that could cut your own access

**Symptom (before the fact):** you are on SSH, about to change an
address, a zone, or an interface's pinning, and if you get it wrong
you lose the session and the box.

**Procedure:**

```
$ einheit-f apply system confirmed 5
applied via f-confd, revision 2

CONFIRM WITHIN 5m — run `confirm system`, or the previous
configuration is restored automatically.
```

Then check you still have the box. If you do:

```
$ einheit-f confirm system
```

If you do not, do nothing. After the window `f-confd` puts the
previous configuration back by itself:

```
audit user=confd cmd=auto_revert ok=true
  outcome=commit-confirm expired; reverted to commit 1
```

**Why it works when a shell trick would not:** the timer lives in
`f-confd`, not in your CLI. A timer in a CLI over SSH dies with the
connection it exists to protect. If you reconnect mid-window, `show
system` leads with the countdown, so you find out the clock is running
without having to know to ask:

```
CONFIRM PENDING — 59s left on revision 2. Run `confirm system` to keep
this configuration, or wait and the previous one is restored.
```

**If f-confd is not running**, the confirmed apply is *refused* rather
than applied without a way back:

```
error  no_confd
the revert timer lives in f-confd, which is not running — a confirmed
apply would have nothing to undo it

hint: start it (systemctl start f-confd), or use `apply system` and
      accept that a change which severs your access will not be
      rolled back
```

Start `f-confd` first. Verified on a VM: armed, counted down, and
reverted the file after the window with no session attached.

### 3.2 Something on the segment might be getting IPv6 around you

**Symptom:** none. That is the problem. A testnet device that
autoconfigures IPv6 from an office router advertisement gets a
globally routable address and a default route that have nothing to do
with `f`, routes around the v4 NAT and the whole firewall, and every
counter on the box keeps climbing exactly as before.

**Procedure:** ask what has arrived and what was formed.

```
$ einheit-f show ipv6
 INTERFACE │ ZONE    │ STANCE │ RAS SEEN │ ADDRESSES
 wan0      │ wan     │ off    │       17 │ (none)
 lan0      │ testnet │ off    │        0 │ (none)

17 router advertisement(s) arrived on a zone whose stance is off,
and were refused. Nothing autoconfigured.
forwarding: off
```

Read the two numbers **together**. `17 / (none)` is the gate holding:
the office is advertising and nothing here took an address. `0 /
(none)` is not the same thing — it is a quiet network, and the box
says so rather than taking credit for it.

The row that matters is any `off` zone with something in ADDRESSES:

```
IPv6 STANCE VIOLATED: wan0 (zone wan) is ipv6 off but holds
2001:0db8:dead:0000:5054:00ff:fef6:0001
```

That is the bypass, live. Re-run `apply system` to put the stance
back, then find out what removed it — the usual answer is something
else on the box writing `net.ipv6.conf.*.accept_ra`, or a port that
came up before `systemd-sysctl` reached it.

`?` in a counter column means the device is not present. It is never
rendered as `0`, because the office may be shouting advertisements at
that port right now.

The full stance — what `off`, `ra` and `full` mean, and why `full` is
refused — is in `docs/IPV6_STANCE.md`.

### 3.3 A service is not running, and you need to know which kind of not-running

**Symptom:** DHCP is not answering. `systemctl status` is not much
help, because systemd reports a unit that was never installed and a
unit that crashed in almost the same way — and it keeps reporting a
deleted unit's last `ActiveState` long after the file is gone.

**Procedure:** ask the appliance, which compares what the model
expects against what systemd says and names the mismatch:

```
$ einheit-f show services
 SERVICE            │ STATE         │ ZONES   │ ANSWERS ON │ UNIT
 dhcp+dns (dnsmasq) │ NOT INSTALLED │ testnet │ lan0       │ f-dnsmasq.service

dhcp+dns (dnsmasq): the model binds a service to testnet, but
f-dnsmasq.service is not installed on this box
```

The states, and what each one means for you:

| STATE | What happened | What to do |
|---|---|---|
| `RUNNING` | Should run, does. | — |
| `NOT CONFIGURED` | Nothing is bound here and nothing runs. Correct. | — |
| `NOT INSTALLED` | The model binds a service here; the unit file is not on the box. | Install the unit (`deploy/systemd/f-dnsmasq.service`), then `systemctl daemon-reload`. |
| `STOPPED` | The unit exists and nobody ever started it. | `systemctl enable --now f-dnsmasq` |
| `FAILED` | It tried and died. The last thing it said is in the detail line. | Read the detail, then `journalctl -u f-dnsmasq`. |
| `RESTARTING` | Flapping — systemd calls this `activating` for the whole restart burst, which reads as "starting". | Treat as failing. `journalctl -u f-dnsmasq`. |
| `UNEXPECTED` | Running, and the model says it should not be. | Something else is serving this segment. Find it. |
| `UNKNOWN` | systemd could not be reached. | Not the same as fine. Check systemd. |

The one to be careful with is `RESTARTING`. A unit that flaps forever
looks alive in every dashboard while serving nobody; `f-dnsmasq.service`
therefore has a `StartLimitBurst` so it eventually sits in `failed`
where both systemd and `show services` say so out loud.

### 3.4 A restart left pins behind in bpffs

**Symptom:** `fd` restarts and either refuses to load a bundle, or
loads it and the connection tracking behaves as though it remembers
things it should not. BPF maps pinned under `/sys/fs/bpf/f` outlive
the process that made them — that is what keeps conntrack state across
a daemon restart, and it is also what leaves debris behind when the
policy changes shape.

**What the box does about it, and it matters which case you are in:**

- **Cold boot** (a *previous* `fd` left the pins). Pins the incoming
  bundle cannot reuse are **removed**. The alternative is a daemon
  that will not start, and a firewall that is down filters nothing at
  all. Conntrack entries the daemon's own GC rule would already have
  condemned are swept on adoption, so an adopted table does not come
  back full of week-old flows.
- **Hot reload** (this same `fd` has the current policy attached).
  A pin that cannot be reused is **left alone**, the load fails, and
  the running policy stays up. There is a fallback here, so destroying
  live state to force the new bundle in would be the wrong trade.

**Recovery:** on a refused hot reload the message names the map and
both definitions — the one the loading zone declares and the one
already pinned. Fix the definition mismatch in the policy, or, if you
genuinely want the new shape and can afford to lose the state, restart
`fd` so the cold-boot rule applies:

```
$ sudo systemctl restart fd
$ einheit-f show zones
```

Note the asymmetry that trips people up: a restart discards a
*policy-scoped* pin whose definition changed, but **adopts** a
persistent one (`conntrack`, `fwl_nat`) whose definition still
matches. If you want a persistent map genuinely empty, the pin has to
go — see §3.4.

Check the `ATTACHED` and `MODE` columns afterwards. A declared
interface with no attach shows `(none)`, and `generic` in MODE means
you are on the software slow path, not at line rate.

### 3.5 NAT stops working for new flows

**Symptom:** existing connections through the box keep working, new
ones go out and nothing comes back. Typically after a long soak or a
scan, with many short-lived flows.

**Cause:** the shared NAT map (`fwl_nat`) is a fixed-size hash. Every
translated flow installs a reply mapping; when the map is full, new
mappings cannot be installed and the *return* packet has nothing to
de-NAT against.

**What this build tells you.** `show nat` lists the active
translations and the masquerade source address:

```
$ einheit-f show nat
masquerade source: 198.51.100.9
 PROTO │ TYPE │ ORIG SRC          │ ORIG DST        │ TRANSLATED
 tcp   │ snat │ 10.10.0.132:51234 │ 8.8.8.8:443     │ 198.51.100.9:51234
```

A table that is long and full of stale-looking entries, next to
outbound traffic that does not come back, is the signature.

**Restarting `fd` does not clear it.** This surprises people, so it is
worth being explicit. `fwl_nat` is a **persistent** map: it is pinned
under `/sys/fs/bpf/f/` and a cold boot *adopts* it if the incoming
bundle declares the same definition — deliberately, so that translated
flows survive a daemon restart. Conntrack entries are swept against
the GC timeout when they are adopted; NAT mappings are not. Measured
on a VM, one translation installed by real traffic:

```
after traffic:                    1 translation
after a plain restart of fd:      1 translation
after removing the fwl_nat pin:   0 translations
```

**Recovery, in order of how much it costs you:**

1. **Wait.** Mappings go when the flows that own them do. If the box
   is otherwise healthy this is the cheapest fix.
2. **Drop the pin.** This is the one that actually empties the table.
   It also throws away the translations for every *live* flow, so
   anything currently connected through the box breaks:

   ```
   $ einheit-f show nat            # confirm the table is the problem
   $ sudo systemctl stop fd
   $ sudo rm -f /sys/fs/bpf/f/fwl_nat
   $ sudo systemctl start fd
   $ einheit-f show nat            # empty
   ```

   Do not delete the pin while `fd` is running.
3. If it fills again quickly, the pool is genuinely too small for the
   traffic; that is a policy change, not an operational one.

**Known gap, this build.** There is no occupancy figure and no log line
when an allocation fails: `bpf_map_update_elem` on `fwl_nat` ignores
its return value, so a full table is silent in the datapath and you
diagnose by symptom. The refusal-and-log, the per-mapping lifetime tied
to its flow, and the occupancy report are being developed on the rig
branch (`origin/f-rig`) and are **not** in this build. If `show nat` on
your box prints an occupancy line, you have the newer one — read that
instead of guessing from the table length.

---

## 4. Reference: what each command is for

| Command | Question it answers |
|---|---|
| `show system` | What ports, zones and services are declared, and where will services answer? |
| `show services` | Are the backing daemons running, and if not, which kind of not-running? |
| `show ipv6` | Have router advertisements arrived, and did anything autoconfigure from one? |
| `check system` | Does the configuration validate, without applying it? |
| `apply system` | Make the configuration live. |
| `apply system confirmed <min>` | Make it live with an automatic undo if you do not confirm. |
| `confirm system` | Keep a confirmed apply; cancel the undo. |
| `show leases` | What has taken an address, when did it appear, when was it last seen? |
| `show leases new` | What has appeared in the last 15 minutes? |
| `watch show leases [window]` | Show me arrivals as they happen. |
| `show device <mac\|ip\|name>` | Everything about one device, including its open connections. |
| `set reservation <mac> <ip> [name]` | Pin a board to an address. |
| `no reservation <mac>` | Unpin it. |
| `show zones` | Which interfaces are in which zone, are they attached, native or generic XDP? |
| `show nat` | Active translations and the masquerade source. |
| `show conntrack` | The connection-tracking table. |
| `show counters` / `show firewall rules` | Per-rule hit counts. |

Global flags worth knowing: `--format json|yaml|set`, `--width N`,
`--color never`, `--ascii`.

---

## 5. Where the state lives

| Path | What it is | Who writes it |
|---|---|---|
| `/etc/f/system.yaml` | The system configuration. The only thing you edit. | you, and `set address` / `set reservation` |
| `/etc/f/generated/dnsmasq.conf` | Derived artifact. Digest-stamped; edits are reported as drift. | `apply system` |
| `/etc/systemd/network/10-f-*.network` | Derived artifact. | `apply system` |
| `/var/lib/f/dnsmasq.leases` | dnsmasq's lease database. Read-only to us. | dnsmasq |
| `/var/lib/f/devices.json` | Device history: when each MAC first appeared. | whatever runs `show leases` |
| `/sys/fs/bpf/f/` | Pinned BPF maps — conntrack and NAT state. | `fd` |

`devices.json` is the only file here that records something nothing
else knows. Delete it and every device on the segment reverts to
"found, not watched": ages become `>=` bounds and nothing is marked
`NEW` until the next arrival. That is a loss of information, not a
fault, and the view says so the first time it runs afterwards.

If it cannot be written — running as a non-root user, or a full
filesystem — `show leases` says so at the top rather than quietly
losing the ability to detect arrivals:

```
device history is NOT being recorded (cannot write
/var/lib/f/devices.json) — arrivals will not be detected
```
