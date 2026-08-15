# When it goes wrong

Every entry here is something that has actually happened on a real box, written up after it was fixed. They are ordered by how likely you are to hit them, not by severity.

If you are looking for a specific error code, [reference/error-codes.md](reference/error-codes.md) is the index.

---

## `show services` says a daemon is running, but nothing on the segment is being served

**Symptom.** `systemctl` says `active`. `show services` says `running`. DHCP does not answer, or DNS does not answer, or both. Nothing is in the journal that looks like a failure.

**Look at `ANSWERS ON`.**

```
$ einheit-f show services
 SERVICE            │ STATE   │ ZONES   │ BOUND TO │ ANSWERS ON    │ UNIT
 dhcp+dns (dnsmasq) │ running │ testnet │ lan0     │ LOOPBACK ONLY │ f-dnsmasq.service

dhcp+dns (dnsmasq): systemd says this unit is running, and it is — but
the model binds it to lan0 and the kernel shows it listening on
0.0.0.0:67/udp, 127.0.0.1:53/tcp, 127.0.0.1:53/udp. It is running and
answering nobody on lan0. The usual cause is a generated file naming an
interface that does not exist yet: check `show system` for a pending
rename.
```

`BOUND TO` is what the configuration asked for. `ANSWERS ON` is read out of the kernel's socket table. When they disagree, the daemon started cleanly against a config naming a port that is not there — dnsmasq in particular logs `warning: interface lan0 does not currently exist`, binds DNS to loopback, and carries on.

**Fix.** Almost always the next entry: the port exists but has not been renamed yet. `show system` will say so.

**Why this used to be invisible.** `ANSWERS ON` was computed from zone membership — the same model that generated the config. It printed `lan0` whether dnsmasq was bound to `lan0` or to nothing at all, because both numbers came from the same place. A column that cannot disagree with the config it reports on is not evidence.

**On `every port (wildcard socket)`.** dnsmasq always holds a wildcard DHCP socket; DHCP containment is enforced per received packet, not by binding. So a wildcard is not a containment failure and is not evidence about which segment is served. The line under the table says so.

---

## A configuration was applied, but the ports it names do not exist yet

**Symptom.** `apply system` reported success. Nothing works. `show services` says the daemon is bound to loopback.

**Read the end of the apply output.**

```
PENDING RENAME: lan0 (currently enp1s0f1). Until the rename happens
those names match no device, so every generated file that mentions them
binds nothing — dnsmasq will start cleanly and answer on loopback.
Either reboot, or apply the rename now:
  udevadm control --reload
  ip link set enp1s0f1 down
  udevadm trigger --action=add /sys/class/net/enp1s0f1
Then `show system` must read PRESENT: yes before this configuration is
doing anything.
```

**Why it happens.** An interface's durable name is pinned by a `.link` unit that udev applies when a device appears. Writing the unit does not rename a port that is already up — and renaming a live port out from under an operator is not something an `apply` should do by itself.

**Confirm it either way in `show system`:**

```
 INTERFACE │ PINNED TO         │ ADDRESS      │ ZONE    │ PRESENT
 lan0      │ 52:54:00:aa:bb:02 │ 10.10.0.1/24 │ testnet │ pending rename (now enp1s0f1)
```

`PRESENT` answers "is the port in the `PINNED TO` column here", matching on the hardware identity rather than on the name. It used to match by name, which reported `no` for a port that was plugged in, powered and correctly identified one column to the left — wrong at exactly the moment it mattered.

The other values it can take:

| `PRESENT` | Meaning |
|---|---|
| `yes` | The pinned port is here and already carries this name. The only state in which artifacts naming it bind anything. |
| `pending rename (now X)` | Here, correctly identified, under its kernel name. Apply the rename or reboot. |
| `WRONG PORT` | A port with this *name* exists and it is not the one you pinned. A firewall pointing at the wrong port is a bypass, not an outage. Deal with this first. |
| `no` | No port on this box carries that identity. Check the cable and the MAC. |
| `?` | The port table could not be read. Not the same as `no`, and never rendered as it. |

---

## An internal name resolves to nothing, with no error

**Symptom.** `intranet.corp` returns an empty answer. No `NXDOMAIN`, no `SERVFAIL` — an empty answer, which most clients render as "not found". Public names resolve fine. The only trace anywhere:

```
$ journalctl -u f-dnsmasq | grep rebind
possible DNS-rebind attack detected: intranet.corp
```

**Cause.** DNS rebind protection is on. It discards any upstream answer pointing into private address space — and in an office, internal names are private-addressed by definition.

**Check it without knowing to look in the journal:**

```
$ einheit-f show services
...
DNS rebind protection is ON, exempting no domain. An upstream answer
pointing into private address space is discarded and the client sees an
empty answer with no error — every internal name in the building
resolves to nothing. List the internal domains under `rebind_ok:`.
```

**Fix.** Either turn it off, which is the default:

```yaml
services:
  dns:
    - zone: testnet
      upstream: [9.9.9.9]
```

or keep it and name the exceptions:

```yaml
services:
  dns:
    - zone: testnet
      upstream: [9.9.9.9]
      stop_dns_rebind: true
      rebind_ok: [corp, internal.example]
```

then `apply system`. `check system` warns about the first shape as `SC045`.

**If you are testing this:** dnsmasq's private-address test also covers TEST-NET, so `203.0.113.x` is **not** a valid "public" control. Use a real public address.

---

## An old interface name is still deciding which port gets renamed

**Symptom.** The configuration is right, `apply system` succeeded, and the port still comes up under its kernel name after a reboot. Nothing logs an error.

**Cause.** Two `.link` units pinning the same MAC to different names. udev applies `.link` files in **filename order** and the first match wins, so `10-f-enp1s0f1.link` beats `10-f-lan0.link` — and the loser is the one you wrote on purpose.

The ordinary way to get there: use `set address enp1s0f1 ...` once while exploring, then write the real configuration.

**What the box does now.** `apply system` removes generated units whose interface has left the model, and names each one:

```
removed /etc/systemd/network/10-f-enp1s0f1.link (its interface is no
longer in the configuration)
```

A file it did **not** write is never deleted — it is reported instead:

```
LEFT IN PLACE /etc/systemd/network/05-vendor.link — we did not write
it, so it is not ours to delete. It may still decide a port's name.
```

and if that file claims a MAC this configuration also claims, under a different name, the apply is **refused**:

```
another .link unit claims a port this configuration also claims:
  /etc/systemd/network/05-vendor.link pins 52:54:00:aa:bb:02 to 'eth7',
  but the system configuration pins it to 'lan0'
udev applies .link files in filename order, so whichever name sorts
first wins and the loser is silent. Remove the other unit, or re-apply
with force to proceed anyway.
```

**Fix.** Remove the other unit, or decide you want it and `apply system force`.

---

## You are about to change something that could cut your own access

That has its own page: [howto/change-something-safely.md](howto/change-something-safely.md).

---

## Something on the segment might be getting IPv6 around you

**Symptom:** none. That is the problem. A bench device that autoconfigures IPv6 from an office router advertisement gets a globally routable address and a default route that have nothing to do with this box, routes around the v4 NAT and the whole firewall, and every counter keeps climbing exactly as before.

**Ask what arrived and what was formed.**

```
$ einheit-f show ipv6
 INTERFACE │ ZONE    │ STANCE │ RAS SEEN │ ADDRESSES
 wan0      │ wan     │ off    │       17 │ (none)
 lan0      │ testnet │ off    │        0 │ (none)

17 router advertisement(s) arrived on a zone whose stance is off,
and were refused. Nothing autoconfigured.
forwarding: off
```

Read the two numbers **together**. `17 / (none)` is the gate holding: the office is advertising and nothing here took an address. `0 / (none)` is not the same thing — it is a quiet network, and the box says so rather than taking credit for it.

The row that matters is any `off` zone with something in `ADDRESSES`:

```
IPv6 STANCE VIOLATED: wan0 (zone wan) is ipv6 off but holds
2001:0db8:dead:0000:5054:00ff:fef6:0001
```

That is the bypass, live. Re-run `apply system` to put the stance back, then find out what removed it — usually something else on the box writing `net.ipv6.conf.*.accept_ra`, or a port that came up before `systemd-sysctl` reached it.

`?` in a counter column means the device is not present. It is never rendered as `0`, because the office may be shouting advertisements at that port right now.

**Known limit.** A stance change does not evict addresses that have already been formed. Moving a zone from `ra` to `off` stops new autoconfiguration and reports the old address as a violation; it does not remove it.

The full stance is in [IPV6_STANCE.md](IPV6_STANCE.md).

---

## The timestamps are wrong, or you do not know whether to believe them

**Symptom:** log lines dated 1970, ages in `show leases` that make no sense, or a hunch that the box does not know what time it is.

Conntrack timeouts, rate-limit windows and every timestamp on this box are stated in one clock. If that clock is wrong, none of it is a little bit wrong — the *ordering* is gone, which is what any later analysis actually depends on.

```
$ einheit-f show time
 FIELD      │ VALUE
 trust      │ synchronised
 rtc        │ present — rtc0 (rk808-rtc)
 wall clock │ 2026-08-14 17:52:03 UTC
 uptime     │ 3h
 reference  │ Reference ID : 8EFB2A0A (192.0.2.10); Stratum : 3
```

The row that matters is **trust**, and there are four answers:

| trust | What it means | What to do |
|---|---|---|
| `synchronised` | The kernel says a time source is disciplining the clock. Timestamps mean what they say. | nothing |
| `NOT YET SYNCHRONISED` | An upstream is configured and has not converged. Normal for the first seconds after boot. | if it persists, check the uplink can reach the upstream |
| `NO TIME SOURCE` | Nothing is configured to set the clock, so nothing ever will. | add an `ntp:` service with an `upstream:`, then `apply system` |
| `unknown` | The state could not be read. **Not** the same as correct. | investigate; this should not happen |

When the clock cannot be trusted, every view that prints one leads with a banner rather than making you notice for yourself:

```
THE CLOCK IS AT THE EPOCH. Every timestamp below is wrong, and logs
written now are stamped 1970 — an upstream is configured and has not
converged. This board has no RTC, so it starts from the epoch on
every boot.
```

Note the **rtc** row. It is a hardware fact the board answers for itself, and it changes what "not yet synchronised" means: with an RTC the clock is merely a little out; without one it started at zero and there is nothing to fall back on until the network comes up.

**uptime is always trustworthy.** It is monotonic and owes nothing to NTP, so it is the ordering that still works for anything stamped before the clock was set. Correlating events across a window that includes a boot: use it.

Two things worth knowing about how time gets here:

- The first correction is a **step, not a slew** (`makestep 1.0 3`). A board that boots at the epoch cannot be walked to the right time in any useful period, and the window before the first correction is exactly the window where timestamps are worthless.
- The NTP **server** answers only on the zone it is bound to. `show services` names where; the uplink is never in that list, and with `serve: false` there is no server socket at all.

**If chronyd will not start with a permission error on a file you can read perfectly well:** the generated config lives at `/etc/chrony/f-generated.conf` rather than under `/etc/f/`, because Debian's AppArmor profile confines chronyd to `/etc/chrony/{,**}`. The artifact moved rather than the policy.

---

## The box is running out of disk, or has quietly stopped recording

**Symptom:** either nothing at all, or a service that will not start for no reason it can articulate. An appliance that fills its own disk stops working, and it does it at the office rather than on the bench.

```
$ einheit-f show storage
 WHAT             │ VALUE
 free space       │ 3812 MiB of 4096 MiB
 compiled bundles │ 47 using 384 KiB
 beyond the limit │ 37 (keeping 10)
 journal          │ 198 MiB
 dropped logs     │ 0 message(s) in 0 burst(s), 24h

37 bundle(s) are beyond the retention limit. fd prunes after each
reload; `f-sysconf prune` does it now.
```

**Compiled bundles.** Every reload writes a new timestamped directory under `/usr/share/f/compiled/` and repoints `current`. `fd` prunes after each successful reload — after the symlink moves, so the running policy is already `current` and therefore never a candidate. Tidying up must not be able to cause an outage. By hand: `f-sysconf prune --dry-run`, then `f-sysconf prune`.

**Dropped logs.** This is the row to read. journald's default answer to a high event rate is to discard silently, and a broadcast storm is exactly a high event rate — so the default trades away the minute most worth having. `apply system` writes `/etc/systemd/journald.conf.d/10-f.conf` with `RateLimitBurst=0`, which disables the limiter and leaves the disk cap as the only bound.

If that row is ever non-zero, something put the limiter back. Re-run `apply system`, then find out what.

**Do not trust a zero there too far.** Measured on systemd 257: the "Suppressed N messages" record is written at the *end* of the rate-limit interval, so a read taken during a storm reports zero while messages are being thrown away; and it is written *lazily*, on the next message from that source after the interval expires — so a box that goes quiet after a storm never records that it dropped anything at all. That is the argument for turning the limiter off rather than for watching the counter.

`show storage` exits non-zero when the disk is tight, when events have been dropped, or when it could not read the paths at all — the last because "could not look" is not the same as "nothing there".

---

## A service is not running, and you need to know which kind of not-running

**Symptom:** DHCP is not answering. `systemctl status` is not much help: systemd reports a unit that was never installed and a unit that crashed in almost the same way, and it keeps reporting a deleted unit's last `ActiveState` long after the file is gone.

```
$ einheit-f show services
 SERVICE            │ STATE         │ ZONES   │ BOUND TO │ ANSWERS ON │ UNIT
 dhcp+dns (dnsmasq) │ NOT INSTALLED │ testnet │ lan0     │ ? (not running) │ f-dnsmasq.service

dhcp+dns (dnsmasq): the model binds a service to testnet, but
f-dnsmasq.service is not installed on this box
```

| STATE | What happened | What to do |
|---|---|---|
| `running` | Should run, does. | — |
| `not configured` | Nothing is bound here and nothing runs. Correct. | — |
| `NOT INSTALLED` | The model binds a service here; the unit file is not on the box. | Install it (`deploy/systemd/f-dnsmasq.service`), then `systemctl daemon-reload`. |
| `STOPPED` | The unit exists and nobody ever started it. | `systemctl enable --now f-dnsmasq` |
| `FAILED` | It tried and died. The last thing it said is in the detail line. | Read the detail, then `journalctl -u f-dnsmasq`. |
| `RESTARTING (failing)` | Flapping. systemd calls this `activating` for the whole restart burst, which reads as "starting". | Treat as failing. `journalctl -u f-dnsmasq`. |
| `running (not in the config)` | Running, and the model says it should not be. | Something else is serving this segment. Find it. |
| `unknown` | systemd could not be reached. | Not the same as fine. |

The one to be careful with is `RESTARTING`. A unit that flaps forever looks alive in every dashboard while serving nobody; `f-dnsmasq.service` therefore carries a `StartLimitBurst` so it eventually sits in `failed`, where both systemd and this view say so out loud.

And note that `running` in the STATE column is a statement about the process, not about the service. Check `ANSWERS ON` as well — see the first entry on this page.

---

## A restart left pins behind in bpffs

**Symptom:** `fd` restarts and either refuses to load a bundle, or loads it and connection tracking behaves as though it remembers things it should not.

BPF maps pinned under `/sys/fs/bpf/f` outlive the process that made them. That is what keeps conntrack state across a daemon restart, and it is also what leaves debris behind when the policy changes shape.

**Which case you are in matters:**

- **Cold boot** — a *previous* `fd` left the pins. Pins the incoming bundle cannot reuse are **removed**. The alternative is a daemon that will not start, and a firewall that is down filters nothing at all. Conntrack entries the daemon's own GC rule would already have condemned are swept on adoption, so an adopted table does not come back full of week-old flows.
- **Hot reload** — this same `fd` has the current policy attached. A pin that cannot be reused is **left alone**, the load fails, and the running policy stays up. There is a fallback here, so destroying live state to force the new bundle in would be the wrong trade.

**Recovery.** On a refused hot reload the message names the map and both definitions — the one the loading zone declares and the one already pinned. Fix the mismatch in the policy, or, if you genuinely want the new shape and can afford to lose the state, restart `fd` so the cold-boot rule applies:

```
$ sudo systemctl restart fd
$ einheit-f show zones
```

Note the asymmetry that trips people up: a restart discards a *policy-scoped* pin whose definition changed, but **adopts** a persistent one (`conntrack`, `fwl_nat`) whose definition still matches. If you want a persistent map genuinely empty, the pin has to go.

Check the `ATTACHED` and `MODE` columns afterwards. A declared interface with no attach shows `(none)`, and `generic` in `MODE` means you are on the software slow path, not at line rate.

---

## NAT stops working for new flows

**Symptom:** existing connections through the box keep working; new ones go out and nothing comes back. Typically after a long soak or a scan, with many short-lived flows.

**Cause.** The shared NAT map (`fwl_nat`) is a fixed-size hash. Every translated flow installs a reply mapping; when the map is full, new mappings cannot be installed and the *return* packet has nothing to de-NAT against.

```
$ einheit-f show nat
masquerade source: 198.51.100.9
 PROTO │ TYPE │ ORIG SRC          │ ORIG DST    │ TRANSLATED
 tcp   │ snat │ 10.10.0.132:51234 │ 8.8.8.8:443 │ 198.51.100.9:51234
```

A table that is long and full of stale-looking entries, next to outbound traffic that does not come back, is the signature.

**Restarting `fd` does not clear it.** This surprises people, so it is worth being explicit. `fwl_nat` is a **persistent** map: pinned under `/sys/fs/bpf/f/`, and a cold boot *adopts* it if the incoming bundle declares the same definition — deliberately, so translated flows survive a daemon restart. Conntrack entries are swept against the GC timeout when adopted; NAT mappings are not. Measured on a VM, one translation installed by real traffic:

```
after traffic:                    1 translation
after a plain restart of fd:      1 translation
after removing the fwl_nat pin:   0 translations
```

**Recovery, in order of how much it costs you:**

1. **Wait.** Mappings go when the flows that own them do. If the box is otherwise healthy this is the cheapest fix.
2. **Drop the pin.** This is the one that actually empties the table. It also throws away the translations for every *live* flow, so anything currently connected through the box breaks:

   ```
   $ einheit-f show nat            # confirm the table is the problem
   $ sudo systemctl stop fd
   $ sudo rm -f /sys/fs/bpf/f/fwl_nat
   $ sudo systemctl start fd
   $ einheit-f show nat            # empty
   ```

   Do not delete the pin while `fd` is running.
3. If it fills again quickly, the pool is genuinely too small for the traffic. That is a policy change, not an operational one.

**Known gap in this build.** There is no occupancy figure and no log line when an allocation fails: `bpf_map_update_elem` on `fwl_nat` ignores its return value, so a full table is silent in the datapath and you diagnose by symptom. The refusal-and-log, the per-mapping lifetime tied to its flow, and the occupancy report exist on the rig branch and are not merged here. If `show nat` on your box prints an occupancy line, you have the newer one — read that rather than guessing from the table length.

---

## The bench gets no addresses the moment the firewall is loaded

**Symptom:** DHCP works with `fd` stopped and stops the moment a policy is loaded. Nothing is logged. On the office side of the uplink, a capture shows the bench's request arriving there:

```
10.99.82.1.68 > 255.255.255.255.67
```

**Cause.** A gateway zone whose block is `masquerade` then `redirect to wan` with nothing above it. Both actions are unconditional, so a packet addressed to *this box* — and a DHCP DISCOVER is addressed to `255.255.255.255`, because the client has neither an address of its own nor yours — is source-NATed and broadcast onto the office network. The appliance's own DHCP server, correctly bound and correctly contained, never sees it.

**Fix.** Two terminal rules ahead of the rewrite:

```
@xdp(lan)
allow if pkt.proto == udp and pkt.dst_port == 67
allow if pkt.dst_ip == 10.10.0.1
masquerade
redirect to wan
```

`allow` is terminal, so a packet these match never reaches `masquerade`. See [fwl/06-nat.md](fwl/06-nat.md) and `fwl/examples/storm_shield.fw`.

While you are there: the same block should drop the bench's own broadcast and multicast rather than masquerading it onto the uplink one frame at a time. That is the difference between a storm shield and a storm.

---

## Small things work and large transfers hang

**Cause.** `allow if conntrack(pkt).state == established` on the zone facing the outside.

An ICMP error carries no ports, so it can never be `established` — including the fragmentation-needed message that path-MTU discovery depends on. Ping works, DNS works, SSH connects, and every large transfer stops partway with nothing logged.

**Fix.** `allow if conntrack(pkt).state in [established, related]`. See [fwl/04-stateful.md](fwl/04-stateful.md#why--established-is-the-wrong-spelling).

---

## Nothing crosses the box, and `show zones` looks fine

**Symptom.** The box answers, its addresses are up, `show zones` shows every port attached, and no traffic gets from one zone to another. A ping from the inside to the box works; a ping *through* it does not.

**Read `forwarding` in `show status` first.** It is there in every state, and it is the only line that distinguishes the four:

```
$ einheit-f show status | grep -i forwarding
 forwarding   OFF — this box is not routing (cold boot: NO interface is
              running an f program, so nothing is being filtered)
```

**This box fails closed: it routes only while it is filtering.** `fd` owns `net.ipv4.ip_forward` — it lowers it on the way in, raises it once a compiled bundle is attached to at least one interface, and lowers it again when it stops, when an attach leaves nothing in the packet path, and when it is killed. The generated `/etc/sysctl.d/10-f-forwarding.conf` sets it to `0` and is only the boot-time floor.

That is a deliberate reversal of an earlier decision, and knowing why saves you the wrong fix. A box whose bundle had been removed used to refuse to start `fd` — correctly and loudly — and go on routing anyway, unfiltered and un-NATed, because the sysctl had been written once at provisioning time and reapplied every boot. An unsolicited inbound connection the healthy box refused with zero frames on the inside wire completed end to end. **A box that does not forward is a fault you can see; a box that forwards unfiltered is one you cannot.**

**So do not set the sysctl by hand.** What each row means:

| `forwarding` says | What is true | What to do |
|---|---|---|
| `on (…datapath armed on N interface(s))` | Healthy. The problem is elsewhere — check `MODE` and `ATTACHED` in `show zones`, and `route_unreachable` / `route_no_neighbour` in `show status`. | — |
| `OFF — this box is not routing (…)` | `fd` closed it, because nothing of yours is in the packet path. | Fix what the reason names. This is the fault; forwarding is the symptom. |
| `OFF, and fd did not do it` | The datapath IS armed and something else set the knob to 0. `fd` reports this and deliberately does not override you. | `sysctl -w net.ipv4.ip_forward=1`, then find what set it — usually another drop-in in `/etc/sysctl.d/` sorting after f's own. |
| `ON WITHOUT A DATAPATH` | Seen only in the seconds before `fd` closes it. | Nothing. If it persists, `fd` is not running at all. |

`fctl status` answers the same question in raw JSON, under `route`: `ip_forward`, `forwarding_desired`, `forwarding_reason` and `forwarding_corrections`. A non-zero `forwarding_corrections` means something else on this box writes the knob too.

**The journal carries every transition**, with the reason attached, which is the fastest way to see what happened while you were not looking:

```
$ journalctl -u fd -g forwarding
fd[412]: forwarding: net.ipv4.ip_forward 0 -> 1 (cold boot: datapath
         armed on 2 interface(s)).
fd[412]: forwarding: net.ipv4.ip_forward 1 -> 0 (fd is stopping: XDP is
         being detached from every port).
```

**Why `systemctl stop fd` stops traffic and `systemctl restart fd` does not.** The lowering happens *before* the XDP detach, so there is no window in which this box is a plain unfiltered router; a restart raises it again as soon as the new bundle is attached, which under normal load is a second or two. If you need the box to keep forwarding while you work on `fd`, you do not — that is the whole point.

---

## Where the state lives

| Path | What it is | Who writes it |
|---|---|---|
| `/etc/f/system.yaml` | The system configuration. The only thing you edit. | you, and `set address` / `set reservation` |
| `/etc/f/generated/dnsmasq.conf` | Derived artifact. Digest-stamped; edits are reported as drift. | `apply system` |
| `/etc/chrony/f-generated.conf` | Derived artifact. **Not** under `/etc/f/` — Debian's AppArmor profile confines chronyd to `/etc/chrony/`. | `apply system` |
| `/etc/sysctl.d/10-f-ipv6.conf` | Derived artifact: the per-zone IPv6 stance. | `apply system` |
| `/etc/sysctl.d/10-f-forwarding.conf` | Derived artifact, and only the **boot-time floor** (`ip_forward = 0`). The running value is `fd`'s. | `apply system` writes the file; `fd` writes the kernel |
| `/etc/systemd/journald.conf.d/10-f.conf` | Derived artifact: the journal cap and the rate limiter. | `apply system` |
| `/etc/systemd/network/10-f-*.link` | Derived artifact: hardware identity to durable name. Removed when its interface leaves the model. | `apply system` |
| `/etc/systemd/network/10-f-*.network` | Derived artifact: addressing. | `apply system` |
| `/usr/share/f/compiled/` | Compiled bundles, newest 10 plus whatever `current` points at. | `fd`, pruned after each reload |
| `/var/lib/f/dnsmasq.leases` | dnsmasq's lease database. Read-only to us. | dnsmasq |
| `/var/lib/f/devices.json` | Device history: when each MAC first appeared. | whatever runs `show leases` |
| `/sys/fs/bpf/f/` | Pinned BPF maps — conntrack and NAT state. | `fd` |

`devices.json` is the only file here that records something nothing else knows. Delete it and every device on the segment reverts to "found, not watched": ages become `>=` bounds and nothing is marked `NEW` until the next arrival. That is a loss of information, not a fault, and the view says so the first time it runs afterwards.

If it cannot be written — running as a non-root user, or a full filesystem — `show leases` says so at the top rather than quietly losing the ability to detect arrivals:

```
device history is NOT being recorded (cannot write
/var/lib/f/devices.json) — arrivals will not be detected
```
