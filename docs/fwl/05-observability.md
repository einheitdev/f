# 5. Finding out what is happening

A policy you cannot see the effect of is a policy you cannot tune, and — more to the point — a policy whose failures are invisible. A dropped packet leaves no trace anywhere unless you asked for one.

## `count`

```fwl
@xdp(eth0)
count total
count from_office if pkt.src_ip in 10.0.0.0/8
count ssh_attempts if pkt.proto == tcp and pkt.dst_port == 22
       and pkt.tcp.syn and not pkt.tcp.ack
default drop
```

`count <name>` increments a named counter and **falls through**, so counting does not change what happens to the packet. That makes a counter safe to add to a policy you do not want to disturb.

Because it falls through, position matters in a way that is easy to get wrong: a counter placed after a `drop` counts only the packets that survived it.

```fwl
@xdp(eth0)
count arrived                       # everything
drop if pkt.src_ip in 10.0.0.0/8
count survived_the_office_filter    # only what got past
default allow
```

Both of those are useful; the mistake is writing the second and reading it as the first. Put the total at the top of the block.

**Reading them back: `einheit-f show counters`.** `count` compiles to a slot in the zone's own `fwl_counters_<zone>` map, and the verb reads that map and prints each slot under the name your policy gave it:

```
 ZONE  │ COUNTER                    │ PACKETS
 edge  │ edge_probe                 │       7
 edge  │ edge_never                 │       0
 quiet │ (no count statements)      │       -
```

`show counters <name>` answers for one counter. The names come from the bundle's own generated C — the compiler writes a `// fwl_counter_table:` block into each `<zone>.bpf.c`, and `fd` reads it in the same load that opens the map, so a name and a value always come from the same policy.

Four states are kept apart on purpose, because three of them used to render as the same blank screen. A counter that reads `0` was read and nothing hit it. A zone shown as `(no count statements)` declares none. A zone shown as `(names unknown)` has a map whose slots nobody can name — its generated C is missing — and its counters are deliberately **not** shown as zeros. A zone shown as `(stale table)` has generated C that is not the source of the object that is loaded, so every name it offers would be attached to the wrong slot; none is offered. `show counters <name>` distinguishes them too: a name no policy declares is refused, while a name that was not found in a zone whose table could not be read answers "cannot say whether it exists", which is a different thing.

This verb is not the one that used to be here. The v0.1 `show counters` and `show firewall rules` addressed the single-program firewall, whose `counters` map is not the one your policy writes to; on a v0.4 box they printed "no counters active" and "no rules loaded" beside counters that were moving. `show firewall rules` is still gone, and `clear counters` with it. The rules of the loaded policy are not gone, though: the bundle now carries them per zone and `einheit-f show policy` renders them beside the source, with a verdict on whether the two still agree. They carry no hit counts — a rule and a counter are joined by nothing in that answer, deliberately — so `count` remains the way to measure a rule.

**The same answer on the web UI.** `http://<box>:7542/counters` renders the same table, in the same words, from the same daemon command — a second consumer of one answer, not a second reader of the map. The four states above are four visibly different pages there too; that is asserted rather than assumed (`tests/system/test_ui_counters.py` compares them). The `/policy` page beside it reports what `fd` has **loaded**: each zone's interfaces, the XDP mode measured on them, its redirect and masquerade behaviour, and the counters that zone's loaded policy declares. It does not list rules, and it says so on the page — the daemon holds compiled objects, and there is nothing in the bundle it could be asked for a rule with.

## Counters as evidence

The counters worth having are the ones that let you tell two indistinguishable situations apart. A quiet segment and a broken capture look identical on a screen that only shows what got through.

```fwl
# The office side of a bench gateway. Every drop is counted before it
# happens, so "nothing arrived" and "everything was refused" are
# different numbers rather than the same empty screen.
@xdp(eth0)
count wan_total
count noise_multicast if pkt.dst_ip in 224.0.0.0/4
count noise_broadcast if pkt.dst_ip == 255.255.255.255
count noise_netbios if pkt.proto == udp
       and (pkt.dst_port == 137 or pkt.dst_port == 138)

drop if pkt.dst_ip in 224.0.0.0/4
drop if pkt.dst_ip == 255.255.255.255
drop if pkt.proto == udp
       and (pkt.dst_port == 137 or pkt.dst_port == 138)
default drop
```

`wan_total` at zero and `noise_multicast` at zero mean "the cable is dead". `wan_total` at four hundred thousand and `noise_multicast` at three hundred thousand mean the policy is doing its job. Without the totals both look like a screen full of nothing.

## `log`

```fwl
@xdp(eth0)
log if pkt.proto == tcp and pkt.dst_port == 22 and pkt.tcp.syn
allow if pkt.proto == tcp and pkt.dst_port == 22
default drop
```

`log` writes one fixed-shape event to a BPF ring buffer and falls through. The record carries a timestamp, the rule index, the packet's five-tuple, the action and the zone. Userspace reads the buffer; `einheit-f show log` prints it.

Two limitations to know before you design around it:

- **There is no message and no sampling.** `log` takes no arguments. `log("...", sampled=N)` is named in the v0.1 specification as deferred, and it is still deferred — a page that told you otherwise would be describing something that does not exist. Distinguish rules by the rule index in the record.
- **One matching packet is one event.** A `log` rule on a rule that matches a flood produces a flood of events. Use `count` for volume and `log` for things that should be rare, or gate the `log` behind a rate limit — see [step 7](07-rate-limiting.md).

## What the box does with a flood of events

Worth knowing because it changes what you can trust. journald's default answer to a high event rate is to discard silently, and a broadcast storm is exactly a high event rate — so the default throws away the minute most worth having.

`apply system` writes a journald drop-in with the rate limiter disabled, leaving the disk cap as the only bound. That is the right trade for a box whose job is recording what happened on a hostile segment. `einheit-f show storage` reports how many messages have been dropped; a non-zero number there means something put the limiter back.

Do not lean on that counter, though. journald writes its "suppressed N messages" record at the *end* of the rate-limit interval and *lazily*, on the next message from that source — so a box that goes quiet after a storm never records that it dropped anything at all. That is an argument for turning the limiter off, not for watching the number.

---

Previous: [4. Stateful policy](04-stateful.md) · Next: [6. NAT](06-nat.md)
