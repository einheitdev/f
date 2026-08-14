# 3. Zones

This is the step the whole model hangs off. Everything before it was one program on one port. A zone is what lets a box have an *inside* and an *outside*, and lets a packet cross between them.

## Declaring zones

```fwl
zone wan = [wan0]
zone lan = [lan0, lan1, lan2]

@xdp(wan)
default drop

@xdp(lan)
default allow
```

A zone is a set of interfaces. `@xdp(<zone>)` opens a block of rules for the traffic *arriving* on that zone; the compiler produces one BPF program per zone and the daemon attaches each one to that zone's ports.

An interface belongs to exactly one zone. Declaring it in two is a compile error, not a merge.

**The zone list also lives in `system.yaml`, and that is the copy that owns it.** The system configuration decides which physical port carries which name and which zone it is in; the policy references those names. Today the two are not cross-checked at build time — a typo in a `.fw` zone name is caught, but a zone name that does not exist in the box's `system.yaml` is not. That check is on the list and not yet built.

## Crossing between zones

```fwl
zone wan = [wan0]
zone lan = [lan0]

@xdp(lan)
redirect to wan

@xdp(wan)
default drop
```

`redirect to <zone>` is terminal, like `allow` and `drop`. It hands the frame to the destination zone's ports without going anywhere near the host's network stack or its routing table.

That is worth stopping on, because it is the source of most confusion about `allow`:

| Action | Where the packet goes |
|---|---|
| `allow` | this box's own network stack — for daemons running here |
| `drop` | nowhere |
| `redirect to <zone>` | out of the other zone's ports |

So `allow` on a gateway's inside zone does not forward anything. And `redirect` on a zone that is meant to serve DHCP sends the DHCP request out of the wrong port. Both mistakes are silent.

`redirect` is valid as a rule action with a condition, and as an unconditional statement. It is **not** valid as a default action — `default redirect to wan` is a syntax error, because the default is where you say what happens to traffic you did not decide about, and "send it somewhere else" is a decision.

Where more than one port is in the destination zone, the frame goes out of the zone's device map and the fabric's own learning picks the physical port.

## `pkt.zone`

Inside a block you can ask which zone the packet arrived on:

```fwl
zone wan = [wan0]
zone lan = [lan0]
zone dmz = [dmz0]

@xdp(dmz)
redirect to wan if pkt.zone == dmz
default drop

@xdp(wan)
default drop

@xdp(lan)
default drop
```

Within a single `@xdp` block that is a constant and the compiler folds it, so it is not much use on its own. It earns its place in [step 8](08-advanced.md), where one helper is shared by several zones and needs to know which one called it.

`pkt.zone` compares with `==`, `!=` and `in [...]`. Ordered comparison is refused: zones are names, not a ranking.

## A three-zone shape

```fwl
# Office uplink, test benches, and a DMZ holding one web server.
zone wan = [wan0]
zone lan = [lan0]
zone dmz = [dmz0]

@xdp(wan)
# From the office, only the web server is reachable.
redirect to dmz if pkt.proto == tcp and pkt.dst_port in [80, 443]
default drop

@xdp(lan)
# Benches reach the office and the DMZ.
redirect to wan
default drop

@xdp(dmz)
# The web server answers, and initiates nothing inward.
redirect to wan
default drop
```

This policy has a real hole in it, and it is the one the next step closes: the `wan` block admits *anything* to the DMZ on 80 and 443, including a packet that is not an answer to anything, and the `lan` block has no way to get replies back. Zones move packets; they do not remember conversations.

## Hairpins

`redirect to <the zone the packet arrived on>` is allowed. It forwards the frame back out of the ingress zone, which is what a switch does and occasionally what you want. It will not loop inside the program.

---

Previous: [2. Matching](02-matching.md) · Next: [4. Stateful policy](04-stateful.md)
