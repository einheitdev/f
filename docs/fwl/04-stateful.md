# 4. Stateful policy

Everything so far judged each packet on its own. That is enough for a wall and not enough for a gateway, because the answer to "should this packet be allowed in" is usually "yes, if somebody in here asked for it".

## `conntrack(pkt).state`

```fwl
zone wan = [wan0]
zone lan = [lan0]

@xdp(wan)
allow if conntrack(pkt).state == established
default drop

@xdp(lan)
redirect to wan
```

`conntrack(pkt).state` is the first construct with a side effect. The connection table is a BPF map; an allowed `new` packet **creates** the entry that a later packet reads as `established`. Reading the state does not create anything, and `redirect` alone does not either — entry creation happens on an explicit `allow`.

The states:

| State | Meaning |
|---|---|
| `new` | no entry for this flow |
| `established` | an entry exists, in either direction |
| `related` | an ICMP error whose embedded datagram belongs to a tracked flow |
| `invalid` | the packet cannot be classified |

Only `==`, `!=` and `in` are valid. `conntrack(pkt).state < established` is refused: these are categories, not a scale.

## Why `== established` is the wrong spelling

This is the most expensive small mistake in the language, and it was live in the shipped `storm_shield.fw` example until recently.

```
allow if conntrack(pkt).state == established      # wrong
allow if conntrack(pkt).state in [established, related]   # right
```

An ICMP error carries no ports. It is an ICMP packet whose payload contains the head of the datagram that provoked it, so it can never be `established` in its own right — its tuple is not the flow's tuple. It is `related`: classified from the tuple *embedded in the datagram it carries*.

The error that matters is fragmentation-needed. Path-MTU discovery is how a host learns that a link somewhere along the route has a smaller MTU than it assumed, and the mechanism is exactly this ICMP error coming back. Drop it and:

- ping works, because echo replies are small;
- DNS works, because queries are small;
- SSH connects, because the handshake is small;
- and every large transfer hangs partway through, with nothing logged anywhere, forever.

It presents to the person using the network as "it is slow" or "it is flaky", which is the hardest possible thing to debug and the least likely thing to be reported accurately. IPv6 makes it worse: v6 routers never fragment, so PMTU discovery is the *only* mechanism there is.

Write the list. Every time.

## A stateful gateway

```fwl
zone wan = [wan0]
zone lan = [lan0]

@xdp(wan)
allow if conntrack(pkt).state in [established, related]
default drop

@xdp(lan)
allow
redirect to wan
```

That still does not work, and the reason is instructive. `allow` is terminal, so `redirect to wan` is dead code — everything from the bench is handed to the local stack and nothing ever leaves. The gateway needs the entry to be created *and* the packet to be forwarded, and only one action can be terminal.

The shape that works is in [step 6](06-nat.md), where the NAT rewrite creates the mapping and `redirect` stays the terminal action. Until then, this is the honest version of a two-zone stateful policy where the box itself is the endpoint:

```fwl
zone wan = [wan0]
zone lan = [lan0]

@xdp(lan)
# Traffic to services on this box. Creates the conntrack entry.
allow

@xdp(wan)
# Only answers to conversations this box started.
allow if conntrack(pkt).state in [established, related]
default drop
```

## What state does not do

**It does not survive a policy that changes shape.** The map is pinned, so it survives a daemon restart; a bundle that declares the map differently cannot adopt it. See [recovery.md](../recovery.md#a-restart-left-pins-behind-in-bpffs).

**It is not a substitute for a default action.** An `invalid` packet is not `established`, so it falls through — to whatever the last line says.

**It does not know about application protocols.** There is no FTP helper, no SIP helper. `related` means ICMP errors, not a second data connection somebody negotiated in a payload.

---

Previous: [3. Zones](03-zones.md) · Next: [5. Finding out what is happening](05-observability.md)
