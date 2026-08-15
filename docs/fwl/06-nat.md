# 6. NAT

This is the step the guide has been walking towards: a bench segment with private addresses that reaches the internet through one uplink address, and an office that cannot reach back.

## The three actions

```
masquerade              # source -> the address the daemon holds for this zone
snat to <ip>            # source -> a fixed address
dnat to <ip>:<port>     # destination -> a fixed address and port
```

All three are **non-terminal rewrites**. They translate the packet in place and fall through, so the *next* terminal action is what emits the rewritten frame. That single fact explains most of this page.

`masquerade` uses the address the daemon wrote into the zone's NAT config — which is what makes it work on a DHCP uplink, where you do not know the address when you write the policy. `snat to` is the same rewrite against a literal you do know.

None of the three is valid as a default action.

## The gateway shape

```fwl
zone wan = [wan0]
zone lan = [lan0]

@xdp(lan)
masquerade
redirect to wan

@xdp(wan)
allow if conntrack(pkt).state in [established, related]
default drop
```

Read the `lan` block as one sentence: rewrite the source, then send it out of the uplink. `masquerade` on its own would do nothing you could see, because nothing would emit the packet.

The return path needs no rule. Every zone program in a bundle emits a de-NAT pass that runs **before any rule**: the incoming packet's tuple is looked up in the shared NAT map, and on a hit the recorded side is rewritten back to the original endpoint. So the `wan` block's `conntrack` rule sees the packet as it will be delivered, not as it arrived.

## The shape above is incomplete, and this is the important part of the page

`masquerade` and `redirect to wan` are both unconditional. Anything that reaches them leaves on the uplink wearing this box's address — **including packets that were never going anywhere, because they were addressed to this box.**

The case that finds it is DHCP. A client with no lease has neither an address of its own nor yours, so its DISCOVER is addressed to `255.255.255.255`. With the block above, that request is source-NATed to the gateway's uplink address and broadcast onto the office network, where it arrives as

```
10.99.82.1.68 > 255.255.255.255.67
```

while this box's own DHCP server — correctly bound, correctly contained, listening on exactly the right port — never sees the packet at all. The bench does not get an address. Stopping the firewall fixes it, which sends you looking in the wrong place.

The fix is two terminal rules ahead of the rewrite:

```fwl
zone wan = [wan0]
zone lan = [lan0]

@xdp(lan)
# DHCP first, and matched by port rather than by address: a client
# with no lease cannot address us.
allow if pkt.proto == udp and pkt.dst_port == 67
# ...and everything aimed at the gateway address itself: DNS, NTP, ssh.
allow if pkt.dst_ip == 10.10.0.1
masquerade
redirect to wan

@xdp(wan)
allow if conntrack(pkt).state in [established, related]
default drop
```

`allow` is terminal, so a packet these rules match never reaches `masquerade`.

The same reasoning covers the bench's own broadcast and multicast. None of it is routable and all of it would otherwise be masqueraded onto the uplink one frame at a time, which is how an appliance whose job is to keep noise *out* of the bench ends up putting bench noise into the office:

```fwl
zone wan = [wan0]
zone lan = [lan0]

@xdp(lan)
allow if pkt.proto == udp and pkt.dst_port == 67
allow if pkt.dst_ip == 10.10.0.1

# The bench's own noise stays on the bench.
drop if pkt.dst_ip in 224.0.0.0/4
drop if pkt.dst_ip == 255.255.255.255
drop if pkt.dst_ip == 10.10.0.255
drop if pkt.proto == udp
       and (pkt.dst_port == 137 or pkt.dst_port == 138)

masquerade
redirect to wan

@xdp(wan)
allow if conntrack(pkt).state in [established, related]
default drop
```

`fwl/examples/storm_shield.fw` is this policy, finished, with the office-facing half written out too.

## Port forwarding

```fwl
zone wan = [wan0]
zone lan = [lan0]

@xdp(wan)
# Public TCP/80 lands on the internal web server's 8080.
dnat to 10.10.0.20:8080 if pkt.proto == tcp and pkt.dst_port == 80
redirect to lan if pkt.proto == tcp and pkt.dst_port == 80
allow if conntrack(pkt).state in [established, related]
default drop

@xdp(lan)
masquerade
redirect to wan
```

Two rules, not one, and for the same reason as before: `dnat` rewrites and falls through, `redirect` emits. The reply mapping installed by the `dnat` restores the original public destination on the way back.

Note that the `redirect` rule tests the *original* port. Conditions after a rewrite still read the pre-NAT fields — the emitter captures them up front — so `pkt.dst_port == 80` is still true on the line below the `dnat`.

## Things to know before you rely on it

- **`snat` and `masquerade` are port-preserving.** The translated source port equals the original. Ephemeral-port reallocation on collision is not in this version, so two inside hosts using the same source port to the same destination collide.
- **IPv4 only.** A v6 frame is never rewritten and creates no mapping.
- **ICMP is not rewritten.** ICMP-error NAT is not in this version.
- **No IP options.** Only the common `ihl == 5` case is rewritten.
- **UDP checksum 0 stays 0.** A computed checksum that folds to zero is stored as `0xffff`, per the RFC.
- **The NAT map is a fixed-size hash and it is pinned.** When it fills, new mappings cannot be installed and return packets have nothing to translate against — existing connections keep working, new ones go out and nothing comes back. Restarting the daemon does *not* clear it. See [recovery.md](../recovery.md#nat-stops-working-for-new-flows).

## Checking your work on a real box

```
$ einheit-f show nat
masquerade source: 198.51.100.9
 PROTO │ TYPE │ ORIG SRC          │ ORIG DST    │ TRANSLATED
 tcp   │ snat │ 10.10.0.132:51234 │ 8.8.8.8:443 │ 198.51.100.9:51234
```

and, for one device behind the translation, `einheit-f show device 10.10.0.132` — which joins through the NAT table, because behind a masquerade the connection table is keyed on the addresses that are on the wire and the device's flows do not appear under its own address at all.

---

Previous: [5. Observability](05-observability.md) · Next: [7. Rate limiting](07-rate-limiting.md)
