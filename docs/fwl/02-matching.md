# 2. Matching on what is in the packet

Step 1 used two fields. This is the rest of them, and the operators that work on them.

## Addresses and networks

```fwl
@xdp(eth0)
drop if pkt.src_ip == 203.0.113.9
drop if pkt.src_ip in 10.0.0.0/8
allow if pkt.dst_ip in 192.168.1.0/24
default drop
```

Addresses are written bare — no quotes. `in` takes a CIDR and means "inside this network". It also takes a list:

```fwl
@xdp(eth0)
allow if pkt.src_ip in [10.0.0.5, 10.0.0.6, 10.0.0.7]
drop if pkt.proto == tcp and pkt.dst_port in [23, 135, 445]
default drop
```

and a range, for ports:

```fwl
@xdp(eth0)
allow if pkt.proto == tcp and pkt.dst_port in 8000..8100
default drop
```

IPv6 has its own fields, `pkt.src_ip6` and `pkt.dst_ip6`, which are separate rather than overloaded — an address is 32 bits or 128 bits and a rule should say which it meant:

```fwl
@xdp(eth0)
drop if pkt.src_ip6 in 2001:db8::/32
default drop
```

## Long lists of addresses: tables

A rule is code. Twenty of them is fine; two thousand is a chain of two thousand comparisons the box walks for every packet, and on the rig that is 12% of line rate against 99% for an empty policy. A **table** is the same intent as data: one lookup against a prefix trie, at a cost that does not depend on how many prefixes are in it. Measured, 50,000 prefixes cost what 1,000 cost, and both cost what none cost.

```fwl
table corporate_blocklist {
  kind = cidr4
  max = 100000
  source = "feeds/blocklist.txt"
}

@xdp(eth0)
drop if pkt.src_ip in corporate_blocklist
default allow
```

The three attributes are all required.

`kind` is `cidr4` or `cidr6` and fixes the key width. Everywhere else FWL infers what a value is; a table cannot, because the map is created before any entry exists and an empty table still has to have a key size.

`max` is capacity. It lives in the policy rather than the config because it is a shape the map is created with, so it belongs beside the rules that depend on it. A source file with more prefixes than `max` is **refused, not truncated** — a blocklist quietly missing entries forwards exactly the traffic it was written to drop.

`source` is a file of one prefix per line; `#` starts a comment and blank lines are ignored. A relative path is read next to the `.fw`, so a policy and its feed travel together. Today the file is read when you compile, so changing the list means recompiling.

Matching is the ordinary `in`, so a table goes anywhere a CIDR does — under `not`, inside an `or`, in a `def` body, in a helper shared between zones. A table is named once for the whole file and every zone that matches against it means the same set.

Nothing about a table is allowed to be quietly empty. An undeclared name, a `source` that does not exist, a file that resolves to nothing, an entry of the wrong family — each is a compile error naming the table and the line, because a rule that never matches is a hole that nothing on a running box reports.

An alias gives one table a second name, which is what lets a block of policy pasted from somewhere else keep the vocabulary it was written with:

```fwl
table corporate_blocklist {
  kind = cidr4
  max = 100000
  source = "feeds/blocklist.txt"
}

table badhosts = corporate_blocklist

@xdp(eth0)
drop if pkt.src_ip in badhosts
default allow
```

`badhosts` and `corporate_blocklist` are one table with one set of contents. The alias sits with the pasted block and can be deleted with it.

## Ports and protocols

`pkt.proto` takes `tcp`, `udp`, `icmp` or `icmp6`. `pkt.src_port` and `pkt.dst_port` are 16-bit and need a TCP-or-UDP guard.

```fwl
@xdp(eth0)
allow if pkt.proto == udp and pkt.src_port == 53
drop if pkt.proto == icmp
default drop
```

## Comparison and composition

`==`, `!=`, `<`, `<=`, `>`, `>=` and `in`. Ordered comparison is only meaningful on numbers, so `pkt.src_ip < 10.0.0.5` is a type error rather than a surprising answer about byte order.

Conditions compose with `and`, `or` and parentheses. `and` binds tighter than `or`, so parenthesise anything you would have to think about:

```fwl
@xdp(eth0)
drop if pkt.proto == udp
       and (pkt.dst_port == 137 or pkt.dst_port == 138)
default drop
```

Without those parentheses the rule would read "UDP with destination port 137, or anything at all with destination port 138", which is a different rule and one that would not compile — the second half has lost its guard.

## TCP flags

All eight, as booleans:

```
pkt.tcp.syn  pkt.tcp.ack  pkt.tcp.fin  pkt.tcp.rst
pkt.tcp.psh  pkt.tcp.urg  pkt.tcp.ece  pkt.tcp.cwr
```

A bare flag field is a valid condition on its own; there is no truthiness coercion for anything else.

```fwl
@xdp(eth0)
# A connection attempt is SYN without ACK. The `and not` matters: a
# SYN-ACK is a *reply*, and treating it as an attempt makes every
# established conversation look like a new one.
count attempts if pkt.proto == tcp and pkt.tcp.syn
       and not pkt.tcp.ack
# Nobody sends SYN and FIN together except a scanner.
drop if pkt.proto == tcp and pkt.tcp.syn and pkt.tcp.fin
default allow
```

## ICMP

```fwl
@xdp(eth0)
# Echo request, so ping works.
allow if pkt.proto == icmp and pkt.icmp.type == 8
# Fragmentation needed, which is what path-MTU discovery runs on.
# Dropping this gives you a network where ping works and every large
# transfer hangs.
allow if pkt.proto == icmp and pkt.icmp.type == 3
       and pkt.icmp.code == 4
default drop
```

ICMPv6 is `pkt.icmp6.type` and `pkt.icmp6.code`, guarded by `pkt.proto == icmp6`. The canonical rule you will want is neighbour discovery, without which a v6 segment does not work at all:

```fwl
@xdp(eth0)
allow if pkt.proto == icmp6 and pkt.icmp6.type in [133, 134, 135, 136]
default drop
```

## VLAN

```fwl
@xdp(eth0)
allow if pkt.vlan_id == 42
drop if pkt.vlan_priority >= 6
default drop
```

A tagged frame is parsed through its 802.1Q header, so every other field means what it means on the inner packet. On an untagged frame `pkt.vlan_id` is 0.

## Truncated and malformed packets

Every field read is bounds-checked. A packet too short to contain the header a rule wants to read does not match that rule, and it does not crash the program — it falls through to the next one. That is the only sane answer at line rate, and it is another reason the default action is the most important line in the file.

## What a policy of this shape looks like finished

```fwl
# Bench appliance: management from the jump host, and nothing else.
@xdp(eth0)

# Ping, both directions of the diagnostic, and the frag-needed that
# large transfers depend on.
allow if pkt.proto == icmp and pkt.icmp.type in [0, 8]
allow if pkt.proto == icmp and pkt.icmp.type == 3

# Management, from one host.
allow if pkt.proto == tcp and pkt.src_ip == 10.0.0.5
       and pkt.dst_port == 22

# The Windows file-sharing ports, which on a flat office L2 arrive
# constantly and are never wanted here.
drop if pkt.proto == udp
       and (pkt.dst_port == 137 or pkt.dst_port == 138)
drop if pkt.proto == tcp and pkt.dst_port in [139, 445]

default drop
```

---

Previous: [1. A first policy](01-first-policy.md) · Next: [3. Zones](03-zones.md)
