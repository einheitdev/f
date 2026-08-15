# 1. A first policy

## The smallest thing that is a policy

```fwl
@xdp(eth0)
default drop
```

Three things are happening. `@xdp(eth0)` says which port this program attaches to. `default drop` is the fallback: any packet that reaches the end of the rule list without matching a terminal action gets dropped. And there are no rules, so every packet reaches the end.

That policy is a wall. Here is one with a door in it:

```fwl
@xdp(eth0)
allow if pkt.proto == tcp and pkt.dst_port == 22
default drop
```

Read it top to bottom, the way the kernel does. A packet arrives. Rule one asks whether it is TCP to port 22; if so, `allow` — which is *terminal*, so evaluation stops and the packet goes to this box's network stack. If not, evaluation falls off the end and `default drop` gets it.

## Rule shape

```
<action> [if <condition>] [limited by rate_limit(...)]
```

The action comes first. It is the thing you are doing; the condition is the thing you are doing it to. Actions in this step:

| Action | Terminal | Effect |
|---|---|---|
| `allow` | yes | hand the packet to this box's network stack |
| `drop` | yes | discard it |
| `count <name>` | no | increment a named counter, keep evaluating |
| `log` | no | write an event to the ring buffer, keep evaluating |

`default` takes only `allow` or `drop`. `default count x` is a syntax error, and deliberately: "fall through to the next rule" is not a meaningful thing for the last rule to do.

## Order is the policy

These two policies are not the same:

```fwl
@xdp(eth0)
drop if pkt.src_ip == 10.0.0.9
allow if pkt.proto == tcp and pkt.dst_port == 22
default drop
```

```fwl
@xdp(eth0)
allow if pkt.proto == tcp and pkt.dst_port == 22
drop if pkt.src_ip == 10.0.0.9
default drop
```

In the first, `10.0.0.9` cannot reach SSH. In the second it can, because `allow` already fired and evaluation stopped before the `drop` was ever reached. There is no priority mechanism and no implicit reordering: the first terminal match wins, and that is the entire dispatch rule.

This is why a policy is read out loud from the top, and why `drop` rules that are meant to be exceptions go above the `allow` they are exceptions to.

## Protocol guards

Notice the `pkt.proto == tcp and` in front of every port comparison above. It is not decoration and it is not inferred. `pkt.dst_port` only exists on TCP and UDP, and FWL refuses to read it from a packet that might not have one:

```
$ fwl check nogaurd.fw
error: 2:10: pkt.dst_port requires 'pkt.proto == tcp or udp' guard
```

The reason is that the alternative is worse than a compile error. Without the guard the emitted program would read whatever bytes happen to sit at the port offset of an ICMP packet or a fragment, compare them to 22, and occasionally match. A firewall that admits the wrong packet one time in ten thousand is not a firewall with a bug, it is a firewall you cannot reason about at all.

The same rule applies to `pkt.tcp.*` (needs `pkt.proto == tcp`) and `pkt.icmp.*` (needs `pkt.proto == icmp`). The guard has to be reachable in the same condition, joined by `and`.

A useful side effect: a rule that reads "TCP to port 22" is one you can check against a firewall request without translating it in your head first.

## Comments, and writing them for the next person

```fwl
# Management access. Restricted to the jump host; everything else that
# reaches this port is somebody scanning.
@xdp(eth0)
allow if pkt.proto == tcp and pkt.src_ip == 10.0.0.5
       and pkt.dst_port == 22
default drop
```

A rule can be continued on the next line by indenting it. Comments run from `#` to end of line.

The comments worth writing are the ones that say *why*. What the rule does is in the rule.

## Try it

```
$ fwl check policy.fw
ok

$ fwl compile policy.fw -o policy.bpf.c
```

`fwl check` runs the parser and the analyzer and prints nothing but `ok` when the program is well formed. Errors are named, located, and refused.

---

Next: [2. Matching on what is in the packet](02-matching.md)
