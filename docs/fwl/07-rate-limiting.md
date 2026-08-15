# 7. Rate limiting

One stateful primitive, attached to a rule rather than standing on its own.

## The modifier

```
<rule> limited by rate_limit(<N>, per=<field>[, scope=<zone|global>])
```

`per=` takes `src_ip`, `dst_ip`, `src_port` or `dst_port`, and it is the *bucket key*: one budget per distinct value of that field.

## Reading it correctly

The reading that matches the words is: **the rule fires only once the bucket already holds `N` in the current second.**

```fwl
@xdp(eth0)
# The 11th and subsequent SYNs from one source in one second are
# dropped. The first ten are not dropped *by this rule*, so they fall
# through to whatever comes next.
drop if pkt.proto == tcp and pkt.dst_port == 22 and pkt.tcp.syn
       and not pkt.tcp.ack
       limited by rate_limit(10, per=src_ip)
allow if pkt.proto == tcp and pkt.dst_port == 22
default drop
```

That two-rule shape is the idiom, and it is worth understanding why it takes two rules. The limiter does not "allow N and drop the rest" on its own — it gates *whether the rule's action fires*. So the drop rule catches the excess, and the allow rule underneath catches everything the drop rule declined to act on.

Written the other way round it does nothing useful:

```fwl
@xdp(eth0)
# This does NOT rate-limit anything: the rule fires only when the
# bucket is already full, so it allows the excess and drops the
# first ten.
allow if pkt.proto == tcp and pkt.dst_port == 22
       limited by rate_limit(10, per=src_ip)
default drop
```

The modifier can also stand without a condition, in which case the rule applies to every packet and the limit alone decides:

```fwl
@xdp(eth0)
# A flood guard for whatever is left after the specific rules above.
drop limited by rate_limit(2000, per=src_ip)
default allow
```

## `scope=`

One program per zone raises a question a single-program world could not ask: when a rule appears in three zones, is `N` a budget per zone or a budget for the box?

```
scope=zone      # default: one budget per zone program
scope=global    # one budget for the rule across the whole bundle
```

`zone` is the default, and it is the behaviour every policy written before `scope=` existed already had, so adding the field changes nothing that is deployed. Under it, a rule written into three zones is three independent budgets and the box admits up to `3N`.

```fwl
zone wan = [wan0]
zone lan = [lan0]

@xdp(wan)
drop limited by rate_limit(1000, per=src_ip, scope=global)
default allow

@xdp(lan)
drop limited by rate_limit(1000, per=src_ip, scope=global)
default allow
```

A `scope=global` bucket is one bucket **per rule**, and "the same rule" means structurally the same rule: same action, same condition, same threshold, same `per=`, same scope. That is what makes the shape above work — one rule written once per block is one rule, so it gets one bucket. Change one of them and you have two rules and two buckets.

## The per-CPU caveat, which you must know before you trust a number

The counter lives in a per-CPU map. `scope=global` makes two zones read the same *map*; each CPU still keeps its own counter within it.

So the budget is **`N` per second per bucket key per CPU**, under both scopes. That multiplier has always been there — a single-zone policy has it too — and `scope=` does not change it.

What this means in practice:

- Two zones' traffic shares a budget when it is handled on the same CPU, and for a single flow (one receive-side-scaling bucket) it normally is.
- Traffic the kernel spreads across CPUs does not share, so a distributed flood gets `N × <cpus>` before the rule fires.
- Therefore `rate_limit` is a **flood guard, not an accounting mechanism**. Set `N` for the order of magnitude you want to survive, not for a number you intend to quote to anybody.

Removing the multiplier is a change to `rate_limit` itself and is not in this version.

## Using it to make `log` survivable

A `log` rule on something that floods produces a flood of events. The limiter gates any rule, including that one:

```fwl
@xdp(eth0)
# One log line per source per second, however hard it is scanning.
log if pkt.proto == tcp and pkt.tcp.syn and not pkt.tcp.ack
       limited by rate_limit(1, per=src_ip)
count scan_attempts if pkt.proto == tcp and pkt.tcp.syn
       and not pkt.tcp.ack
default drop
```

Note the reading again: this logs the *second and subsequent* attempts from a source within a second, and the `count` next to it carries the volume the log deliberately does not.

## Reading the counters back

`einheit-f show counters` prints every counter in the loaded policy under the name that declared it — see [5. Observability](05-observability.md) for the verb and the four states it keeps apart. A limit that never fires and a limit that fires constantly are both worth knowing about, and they are different from the rule's own hit count.

One counter in that list is not one you wrote: `__rate_limit_overflow`. It ticks when the per-CPU rate-limit map's bucket key space is exhausted, and a non-zero reading means some sources are sharing a bucket with others — the limit is still being applied, but not per the `per=` field you asked for. The double underscore marks it as reserved; it is listed rather than hidden, because a limit that has quietly stopped discriminating is exactly the thing a counter view exists to show.

---

Previous: [6. NAT](06-nat.md) · Next: [8. Helpers, Tier 2 and the splitter](08-advanced.md)
