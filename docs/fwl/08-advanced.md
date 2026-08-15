# 8. Helpers, Tier 2 and the splitter

Everything so far was a list of rules. This step is about what to do when the list stops being the right shape — because the same logic belongs in three zones, or because a policy has grown past what one BPF program is allowed to be.

## Tier 2: a policy as a function

A `.fw` file is *either* a list of rules (Tier 1) *or* one function per zone (Tier 2). Not both in one block.

```fwl
zone lan = [lan0]

@xdp(lan)
def bench_policy(pkt):
  if pkt.proto == tcp and pkt.dst_port == 22:
    allow
  if pkt.src_ip in 10.0.0.0/8:
    drop
  allow
```

The same actions, the same terminal/non-terminal split, and the same top-to-bottom evaluation. What you get is nesting and local variables:

```fwl
zone lan = [lan0]

@xdp(lan)
def bench_policy(pkt):
  is_ssh = pkt.proto == tcp and pkt.dst_port == 22
  if is_ssh:
    if pkt.src_ip == 10.0.0.5:
      allow
    drop
  allow
```

Locals are typed and are not numerically convertible. A `bool` local is a valid condition on its own; a `u16` local is not, and `if my_port:` is a type error rather than an implicit "non-zero". There is no truthiness in this language.

Tier 1 rules cannot see Tier 2 locals, which is the other half of the "one or the other" rule.

## Helpers shared between zones

A top-level `def` is a helper. It compiles to a real BPF-to-BPF call — a `static __noinline` function, not an inlined copy — and several zones can call it.

```fwl
zone wan = [wan0]
zone lan = [lan0]
zone dmz = [dmz0]

# The plant-floor firehose, written once.
def kill_noise(pkt):
  if pkt.dst_ip in 224.0.0.0/4:
    drop
  if pkt.dst_ip == 255.255.255.255:
    drop
  if pkt.proto == udp and pkt.dst_port == 137:
    drop

@xdp(wan)
def from_office(pkt):
  kill_noise(pkt)
  drop

@xdp(lan)
def from_bench(pkt):
  kill_noise(pkt)
  redirect to wan

@xdp(dmz)
def from_dmz(pkt):
  kill_noise(pkt)
  redirect to wan
```

A helper's terminal action ends the whole program, not just the helper — `kill_noise` dropping a packet means the caller's next statement never runs. That is what makes the shape above read correctly: "kill the noise, then do the zone's own thing".

Splitting logic into a helper must not change behaviour. That is the property the compiler is tested against directly: a program with a helper and the equivalent program with the helper's body pasted in must evaluate identically on every packet.

**`pkt.zone` is refused inside a helper**, which is worth knowing because it is the first thing you will reach for:

```
error: pkt.zone is not supported inside a helper def 'shared'
       (v0.4 § 6.5): a shared helper has no single ingress zone
```

The reasoning is that a helper is compiled once and called from several zones, so there is no ingress zone to fold the constant against — and a field that silently meant "whichever zone the compiler happened to emit this copy for" would be worse than no field. Zone-specific behaviour goes in the caller:

```fwl
zone wan = [wan0]
zone lan = [lan0]

def kill_ssh(pkt):
  if pkt.proto == tcp and pkt.dst_port == 22:
    drop

@xdp(wan)
def a(pkt):
  kill_ssh(pkt)
  drop

@xdp(lan)
def b(pkt):
  redirect to wan
```

`pkt.zone` is for a Tier 2 program that *is* a zone's own program, where it is a compile-time constant and folds away.

## The pipeline splitter

The kernel's verifier has a complexity ceiling. A policy can grow past it — long address lists, many zones, deep Tier 2 nesting — and the failure mode without help is a program that compiles and then will not load, with a verifier log rather than a diagnostic.

The compiler estimates a program's cost and, when it is too large for one program, splits it into a chain of programs joined by tail calls, carrying the parsed fields forward in a scratch struct. This is automatic: nothing in the source changes, and the split program's behaviour is required to be identical to the unsplit one.

You can force a boundary where you want one. `chain <name>` names the stage that starts there:

```fwl
@xdp(eth0)
allow if pkt.src_ip == 10.0.0.1
chain second_stage
allow if pkt.src_ip == 10.0.0.2
default drop
```

`chain` is a Tier 1 construct only; inside a Tier 2 `def` it is refused, because a stage boundary is a boundary between rules and a function body is not a rule list.

Reasons to reach for it by hand are rare. The two real ones are pinning a boundary so that a policy's shape is stable across edits, and reproducing a split locally that the estimator only reaches on a bigger program.

You do not need to know the split plan to write policy. You do need to know it exists, because it is the answer to "why does this one program show up as several in the loader".

## Where to go from here

- The specifications are the authority on every construct: [v0.1](../FWL_V01_SPEC.md) for rules, operators, `rate_limit`, counters and logging; [v0.2](../FWL_V02_SPEC.md) for IPv6 fields, `geoip()` and Tier 2; [v0.4](../FWL_V04_SPEC.md) for TCP flags, ICMP, VLAN, conntrack, zones and NAT.
- The shipped examples under `fwl/examples/` are policies that are tested, not sketches. `storm_shield.fw` is the finished version of the gateway this guide builds.
- **Helpers and the splitter are implemented and tested but have no specification section.** They are numbered §6.5 and §6.6 in the code and the tests (`fwl/tests/unit/test_multidef.py`, `test_pipeline.py`); those sections do not exist in the v0.4 spec in this branch. Where this page and the code disagree, the code and its tests are the authority — and the missing sections are a known gap.

---

Previous: [7. Rate limiting](07-rate-limiting.md) · Back to [the path](README.md)
