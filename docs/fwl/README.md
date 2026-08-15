# FWL — a guide

FWL is a small declarative language for firewall policy. A `.fw` file declares rules; the compiler turns them into XDP/eBPF programs that run in the kernel's receive path, before the network stack.

The [specifications](../FWL_V01_SPEC.md) answer "what does this construct mean" for somebody who already knows the language exists. This guide is the other thing: a path from nothing to a working office gateway, where each step is a policy you can paste and run and each one builds on the last.

Every policy on these pages compiles. If one does not, that is a bug in the page — `fwl check <file>` is the same check the box runs before it will load anything.

## The path

| Step | You will be able to | |
|---|---|---|
| 1 | Write a policy, understand rule order and the default action | [01-first-policy.md](01-first-policy.md) |
| 2 | Match on addresses, ports, TCP flags and ICMP | [02-matching.md](02-matching.md) |
| 3 | Split a box into zones and move traffic between them | [03-zones.md](03-zones.md) |
| 4 | Write stateful policy — `established`, and why `related` is not optional | [04-stateful.md](04-stateful.md) |
| 5 | Find out what your policy is doing — `count` and `log` | [05-observability.md](05-observability.md) |
| 6 | Build a real gateway — `masquerade`, `snat`, `dnat`, port forwarding | [06-nat.md](06-nat.md) |
| 7 | Survive a flood — `rate_limit`, `scope=`, and the per-CPU caveat | [07-rate-limiting.md](07-rate-limiting.md) |
| 8 | Share logic between zones — helpers, Tier 2, and what the splitter does | [08-advanced.md](08-advanced.md) |

## Before you start

```
$ fwl check policy.fw       # does it compile
$ fwl compile policy.fw -o out.bpf.c
```

On a running box the loop is `einheit-f reload firewall`, which checks, compiles and hot-reloads. A policy that does not compile is never loaded, and a failed load leaves the previous policy running.

## Two facts that explain most surprises

**Rules are ordered and terminal actions stop evaluation.** `allow`, `drop` and `redirect to <zone>` end it. `count`, `log`, `masquerade`, `snat` and `dnat` fall through. The order of a block is the policy.

**`allow` means "give it to this box's own network stack".** It does not mean "forward it". Moving a packet between zones is `redirect`. Almost every gateway policy that behaves strangely does so because one of those two sentences was assumed to be the other.
