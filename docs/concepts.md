# Concepts

What this box is made of, and why it is made that way. No commands here; this is the page that makes the other pages make sense.

---

## The chain everything hangs off

```
physical port  ->  interface  ->  zone  ->  services bind here
```

Read it in that order. Each arrow is a place where a name is assigned and checked against the one before it, and each arrow exists to make a specific mistake impossible rather than merely discouraged.

### Port to interface: a name pinned to hardware

A **port** is a socket on the case. The kernel gives it a name at probe time — `enp1s0f1`, `eth2` — and that name is not an identity: it depends on driver load order, on which slot a card is in, and on what else is plugged in. An **interface** is a durable name of your choosing, pinned to something the hardware carries: a MAC address, or a bus path.

This is not tidiness. udev renumbering a port repoints the policy underneath itself, and **a firewall pointing at the wrong port is a bypass, not an outage**. An outage is loud. A bypass is a wan rule applied to the testnet cable and a testnet rule applied to the office, with every counter climbing and everything appearing to work.

The pinning is written as a `.link` unit that systemd applies at boot. It follows that a freshly written configuration is *not yet* in effect on a running box: the port keeps its kernel name until the rename happens. The box says so — see [recovery.md](recovery.md#a-configuration-was-applied-but-the-ports-it-names-do-not-exist-yet) — because "applied" is a claim about files and this is a claim about the machine.

### Interface to zone: the unit policy talks about

A **zone** is a set of interfaces. It is a fact about the box — *these ports* — not a fact about the policy, so it lives in `system.yaml` and the firewall language references it by name. That ordering matters when you commission a box: interfaces, addressing, DHCP and DNS all come up before any policy exists, which is the order you actually do it in.

An interface belongs to exactly one zone. That is a scalar in the model, not a list, so "in two zones at once" is not a state the configuration can describe.

### Zone to service: why the rogue-DHCP leak is inexpressible

A service — the DHCP server, the DNS forwarder, the NTP server — binds to a **zone**. There is no key anywhere in `system.yaml`, in any service, that names an interface.

That single missing field is what makes the dangerous case structural instead of remembered. "DHCP answers on the office uplink" is the classic appliance disaster: someone types an interface name into a service block, and a testnet DHCP server starts handing out addresses and default routes to the whole company. Here it is not a mistake you can make carefully — it is a sentence the configuration has no words for. The set of ports a service touches is derived from zone membership every time the config is generated, and there is nowhere to write a second, hand-maintained copy of it that could drift.

The generated `dnsmasq.conf` states the containment rather than implying it: every declared interface appears either in an `interface=` line or an `except-interface=` line, and every port that is not to answer DHCP is named in a `no-dhcp-interface=` line. Nothing is contained by being left out of a list.

---

## Generated files, and why you never edit them

`system.yaml` is the document you edit. Everything else the box runs is **derived** from it: the dnsmasq config, the networkd units, the chrony config, the IPv6 sysctls, the journald cap.

Each derived file carries a digest of its own body. That makes three things true:

- an edit to one is *detectable*, and is reported as drift rather than silently overwritten;
- a file that is self-consistent but generated from an older model is *stale*, which is a different fault with a different fix;
- a file we did not write is recognisable as such, and is never deleted.

The rule that follows is the one worth internalising: **the fix for a generated file is never to edit the generated file.** It is to change `system.yaml` and apply. If a procedure anywhere tells you to edit a generated artifact, that procedure is wrong.

The same treatment applies to compiled BPF: a policy is compiled into a bundle, the bundle is what runs, and the bundle is derived.

---

## What the datapath does

A policy is compiled into an XDP/eBPF program that runs in the kernel's receive path, before the network stack. One program per zone; a bundle is the set of them plus a manifest.

Three consequences shape how policies are written.

**Rules are ordered, and terminal actions stop evaluation.** `allow` and `drop` end it. `count`, `log` and the NAT rewrites fall through. So the order of a block is the policy, and a rule placed after a `drop` that already matched never runs.

**`allow` means "hand it to this box's own network stack".** It does not mean "forward it". Getting a packet from one zone to another is `redirect to <zone>`, which is also terminal. This distinction is the one that bites: a gateway block of `masquerade` then `redirect to wan` sends *everything* out of the uplink, including packets addressed to the appliance itself, because neither of those actions is a decision about where the packet was going.

**Masquerade is explained, not performed, here.** `masquerade` rewrites the source address of a packet to the address the daemon wrote into the zone's NAT config, fixes both checksums, and installs a reply mapping in a shared map so the return packet is translated back. It is a *non-terminal rewrite*: it changes the packet and falls through, and the next terminal action is what actually emits it. That is why `masquerade` on its own does nothing visible, and why the rule *after* it is the one that decides whether the rewritten frame goes to the uplink or to the local stack.

The reply mapping is why a gateway needs both halves. The lan zone installs the mapping when it translates a packet out; the wan zone consumes it when the answer comes back, before any of its rules run. Every zone program in a bundle emits that de-NAT pass, which is what lets one zone's decision be undone by another's.

---

## State the box keeps, and where

**Connection tracking** is a BPF map, pinned under `/sys/fs/bpf/f/`, which is what makes it survive a daemon restart. `conntrack(pkt).state` reads it; an allowed `new` packet creates the entry that a later packet reads as `established`.

`established` and `related` are different answers and you need both. An ICMP error carries no ports, so it can never be `established` — including the fragmentation-needed message that path-MTU discovery runs on. A policy that admits only `established` gives you a network where ping works, DNS works, and every large transfer hangs with nothing logged anywhere.

**NAT mappings** live in a second pinned map, shared across zones. It is a fixed-size hash: when it is full, new mappings cannot be installed and the *return* packets have nothing to translate against. This presents as "existing connections fine, new ones go out and nothing comes back".

**Device history** (`/var/lib/f/devices.json`) is the only file on the box that records something nothing else knows: when each MAC was first *seen*. Leases tell you a device is here; only a watched transition tells you it arrived.

That distinction is a convention you will see throughout the output: **an arrival is a transition we witnessed, never a state we inferred.** A device that was already present the first time anything looked gets a `>=` bound on its age and is not marked `NEW`, because a flag that fires for every device on a week-old box teaches you to ignore the column that exists to catch your eye.

---

## The convention that governs every screen

**An empty table always says which kind of empty it is.**

There are two completely different reasons a view shows nothing: there is nothing there, or nobody could ask. Confusing them costs hours. So every value that can be absent travels with the reason it is absent, as a type rather than a habit — a renderer cannot forget which kind of empty it received, because the two are not the same value.

The same rule has a sharper form, and it is the one that produced most of the recent work on this box:

**A column derived from the same model that generated the config cannot be evidence about whether the config worked.** It can only ever agree with itself.

`show services` used to print a column headed `ANSWERS ON`, computed from zone membership. It printed `lan0` whether dnsmasq was bound to `lan0` or bound to nothing at all, because the number came from the same place the config did. It now reads the kernel's socket table: `BOUND TO` is what you asked for, `ANSWERS ON` is where the daemon actually is, and the two being separate columns is the whole point. The same reasoning fixed the `PRESENT` column in `show system`, which used to match ports by name — the one thing that has not happened yet when a rename is pending.

If you find a view that reports on a config using only that config, that is a bug worth reporting.
