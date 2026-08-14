# The per-zone IPv6 stance

**Written 2026-08-14.** What `ipv6:` means in `/etc/f/system.yaml`,
how each stance is enforced, and why one of the three is refused.

## The failure this exists to prevent

The office is flat L2 and has router advertisements on it. A testnet
device that autoconfigures IPv6 from one of them acquires a globally
routable address and a default route that have nothing to do with `f`.

It then **routes around the v4 NAT and the entire firewall**, while
every v4 counter on the box keeps climbing and everything appears to
work perfectly. There is no drop, no log and no symptom. This is the
single most complete bypass available on that network, and it needs no
attacker — it is the default behaviour of every device shipped in the
last fifteen years, waiting for somebody else's router to speak.

So the stance is a statement about **inbound** traffic first. "We do
not send RAs" is the uninteresting half.

## The three stances

### `off` — the default

*No v6 on this zone, in either direction.* An advertisement arriving
here is received, counted, and refused; nothing autoconfigures; no v6
is forwarded.

Enforced in four places, because any one of them alone is a promise
rather than a mechanism:

| Layer | What it does | Artifact |
|---|---|---|
| Host sysctls | `accept_ra=0`, `autoconf=0`, `accept_ra_pinfo=0`, `accept_ra_defrtr=0` per port; the same on `default.*` so an **undeclared** port is covered too | `/etc/sysctl.d/10-f-ipv6.conf` |
| Forwarding | `all.forwarding=0` when no zone asks for v6, so the box is not a v6 router even by accident | same file |
| networkd | `IPv6AcceptRA=no`, `IPv6SendRA=no` on every generated unit, independent of the v4 address mode | `10-f-<iface>.network` |
| dnsmasq | `no-dhcpv6-interface` and `ra-param=<if>,0,0` for every port not in an `ra` zone | `/etc/f/generated/dnsmasq.conf` |

Two of those deserve their reasoning stated, because both look like
over-engineering until you know what they are for.

**`default.accept_ra=0` covers the port nobody declared.** It exists,
it is cabled, and the distribution default is "take an address from
whatever you hear". The model cannot name it, so the model names the
default instead.

**`accept_ra=0` is chosen over `disable_ipv6=1`.** Both refuse the
advertisement — measured, on 6.12, both leave the port with no global
address. The difference is what the kernel counts:

| Setting | Client autoconfigures | `Icmp6InRouterAdvertisements` |
|---|---|---|
| stock | **yes** | +3 |
| `accept_ra=0` | no | **+3** |
| `autoconf=0` | no | +3 |
| `disable_ipv6=1` | no | **0** (drops at `Ip6InDiscards` instead) |

`disable_ipv6` drops the frame before ICMPv6 accounting, which would
make the box **safe and blind at the same time**. A refusal nobody can
count is indistinguishable from a network that never spoke, and the
whole point of taking this box to the office is to find out what that
network is actually doing. So the stance keeps the counter and reads
it back — see *Seeing it* below.

### `ra` — we are the router here

*We send the advertisements, and we still take orders from nobody
else's.* `accept_ra` stays 0 even here: a router that autoconfigures
from a peer has just been told what to do by whoever shouted last.

Requires a v6 prefix on one of the zone's interfaces:

```yaml
zones:
  testnet:
    ipv6: ra
interfaces:
  lan0:
    mac: "52:54:00:aa:bb:02"
    address: 10.10.0.1/24
    address6: fd00:10:10::1/64
    zone: testnet
services:
  dhcp:
    - zone: testnet
      range: 10.10.0.100-10.10.0.200
```

Without one it is **refused** (SC031). This is not pedantry: dnsmasq's
`enable-ra` on its own sends nothing — advertisements go out only on an
interface that also carries a v6 `dhcp-range`. A stance that emitted
the flag alone generated a config line, passed `dnsmasq --test`,
started the daemon and delivered silence. That is BUGLOG #29, and it is
the same shape as everything else found this week: configured, and not
true.

A v6 address on a port whose zone is `off` is refused as well (SC032).
The two statements disagree, and the resolution must not be to quietly
pick one.

### `full` — refused

*Accept upstream RAs, forward v6, filter it like v4.* Representable, so
that the refusal can name it (SC030). It is **not** "unimplemented" —
the datapath forwards v6 today and would forward it here.

The reason is narrower and worse:

> The datapath cannot classify an ICMPv6 error as `related`, so
> `Packet Too Big` cannot reach a host in the zone. **IPv6 routers
> never fragment** — path-MTU discovery is the only mechanism there is,
> with none of the fallback v4 arguably has. A path with a smaller MTU
> anywhere along it therefore fails completely, with no drop counter
> and no log, presenting as *"the network is slow"*.

The IPv4 half of this landed on `f-rig` (`9458d73`): an ICMP error is
classified `related` from the tuple embedded in the datagram it
carries, and translated home per RFC 5508 §4.2. ICMPv6 needs the same
treatment before `full` can be honoured. When it lands, note the
ordering lesson with it — **the inner tuple must be consulted before
the outer one**, or one host's path-MTU error is handed to whichever
host last pinged the same sender.

Related, and true today for anyone writing a policy: `== established`
does **not** admit an ICMP error, because an error carries no ports and
its own 5-tuple reads NEW. The idiom is `in [established, related]`,
as in nftables.

## Seeing it

A gate nobody can see held is indistinguishable from a network that
never spoke. `show ipv6` prints the two numbers that settle it
together:

```
$ einheit-f show ipv6
 INTERFACE │ ZONE    │ STANCE │ RAS SEEN │ ADDRESSES
 wan0      │ wan     │ off    │       17 │ (none)
 lan0      │ testnet │ off    │        0 │ (none)

17 router advertisement(s) arrived on a zone whose stance is off,
and were refused. Nothing autoconfigured.
forwarding: off
```

Seventeen arrived and nothing was formed: that pair is the gate
holding. Either number alone is ambiguous in exactly the direction
that gets someone hurt.

When nothing has arrived, the box says so without claiming credit:

```
no router advertisement has arrived on an off zone. That is a quiet
network, not proof the gate works.
```

And when the stance is being violated on a live box — a port that is
`ipv6 off` and holds a global address anyway — it is a fault, not a
row in a table:

```
IPv6 STANCE VIOLATED: wan0 (zone wan) is ipv6 off but holds
2001:0db8:dead:0000:5054:00ff:fef6:0001
That port is carrying v6 the policy does not see. Re-run
`apply system`, then find out what put it back.
```

`f-sysconf status` exits **5** for that, ahead of drift (3) and a
service fault (4). The precedence is the argument: a bypass that is
already happening outranks a config file somebody edited and a daemon
that will not start.

A port whose counters could not be read renders as `?`, never as `0`.
The office may be shouting advertisements at it right now.

## Proof

`tests/system/test_ipv6_ra_gate.py` — 28 assertions against a real
kernel, three namespaces and a hand-built RA (`ra_inject.py`, written
from RFC 4861 §4.2 and §4.6.2).

Two positive controls come first, because without them the gate's
silence proves nothing:

1. **The advertisement is real and this exact port accepts it.** With
   stock settings, the appliance's own uplink autoconfigures from the
   injected RA.
2. **The probe can see a leak.** With the appliance bridging its two
   ports, the RA crosses to the testnet and the client there
   autoconfigures — the bypass, actually happening.

Then the gate, asserted as a pair:

```
gate: wan0 ras 3->6 addrs=[] | tn0 ras 3->3 addrs=[]
```

Three arrived at the uplink and were refused; zero reached the
testnet; nothing autoconfigured on either side.

And finally the failure is made loud: `accept_ra` is put back by hand,
a port genuinely autoconfigures, and the box is required to say so and
exit non-zero.

## Diagnostic codes

| Code | Meaning |
|---|---|
| SC029 | zone asks for RAs but has no DHCP service to send them |
| SC030 | zone asks for `full`, which this build refuses |
| SC031 | zone asks for RAs but has no prefix to advertise |
| SC032 | v6 address on a port whose zone says v6 is off, or a malformed one |
| SC103 | unknown stance word |

## What is still open

- **`full` needs ICMPv6 `related`** in the datapath before it can be
  offered. Until then the refusal is the honest answer.
- **The datapath is not part of the enforcement.** The stance is
  enforced in the host stack and the service plane. An FWL policy that
  redirects a v6 frame between zones would still do so — v6 frames
  reach the default action, so `default drop` covers it, but a
  permissive policy is not checked against the zone's stance. The
  compiler does not yet read `system.yaml` (it is on the roadmap for
  zone-name validation); this belongs in the same pass.
- **A stance change does not evict addresses already formed.** Moving
  a zone from `ra` to `off` stops new autoconfiguration and reports the
  old address as a violation, but does not remove it. Reported rather
  than silently reconciled, on the same principle as artifact drift.
