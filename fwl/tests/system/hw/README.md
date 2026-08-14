# Hardware system tests — f v0.4 on the physical rig

Wire-level tests for the FWL construct matrix (`context/test-plan.md`
in the f-rig workspace). Each `l1_*.sh` script is self-contained: it
deploys a minimal policy through the real `fd` daemon, sends crafted
frames from one i350 port through the EX2300 switch into another, and
asserts on two independent witnesses:

1. **FWL counters** — per-rule `count` deltas read from the pinned
   `fwl_counters` map (`bpftool map dump`).
2. **Receiver sniffer** — an AF_PACKET tap on the receiving port.
   XDP_DROP happens before AF_PACKET, so dropped frames are invisible
   to the sniffer while passed frames appear. The sniffer therefore
   observes the *disposition*, not just the arrival.
3. **A real socket on a real far side** (`realsock.py` +
   `hw::host_up`) — an ordinary Linux stack in its own namespace, with
   its own MAC, NOT promiscuous, completing a real TCP exchange.

### Why the third witness exists, and when you must use it

Witnesses 1 and 2 answer "what did the datapath do to the frame" and
"did the frame reach this cable". Neither answers "would a real host
accept it", and for a whole class of defect those are different
questions. The instance that motivated this: `redirect` never rewrote
the destination MAC, so every masqueraded frame left carrying the
firewall's own address. The next hop's NIC reports `PACKET_OTHERHOST`
and its stack discards the frame before any socket exists — but a
promiscuous AF_PACKET witness counts it, and every counter climbs. 1822
unit cases, eleven `l11_*` scenarios and a NAT soak all agreed
masquerade worked.

Worse, most NAT scenarios pair the translation with `allow`, not
`redirect`, so the frame is handed to the local stack on a port with no
address and dropped. It was never forwarded anywhere at all. Their
evidence is real evidence *of the rewrite* and none whatsoever *of
delivery*.

**Any assertion of the form "the packet got there" needs witness 3.**
Use 1 and 2 for per-frame counts, checksum validity, disposition, and
anything a socket cannot see (an ICMP error's embedded header, a
crafted malformed frame, 80 000 flows). They are not interchangeable
and both are kept.

## Topology

```
enp1s0f0 (sender, no XDP) ==EX2300==> enp1s0f1 (zone t, XDP + sniffer)
```

For the routed scenarios (`l2_02` acceptance leg, `l2_03`, `l11_04`
acceptance leg, `l12_01`) the same three ports carry a real gateway,
with both far hosts hanging off the one trunk port:

```
  netns fguest  10.99.21.5        (macvlan on f0, untagged -> vlan 801)
        |
     [ EX2300 ]
        |
  enp1s0f1  10.99.21.1   zone lan  [XDP: masquerade + redirect]
  enp1s0f2  10.99.200.2  zone wan  [XDP: de-NAT + redirect]
        |
     [ EX2300 ]
        |
  netns fserver 10.99.200.9       (vlan 802 subinterface of f0)
```

Both far hosts are on `enp1s0f0` because it is the only trunk port: a
macvlan carries the untagged (VLAN 801) side and an 802.1Q
subinterface carries the tagged (VLAN 802) side, each moved into its
own namespace. Neither is promiscuous, and `hw::host_up` asserts that
rather than assuming it.

These scenarios need `net.ipv4.ip_forward=1` and set it themselves,
restoring the previous value on exit. They also put transient addresses
on the two data ports and remove them on exit.

Test frames use inert addresses (10.99.0.0/16, locally-administered
MACs 02:00:00:00:00:01/02). The receive port runs promiscuous — the
i350 MAC filter would otherwise drop builder-MAC unicast before XDP.
The switch FDB is taught both MACs before each run so frames unicast
port-to-port; nothing is broadcast (household-LAN rule).

## Running

From ksys (syncs this tree to the rig, runs there, streams output):

```bash
tests/system/hw/hw.sh l1_01_proto_port_cidr   # one scenario
tests/system/hw/hw.sh run_l1                  # the whole layer
```

On the rig directly: `bash /opt/fwl/tests/system/hw/<script>.sh`.

Every script restores the operator smoke policy (`/etc/f/rules.fw`)
on exit, so the rig is always left in the walk-up state.

## Files

- `hwlib.sh` — deploy/counters/sniffer/FDB plumbing shared by tests.
- `sendmany.py` — batch AF_PACKET sender using `fwl.pkt` builders.
- `sniff.py` — receiving-port witness; JSON tallies by flow key.
- `realsock.py` — the acceptance witness: a real listening socket and a
  real client, both on ordinary non-promiscuous stacks. The server
  reports the PEER address of each accepted connection, so one object
  proves the far side took the bytes AND that the source was
  translated; neither is evidence without the other.
- `tc_egress_probe.bpf.c` — a measurement for `l12_01`, not a product
  component: counts IPv4 packets at a TC egress hook, to establish what
  such a hook can and cannot see.
- `ringlog.py` — consumes the pinned `fwl_log_events` ring buffer.
  Decodes with `fwl.log_abi` (the same layout the .pkt oracle reads),
  validates each record's ABI header, and resolves `zone_id` to a zone
  name through the running bundle's `manifest.json["zone_ids"]`. Exits
  3 if it ever rejected a record.
- `sendraw.py` — deliberately ugly frames the builders cannot make:
  fragments, IP options, truncated L4, QinQ, and (`icmperr`) a real
  RFC 1191 ICMP error carrying a next-hop MTU and the embedded header
  of the datagram that provoked it.
- `l1_*.sh` — one script per test-plan row.
- `run_l1.sh` — runs every `l1_*` script, prints a summary table.
- `natsoak_*` — the NAT/masquerade soak (policy, traffic generator,
  per-sample wire probe, sampler, report). See below.
- `run_l11.sh` — the ceiling probes. None FAILs by design any more.

### Ceiling probes (`l10_*`, `l11_*`) — read the evidence, not the code

These do not ask "does the feature work". They ask "where does it stop
working", and they were written to RECORD the answer rather than to
assert a hoped-for one. When a ceiling closes, the probe is tightened
to the behaviour that replaced it — the exact value, not a looser
bound — and taken off the by-design-FAIL list, so a failure there is a
regression. `l11_01`, `l11_02`, `l11_04` and `l11_05` have all been through
that, and **none of these probes FAILs by design any more** — a FAIL
in any of them is a regression. `l11_05` was the last: an ICMP error
names its flow in its payload, which nothing read, so path-MTU
discovery was structurally broken for a masqueraded flow. It now
asserts the opposite exactly — delivered to the owning host with both
headers translated and every checksum valid — with controls for an
error naming a flow the NAT does not hold and for the same policy
written `== established`. `l11_06` (occupancy curve) was added
with the collector and asserts the SHAPE of the curve, because a cap
that is far away and a cap that is merely not yet reached look
identical in a single sample.

They all share one property that keeps them out of the `.pkt` corpus:
each is about the system over TIME or over the SET of loaded state — a
table that fills after 65536 packets, a mapping a later packet
overwrites, a garbage collector running in the daemon's main loop, a
de-NAT ordered after a conntrack lookup. `BPF_PROG_RUN` evaluates one
packet against one object with a fresh map and can see none of it.

`l11_05` moves the send port into a network namespace so a real TCP
transfer is forced onto the copper (both i350 ports are on the same
machine, so a plain socket would go over loopback). Its cleanup
deletes the namespace unconditionally — that is what returns the
interface to the root namespace — because leaving it there would stop
the smoke policy attaching and leave the rig broken for whoever walks
up next.

### The NAT soak

`natsoak_start.sh` is the 48 h soak's discipline pointed at the code
path the office deployment depends on. The difference that matters is
`natsoak_probe.py`: every sample sends a known burst and reads the
frames back off the receiving port, so a sample records what the
firewall DID, not just that it was running. Every counter in that
policy would keep climbing with the NAT rewrite disabled entirely.

Its traffic generator recomputes BOTH checksums after patching a
frame's addresses and ports. Fixing only the IPv4 one is not cosmetic:
the NAT rewrite updates the L4 checksum incrementally, so a wrong
value going in stays wrong going out, and the soak's own witness then
reports every translated frame as corrupt — a generator artefact that
looks exactly like the defect being watched for.

### Tests that need more than one zone loaded at once

`l8_07_bundle_map_isolation.sh`, `l8_08_rate_limit_scope.sh` and
`l8_11_log_zone_attribution.sh` assert on properties of the artifact
SET rather than of one program: which pinned names two zone objects
share, what that sharing does to traffic, and whether two zones writing
into one ring buffer stay distinguishable. `BPF_PROG_RUN` loads one
object at a time, so the whole corpus is blind to all three — they can
only run here.

`l8_11` is also the only test in which BOTH data-plane ports receive
traffic (each zone has to log something of its own). That needs
`hw::open_reverse_path` — promisc on the normal sending port plus a
reverse wire probe — and `hw::send_reverse`, which swaps the builder
frame's MACs so it unicasts back down the taught path instead of being
addressed at the port it just left.

`l8_08` also pins the data-plane ports' queue IRQs to one CPU for its
duration (`hw::pin_irqs_to_cpu`, restored on exit). The rate-limit map
is per-CPU, so without that the test would be measuring RSS placement
instead of map sharing.
