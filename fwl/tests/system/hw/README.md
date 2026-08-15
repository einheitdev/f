# Hardware system tests — f v0.4 on the physical rig

Wire-level tests for the FWL construct matrix (`context/test-plan.md` in the f-rig workspace). Each `l1_*.sh` script is self-contained: it deploys a minimal policy through the real `fd` daemon, sends crafted frames from one i350 port through the EX2300 switch into another, and asserts on two independent witnesses:

1. **FWL counters** — per-rule `count` deltas read from the pinned `fwl_counters` map (`bpftool map dump`).
2. **Receiver sniffer** — an AF_PACKET tap on the receiving port. XDP_DROP happens before AF_PACKET, so dropped frames are invisible to the sniffer while passed frames appear. The sniffer therefore observes the *disposition*, not just the arrival.
3. **A real socket on a real far side** (`realsock.py` + `hw::host_up`) — an ordinary Linux stack in its own namespace, with its own MAC, NOT promiscuous, completing a real TCP exchange.

### Why the third witness exists, and when you must use it

Witnesses 1 and 2 answer "what did the datapath do to the frame" and "did the frame reach this cable". Neither answers "would a real host accept it", and for a whole class of defect those are different questions. The instance that motivated this: `redirect` never rewrote the destination MAC, so every masqueraded frame left carrying the firewall's own address. The next hop's NIC reports `PACKET_OTHERHOST` and its stack discards the frame before any socket exists — but a promiscuous AF_PACKET witness counts it, and every counter climbs. 1822 unit cases, eleven `l11_*` scenarios and a NAT soak all agreed masquerade worked.

Worse, most NAT scenarios pair the translation with `allow`, not `redirect`, so the frame is handed to the local stack on a port with no address and dropped. It was never forwarded anywhere at all. Their evidence is real evidence *of the rewrite* and none whatsoever *of delivery*.

**Any assertion of the form "the packet got there" needs witness 3.** Use 1 and 2 for per-frame counts, checksum validity, disposition, and anything a socket cannot see (an ICMP error's embedded header, a crafted malformed frame, 80 000 flows). They are not interchangeable and both are kept.

## The vacuity sweep — does each scenario notice its own defect?

Every serious defect found in the week of 2026-08-12..14 was one class: **the instrument did not measure what it claimed to measure.** A promiscuous witness for a delivery claim. A deploy that cleared the pin root it was supposed to leave dirty. A regression gate that had been red on every cycle it ever ran. A credential check that was a file-existence test. A status field re-derived from the model that produced it. A 42-byte control frame too short to be misread.

None of those is a product bug. Each is a test that could not fail.

`vacuity_sweep.py` generalises the by-hand cure. For each scenario, `sweep_registry.py` names the defect that scenario exists to catch; the sweep plants it and requires the scenario to go **red**.

```bash
sweep.sh preflight     # static: does every plant still match its target?
sweep.sh run           # the whole sweep (hours) — runs ON the rig
sweep.sh run --only l2_03_masquerade
sweep.sh report        # render the verdicts, witnesses, invariants, lint
sweep.sh restore       # smoke policy, walk-up ready
sweep.sh pull <dir>    # copy results/history/logs off the rig
```

### The verdict vocabulary, which is the part to get right

| verdict | meaning |
|---|---|
| `discriminating` | red with the defect, green without. It measures. |
| `vacuous` | **green with its subject broken.** A finding. |
| `unrunnable` | the question could not be put — the plant did not apply, its own verification says the defect is absent, or the scenario is red with no plant at all. |
| `declared` | the subject genuinely cannot be broken on this bench, with the reason recorded. Counted separately; never silently skipped. |

`unrunnable` is deliberately not folded into either of the others. It is a defect in the SWEEP, and treating it as a pass is how a whole section of soak reporting came to carry no information.

A run that is green under the plant proves vacuity on its own, so the baseline is only paid for when the plant went red — which is also why every vacuity finding is confirmed by a second run before it is reported.

### A plant must verify itself

The sweep's first run reported `l3_08` vacuous. It was not: the plant set `RuntimeDirectoryPreserve=no` on **f-confd**, and the directory is deleted by the unit that STOPS, which is fd. The drop-in installed perfectly and changed nothing. "The edit was made" and "the defect is present" are different claims — exactly the distinction this sweep exists to enforce — so a `Plant` may carry a `verify` command that reads the defect's state back, and a plant whose verification fails is `unrunnable`, never `vacuous`.

### Witness classification

`sweep_lib.classify_witness` records what KIND of evidence each scenario rests on, ranked:

```
[5] real_socket        a real non-promiscuous Linux stack ACCEPTED the
                       bytes, and its own kernel reports the peer
[4] switch_witness     a copy made by the EX2300, which the DUT cannot
                       influence
[3] kernel_state       the kernel queried independently of the daemon
[3] nic_counter        the frame left on copper
[2] sniffer_promisc    a promiscuous AF_PACKET tap: the frame was on
                       this cable and survived XDP
[1] counter            the program ran a rule
[1] daemon_selfreport  the daemon's report of itself
```

A1 was invisible for months because nothing named the difference between "a frame was on the cable" and "a host accepted it". Every scenario whose strongest witness is rank <= 2 must carry a `witness_note` saying why that is the right witness — most of them legitimately measure something no socket can see (an embedded ICMP header, 80 000 flows, a crafted malformed frame), and the point is that the file now says so instead of leaving it to be assumed. The report names any that do not.

### Invariant verdicts, and the static lint

`History` keeps every scenario's and every CHECK's verdict across runs. A check that has never been red carries no information; a check that has never been green is the `regress` shape, red as its normal colour, hiding the first real regression behind the declared ones. Both are reported.

The lint is the free half: a conditional that cannot fail yet emits a PASS is found by reading, not by running. Eleven of them were in this suite. They record a bench observation — the i350 accepts oversized frames or it does not — and they now call `record` (a `NOTE:` line kept in the evidence) instead of `pass`, so the green lines in a run's evidence are the ones that could have been red.

## Topology

```
enp1s0f0 (sender, no XDP) ==EX2300==> enp1s0f1 (zone t, XDP + sniffer)
```

For the routed scenarios (`l2_02` acceptance leg, `l2_03`, `l11_04` acceptance leg, `l12_01`, `l12_02`) the same three ports carry a real gateway, with both far hosts hanging off the one trunk port:

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

Both far hosts are on `enp1s0f0` because it is the only trunk port: a macvlan carries the untagged (VLAN 801) side and an 802.1Q subinterface carries the tagged (VLAN 802) side, each moved into its own namespace. Neither is promiscuous, and `hw::host_up` asserts that rather than assuming it.

These scenarios need `net.ipv4.ip_forward=1` and set it themselves, restoring the previous value on exit. They also put transient addresses on the two data ports and remove them on exit.

**`fd` also writes that knob now, and the two do not fight.** Since the fail-closed change the daemon owns `net.ipv4.ip_forward`: it lowers it on the way in and raises it once a bundle is attached to at least one interface. A scenario that sets it to 1 is therefore agreeing with a running `fd` rather than overriding it — and, more to the point, a scenario that sets it to **0 as a control** still works, because the periodic re-check is asymmetric on purpose. `fd` puts the knob back only when it finds it OPEN on a box whose datapath is not armed; a knob it finds CLOSED on an armed box is reported once in the journal and left exactly where the scenario put it. Several of these controls prove "these frames were on the wire and no socket took one" precisely by holding forwarding down under a running `fd`, and making that impossible would have cost them their meaning. See `include/f/route_mgr.h`.

Test frames use inert addresses (10.99.0.0/16, locally-administered MACs 02:00:00:00:00:01/02). The receive port runs promiscuous — the i350 MAC filter would otherwise drop builder-MAC unicast before XDP. The switch FDB is taught both MACs before each run so frames unicast port-to-port; nothing is broadcast (household-LAN rule).

## Running

From ksys (syncs this tree to the rig, runs there, streams output):

```bash
tests/system/hw/hw.sh l1_01_proto_port_cidr   # one scenario
tests/system/hw/hw.sh run_l1                  # the whole layer
```

On the rig directly: `bash /opt/fwl/tests/system/hw/<script>.sh`.

Every script restores the operator smoke policy (`/etc/f/rules.fw`) on exit, so the rig is always left in the walk-up state.

## Files

- `hwlib.sh` — deploy/counters/sniffer/FDB plumbing shared by tests.
- `sendmany.py` — batch AF_PACKET sender using `fwl.pkt` builders.
- `sniff.py` — receiving-port witness; JSON tallies by flow key.
- `realsock.py` — the acceptance witness: a real listening socket and a real client, both on ordinary non-promiscuous stacks. The server reports the PEER address of each accepted connection, so one object proves the far side took the bytes AND that the source was translated; neither is evidence without the other.
- `dnsprobe.py` — a real DNS responder and a real DNS client, for `l12_02`. Not `dig`: the point of that scenario is the ANSWER, an address only the far-side responder can produce, and a tool that prints `status: NOERROR` invites an assertion a cached or locally-synthesised answer satisfies just as well.
- `tc_egress_probe.bpf.c` — the measurement that decided the A4 design, kept because it is the evidence and not the product: it counts IPv4 packets at a TC egress hook, and established that such a hook sees 5/5 of what the local stack sends and 0 of 13 frames the XDP datapath forwards out the same port. The product tracker is `fwl_egress.bpf.c`, emitted into every conntrack-reading bundle by `fwl` (FWL_V04_SPEC.md § 6.9).
- `ringlog.py` — consumes the pinned `fwl_log_events` ring buffer. Decodes with `fwl.log_abi` (the same layout the .pkt oracle reads), validates each record's ABI header, and resolves `zone_id` to a zone name through the running bundle's `manifest.json["zone_ids"]`. Exits 3 if it ever rejected a record.
- `sendraw.py` — deliberately ugly frames the builders cannot make: fragments, IP options, truncated L4, QinQ, and (`icmperr`) a real RFC 1191 ICMP error carrying a next-hop MTU and the embedded header of the datagram that provoked it.
- `l1_*.sh` — one script per test-plan row.
- `run_l1.sh` — runs every `l1_*` script, prints a summary table.
- `natsoak_*` — the NAT/masquerade soak (policy, traffic generator, per-sample wire probe, sampler, report). See below.
- `run_l11.sh` — the ceiling probes. None FAILs by design any more.
- `run_l12.sh` — the two runnable `l12_*` scenarios (~10 min). `l12_03` is excluded because it reboots the rig; run it from ksys by hand, like `l3_03`.
- `l12_*.sh` — flows the appliance itself originates. `l12_01` is the mechanism (an egress hook creates the conntrack entry XDP never could, and refuses to create one for anything the box merely forwarded); `l12_02` is the consequence, and the only user-visible proof there is — a client resolving a name through the box's own forwarder. Neither FAILs by design; `l12_01` used to, as the reproduction of finding A4, and now asserts the behaviour that replaced it.

### Ceiling probes (`l10_*`, `l11_*`) — read the evidence, not the code

These do not ask "does the feature work". They ask "where does it stop working", and they were written to RECORD the answer rather than to assert a hoped-for one. When a ceiling closes, the probe is tightened to the behaviour that replaced it — the exact value, not a looser bound — and taken off the by-design-FAIL list, so a failure there is a regression. `l11_01`, `l11_02`, `l11_04` and `l11_05` have all been through that, and **none of these probes FAILs by design any more** — a FAIL in any of them is a regression. `l11_05` was the last: an ICMP error names its flow in its payload, which nothing read, so path-MTU discovery was structurally broken for a masqueraded flow. It now asserts the opposite exactly — delivered to the owning host with both headers translated and every checksum valid — with controls for an error naming a flow the NAT does not hold and for the same policy written `== established`. `l11_06` (occupancy curve) was added with the collector and asserts the SHAPE of the curve, because a cap that is far away and a cap that is merely not yet reached look identical in a single sample.

They all share one property that keeps them out of the `.pkt` corpus: each is about the system over TIME or over the SET of loaded state — a table that fills after 65536 packets, a mapping a later packet overwrites, a garbage collector running in the daemon's main loop, a de-NAT ordered after a conntrack lookup. `BPF_PROG_RUN` evaluates one packet against one object with a fresh map and can see none of it.

`l11_05` moves the send port into a network namespace so a real TCP transfer is forced onto the copper (both i350 ports are on the same machine, so a plain socket would go over loopback). Its cleanup deletes the namespace unconditionally — that is what returns the interface to the root namespace — because leaving it there would stop the smoke policy attaching and leave the rig broken for whoever walks up next.

### The NAT soak

`natsoak_start.sh` is the 48 h soak's discipline pointed at the code path the office deployment depends on. The difference that matters is `natsoak_probe.py`: every sample sends a known burst and reads the frames back off the receiving port, so a sample records what the firewall DID, not just that it was running. Every counter in that policy would keep climbing with the NAT rewrite disabled entirely.

Its traffic generator recomputes BOTH checksums after patching a frame's addresses and ports. Fixing only the IPv4 one is not cosmetic: the NAT rewrite updates the L4 checksum incrementally, so a wrong value going in stays wrong going out, and the soak's own witness then reports every translated frame as corrupt — a generator artefact that looks exactly like the defect being watched for.

### Tests that need more than one zone loaded at once

`l8_07_bundle_map_isolation.sh`, `l8_08_rate_limit_scope.sh` and `l8_11_log_zone_attribution.sh` assert on properties of the artifact SET rather than of one program: which pinned names two zone objects share, what that sharing does to traffic, and whether two zones writing into one ring buffer stay distinguishable. `BPF_PROG_RUN` loads one object at a time, so the whole corpus is blind to all three — they can only run here.

`l8_11` is also the only test in which BOTH data-plane ports receive traffic (each zone has to log something of its own). That needs `hw::open_reverse_path` — promisc on the normal sending port plus a reverse wire probe — and `hw::send_reverse`, which swaps the builder frame's MACs so it unicasts back down the taught path instead of being addressed at the port it just left.

`l8_08` also pins the data-plane ports' queue IRQs to one CPU for its duration (`hw::pin_irqs_to_cpu`, restored on exit). The rate-limit map is per-CPU, so without that the test would be measuring RSS placement instead of map sharing.
