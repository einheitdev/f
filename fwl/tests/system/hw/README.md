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

## Topology

```
enp1s0f0 (sender, no XDP) ==EX2300==> enp1s0f1 (zone t, XDP + sniffer)
```

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
- `ringlog.py` — consumes the pinned `fwl_log_events` ring buffer.
  Decodes with `fwl.log_abi` (the same layout the .pkt oracle reads),
  validates each record's ABI header, and resolves `zone_id` to a zone
  name through the running bundle's `manifest.json["zone_ids"]`. Exits
  3 if it ever rejected a record.
- `l1_*.sh` — one script per test-plan row.
- `run_l1.sh` — runs every `l1_*` script, prints a summary table.

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
