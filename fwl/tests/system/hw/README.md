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
- `l1_*.sh` — one script per test-plan row.
- `run_l1.sh` — runs every `l1_*` script, prints a summary table.
