# Hardware bench suite

The layered validation suite that runs on the f-rig bench: real NIC, real switch, real ARM64. Everything here needs hardware and root, so none of it runs in CI — which is exactly why it belongs in the repo rather than only on the machine that can execute it.

It lived on the rig alone until 2026-08-19, at `/opt/fwl/tests/system/hw`, on one disk with no version control. Several of these encode bench topology and defect knowledge that cost hardware time to discover and cannot be reconstructed from the source they test.

## Layout

| Prefix | Covers |
|---|---|
| `l1_*` | Field matching: protocols, ports, CIDRs, TCP flags, ICMP, VLAN, IPv6, geoip, conntrack |
| `l2_*` | Zones, redirect, SNAT/DNAT/masquerade, pipeline split, storm shield, two uplinks |
| `l7_*` | Tier 2: semantics, multi-def zones, the two rate-limit forms compared |
| `l10_*` | Capacity: conntrack table limits, rate-limit evasion |
| `l11_*` | NAT under load: port collision, table ceiling, GC under churn, PMTU |
| `l12_*` | Box-originated flows, DNS forwarding, egress cold boot |
| `l13_*` | Load: the policy cost ladder — what the SoC gives out at, and what each construct costs per packet |
| `gwsoak*` | The long gateway soak: driver, traffic generators, policies, report |
| `sweep_registry.py` | The vacuity sweep — plants each test's defect and requires it to go red |
| `hwlib.sh` | Shared bench primitives: deploy, send, sniff, counter reads, assertions |

## Running the load ladder (`l13_01`)

Two topologies, and only one of them measures the firewall.

**Generator on the rig** (default) — self-contained, needs nothing plugged in, and every number is a **lower bound**: pktgen competes with the datapath for the same CPUs. Useful for a quick look, not for a figure anyone quotes.

```sh
./l13_01_policy_cost_ladder.py --seconds 20
```

**Generator off-box** — the workstation on the EX2300's SFP ports, feeding the i350. The rig then does nothing but receive, and the readings are the datapath's own.

```sh
./l13_01_policy_cost_ladder.py --gen-host ksys --gen-iface enp3s0f0 \
    --seconds 20
```

Think in **packets**, not bits. The i350 is four 1 GbE ports, so 64-byte line rate is 4 x 1.488 = **5.95 Mpps**, and that is what should outrun the SoC. A 1500-byte flood at the same bandwidth is 24 times fewer packets and will tell you almost nothing about XDP cost.

A 10 GbE source into 1 GbE ports means the **switch** drops the excess, at which point the ladder measures the EX2300's egress queue instead of the firewall. Pace the generator near per-port line rate rather than blasting.

Requires on the generator: `pktgen` (mainline, `modprobe pktgen`), passwordless `sudo`, and ssh from the rig. Requires on the switch: the SFP port and the i350 ports in one VLAN, and frames addressed to MACs the FDB knows — `hw::teach_fdb` does that for on-box tests and the two-box case needs the same treatment.

## The vacuity sweep

A test that passes proves nothing until you know it can fail. `sweep_registry.py` names, for each scenario, the defect it claims to guard and how to plant it — then requires the scenario to go red. A scenario that stays green with its bug planted is reported **vacuous**, and several here have been.

Its history is keyed by scenario ID. That is why `l7_01_tier2_rate_limit_gap` keeps the word `gap` in its name even though the gap closed on 2026-08-19: renaming it would reset the record of whether that check has ever gone red.

## Keeping this copy and the rig in step

The rig runs from `/opt/fwl/tests/system/hw`. **This directory is the source of truth; the rig's copy is a deployment.** A fix lands here first and then goes to the rig, and a soak in progress is a reason to delay the push rather than to edit the rig directly — a policy change mid-run opens a new epoch and the report has to judge each epoch on its own bar.

As of 2026-08-19 they differ deliberately: `l7_01` and `sweep_registry.py` here expect a compiler at or past the Tier 2 `rate_limit` implementation, and the rig is mid-soak on an older build.
