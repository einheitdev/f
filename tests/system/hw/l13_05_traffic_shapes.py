#!/usr/bin/env python3
"""Which traffic patterns hurt, holding the policy constant.

Every throughput number this project has produced was measured with
one traffic shape: uniform random 5-tuples, one protocol, perfectly
paced, one frame-size distribution. That shape was chosen because it
is easy to generate and it saturates the box, not because anything
sends it. A firewall in a plant sees VLAN tags, broadcast storms, a
handful of elephant flows carrying most of the bytes, and a long tail
of connections that live for three packets.

The policy is held constant and the SHAPE is swept, so the column
that moves is the one being tested. What comes out is not a ceiling;
it is a ratio against the shape every previous number was measured
with, which is the honest way to read those numbers afterwards.

Why each shape is here:

  uniform        the baseline every earlier measurement used
  single-flow    one 5-tuple. Conntrack hits every time and the map
                 is one hot cache line -- the cheapest case, and a
                 useful upper bound on what state lookup costs
  few-elephants  64 flows of 10,000 packets. Real bulk traffic, and
                 the case where a flow table is nearly free
  many-mice      every packet a new flow. Every lookup misses and
                 every miss may insert; this is the regime that made
                 the NAT allocator decay from 16,500/s to 2,400/s,
                 and it is also what the earlier "random tuples"
                 tests were unwittingly measuring
  vlan           tagged frames. The parse path grows a step, and
                 zones are carved by VLAN in most real deployments
  broadcast      dst_mac ff:ff:ff:ff:ff:ff. No conntrack, no NAT, a
                 different verdict path -- and the case `f` is
                 pitched at for storm shielding
  multicast      the industrial-protocol case: PROFINET, EtherNet/IP
                 and mDNS are all multicast, and a plant floor is
                 full of them
  mac-churn      256 destination MACs. Pressures the neighbour and
                 devmap paths rather than the flow table

A shape that cannot be generated is reported as such rather than
silently skipped: a missing row reads like a passing row.
"""

import argparse
import importlib.util
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent

def _load(name, filename):
  spec = importlib.util.spec_from_file_location(name, HERE / filename)
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module

# (label, extra pktgen settings, what it is meant to stress)
SHAPES = [
  ("uniform", [], "the baseline every earlier number used"),
  ("single-flow", ["flows 1", "flowlen 0"], "conntrack always hits"),
  ("few-elephants", ["flows 64", "flowlen 10000"], "bulk transfer"),
  ("many-mice", ["flows 1000000", "flowlen 1"], "every packet a new flow"),
  ("vlan", ["vlan_id 100"], "tagged frames, one more parse step"),
  ("broadcast", ["dst_mac ff:ff:ff:ff:ff:ff"], "storm shield case"),
  ("multicast", ["dst_mac 01:00:5e:00:00:01"], "PROFINET / mDNS shape"),
  ("mac-churn", ["dst_mac_count 256"], "neighbour and devmap pressure"),
]

def main():
  ap = argparse.ArgumentParser(description=__doc__)
  ap.add_argument("--dut-host", required=True)
  ap.add_argument("--rx-iface", required=True)
  ap.add_argument("--tx-iface", required=True)
  ap.add_argument("--gen-iface", required=True)
  ap.add_argument("--dst-mac", required=True)
  ap.add_argument("--gen-cpus", default="0,1,2,3,4,5")
  ap.add_argument("--frames", default="imix")
  ap.add_argument("--line-gbit", type=float, default=10.0)
  ap.add_argument("--seconds", type=float, default=10)
  ap.add_argument("--tolerance", type=float, default=0.01)
  ap.add_argument("--precision", type=float, default=0.02)
  ap.add_argument("--shapes", default="",
                  help="comma-separated subset; default is all")
  ap.add_argument("--watchdog", type=int, default=180)
  ap.add_argument("--watchdog-path",
                  default="/usr/local/bin/f-hw-watchdog")
  ap.add_argument("--out", default="/tmp/traffic-shapes")
  args = ap.parse_args()

  rfc = _load("rfc2544", "l13_02_rfc2544_throughput.py")
  acl = _load("aclscale", "l13_03_acl_scale.py")
  rfc.LINE_BITS = int(args.line_gbit * 1_000_000_000)
  mix = rfc.parse_mixes(args.frames)[0]
  dut = rfc.Dut(args.dut_host)
  if dut.sh("true").returncode != 0:
    sys.exit(f"cannot reach {args.dut_host}")

  wanted = [s.strip() for s in args.shapes.split(",") if s.strip()]
  shapes = [s for s in SHAPES if not wanted or s[0] in wanted]
  cpus = [int(c) for c in args.gen_cpus.split(",")]
  out = pathlib.Path(args.out)
  out.mkdir(parents=True, exist_ok=True)

  results, baseline = [], None
  print(f"{mix.label} frames, policy held constant, shape swept\n")
  for label, extra, why in shapes:
    direction = rfc.Direction(args.gen_iface, cpus, args.dst_mac,
                              args.rx_iface, args.tx_iface,
                              extra=extra)
    gen = rfc.Generator([direction], mix)
    log = []
    try:
      with acl.Guard(dut, args.watchdog, args.watchdog_path):
        # A setting pktgen rejects leaves the shape unapplied, and an
        # unapplied shape measures the baseline again under another
        # name -- the quietest way to produce a table of lies.
        if not gen.configure(1000):
          print(f"  {label:<15} COULD NOT APPLY: {extra}")
          results.append({"shape": label, "error": "configure failed",
                          "extra": extra})
          continue
        best = rfc.search(dut, gen, args.seconds, mix, "forward",
                          args.tolerance, log, args.precision)
    finally:
      gen.cleanup()
    pps = best["offered_pps"] if best else 0
    if label == "uniform":
      baseline = pps or None
    rel = f"{100.0 * pps / baseline:5.1f}%" if baseline and pps else "  -  "
    print(f"  {label:<15}{pps:>12,} pps  {rel}  {why}", flush=True)
    results.append({"shape": label, "pps": pps, "extra": extra,
                    "gbit": round(mix.gbit(pps), 3), "trials": log})

  print("\n" + "=" * 72)
  print("TRAFFIC SHAPE vs THROUGHPUT (policy constant)")
  print("=" * 72)
  for r in results:
    if "error" in r:
      print(f'  {r["shape"]:<15}{"NOT APPLIED":>14}  {r["error"]}')
      continue
    rel = (f'{100.0 * r["pps"] / baseline:5.1f}%'
           if baseline else "  -  ")
    print(f'  {r["shape"]:<15}{r["pps"]:>12,} pps{rel:>9}'
          f'{r["gbit"]:>9.2f} Gb/s')
  path = out / "traffic-shapes.json"
  path.write_text(json.dumps(results, indent=2))
  print(f"\nfull trials: {path}")
  return 0

if __name__ == "__main__":
  sys.exit(main())
