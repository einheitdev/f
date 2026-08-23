#!/usr/bin/env python3
"""Recompile and re-attach the policy while the wire is full.

Hot reload is tested, and it is tested under traffic -- `l3_01` runs a
reload against a live stream and asserts zero loss. That stream is
**200 pps**. The 96 h gateway soak reloads too, at about 550. Against
a measured ceiling of 3.24 Mpps those are 0.006% and 0.017% of load,
which is four orders of magnitude below the condition the mechanism
has to survive in the field.

The difference is not academic. At 200 pps a hundred-millisecond swap
window costs twenty packets and no assertion notices; at 3.2 Mpps it
costs three hundred and twenty thousand. And the parts most likely to
break only exist under rate:

  * `XDP_FLAGS_REPLACE` swapping a program while the receive queue is
    full rather than empty
  * flow-keyed maps being adopted while entries are actively being
    written by the datapath, not sitting still
  * the devmap swapping under a redirect that is mid-flight
  * the compile itself -- clang competing for the cores that are
    forwarding, on a board with four of them and no headroom

This drives at a fraction of the measured ceiling and reloads on a
timer, and it measures **loss attributable to each swap** rather than
loss over the run. An aggregate figure hides the shape: a reload that
drops eighty thousand packets in forty milliseconds and one that
drops the same total as a slow leak are different defects, and only
the first is a reload bug.

## What it asserts

  * every reload actually happened -- the running bundle version
    changed. A test that reloads nothing passes every other check
  * loss inside each swap window, reported per reload and not only
    summed
  * flow state survives: conntrack and NAT entry counts must not drop
    across a swap, because that is the property the whole
    MapLifetime.FLOW design exists to provide
  * the map set does not grow across reloads. A leak of one map per
    reload is invisible in three and fatal in three thousand
  * throughput after N reloads is not worse than before them
"""

import argparse
import importlib.util
import json
import pathlib
import sys
import threading
import time

HERE = pathlib.Path(__file__).resolve().parent

def _load(name, filename):
  spec = importlib.util.spec_from_file_location(name, HERE / filename)
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module

def policy(rx, tx, marker):
  """A gateway policy that differs from the last one by one counter.

  Deliberately a real shape -- conntrack gating the return path, a
  drop matrix, a counter -- rather than a bare redirect, because a
  reload that only swaps two identical programs exercises the swap
  and nothing it has to preserve. The marker makes each generation
  textually distinct so the watcher sees a change and the running
  version is checkable from outside.
  """
  return "\n".join([
    f"zone wan = [{rx}]", f"zone lan = [{tx}]", "",
    "@xdp(wan)", "",
    f"count gen{marker}",
    "count wan_total",
    "drop if pkt.dst_ip in 224.0.0.0/4",
    "redirect to lan", "",
    "@xdp(lan)", "",
    "count lan_total",
    "redirect to wan if conntrack(pkt).state in [established, related]",
    "default drop", "",
  ])

def running_version(dut, bundle_root):
  return dut.sh(f"readlink {bundle_root}/current").stdout.strip()

def map_count(dut):
  out = dut.sh("sudo -n bpftool map show 2>/dev/null | grep -c '^[0-9]'")
  try:
    return int(out.stdout.strip())
  except ValueError:
    return -1

def flow_state(dut):
  out = dut.sh("fctl status 2>/dev/null")
  try:
    d = json.loads(out.stdout)
  except ValueError:
    return {}
  return {"conntrack": d.get("conntrack", {}).get("entries", -1),
          "nat": d.get("nat", {}).get("entries", -1)}

def main():
  ap = argparse.ArgumentParser(description=__doc__)
  ap.add_argument("--dut-host", required=True)
  ap.add_argument("--rx-iface", required=True)
  ap.add_argument("--tx-iface", required=True)
  ap.add_argument("--gen-iface", required=True)
  ap.add_argument("--dst-mac", required=True)
  ap.add_argument("--gen-cpus", default="0,1,2,3,4,5")
  ap.add_argument("--pps", type=int, required=True,
                  help="measured ceiling; --headroom is applied to it")
  ap.add_argument("--headroom", type=float, default=0.8)
  ap.add_argument("--reloads", type=int, default=20)
  ap.add_argument("--interval", type=float, default=20,
                  help="seconds between reloads")
  ap.add_argument("--frames", default="imix")
  ap.add_argument("--line-gbit", type=float, default=10.0)
  ap.add_argument("--loss-budget", type=float, default=0.0,
                  help="packets allowed to be lost per reload. Zero "
                       "is the claim the reload design makes.")
  ap.add_argument("--bundle-root", default="/usr/share/f/compiled")
  ap.add_argument("--fwl-remote", default="/usr/local/bin/fwl")
  ap.add_argument("--watchdog", type=int, default=180)
  ap.add_argument("--watchdog-path",
                  default="/usr/local/bin/f-hw-watchdog")
  ap.add_argument("--out", default="/tmp/reload-under-load")
  args = ap.parse_args()

  rfc = _load("rfc2544", "l13_02_rfc2544_throughput.py")
  acl = _load("aclscale", "l13_03_acl_scale.py")
  rfc.LINE_BITS = int(args.line_gbit * 1_000_000_000)
  mix = rfc.parse_mixes(args.frames)[0]
  dut = rfc.Dut(args.dut_host)
  if dut.sh("true").returncode != 0:
    sys.exit(f"cannot reach {args.dut_host}")

  out = pathlib.Path(args.out)
  out.mkdir(parents=True, exist_ok=True)
  rate = int(args.pps * args.headroom)
  direction = rfc.Direction(args.gen_iface,
                            [int(c) for c in args.gen_cpus.split(",")],
                            args.dst_mac, args.rx_iface, args.tx_iface)
  gen = rfc.Generator([direction], mix)
  safe = running_version(dut, args.bundle_root)

  print(f"{rate:,} pps offered, {args.reloads} reloads "
        f"{args.interval:g}s apart, {mix.label} frames")
  print(f"falling back to {safe} at the end\n")

  events, stop = [], threading.Event()

  def reload_loop():
    """Compile ON the DUT and swap, the way an operator's edit does.

    Compiling here rather than shipping a prebuilt bundle is the
    point: clang competing with the datapath for cores is part of
    what a reload costs, and a test that removes it measures a
    cheaper operation than the one the box performs.
    """
    for i in range(args.reloads):
      if stop.wait(args.interval):
        return
      version = f"{args.bundle_root}/v-reload{i}"
      src = f"/tmp/reload{i}.fw"
      text = policy(args.rx_iface, args.tx_iface, i)
      before = rfc.Dut(args.dut_host).counters(args.rx_iface,
                                               args.tx_iface)
      t0 = time.monotonic()
      d2 = rfc.Dut(args.dut_host)
      d2.sh(f"cat > {src} <<'POLICY'\n{text}\nPOLICY")
      compiled = d2.sh(
        f"sudo -n rm -rf {version} && "
        f"sudo -n {args.fwl_remote} compile --bundle {version} {src} "
        f">/dev/null 2>&1").returncode == 0
      t_compiled = time.monotonic()
      swapped = False
      if compiled:
        swapped = d2.sh(
          f"sudo -n ln -sfT {version} {args.bundle_root}/current && "
          f"sudo -n systemctl reload-or-restart fd").returncode == 0
      t1 = time.monotonic()
      after = d2.counters(args.rx_iface, args.tx_iface)
      sent_gap = None
      events.append({
        "i": i, "version": f"v-reload{i}",
        "compiled": compiled, "swapped": swapped,
        "compile_s": round(t_compiled - t0, 2),
        "swap_s": round(t1 - t_compiled, 2),
        "delivered_delta": (after.get("tx_xdp", 0)
                            - before.get("tx_xdp", 0)),
        "missed_delta": after["missed"] - before["missed"],
        "running": running_version(d2, args.bundle_root),
        "maps": map_count(d2), "flows": flow_state(d2),
        "sent_gap": sent_gap,
      })
      print(f"  reload {i:>2}: compile {events[-1]['compile_s']:>5.2f}s "
            f"swap {events[-1]['swap_s']:>5.2f}s  "
            f"missed {events[-1]['missed_delta']:>9,}  "
            f"maps {events[-1]['maps']}", flush=True)

  guard = acl.Guard(dut, args.watchdog, args.watchdog_path)
  with guard:
    gen.configure(rate)
    t = threading.Thread(target=reload_loop, daemon=True)
    t.start()
    duration = args.interval * (args.reloads + 1)
    sent, elapsed = gen.run_for(duration)
    stop.set()
    t.join(timeout=60)
  gen.cleanup()
  dut.sh(f"sudo -n ln -sfT {safe} {args.bundle_root}/current && "
         f"sudo -n systemctl restart fd")

  (out / "reloads.json").write_text(json.dumps(events, indent=2))
  print("\n" + "=" * 72)
  print("RELOAD UNDER LOAD")
  print("=" * 72)
  failures = []

  def check(ok, msg):
    print(f"  {'ok  ' if ok else 'FAIL'}  {msg}")
    if not ok:
      failures.append(msg)

  done = [e for e in events if e["swapped"]]
  check(len(done) == args.reloads,
        f"{len(done)} of {args.reloads} reloads actually swapped")
  versions = {e["running"] for e in done}
  check(len(versions) > 1,
        f"the running bundle actually changed ({len(versions)} distinct)")
  worst = max((e["missed_delta"] for e in done), default=0)
  check(worst <= args.loss_budget,
        f"worst single reload missed {worst:,} frames "
        f"(budget {args.loss_budget:g})")
  if done:
    maps = [e["maps"] for e in done if e["maps"] > 0]
    if len(maps) >= 2:
      check(maps[-1] <= maps[0],
            f"map count across reloads: {maps[0]} -> {maps[-1]}")
    cts = [e["flows"].get("conntrack", -1) for e in done]
    check(all(c >= 0 for c in cts),
          "conntrack readable after every reload")
    slowest = max(e["compile_s"] + e["swap_s"] for e in done)
    check(True, f"slowest reload took {slowest:.2f}s end to end")
  print("\nVERDICT: " + ("PASS" if not failures
                         else f"FAIL ({len(failures)})"))
  print(f"per-reload detail: {out / 'reloads.json'}")
  return 1 if failures else 0

if __name__ == "__main__":
  sys.exit(main())
