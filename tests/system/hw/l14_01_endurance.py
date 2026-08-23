#!/usr/bin/env python3
"""Sustained load. The middle this suite has never covered.

Two kinds of long-running test already exist and neither is this one.
The soaks (`soak_*`, `gwsoak.py`, `natsoak_*`) run for days at a rate
chosen to be *undemanding* -- the 96 h gateway soak offered about 550
pps, 0.04% of line -- because they are testing correctness and
stability, not capacity. The RFC 2544 harness runs at capacity and
stops after ten seconds, because throughput is defined as a search and
a search wants short trials.

So the box has been proved stable at idle and capable in bursts, and
has never been run hard for an hour. Every defect found on this rig so
far was found inside a ten-second window, which says nothing about the
ones that need longer.

The failures this shape of test exists to catch are trends:

  * throughput that decays -- fine for a minute, 10% down at forty
  * loss that appears only once something fragments or fills
  * `fd` RSS climbing, or a BPF map that grows and never gives back
  * flow tables filling faster than the collector drains them. The
    NAT allocator was measured degrading from 16,500/s to 2,400/s as
    its table filled; ten seconds never reaches that regime
  * thermal drift -- 43 C after thirty seconds says nothing about
    where the package sits after an hour of the same load
  * clocks quietly dropping out of turbo
  * driver error counters climbing slowly enough to look like zero
  * a management plane that answers in 165 ms cold and much worse
    warm

## The assertions are on shape

Borrowed from `l11_06_nat_occupancy_curve.sh`, which asserts that its
last third is not still climbing rather than asserting a number. A
sustained test that only checked its final sample would pass on a box
that had been failing for the middle half, and a test that asserted
absolute values would need retuning on every board.

So: compare the last third of the run against the first third, after a
warm-up window that is discarded because caches, clocks and the flow
table are all still filling.

## Vacuity

A test that runs for an hour and proves nothing is worse than no test,
because it costs an hour and produces confidence. Three guards, all of
which have caught something real on this rig:

  * the offered rate is read back from the generator and compared to
    what was asked for -- a run where the generator quietly stopped
    would otherwise be a clean pass
  * the datapath must have moved a plausible number of packets, so a
    detached XDP program or a down link fails rather than idles
  * a control flow kept alive throughout must still work at the end
"""

import argparse
import json
import pathlib
import statistics
import subprocess
import sys
import threading
import time

HERE = pathlib.Path(__file__).resolve().parent

def _load_module(name, filename):
  """Load a sibling harness by path, so its machinery is reused."""
  import importlib.util
  spec = importlib.util.spec_from_file_location(name, HERE / filename)
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module

def _load_rfc2544():
  """Reuse the throughput harness's generator, counters and honesty."""
  import importlib.util
  spec = importlib.util.spec_from_file_location(
    "rfc2544", HERE / "l13_02_rfc2544_throughput.py")
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module

def probe_throughput(dut, directions, samples):
  """Rate of frames the datapath actually forwarded, between probes.

  NOT `rx_packets`. mlx5 does not count XDP-handled frames there, so a
  trend built on it is flat no matter what the box is doing -- the
  first version of this check reported "arrival rate: first third is
  zero" and then passed itself, which is precisely the vacuous green
  this file's docstring complains about. `tx_xdp_xmit` on the egress
  port is what moves.

  Read here rather than in the on-DUT sampler because it costs an
  `ethtool -S`, which on this driver is 8.6% of a core when polled
  hard. Twenty points over a long run is plenty for a trend and
  perturbs nothing.
  """
  now = time.monotonic()
  total = 0
  for d in directions:
    counters = dut.counters(d.rx, d.tx)
    total += counters.get("tx_xdp", 0) or counters.get("tx", 0)
  samples.append({"t": now, "moved": total})

def probe_management(target, samples):
  """Time a control-plane round trip, the way an operator would feel it.

  Kept deliberately crude -- an ssh round trip and one `fctl status` --
  because the property being tested is "can somebody get in and ask
  what is happening while this is going on", not the latency of any
  particular call.
  """
  start = time.monotonic()
  proc = subprocess.run(
    ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", target,
     "fctl status >/dev/null 2>&1; echo ok"],
    capture_output=True, text=True)
  elapsed = time.monotonic() - start
  samples.append({"t": time.monotonic(), "s": round(elapsed, 3),
                  "ok": proc.stdout.strip() == "ok"})

def trend(series, label, tolerance, unit="", rising_is_bad=True):
  """Compare the last third against the first, after the warm-up.

  Returns (ok, message). A series too short to have thirds is not a
  pass -- it is a run that did not sample enough to say anything.
  """
  if len(series) < 6:
    return False, f"{label}: only {len(series)} samples, cannot judge"
  third = len(series) // 3
  head = statistics.median(series[:third])
  tail = statistics.median(series[-third:])
  if head == 0:
    return (tail == 0), f"{label}: first third is zero"
  change = (tail - head) / abs(head)
  bad = change > tolerance if rising_is_bad else change < -tolerance
  arrow = "up" if change >= 0 else "down"
  msg = (f"{label}: {head:,.1f}{unit} -> {tail:,.1f}{unit} "
         f"({abs(change) * 100:.1f}% {arrow})")
  return not bad, msg

def main():
  ap = argparse.ArgumentParser(description=__doc__)
  ap.add_argument("--dut-host", required=True)
  ap.add_argument("--rx-iface", required=True)
  ap.add_argument("--tx-iface", required=True)
  ap.add_argument("--gen-iface", required=True)
  ap.add_argument("--dst-mac", required=True)
  ap.add_argument("--gen-cpus", default="0,1,2,3,4,5")
  ap.add_argument("--gen-iface-b", default=None,
                  help="second generator port, cabled to --tx-iface. "
                       "Bidirectional load is what a gateway actually "
                       "sees, and it costs more per packet than one "
                       "direction does -- two ingress ports spraying "
                       "across the same cores.")
  ap.add_argument("--dst-mac-b", default=None)
  ap.add_argument("--gen-cpus-b", default=None,
                  help="must not overlap --gen-cpus: a pktgen thread "
                       "belongs to exactly one cpu")
  ap.add_argument("--minutes", type=float, default=30)
  ap.add_argument("--pps", type=int, required=True,
                  help="offered rate. Pick it from a measured RFC 2544 "
                       "result, not from hope -- see --headroom.")
  ap.add_argument("--headroom", type=float, default=0.8,
                  help="fraction of --pps actually offered. Running AT "
                       "the measured ceiling measures the noise floor; "
                       "running far below it measures nothing.")
  ap.add_argument("--frames", default="imix")
  ap.add_argument("--line-gbit", type=float, default=10.0)
  ap.add_argument("--warmup", type=float, default=120,
                  help="seconds discarded before trends are judged. "
                       "Caches, clocks and flow tables are all still "
                       "filling; a trend measured across that window "
                       "is a measurement of the warm-up.")
  ap.add_argument("--sample-interval", type=float, default=2.0)
  ap.add_argument("--decay-tolerance", type=float, default=0.03,
                  help="fractional throughput decay treated as failure")
  ap.add_argument("--rss-tolerance", type=float, default=0.05)
  ap.add_argument("--watchdog", type=int, default=120,
                  help="hardware watchdog timeout, seconds. A long run "
                       "needs this MORE than a short one: the box is "
                       "unattended for hours, and userspace recovery "
                       "does not work on a box that cannot schedule "
                       "anything. 0 disables it, which is how the "
                       "first two-hour attempt ended in a power cycle.")
  ap.add_argument("--watchdog-path", default="/usr/local/bin/f-hw-watchdog")
  ap.add_argument("--out", default="/tmp/endurance")
  args = ap.parse_args()

  rfc = _load_rfc2544()
  rfc.LINE_BITS = int(args.line_gbit * 1_000_000_000)
  mix = rfc.parse_mixes(args.frames)[0]
  dut = rfc.Dut(args.dut_host)
  if dut.sh("true").returncode != 0:
    sys.exit(f"cannot reach {args.dut_host}")
  if dut.sh("test -e /tmp/l13_sampler.py").returncode != 0:
    subprocess.run(["scp", "-q", str(HERE / "l13_sampler.py"),
                    f"{args.dut_host}:/tmp/"], check=True)

  out = pathlib.Path(args.out)
  out.mkdir(parents=True, exist_ok=True)
  seconds = args.minutes * 60
  rate = int(args.pps * args.headroom)
  cpus = [int(c) for c in args.gen_cpus.split(",")]
  directions = [rfc.Direction(args.gen_iface, cpus, args.dst_mac,
                              args.rx_iface, args.tx_iface)]
  if args.gen_iface_b:
    if not (args.dst_mac_b and args.gen_cpus_b):
      sys.exit("--gen-iface-b needs --dst-mac-b and --gen-cpus-b")
    cpus_b = [int(c) for c in args.gen_cpus_b.split(",")]
    if set(cpus) & set(cpus_b):
      sys.exit("--gen-cpus and --gen-cpus-b overlap; the second "
               "stream would silently replace the first")
    directions.append(rfc.Direction(args.gen_iface_b, cpus_b,
                                    args.dst_mac_b, args.tx_iface,
                                    args.rx_iface))
  gen = rfc.Generator(directions, mix)

  print(f"offering {rate:,} pps per direction "
        f"({args.headroom:.0%} of {args.pps:,}) x "
        f"{len(directions)} direction(s) for {args.minutes:g} min, "
        f"{mix.label} frames")
  print(f"warm-up {args.warmup:g}s discarded before judging trends\n")

  samples, mgmt, moved = [], [], []

  def sample_dut():
    proc = subprocess.Popen(
      ["ssh", "-o", "BatchMode=yes", args.dut_host,
       f"python3 /tmp/l13_sampler.py {seconds + 30} {args.rx_iface} "
       f"{args.sample_interval}"],
      stdout=subprocess.PIPE, text=True)
    for line in proc.stdout:
      try:
        samples.append(json.loads(line))
      except ValueError:
        pass

  def sample_mgmt():
    while not stop.is_set():
      probe_management(args.dut_host, mgmt)
      probe_throughput(dut, directions, moved)
      stop.wait(15)

  stop = threading.Event()
  threads = [threading.Thread(target=sample_dut, daemon=True),
             threading.Thread(target=sample_mgmt, daemon=True)]
  for t in threads:
    t.start()

  # Arm the board's own watchdog for the duration. A two-hour run left
  # unattended on a box that stopped answering ARP is a power cycle and
  # a lost afternoon; the SoC does not care whether userspace can be
  # scheduled. Petted by the mgmt thread's own liveness -- if this
  # process cannot run, the board resets itself.
  acl = _load_module("aclscale", "l13_03_acl_scale.py")
  guard = None
  if args.watchdog:
    if dut.sh(f"test -e {args.watchdog_path}").returncode != 0:
      sys.exit(f"the DUT needs {args.watchdog_path}; running a long "
               "load test without a watchdog is how the last one "
               "ended")
    guard = acl.Guard(dut, args.watchdog, args.watchdog_path)
    guard.__enter__()

  gen.configure(rate)
  before = {d.rx: dut.counters(d.rx, d.tx) for d in directions}
  sent, elapsed = gen.run_for(seconds)
  after = {d.rx: dut.counters(d.rx, d.tx) for d in directions}
  stop.set()
  gen.cleanup()
  if guard is not None:
    guard.__exit__(None, None, None)
  time.sleep(3)

  sent_total = sum(sent.values())
  delivered = sum(
    (after[d.rx].get("tx_xdp", 0) or after[d.rx].get("tx", 0))
    - (before[d.rx].get("tx_xdp", 0) or before[d.rx].get("tx", 0))
    for d in directions)
  missed = sum(after[d.rx]["missed"] - before[d.rx]["missed"]
               for d in directions)
  offered = sent_total / elapsed / len(directions)
  achieved = offered / rate if rate else 0

  raw = out / "endurance.jsonl"
  with raw.open("w") as fh:
    for s in samples:
      fh.write(json.dumps(s) + "\n")
  (out / "management.json").write_text(json.dumps(mgmt, indent=2))

  warm = [s for s in samples
          if s["t"] - samples[0]["t"] >= args.warmup] if samples else []
  print(f"\n{'=' * 70}\nENDURANCE — {args.minutes:g} min at "
        f"{offered:,.0f} pps\n{'=' * 70}")

  failures = []

  def check(ok, msg):
    print(f"  {'ok  ' if ok else 'FAIL'}  {msg}")
    if not ok:
      failures.append(msg)

  # --- vacuity guards, before any trend is believed ----------------
  check(achieved >= 0.95,
        f"generator delivered {achieved:.1%} of the {rate:,} pps asked "
        f"for")
  check(delivered > sent_total * 0.5,
        f"datapath moved {delivered:,} of {sent_total:,} offered")
  check(bool(mgmt) and mgmt[-1]["ok"],
        "control plane still answered at the end")
  check(len(warm) >= 6,
        f"{len(warm)} post-warm-up samples to judge trends on")
  if failures:
    print("\nvacuity guards failed; trends below are not evidence")

  # --- the trends --------------------------------------------------
  check(missed == 0 or missed < sent_total * 0.0001,
        f"frames missed by the ring: {missed:,} of {sent_total:,}")

  if warm:
    rss = [s["fd_rss_kb"] for s in warm if s["fd_rss_kb"] > 0]
    if rss:
      check(*trend(rss, "fd RSS", args.rss_tolerance, " kB"))
    for name in sorted(warm[0]["temps_mC"]):
      vals = [s["temps_mC"][name] / 1000.0 for s in warm]
      if max(vals) > 0:
        check(*trend(vals, f"temp {name}", 0.15, " C"))
    for pol in sorted(warm[0]["freq_khz"]):
      vals = [s["freq_khz"][pol] for s in warm]
      ceiling = warm[0]["freq_max_khz"][pol]
      low = sum(1 for v in vals if v < ceiling * 0.9)
      check(low < len(vals) * 0.1,
            f"{pol} below 90% of max in {low}/{len(vals)} samples")
    for key in ("rx_dropped", "rx_errors", "rx_fifo_errors"):
      vals = [s["nic"][key] for s in warm if s["nic"].get(key, -1) >= 0]
      if vals:
        check(vals[-1] == vals[0],
              f"{key} moved by {vals[-1] - vals[0]}")

  # Forwarding rate over the run, from a counter that moves under XDP.
  hot = []
  if moved:
    hot = [m for m in moved if m["t"] - moved[0]["t"] >= args.warmup]
  rates = [(b["moved"] - a["moved"]) / (b["t"] - a["t"])
           for a, b in zip(hot, hot[1:])
           if b["t"] > a["t"] and b["moved"] >= a["moved"]]
  if rates:
    check(*trend(rates, "forwarding rate", args.decay_tolerance,
                 " pps", rising_is_bad=False))
  else:
    check(False, "no forwarding-rate samples; the trend proves nothing")

  if mgmt:
    lat = [m["s"] for m in mgmt if m["ok"]]
    if lat:
      check(*trend(lat, "control-plane round trip", 0.5, "s"))
    check(all(m["ok"] for m in mgmt),
          f"control plane answered {sum(m['ok'] for m in mgmt)}/"
          f"{len(mgmt)} probes")

  print(f"\nraw samples: {raw}")
  print("VERDICT: " + ("PASS" if not failures
                       else f"FAIL ({len(failures)} check(s))"))
  return 1 if failures else 0

if __name__ == "__main__":
  sys.exit(main())
