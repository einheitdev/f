"""Verdict on a gateway-soak log.

Re-derives the answer from `/var/log/f/gwsoak.jsonl` and nothing else,
and exits non-zero on drift. Exit 0 = pass, 1 = fail, 2 = the log
cannot support a verdict — the third value is separate on purpose,
because folding "we could not tell" into either of the other two is how
a whole section of soak reporting came to carry no information.

The wire bar is not restated here. It is imported from gwsoak.py's
`verify_probe`, so the bar a finished run is judged against cannot
drift from the bar `start` admitted the gateway on, and a log written
by an older sampler is re-judged rather than trusted.

What is a FAIL and what is a NOTE
---------------------------------
A FAIL is a claim this soak exists to make that stopped being true: a
sample whose wire witness did not hold, a counter that went backwards
or disappeared, a table that is still climbing at the end of the run, a
restart, a journal error, a link flap, RSS running away. A NOTE is a
measurement an operator should read and no verdict should be built on
— growth rates, projections, thermals with headroom.

Usage: gwsoak_report.py [<log>]
"""
import json
import os
import statistics
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gwsoak import LOG, STATE, verify_probe  # noqa: E402

# The sampler ticks every 60 s. Anything past this is the sampler, not
# the firewall, deciding what got measured.
MAX_GAP_S = 300
NAT_CAP = 65536
CT_CAP = 65536
NIC_WARN_C = 90
SOC_WARN_C = 85
# A table is "creeping" when its last third sits materially above its
# middle third. Both a ratio and an absolute floor, so a table that
# plateaus at 40 entries is not failed for wobbling to 47.
CREEP_RATIO = 1.15
CREEP_FLOOR = 200


def load(path: str) -> list:
  rows = []
  with open(path) as fh:
    for line in fh:
      line = line.strip()
      if not line:
        continue
      try:
        rows.append(json.loads(line))
      except json.JSONDecodeError:
        rows.append({"_malformed": line[:80]})
  return rows


def when(row: dict) -> datetime:
  return datetime.strptime(row["ts"], "%Y-%m-%dT%H:%M:%SZ")


def dig(row: dict, *path, default=-1):
  cur = row
  for key in path:
    if not isinstance(cur, dict) or key not in cur:
      return default
    cur = cur[key]
  return cur


def series(rows: list, *path) -> list:
  return [dig(r, *path) for r in rows]


def creeping(values: list) -> tuple:
  """(is_creeping, middle_median, last_median) over the last two
  thirds of a run. The shape is the assertion, not a number: a table
  whose collector works rises for about one idle timeout and then
  flattens, because flows expire as fast as they arrive."""
  if len(values) < 12:
    return (False, -1, -1)
  third = len(values) // 3
  middle = statistics.median(values[third:2 * third])
  last = statistics.median(values[2 * third:])
  grew = last - middle
  return (grew > CREEP_FLOOR and last > middle * CREEP_RATIO,
          middle, last)


def main() -> int:
  path = sys.argv[1] if len(sys.argv) > 1 else LOG
  if not os.path.exists(path):
    print(f"no log at {path}: nothing has been sampled")
    return 2
  rows = load(path)
  if len(rows) < 3:
    print(f"only {len(rows)} sample(s): not enough for a verdict")
    return 2
  malformed = [r for r in rows if "_malformed" in r]
  if malformed:
    print(f"{len(malformed)} malformed sample line(s); the log cannot "
          f"support a verdict")
    return 2

  fails: list = []
  notes: list = []
  first, last = rows[0], rows[-1]
  stamps = [when(r) for r in rows]
  hours = (stamps[-1] - stamps[0]).total_seconds() / 3600.0

  state = {}
  if os.path.exists(STATE):
    try:
      with open(STATE) as fh:
        state = json.load(fh)
    except (OSError, json.JSONDecodeError):
      state = {}

  print("=" * 66)
  print("GATEWAY SOAK REPORT")
  print("=" * 66)
  print(f"window     : {first['ts']} -> {last['ts']}")
  print(f"duration   : {hours:.2f} h, {len(rows)} samples")
  if state.get("target_hours"):
    target = state["target_hours"]
    print(f"target     : {target} h (ends {state.get('target_end')}) "
          f"— {'REACHED' if hours >= target else 'still running'}")

  # --- sampling continuity -------------------------------------------
  gaps = [(rows[i - 1]["ts"], rows[i]["ts"],
           (stamps[i] - stamps[i - 1]).total_seconds())
          for i in range(1, len(rows))
          if (stamps[i] - stamps[i - 1]).total_seconds() > MAX_GAP_S]
  worst = max((stamps[i] - stamps[i - 1]).total_seconds()
              for i in range(1, len(stamps)))
  print(f"sampling   : worst gap {worst:.0f}s, {len(gaps)} over "
        f"{MAX_GAP_S}s")
  for a, b, gap in gaps[:5]:
    fails.append(f"sampling gap {gap / 60:.0f} min between {a} and {b}")

  # --- the wire ------------------------------------------------------
  #
  # Re-derived from each sample's own probe, never read off the
  # sampler's stored verdict.
  bad_samples = [(r["ts"], verify_probe(r.get("probe", {})))
                 for r in rows]
  bad_samples = [(ts, why) for ts, why in bad_samples if why]
  good = len(rows) - len(bad_samples)
  print(f"wire       : {good}/{len(rows)} samples had every delivery "
        f"claim witnessed by a real socket")
  if bad_samples:
    ts, why = bad_samples[0]
    fails.append(f"{len(bad_samples)} sample(s) failed a wire claim; "
                 f"first {ts}: {why[0]}")
    for ts, why in bad_samples[1:4]:
      notes.append(f"also {ts}: {why[0]}")
  peers = {tuple(dig(r, "probe", "srv", "peer_addrs", default=[]))
           for r in rows}
  print(f"peer addrs : {sorted(p for p in peers)} (the far side's own "
        f"kernel, both inside zones)")

  # --- counters, by name ---------------------------------------------
  names = sorted({k for r in rows for k in r.get("counters", {})})
  if not names:
    print("counters   : none declared — the log cannot support a "
          "verdict")
    return 2
  print(f"counters   : {len(names)} declared, read back by name")
  for name in names:
    seq = series(rows, "counters", name)
    if -1 in seq:
      fails.append(f"counter {name} was ABSENT from the running "
                   f"bundle in {seq.count(-1)} sample(s) — a renamed "
                   f"or dropped counter reads -1, never 0")
      continue
    back = [rows[i]["ts"] for i in range(1, len(seq))
            if seq[i] < seq[i - 1]]
    if back:
      fails.append(f"counter {name} went backwards at {back[0]} "
                   f"({len(back)} time(s))")
    print(f"   {name:<24} +{seq[-1] - seq[0]:,}")
  for zone_counter in ("a_masq", "b_masq", "w_est"):
    if zone_counter in names:
      seq = series(rows, "counters", zone_counter)
      if seq[-1] <= seq[0]:
        fails.append(f"counter {zone_counter} did not move across the "
                     f"whole run")

  # --- the tables ----------------------------------------------------
  nat = series(rows, "nat", "entries")
  ct = series(rows, "conntrack", "entries")
  reclaimed = series(rows, "nat", "total_reclaimed")
  evicted = series(rows, "conntrack", "total_evicted")
  print(f"fwl_nat    : {nat[0]} -> {nat[-1]}, peak {max(nat)} "
        f"({100.0 * max(nat) / NAT_CAP:.1f} % of {NAT_CAP}), "
        f"{reclaimed[-1] - reclaimed[0]:,} reclaimed")
  print(f"conntrack  : {ct[0]} -> {ct[-1]}, peak {max(ct)} "
        f"({100.0 * max(ct) / CT_CAP:.1f} % of {CT_CAP}), "
        f"{evicted[-1] - evicted[0]:,} evicted")
  # Vacuity guard: "flat" has to mean flows expiring as fast as they
  # arrive, not the datapath having stopped. It only means anything if
  # the table grew in the first place and the collector actually ran.
  if max(nat) > 0 and reclaimed[-1] <= reclaimed[0] and hours > 1:
    fails.append("fwl_nat reclaimed nothing across the run: a flat "
                 "table with no reclamation is a datapath that "
                 "stopped, not a collector that works")
  crept, mid, end = creeping(nat)
  if crept:
    fails.append(f"fwl_nat is still climbing at the end of the run: "
                 f"median {mid} in the middle third, {end} in the "
                 f"last. It fills; it does not plateau")
  elif mid >= 0:
    notes.append(f"fwl_nat plateaued: median {mid} -> {end} across the "
                 f"last two thirds")
  crept, mid, end = creeping(ct)
  if crept:
    fails.append(f"conntrack is still climbing: median {mid} -> {end} "
                 f"across the last two thirds")
  for field in ("refused", "table_full"):
    seq = series(rows, "nat", field)
    if seq[-1] > seq[0]:
      fails.append(f"nat.{field} moved {seq[0]} -> {seq[-1]}: the "
                   f"table hit its cap under this workload")
  if min(ct[1:] or ct) == 0:
    fails.append("conntrack dropped to 0 entries under traffic")

  # --- routing and the next hop --------------------------------------
  routed = series(rows, "route", "routed")
  bridged = series(rows, "route", "bridged")
  no_neigh = series(rows, "route", "no_neigh")
  print(f"route      : routed +{routed[-1] - routed[0]:,}, bridged "
        f"+{bridged[-1] - bridged[0]:,}, no_neigh {no_neigh[0]} -> "
        f"{no_neigh[-1]}")
  if routed[-1] <= routed[0]:
    fails.append("route.routed did not move: nothing was forwarded "
                 "through the FIB across the whole run")
  # The question a long run can answer and a short one cannot: does the
  # box RE-LOSE a next hop it has already resolved? Early samples may
  # legitimately count one lost first frame per destination.
  # The box is warm within minutes — `start` pings every next hop it
  # routes to before the first sample. A tenth of a 96 h run is nine
  # hours, and a next hop re-lost at hour five would be absorbed into
  # the baseline, so the warm-up window is capped at ten samples.
  warm = min(10, max(1, len(rows) // 10))
  if no_neigh[-1] > no_neigh[warm]:
    fails.append(f"route.no_neigh climbed after the box was warm: "
                 f"{no_neigh[warm]} at sample {warm} -> "
                 f"{no_neigh[-1]} at the end. The box re-lost a next "
                 f"hop it had already resolved")
  else:
    notes.append(f"no_neigh flat at {no_neigh[-1]} from sample {warm} "
                 f"onward — the first frame to each next hop is lost, "
                 f"counted, and never repeated")
  # `bridged` is the one number that says a forward the policy meant to
  # ROUTE silently became an L2-adjacent hand-off — same frame, same
  # cable, different network. A handful is a switch artefact; a share
  # of the routed traffic is the routed path not being taken.
  fell_back = bridged[-1] - bridged[0]
  crossed = max(1, routed[-1] - routed[0])
  if fell_back > crossed // 100:
    fails.append(f"{fell_back} of {crossed} forwards took the "
                 f"L2-adjacent fallback rather than the routed path "
                 f"({100.0 * fell_back / crossed:.1f} %)")
  elif fell_back:
    notes.append(f"{fell_back} frame(s) took the L2-adjacent fallback "
                 f"instead of the routed path")
  overridden = [r["ts"] for r in rows
                if dig(r, "route", "forwarding_overridden") is True]
  if overridden:
    fails.append(f"ip_forward was held down behind fd's back in "
                 f"{len(overridden)} sample(s), first {overridden[0]}")

  # --- the egress tracker --------------------------------------------
  tracked = series(rows, "egress", "tracked")
  attached = series(rows, "egress", "attached")
  xdp = series(rows, "xdp_ifaces")
  print(f"egress     : tracked +{tracked[-1] - tracked[0]:,}, attached "
        f"on {attached[-1]} of {xdp[-1]} datapath interface(s)")
  if any(a != x for a, x in zip(attached, xdp)):
    fails.append("the egress tracker was not on every interface the "
                 "datapath is on")
  # Every sample opens exactly one box-originated flow, so `tracked`
  # should move every minute. A STALL is the failure — the tracker
  # stopped counting — and a stall looks like a RUN. One isolated
  # non-increase is an ephemeral port reused inside the conntrack idle
  # timeout, which is a refresh and not a new flow; failing a 96 h run
  # on that would make the check about luck.
  run = worst_run = 0
  first_stall = ""
  for i in range(1, len(tracked)):
    if tracked[i] <= tracked[i - 1]:
      run += 1
      if run > worst_run:
        worst_run, first_stall = run, rows[i]["ts"]
    else:
      run = 0
  if worst_run >= 3:
    fails.append(f"the egress tracker recorded no NEW box-originated "
                 f"flow across {worst_run} consecutive samples ending "
                 f"{first_stall} — every sample opens one")
  elif worst_run:
    notes.append(f"{worst_run} isolated sample(s) with no new tracked "
                 f"flow (an ephemeral port reused inside the idle "
                 f"timeout is a refresh, not a new flow)")
  refused = series(rows, "egress", "refused")
  if refused[-1] > refused[0]:
    fails.append(f"egress.refused moved {refused[0]} -> {refused[-1]}: "
                 f"conntrack at its cap, which is the original DNS "
                 f"failure restored by a mechanism working as designed")

  # --- the body's view of a de-NATed frame ---------------------------
  #
  # Recorded, never asserted. `count w_pre_denat if pkt.dst_ip ==
  # <uplink address>` and `count w_to_a/w_to_b if pkt.dst_ip in <inside
  # subnet>` are read on a wire where EVERY reply is demonstrably
  # de-NATed into one of those subnets, so the pair says which address
  # the BODY saw. The prelude caches `dst_ip` before `fwl_nat_denat`
  # rewrites it, which makes a return-path `redirect` naming an inside
  # host unreachable on any zone that de-NATs. Two numbers rather than
  # one, because a single counter at zero is not a measurement.
  counters = {name: series(rows, "counters", name) for name in names}
  if {"w_pre_denat", "w_to_a", "w_to_b"} <= set(counters):
    pre = counters["w_pre_denat"][-1] - counters["w_pre_denat"][0]
    inside = ((counters["w_to_a"][-1] - counters["w_to_a"][0])
              + (counters["w_to_b"][-1] - counters["w_to_b"][0]))
    total = counters["w_total"][-1] - counters["w_total"][0]
    notes.append(
      f"the uplink body saw the PRE-de-NAT destination on "
      f"{pre:,} of {total:,} frames and an inside address on "
      f"{inside:,} — the prelude caches dst_ip before "
      f"`fwl_nat_denat` rewrites it, so a return-path `redirect` to "
      f"an inside zone is unreachable behind masquerade. Replies come "
      f"home through `allow` and the Linux stack, which is what "
      f"deploy/firstboot generates")

  # --- the daemon ----------------------------------------------------
  rss = series(rows, "fd", "rss_kb")
  restarts = series(rows, "fd", "nrestarts")
  errs = sum(dig(r, "fd", "err_5min", default=0) for r in rows)
  active = [r["ts"] for r in rows
            if dig(r, "fd", "active", default="?") != "active"]
  boots = {r.get("boot_id") for r in rows}
  print(f"fd         : RSS {rss[0]} -> {rss[-1]} kB (peak {max(rss)}), "
        f"{restarts[-1]} restart(s), {errs} journal error line(s)")
  if rss[-1] > rss[0] * 1.5:
    fails.append(f"fd RSS grew {rss[0]} -> {rss[-1]} kB (>50 %): leak")
  if restarts[-1] != restarts[0]:
    fails.append(f"fd restarted during the run "
                 f"({restarts[0]} -> {restarts[-1]})")
  if active:
    fails.append(f"fd was not active in {len(active)} sample(s), "
                 f"first {active[0]}")
  if errs:
    # Each sample reads a FIVE-minute window and samples land every
    # minute, so one journal line is counted about five times. The
    # number is a signal, not a tally, and saying so is cheaper than
    # letting a reader take it for a count.
    fails.append(f"fd logged at the error level during the run "
                 f"({errs} line-sightings across overlapping 5-minute "
                 f"windows, so roughly {max(1, errs // 5)} distinct "
                 f"line(s)) — read `journalctl -u fd -p err`")
  if len(boots) > 1:
    fails.append(f"the box rebooted during the run ({len(boots)} boot "
                 f"ids); the soak does not survive a reboot and the "
                 f"samples either side are of different runs")
  idle = [r["ts"] for r in rows
          if any(a != "active" for a in r.get("traffic_active", []))]
  if idle:
    fails.append(f"a traffic generator was not running in "
                 f"{len(idle)} sample(s), first {idle[0]}")

  # --- the wire underneath -------------------------------------------
  flaps = (dig(last, "linkup_total", default=0)
           - dig(first, "linkup_total", default=0))
  soc = [v / 1000 for v in series(rows, "sys", "soc_temp_mC") if v > 0]
  nic = [v / 1000 for v in series(rows, "sys", "i350_die_mC") if v > 0]
  print(f"link flaps : {flaps}")
  if flaps < 0:
    # The count comes from the kernel ring buffer, which wraps. Over
    # four days it can wrap, and a wrapped count reads as a NEGATIVE
    # delta. Failing on that would be failing on the instrument.
    notes.append(f"the dmesg ring wrapped during the run "
                 f"(link-up delta {flaps}); link stability cannot be "
                 f"judged from it for this window")
    flaps = 0
  if soc:
    print(f"SoC temp   : {min(soc):.1f} - {max(soc):.1f} C")
  if nic:
    print(f"i350 die   : {min(nic):.1f} - {max(nic):.1f} C")
  if flaps:
    fails.append(f"{flaps} data-port link-up event(s) during the run")
  if soc and max(soc) >= SOC_WARN_C:
    fails.append(f"SoC peaked at {max(soc):.1f} C")
  if nic and max(nic) >= NIC_WARN_C:
    fails.append(f"i350 die peaked at {max(nic):.1f} C")

  print()
  print("Rate limiting and sampled logging are COUNTER-witnessed here, "
        "as in the")
  print("2026-08-08 soak: there is no delivery claim in \"the limiter "
        "dropped the")
  print("excess\", so no socket can witness it. Every DELIVERY claim "
        "above rests on")
  print("a real non-promiscuous socket and the far side's own kernel "
        "naming the peer.")
  print()
  for note in notes[:12]:
    print(f"NOTE: {note}")
  if fails:
    print(f"VERDICT: FAIL — {len(fails)} problem(s)")
    for problem in fails:
      print(f"  - {problem}")
    return 1
  print("VERDICT: PASS — every sample's delivery claim was checked "
        "against a real socket on the far side, and nothing drifted")
  return 0


if __name__ == "__main__":
  sys.exit(main())
