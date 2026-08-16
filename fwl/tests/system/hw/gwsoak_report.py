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

Epochs — a run whose policy changed
-----------------------------------
`gwsoak.py append` changes the policy of a RUNNING soak by a
deliberate hot reload, and every counter in this log comes out of a
MapLifetime.POLICY map: slot i belongs to the compilation that
allocated it, so a reload zeroes all of them by design. Read as one
series, that is nineteen counters going backwards in the same second.

So the report SEGMENTS the run on the `epoch` each sample carries and
judges every accumulating quantity within its own epoch: counters,
the routed tally, the reclaim/evict totals, the egress tracker. Each
epoch's deltas are printed separately and labelled with what changed.
A sample with no `epoch` field is epoch 1 — the field was added by the
first append and its absence is the marker.

Three things this deliberately does NOT excuse. Anything that is one
fact about one long-lived process — fd's RSS, its restart count, the
boot id, link flaps, thermals — is judged across the WHOLE run, so a
policy change can never be used to hide a daemon that died. The
occupancy of `fwl_nat` and `conntrack` is likewise judged whole: those
two are MapLifetime.FLOW and a reload does not touch them, so a step
in the curve at the boundary would be a real one. And an UNDECLARED
reload — a policy changed without the epoch moving — still reads as
every counter going backwards at once, and still fails.

Usage: gwsoak_report.py [<log>]
"""
import json
import os
import statistics
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gwsoak import EPOCHS, FIRST_EPOCH, LOG, STATE, verify_probe  # noqa: E402,E501

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


def epoch_of(row: dict) -> int:
  """Which policy this sample was taken under.

  A row with no `epoch` field predates the first append, and that is
  the marker rather than a default worth arguing about: the field is
  written by every sampler that can produce more than one epoch.
  """
  value = row.get("epoch", FIRST_EPOCH)
  return value if isinstance(value, int) else FIRST_EPOCH


def segment(rows: list) -> list:
  """[(epoch, rows)] in order, one entry per contiguous run."""
  out: list = []
  for row in rows:
    epoch = epoch_of(row)
    if not out or out[-1][0] != epoch:
      out.append((epoch, []))
    out[-1][1].append(row)
  return out


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
  bad_samples = [(r["ts"], verify_probe(r.get("probe", {}),
                                        epoch_of(r)))
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

  # --- the policy epochs ---------------------------------------------
  #
  # Printed BEFORE the counters, because from here down every
  # accumulating number is a per-epoch number and a reader has to know
  # where the boundary is before they read one.
  blocks = segment(rows)
  order = [e for e, _ in blocks]
  if len(set(order)) != len(order) or order != sorted(order):
    print(f"the epoch went backwards or repeated ({order}); the log "
          f"cannot support a verdict")
    return 2
  recorded = {e["epoch"]: e for e in state.get("epochs", [])
              if isinstance(e, dict) and "epoch" in e}
  print(f"policy     : {len(blocks)} epoch(s), "
        f"{'unchanged across the run' if len(blocks) == 1 else 'CHANGED MID-RUN'}")  # noqa: E501
  for epoch, block in blocks:
    known = recorded.get(epoch, {})
    what = known.get("what") or EPOCHS.get(epoch, {}).get(
      "what", "(nothing recorded about this epoch)")
    print(f"   epoch {epoch}: {block[0]['ts']} -> {block[-1]['ts']}, "
          f"{len(block)} sample(s)")
    print(f"      {what}")
    sha = known.get("policy_sha") or block[-1].get("policy_sha", "")
    if sha:
      print(f"      policy sha256 {sha[:16]}")
  if len(blocks) > 1:
    print("   counters, the routed tally, the reclaim/evict totals "
          "and the egress tracker are")
    print("   judged INSIDE each epoch — they come out of "
          "MapLifetime.POLICY maps and a reload")
    print("   zeroes them by design. fd, the boot id, link flaps, "
          "thermals and the two")
    print("   MapLifetime.FLOW tables are judged across the whole "
          "run and are not excused.")

  # --- counters, by name, within each epoch ---------------------------
  names = sorted({k for r in rows for k in r.get("counters", {})})
  if not names:
    print("counters   : none declared — the log cannot support a "
          "verdict")
    return 2
  for epoch, block in blocks:
    declared = sorted({k for r in block for k in r.get("counters", {})})
    label = "" if len(blocks) == 1 else f" (epoch {epoch})"
    print(f"counters   : {len(declared)} declared, read back by "
          f"name{label}")
    for name in declared:
      seq = series(block, "counters", name)
      if -1 in seq:
        fails.append(f"epoch {epoch}: counter {name} was ABSENT from "
                     f"the running bundle in {seq.count(-1)} of "
                     f"{len(seq)} sample(s) — a renamed or dropped "
                     f"counter reads -1, never 0")
        continue
      back = [block[i]["ts"] for i in range(1, len(seq))
              if seq[i] < seq[i - 1]]
      if back:
        fails.append(f"epoch {epoch}: counter {name} went backwards "
                     f"at {back[0]} ({len(back)} time(s))")
      print(f"   {name:<24} +{seq[-1] - seq[0]:,}")
    spec = EPOCHS.get(epoch, {})
    for name in spec.get("must_move", ()):
      if name not in declared:
        fails.append(f"epoch {epoch}: counter {name} is not declared "
                     f"by the running bundle at all — this epoch is "
                     f"defined by having it")
        continue
      seq = series(block, "counters", name)
      if len(seq) > 1 and seq[-1] <= seq[0]:
        fails.append(f"epoch {epoch}: counter {name} did not move "
                     f"across the epoch")
    # The Tier 2 zones' arithmetic. Every frame a Tier 2 `def` sees is
    # counted once in the zone total and once in exactly one leaf, so
    # the sum IS the total — at every instant, at any rate. A guard
    # that stopped gating puts a frame in two leaves, a helper whose
    # `drop` stopped returning the caller's verdict puts a dropped
    # frame in a leaf as well, and a collapsed branch puts it in none.
    for total_name, leaves in spec.get("identities", ()):
      broken = []
      for row in block:
        counters = row.get("counters", {})
        if total_name not in counters or any(x not in counters
                                             for x in leaves):
          continue
        total = counters[total_name]
        summed = sum(counters[x] for x in leaves)
        if total != summed:
          broken.append((row["ts"], total, summed))
      if broken:
        ts, total, summed = broken[0]
        fails.append(
          f"epoch {epoch}: the Tier 2 identity {total_name} == "
          f"{' + '.join(leaves)} failed in {len(broken)} sample(s), "
          f"first {ts}: {total_name}={total:,} but the leaves sum to "
          f"{summed:,} (difference {total - summed:,}). Every frame "
          f"the zone's def sees lands in exactly one leaf, so this "
          f"is the Tier 2 conjunction, not the traffic")
      elif spec.get("identities"):
        notes.append(f"epoch {epoch}: {total_name} == the sum of its "
                     f"{len(leaves)} leaves in all {len(block)} "
                     f"sample(s)")

  # --- the tables ----------------------------------------------------
  # `fwl_nat` and `conntrack` are MapLifetime.FLOW: a reload does not
  # touch them, so the occupancy curve is ONE continuous measurement
  # across every epoch and is read as one. The reclaim and evict
  # totals beside them are not — they live in `fwl_nat_stats`, which
  # is MapLifetime.POLICY — so those are summed per epoch.
  nat = series(rows, "nat", "entries")
  ct = series(rows, "conntrack", "entries")
  reclaimed = sum(max(0, series(b, "nat", "total_reclaimed")[-1]
                      - series(b, "nat", "total_reclaimed")[0])
                  for _, b in blocks)
  evicted = sum(max(0, series(b, "conntrack", "total_evicted")[-1]
                    - series(b, "conntrack", "total_evicted")[0])
                for _, b in blocks)
  print(f"fwl_nat    : {nat[0]} -> {nat[-1]}, peak {max(nat)} "
        f"({100.0 * max(nat) / NAT_CAP:.1f} % of {NAT_CAP}), "
        f"{reclaimed:,} reclaimed")
  print(f"conntrack  : {ct[0]} -> {ct[-1]}, peak {max(ct)} "
        f"({100.0 * max(ct) / CT_CAP:.1f} % of {CT_CAP}), "
        f"{evicted:,} evicted")
  # Vacuity guard: "flat" has to mean flows expiring as fast as they
  # arrive, not the datapath having stopped. It only means anything if
  # the table grew in the first place and the collector actually ran.
  if max(nat) > 0 and reclaimed <= 0 and hours > 1:
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
    for epoch, block in blocks:
      seq = series(block, "nat", field)
      if seq[-1] > seq[0]:
        fails.append(f"epoch {epoch}: nat.{field} moved {seq[0]} -> "
                     f"{seq[-1]}: the table hit its cap under this "
                     f"workload")
  if min(ct[1:] or ct) == 0:
    fails.append("conntrack dropped to 0 entries under traffic")

  # --- routing and the next hop --------------------------------------
  # `fwl_route_stats` is MapLifetime.POLICY, so each epoch counts from
  # zero. Read whole, the tally at the boundary would look like the
  # box un-forwarding five million frames.
  no_neigh = series(rows, "route", "no_neigh")
  routed_total = sum(max(0, series(b, "route", "routed")[-1]
                         - series(b, "route", "routed")[0])
                     for _, b in blocks)
  fell_back = sum(max(0, series(b, "route", "bridged")[-1]
                      - series(b, "route", "bridged")[0])
                  for _, b in blocks)
  print(f"route      : routed +{routed_total:,}, bridged "
        f"+{fell_back:,}, no_neigh {no_neigh[0]} -> {no_neigh[-1]}")
  for epoch, block in blocks:
    seq = series(block, "route", "routed")
    if len(seq) > 1 and seq[-1] <= seq[0]:
      fails.append(f"epoch {epoch}: route.routed did not move — "
                   f"nothing was forwarded through the FIB")
  if routed_total <= 0:
    fails.append("route.routed did not move: nothing was forwarded "
                 "through the FIB across the whole run")
  # The question a long run can answer and a short one cannot: does the
  # box RE-LOSE a next hop it has already resolved? Early samples may
  # legitimately count one lost first frame per destination.
  # The box is warm within minutes — `start` pings every next hop it
  # routes to before the first sample. A tenth of a 96 h run is nine
  # hours, and a next hop re-lost at hour five would be absorbed into
  # the baseline, so the warm-up window is capped at ten samples.
  #
  # Per epoch, because a reload zeroes this tally too: an epoch's own
  # first frame to each next hop is legitimately lost again, and
  # comparing the second epoch's warm reading against the first
  # epoch's would fail on the reset rather than on the box.
  for epoch, block in blocks:
    seq = series(block, "route", "no_neigh")
    warm = min(10, max(1, len(block) // 10))
    if warm >= len(seq):
      continue
    if seq[-1] > seq[warm]:
      fails.append(f"epoch {epoch}: route.no_neigh climbed after the "
                   f"box was warm: {seq[warm]} at sample {warm} -> "
                   f"{seq[-1]} at the end. The box re-lost a next hop "
                   f"it had already resolved")
    else:
      notes.append(f"epoch {epoch}: no_neigh flat at {seq[-1]} from "
                   f"sample {warm} onward — the first frame to each "
                   f"next hop is lost, counted, and never repeated")
  # `bridged` is the one number that says a forward the policy meant to
  # ROUTE silently became an L2-adjacent hand-off — same frame, same
  # cable, different network. A handful is a switch artefact; a share
  # of the routed traffic is the routed path not being taken.
  crossed = max(1, routed_total)
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
  attached = series(rows, "egress", "attached")
  xdp = series(rows, "xdp_ifaces")
  tracked_total = sum(max(0, series(b, "egress", "tracked")[-1]
                          - series(b, "egress", "tracked")[0])
                      for _, b in blocks)
  print(f"egress     : tracked +{tracked_total:,}, attached "
        f"on {attached[-1]} of {xdp[-1]} datapath interface(s)")
  if any(a != x for a, x in zip(attached, xdp)):
    fails.append("the egress tracker was not on every interface the "
                 "datapath is on")
  # Every sample opens exactly one box-originated flow, so `tracked`
  # should move every minute. A STALL is the failure — the tracker
  # stopped counting — and a stall looks like a RUN. One isolated
  # non-increase is an ephemeral port reused inside the conntrack idle
  # timeout, which is a refresh and not a new flow; failing a 96 h run
  # on that would make the check about luck. Per epoch, because
  # `fwl_egress_stats` is MapLifetime.POLICY and the boundary sample
  # is a reset rather than a stall.
  for epoch, block in blocks:
    tracked = series(block, "egress", "tracked")
    run = worst_run = 0
    first_stall = ""
    for i in range(1, len(tracked)):
      if tracked[i] <= tracked[i - 1]:
        run += 1
        if run > worst_run:
          worst_run, first_stall = run, block[i]["ts"]
      else:
        run = 0
    if worst_run >= 3:
      fails.append(f"epoch {epoch}: the egress tracker recorded no "
                   f"NEW box-originated flow across {worst_run} "
                   f"consecutive samples ending {first_stall} — "
                   f"every sample opens one")
    elif worst_run:
      notes.append(f"epoch {epoch}: {worst_run} isolated sample(s) "
                   f"with no new tracked flow (an ephemeral port "
                   f"reused inside the idle timeout is a refresh, "
                   f"not a new flow)")
    refused = series(block, "egress", "refused")
    if refused[-1] > refused[0]:
      fails.append(f"epoch {epoch}: egress.refused moved {refused[0]} "
                   f"-> {refused[-1]}: conntrack at its cap, which is "
                   f"the original DNS failure restored by a mechanism "
                   f"working as designed")

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
  wanted = ("w_pre_denat", "w_to_a", "w_to_b", "w_total")

  def summed(name: str) -> int:
    """A counter's movement across every epoch that declared it."""
    return sum(max(0, series(b, "counters", name)[-1]
                   - series(b, "counters", name)[0])
               for _, b in blocks
               if name in b[0].get("counters", {}))

  if set(wanted) <= set(names):
    pre = summed("w_pre_denat")
    inside = summed("w_to_a") + summed("w_to_b")
    total = summed("w_total")
    notes.append(
      f"the uplink body saw the PRE-de-NAT destination on "
      f"{pre:,} of {total:,} frames and an inside address on "
      f"{inside:,} — the prelude caches dst_ip before "
      f"`fwl_nat_denat` rewrites it, so a return-path `redirect` to "
      f"an inside zone is unreachable behind masquerade. Replies come "
      f"home through `allow` and the Linux stack, which is what "
      f"deploy/firstboot generates")

  # --- the daemon ----------------------------------------------------
  #
  # Judged across the WHOLE run and never per epoch. A hot reload does
  # not restart fd — that is the point of it — so a restart, a boot,
  # an error line or RSS running away is one fact about one process,
  # and segmenting the run on the policy must not become a way to
  # excuse any of them. `append` uses fd's own watcher for exactly
  # this reason: `deploy` would stop and start fd, and this check
  # would fail it, correctly.
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
  if len(blocks) > 1:
    print()
    print("Tier 2 rate limiting is NOT witnessed here and cannot be: "
          "a Tier 2")
    print("`rate_limit(...)` emits a compile-time constant false "
          "(l7_01_tier2_rate_limit_gap),")
    print("so the epoch-2 zones carry no limiter and the flood stays "
          "on the Tier 1 zones,")
    print("where it is measured exactly as it was before the "
          "boundary.")
  print()
  for note in notes[:20]:
    print(f"NOTE: {note}")
  if fails:
    print(f"VERDICT: FAIL — {len(fails)} problem(s)")
    for problem in fails:
      print(f"  - {problem}")
    return 1
  if len(blocks) > 1:
    print(f"VERDICT: PASS — every sample's delivery claim was checked "
          f"against a real socket on the far side, in each of the "
          f"{len(blocks)} policy epochs on its own epoch's bar, and "
          f"nothing drifted")
    return 0
  print("VERDICT: PASS — every sample's delivery claim was checked "
        "against a real socket on the far side, and nothing drifted")
  return 0


if __name__ == "__main__":
  sys.exit(main())
