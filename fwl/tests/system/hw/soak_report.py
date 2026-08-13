"""Post-soak analysis: turn soak.jsonl into a verdict.

Reads the sample log a soak run produced and checks every property
the soak exists to test — counter monotonicity, memory drift,
conntrack stability, daemon health, thermals, and sampling
continuity — then prints a report and exits non-zero if any check
fails. This is the Layer-5 evidence artifact; `soak_status.sh` is
the live glance, this is the verdict.

Usage: soak_report.py <soak.jsonl>
"""
import json
import sys
from datetime import datetime

# A sampler tick is 5 min; flag gaps beyond this (missed timer runs,
# reboots, or a stalled sampler).
MAX_GAP_S = 900
# The i350 die's critical threshold is 110 C; alert well below.
NIC_WARN_C = 90
SOC_WARN_C = 85


def load(path):
  rows = []
  for line in open(path):
    line = line.strip()
    if line:
      rows.append(json.loads(line))
  return rows


def ts(row):
  return datetime.strptime(row["ts"], "%Y-%m-%dT%H:%M:%SZ")


def check_monotonic_counters(rows, problems):
  """Every FWL counter slot must never decrease."""
  slots = sorted({k for r in rows for k in r["counters"]}, key=int)
  regressions = []
  for slot in slots:
    prev = None
    for r in rows:
      cur = r["counters"].get(slot)
      if cur is None:
        continue
      if prev is not None and cur < prev:
        regressions.append((slot, r["ts"], prev, cur))
      prev = cur
  if regressions:
    for slot, when, before, after in regressions[:5]:
      problems.append(
        f"counter slot {slot} went backwards at {when}: "
        f"{before} -> {after}"
      )
  return slots, regressions


def main() -> int:
  rows = load(sys.argv[1])
  if len(rows) < 2:
    print("not enough samples")
    return 2
  problems = []

  first, last = rows[0], rows[-1]
  duration = (ts(last) - ts(first)).total_seconds()

  # --- sampling continuity -----------------------------------------
  gaps = []
  for a, b in zip(rows, rows[1:]):
    gap = (ts(b) - ts(a)).total_seconds()
    if gap > MAX_GAP_S:
      gaps.append((a["ts"], b["ts"], gap))
  for when, then, gap in gaps[:5]:
    problems.append(
      f"sampling gap {gap / 60:.0f} min between {when} and {then}"
    )

  # --- counters -----------------------------------------------------
  slots, regressions = check_monotonic_counters(rows, problems)
  total_first = sum(first["counters"].values())
  total_last = sum(last["counters"].values())

  # --- memory -------------------------------------------------------
  rss = [r["fd_rss_kb"] for r in rows]
  rss_growth = rss[-1] - rss[0]
  if rss[-1] > rss[0] * 1.5:
    problems.append(
      f"fd RSS grew {rss[0]} -> {rss[-1]} kB (>50%): possible leak"
    )

  # --- conntrack ----------------------------------------------------
  # Only samples where traffic has actually been counted can carry an
  # established flow: soak_start.sh takes a baseline sample before the
  # generator's first frame, and that one legitimately reads 0.
  ct = [r["conntrack"] for r in rows
        if r["conntrack"] >= 0 and sum(r["counters"].values()) > 0]
  if ct and min(ct) == 0:
    problems.append(
      "conntrack dropped to 0 entries under traffic: the "
      "established flow broke"
    )

  # --- daemon health ------------------------------------------------
  inactive = [r["ts"] for r in rows if r["fd_active"] != "active"]
  if inactive:
    problems.append(
      f"fd not active in {len(inactive)} sample(s), first "
      f"{inactive[0]}"
    )
  err_total = sum(r["fd_err_5min"] for r in rows)
  if err_total:
    problems.append(f"{err_total} fd journal error line(s) logged")

  # --- link stability -----------------------------------------------
  flaps = last["linkup_total"] - first["linkup_total"]
  if flaps:
    problems.append(f"{flaps} data-port link-up event(s) during run")

  # --- thermals -----------------------------------------------------
  soc = [r["soc_temp_mC"] / 1000 for r in rows if r["soc_temp_mC"]]
  nic = [r.get("i350_die_mC", 0) / 1000 for r in rows
         if r.get("i350_die_mC")]
  if soc and max(soc) >= SOC_WARN_C:
    problems.append(f"SoC peaked at {max(soc):.1f} C")
  if nic and max(nic) >= NIC_WARN_C:
    problems.append(f"i350 die peaked at {max(nic):.1f} C")

  # --- report -------------------------------------------------------
  print("=" * 62)
  print("SOAK REPORT")
  print("=" * 62)
  print(f"window      : {first['ts']} -> {last['ts']}")
  print(f"duration    : {duration / 3600:.1f} h, {len(rows)} samples")
  print(f"sampling    : {len(gaps)} gap(s) > {MAX_GAP_S // 60} min")
  print()
  print(f"frames      : {total_last - total_first:,} counted "
        f"({(total_last - total_first) / duration:,.0f}/s avg)")
  print(f"rx_packets  : "
        f"{last['rx_packets'] - first['rx_packets']:,} on the DUT port")
  print(f"counters    : {len(slots)} slots, "
        f"{len(regressions)} regression(s)")
  for slot in slots:
    delta = last['counters'].get(slot, 0) - first['counters'].get(slot, 0)
    print(f"   slot {slot}: +{delta:,}")
  print()
  print(f"fd RSS      : {rss[0]} -> {rss[-1]} kB "
        f"(delta {rss_growth:+d}, peak {max(rss)})")
  print(f"fd active   : {len(rows) - len(inactive)}/{len(rows)} samples")
  print(f"fd errors   : {err_total}")
  if ct:
    print(f"conntrack   : min {min(ct)}, max {max(ct)} entries")
  print(f"link flaps  : {flaps}")
  if soc:
    print(f"SoC temp    : {min(soc):.1f} - {max(soc):.1f} C "
          f"(mean {sum(soc) / len(soc):.1f})")
  if nic:
    print(f"i350 die    : {min(nic):.1f} - {max(nic):.1f} C "
          f"(mean {sum(nic) / len(nic):.1f})")
  print()
  if problems:
    print(f"VERDICT: FAIL — {len(problems)} problem(s)")
    for p in problems:
      print(f"  - {p}")
    return 1
  print("VERDICT: PASS — no drift, no leak, no daemon incident")
  return 0


if __name__ == "__main__":
  sys.exit(main())
