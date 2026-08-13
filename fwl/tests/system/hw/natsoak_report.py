"""Verdict on a NAT-soak log.

Reads /var/log/f/natsoak.jsonl and answers the questions a soak is run
to answer, refusing to answer any of them from an empty or truncated
record. Exit 0 = pass, 1 = fail, 2 = the log cannot support a verdict.

The checks that matter here are the wire ones. Counters climbing and
RSS staying flat say the daemon lived; they say nothing about whether
it was still translating. Every sample carries the result of a real
burst, so the pass condition is that every sample's egress translated,
every sample's long-lived mapping resolved, and no sample leaked an
un-translated source address.

Usage: natsoak_report.py [<log>]
"""
import json
import sys


def load(path: str) -> list[dict]:
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


def main() -> int:
  path = sys.argv[1] if len(sys.argv) > 1 \
      else "/var/log/f/natsoak.jsonl"
  rows = load(path)
  if len(rows) < 3:
    print(f"only {len(rows)} samples: not enough for a verdict")
    return 2
  bad = [r for r in rows if "_malformed" in r]
  if bad:
    print(f"{len(bad)} malformed sample lines")
    return 2

  first, last = rows[0], rows[-1]
  print(f"samples:   {len(rows)}")
  print(f"window:    {first['ts']} -> {last['ts']}")

  # Sampling gaps: a missing minute means the sampler, not the
  # firewall, decided what got measured.
  import datetime
  ts = [datetime.datetime.strptime(r["ts"], "%Y-%m-%dT%H:%M:%SZ")
        for r in rows]
  gaps = [(ts[i] - ts[i - 1]).total_seconds()
          for i in range(1, len(ts))]
  worst_gap = max(gaps) if gaps else 0
  hours = (ts[-1] - ts[0]).total_seconds() / 3600.0
  print(f"duration:  {hours:.2f} h, worst sampling gap "
        f"{worst_gap:.0f}s")

  fails: list[str] = []
  notes: list[str] = []

  # --- the wire assertions ------------------------------------------
  burst = rows[0].get("probe", {}).get("burst", 10)
  eg_bad = [r["ts"] for r in rows
            if r.get("probe", {}).get("egress_ok", 0) < burst]
  leak = [r["ts"] for r in rows
          if r.get("probe", {}).get("egress_leak", 0) > 0]
  stable_bad = [r["ts"] for r in rows
                if r.get("probe", {}).get("stable_denat", 0) < burst]
  fresh_bad = [r["ts"] for r in rows
               if r.get("probe", {}).get("fresh_denat", 0) < burst]
  csum = [r["ts"] for r in rows
          if r.get("probe", {}).get("badcsum", 0) > 0]
  print(f"wire: egress translated in "
        f"{len(rows) - len(eg_bad)}/{len(rows)} samples; "
        f"long-lived mapping resolved in "
        f"{len(rows) - len(stable_bad)}/{len(rows)}; "
        f"fresh mapping resolved in "
        f"{len(rows) - len(fresh_bad)}/{len(rows)}")
  if eg_bad:
    fails.append(f"egress not fully translated in {len(eg_bad)} "
                 f"samples (first {eg_bad[0]})")
  if leak:
    fails.append(f"UN-TRANSLATED SOURCE ADDRESS on the wire in "
                 f"{len(leak)} samples (first {leak[0]})")
  if stable_bad:
    fails.append(f"the long-lived NAT mapping stopped resolving in "
                 f"{len(stable_bad)} samples (first {stable_bad[0]})")
  if fresh_bad:
    fails.append(f"a fresh NAT mapping failed to resolve in "
                 f"{len(fresh_bad)} samples (first {fresh_bad[0]})")
  if csum:
    fails.append(f"bad checksum on a NATed frame in {len(csum)} "
                 f"samples (first {csum[0]})")

  # --- the tables ---------------------------------------------------
  nat0, nat1 = first["nat_entries"], last["nat_entries"]
  print(f"fwl_nat:   {nat0} -> {nat1} entries "
        f"(cap 65536, no aging path)")
  if hours > 0.05 and nat1 > nat0:
    rate = (nat1 - nat0) / hours
    left = (65536 - nat1) / rate if rate > 0 else float("inf")
    notes.append(f"fwl_nat grew at {rate:.0f} entries/h; at that rate "
                 f"the table fills in {left:.1f} h from here. It has "
                 f"no garbage collector, so this slope never reverses "
                 f"— see l11_02_nat_table_ceiling.sh")
  ct = [r["conntrack"] for r in rows]
  print(f"conntrack: {ct[0]} -> {ct[-1]} (peak {max(ct)})")

  # --- liveness / leak ----------------------------------------------
  rss = [int(r["fd_rss_kb"]) for r in rows]
  print(f"fd RSS:    {rss[0]} -> {rss[-1]} kB (peak {max(rss)})")
  if rss[-1] > rss[0] * 2:
    fails.append("fd RSS more than doubled (leak?)")
  inactive = [r["ts"] for r in rows if r["fd_active"] != "active"]
  if inactive:
    fails.append(f"fd not active in {len(inactive)} samples")
  errs = sum(int(r["fd_err_5min"]) for r in rows)
  if errs:
    fails.append(f"{errs} journal error lines across the run")

  # Counter monotonicity: a slot going backwards is either a restart
  # or a rebuilt map, and either invalidates the rest.
  for slot in first["counters"]:
    seq = [int(r["counters"].get(slot, 0)) for r in rows]
    for i in range(1, len(seq)):
      if seq[i] < seq[i - 1]:
        fails.append(f"counter slot {slot} went backwards at "
                     f"{rows[i]['ts']}")
        break
  print(f"counters:  {first['counters']} -> {last['counters']}")

  flaps = int(last["linkup_total"]) - int(first["linkup_total"])
  nic = max(int(r["i350_die_mC"]) for r in rows)
  print(f"link flaps: {flaps}; i350 die peak {nic / 1000:.0f} C")
  if flaps:
    notes.append(f"{flaps} link up events during the run")

  print()
  for n in notes:
    print(f"NOTE: {n}")
  if fails:
    for f in fails:
      print(f"FAIL: {f}")
    return 1
  print("VERDICT: PASS — every sample's NAT claim was checked against "
        "the frames on the wire")
  return 0


if __name__ == "__main__":
  sys.exit(main())
