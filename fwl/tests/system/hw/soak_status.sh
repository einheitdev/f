#!/usr/bin/env bash
# Soak health at a glance: latest sample + drift vs the first sample.
set -u
OUT=/var/log/f/soak.jsonl
[ -s "$OUT" ] || { echo "no samples yet ($OUT empty)"; exit 1; }
systemctl is-active f-soak-traffic >/dev/null \
  && echo "traffic: running" || echo "traffic: NOT RUNNING"
echo "samples: $(wc -l < "$OUT")"
python3 - "$OUT" <<'EOF'
import json
import sys

lines = [json.loads(x) for x in open(sys.argv[1])]
first, last = lines[0], lines[-1]
print(f"first:  {first['ts']}")
print(f"last:   {last['ts']}  fd={last['fd_active']}")
print(f"fd RSS: {first['fd_rss_kb']} -> {last['fd_rss_kb']} kB")
print(f"SoC:    {last['soc_temp_mC'] / 1000:.1f} C")
print(f"conntrack entries: {last['conntrack']}")
print(f"fd errors (last 5 min): {last['fd_err_5min']}")
print(f"rx_packets: {last['rx_packets']}")
print("counters (slot: value):", last["counters"])
# Drift checks.
bad = []
if int(last["fd_rss_kb"]) > int(first["fd_rss_kb"]) * 2:
  bad.append("fd RSS more than doubled (leak?)")
for k, v in first["counters"].items():
  if last["counters"].get(k, 0) < v:
    bad.append(f"counter slot {k} went BACKWARDS")
if last["fd_active"] != "active":
  bad.append("fd is not active")
print("DRIFT: " + ("; ".join(bad) if bad else "none detected"))
EOF
