#!/usr/bin/env bash
# NAT soak health at a glance.
set -u
OUT=/var/log/f/natsoak.jsonl
[ -s "$OUT" ] || { echo "no samples yet ($OUT empty)"; exit 1; }
systemctl is-active f-natsoak-traffic >/dev/null \
  && echo "traffic: running" || echo "traffic: NOT RUNNING"
exec python3 "$(dirname "$0")/natsoak_report.py" "$OUT"
