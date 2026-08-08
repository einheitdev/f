#!/usr/bin/env bash
# One soak sample: append a JSON line of health metrics to the log.
# Driven every 5 min by the soak_start.sh transient timer.
set -u
OUT=/var/log/f/soak.jsonl
PIN=/sys/fs/bpf/f

counters=$(bpftool map dump pinned "$PIN"/fwl_counters_wan \
  2>/dev/null | python3 -c "
import json, sys
try:
  entries = json.load(sys.stdin)
except Exception:
  print('{}'); raise SystemExit
print(json.dumps({str(e['key']):
  sum(v['value'] for v in e['values']) for e in entries}))
")
fd_rss=$(awk '/VmRSS/{print $2}' /proc/$(pidof fd)/status \
  2>/dev/null || echo 0)
ct=$(fctl status 2>/dev/null | python3 -c "
import json, sys
try:
  print(json.load(sys.stdin)['conntrack']['entries'])
except Exception:
  print(-1)
")
temp=$(cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null || echo 0)
errs=$(journalctl -u fd --since "-5min" -p err --no-pager -q \
  | wc -l)
flaps=$(dmesg | grep -c "enp1s0f[012].*Link is Up" || true)
rx=$(ethtool -S enp1s0f1 | awk '/^ *rx_packets:/{print $2}')

printf '{"ts":"%s","counters":%s,"fd_rss_kb":%s,"conntrack":%s,"soc_temp_mC":%s,"fd_err_5min":%s,"linkup_total":%s,"rx_packets":%s,"fd_active":"%s"}\n' \
  "$(date -u +%FT%TZ)" "$counters" "$fd_rss" "$ct" "$temp" \
  "$errs" "$flaps" "$rx" "$(systemctl is-active fd)" >> "$OUT"
