#!/usr/bin/env bash
# One NAT-soak sample: health metrics AND a live wire assertion.
#
# The 48 h soak of 2026-08-08 sampled counters, RSS and temperature.
# Every one of those would have looked identical with the NAT rewrite
# switched off, so this one also runs natsoak_probe.py each time: it
# sends a known burst and reads the frames back off the receiving port.
# A sample therefore records what the firewall DID, not only that it
# was running.
set -u
OUT=/var/log/f/natsoak.jsonl
PIN=/sys/fs/bpf/f
export PYTHONPATH=/opt/fwl:/opt/fwl-deps
HERE="$(cd "$(dirname "$0")" && pwd)"

counters=$(bpftool map dump pinned "$PIN"/fwl_counters_lan \
  2>/dev/null | python3 -c "
import json, sys
try:
  entries = json.load(sys.stdin)
except Exception:
  print('{}'); raise SystemExit
print(json.dumps({str(e['key']):
  sum(v['value'] for v in e['values']) for e in entries}))
")

# Both flow tables. conntrack is reported by fctl; fwl_nat is not
# reported anywhere, so it has to be counted out of bpffs by hand —
# which is also the point: an operator has no way to watch the table
# that has no garbage collector behind it.
map_entries() {
  if [ ! -e "$PIN/$1" ]; then echo -1; return; fi
  bpftool -j map dump pinned "$PIN/$1" 2>/dev/null \
    | python3 -c "import json,sys; print(len(json.load(sys.stdin)))" \
    2>/dev/null || echo -1
}

nat_entries=$(map_entries fwl_nat)
ct=$(fctl status 2>/dev/null | python3 -c "
import json, sys
try:
  print(json.load(sys.stdin)['conntrack']['entries'])
except Exception:
  print(-1)
")
fd_rss=$(awk '/VmRSS/{print $2}' /proc/"$(pidof fd)"/status \
  2>/dev/null || echo 0)
fd_cpu=$(awk '{print int(($14 + $15) * 1000 / '"$(getconf CLK_TCK)"')}' \
  /proc/"$(pidof fd)"/stat 2>/dev/null || echo 0)
temp=$(cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null || echo 0)
nic=$(cat /sys/class/hwmon/hwmon8/temp1_input 2>/dev/null || echo 0)
errs=$(journalctl -u fd --since "-5min" -p err --no-pager -q | wc -l)
flaps=$(dmesg | grep -c "enp1s0f[012].*Link is Up" || true)
rx=$(ethtool -S enp1s0f1 | awk '/^ *rx_packets:/{print $2}')

# The wire assertion. A rotating source port each sample, so the
# "fresh flow" half is genuinely fresh and the growth of fwl_nat is
# driven by something whose rate we know.
port=$((45000 + ($(date +%s) / 60) % 15000))
probe=$(timeout 20 python3 "$HERE/natsoak_probe.py" \
  enp1s0f0 enp1s0f1 "$port" 2>/dev/null)
[ -n "$probe" ] || probe='{"error":"probe failed"}'

printf '{"ts":"%s","counters":%s,"nat_entries":%s,"conntrack":%s,"fd_rss_kb":%s,"fd_cpu_ms":%s,"soc_temp_mC":%s,"i350_die_mC":%s,"fd_err_5min":%s,"linkup_total":%s,"rx_packets":%s,"fd_active":"%s","probe":%s}\n' \
  "$(date -u +%FT%TZ)" "$counters" "$nat_entries" "$ct" "$fd_rss" \
  "$fd_cpu" "$temp" "$nic" "$errs" "$flaps" "$rx" \
  "$(systemctl is-active fd)" "$probe" >> "$OUT"
