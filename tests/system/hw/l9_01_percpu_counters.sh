#!/usr/bin/env bash
# Per-CPU counter exactness under multi-queue RSS.
#
# fwl_counters is a PERCPU_ARRAY: each CPU increments its own slot
# and readers sum across CPUs. If traffic spreads across RX queues
# (different source IPs hash to different queues), a summing bug or a
# missed CPU shows up as a count that is short — and would be
# invisible to any single-flow test, because one flow pins one queue.
#
# Sends a large volume across many source IPs and asserts the sum is
# EXACT, then reports how many CPUs actually participated.
source "$(dirname "$0")/hwlib.sh"
hw::require_root
trap hw::finish EXIT

FW=$(mktemp --suffix=.fw)
cat > "$FW" <<EOF
zone t = [$RECV_IF]

@xdp(t)

count total if pkt.src_ip in 10.99.180.0/24
default allow
EOF
hw::deploy l9-01 "$FW"

SOURCES=32
PER_SRC=100
EXPECTED=$((SOURCES * PER_SRC))

BEFORE=$(hw::counter total)
$PY - "$SEND_IF" "$SOURCES" "$PER_SRC" <<'EOF'
import socket
import sys
sys.path.insert(0, "/opt/fwl/tests/system/hw")
from fwl import pkt
iface, sources, per_src = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind((iface, 0))
frames = [
  pkt.build_packet(pkt.parse_builder(
    f'udp(src_ip="10.99.180.{i + 1}", dst_port=5400)'
  )).raw
  for i in range(sources)
]
for _ in range(per_src):
  for f in frames:
    s.send(f)
s.close()
print(f"sent {sources * per_src} frames from {sources} sources")
EOF
sleep 2
AFTER=$(hw::counter total)
DELTA=$((AFTER - BEFORE))

# How many CPUs hold a non-zero value for this slot?
CPUS=$(bpftool map dump pinned "$PIN/fwl_counters_t" 2>/dev/null | $PY -c "
import json, sys
try:
  entries = json.load(sys.stdin)
except Exception:
  print(0); raise SystemExit
for e in entries:
  if e['key'] == 0:
    print(sum(1 for v in e['values'] if v['value'] > 0))
    break
else:
  print(0)
")

log "counter delta $DELTA (expected $EXPECTED), non-zero CPUs: $CPUS"
assert_eq "per-CPU counter sum is exact across $SOURCES sources" \
  "$DELTA" "$EXPECTED"
if [ "$CPUS" -gt 1 ]; then
  record "traffic genuinely spread across $CPUS CPUs — the sum is a \
real multi-CPU aggregation, not a single-queue artifact"
else
  log "NOTE: only $CPUS CPU carried traffic, so this run did not \
exercise multi-queue aggregation. RSS on the i350 hashes on the \
5-tuple; if this persists, check 'ethtool -l $RECV_IF' and the RX \
queue count."
fi
