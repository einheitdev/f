#!/usr/bin/env bash
# Is conntrack garbage collection alive in bundle (multi-zone) mode?
#
# ConntrackMgr::MaybeRunGc returns early unless `enabled`, and
# `enabled` is set only by ApplyConfig — the single-program rule path.
# EngineInit's multi-zone branch sets conntrack.map_fd and nothing
# else. So in a v0.4 bundle deployment (which is every deployment)
# GC may never run: entries accumulate to the map cap and then new
# flows stop being tracked, silently degrading every
# established-state rule.
#
# Measured here rather than argued: create many distinct flows, watch
# the entry count and total_evicted over a window longer than the
# 30 s GC interval. Growth with zero evictions across several
# intervals means GC is not running.
source "$(dirname "$0")/hwlib.sh"
hw::require_root
trap hw::finish EXIT

FW=$(mktemp --suffix=.fw)
cat > "$FW" <<EOF
zone t = [$RECV_IF]

@xdp(t)

count est if conntrack(pkt).state == established
allow if conntrack(pkt).state == established
count opened if pkt.proto == tcp and pkt.tcp.syn
allow if pkt.proto == tcp and pkt.tcp.syn
default drop
EOF
hw::deploy l8-02 "$FW"

ct_entries() {
  fctl status 2>/dev/null | $PY -c "
import json, sys
try:
  print(json.load(sys.stdin)['conntrack']['entries'])
except Exception:
  print(-1)
"
}
ct_field() {
  fctl status 2>/dev/null | $PY -c "
import json, sys
try:
  print(json.load(sys.stdin)['conntrack']['$1'])
except Exception:
  print('?')
"
}

log "conntrack enabled flag: $(ct_field enabled)"
log "gc_interval_s=$(ct_field gc_interval_s) timeout_s=$(ct_field timeout_s)"

START=$(ct_entries)
# 400 distinct flows: each SYN is an explicit allow on a `new`
# packet, so each creates an entry.
for i in $(seq 1 4); do
  $PY - "$SEND_IF" "$i" <<'EOF'
import socket
import sys
sys.path.insert(0, "/opt/fwl/tests/system/hw")
from fwl import pkt
iface, batch = sys.argv[1], int(sys.argv[2])
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind((iface, 0))
for j in range(100):
  port = 30000 + batch * 100 + j
  b = (f'tcp(src_ip="10.99.141.{batch}", dst_ip="10.99.141.200", '
       f'src_port={port}, dst_port=80, syn=true)')
  s.send(pkt.build_packet(pkt.parse_builder(b)).raw)
s.close()
EOF
done
sleep 2
AFTER_CREATE=$(ct_entries)
CREATED=$((AFTER_CREATE - START))
log "entries: $START -> $AFTER_CREATE (created $CREATED)"
assert_range "flows were tracked (entries grew)" "$CREATED" 300 400

# Watch across >2 GC intervals (30 s each) with the flows idle. A
# live GC with the default 300 s timeout will not evict yet, so the
# signal we can get in reasonable time is whether GC RUNS at all —
# reported via total_evicted and the `enabled` flag.
sleep 75
IDLE_ENTRIES=$(ct_entries)
EVICTED=$(ct_field total_evicted)
ENABLED=$(ct_field enabled)
log "after 75 s idle: entries=$IDLE_ENTRIES evicted=$EVICTED \
enabled=$ENABLED"

if [ "$ENABLED" = "False" ] || [ "$ENABLED" = "false" ]; then
  fail "CONNTRACK GC IS DEAD IN BUNDLE MODE: conntrack.enabled is \
$ENABLED, so MaybeRunGc returns immediately and no entry is ever \
evicted. Entries only grow ($AFTER_CREATE now). At the 65536-entry \
map cap, new flows stop being tracked and every established-state \
rule silently starts mismatching. Nothing logs this. The flag is set \
only by ApplyConfig, which the multi-zone path never calls."
else
  pass "conntrack GC is enabled in bundle mode (enabled=$ENABLED, \
evicted=$EVICTED)"
fi
