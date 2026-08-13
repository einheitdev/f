#!/usr/bin/env bash
# CEILING PROBE: conntrack GC under churn, as distinct from GC at rest.
#
# l10_01 shows the table fills and drains. That is GC at rest: one
# flood, then silence, then a sweep with nothing competing. The office
# deployment is the opposite — testnets browsing means a continuous
# stream of short-lived flows, so the sweep runs against a table that
# is being written while it is read.
#
# Three things are worth measuring rather than assuming:
#
#   1. COST. `ConntrackMgr::RunGc` is a userspace serial scan:
#      bpf_map_get_next_key + bpf_map_lookup_elem for every entry,
#      then a delete for every stale one. It runs INLINE in the
#      daemon's main loop (engine.cc, after the 100 ms zmq::poll), the
#      same thread that answers fctl and the REST API. So does
#      `ConntrackMgr::GetState`, which counts entries by walking the
#      whole map. Both are O(table), both block the control plane.
#   2. THE REAL CAPACITY. Entries leave only when they are 300 s idle.
#      A sustained new-flow rate R therefore parks R x 300 entries in
#      the table regardless of how briefly each flow lives. The
#      capacity that matters is not 65536 concurrent flows, it is
#      65536/300 = 218 NEW FLOWS PER SECOND sustained.
#   3. WHETHER THE DATAPATH CARES. XDP runs in NAPI, not in fd. If the
#      control plane stalls, packets should keep being filtered
#      correctly. That is the half of this that had better be good
#      news, and it is asserted, not assumed.
source "$(dirname "$0")/hwlib.sh"
hw::require_root
trap hw::finish EXIT

CHURN_S=60
CHURN_PPS=2500

FW=$(mktemp --suffix=.fw)
cat > "$FW" <<EOF
zone t = [$RECV_IF]

@xdp(t)

count est if conntrack(pkt).state == established
count control if pkt.src_ip == 10.99.51.1 and pkt.proto == tcp
       and pkt.dst_port == 7777
allow if pkt.src_ip == 10.99.51.1 and pkt.proto == tcp
       and pkt.dst_port == 7777
count opened if pkt.proto == tcp and pkt.tcp.syn
allow if pkt.proto == tcp and pkt.tcp.syn
default drop
EOF
hw::deploy l11-03 "$FW"

ct() {
  fctl status 2>/dev/null | $PY -c "
import json, sys
try:
  print(json.load(sys.stdin)['conntrack']['$1'])
except Exception:
  print(-1)
"
}

# Round-trip latency of one control-plane request, in milliseconds.
# fctl status is the operator's only health command and the REST API's
# status handler runs the same GetState, so this IS the metric an
# operator or a monitoring poller would feel.
# Timed in bash rather than through a python wrapper: a python
# interpreter start is tens of milliseconds and would sit on top of
# every sample, which is the same order as the signal being measured.
status_ms() {
  local t0 t1
  t0=$(date +%s%N)
  fctl status >/dev/null 2>&1
  t1=$(date +%s%N)
  echo $(( (t1 - t0) / 1000000 ))
}

# median and max of N status_ms samples.
latency_stats() {
  local n="$1" i
  local -a v=()
  for i in $(seq 1 "$n"); do v+=("$(status_ms)"); done
  printf '%s\n' "${v[@]}" | sort -n | awk '
    {a[NR] = $1}
    END {printf "%d %d\n", a[int((NR + 1) / 2)], a[NR]}'
}

fd_cpu_ms() {
  awk '{print int(($14 + $15) * 1000 / '"$(getconf CLK_TCK)"')}' \
    "/proc/$(pidof fd)/stat"
}

# --- 1. baseline: empty table ---------------------------------------
read -r BASE_MED BASE_MAX <<< "$(latency_stats 15)"
C0=$(fd_cpu_ms); sleep 30; C1=$(fd_cpu_ms)
BASE_CPU=$((C1 - C0))
log "baseline (0 entries): fctl status median ${BASE_MED} ms, max \
${BASE_MAX} ms; fd used ${BASE_CPU} ms CPU over 30 s"

# --- 2. sustained churn ---------------------------------------------
# A steady stream of DISTINCT short-lived flows — the browsing-testnet
# shape, not a flood of one flow.
log "generating $CHURN_PPS distinct new flows/s for ${CHURN_S}s"
$PY - "$SEND_IF" "$CHURN_PPS" "$CHURN_S" > /tmp/l11_03_churn.log 2>&1 <<'PYEOF' &
import socket
import struct
import sys
import time
sys.path.insert(0, "/opt/fwl")
sys.path.insert(0, "/opt/fwl-deps")
from fwl import pkt

iface, pps, dur = sys.argv[1], float(sys.argv[2]), float(sys.argv[3])
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind((iface, 0))
frame = bytearray(pkt.build_packet(pkt.parse_builder(
  'tcp(src_ip="10.99.50.1", dst_ip="10.99.55.1", '
  'src_port=1024, dst_port=80, syn=true)'
)).raw)

def fix_ip_csum(f):
  struct.pack_into(">H", f, 24, 0)
  total = sum(struct.unpack(">10H", bytes(f[14:34])))
  while total >> 16:
    total = (total & 0xFFFF) + (total >> 16)
  struct.pack_into(">H", f, 24, (~total) & 0xFFFF)

start = time.monotonic()
sent = 0
while time.monotonic() - start < dur:
  # Every packet a new 5-tuple: walk the destination address and the
  # source port together so no key repeats within the run.
  frame[32] = (sent >> 8) & 0xFF
  frame[33] = 1 + (sent >> 16) % 250
  struct.pack_into(">H", frame, 34, 1024 + (sent & 0xFF))
  fix_ip_csum(frame)
  try:
    s.send(bytes(frame))
  except OSError:
    pass
  sent += 1
  target = start + sent / pps
  now = time.monotonic()
  if target > now:
    time.sleep(target - now)
s.close()
print(f"churn: {sent} distinct flows in "
      f"{time.monotonic() - start:.1f}s")
PYEOF
CHURN_PID=$!

sleep 5
CTRL_BEFORE=$(hw::counter control)
sleep 10
read -r CHURN_MED CHURN_MAX <<< "$(latency_stats 15)"
CT_MID=$(ct entries)
log "during churn: fctl status median ${CHURN_MED} ms, max \
${CHURN_MAX} ms; conntrack=$CT_MID"

# The datapath, measured while the control plane is under load: a
# known flow, sent at a known count, must be counted exactly.
hw::sniff_start 6
hw::send 200 'tcp(src_ip="10.99.51.1", dst_ip="10.99.51.9", src_port=33333, dst_port=7777, syn=true)'
sleep 1
hw::sniff_wait
CTRL_AFTER=$(hw::counter control)
CTRL_DELTA=$((CTRL_AFTER - CTRL_BEFORE))
CTRL_WIRE=$(hw::sniff_get tcp:10.99.51.1:7777)
assert_eq "datapath under churn: control flow counted" \
  "$CTRL_DELTA" 200
assert_eq "datapath under churn: control flow passed on the wire" \
  "$CTRL_WIRE" 200

wait "$CHURN_PID" 2>/dev/null || true
cat /tmp/l11_03_churn.log
sleep 3
CT_FULL=$(ct entries)
log "after ${CHURN_S}s of churn: conntrack=$CT_FULL"

# --- 3. cost with the table loaded, at rest -------------------------
read -r FULL_MED FULL_MAX <<< "$(latency_stats 15)"
C0=$(fd_cpu_ms); sleep 30; C1=$(fd_cpu_ms)
FULL_CPU=$((C1 - C0))
log "loaded ($CT_FULL entries), traffic stopped: fctl status median \
${FULL_MED} ms, max ${FULL_MAX} ms; fd used ${FULL_CPU} ms CPU over \
30 s (one sweep interval is 30 s, so this is ~one full-table scan)"

# --- 4. the eviction burst ------------------------------------------
# 300 s after the churn stops every entry goes stale at once, and the
# next sweep deletes all of them in one pass, inline in the loop that
# answers fctl. Poll continuously across that window and keep the
# worst round trip: that number is how long the control plane is
# unavailable when a busy period ends.
log "polling the control plane across the eviction burst (~5.5 min)"
WORST=0
DEADLINE=$(( $(date +%s) + 340 ))
SAMPLES=0
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
  MS=$(status_ms)
  SAMPLES=$((SAMPLES + 1))
  [ "$MS" -gt "$WORST" ] && WORST=$MS
done
CT_DRAINED=$(ct entries)
EVICTED=$(ct total_evicted)
log "eviction window: $SAMPLES control requests, worst round trip \
${WORST} ms; conntrack $CT_FULL -> $CT_DRAINED (evicted $EVICTED)"

# --- findings --------------------------------------------------------
log "=== GC under churn: measured ==="
log "fctl status latency: empty ${BASE_MED}/${BASE_MAX} ms (med/max), \
during churn ${CHURN_MED}/${CHURN_MAX} ms, loaded-at-rest \
${FULL_MED}/${FULL_MAX} ms, worst across the eviction burst \
${WORST} ms"
log "fd CPU per 30 s: ${BASE_CPU} ms empty vs ${FULL_CPU} ms with \
$CT_FULL entries — the sweep rescans the whole table every 30 s \
whether or not anything is stale"

if [ "$CT_FULL" -gt 1000 ]; then
  pass "churn parks entries in the table: $CHURN_PPS new flows/s for \
${CHURN_S}s left $CT_FULL entries. Entries leave only at the 300 s \
idle timeout, so a sustained rate R parks R x 300 of them: the \
sustainable new-flow rate is 65536/300 = 218/s, NOT 65536 concurrent \
flows. Above that the table is permanently full and stateful policy \
is permanently degraded."
else
  fail "churn left only $CT_FULL entries — the generator did not \
create distinct flows, so nothing here is measured"
fi

if [ "$EVICTED" -gt 0 ]; then
  pass "GC drained the churn ($CT_FULL -> $CT_DRAINED, evicted \
$EVICTED) — it does keep up once the traffic stops"
else
  fail "GC evicted nothing across the window; the table stays full"
fi
