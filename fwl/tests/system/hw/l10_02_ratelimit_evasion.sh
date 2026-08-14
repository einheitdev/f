#!/usr/bin/env bash
# Can a rate limit be evaded by source diversity?
#
# `rate_limit(N, per=src_ip)` keys buckets in a 4096-entry per-CPU
# hash. FWL_V01_SPEC:329-333 says that when the map is full "the new
# entry is dropped silently — the rule treats the new bucket as
# below threshold". Read as an attacker: **spread traffic across
# more than 4096 sources and the rule stops firing**. Every source
# then gets a free pass, no matter the aggregate rate.
#
# That is inherent to a fixed-size bucket table, not a defect to be
# fixed here — but it is a property an operator must know before
# relying on rate_limit as a flood defence, and the reserved
# `__rate_limit_overflow` counter exists precisely to make it
# visible. This measures both: whether evasion works, and whether
# the overflow counter reports it.
#
# The comparison is what makes it meaningful: one heavy source (must
# be capped) against thousands of light ones (aggregate far above
# the same threshold).
source "$(dirname "$0")/hwlib.sh"
hw::require_root
trap hw::finish EXIT

LIMIT=10
FW=$(mktemp --suffix=.fw)
cat > "$FW" <<EOF
zone t = [$RECV_IF]

@xdp(t)

count seen if pkt.src_ip in 10.99.0.0/16
drop if pkt.proto == udp and pkt.dst_port == 7000
       limited by rate_limit($LIMIT, per=src_ip)
default allow
EOF
hw::deploy l10-02 "$FW"

# --- control: a single source must be capped ---
hw::sniff_start 8
hw::send 500 'udp(src_ip="10.99.210.1", dst_port=7000)'
sleep 1
hw::sniff_wait
SINGLE=$(hw::sniff_get udp:10.99.210.1:7000)
log "single source: $SINGLE/500 passed (limit $LIMIT)"
assert_range "control: one heavy source is capped" \
  "$SINGLE" "$LIMIT" "$((LIMIT * 3))"

# --- the evasion: many sources, each under the limit ---
# 8192 distinct sources x 5 frames = 40960 frames, an aggregate
# hundreds of times the threshold, but no single source exceeds it.
SOURCES=8192
PER=5
$PY - "$SEND_IF" "$SOURCES" "$PER" <<'EOF'
import socket
import sys
sys.path.insert(0, "/opt/fwl")
sys.path.insert(0, "/opt/fwl-deps")
from fwl import pkt
iface, sources, per = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind((iface, 0))
frame = bytearray(pkt.build_packet(pkt.parse_builder(
  'udp(src_ip="10.99.0.0", dst_port=7000)'
)).raw)
sent = 0
for i in range(sources):
  # IPv4 source at bytes 26..29: sweep 10.99.<hi>.<lo>
  frame[28] = (i >> 8) & 0xFF
  frame[29] = i & 0xFF
  for _ in range(per):
    try:
      s.send(bytes(frame))
      sent += 1
    except OSError:
      pass
s.close()
print(f"sent {sent} frames from {sources} distinct sources")
EOF
sleep 2

SEEN=$(hw::counter seen)
# -1 means the running bundle declares no such counter at all,
# which is a different answer from "it stayed at zero" and the
# note below now says which one it got.
OVERFLOW=$(hw::counter __rate_limit_overflow 2>/dev/null)
OVERFLOW=${OVERFLOW:--1}
log "distributed flood: program saw $SEEN frames, \
__rate_limit_overflow=$OVERFLOW"

# Sample a source from beyond the bucket table's capacity and check
# whether the rule still bites for it.
hw::sniff_start 8
hw::send 200 'udp(src_ip="10.99.31.200", dst_port=7000)'
sleep 1
hw::sniff_wait
LATE=$(hw::sniff_get udp:10.99.31.200:7000)
log "a source arriving after the bucket table filled: $LATE/200 \
passed (limit $LIMIT)"

if [ "$LATE" -gt "$((LIMIT * 3))" ]; then
  record "EVASION CONFIRMED and it is the documented behaviour: once \
the 4096-bucket table is full, a new source is treated as below \
threshold and passes $LATE/200 despite the limit being $LIMIT. \
rate_limit(per=src_ip) is a per-source fairness control, NOT a \
defence against a distributed flood. Operators should alarm on \
__rate_limit_overflow (currently $OVERFLOW) rather than assume the \
limit holds."
else
  record "the limit still bit for a late source ($LATE/200) — the \
bucket table had room or recycled entries"
fi

if [ "$OVERFLOW" -gt 0 ]; then
  record "__rate_limit_overflow reported the pressure ($OVERFLOW), so \
the condition is at least observable"
else
  log "NOTE: __rate_limit_overflow read $OVERFLOW (-1 = the bundle \
declares no such counter; 0 = it exists and did not tick). Either the \
table never overflowed, or the overflow path did not tick — if evasion \
was confirmed above while this stayed 0, the condition is happening \
silently and that is the more serious half."
fi
