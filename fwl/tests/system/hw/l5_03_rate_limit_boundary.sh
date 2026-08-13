#!/usr/bin/env bash
# rate_limit at the exact threshold, and per-bucket independence.
#
# FWL_V01_SPEC:288-294: the first N matching packets per bucket per
# second are NOT dropped; packet N+1 onward are. Sending exactly N
# in well under a second must therefore drop nothing.
#
# Also asserts buckets are keyed per source: a second source gets its
# own allowance, and a third source under the limit is untouched
# while the first is being capped.
source "$(dirname "$0")/hwlib.sh"
hw::require_root
trap hw::finish EXIT

LIMIT=20
FW=$(mktemp --suffix=.fw)
cat > "$FW" <<EOF
zone t = [$RECV_IF]

@xdp(t)

count seen_a if pkt.src_ip == 10.99.152.1
count seen_b if pkt.src_ip == 10.99.152.2
drop if pkt.src_ip in 10.99.152.0/24
       limited by rate_limit($LIMIT, per=src_ip)
default allow
EOF
hw::deploy l5-03 "$FW"

# Exactly LIMIT from source A: nothing should be dropped.
hw::sniff_start 6
hw::send "$LIMIT" 'udp(src_ip="10.99.152.1", dst_port=5200)'
sleep 1
hw::sniff_wait
EXACT=$(hw::sniff_get udp:10.99.152.1:5200)
assert_eq "exactly N=$LIMIT from one source: none dropped" \
  "$EXACT" "$LIMIT"

# A fresh source in the same second gets its own bucket.
hw::sniff_start 6
hw::send "$LIMIT" 'udp(src_ip="10.99.152.2", dst_port=5201)'
sleep 1
hw::sniff_wait
assert_eq "a different source has an independent bucket" \
  "$(hw::sniff_get udp:10.99.152.2:5201)" "$LIMIT"

# Now exceed on a third source and confirm the cap engages, while a
# quiet fourth source is untouched in the same window.
hw::sniff_start 8
hw::send 200 'udp(src_ip="10.99.152.3", dst_port=5202)'
hw::send 5 'udp(src_ip="10.99.152.4", dst_port=5203)'
sleep 1
hw::sniff_wait
FLOOD=$(hw::sniff_get udp:10.99.152.3:5202)
QUIET=$(hw::sniff_get udp:10.99.152.4:5203)
log "flood source passed $FLOOD/200, quiet source passed $QUIET/5"
assert_range "flooding source is capped near the limit" \
  "$FLOOD" "$LIMIT" "$((LIMIT * 2))"
assert_eq "quiet source unaffected by another source's flood" \
  "$QUIET" 5
