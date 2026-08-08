#!/usr/bin/env bash
# Test-plan L1 row 6: rate_limit(per=src_ip) — one source floods past
# the limit and is capped; another stays under and passes untouched.
#
# Semantics (FWL v0.1 §rate_limit): the first N matching packets per
# bucket per second are NOT dropped; packet N+1 onward are. The burst
# of 500 is sent in well under a second, so 50..100 survivors are
# accepted (window straddle can admit up to 2N).
source "$(dirname "$0")/hwlib.sh"
hw::require_root
trap hw::finish EXIT

FW=$(mktemp --suffix=.fw)
cat > "$FW" <<EOF
zone t = [$RECV_IF]

@xdp(t)

count seen_a if pkt.src_ip == 10.99.6.1
count seen_b if pkt.src_ip == 10.99.6.2
drop if pkt.src_ip in 10.99.6.0/24
       limited by rate_limit(50, per=src_ip)
count passed_a if pkt.src_ip == 10.99.6.1
count passed_b if pkt.src_ip == 10.99.6.2
default allow
EOF
hw::deploy l1-06 "$FW"

hw::sniff_start 8
hw::send 500 'udp(src_ip="10.99.6.1", dst_port=6100)'
hw::send 20  'udp(src_ip="10.99.6.2", dst_port=6200)'
sleep 1
hw::sniff_wait

assert_eq "counter seen_a (flood arrived)" "$(hw::counter seen_a)" 500
assert_eq "counter seen_b" "$(hw::counter seen_b)" 20
assert_range "counter passed_a (capped)" "$(hw::counter passed_a)" 50 100
assert_eq "counter passed_b (untouched)" "$(hw::counter passed_b)" 20
WIRE_A=$(hw::sniff_get udp:10.99.6.1:6100)
assert_range "wire flood survivors" "$WIRE_A" 50 100
assert_eq "wire quiet source passed" \
  "$(hw::sniff_get udp:10.99.6.2:6200)" 20
