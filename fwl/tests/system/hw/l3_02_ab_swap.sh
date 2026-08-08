#!/usr/bin/env bash
# Test-plan L3 row 2: rule change mid-traffic — the changed rule
# flips behavior, untouched flows are uninterrupted.
#
# Two steady flows: A (allowed before and after) and B (dropped
# before, allowed after). The policy edit lands mid-stream via the
# watcher. Afterwards: flow A arrived in full (uninterrupted), flow B
# shows a partial count that starts at the reload (old rule stopped).
source "$(dirname "$0")/hwlib.sh"
hw::require_root

RULES_BAK=$(mktemp)
cp /etc/f/rules.fw "$RULES_BAK"
cleanup() {
  cp "$RULES_BAK" /etc/f/rules.fw
  hw::finish
}
trap cleanup EXIT

FW=$(mktemp --suffix=.fw)
cat > "$FW" <<EOF
zone t = [$RECV_IF]

@xdp(t)

count flow_a if pkt.src_ip == 10.99.53.1
count flow_b if pkt.src_ip == 10.99.53.2
drop if pkt.proto == udp and pkt.src_ip == 10.99.53.2
allow if pkt.proto == udp
default drop
EOF
hw::deploy l3-02 "$FW"
cp "$FW" /etc/f/rules.fw

hw::sniff_start 18
$PY "$HERE/sendmany.py" --pps 200 "$SEND_IF" 2400 \
  'udp(src_ip="10.99.53.1", dst_port=5301)' > /tmp/l3a.out &
PID_A=$!
$PY "$HERE/sendmany.py" --pps 200 "$SEND_IF" 2400 \
  'udp(src_ip="10.99.53.2", dst_port=5302)' > /tmp/l3b.out &
PID_B=$!
sleep 4

# Mid-stream: the same policy without flow B's drop rule.
cat > /etc/f/rules.fw <<EOF
zone t = [$RECV_IF]

@xdp(t)

count flow_a if pkt.src_ip == 10.99.53.1
count flow_b if pkt.src_ip == 10.99.53.2
allow if pkt.proto == udp
default drop
EOF

wait "$PID_A" "$PID_B"
hw::sniff_wait
A_WIRE=$(hw::sniff_get udp:10.99.53.1:5301)
B_WIRE=$(hw::sniff_get udp:10.99.53.2:5302)

journalctl -u fd --since "-60s" --no-pager | grep -q reload \
  && pass "reload fired mid-stream" \
  || fail "no reload observed"

assert_eq "untouched flow A uninterrupted (2400/2400)" \
  "$A_WIRE" 2400
# B ran 12 s; the edit landed ~4 s in, watcher interval 5 s: expect
# roughly the last 4-7 s of B to pass = 800..1600 frames. Zero means
# the rule never flipped; 2400 means it never dropped.
assert_range "flow B flipped mid-stream" "$B_WIRE" 400 2000
