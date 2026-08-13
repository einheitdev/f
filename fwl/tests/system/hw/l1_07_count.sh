#!/usr/bin/env bash
# Test-plan L1 row 7: count — traffic-triggered counters with
# monotone deltas across two rounds.
source "$(dirname "$0")/hwlib.sh"
hw::require_root
trap hw::finish EXIT

FW=$(mktemp --suffix=.fw)
cat > "$FW" <<EOF
zone t = [$RECV_IF]

@xdp(t)

count round_frames if pkt.src_ip == 10.99.8.1
count all_test if pkt.src_ip in 10.99.8.0/24
default allow
EOF
hw::deploy l1-07 "$FW"

hw::send 70 'udp(src_ip="10.99.8.1", dst_port=7100)'
sleep 1
R1=$(hw::counter round_frames)
A1=$(hw::counter all_test)
assert_eq "round 1: round_frames" "$R1" 70
assert_eq "round 1: all_test" "$A1" 70

hw::send 30 'udp(src_ip="10.99.8.1", dst_port=7100)'
sleep 1
R2=$(hw::counter round_frames)
A2=$(hw::counter all_test)
assert_eq "round 2: round_frames (monotone)" "$R2" 100
assert_eq "round 2: all_test (monotone)" "$A2" 100
