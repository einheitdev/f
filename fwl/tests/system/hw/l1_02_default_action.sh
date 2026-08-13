#!/usr/bin/env bash
# Test-plan L1 row 2: default action.
# The same traffic against `default drop` vs `default allow` —
# blocked at the wire in one, passed in the other.
source "$(dirname "$0")/hwlib.sh"
hw::require_root
trap hw::finish EXIT

FW=$(mktemp --suffix=.fw)

# Phase A: default drop.
cat > "$FW" <<EOF
zone t = [$RECV_IF]

@xdp(t)

count seen if pkt.src_ip == 10.99.2.1
default drop
EOF
hw::deploy l1-02a "$FW"
hw::sniff_start 5
hw::send 100 'udp(src_ip="10.99.2.1", dst_port=5000)'
sleep 1
hw::sniff_wait
assert_eq "drop: counter saw frames" "$(hw::counter seen)" 100
assert_eq "drop: wire passed none" \
  "$(hw::sniff_get udp:10.99.2.1:5000)" 0

# Phase B: default allow.
cat > "$FW" <<EOF
zone t = [$RECV_IF]

@xdp(t)

count seen if pkt.src_ip == 10.99.2.1
default allow
EOF
hw::deploy l1-02b "$FW"
hw::sniff_start 5
hw::send 100 'udp(src_ip="10.99.2.1", dst_port=5000)'
sleep 1
hw::sniff_wait
assert_eq "allow: counter saw frames" "$(hw::counter seen)" 100
assert_eq "allow: wire passed all" \
  "$(hw::sniff_get udp:10.99.2.1:5000)" 100
