#!/usr/bin/env bash
# Test-plan L1 row 4: ICMP type/code — allow echo request, drop
# redirect; selective at the wire.
source "$(dirname "$0")/hwlib.sh"
hw::require_root
trap hw::finish EXIT

FW=$(mktemp --suffix=.fw)
cat > "$FW" <<EOF
zone t = [$RECV_IF]

@xdp(t)

count echo_req if pkt.proto == icmp and pkt.icmp.type == 8
count redir if pkt.proto == icmp and pkt.icmp.type == 5
drop if pkt.proto == icmp and pkt.icmp.type == 5
default allow
EOF
hw::deploy l1-04 "$FW"

hw::sniff_start 5
hw::send 100 'icmp(src_ip="10.99.4.1", type=8, code=0)'
hw::send 100 'icmp(src_ip="10.99.4.1", type=5, code=1)'
sleep 1
hw::sniff_wait

assert_eq "counter echo_req" "$(hw::counter echo_req)" 100
assert_eq "counter redirect" "$(hw::counter redir)" 100
assert_eq "wire echo passed"     "$(hw::sniff_get icmp:10.99.4.1:8)" 100
assert_eq "wire redirect dropped" "$(hw::sniff_get icmp:10.99.4.1:5)" 0
