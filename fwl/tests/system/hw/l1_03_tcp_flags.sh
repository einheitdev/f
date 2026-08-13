#!/usr/bin/env bash
# Test-plan L1 row 3: TCP flags — drop SYN-without-ACK; SYN+ACK and
# bare ACK pass.
source "$(dirname "$0")/hwlib.sh"
hw::require_root
trap hw::finish EXIT

FW=$(mktemp --suffix=.fw)
cat > "$FW" <<EOF
zone t = [$RECV_IF]

@xdp(t)

count syn_only if pkt.proto == tcp and pkt.tcp.syn
       and not pkt.tcp.ack
count synack   if pkt.proto == tcp and pkt.tcp.syn and pkt.tcp.ack
count ack_only if pkt.proto == tcp and pkt.tcp.ack
       and not pkt.tcp.syn
drop if pkt.proto == tcp and pkt.tcp.syn and not pkt.tcp.ack
default allow
EOF
hw::deploy l1-03 "$FW"

hw::sniff_start 6
hw::send 100 'tcp(src_ip="10.99.3.1", dst_port=6001, syn=true)'
hw::send 100 'tcp(src_ip="10.99.3.1", dst_port=6002, syn=true, ack=true)'
hw::send 100 'tcp(src_ip="10.99.3.1", dst_port=6003, ack=true)'
sleep 1
hw::sniff_wait

assert_eq "counter syn_only" "$(hw::counter syn_only)" 100
assert_eq "counter synack"   "$(hw::counter synack)"   100
assert_eq "counter ack_only" "$(hw::counter ack_only)" 100
assert_eq "wire SYN dropped"    "$(hw::sniff_get tcp:10.99.3.1:6001)" 0
assert_eq "wire SYN+ACK passed" "$(hw::sniff_get tcp:10.99.3.1:6002)" 100
assert_eq "wire ACK passed"     "$(hw::sniff_get tcp:10.99.3.1:6003)" 100
