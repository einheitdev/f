#!/usr/bin/env bash
# Test-plan L1 row 1: proto/port/CIDR match.
# allow tcp 80/443, drop the rest; conditioned counters + receiver
# sniffer prove the disposition at the wire.
source "$(dirname "$0")/hwlib.sh"
hw::require_root
trap hw::finish EXIT

FW=$(mktemp --suffix=.fw)
cat > "$FW" <<EOF
zone t = [$RECV_IF]

@xdp(t)

count hit_80   if pkt.proto == tcp and pkt.dst_port == 80
count hit_443  if pkt.proto == tcp and pkt.dst_port == 443
count hit_cidr if pkt.src_ip in 10.99.7.0/24
count tcp_seen if pkt.proto == tcp
allow if pkt.proto == tcp and pkt.dst_port == 80
allow if pkt.proto == tcp and pkt.dst_port == 443
default drop
EOF
hw::deploy l1-01 "$FW"

hw::sniff_start 8
hw::send 100 'tcp(src_ip="10.99.1.1", dst_port=80)'
hw::send 100 'tcp(src_ip="10.99.1.1", dst_port=443)'
hw::send 100 'tcp(src_ip="10.99.1.1", dst_port=8080)'
hw::send 50  'udp(src_ip="10.99.7.5", dst_port=9999)'
sleep 1
hw::sniff_wait

assert_eq "counter hit_80"   "$(hw::counter hit_80)"   100
assert_eq "counter hit_443"  "$(hw::counter hit_443)"  100
assert_eq "counter hit_cidr" "$(hw::counter hit_cidr)" 50
assert_eq "counter tcp_seen" "$(hw::counter tcp_seen)" 300
# The sniffer sits after XDP: allowed ports appear, dropped do not.
assert_eq "wire tcp:80 passed"     "$(hw::sniff_get tcp:10.99.1.1:80)"  100
assert_eq "wire tcp:443 passed"    "$(hw::sniff_get tcp:10.99.1.1:443)" 100
assert_eq "wire tcp:8080 dropped"  "$(hw::sniff_get tcp:10.99.1.1:8080)" 0
assert_eq "wire udp:9999 dropped"  "$(hw::sniff_get udp:10.99.7.5:9999)" 0
