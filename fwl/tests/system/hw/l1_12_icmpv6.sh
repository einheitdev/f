#!/usr/bin/env bash
# ICMPv6 type/code on wire, and its separation from ICMPv4.
#
# pkt.icmp6.type and pkt.icmp.type are distinct fields (FWL_V02_SPEC:
# ICMP6_FIELD is lexed ahead of ICMP_FIELD). A program matching
# icmp6 types must not fire on ICMPv4 frames carrying the same type
# number — an easy emitter bug that only a real dual-stack wire test
# catches. Type 128 = echo request, 137 = redirect (RFC 4443).
source "$(dirname "$0")/hwlib.sh"
hw::require_root
trap hw::finish EXIT

FW=$(mktemp --suffix=.fw)
cat > "$FW" <<EOF
zone t = [$RECV_IF]

@xdp(t)

count v6_echo if pkt.proto == icmp6 and pkt.icmp6.type == 128
count v6_redir if pkt.proto == icmp6 and pkt.icmp6.type == 137
count v4_echo if pkt.proto == icmp and pkt.icmp.type == 8
drop if pkt.proto == icmp6 and pkt.icmp6.type == 137
default allow
EOF
hw::deploy l1-12 "$FW"

hw::sniff_start 8
hw::send 100 'icmp6(src_ip="2001:db8:99:aa::1", dst_ip="2001:db8:99:aa::2", type=128, code=0)'
hw::send 100 'icmp6(src_ip="2001:db8:99:aa::1", dst_ip="2001:db8:99:aa::2", type=137, code=0)'
hw::send 100 'icmp(src_ip="10.99.12.1", type=8, code=0)'
# ICMPv4 type 128 — the same number as a v6 echo request. The v6
# rule must ignore it entirely.
hw::send 50 'icmp(src_ip="10.99.12.2", type=128, code=0)'
sleep 1
hw::sniff_wait

assert_eq "counter v6_echo" "$(hw::counter v6_echo)" 100
assert_eq "counter v6_redir" "$(hw::counter v6_redir)" 100
assert_eq "counter v4_echo" "$(hw::counter v4_echo)" 100
assert_eq "wire: ICMPv6 echo passed" \
  "$(hw::sniff_get 'icmp6:2001:db8:99:aa::1:128')" 100
assert_eq "wire: ICMPv6 redirect dropped" \
  "$(hw::sniff_get 'icmp6:2001:db8:99:aa::1:137')" 0
assert_eq "wire: ICMPv4 echo unaffected" \
  "$(hw::sniff_get icmp:10.99.12.1:8)" 100
assert_eq "wire: ICMPv4 type 128 NOT matched by the icmp6 rule" \
  "$(hw::sniff_get icmp:10.99.12.2:128)" 50
