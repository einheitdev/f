#!/usr/bin/env bash
# IPv6 field matching on wire: proto, ports, prefix (CIDR), and the
# v4/v6 separation — a v4 rule must not catch a v6 frame and vice
# versa (FWL_V02_SPEC "Compilation": the prelude branches on
# EtherType and the two families populate the same variables, so a
# family mix-up would be invisible to the interpreter but visible
# here).
source "$(dirname "$0")/hwlib.sh"
hw::require_root
trap hw::finish EXIT

FW=$(mktemp --suffix=.fw)
cat > "$FW" <<EOF
zone t = [$RECV_IF]

@xdp(t)

count v6_tcp80 if pkt.proto == tcp and pkt.dst_port == 80
count v6_prefix if pkt.src_ip6 in 2001:db8:99:aa::/64
count v4_only if pkt.src_ip in 10.99.11.0/24
drop if pkt.src_ip6 in 2001:db8:99:dd::/64
default allow
EOF
hw::deploy l1-11 "$FW"

hw::sniff_start 8
# v6 TCP/80 from the "allowed" prefix.
hw::send 100 'tcp6(src_ip="2001:db8:99:aa::1", dst_ip="2001:db8:99:aa::2", dst_port=80, syn=true)'
# v6 UDP from the blocked prefix.
hw::send 100 'udp6(src_ip="2001:db8:99:dd::1", dst_ip="2001:db8:99:aa::2", dst_port=5353)'
# v4 traffic that must NOT satisfy any v6 rule.
hw::send 100 'tcp(src_ip="10.99.11.1", dst_port=80)'
sleep 1
hw::sniff_wait

# pkt.proto/dst_port are family-agnostic: both the v6 and the v4
# TCP/80 frames match, so 200.
assert_eq "counter v6_tcp80 (family-agnostic proto/port)" \
  "$(hw::counter v6_tcp80)" 200
# The v6 prefix rule must count only the v6 frames from that /64.
assert_eq "counter v6_prefix (v6 CIDR)" "$(hw::counter v6_prefix)" 100
# The v4 CIDR rule must not be satisfied by any v6 frame.
assert_eq "counter v4_only (v4 CIDR, no v6 leakage)" \
  "$(hw::counter v4_only)" 100
assert_eq "wire: v6 allowed prefix passed" \
  "$(hw::sniff_get 'tcp6:2001:db8:99:aa::1:80')" 100
assert_eq "wire: v6 blocked prefix dropped" \
  "$(hw::sniff_get 'udp6:2001:db8:99:dd::1:5353')" 0
assert_eq "wire: v4 frame unaffected by v6 drop rule" \
  "$(hw::sniff_get tcp:10.99.11.1:80)" 100
