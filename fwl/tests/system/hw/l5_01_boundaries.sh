#!/usr/bin/env bash
# Boundary values: the places where off-by-one lives.
#
# Ranges (inclusive both ends), port 0 and 65535, CIDR /32 and /0,
# ICMP type 0 and 255, and operator precedence (`and` binds tighter
# than `or` — the spec calls this trap out explicitly).
source "$(dirname "$0")/hwlib.sh"
hw::require_root
trap hw::finish EXIT

FW=$(mktemp --suffix=.fw)
cat > "$FW" <<EOF
zone t = [$RECV_IF]

@xdp(t)

count in_range if pkt.proto == udp and pkt.dst_port in 5000..5002
count port_zero if pkt.proto == udp and pkt.dst_port == 0
count port_max if pkt.proto == udp and pkt.dst_port == 65535
count host32 if pkt.src_ip in 10.99.150.7/32
count any_v4 if pkt.src_ip in 0.0.0.0/0
count icmp_zero if pkt.proto == icmp and pkt.icmp.type == 0
count icmp_max if pkt.proto == icmp and pkt.icmp.type == 255
default allow
EOF
hw::deploy l5-01 "$FW"

hw::sniff_start 12
# Range edges: 4999 out, 5000/5001/5002 in, 5003 out.
for p in 4999 5000 5001 5002 5003; do
  hw::send 20 "udp(src_ip=\"10.99.150.1\", dst_port=$p)"
done
# Port extremes.
hw::send 20 'udp(src_ip="10.99.150.2", dst_port=0)'
hw::send 20 'udp(src_ip="10.99.150.3", dst_port=65535)'
# /32 host route: .7 matches, .8 does not.
hw::send 20 'udp(src_ip="10.99.150.7", dst_port=9000)'
hw::send 20 'udp(src_ip="10.99.150.8", dst_port=9000)'
# ICMP type extremes.
hw::send 20 'icmp(src_ip="10.99.150.4", type=0, code=0)'
hw::send 20 'icmp(src_ip="10.99.150.5", type=255, code=0)'
sleep 1
hw::sniff_wait

# 5000, 5001, 5002 = 3 x 20. Inclusive on both ends.
assert_eq "range 5000..5002 is inclusive both ends (3 ports x 20)" \
  "$(hw::counter in_range)" 60
assert_eq "port 0 matches exactly" "$(hw::counter port_zero)" 20
assert_eq "port 65535 matches exactly" "$(hw::counter port_max)" 20
assert_eq "/32 matches exactly one host" "$(hw::counter host32)" 20
assert_eq "icmp type 0 matches" "$(hw::counter icmp_zero)" 20
assert_eq "icmp type 255 matches" "$(hw::counter icmp_max)" 20
# 5 range probes + 2 port extremes + 2 host probes + 2 icmp = 11 x 20
assert_eq "0.0.0.0/0 matches every IPv4 frame" \
  "$(hw::counter any_v4)" 220
