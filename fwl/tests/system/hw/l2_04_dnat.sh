#!/usr/bin/env bash
# Test-plan L2 row 3: DNAT port-forward with reply mapping.
#
# Inbound to the "public" address:port is rewritten to the lan host;
# the reply direction restores the public source. Checksums must be
# valid after both rewrites (address AND port change).
source "$(dirname "$0")/hwlib.sh"
hw::require_root
trap hw::finish EXIT

FW=$(mktemp --suffix=.fw)
cat > "$FW" <<EOF
zone t = [$RECV_IF]

@xdp(t)

count inbound if pkt.dst_ip == 10.99.22.1
dnat to 10.99.22.7:8080 if pkt.proto == tcp and pkt.dst_ip == 10.99.22.1 and pkt.dst_port == 80
allow if pkt.proto == tcp
default drop
EOF
hw::deploy l2-04 "$FW"

hw::sniff_start 8 --detail
# Inbound: client 10.99.22.100 -> public 10.99.22.1:80.
hw::send 100 'tcp(src_ip="10.99.22.100", dst_ip="10.99.22.1", src_port=51000, dst_port=80, syn=true)'
sleep 1
# Reply: lan host 10.99.22.7:8080 -> client. The mapping must restore
# the public source 10.99.22.1:80.
hw::send 50 'tcp(src_ip="10.99.22.7", dst_ip="10.99.22.100", src_port=8080, dst_port=51000, ack=true)'
sleep 1
hw::sniff_wait

assert_eq "counter inbound" "$(hw::counter inbound)" 100
assert_eq "wire: dst rewritten to lan host:port, checksums valid" \
  "$(hw::sniff_get 'tcp:10.99.22.100>10.99.22.7:8080:ok')" 100
assert_eq "wire: nothing left at the public dst" \
  "$(hw::sniff_get 'tcp:10.99.22.100>10.99.22.1:80:ok')" 0
assert_eq "wire: reply source restored to public addr:port" \
  "$(hw::sniff_get 'tcp:10.99.22.1>10.99.22.100:51000:ok')" 50
assert_eq "wire: reply not leaked from lan addr" \
  "$(hw::sniff_get 'tcp:10.99.22.7>10.99.22.100:51000:ok')" 0
