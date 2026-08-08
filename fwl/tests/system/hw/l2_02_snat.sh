#!/usr/bin/env bash
# Test-plan L2 row 2a: source NAT (`snat to`) with reply de-NAT.
#
# The NAT-rewritten frame is passed (not redirected), so the receiving
# port's AF_PACKET witness sees the frame AFTER the XDP rewrite:
# translated source address and RECOMPUTED, VALID checksums — the
# ANTI_STUB evidence a stub cannot fake. The reply direction proves
# the fwl_nat mapping: the return frame's destination is rewritten
# back to the original private address.
source "$(dirname "$0")/hwlib.sh"
hw::require_root
trap hw::finish EXIT

FW=$(mktemp --suffix=.fw)
cat > "$FW" <<EOF
zone t = [$RECV_IF]

@xdp(t)

count outbound if pkt.src_ip == 10.99.20.5
snat to 10.99.200.1 if pkt.proto == tcp and pkt.src_ip == 10.99.20.5
allow if pkt.proto == tcp
default drop
EOF
hw::deploy l2-02 "$FW"

hw::sniff_start 8 --detail
# Outbound: private 10.99.20.5 -> server 10.99.20.9:80.
hw::send 100 'tcp(src_ip="10.99.20.5", dst_ip="10.99.20.9", src_port=41000, dst_port=80, syn=true)'
sleep 1
# Reply: server 10.99.20.9:80 -> the PUBLIC (translated) address.
# De-NAT must rewrite the destination back to 10.99.20.5:41000.
hw::send 50 'tcp(src_ip="10.99.20.9", dst_ip="10.99.200.1", src_port=80, dst_port=41000, ack=true)'
sleep 1
hw::sniff_wait

assert_eq "counter outbound (pre-NAT match)" \
  "$(hw::counter outbound)" 100
assert_eq "wire: src translated, checksums valid" \
  "$(hw::sniff_get 'tcp:10.99.200.1>10.99.20.9:80:ok')" 100
assert_eq "wire: no un-translated leak" \
  "$(hw::sniff_get 'tcp:10.99.20.5>10.99.20.9:80:ok')" 0
assert_eq "wire: reply de-NATed to private addr, checksums valid" \
  "$(hw::sniff_get 'tcp:10.99.20.9>10.99.20.5:41000:ok')" 50
assert_eq "wire: no reply leaked at public addr" \
  "$(hw::sniff_get 'tcp:10.99.20.9>10.99.200.1:41000:ok')" 0
