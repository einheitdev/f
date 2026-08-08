#!/usr/bin/env bash
# Test-plan L2 row 2b: masquerade — the daemon-resolved NAT source.
#
# masquerade translates to "the WAN interface address": fd resolves
# the redirect-destination zone's first IPv4 at bundle load and
# writes it into the pinned fwl_nat_cfg map. A transient test address
# on the wan-zone port ($WAN_IF, 10.99.0.0/16 space, removed on exit)
# gives it something to resolve; the journal line + the translated
# source on the wire prove the whole chain end to end.
source "$(dirname "$0")/hwlib.sh"
hw::require_root

WAN_IF="${WAN_IF:-enp1s0f2}"
MASQ_ADDR=10.99.200.2

cleanup() {
  ip addr del "$MASQ_ADDR/24" dev "$WAN_IF" 2>/dev/null || true
  hw::finish
}
trap cleanup EXIT

ip addr add "$MASQ_ADDR/24" dev "$WAN_IF" 2>/dev/null || true

FW=$(mktemp --suffix=.fw)
cat > "$FW" <<EOF
zone t = [$RECV_IF]
zone wanz = [$WAN_IF]

@xdp(t)

count outbound if pkt.src_ip == 10.99.21.5
masquerade if pkt.src_ip == 10.99.21.5
redirect to wanz if pkt.proto == udp and pkt.dst_port == 1
allow if pkt.proto == tcp
default drop
EOF
hw::deploy l2-03 "$FW"

journalctl -u fd -n 20 --no-pager | grep -q \
  "masquerade address $MASQ_ADDR" \
  && pass "fd resolved masquerade address from wan zone" \
  || fail "no masquerade-address line in fd journal"

hw::sniff_start 6 --detail
hw::send 100 'tcp(src_ip="10.99.21.5", dst_ip="10.99.21.9", src_port=42000, dst_port=443, syn=true)'
sleep 1
hw::sniff_wait

assert_eq "counter outbound" "$(hw::counter outbound)" 100
assert_eq "wire: src is the daemon-resolved wan address" \
  "$(hw::sniff_get "tcp:$MASQ_ADDR>10.99.21.9:443:ok")" 100
assert_eq "wire: no un-translated leak" \
  "$(hw::sniff_get 'tcp:10.99.21.5>10.99.21.9:443:ok')" 0
