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
count pings if pkt.proto == icmp
masquerade if pkt.src_ip == 10.99.21.5
redirect to wanz if pkt.proto == udp and pkt.dst_port == 1
allow if pkt.proto == tcp
allow if pkt.proto == icmp
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

# --- ICMP through the same masquerade -------------------------------
# A source NAT installs a mapping for a frame with no L4 ports too,
# keyed on ports 0 — and de-NAT used to return early for anything that
# was not TCP or UDP, so the mapping was written and never read. The
# egress half worked and the return half did not: a masqueraded host
# could ping out and never hear back, with the two oracles disagreeing
# about it and no corpus case going through that door. Both halves are
# asserted here, in that order, so the reply assertion cannot pass
# without the request having been translated first.
hw::sniff_start 6 --detail
hw::send 30 'icmp(src_ip="10.99.21.5", dst_ip="10.99.21.9", type=8, code=0)'
sleep 1
hw::send 30 "icmp(src_ip=\"10.99.21.9\", dst_ip=\"$MASQ_ADDR\", \
type=0, code=0)"
sleep 1
hw::sniff_wait

assert_eq "counter pings (request + reply seen by the datapath)" \
  "$(hw::counter pings)" 60
assert_eq "wire: the echo request's source is the masquerade address" \
  "$(hw::sniff_get "icmp:$MASQ_ADDR>10.99.21.9:8.0")" 30
assert_eq "wire: no un-translated echo request leaked" \
  "$(hw::sniff_get 'icmp:10.99.21.5>10.99.21.9:8.0')" 0
assert_eq "wire: the echo REPLY is de-NATed back to the host" \
  "$(hw::sniff_get "icmp:10.99.21.9>10.99.21.5:0.0")" 30
assert_eq "wire: no echo reply stranded at the masquerade address" \
  "$(hw::sniff_get "icmp:10.99.21.9>$MASQ_ADDR:0.0")" 0

# The other half of ICMP, so nobody reads the above as more than it
# is: an ICMP ERROR names its flow in its PAYLOAD (the embedded IP
# header + 8 bytes), which is a different lookup entirely — and the
# one path-MTU discovery depends on. It is asserted where it belongs,
# on a policy that is stateful, in l11_05.
log "NOTE: this is echo/echo-reply de-NAT, keyed on the error-free \
ports-0 mapping. ICMP ERROR translation (RFC 5508, off the embedded \
datagram) is asserted in l11_05_icmp_pmtu."
