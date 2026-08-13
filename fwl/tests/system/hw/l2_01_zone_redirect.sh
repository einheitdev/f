#!/usr/bin/env bash
# Test-plan L2 row 1: zone redirect on real ports — hairpin form.
#
# On a flat L2 fabric a cross-zone redirect reflects: the redirected
# frame keeps its dst MAC, the switch forwards it straight back to
# the ingress port, and the pair loops at line rate. Until the EX2300
# is carved into per-zone VLANs (operator/switch access), this test
# uses the spec-legal HAIRPIN redirect (`redirect to <ingress zone>`):
# the redirected frame egresses the ingress port, and the switch's
# same-port filter (dst MAC learned on that very port) terminates it.
# No loop, bounded traffic, and the full redirect datapath — XDP
# verdict, devmap lookup, ndo_xdp_xmit through the real igb driver
# onto copper — is exercised and measured:
#
#   - FWL counter: the rule fired N times.
#   - i350 hardware TX counter on the XDP port: N frames physically
#     left the wire. Nothing else transmits on this port (no host L3),
#     so the delta is the redirect and only the redirect.
source "$(dirname "$0")/hwlib.sh"
hw::require_root
trap hw::finish EXIT

FW=$(mktemp --suffix=.fw)
cat > "$FW" <<EOF
zone t = [$RECV_IF]

@xdp(t)

count redirected if pkt.src_ip == 10.99.30.5
redirect to t if pkt.src_ip == 10.99.30.5
default allow
EOF
hw::deploy l2-01 "$FW"

tx_of() { ethtool -S "$RECV_IF" | awk '/^ *tx_packets:/{print $2}'; }
RX_TX0=$(tx_of)

hw::send 200 'udp(src_ip="10.99.30.5", dst_port=3005)'
sleep 1

TX_DELTA=$(( $(tx_of) - RX_TX0 ))
assert_eq "counter redirected" "$(hw::counter redirected)" 200
# The i350 counts a handful of its own pause/management frames at
# most; 200 test frames dominate.
assert_range "hardware tx_packets delta (ndo_xdp_xmit)" \
  "$TX_DELTA" 200 205
