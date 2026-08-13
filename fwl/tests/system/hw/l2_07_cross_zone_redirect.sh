#!/usr/bin/env bash
# Test-plan L2 row 1, full form: TRUE cross-zone redirect on copper.
#
# Requires the EX2300 carve-up (2026-08-08): f-lan 801 untagged on
# ge-0/0/24 (f0) + ge-0/0/25 (f1); f-wan 802 access on ge-0/0/26
# (f2) and TAGGED on ge-0/0/24. Path under test:
#
#   f0 --untagged/f-lan--> f1 [@xdp lan: redirect to wan]
#      --ndo_xdp_xmit--> f2 wire --f-wan--> switch floods 802
#      --tagged 802--> f0  (the capture witness)
#
# The redirected frame can ONLY return to f0 through f-wan — f2 has
# no f-lan membership — so every frame the f0 sniffer receives is
# one that physically crossed zone wan's port. Four independent
# witnesses: the FWL counter, the i350 f2 TX counter, the EX2300's
# own ge-0/0/26 input counter (read via ssh ex01 — ground truth the
# DUT cannot influence), and the f0 capture.
source "$(dirname "$0")/hwlib.sh"
hw::require_root
trap hw::finish EXIT

WAN_IF="${WAN_IF:-enp1s0f2}"
SW_WAN_PORT="${SW_WAN_PORT:-ge-0/0/26}"

FW=$(mktemp --suffix=.fw)
cat > "$FW" <<EOF
zone lan = [$RECV_IF]
zone wan = [$WAN_IF]

@xdp(lan)

count redirected if pkt.src_ip == 10.99.33.5
redirect to wan if pkt.src_ip == 10.99.33.5
default allow

@xdp(wan)

count wan_in
default allow
EOF
# The wan zone carries its own (trivial) program: the igb driver only
# initializes XDP TX queues — the ndo_xdp_xmit path a redirect lands
# on — when an XDP program is attached to the target interface.
hw::deploy l2-07 "$FW"
ip link set dev "$SEND_IF" promisc on
ethtool -K "$SEND_IF" rxvlan off 2>/dev/null || true

# The physical (MAC) input counter — the `statistics` view's logical
# counter lags by minutes on the EX2300.
sw_in() {
  ssh -o BatchMode=yes ex01 \
    "show interfaces $SW_WAN_PORT extensive | match \"Input  packets\"" \
    2>/dev/null | awk 'NR==1{print $3}'
}
tx_of() { ethtool -S "$WAN_IF" | awk '/^ *tx_packets:/{print $2}'; }

SW0=$(sw_in)
TX0=$(tx_of)

# Capture on the SENDER port: outgoing copies are filtered by the
# sniffer, so every counted frame is the redirected one coming back
# through f-wan.
CAP_OUT=$(mktemp)
$PY "$HERE/sniff.py" "$SEND_IF" 8 > "$CAP_OUT" &
CAPPID=$!
sleep 0.5

hw::send 300 'udp(src_ip="10.99.33.5", dst_port=3307)'
sleep 1
wait "$CAPPID"

TX_DELTA=$(( $(tx_of) - TX0 ))
SW_DELTA=$(( $(sw_in) - SW0 ))
# The return frames reach f0 through its TAGGED f-wan membership;
# the sniffer restores kernel-stripped tags, so the key carries the
# vlan802 prefix — direct proof the frame came back via zone wan's
# VLAN and no other path.
BACK=$($PY -c "
import json
print(json.load(open('$CAP_OUT')).get('vlan802:udp:10.99.33.5:3307', 0))
")

assert_eq "FWL counter: redirect rule fired" \
  "$(hw::counter redirected)" 300
assert_range "i350 $WAN_IF tx_packets (left the DUT on copper)" \
  "$TX_DELTA" 300 305
assert_range "EX2300 $SW_WAN_PORT input packets (switch witness)" \
  "$SW_DELTA" 300 310
assert_eq "frame returned to f0 tagged f-wan/802 (full circle)" \
  "$BACK" 300
