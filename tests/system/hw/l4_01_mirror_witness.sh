#!/usr/bin/env bash
# Test-plan Layer 4: EX2300 port-mirror ground truth.
#
# The switch mirrors every frame it delivers to the DUT port (f1)
# into VLAN f-mirror -> f0. The mirror copy is made by the SWITCH,
# before and independent of anything XDP does — evidence the DUT
# cannot influence. This closes the ANTI_STUB loop on drop tests:
#
#   - mirror (f0):  BOTH flows physically delivered to the DUT
#   - DUT tap (f1): only the allowed flow survived XDP
#   - FWL counters: the program saw and counted both
#
# A "drop" proven only DUT-side could in principle be a delivery
# failure; the mirror shows delivery, so the missing frames died in
# the DUT's policy — nowhere else.
source "$(dirname "$0")/hwlib.sh"
hw::require_root
cleanup() {
  hw::mirror_off
  hw::finish
}
trap cleanup EXIT

FW=$(mktemp --suffix=.fw)
cat > "$FW" <<EOF
zone t = [$RECV_IF]

@xdp(t)

count seen_pass if pkt.src_ip == 10.99.71.1
count seen_drop if pkt.src_ip == 10.99.71.2
drop if pkt.src_ip == 10.99.71.2
default allow
EOF
hw::deploy l4-01 "$FW"
# The mirror copies carry the builder dst MAC, not f0's — the i350
# filters them without promisc (XDP attach cycles reset the port).
ip link set dev "$SEND_IF" promisc on
ethtool -K "$SEND_IF" rxvlan off 2>/dev/null || true
hw::mirror_on
# Junos reports commit complete before the analyzer is programmed
# into the dataplane; give it a moment.
sleep 10

# Witness A: the switch's copies, on the sender port.
MIR_OUT=$(mktemp)
$PY "$HERE/sniff.py" "$SEND_IF" 8 > "$MIR_OUT" &
MIRPID=$!
# Witness B: the DUT-side tap (post-XDP).
hw::sniff_start 8

hw::send 150 'udp(src_ip="10.99.71.1", dst_port=7101)'
hw::send 150 'udp(src_ip="10.99.71.2", dst_port=7102)'
sleep 1
wait "$MIRPID"
hw::sniff_wait
hw::mirror_off

mir() {
  $PY -c "
import json
print(json.load(open('$MIR_OUT')).get('$1', 0))
"
}

assert_eq "counter: allowed flow seen" "$(hw::counter seen_pass)" 150
assert_eq "counter: dropped flow seen" "$(hw::counter seen_drop)" 150
assert_eq "mirror: allowed flow delivered to DUT" \
  "$(mir vlan803:udp:10.99.71.1:7101)" 150
assert_eq "mirror: DROPPED flow was also delivered to DUT" \
  "$(mir vlan803:udp:10.99.71.2:7102)" 150
assert_eq "DUT tap: allowed flow survived XDP" \
  "$(hw::sniff_get udp:10.99.71.1:7101)" 150
assert_eq "DUT tap: dropped flow died IN the DUT" \
  "$(hw::sniff_get udp:10.99.71.2:7102)" 0
