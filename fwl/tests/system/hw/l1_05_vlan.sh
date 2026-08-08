#!/usr/bin/env bash
# Test-plan L1 row 5: 802.1Q VLAN match — drop vlan_id 100, pass
# vlan_id 200 and untagged.
#
# CAVEAT: this needs the EX2300 to forward tagged frames between the
# two test ports (trunk/tagged membership). On plain access ports the
# switch may discard tagged frames — the script detects that case
# (tagged frames never arrive: arrived_* counters stay 0) and reports
# BLOCKED instead of failing the construct.
source "$(dirname "$0")/hwlib.sh"
hw::require_root
trap hw::finish EXIT

FW=$(mktemp --suffix=.fw)
cat > "$FW" <<EOF
zone t = [$RECV_IF]

@xdp(t)

count arrived_v100 if pkt.vlan_id == 100
count arrived_v200 if pkt.vlan_id == 200
count arrived_untagged if pkt.src_ip == 10.99.5.9
drop if pkt.vlan_id == 100
default allow
EOF
hw::deploy l1-05 "$FW"

hw::sniff_start 6
hw::send 100 'udp(src_ip="10.99.5.1", dst_port=5100, vlan_id=100)'
hw::send 100 'udp(src_ip="10.99.5.2", dst_port=5200, vlan_id=200)'
hw::send 100 'udp(src_ip="10.99.5.9", dst_port=5900)'
sleep 1
hw::sniff_wait

V100=$(hw::counter arrived_v100)
V200=$(hw::counter arrived_v200)
if [ "$V100" -eq 0 ] && [ "$V200" -eq 0 ]; then
  fail "BLOCKED: tagged frames never reached $RECV_IF — check EX2300 \
tagged membership AND 'ethtool -K $RECV_IF rxvlan off' (the i350 \
strips tags in hardware before XDP otherwise)"
else
  # XDP counters prove the in-program tag match; the sniffer
  # recovers kernel-stripped tags via PACKET_AUXDATA, so passed
  # tagged frames keep their vlan<id>: key.
  assert_eq "counter arrived_v100 (tag matched in XDP)" "$V100" 100
  assert_eq "counter arrived_v200 (tag matched in XDP)" "$V200" 100
  assert_eq "wire v100 dropped" \
    "$(hw::sniff_get vlan100:udp:10.99.5.1:5100)" 0
  assert_eq "wire v200 passed (tag restored from auxdata)" \
    "$(hw::sniff_get vlan200:udp:10.99.5.2:5200)" 100
fi
assert_eq "counter arrived_untagged" "$(hw::counter arrived_untagged)" 100
assert_eq "wire untagged passed" \
  "$(hw::sniff_get udp:10.99.5.9:5900)" 100
