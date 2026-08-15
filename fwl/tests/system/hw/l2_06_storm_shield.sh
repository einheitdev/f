#!/usr/bin/env bash
# Test-plan L2 row 5: storm_shield.fw — the dogfood policy on copper.
#
# Deploys the real example (interface names adapted): wan zone on the
# receive port eats the broadcast-domain firehose; lan zone sits on
# the second data port (idle here — its masquerade+redirect path is
# covered by l2_01/l2_03).
#
# NOTE: the lan block of storm_shield.fw now carries the appliance's
# own testnet address (10.99.82.1) and that segment's directed
# broadcast, because without them a client's DHCP DISCOVER was
# masqueraded and broadcast onto the uplink (A3). This test only sends
# on the wan side, so the sed below does not rewrite those; a rig run
# that exercises the lan side must set them to the rig's own segment.
# The interpreter/BPF coverage of that ordering is
# tests/corpus/25_local_delivery and tests/unit/test_examples.py.
#
# The last assertion is a CONTROL, not a known gap. It used to be a
# gap: in v0.4 bundle mode the lan program (masquerade + redirect)
# created no conntrack entry, so `allow if conntrack(pkt).state ==
# established` on the wan side could never match and every reply was
# de-NATed and then dropped. That is closed -- `fwl_snat_egress` now
# inserts the post-NAT tuple as the NAT mapping's reclamation anchor,
# and that entry is exactly what the wan zone's conntrack lookup
# finds. Verified end to end on 2026-08-14: a far-side SYN-ACK to a
# masqueraded flow crosses `default drop` and is de-NATed home.
#
# So the frame this test sends is dropped for the RIGHT reason now --
# nothing on the testnet initiated it -- and the assertion below is
# what would catch a policy that started admitting unsolicited
# replies. Do not read it as a pinned defect.
source "$(dirname "$0")/hwlib.sh"
hw::require_root
trap hw::finish EXIT

LAN_IF="${LAN_IF:-enp1s0f2}"
FW=$(mktemp --suffix=.fw)
sed -e "s/\bwan0\b/$RECV_IF/g" -e "s/\blan0\b/$LAN_IF/g" \
  /opt/fwl/examples/storm_shield.fw > "$FW"
hw::deploy l2-06 "$FW"

hw::sniff_start 8
# The plant-floor firehose, as unicast MACs through the switch:
hw::send 100 'udp(src_ip="10.99.40.1", dst_ip="239.255.255.250", dst_port=1900)'
hw::send 100 'udp(src_ip="10.99.40.1", dst_ip="255.255.255.255", dst_port=7437)'
hw::send 100 'udp(src_ip="10.99.40.2", dst_ip="10.99.40.9", dst_port=137)'
# A DHCP offer (broadcast reply from a server) must survive:
hw::send 20 'udp(src_ip="10.99.40.3", dst_ip="255.255.255.255", src_port=67, dst_port=68)'
# An unsolicited "reply" — no testnet flow initiated it:
hw::send 50 'tcp(src_ip="10.99.40.9", dst_ip="10.99.40.2", src_port=443, dst_port=52000, syn=true, ack=true)'
sleep 1
hw::sniff_wait

# The multicast/broadcast counters legitimately catch ambient VLAN
# noise (IGMP, mDNS) on top of the test frames — small headroom.
assert_range "counter noise_multicast" \
  "$(hw::counter noise_multicast)" 100 115
assert_range "counter noise_broadcast" \
  "$(hw::counter noise_broadcast)" 120 135
assert_eq "counter noise_netbios" "$(hw::counter noise_netbios)" 100
assert_range "counter wan_total (all of the above)" \
  "$(hw::counter wan_total)" 370 400
assert_eq "wire: SSDP dead" \
  "$(hw::sniff_get udp:10.99.40.1:1900)" 0
assert_eq "wire: broadcast dead" \
  "$(hw::sniff_get udp:10.99.40.1:7437)" 0
assert_eq "wire: NetBIOS dead" \
  "$(hw::sniff_get udp:10.99.40.2:137)" 0
assert_eq "wire: DHCP offer survives" \
  "$(hw::sniff_get udp:10.99.40.3:68)" 20
# The documented gap: replies cannot become established in v0.4.
assert_eq "wire: unsolicited reply dropped (v0.4 gap: NO flow can \
be established — see header)" \
  "$(hw::sniff_get tcp:10.99.40.9:52000)" 0
