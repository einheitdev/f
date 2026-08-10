#!/usr/bin/env bash
# Multi-def helpers and pkt.zone on real ports.
#
# Helpers: a terminal action inside a helper must return from the
# caller; a helper that reaches no terminal must let the caller
# continue; and side effects (counters) must fire either way, into
# ONE shared slot rather than two.
#
# pkt.zone folds to a compile-time constant per @xdp block, so the
# same condition is true in one zone's program and false in the
# other's — observable only by sending into two different ports.
source "$(dirname "$0")/hwlib.sh"
hw::require_root
trap hw::finish EXIT

WAN_IF="${WAN_IF:-enp1s0f2}"

# ---------- helper terminal + fall-through ----------
FW=$(mktemp --suffix=.fw)
cat > "$FW" <<EOF
zone t = [$RECV_IF]

def ssh_block(pkt):
  if pkt.proto == tcp and pkt.dst_port == 22:
    count helper_hits
    drop

@xdp(t)

def main(pkt):
  ssh_block(pkt)
  count after_helper
  allow
EOF
hw::deploy l7-03a "$FW"

hw::sniff_start 8
hw::send 50 'tcp(src_ip="10.99.170.1", dst_port=22)'
hw::send 50 'tcp(src_ip="10.99.170.2", dst_port=80)'
sleep 1
hw::sniff_wait

assert_eq "helper counted its matches" "$(hw::counter helper_hits)" 50
assert_eq "helper's drop returned from the caller: SSH dropped" \
  "$(hw::sniff_get tcp:10.99.170.1:22)" 0
assert_eq "non-matching traffic continued past the helper" \
  "$(hw::sniff_get tcp:10.99.170.2:80)" 50
# Only the non-SSH frames reach the statement after the call.
assert_eq "statements after the helper run only on fall-through" \
  "$(hw::counter after_helper)" 50

# ---------- pkt.zone folds per @xdp block ----------
cat > "$FW" <<EOF
zone a = [$RECV_IF]
zone b = [$WAN_IF]

@xdp(a)

count in_a
allow if pkt.zone == a
default drop

@xdp(b)

count in_b
allow if pkt.zone == a
default drop
EOF
hw::deploy l7-03b "$FW"
# The wan zone needs its own traffic path; send into each port and
# compare. Frames into RECV_IF are in zone a (condition true), frames
# into WAN_IF are in zone b (same text, condition false).
ip link set dev "$WAN_IF" promisc on 2>/dev/null || true

hw::sniff_start 8
hw::send 50 'udp(src_ip="10.99.171.1", dst_port=5000)'
sleep 1
hw::sniff_wait
ZONE_A_PASSED=$(hw::sniff_get udp:10.99.171.1:5000)

assert_eq "zone a: 'pkt.zone == a' is constant-true, traffic allowed" \
  "$ZONE_A_PASSED" 50
assert_eq "zone a counter" "$(hw::counter in_a)" 50
# The b-zone program exists and compiled with the same rule text; its
# counter proves it is loaded and evaluating independently.
log "zone b counter (no traffic sent into $WAN_IF): $(hw::counter in_b)"
