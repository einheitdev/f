#!/usr/bin/env bash
# Test-plan L1 row 10: conntrack state — established-only inbound.
# The state machine on real wire, order-dependent:
#   phase 0: replies BEFORE any flow exists -> dropped (no entry)
#   phase 1: initiator SYN allowed by explicit rule -> creates entry
#   phase 2: the same replies now read established -> pass
#   phase 3: unrelated new inbound -> still dropped
source "$(dirname "$0")/hwlib.sh"
hw::require_root
trap hw::finish EXIT

FW=$(mktemp --suffix=.fw)
cat > "$FW" <<EOF
zone t = [$RECV_IF]

@xdp(t)

count est_pass if conntrack(pkt).state == established
allow if conntrack(pkt).state == established
count initiated if pkt.src_ip == 10.99.10.1 and pkt.proto == tcp
       and pkt.tcp.syn
allow if pkt.src_ip == 10.99.10.1 and pkt.proto == tcp
       and pkt.tcp.syn
count dropped_rest
default drop
EOF
hw::deploy l1-10 "$FW"

REPLY='tcp(src_ip="10.99.10.9", dst_ip="10.99.10.1", src_port=80, dst_port=41000, syn=true, ack=true)'
INIT='tcp(src_ip="10.99.10.1", dst_ip="10.99.10.9", src_port=41000, dst_port=80, syn=true)'
OTHER='tcp(src_ip="10.99.10.3", dst_ip="10.99.10.1", src_port=4444, dst_port=41000, syn=true)'

hw::sniff_start 10

# Phase 0: replies with no conntrack entry — must be dropped.
hw::send 20 "$REPLY"
sleep 1
P0_EST=$(hw::counter est_pass)
assert_eq "phase 0: no established hits yet" "$P0_EST" 0

# Phase 1: the initiator's SYN — explicit allow creates the entry.
hw::send 1 "$INIT"

# Phase 2: the same replies — reverse-tuple hit, established, pass.
hw::send 100 "$REPLY"

# Phase 3: unrelated inbound — no entry, no allow rule, dropped.
hw::send 50 "$OTHER"
sleep 1
hw::sniff_wait

assert_eq "initiator SYN allowed" "$(hw::counter initiated)" 1
assert_eq "established replies counted" "$(hw::counter est_pass)" 100
assert_eq "wire: pre-entry replies dropped, post-entry passed" \
  "$(hw::sniff_get tcp:10.99.10.9:41000)" 100
assert_eq "wire: initiator SYN passed" \
  "$(hw::sniff_get tcp:10.99.10.1:80)" 1
assert_eq "wire: unrelated inbound dropped" \
  "$(hw::sniff_get tcp:10.99.10.3:41000)" 0
