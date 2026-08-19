#!/usr/bin/env bash
# Two documented IPv6 semantics with real operational teeth.
#
# PHASE A — a program touching no IPv6 surface is "v0.1-shaped":
# it parses IPv4 only, so an IPv6 frame matches no rule. The spec is
# explicit about where such a frame ends up:
#
#   "Frames with EtherType 0x86DD (IPv6) fall through every rule,
#    exactly as in v0.1, and reach the default action."
#                                        (FWL_V02_SPEC.md:937)
#
# So `default drop` must DROP IPv6. The emitter's non-IP early-out
# used to swallow them first, making a deny-all policy forward 100%
# of IPv6 traffic — verified on this rig at 100/100 before the fix.
# The early-out exists to protect ARP/BPDU (soak Incident #3), which
# is right; it simply must not apply to IPv6, which is IP.
#
# PHASE B — with the v6 path activated (one `pkt.src_ip6` rule is
# enough), the same frames become subject to the rules. Conntrack,
# however, stays IPv4-only in v0.4 (FWL_V04_SPEC § Conntrack: "On an
# IPv6 frame conntrack(pkt).state is always `new`"), so a v6 reply
# never reads established while the identical v4 exchange does.
source "$(dirname "$0")/hwlib.sh"
hw::require_root
trap hw::finish EXIT

V6_SYN='tcp6(src_ip="2001:db8:99:aa::1", dst_ip="2001:db8:99:aa::9", src_port=44000, dst_port=80, syn=true)'
V6_REPLY='tcp6(src_ip="2001:db8:99:aa::9", dst_ip="2001:db8:99:aa::1", src_port=80, dst_port=44000, ack=true)'
V4_SYN='tcp(src_ip="10.99.13.1", dst_ip="10.99.13.9", src_port=44000, dst_port=80, syn=true)'
V4_REPLY='tcp(src_ip="10.99.13.9", dst_ip="10.99.13.1", src_port=80, dst_port=44000, ack=true)'

# ---------- PHASE A: v0.1-shaped deny-all ----------
FW=$(mktemp --suffix=.fw)
cat > "$FW" <<EOF
zone t = [$RECV_IF]

@xdp(t)

count seen_v4 if pkt.src_ip in 10.99.13.0/24
default drop
EOF
hw::deploy l1-13a "$FW"

hw::sniff_start 6
hw::send 100 "$V4_SYN"
hw::send 100 "$V6_SYN"
sleep 1
hw::sniff_wait

assert_eq "deny-all: v4 frames seen by the program" \
  "$(hw::counter seen_v4)" 100
assert_eq "deny-all: v4 frames DROPPED as intended" \
  "$(hw::sniff_get tcp:10.99.13.1:80)" 0
assert_eq "deny-all WITHOUT a v6 rule: IPv6 reaches the default \
action and is DROPPED (FWL_V02_SPEC:937; regression witness for the \
early-out that used to forward all IPv6)" \
  "$(hw::sniff_get 'tcp6:2001:db8:99:aa::1:80')" 0

# ---------- PHASE B: v6 path activated ----------
cat > "$FW" <<EOF
zone t = [$RECV_IF]

@xdp(t)

count v6_seen if pkt.src_ip6 in 2001:db8:99::/48
count est_hits if conntrack(pkt).state == established
allow if conntrack(pkt).state == established
count initiator if pkt.proto == tcp and pkt.tcp.syn and not pkt.tcp.ack
allow if pkt.proto == tcp and pkt.tcp.syn and not pkt.tcp.ack
default drop
EOF
hw::deploy l1-13b "$FW"

hw::sniff_start 10
hw::send 1 "$V4_SYN"
hw::send 1 "$V6_SYN"
sleep 1
hw::send 50 "$V4_REPLY"
hw::send 50 "$V6_REPLY"
sleep 1
hw::sniff_wait

assert_eq "activated: v6 frames now parsed" "$(hw::counter v6_seen)" 51
assert_eq "activated: both SYNs matched the tcp rule" \
  "$(hw::counter initiator)" 2
assert_eq "activated: established hits are v4-only (v0.4 limit)" \
  "$(hw::counter est_hits)" 50
assert_eq "wire: v4 reply passed via conntrack" \
  "$(hw::sniff_get tcp:10.99.13.9:44000)" 50
assert_eq "wire: v6 reply DROPPED — no v6 conntrack in v0.4" \
  "$(hw::sniff_get 'tcp6:2001:db8:99:aa::9:44000')" 0
assert_eq "wire: v6 SYN passed via the explicit tcp rule" \
  "$(hw::sniff_get 'tcp6:2001:db8:99:aa::1:80')" 1
