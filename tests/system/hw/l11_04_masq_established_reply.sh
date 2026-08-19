#!/usr/bin/env bash
# Does masquerade compose with a stateful return-path policy?
#
# The office policy is going to be, near enough verbatim:
#
#     masquerade                                  # testnets -> uplink
#     allow if conntrack(pkt).state == established  # replies come back
#     default drop                                # nothing else in
#
# Both halves are proven separately — l1_10 for conntrack, l2_03 and
# l11_01 for masquerade — but never together, because every NAT test
# so far paired masquerade with a stateless `allow if pkt.proto == tcp`.
#
# The reason to suspect they do not compose is the order of the emitted
# program (emitter._emit_program): `{prelude}{nat_denat}{body}`. The
# PRELUDE does the conntrack lookup, and it runs BEFORE the de-NAT
# pass. So a reply is looked up under the tuple it carries on the wire
# (peer -> MASQUERADE ADDRESS), while the entry was created by the
# guest's outbound SYN under the tuple it had before translation
# (GUEST -> peer). Two different keys for the same connection.
#
# ANSWERED, and the answer changed: they do compose. `fwl_snat_egress`
# now also inserts the POST-translation tuple into conntrack, so the
# key a real reply arrives carrying is a key that exists. This probe
# measured the gap before that landed; it is kept because the gap is
# one emitter edit away from returning, and the verdict block below
# reports either outcome on its own evidence.
#
# Structured as a controlled experiment: the identical conntrack policy
# is run twice, once without NAT and once with, against the identical
# traffic. If only the NAT run loses the reply, NAT is the cause.
source "$(dirname "$0")/hwlib.sh"
hw::require_root

WAN_IF="${WAN_IF:-enp1s0f2}"
MASQ_ADDR=10.99.200.2
GUEST=10.99.60.5
PEER=10.99.70.9
SPORT=41000

cleanup() {
  ip addr del "$MASQ_ADDR/24" dev "$WAN_IF" 2>/dev/null || true
  hw::finish
}
trap cleanup EXIT

ip addr add "$MASQ_ADDR/24" dev "$WAN_IF" 2>/dev/null || true

syn() {
  hw::send 20 "tcp(src_ip=\"$GUEST\", dst_ip=\"$PEER\", \
src_port=$SPORT, dst_port=443, syn=true)"
}

# --- control: the same stateful policy, no NAT ----------------------
CTRL=$(mktemp --suffix=.fw)
cat > "$CTRL" <<EOF
zone t = [$RECV_IF]

@xdp(t)

count opened if pkt.proto == tcp and pkt.tcp.syn
allow if pkt.proto == tcp and pkt.tcp.syn
count est if conntrack(pkt).state == established
allow if conntrack(pkt).state == established
default drop
EOF
hw::deploy l11-04a "$CTRL"

hw::sniff_start 8 --detail --srcport
syn
sleep 1
hw::send 20 "tcp(src_ip=\"$PEER\", dst_ip=\"$GUEST\", src_port=443, \
dst_port=$SPORT, ack=true)"
sleep 1
hw::sniff_wait

CTRL_EST=$(hw::counter est)
CTRL_BACK=$(hw::sniff_get "tcp:$PEER:443>$GUEST:$SPORT:ok")
assert_eq "control: outbound SYN opened the flow" \
  "$(hw::counter opened)" 20
assert_eq "control: the reply reads ESTABLISHED" "$CTRL_EST" 20
assert_eq "control: the reply is delivered to the guest" \
  "$CTRL_BACK" 20
pass "control established: 'allow if established' does exactly what \
it says when no NAT is involved"

# --- the same policy with masquerade in front of it -----------------
NAT=$(mktemp --suffix=.fw)
cat > "$NAT" <<EOF
zone lan = [$RECV_IF]
zone wanz = [$WAN_IF]

@xdp(lan)

count opened if pkt.proto == tcp and pkt.tcp.syn
masquerade if pkt.src_ip in 10.99.60.0/24
redirect to wanz if pkt.proto == udp and pkt.dst_port == 1
allow if pkt.proto == tcp and pkt.tcp.syn
count est if conntrack(pkt).state == established
allow if conntrack(pkt).state == established
default drop
EOF
hw::deploy l11-04b "$NAT"

journalctl -u fd -n 30 --no-pager | grep -q "masquerade address $MASQ_ADDR" \
  && pass "fd resolved the masquerade address" \
  || fail "no masquerade-address line in fd journal"

hw::sniff_start 8 --detail --srcport
syn
sleep 1
# The reply as it really arrives from the internet: addressed to the
# masquerade address, not to the guest.
hw::send 20 "tcp(src_ip=\"$PEER\", dst_ip=\"$MASQ_ADDR\", \
src_port=443, dst_port=$SPORT, ack=true)"
sleep 1
hw::sniff_wait

NAT_OUT=$(hw::sniff_get "tcp:$MASQ_ADDR:$SPORT>$PEER:443:ok")
NAT_EST=$(hw::counter est)
NAT_HOME=$(hw::sniff_get "tcp:$PEER:443>$GUEST:$SPORT:ok")
NAT_RAW=$(hw::sniff_get "tcp:$PEER:443>$MASQ_ADDR:$SPORT:ok")
CT_ENTRIES=$(hw::map_entries conntrack)
NAT_ENTRIES=$(hw::map_entries fwl_nat)

assert_eq "with NAT: outbound SYN opened the flow" \
  "$(hw::counter opened)" 20
assert_eq "with NAT: the outbound half is translated correctly" \
  "$NAT_OUT" 20
assert_eq "with NAT: the reply mapping was installed" \
  "$NAT_ENTRIES" 1
# TWO entries, and the second one is the answer to this whole probe.
# The `allow` rule inserts the tuple the packet had when it matched —
# pre-translation, (GUEST -> peer) — and `fwl_snat_egress` inserts the
# post-NAT tuple, (MASQ_ADDR -> peer). A reply from the internet
# carries the reverse of the SECOND one, which is why it now reads
# established at all. Asserting 1 here was correct only while the
# egress helper did not track the flow; the count is the mechanism,
# so it is checked rather than loosened.
assert_eq "with NAT: BOTH the pre- and post-translation tuples are in \
the conntrack table" "$CT_ENTRIES" 2

# Third leg, to make the diagnosis exact rather than merely suggestive.
# The same NAT build, the same conntrack entry, but a reply addressed
# to the GUEST instead of to the masquerade address — a packet no real
# network would produce, whose only purpose is to present the key the
# entry was actually created under. If THIS one reads established, the
# conntrack machinery is alive and correct in a NAT build and the only
# broken thing is which key a real reply arrives carrying.
EST_BEFORE=$(hw::counter est)
hw::sniff_start 6 --detail --srcport
hw::send 20 "tcp(src_ip=\"$PEER\", dst_ip=\"$GUEST\", src_port=443, \
dst_port=$SPORT, ack=true)"
sleep 1
hw::sniff_wait
DIRECT_EST=$(( $(hw::counter est) - EST_BEFORE ))
DIRECT_BACK=$(hw::sniff_get "tcp:$PEER:443>$GUEST:$SPORT:ok")
assert_eq "with NAT: a reply presenting the PRE-translation tuple \
still reads ESTABLISHED" "$DIRECT_EST" 20
assert_eq "... and is delivered" "$DIRECT_BACK" 20
pass "conntrack is intact in a NAT build under BOTH keys: the \
pre-translation tuple this leg presents, and the post-translation one \
a real reply carries. That second entry is what closed the gap"

log "=== the composition, measured ==="
log "reply: est counter $NAT_EST/20 (control was $CTRL_EST/20); \
delivered to the guest $NAT_HOME/20; left on the wire addressed to \
the masquerade address $NAT_RAW/20"

if [ "$NAT_EST" -eq 0 ] && [ "$NAT_HOME" -eq 0 ] && \
   [ "$NAT_RAW" -eq 0 ]; then
  fail "MASQUERADE AND STATEFUL RETURN DO NOT COMPOSE. Identical \
policy, identical traffic: without NAT the reply reads ESTABLISHED \
($CTRL_EST/20) and reaches the guest ($CTRL_BACK/20); with masquerade \
in front of it the reply reads NEITHER established nor anything else \
that matches — 0/20 — and is dropped by \`default drop\`. Both halves \
of the state are present and correct (conntrack $CT_ENTRIES entry, \
fwl_nat $NAT_ENTRIES mapping); they are simply keyed differently. The \
conntrack lookup lives in the prelude and the de-NAT runs after it, so \
the reply is looked up as (peer -> $MASQ_ADDR) while the entry was \
created as ($GUEST -> peer). This is the exact policy the office \
deployment needs, and it black-holes every reply."
elif [ "$NAT_EST" -gt 0 ] && [ "$NAT_HOME" -gt 0 ]; then
  pass "they compose: the reply read ESTABLISHED ($NAT_EST/20) and \
was delivered de-NATed to the guest ($NAT_HOME/20)"
else
  fail "partial/unreadable result: est=$NAT_EST home=$NAT_HOME \
raw=$NAT_RAW — investigate before drawing a conclusion"
fi

# ---------------------------------------------------------------------
# Fourth leg: the office policy, on a routed path, proved by ACCEPTANCE.
#
# Everything above is crafted frames witnessed by a promiscuous
# AF_PACKET socket on the interface they arrived on. That is exactly
# the right instrument for the question those legs ask — which conntrack
# key a reply is looked up under — and it is the wrong instrument for
# "does this policy carry a network", because it counts frames a real
# stack drops and it never required the packet to leave the box at all.
#
# So the composition the office actually deploys gets asserted the other
# way: two real Linux hosts either side, neither promiscuous, and a TCP
# exchange that has to complete. Nothing here can pass on a frame that
# was addressed to the wrong MAC, or that was never forwarded.
# ---------------------------------------------------------------------
PARENT="${SEND_IF}"
WAN_VLAN="${WAN_VLAN:-802}"
LAN_ADDR=10.99.60.1
RGUEST=10.99.60.5
RSERVER=10.99.200.9
RPORT=8443
FWD_SAVED=""
ip addr add "$LAN_ADDR/24" dev "$RECV_IF" 2>/dev/null || true

OFFICE=$(mktemp --suffix=.fw)
cat > "$OFFICE" <<EOF3
zone lan = [$RECV_IF]
zone wanz = [$WAN_IF]

@xdp(lan)

count out_new if pkt.proto == tcp and pkt.tcp.syn
masquerade if pkt.src_ip in 10.99.60.0/24
redirect to wanz if pkt.src_ip in 10.99.60.0/24
allow

@xdp(wanz)

count back_est if conntrack(pkt).state in [established, related]
redirect to lan if conntrack(pkt).state in [established, related]
default drop
EOF3
hw::deploy l11-04c "$OFFICE"
hw::host_up oguest "$PARENT" none "$RGUEST/24" "$LAN_ADDR"
hw::host_up oserver "$PARENT" "$WAN_VLAN" "$RSERVER/24"
FWD_SAVED=$(hw::forwarding 1)
ping -c1 -W2 -I "$RECV_IF" "$RGUEST" >/dev/null 2>&1 || true
ping -c1 -W2 -I "$WAN_IF" "$RSERVER" >/dev/null 2>&1 || true

hw::server_start oserver "$RSERVER" "$RPORT" 8 25
OFFICE_CLIENT=$(hw::client oguest "$RSERVER" "$RPORT" 8 4)
hw::server_wait
log "office client: $OFFICE_CLIENT"
log "office server: $(cat "$SERVER_OUT")"

assert_eq "office policy: the far side ACCEPTED every connection" \
  "$(hw::server_get accepted)" 8
assert_eq "office policy: every exchange completed end to end" \
  "$(hw::jget "$OFFICE_CLIENT" completed)" 8
assert_str "office policy: the server saw only the masquerade address" \
  "$(hw::server_get peer_addrs)" "$MASQ_ADDR"
# The return direction crossed `default drop` on the strength of the
# conntrack state alone. Without the post-translation tuple this probe
# was written to measure, this number is 0 and nothing above completes.
assert_eq "office policy: the replies were admitted as established" \
  "$([ "$(hw::counter back_est)" -gt 0 ] && echo 1 || echo 0)" 1
assert_eq "office policy: the datapath ROUTED both directions" \
  "$([ "$(hw::route routed)" -gt 0 ] && echo 1 || echo 0)" 1
echo "$FWD_SAVED" > /proc/sys/net/ipv4/ip_forward
ip addr del "$LAN_ADDR/24" dev "$RECV_IF" 2>/dev/null || true
