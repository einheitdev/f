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
assert_eq "with NAT: the flow IS in the conntrack table" \
  "$CT_ENTRIES" 1

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
pass "conntrack itself is intact in a NAT build — the entry is there \
and readable. The only thing wrong is which key a real reply carries"

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
