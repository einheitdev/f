#!/usr/bin/env bash
# CEILING PROBE: where does masquerade stop being able to multiplex
# several hosts behind one address, and what does it do at that point?
#
# The office deployment is several testnets behind one masquerade
# address, all browsing. The intuitive ceiling is "65535 ephemeral
# ports". It is not. v0.4 masquerade is PORT-PRESERVING (spec § NAT:
# "the translated source port equals the original ... ephemeral-port
# reallocation on collision is Phase 5.3"), so the reply mapping is
# keyed on the tuple the packet already had:
#
#   key   = (peer_addr, masq_addr, peer_port, ORIGINAL src_port, proto)
#   value = (original src_addr, original src_port)
#
# Two hosts that happen to pick the same ephemeral source port toward
# the same destination produce the SAME key with DIFFERENT values, and
# the install is BPF_ANY — an overwrite. The ceiling is therefore not
# a pool running out, it is the FIRST source-port collision between
# any two hosts talking to the same destination. This test drives that
# collision deliberately and records what happens to the first host's
# return traffic.
#
# Deliberately structured so nothing can pass vacuously: the same
# reply frame, byte for byte, is sent twice — once before the
# collision and once after — and the assertion is on which host it is
# delivered to each time.
source "$(dirname "$0")/hwlib.sh"
hw::require_root

WAN_IF="${WAN_IF:-enp1s0f2}"
MASQ_ADDR=10.99.200.2
HOST_A=10.99.30.5
HOST_B=10.99.31.5
PEER=10.99.35.9
SPORT=40000

cleanup() {
  ip addr del "$MASQ_ADDR/24" dev "$WAN_IF" 2>/dev/null || true
  hw::finish
}
trap cleanup EXIT

ip addr add "$MASQ_ADDR/24" dev "$WAN_IF" 2>/dev/null || true

FW=$(mktemp --suffix=.fw)
cat > "$FW" <<EOF
zone lan = [$RECV_IF]
zone wanz = [$WAN_IF]

@xdp(lan)

count egress_a if pkt.src_ip == $HOST_A
count egress_b if pkt.src_ip == $HOST_B
count replies if pkt.src_ip == $PEER
masquerade if pkt.src_ip in 10.99.30.0/23
redirect to wanz if pkt.proto == udp and pkt.dst_port == 1
allow if pkt.proto == tcp
default drop
EOF
hw::deploy l11-01 "$FW"

journalctl -u fd -n 30 --no-pager | grep -q "masquerade address $MASQ_ADDR" \
  && pass "fd resolved the masquerade address from the wan zone" \
  || fail "no masquerade-address line in fd journal"

egress() {
  hw::send 20 "tcp(src_ip=\"$1\", dst_ip=\"$PEER\", src_port=$SPORT, \
dst_port=443, syn=true)"
}

# The reply is IDENTICAL in both rounds: source $PEER:443, destination
# the masquerade address, destination port $SPORT. Nothing in it names
# host A or host B — that is exactly the information a port-preserving
# NAT has thrown away.
reply() {
  hw::send 20 "tcp(src_ip=\"$PEER\", dst_ip=\"$MASQ_ADDR\", \
src_port=443, dst_port=$SPORT, ack=true)"
}

# --- round 1: host A alone -----------------------------------------
hw::sniff_start 8 --detail --srcport
egress "$HOST_A"
sleep 1
reply
sleep 1
hw::sniff_wait

A_OUT=$(hw::sniff_get "tcp:$MASQ_ADDR:$SPORT>$PEER:443:ok")
A_BACK=$(hw::sniff_get "tcp:$PEER:443>$HOST_A:$SPORT:ok")
B_BACK=$(hw::sniff_get "tcp:$PEER:443>$HOST_B:$SPORT:ok")
NAT_ENTRIES_1=$(hw::map_entries fwl_nat)

assert_eq "counter egress_a" "$(hw::counter egress_a)" 20
assert_eq "wire: host A's source translated to the masq address" \
  "$A_OUT" 20
assert_eq "wire: A's reply de-NATed to host A" "$A_BACK" 20
assert_eq "wire: A's reply did NOT go to host B" "$B_BACK" 0
assert_eq "one reply mapping installed" "$NAT_ENTRIES_1" 1
log "PORT PRESERVATION: host A used source port $SPORT and left as \
$MASQ_ADDR:$SPORT — the translated port equals the original, so the \
mapping is keyed on a port the guest chose, not one the NAT owns."

# --- round 2: host B collides on the same source port ---------------
# Nothing exotic: two hosts picking the same ephemeral port toward the
# same destination. On a testnet browsing the same CDN this is a
# birthday problem over the ~28k-port Linux ephemeral range.
hw::sniff_start 8 --detail --srcport
egress "$HOST_B"
sleep 1
reply
sleep 1
hw::sniff_wait

B_OUT=$(hw::sniff_get "tcp:$MASQ_ADDR:$SPORT>$PEER:443:ok")
A_BACK2=$(hw::sniff_get "tcp:$PEER:443>$HOST_A:$SPORT:ok")
B_BACK2=$(hw::sniff_get "tcp:$PEER:443>$HOST_B:$SPORT:ok")
NAT_ENTRIES_2=$(hw::map_entries fwl_nat)

assert_eq "counter egress_b" "$(hw::counter egress_b)" 20
assert_eq "wire: host B also left as $MASQ_ADDR:$SPORT (no port \
reallocation on collision)" "$B_OUT" 20
assert_eq "the colliding flow did NOT get its own mapping" \
  "$NAT_ENTRIES_2" 1

# The measurement. The same reply frame now resolves to a different
# host. Assert the observed behaviour rather than a hoped-for one:
# this test exists to RECORD the ceiling, so it fails only if the
# evidence is unreadable, not because the ceiling is where it is.
log "=== behaviour at the ceiling ==="
log "identical reply frame ($PEER:443 -> $MASQ_ADDR:$SPORT): \
round 1 delivered to A x$A_BACK / B x$B_BACK; \
round 2 delivered to A x$A_BACK2 / B x$B_BACK2"

if [ "$B_BACK2" -gt 0 ] && [ "$A_BACK2" -eq 0 ]; then
  pass "CEILING MEASURED — host B's egress packet silently \
overwrote host A's reply mapping. Host A's return traffic is now \
delivered to host B ($B_BACK2/20), and host A receives none ($A_BACK2/20). \
The failure is not a refusal and not a drop: it is MISDELIVERY of one \
tenant's inbound TCP payload to another tenant behind the same \
masquerade address. Nothing is logged, no counter moves, and host A \
sees a connection that simply stops."
elif [ "$A_BACK2" -gt 0 ] && [ "$B_BACK2" -eq 0 ]; then
  fail "unexpected: the mapping survived the collision. Either the \
build allocates ports after all (spec says it does not) or the \
collision did not happen — re-check the test before believing it."
else
  fail "the reply reached neither host (A=$A_BACK2 B=$B_BACK2): the \
evidence is unreadable, so nothing is measured here"
fi

# --- what the ceiling is worth in numbers ---------------------------
# Linux picks ephemeral ports from 32768-60999 (28232 values). For N
# concurrent flows from distinct hosts to the SAME destination
# address+port, the chance that some pair collides is the birthday
# bound 1 - prod(1 - i/28232).
$PY - <<'EOF'
POOL = 60999 - 32768 + 1
print(f"[l11_01] ephemeral pool per (dst_ip, dst_port): {POOL}")
for n in (50, 100, 200, 400, 800):
  p = 1.0
  for i in range(n):
    p *= (POOL - i) / POOL
  print(f"[l11_01]   {n:4d} concurrent flows to one destination -> "
        f"{(1 - p) * 100:5.1f}% chance of at least one collision")
EOF
log "Read that against the deployment: several testnets browsing means \
hundreds of concurrent flows to a handful of popular destination \
addresses on port 443. The ceiling is reached in normal use, not \
under attack."
