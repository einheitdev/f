#!/usr/bin/env bash
# Two hosts behind one masquerade address pick the same ephemeral port
# toward the same destination. Whose reply is it?
#
# This was a ceiling probe and its answer was the worst kind. v0.4
# masquerade was port-preserving with no fallback, so the reply mapping
# was keyed on the tuple the packet already had:
#
#   key   = (peer_addr, masq_addr, peer_port, ORIGINAL src_port, proto)
#
# Two hosts sharing an ephemeral port to one destination produced the
# SAME key with DIFFERENT values, and the install was BPF_ANY — an
# overwrite. Measured here on the wire: the identical reply frame went
# to host A 20/20 before the collision and to host B 20/20 after. Not a
# refusal and not a drop — MISDELIVERY of one tenant's inbound TCP
# payload to another, with nothing logged and no counter moving. At the
# ~28k-port Linux ephemeral range that is a coin flip at 200 concurrent
# flows to one destination: normal browsing, not an attack.
#
# The install is now BPF_NOEXIST, so a collision is DETECTED. The port
# is preserved when the key is free — that preference was never the
# defect — and when it is not, the mapping is moved to a port in the
# NAT-owned range 49152-65535 and the source port is rewritten with it.
# The two flows end up with two keys, so the two replies are no longer
# the same frame at all.
#
# The test keeps its original shape, because that shape is what made
# the defect visible: the same reply frame, byte for byte, sent before
# and after the collision, with the assertion on which host receives
# it. What changed is that the second round now also asserts the
# SECOND host's own reply arrives — and, above all, that host A's
# mapping is untouched.
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
REALLOC_BEFORE=$(hw::nat port_reallocated)
hw::sniff_start 8 --detail --srcport
egress "$HOST_B"
sleep 1
reply
sleep 1
hw::sniff_wait

B_OUT_SAME=$(hw::sniff_get "tcp:$MASQ_ADDR:$SPORT>$PEER:443:ok")
A_BACK2=$(hw::sniff_get "tcp:$PEER:443>$HOST_A:$SPORT:ok")
B_BACK2=$(hw::sniff_get "tcp:$PEER:443>$HOST_B:$SPORT:ok")
NAT_ENTRIES_2=$(hw::map_entries fwl_nat)
REALLOC_AFTER=$(hw::nat port_reallocated)

assert_eq "counter egress_b" "$(hw::counter egress_b)" 20

# The port host B actually left on. Read it off the wire rather than
# recomputing the emitter's hash here: a test that derives the expected
# port from the same function it is testing asserts nothing about it.
# Keys are "<proto>:<src_ip>:<src_port>><dst_ip>:<dst_port>:ok".
B_PORT=$($PY -c "
import json
with open('$SNIFF_OUT') as fh:
  seen = json.load(fh)
best, port = 0, 0
for key, n in seen.items():
  if not key.startswith('tcp:$MASQ_ADDR:'):
    continue
  sport = int(key.split(':')[2].split('>')[0])
  if key.split('>', 1)[1].startswith('$PEER:443') and n > best:
    best, port = n, sport
print(port if best >= 20 else 0)
")
log "host B left as $MASQ_ADDR:$B_PORT, host A holds $MASQ_ADDR:$SPORT"

# --- the assertions that replaced the ceiling ------------------------
assert_eq "wire: host B did NOT reuse host A's translated port" \
  "$B_OUT_SAME" 0
assert_range "wire: host B's port came from the NAT-owned range" \
  "$B_PORT" 49152 65535
assert_eq "the colliding flow got its OWN mapping" "$NAT_ENTRIES_2" 2
if [ "$REALLOC_AFTER" -gt "$REALLOC_BEFORE" ]; then
  pass "the reallocation is COUNTED and readable from fctl status \
($REALLOC_BEFORE -> $REALLOC_AFTER)"
else
  fail "a port was reallocated on the wire but fctl status counted \
none ($REALLOC_BEFORE -> $REALLOC_AFTER): the datapath and the \
reporting disagree"
fi

# The measurement that used to record the defect. The identical reply
# frame is sent again; it must still belong to host A, because host A
# is the only flow holding that key.
log "=== the same reply frame, after the collision ==="
log "identical reply frame ($PEER:443 -> $MASQ_ADDR:$SPORT): \
round 1 delivered to A x$A_BACK / B x$B_BACK; \
round 2 delivered to A x$A_BACK2 / B x$B_BACK2"
assert_eq "wire: A's reply STILL reaches host A after the collision" \
  "$A_BACK2" 20
assert_eq "wire: A's reply never reaches host B" "$B_BACK2" 0

# ...and host B's own reply, addressed to the port it was given, has
# to arrive too. Without this the test would pass on a build that
# simply dropped every colliding flow.
hw::sniff_start 8 --detail --srcport
hw::send 20 "tcp(src_ip=\"$PEER\", dst_ip=\"$MASQ_ADDR\", \
src_port=443, dst_port=$B_PORT, ack=true)"
sleep 1
hw::sniff_wait
B_HOME=$(hw::sniff_get "tcp:$PEER:443>$HOST_B:$SPORT:ok")
A_STEAL=$(hw::sniff_get "tcp:$PEER:443>$HOST_A:$SPORT:ok")
assert_eq "wire: B's reply de-NATs to host B on its ORIGINAL port" \
  "$B_HOME" 20
assert_eq "wire: B's reply does not leak to host A" "$A_STEAL" 0

pass "NO MISDELIVERY — two hosts, one ephemeral port, one \
destination, and each reply reaches the host that opened the \
connection. The old build delivered the identical frame to A 20/20 \
before the collision and to B 20/20 after; the mapping is now claimed \
with BPF_NOEXIST, so the second flow is moved to its own key instead \
of taking over the first's."

# --- what the collision rate is, now that it is handled -------------
# Linux picks ephemeral ports from 32768-60999 (28232 values). For N
# concurrent flows from distinct hosts to the SAME destination
# address+port, the chance that some pair collides is the birthday
# bound 1 - prod(1 - i/28232). These are no longer misdeliveries —
# they are reallocations, and the fctl counter above is where an
# operator sees how many.
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
addresses on port 443. Collisions happen in normal use — they are now \
resolved and counted rather than silently misdelivered."
