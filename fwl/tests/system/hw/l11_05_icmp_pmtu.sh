#!/usr/bin/env bash
# ICMP and path-MTU: the failure that presents as "the network is
# slow" and never as a firewall fault.
#
# Small packets work, DNS works, a browser mostly works, and then
# someone moves a large file and TCP hangs with nothing logged
# anywhere. The mechanism is always the same: a hop on the path cannot
# carry the sender's segment, the router that would say so sends an
# ICMP "fragmentation needed" (type 3 code 4) carrying the next-hop
# MTU, and something in between drops it. The sender never learns, and
# retransmits the same too-large segment until it gives up.
#
# Four questions, in the order they bite:
#
#   1. Does a large real TCP transfer cross `f` at all? Every wire
#      test so far sends crafted 54-byte frames; nothing has pushed a
#      full-size stream through the XDP program.
#   2. With the path MTU constrained, does it hang? (It must, or the
#      rest of this measures nothing.)
#   3. Is the ICMP that would fix it ADMITTED by a realistic stateful
#      policy?
#   4. Behind masquerade, is it STEERED to the host that owns the
#      flow? An ICMP error names its flow in its payload, not in its
#      own header, so a NAT has to read one header deeper.
#
# Parts 1-2 need a real TCP stack on each end of the wire. Both i350
# ports are on the same machine, so a socket between them would go
# over loopback and never touch the switch; the send port is therefore
# moved into a network namespace, which forces the traffic onto the
# copper.
source "$(dirname "$0")/hwlib.sh"
hw::require_root

WAN_IF="${WAN_IF:-enp1s0f2}"
MASQ_ADDR=10.99.200.2
GUEST=10.99.61.5
PEER=10.99.71.9
SPORT=41500
NS=fpmtu
NS_ADDR=10.99.90.1
HOST_ADDR=10.99.90.9
XFER_MB=200

cleanup() {
  # Deleting the namespace returns any physical interface inside it to
  # the root namespace. Do it unconditionally: leaving $SEND_IF in a
  # namespace would make the smoke policy fail to attach and would
  # leave the rig broken for the next person to walk up to it.
  ip netns del "$NS" 2>/dev/null || true
  sleep 1
  ip link set dev "$SEND_IF" up 2>/dev/null || true
  ip link set dev "$RECV_IF" mtu 1500 2>/dev/null || true
  ip addr flush dev "$RECV_IF" 2>/dev/null || true
  ip addr del "$MASQ_ADDR/24" dev "$WAN_IF" 2>/dev/null || true
  if ! ip link show "$SEND_IF" >/dev/null 2>&1; then
    fail "ABORT: $SEND_IF did not come back from namespace $NS — \
the rig needs attention before the next test"
  fi
  hw::finish
}
trap cleanup EXIT

# ====================================================================
# Parts 3 and 4 first: they use the ordinary crafted-frame path, which
# needs $SEND_IF still in the root namespace.
# ====================================================================
ip addr add "$MASQ_ADDR/24" dev "$WAN_IF" 2>/dev/null || true

FW=$(mktemp --suffix=.fw)
cat > "$FW" <<EOF
zone lan = [$RECV_IF]
zone wanz = [$WAN_IF]

@xdp(lan)

count opened if pkt.proto == tcp and pkt.tcp.syn
count icmp_unreach if pkt.proto == icmp and pkt.icmp.type == 3
masquerade if pkt.src_ip in 10.99.61.0/24
redirect to wanz if pkt.proto == udp and pkt.dst_port == 1
allow if pkt.proto == tcp and pkt.tcp.syn
allow if conntrack(pkt).state == established
default drop
EOF
hw::deploy l11-05 "$FW"

# Open a masqueraded flow so there is something for the error to be
# about, and so a NAT has a mapping it could use to steer it.
hw::send 20 "tcp(src_ip=\"$GUEST\", dst_ip=\"$PEER\", \
src_port=$SPORT, dst_port=443, syn=true)"
sleep 1
assert_eq "a masqueraded flow is open" "$(hw::counter opened)" 20
assert_eq "its reply mapping exists" "$(hw::map_entries fwl_nat)" 1

# The frag-needed a router on the path would send: from the router's
# own address, to the address it saw as the source — the MASQUERADE
# address — carrying next-hop MTU 1400 and the first 28 bytes of the
# datagram it could not forward.
hw::sniff_start 8 --detail --srcport
$PY "$HERE/sendraw.py" "$SEND_IF" 20 icmperr \
  src_ip=10.99.71.254 dst_ip="$MASQ_ADDR" type=3 code=4 mtu=1400 \
  orig_src="$MASQ_ADDR" orig_dst="$PEER" orig_sport="$SPORT" \
  orig_dport=443 orig_len=1500
sleep 1
hw::sniff_wait

ICMP_SEEN=$(hw::counter icmp_unreach)
ICMP_TO_MASQ=$(hw::sniff_get "icmp:10.99.71.254>$MASQ_ADDR:3.4")
ICMP_TO_GUEST=$(hw::sniff_get "icmp:10.99.71.254>$GUEST:3.4")

assert_eq "the error did reach the datapath (counter)" \
  "$ICMP_SEEN" 20
log "=== ICMP frag-needed, measured ==="
log "admitted to the wire: to the masquerade address \
$ICMP_TO_MASQ/20, steered to the guest $ICMP_TO_GUEST/20"

if [ "$ICMP_TO_MASQ" -eq 0 ] && [ "$ICMP_TO_GUEST" -eq 0 ]; then
  fail "ICMP UNREACHABLE IS DROPPED by a realistic stateful policy. \
The datapath saw all 20 (counter $ICMP_SEEN) and passed none. \
conntrack keys on (addresses, PORTS, proto) and an ICMP error has no \
ports, so its key is (router, firewall, 0, 0, 1) — which matches \
nothing, reads NEW, and falls to \`default drop\`. There is no rule an \
operator could write to fix this and still be stateful: \
\`allow if conntrack(pkt).state == established\` can never match an \
ICMP error, because v0.4 conntrack has no notion of an error RELATED \
to a flow (the \`related\` keyword is encoded and never produced). The \
only fix available today is a blanket \`allow if pkt.proto == icmp\`, \
which admits every ICMP from anywhere."
elif [ "$ICMP_TO_GUEST" -gt 0 ]; then
  pass "the error was admitted AND steered to the guest \
($ICMP_TO_GUEST/20) — path-MTU discovery works through the NAT"
else
  fail "PARTIAL: the error was admitted ($ICMP_TO_MASQ/20) but left \
addressed to the masquerade address; the guest behind the NAT never \
sees it. fwl_nat_denat returns early for anything that is not TCP or \
UDP, and the flow identity of an ICMP error lives in its PAYLOAD (the \
embedded IP + 8 bytes), which nothing reads. So even a permissive \
ICMP rule cannot deliver it: path-MTU discovery is structurally \
broken for every masqueraded flow."
fi

# The same error under the most permissive ICMP rule an operator could
# write. If it still does not reach the guest, the problem is the NAT,
# not the policy — and that distinction decides whether it is
# configurable or a code change.
FW2=$(mktemp --suffix=.fw)
cat > "$FW2" <<EOF
zone lan = [$RECV_IF]
zone wanz = [$WAN_IF]

@xdp(lan)

count opened if pkt.proto == tcp and pkt.tcp.syn
count icmp_unreach if pkt.proto == icmp and pkt.icmp.type == 3
masquerade if pkt.src_ip in 10.99.61.0/24
redirect to wanz if pkt.proto == udp and pkt.dst_port == 1
allow if pkt.proto == icmp
allow if pkt.proto == tcp
default drop
EOF
hw::deploy l11-05b "$FW2"
hw::send 20 "tcp(src_ip=\"$GUEST\", dst_ip=\"$PEER\", \
src_port=$SPORT, dst_port=443, syn=true)"
sleep 1

hw::sniff_start 8 --detail --srcport
$PY "$HERE/sendraw.py" "$SEND_IF" 20 icmperr \
  src_ip=10.99.71.254 dst_ip="$MASQ_ADDR" type=3 code=4 mtu=1400 \
  orig_src="$MASQ_ADDR" orig_dst="$PEER" orig_sport="$SPORT" \
  orig_dport=443 orig_len=1500
sleep 1
hw::sniff_wait
P_MASQ=$(hw::sniff_get "icmp:10.99.71.254>$MASQ_ADDR:3.4")
P_GUEST=$(hw::sniff_get "icmp:10.99.71.254>$GUEST:3.4")
log "under a blanket 'allow if pkt.proto == icmp': to the masquerade \
address $P_MASQ/20, steered to the guest $P_GUEST/20"
if [ "$P_MASQ" -gt 0 ] && [ "$P_GUEST" -eq 0 ]; then
  fail "PERMISSIVE ICMP DOES NOT HELP: the error is admitted \
($P_MASQ/20) and still stops at the firewall's own address. No policy \
can deliver an ICMP error to a host behind masquerade in v0.4, \
because de-NAT never looks at ICMP. The spec says so — \
'v0.4 NAT does not rewrite ICMP (ICMP-error NAT is Phase 5.3)' — this \
measures what that sentence costs on the wire."
elif [ "$P_GUEST" -gt 0 ]; then
  pass "a permissive ICMP rule does deliver the error to the guest \
($P_GUEST/20), so this is a policy question, not a code one"
else
  fail "the error vanished under a blanket allow (masq=$P_MASQ \
guest=$P_GUEST): unreadable"
fi

# ====================================================================
# Parts 1 and 2: a real TCP transfer over the copper.
# ====================================================================
XFW=$(mktemp --suffix=.fw)
cat > "$XFW" <<EOF
zone t = [$RECV_IF]

@xdp(t)

count bulk if pkt.proto == tcp and pkt.dst_port == 5001
count bigframe if pkt.proto == udp and pkt.dst_port == 9
allow if pkt.proto == udp and pkt.dst_port == 9
allow if pkt.proto == tcp and pkt.tcp.syn
allow if conntrack(pkt).state == established
allow if pkt.proto == icmp
default drop
EOF
hw::deploy l11-05c "$XFW"

ip addr flush dev "$RECV_IF" 2>/dev/null || true
ip addr add "$HOST_ADDR/24" dev "$RECV_IF"
ip netns del "$NS" 2>/dev/null || true
ip netns add "$NS"
ip link set "$SEND_IF" netns "$NS"
ip netns exec "$NS" ip link set lo up
ip netns exec "$NS" ip link set "$SEND_IF" up
ip netns exec "$NS" ip addr add "$NS_ADDR/24" dev "$SEND_IF"
# Give the link a moment to come back after the namespace move.
for _ in $(seq 1 30); do
  ip netns exec "$NS" ping -c1 -W1 "$HOST_ADDR" >/dev/null 2>&1 \
    && break
  sleep 1
done
if ! ip netns exec "$NS" ping -c2 -W1 "$HOST_ADDR" >/dev/null 2>&1; then
  hw::abort "no IP connectivity across the switch from namespace $NS"
fi
pass "real IP path up across the switch: $NS_ADDR -> $HOST_ADDR \
through the XDP program"

cat > /tmp/l11_05_srv.py <<'PYEOF'
import socket
import sys
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind((sys.argv[1], 5001))
srv.listen(1)
srv.settimeout(float(sys.argv[2]))
try:
  c, _ = srv.accept()
except socket.timeout:
  print(0)
  raise SystemExit(0)
c.settimeout(float(sys.argv[2]))
total = 0
try:
  while True:
    b = c.recv(1 << 20)
    if not b:
      break
    total += len(b)
except (socket.timeout, OSError):
  pass
print(total)
PYEOF

cat > /tmp/l11_05_cli.py <<'PYEOF'
import socket
import sys
import time
host, mb, timeout = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
buf = b"x" * (1 << 20)
s = socket.socket()
s.settimeout(timeout)
t0 = time.monotonic()
try:
  s.connect((host, 5001))
  for _ in range(mb):
    s.sendall(buf)
  s.shutdown(socket.SHUT_WR)
except (socket.timeout, OSError) as e:
  print(f"STALLED after {time.monotonic() - t0:.1f}s: {e}")
  raise SystemExit(1)
print(f"sent {mb} MB in {time.monotonic() - t0:.1f}s")
PYEOF

run_transfer() {
  local timeout="$1" mb="$2"
  $PY /tmp/l11_05_srv.py "$HOST_ADDR" "$timeout" > /tmp/l11_05_rx &
  local srv=$!
  sleep 2
  local out
  out=$(ip netns exec "$NS" $PY /tmp/l11_05_cli.py "$HOST_ADDR" \
    "$mb" "$timeout" 2>&1)
  local rc=$?
  wait "$srv" 2>/dev/null || true
  echo "$out"
  echo "received_bytes=$(cat /tmp/l11_05_rx)"
  return $rc
}

# --- part 1: clean path, MTU 1500 both ends -------------------------
ip link set dev "$RECV_IF" mtu 1500
ip netns exec "$NS" ip link set dev "$SEND_IF" mtu 1500
BULK0=$(hw::counter bulk)
T0=$(date +%s)
CLEAN=$(run_transfer 90 "$XFER_MB")
T1=$(date +%s)
log "clean path: $CLEAN"
RX=$(echo "$CLEAN" | awk -F= '/received_bytes/{print $2}')
BULK1=$(hw::counter bulk)
WANT=$((XFER_MB * 1024 * 1024))
ELAPSED=$((T1 - T0))
[ "$ELAPSED" -gt 0 ] || ELAPSED=1
assert_eq "clean path: every byte arrived" "$RX" "$WANT"
if [ "$((BULK1 - BULK0))" -gt 1000 ]; then
  pass "the XDP program saw the stream: bulk counter +$((BULK1 - BULK0)) \
segments for a ${XFER_MB} MB transfer in ${ELAPSED}s \
(~$((XFER_MB * 8 / ELAPSED)) Mbit/s across the switch)"
else
  fail "bulk counter only moved $((BULK1 - BULK0)): the transfer did \
not go through the XDP program, so it measures nothing"
fi

# --- part 2a: does an undersized link actually swallow a frame? ------
# Ask the blunt question first, with a frame TCP would never emit.
# MSS negotiation means two directly-connected hosts agree on a
# segment size at handshake time and never exceed it, so a TCP test
# alone cannot tell "the link carries oversized frames" apart from
# "the sender never sent one". A single 1514-byte UDP datagram at an
# MTU-1400 receiver separates them.
# Changing the MTU on igb takes the interface down and up, so the
# switch port renegotiates and the wire is dead for several seconds.
# Waiting a fixed 3 s here first produced "0 frames arrived" and would
# have been read as the link swallowing them — the exact wrong
# conclusion, reached from a dead wire rather than a policed one.
wait_wire() {
  local i
  for i in $(seq 1 40); do
    ip netns exec "$NS" ping -c1 -W1 "$HOST_ADDR" >/dev/null 2>&1 \
      && return 0
    sleep 1
  done
  return 1
}

ip link set dev "$RECV_IF" mtu 1400
wait_wire || hw::abort "wire never came back after the MTU change"
# $SEND_IF lives in the namespace now, so the sender runs there and
# the usual two-sided FDB teach cannot. Teaching the RECEIVING side is
# enough: a frame sourced from ..:02 out of $RECV_IF makes the switch
# learn that MAC on that port, so the builder frames unicast to it.
$PY - "$RECV_IF" <<'PYEOF'
import socket
import sys
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind((sys.argv[1], 0))
for _ in range(3):
  s.send(b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02"
         + b"\x88\xb5" + bytes(60))
s.close()
PYEOF
OVER0=$(ethtool -S "$RECV_IF" | awk '/rx_(long_length|over)_errors/{s+=$2} END{print s+0}')
BF0=$(hw::counter bigframe)
hw::sniff_start 6
ip netns exec "$NS" $PY "$HERE/sendraw.py" "$SEND_IF" 20 bigudp \
  size=1514 src_ip="$NS_ADDR" dst_ip="$HOST_ADDR" dport=9 >/dev/null
ip netns exec "$NS" $PY "$HERE/sendraw.py" "$SEND_IF" 20 bigudp \
  size=1000 src_ip="$NS_ADDR" dst_ip="$HOST_ADDR" dport=9 >/dev/null
sleep 1
hw::sniff_wait
OVER1=$(ethtool -S "$RECV_IF" | awk '/rx_(long_length|over)_errors/{s+=$2} END{print s+0}')
BIG=$(hw::sniff_get "udp:$NS_ADDR:9")
BF1=$(hw::counter bigframe)
# Two witnesses, so "the NIC dropped it" and "the policy dropped it"
# cannot be confused: the counter says the frame reached XDP, the
# sniffer says it got past it.
log "at link MTU 1400: of 20 oversized (1514 B) + 20 legal (1000 B) \
UDP frames, $((BF1 - BF0)) reached XDP and $BIG reached the wire; NIC \
oversize/length errors +$((OVER1 - OVER0))"

# --- part 2b: a path MTU that shrinks under an open connection ------
# The only black hole two directly-connected hosts can build: negotiate
# the MSS at 1500 and then take the link down to 1400 mid-stream. MSS
# is fixed at handshake, so neither end renegotiates — which is exactly
# what happens in the field when the constrained hop is somewhere
# upstream and the endpoints never saw it.
ip link set dev "$RECV_IF" mtu 1500
wait_wire || hw::abort "wire never came back after restoring the MTU"
BULK2=$(hw::counter bulk)
( sleep 3; ip link set dev "$RECV_IF" mtu 1400 ) &
SHRINK=$!
CONSTRAINED=$(run_transfer 30 "$XFER_MB") && XRC=0 || XRC=1
wait "$SHRINK" 2>/dev/null || true
OVER2=$(ethtool -S "$RECV_IF" | awk '/rx_(long_length|over)_errors/{s+=$2} END{print s+0}')
RX2=$(echo "$CONSTRAINED" | awk -F= '/received_bytes/{print $2}')
BULK3=$(hw::counter bulk)
log "path MTU shrunk to 1400 three seconds into the transfer (which \
also bounces the link, so this doubles as a mid-stream link-flap \
test): $CONSTRAINED"
log "NIC oversize/length errors +$((OVER2 - OVER1)); bulk counter \
+$((BULK3 - BULK2))"

log "=== ICMP/PMTU: what was measured ==="
if [ "$BIG" -ge 20 ] && [ "$BIG" -lt 40 ]; then
  pass "the receiving link DOES swallow oversized frames silently: \
only the 20 legal frames arrived, the 20 at 1514 B did not \
($BIG/40 total). A hop whose MTU the sender does not know about is a \
black hole, and nothing on the wire says so — which is the whole \
reason ICMP frag-needed exists"
elif [ "$BIG" -ge 40 ]; then
  pass "BENCH LIMIT RECORDED — the receiving link accepted the \
oversized frames as readily as the legal ones ($BIG/40, NIC \
oversize/length errors +$((OVER1 - OVER0))). igb allocates 2 KB \
receive buffers and does not police frame size against the MTU, so a \
genuine path-MTU black hole CANNOT be built between two \
directly-connected i350 ports. That is a fact about this bench, not \
about the firewall: it means the 'transfer hangs' half of this \
question cannot be reproduced here, and the ICMP measurements above \
are what the answer rests on."
else
  log "NOTE: only $BIG/40 UDP frames arrived at all — the legal ones \
did not make it either, so this sub-measurement is unreadable"
fi

if [ "$XRC" -ne 0 ] || [ "${RX2:-0}" -lt "$WANT" ]; then
  pass "PMTU BLACK HOLE REPRODUCED — the transfer stalled with \
${RX2:-0} of $WANT bytes delivered and no error surfaced anywhere. \
This is the shape of the office failure: ping works, DNS works, small \
requests work, and a large transfer hangs. The thing that would \
rescue it is the router's ICMP frag-needed — which, measured above, \
this firewall drops under a stateful policy and cannot deliver to a \
host behind masquerade under any policy."
else
  pass "the transfer completed (${RX2} bytes) with the link MTU cut \
to 1400 under an open connection — consistent with the frame-size \
measurement above: the receiver takes oversized frames anyway, so \
there was no black hole to fall into. What this DOES establish is \
that f itself does not break a large transfer: 200 MB of real TCP, \
every byte, through the XDP program, twice"
fi
