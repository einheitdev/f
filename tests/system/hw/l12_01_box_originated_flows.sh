#!/usr/bin/env bash
# The appliance can use its own network (finding A4, closed).
#
# The finding
# -----------
# XDP conntrack only ever sees INGRESS. A flow the box itself
# originates — the DNS query the forwarder sends upstream, the NTP
# exchange that sets its clock, the update it fetches — leaves through
# the local stack, which no XDP program is attached to. No conntrack
# entry was created, the reply arrived on the WAN port, read NEW, and
# `default drop` ate it. Measured here on 2026-08-14: 5 requests out of
# the box's own WAN address, 5 replies at the port by datapath counter,
# 0 survived, conntrack 0 -> 0.
#
# The fix
# -------
# A TC clsact egress hook, attached by `fd` to every interface the
# bundle attaches XDP to, which creates one conntrack entry per flow
# this box starts. This scenario asserts the behaviour that REPLACED the
# failure, and each of the three claims the design rests on:
#
#   1. the box's own flow now gets its replies, and gets them because a
#      conntrack entry exists — not because the policy grew permissive;
#   2. the hook does NOT track what the box merely FORWARDS. A packet
#      the local stack sent carries the socket that sent it; a forwarded
#      one has none. Without that gate the tracker would admit the
#      replies of every forwarded flow — a policy change made by a
#      component whose job is to observe;
#   3. the entry is a 5-tuple, so an unsolicited packet to the same port
#      from anywhere else is still dropped. A fix that opened the port
#      would pass claim 1 and be far worse than the bug.
#
# Prepared to be re-runnable by the operator; it changes nothing
# permanently and restores the smoke policy on exit.
source "$(dirname "$0")/hwlib.sh"
hw::require_root

LAN_IF="${RECV_IF}"
WAN_IF="${WAN_IF:-enp1s0f2}"
PARENT="${SEND_IF}"
WAN_VLAN="${WAN_VLAN:-802}"

LAN_ADDR=10.99.21.1
WAN_ADDR=10.99.200.2
GUEST=10.99.21.5
SERVER=10.99.200.9
INTRUDER=10.99.200.77
UDP_PORT=9953
FWD_SAVED=""

cleanup() {
  [ -n "$FWD_SAVED" ] && echo "$FWD_SAVED" > /proc/sys/net/ipv4/ip_forward
  pkill -f 'realsock.py server' 2>/dev/null || true
  ip addr del "$LAN_ADDR/24" dev "$LAN_IF" 2>/dev/null || true
  ip addr del "$WAN_ADDR/24" dev "$WAN_IF" 2>/dev/null || true
  hw::finish
}
trap cleanup EXIT

ip addr add "$LAN_ADDR/24" dev "$LAN_IF" 2>/dev/null || true
ip addr add "$WAN_ADDR/24" dev "$WAN_IF" 2>/dev/null || true

# The realistic office WAN policy: stateful return path, nothing else.
# This is the policy the deployment needs, written the way the handbook
# now says to write it. `default drop` is what ate the replies.
FW=$(mktemp --suffix=.fw)
cat > "$FW" <<EOF
zone lan = [$LAN_IF]
zone wanz = [$WAN_IF]

@xdp(lan)

count guest_out if pkt.src_ip == $GUEST
masquerade if pkt.src_ip == $GUEST and pkt.dst_ip == $SERVER
redirect to wanz if pkt.src_ip == $GUEST and pkt.dst_ip == $SERVER
allow

@xdp(wanz)

count wan_seen
count wan_udp if pkt.proto == udp
allow if conntrack(pkt).state in [established, related]
redirect to lan if pkt.src_ip == $SERVER and pkt.proto == tcp
default drop
EOF
hw::deploy l12-01 "$FW"

hw::host_up fserver "$PARENT" "$WAN_VLAN" "$SERVER/24"
hw::host_up fguest "$PARENT" none "$GUEST/24" "$LAN_ADDR"
FWD_SAVED=$(hw::forwarding 1)
ping -c1 -W2 -I "$WAN_IF" "$SERVER" >/dev/null 2>&1 || true
ping -c1 -W2 -I "$LAN_IF" "$GUEST" >/dev/null 2>&1 || true

# ---------------------------------------------------------------------
# 0. The tracker is attached, and to the ports the datapath is on.
#
# Asked first and asked of the DAEMON, because every assertion below
# would also pass on a box where `default drop` had quietly gone
# missing. The interface count is what says the hook is in the path;
# "an object loaded" says nothing about it, which is the whole reason
# the XDP path has a rule against reporting success attached to
# nothing.
# ---------------------------------------------------------------------
log "=== is the egress tracker actually attached? ==="
# The LIVE count, not the daemon's record of what it attached: `fctl
# status` asks the kernel per interface, exactly as it does for
# `xdp_attached`. A filter removed behind the daemon's back has to read
# as removed, or this assertion is bookkeeping wearing a measurement's
# clothes.
EG_IFACES=$(hw::egress attached)
XDP_IFACES=$(fctl status 2>/dev/null | $PY -c "
import json, sys
try:
  d = json.load(sys.stdin)['interfaces']['interfaces']
  print(sum(1 for i in d if i.get('xdp_attached')))
except Exception:
  print(-1)
")
log "egress tracker on $EG_IFACES interface(s); XDP on $XDP_IFACES"
assert_eq "the egress tracker is attached to every interface the \
datapath is on" "$EG_IFACES" "$XDP_IFACES"
assert_eq "...and that is more than none" \
  "$([ "$EG_IFACES" -ge 1 ] && echo 1 || echo 0)" 1

EG_TRACKED_0=$(hw::egress tracked)
CT_BEFORE=$(hw::ct entries)

# ---------------------------------------------------------------------
# 1. The behaviour that replaced the failure: the BOX's own flow gets
#    its replies back.
# ---------------------------------------------------------------------
log "=== the box's own outbound flow ==="
hw::in fserver $PY -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('$SERVER', $UDP_PORT))
s.settimeout(12)
for _ in range(5):
  try:
    d, a = s.recvfrom(2048)
  except socket.timeout:
    break
  s.sendto(b'reply:' + d, a)
" &
SRV_PID=$!
sleep 1

BOX_OUT=$($PY -c "
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('$WAN_ADDR', 0))
s.settimeout(2)
got = 0
for i in range(5):
  s.sendto(b'query%d' % i, ('$SERVER', $UDP_PORT))
  try:
    s.recv(2048)
    got += 1
  except socket.timeout:
    pass
print(got)
")
wait $SRV_PID 2>/dev/null || true
CT_AFTER=$(hw::ct entries)
EG_TRACKED_1=$(hw::egress tracked)

log "the box sent 5 UDP requests from its own WAN address and got \
back $BOX_OUT"
log "conntrack entries before/after: $CT_BEFORE / $CT_AFTER; \
egress tracked $EG_TRACKED_0 -> $EG_TRACKED_1"
# The exact value, not a lower bound: this is the measurement that used
# to read 0, and "at least one got through" would pass on a box that
# lost four out of five.
assert_eq "every reply to the box's own flow survives 'default drop'" \
  "$BOX_OUT" 5
# Vacuity guard, kept from the failing version: the replies really did
# arrive at the WAN port. Without it the claim above could pass on a
# server that never answered.
assert_eq "the replies DID arrive at the wan port (so this is not an \
empty wire)" \
  "$([ "$(hw::counter wan_udp)" -ge 5 ] && echo 1 || echo 0)" 1
# ...and WHY they survived. A conntrack entry now exists for a flow no
# XDP program ever saw the start of, which is the entire mechanism.
# Without this the same PASS would be produced by a policy that had
# quietly stopped dropping.
assert_eq "...because the egress hook created a conntrack entry for a \
flow XDP never saw start" \
  "$([ "$EG_TRACKED_1" -gt "$EG_TRACKED_0" ] && echo 1 || echo 0)" 1
# One entry per originated flow. The socket is reused across all five
# requests, so five requests are one flow, and a tracker that probed
# only one direction of the 5-tuple would have inserted more.
assert_eq "one conntrack entry for the one flow, not one per packet" \
  "$((CT_AFTER - CT_BEFORE))" 1

# ---------------------------------------------------------------------
# 2. The control that makes the fix a fix rather than an opening.
#
# The entry is an exact 5-tuple. Someone else sending to the same port
# on the same box must still be dropped — including from the same
# segment, which is the strongest form of the question this bench can
# ask. A fix that admitted on "the port is open" would pass every
# assertion above and be far worse than the bug it closed.
# ---------------------------------------------------------------------
log "=== does it open the port to anyone else? ==="
# A second source address on the far host rather than a second netns:
# the bench has ONE trunk port, so a second VLAN-802 subinterface on it
# is not a thing the kernel will make. It costs nothing here — the
# entry is keyed on the 5-TUPLE, so what has to differ is the source
# address or the source port, and both are exercised below. The
# sharper of the two is the second: the identical host, the identical
# destination port, one different source port.
hw::in fserver ip addr add "$INTRUDER/24" dev "vl${WAN_VLAN}fserver" \
  2>/dev/null || true
# A listener on the box, so "nothing answered" cannot be mistaken for
# "the firewall dropped it": the socket exists and is bound.
$PY -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('$WAN_ADDR', $UDP_PORT))
s.settimeout(8)
n = 0
try:
  while True:
    d, a = s.recvfrom(2048)
    n += 1
    s.sendto(b'ack', a)
except socket.timeout:
  pass
print(n)
" > /tmp/l12-intruder-rx &
LSN_PID=$!
sleep 1
WAN_UDP_0=$(hw::counter wan_udp)
INTRUDER_GOT=$(hw::in fserver $PY -c "
import socket
got = 0
# (a) a different source ADDRESS on the same segment.
a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
a.bind(('$INTRUDER', 0))
a.settimeout(1)
# (b) the SAME source address the tracked flow used, one different
#     source port. Everything an 'is this port open' check could look
#     at is identical.
b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
b.bind(('$SERVER', 0))
b.settimeout(1)
for s in (a, b):
  for i in range(5):
    s.sendto(b'unsolicited', ('$WAN_ADDR', $UDP_PORT))
    try:
      s.recv(2048)
      got += 1
    except socket.timeout:
      pass
print(got)
")
wait $LSN_PID 2>/dev/null || true
BOX_RX=$(cat /tmp/l12-intruder-rx 2>/dev/null || echo -1)
WAN_UDP_1=$(hw::counter wan_udp)
log "unsolicited: sender got $INTRUDER_GOT answers, the box's socket \
saw $BOX_RX datagrams, wan_udp +$((WAN_UDP_1 - WAN_UDP_0))"
assert_eq "an unsolicited packet to a bound port is still dropped \
before any socket, from a new address AND from the tracked flow's own \
address on a new port" "$BOX_RX" 0
assert_eq "...so the sender hears nothing" "$INTRUDER_GOT" 0
# Vacuity guard: the frames were on the cable. Without this the two
# assertions above are satisfied by a bench that sent nothing.
assert_eq "those frames DID reach the wan port (a policy drop, not an \
empty wire)" \
  "$([ $((WAN_UDP_1 - WAN_UDP_0)) -ge 10 ] && echo 1 || echo 0)" 1
rm -f /tmp/l12-intruder-rx

# ---------------------------------------------------------------------
# 3. The discriminator, measured: a FORWARDED packet is not tracked.
#
# The gate is `skb->sk`: locally-originated packets carry the socket
# that sent them, forwarded ones do not. Reaching the qdisc layer with
# a forwarded packet at all needs the kernel forwarding path (XDP's
# bpf_redirect_map leaves below the qdisc entirely, which is the other
# half of why this hook is free), so this leg deploys a policy that
# PASSES the guest's traffic to the stack and lets ip_forward route it.
# ---------------------------------------------------------------------
log "=== does it track what the box merely FORWARDS? ==="
FW2=$(mktemp --suffix=.fw)
cat > "$FW2" <<EOF
zone lan = [$LAN_IF]
zone wanz = [$WAN_IF]

@xdp(lan)

count lan_seen
allow

@xdp(wanz)

count wan_seen
count wan_udp if pkt.proto == udp
allow if conntrack(pkt).state in [established, related]
default drop
EOF
hw::deploy l12-01b "$FW2"
# Same host names, deliberately: hw::host_up deletes the namespace
# first, and the bench has ONE trunk port, so a second VLAN-802
# subinterface on it does not exist to be made.
hw::host_up fserver "$PARENT" "$WAN_VLAN" "$SERVER/24"
hw::host_up fguest "$PARENT" none "$GUEST/24" "$LAN_ADDR"
ping -c1 -W2 -I "$WAN_IF" "$SERVER" >/dev/null 2>&1 || true
ping -c1 -W2 -I "$LAN_IF" "$GUEST" >/dev/null 2>&1 || true

EG_SEEN_0=$(hw::egress seen)
EG_NOTLOCAL_0=$(hw::egress not_local)
EG_TRACKED_0=$(hw::egress tracked)
# The guest talks THROUGH the box: XDP_PASS on lan, ip_forward routes
# it out wanz, and it therefore crosses the clsact egress hook.
hw::in fguest $PY -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(0.4)
for i in range(10):
  s.sendto(b'fwd%d' % i, ('$SERVER', $UDP_PORT))
" >/dev/null 2>&1 || true
sleep 1
EG_SEEN_1=$(hw::egress seen)
EG_NOTLOCAL_1=$(hw::egress not_local)
EG_TRACKED_1=$(hw::egress tracked)
log "forwarded burst: hook saw +$((EG_SEEN_1 - EG_SEEN_0)), of which \
+$((EG_NOTLOCAL_1 - EG_NOTLOCAL_0)) had no socket; tracked \
+$((EG_TRACKED_1 - EG_TRACKED_0))"
# Vacuity guard first: the hook has to have SEEN the burst, or "it
# tracked none of it" is a claim about an empty wire — which is exactly
# how a passing test would hide a gate that rejects everything.
assert_eq "the hook DID see the forwarded burst at the qdisc layer" \
  "$([ $((EG_SEEN_1 - EG_SEEN_0)) -ge 10 ] && echo 1 || echo 0)" 1
assert_eq "...and classified it as not-locally-originated" \
  "$([ $((EG_NOTLOCAL_1 - EG_NOTLOCAL_0)) -ge 10 ] && echo 1 || echo 0)" 1
assert_eq "so it tracked NONE of it — a forwarded flow's replies are \
still the policy's business, not the tracker's" \
  "$((EG_TRACKED_1 - EG_TRACKED_0))" 0

# And the same hook still tracks what this box sends, under this same
# policy — the positive half of the same measurement, so a gate that
# had simply stopped tracking everything cannot pass this section.
EG_TRACKED_2=$(hw::egress tracked)
# A 5-tuple this box has not used yet. The warm-up ping above already
# created the ICMP entry for (box, server, 0, 0), and conntrack is
# FLOW-lifetime so it survived the redeploy: re-pinging refreshes that
# entry rather than creating one, and this assertion read 0 for a hook
# that was working perfectly. "Tracked" counts NEW flows, so the probe
# has to be a new flow.
$PY -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('$WAN_ADDR', 0))
s.sendto(b'fresh', ('$SERVER', 9999))
" >/dev/null 2>&1 || true
sleep 0.7
EG_TRACKED_3=$(hw::egress tracked)
log "the box's own fresh flow: tracked +$((EG_TRACKED_3 - EG_TRACKED_2))"
assert_eq "the box's OWN traffic is still tracked under the same \
policy (so the gate is not simply off)" \
  "$((EG_TRACKED_3 - EG_TRACKED_2))" 1

# ---------------------------------------------------------------------
# 4. What it costs the conntrack table.
#
# Recorded rather than judged: the shape of the curve is l11_06's
# subject, and a second scenario asserting a number about it would be
# two tests of one thing.
# ---------------------------------------------------------------------
log "=== the accounting question ==="
record "conntrack is the binding constraint: a masquerading policy \
that also reads conntrack creates TWO entries per ONE nat mapping, and \
both tables cap at 65536 (l11_02). Egress tracking adds ONE entry per \
flow the BOX originates, and only those — the hook probes both \
directions before creating anything, so a reply the box sends to a \
client refreshes that client's own entry instead of adding its \
reverse. Entries now: $(hw::ct entries), timeout $(hw::ct timeout_s)s; \
tracked $(hw::egress tracked), refreshed $(hw::egress refreshed), \
refused $(hw::egress refused)."
# The one way this feature can fail silently: conntrack at its cap, the
# insert refused, the query still going out and its reply still dropped.
# Zero here is a real claim about this run, not a placeholder.
assert_eq "no insert was refused (a refusal is a flow whose reply this \
policy WILL drop)" "$(hw::egress refused)" 0

# ---------------------------------------------------------------------
# 5. Why it is this hook and not the other candidate. Kept as a record
#    because it is the evidence the design decision rests on, and it
#    stays true only as long as dnsmasq behaves this way.
# ---------------------------------------------------------------------
if command -v dnsmasq >/dev/null 2>&1; then
  cat > /tmp/l12-dnsmasq.conf <<EOF
port=5354
bind-interfaces
listen-address=$WAN_ADDR
no-resolv
server=$SERVER
EOF
  dnsmasq --conf-file=/tmp/l12-dnsmasq.conf \
    --pid-file=/run/l12-dnsmasq.pid 2>/dev/null || true
  sleep 1
  ($PY -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
q = bytes.fromhex('abcd0100000100000000000003777777076578616d706c6503636f6d0000010001')
s.sendto(q, ('$WAN_ADDR', 5354))
try:
  s.recv(2048)
except Exception:
  pass
" &)
  sleep 0.4
  UNCONN=$(ss -unap 2>/dev/null | grep dnsmasq | grep -c '0\.0\.0\.0:\*')
  TOTAL=$(ss -unap 2>/dev/null | grep -c dnsmasq)
  if [ "$TOTAL" -gt 0 ] && [ "$UNCONN" -eq "$TOTAL" ]; then
    record "the refuted alternative still refutes: dnsmasq's upstream \
sockets carry NO peer ($UNCONN of $TOTAL), so bpf_sk_lookup_udp from \
XDP cannot tell its replies from unsolicited packets to the same port \
— admitting on an unconnected match would open every bound port"
  else
    record "dnsmasq had $((TOTAL - UNCONN)) connected socket(s) of \
$TOTAL; the sk_lookup option is worth re-reading against that"
  fi
  [ -f /run/l12-dnsmasq.pid ] && kill "$(cat /run/l12-dnsmasq.pid)" \
    2>/dev/null
  rm -f /tmp/l12-dnsmasq.conf
else
  record "dnsmasq is not installed here, so the sk_lookup measurement \
did not run this time"
fi
