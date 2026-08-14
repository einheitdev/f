#!/usr/bin/env bash
# The appliance cannot use its own network (finding A4), measured — and
# the design fork it opens, measured rather than argued.
#
# The finding
# -----------
# XDP conntrack only ever sees INGRESS. A flow the box itself
# originates — the DNS query the forwarder sends upstream, the NTP
# exchange that sets its clock, the update it fetches — leaves through
# the local stack, which no XDP program is attached to. No conntrack
# entry is created. The reply arrives on the WAN port, reads NEW, and
# `default drop` eats it. That kills DNS forwarding, which is the entire
# purpose of the DNS service, and NTP, and every update path.
#
# The fork
# --------
# Track egress too (a TC hook), or special-case locally-originated
# flows, or something better. Two candidate mechanisms are measured
# here, because both rest on claims about kernel behaviour that are
# cheaper to test than to reason about:
#
#   1. A TC egress hook. The claim: it sees every packet the local stack
#      sends AND NONE of the traffic the XDP datapath forwards, because
#      bpf_redirect_map() leaves through ndo_xdp_xmit and never enters
#      the qdisc layer. If true, an egress conntrack tracker covers
#      exactly the gap and costs nothing on the forwarding fast path. If
#      false, it double-counts every forwarded packet.
#
#   2. bpf_sk_lookup_udp() from XDP — "does this packet belong to a
#      socket this box has open?", answered from the kernel's own socket
#      table with no second copy of the state. The claim to test is
#      whether it can DISTINGUISH a reply to a flow we originated from
#      an unsolicited packet to a port we happen to listen on. It can
#      only do that when the socket carries a peer, so the question is
#      whether a real DNS forwarder connects its upstream socket.
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
UDP_PORT=9953
FWD_SAVED=""

cleanup() {
  [ -n "$FWD_SAVED" ] && echo "$FWD_SAVED" > /proc/sys/net/ipv4/ip_forward
  tc qdisc del dev "$WAN_IF" clsact 2>/dev/null || true
  rm -f /sys/fs/bpf/tc/globals/fwl_probe_counts 2>/dev/null || true
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
# now says to write it.
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
# 1. Reproduce the finding: the BOX's own flow gets no reply.
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

CT_BEFORE=$(hw::ct entries)
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

log "the box sent 5 UDP requests from its own WAN address and got \
back $BOX_OUT"
log "conntrack entries before/after: $CT_BEFORE / $CT_AFTER"
assert_eq "REPRODUCED: not one reply to the box's own flow survived \
'default drop'" "$BOX_OUT" 0
assert_eq "...and conntrack created no entry for it (XDP sees ingress \
only)" "$CT_AFTER" "$CT_BEFORE"
# Vacuity guard: the replies really did arrive at the WAN port. Without
# this the claim above could pass on a server that never answered.
assert_eq "the replies DID arrive at the wan port (so this is a policy \
drop, not an empty wire)" \
  "$([ "$(hw::counter wan_udp)" -ge 5 ] && echo 1 || echo 0)" 1

# ---------------------------------------------------------------------
# 2. Candidate 1: what a TC egress hook can see.
# ---------------------------------------------------------------------
log "=== what a TC egress hook sees ==="
if ! clang -O2 -g -target bpf \
    -I/usr/include/aarch64-linux-gnu -I/usr/include/x86_64-linux-gnu \
    -c "$HERE/tc_egress_probe.bpf.c" -o /tmp/tc_probe.o \
    2>/tmp/tc_probe.err; then
  fail "could not build the egress probe: $(tail -3 /tmp/tc_probe.err)"
else
  rm -f /sys/fs/bpf/tc/globals/fwl_probe_counts 2>/dev/null || true
  tc qdisc del dev "$WAN_IF" clsact 2>/dev/null || true
  tc qdisc add dev "$WAN_IF" clsact 2>/dev/null || true
  if tc filter add dev "$WAN_IF" egress bpf da obj /tmp/tc_probe.o \
      sec tc 2>/tmp/tc_attach.err; then
    PROBE_MAP=$(find /sys/fs/bpf -name fwl_probe_counts 2>/dev/null \
      | head -1)
    if [ -z "$PROBE_MAP" ]; then
      fail "probe counter map not found under bpffs"
    else
      probe_total() {
        bpftool map dump pinned "$PROBE_MAP" 2>/dev/null | $PY -c "
import json, sys
t = 0
for e in json.load(sys.stdin):
  v = e.get('values')
  t += sum(x['value'] for x in v) if v else e.get('value', 0)
print(t)
"
      }
      T0=$(probe_total)
      # (a) traffic the LOCAL STACK sends out this port.
      ping -c5 -W1 -i 0.2 -I "$WAN_IF" "$SERVER" >/dev/null 2>&1 || true
      sleep 0.5
      T1=$(probe_total)
      # (b) traffic the XDP datapath FORWARDS out this port. The guest
      # is behind the lan zone, so every one of these frames leaves via
      # bpf_redirect_map() on WAN_IF.
      GUEST_0=$(hw::counter guest_out)
      hw::client fguest "$SERVER" 9 3 1 >/dev/null 2>&1 || true
      hw::in fguest ping -c10 -W1 -i 0.2 "$SERVER" >/dev/null 2>&1 || true
      sleep 0.5
      T2=$(probe_total)
      GUEST_1=$(hw::counter guest_out)
      log "egress probe: locally-originated burst +$((T1 - T0)), \
XDP-forwarded burst +$((T2 - T1)) (datapath forwarded \
$((GUEST_1 - GUEST_0)) frames in that window)"
      assert_eq "an egress hook DOES see what the local stack sends" \
        "$([ $((T1 - T0)) -ge 5 ] && echo 1 || echo 0)" 1
      # Vacuity guard: the second burst must really have crossed the
      # datapath, or "the hook saw none of it" is a claim about an
      # empty wire.
      assert_eq "the XDP datapath really did forward in that window" \
        "$([ $((GUEST_1 - GUEST_0)) -ge 10 ] && echo 1 || echo 0)" 1
      # The load-bearing half of the recommendation. A redirect leaves
      # via ndo_xdp_xmit, below the qdisc layer, so the hook is free of
      # the forwarding fast path entirely.
      assert_eq "and does NOT see what XDP redirects (so it costs the \
fast path nothing)" \
        "$([ $((T2 - T1)) -le 2 ] && echo 1 || echo 0)" 1
    fi
  else
    fail "could not attach the egress probe: \
$(tail -2 /tmp/tc_attach.err)"
  fi
fi

# ---------------------------------------------------------------------
# 3. Candidate 2: can the kernel's socket table answer instead?
#
# bpf_sk_lookup_udp() from XDP needs no second copy of the state at
# all. It can only distinguish "a reply to a flow we originated" from
# "an unsolicited packet to a port we listen on" when the socket
# carries a PEER — an unconnected server socket matches any source. So
# the question that decides the candidate is whether a real DNS
# forwarder connects its upstream socket.
# ---------------------------------------------------------------------
log "=== can the socket table tell a reply from an arrival? ==="
CONNECTED=$($PY -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('$WAN_ADDR', 0))
s.connect(('$SERVER', $UDP_PORT))
print(1 if s.getpeername() else 0)
")
assert_eq "a CONNECTED udp socket carries a peer (so sk_lookup could \
discriminate)" "$CONNECTED" 1

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
  # Fire a query it must forward upstream, then look at the socket it
  # used while the query is in flight.
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
  log "dnsmasq udp sockets: $TOTAL, of which unconnected: $UNCONN"
  if [ "$TOTAL" -gt 0 ] && [ "$UNCONN" -eq "$TOTAL" ]; then
    record "MEASURED: dnsmasq's upstream sockets carry NO peer, so \
sk_lookup cannot tell its replies from unsolicited packets to the same \
port — candidate 2 is refuted for the case that matters most"
  else
    log "NOTE: dnsmasq had $((TOTAL - UNCONN)) connected socket(s); \
re-read the sk_lookup option against that"
  fi
  [ -f /run/l12-dnsmasq.pid ] && kill "$(cat /run/l12-dnsmasq.pid)" \
    2>/dev/null
  rm -f /tmp/l12-dnsmasq.conf
else
  log "NOTE: dnsmasq is not installed here; the sk_lookup measurement \
needs it (it is the DNS forwarder the appliance ships)"
fi

# ---------------------------------------------------------------------
# 4. What it would cost the conntrack table.
# ---------------------------------------------------------------------
log "=== the accounting question ==="
log "conntrack is already the binding constraint: a masquerading policy \
that reads conntrack creates TWO entries per ONE nat mapping, and both \
tables cap at 65536 (l11_02). Tracking egress adds one entry per flow \
the BOX originates. Entries now: $(hw::ct entries), \
cap timeout $(hw::ct timeout_s)s."
