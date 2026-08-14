#!/usr/bin/env bash
# Test-plan L2 row 2b: masquerade — proved by a far side that ACCEPTED
# it, not by a capture that saw it go past.
#
# What this scenario used to be, and why it proved nothing
# --------------------------------------------------------
# It sent 100 crafted SYNs into a program that masqueraded them and then
# `allow`ed them (XDP_PASS), and counted the rewritten frames on the
# SAME interface with a promiscuous AF_PACKET socket. Three things were
# never asked:
#
#   * the frame never left the interface it arrived on — `allow` hands
#     it to the local stack, which has no address on that port and
#     discards it. Nothing was forwarded anywhere.
#   * `redirect` never rewrote the destination MAC, so a frame that HAD
#     been forwarded would have left carrying the firewall's own MAC.
#     The next hop's NIC reports PACKET_OTHERHOST and its stack drops it
#     before any socket exists.
#   * a promiscuous witness counts exactly those frames. That is why the
#     capture was perfect and the network carried nothing.
#
# What it is now
# --------------
# A real routed gateway with real hosts either side, each an ordinary
# Linux stack in its own namespace with its own MAC and NOT promiscuous:
#
#   guest 10.99.21.5   --(vlan 801)-->  lan0 [XDP: masquerade+redirect]
#                                         |  10.99.21.1
#                                       wan0  10.99.200.2
#   server 10.99.200.9 <--(vlan 802)------/  [XDP: de-NAT + redirect]
#
# The assertion is a completed TCP exchange: the server's `accept()`
# returns, the payload round-trips, and the peer address the server
# reports is the masquerade address. One object proves the far side
# accepted the frame AND that it was translated — neither is evidence
# without the other, and neither can be faked by a frame on a wire.
#
# Two controls, because a pass must be attributable:
#
#   1. `net.ipv4.ip_forward=0`. The FIB lookup then answers
#      FWD_DISABLED, the redirect falls back to the L2-adjacent forward
#      this suite used to test, and the SAME exchange must fail. That
#      is A1 and A2 in one measurement: the MAC rewrite is what carries
#      the traffic, and the sysctl is what permits the rewrite.
#   2. The datapath's own routed/bridged tally must agree with the
#      socket both times. If the socket succeeds while `routed` is 0,
#      something other than this code path carried the packets.
source "$(dirname "$0")/hwlib.sh"
hw::require_root

LAN_IF="${RECV_IF}"           # the firewall's inside port (XDP)
WAN_IF="${WAN_IF:-enp1s0f2}"  # the firewall's outside port (XDP)
PARENT="${SEND_IF}"           # carries both far hosts (trunk port)
WAN_VLAN="${WAN_VLAN:-802}"

LAN_ADDR=10.99.21.1
MASQ_ADDR=10.99.200.2
GUEST=10.99.21.5
SERVER=10.99.200.9
PORT=8443

FWD_SAVED=""

cleanup() {
  [ -n "$FWD_SAVED" ] && echo "$FWD_SAVED" > /proc/sys/net/ipv4/ip_forward
  ip addr del "$LAN_ADDR/24" dev "$LAN_IF" 2>/dev/null || true
  ip addr del "$MASQ_ADDR/24" dev "$WAN_IF" 2>/dev/null || true
  hw::finish
}
trap cleanup EXIT

# The firewall's own two legs. Without them it has no routing table
# entry for either segment and cannot resolve a next hop for anything —
# a router with no addresses is not a router.
ip addr add "$LAN_ADDR/24" dev "$LAN_IF" 2>/dev/null || true
ip addr add "$MASQ_ADDR/24" dev "$WAN_IF" 2>/dev/null || true

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

count wan_in if pkt.src_ip == $SERVER
redirect to lan if pkt.src_ip == $SERVER
allow
EOF
hw::deploy l2-03 "$FW"

journalctl -u fd -n 40 --no-pager | grep -q \
  "masquerade address $MASQ_ADDR" \
  && pass "fd resolved masquerade address from wan zone" \
  || fail "no masquerade-address line in fd journal"

# The two far hosts. The guest's default route is the firewall, which
# is what makes its frames arrive addressed to the firewall's MAC —
# the whole reason the destination MAC has to be rewritten on the way
# out.
hw::host_up fguest "$PARENT" none "$GUEST/24" "$LAN_ADDR"
hw::host_up fserver "$PARENT" "$WAN_VLAN" "$SERVER/24"

# Warm the firewall's own neighbour table. XDP cannot resolve ARP; the
# stack can, and on a live box it has (this router talks to its own
# gateway for DNS and NTP). Doing it explicitly keeps the measurement
# about the MAC rewrite instead of about ARP timing — and the NO_NEIGH
# path is measured separately, below.
ping -c1 -W2 -I "$LAN_IF" "$GUEST" >/dev/null 2>&1 || true
ping -c1 -W2 -I "$WAN_IF" "$SERVER" >/dev/null 2>&1 || true
ip neigh show | grep -qE "^$GUEST " \
  && pass "firewall resolved the guest's MAC" \
  || fail "no neighbour entry for $GUEST — the return path cannot route"
ip neigh show | grep -qE "^$SERVER " \
  && pass "firewall resolved the server's MAC" \
  || fail "no neighbour entry for $SERVER — the forward path cannot route"

# ---------------------------------------------------------------------
# The measurement: forwarding ON.
# ---------------------------------------------------------------------
FWD_SAVED=$(hw::forwarding 1)
log "net.ipv4.ip_forward was $FWD_SAVED, now 1"

ROUTED_0=$(hw::route routed)
BRIDGED_0=$(hw::route bridged)
assert_eq "fctl status has a route section" \
  "$([ "$ROUTED_0" -ge 0 ] && echo 1 || echo 0)" 1

hw::server_start fserver "$SERVER" "$PORT" 10 25
CLIENT=$(hw::client fguest "$SERVER" "$PORT" 10 4)
hw::server_wait
log "client: $CLIENT"
log "server: $(cat "$SERVER_OUT")"

assert_eq "far side ACCEPTED the masqueraded connections" \
  "$(hw::server_get accepted)" 10
assert_eq "far side echoed every one (a real payload round trip)" \
  "$(hw::server_get echoed)" 10
assert_eq "guest completed every exchange end to end" \
  "$(hw::jget "$CLIENT" completed)" 10
# The same object that proves acceptance proves translation: the peer
# the server's own kernel reports is the firewall's WAN address, and
# exactly one address, so nothing leaked untranslated alongside it.
assert_str "server saw ONE source address, the masquerade address" \
  "$(hw::server_get peer_addrs)" "$MASQ_ADDR"

ROUTED_1=$(hw::route routed)
assert_eq "the datapath says it ROUTED (not bridged) those forwards" \
  "$([ "$ROUTED_1" -gt "$ROUTED_0" ] && echo 1 || echo 0)" 1
assert_eq "the box reports forwarding enabled" \
  "$(hw::route ip_forward)" 1
assert_eq "counter guest_out moved" \
  "$([ "$(hw::counter guest_out)" -gt 0 ] && echo 1 || echo 0)" 1
assert_eq "counter wan_in moved (replies came back through the wan zone)" \
  "$([ "$(hw::counter wan_in)" -gt 0 ] && echo 1 || echo 0)" 1

# ---------------------------------------------------------------------
# Control: the same everything with routing switched off.
#
# This is the state the box shipped in. bpf_fib_lookup answers
# FWD_DISABLED, no next hop is resolved, and the redirect forwards the
# frame with the destination MAC it arrived carrying — which is what
# the old sniffer-based assertions were passing on.
# ---------------------------------------------------------------------
hw::forwarding 0 >/dev/null
log "control: net.ipv4.ip_forward = 0"
ROUTED_2=$(hw::route routed)
BRIDGED_2=$(hw::route bridged)

hw::server_start fserver "$SERVER" "$PORT" 5 12
CLIENT_OFF=$(hw::client fguest "$SERVER" "$PORT" 5 2)
hw::server_wait
log "control client: $CLIENT_OFF"
log "control server: $(cat "$SERVER_OUT")"

assert_eq "control: NOTHING reached the far side's socket" \
  "$(hw::server_get accepted)" 0
assert_eq "control: no exchange completed" \
  "$(hw::jget "$CLIENT_OFF" completed)" 0
assert_eq "control: the datapath BRIDGED those forwards" \
  "$([ "$(hw::route bridged)" -gt "$BRIDGED_2" ] && echo 1 || echo 0)" 1
assert_eq "control: and routed none of them" \
  "$(hw::route routed)" "$ROUTED_2"
assert_eq "control: the box reports forwarding disabled" \
  "$(hw::route ip_forward)" 0
# The frames were on the wire the whole time. This is the assertion
# that names the old defect: the datapath counter climbed, so the
# packets arrived and were processed and forwarded, and no socket on
# the far side ever saw one. A promiscuous capture on that segment
# would have counted every frame and called it a pass.
assert_eq "control: the frames DID arrive and were forwarded" \
  "$([ "$(hw::counter guest_out)" -gt 0 ] && echo 1 || echo 0)" 1

hw::forwarding 1 >/dev/null

# ---------------------------------------------------------------------
# ICMP through the same masquerade, kept from the old scenario because
# it covers a different door: a source NAT installs a ports-0 mapping
# for a frame with no L4 ports, and de-NAT used to return early for
# anything that was not TCP or UDP. Both halves, in order, so the reply
# assertion cannot pass without the request having been translated.
#
# Real sockets again: `ping` in the guest namespace is a real ICMP
# socket, and it only reports a reply its own stack accepted.
# ---------------------------------------------------------------------
PING_OUT=$(hw::in fguest ping -c5 -W2 -i 0.3 "$SERVER" 2>&1 || true)
log "guest ping: $(echo "$PING_OUT" | tail -2 | tr '\n' ' ')"
RECV=$(echo "$PING_OUT" | grep -oE '[0-9]+ received' | grep -oE '^[0-9]+')
assert_eq "the guest's own stack accepted the echo replies" \
  "${RECV:-0}" 5

# ---------------------------------------------------------------------
# The next-hop failure mode, measured rather than reasoned about.
# Flushing the neighbour entry for the server leaves the FIB lookup
# with a route and no MAC. XDP cannot ARP; the stack can, so the packet
# is handed over — and a MASQUERADED packet does not survive that trip,
# because its source is one of this box's own addresses and
# fib_validate_source rejects it as a martian. The counter is the only
# trace of it.
# ---------------------------------------------------------------------
NN_0=$(hw::route no_neigh)
ip neigh flush to "$SERVER" 2>/dev/null || true
hw::in fguest timeout 2 $PY "$HERE/realsock.py" client "$SERVER" \
  "$PORT" 1 1 >/dev/null 2>&1 || true
NN_1=$(hw::route no_neigh)
if [ "$NN_1" -gt "$NN_0" ]; then
  pass "an unresolved next hop is counted (no_neigh $NN_0 -> $NN_1), \
not silently dropped"
else
  log "NOTE: no_neigh did not move ($NN_0 -> $NN_1) — the stack \
answered the ARP inside the window. Not a failure; the counter is \
asserted, the race is not."
fi
ping -c1 -W2 -I "$WAN_IF" "$SERVER" >/dev/null 2>&1 || true

log "NOTE: ICMP ERROR translation (RFC 5508, off the embedded \
datagram) is a different lookup and is asserted in l11_05_icmp_pmtu."
