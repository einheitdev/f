#!/usr/bin/env bash
# Test-plan L2 row 2a: source NAT (`snat to`) with reply de-NAT.
#
# READ THIS BEFORE TRUSTING THE ASSERTIONS BELOW.
#
# Everything from `hw::sniff_start` down witnesses the frame on the
# interface it ARRIVED on, with a promiscuous AF_PACKET socket, after an
# `allow` handed it to a local stack that has no address on that port
# and discarded it. That is real evidence of ONE thing — the rewrite
# happened and the checksums are valid, which a stub cannot fake — and
# no evidence at all that the translated frame was ever forwarded, let
# alone accepted. A promiscuous witness counts frames a real IP stack
# drops, so for the whole life of this suite "masquerade works" meant
# "the bytes changed", never "the far side got it".
#
# The acceptance leg at the bottom is the one that answers the other
# question, on a real routed path with a real socket. The two are kept
# apart deliberately: the crafted-frame leg can assert per-frame counts
# and checksum validity that a socket cannot see, and the socket can
# assert delivery that no capture can.
source "$(dirname "$0")/hwlib.sh"
hw::require_root

WAN_IF="${WAN_IF:-enp1s0f2}"
PARENT="${SEND_IF}"
WAN_VLAN="${WAN_VLAN:-802}"
LAN_ADDR=10.99.20.1
SNAT_ADDR=10.99.200.1
GUEST=10.99.20.5
SERVER=10.99.200.9
PORT=8080
FWD_SAVED=""

cleanup() {
  [ -n "$FWD_SAVED" ] && echo "$FWD_SAVED" > /proc/sys/net/ipv4/ip_forward
  ip addr del "$LAN_ADDR/24" dev "$RECV_IF" 2>/dev/null || true
  ip addr del "$SNAT_ADDR/24" dev "$WAN_IF" 2>/dev/null || true
  hw::finish
}
trap cleanup EXIT

FW=$(mktemp --suffix=.fw)
cat > "$FW" <<EOF
zone t = [$RECV_IF]

@xdp(t)

count outbound if pkt.src_ip == 10.99.20.5
snat to 10.99.200.1 if pkt.proto == tcp and pkt.src_ip == 10.99.20.5
allow if pkt.proto == tcp
default drop
EOF
hw::deploy l2-02 "$FW"

hw::sniff_start 8 --detail
# Outbound: private 10.99.20.5 -> server 10.99.20.9:80.
hw::send 100 'tcp(src_ip="10.99.20.5", dst_ip="10.99.20.9", src_port=41000, dst_port=80, syn=true)'
sleep 1
# Reply: server 10.99.20.9:80 -> the PUBLIC (translated) address.
# De-NAT must rewrite the destination back to 10.99.20.5:41000.
hw::send 50 'tcp(src_ip="10.99.20.9", dst_ip="10.99.200.1", src_port=80, dst_port=41000, ack=true)'
sleep 1
hw::sniff_wait

assert_eq "counter outbound (pre-NAT match)" \
  "$(hw::counter outbound)" 100
assert_eq "wire: src translated, checksums valid" \
  "$(hw::sniff_get 'tcp:10.99.200.1>10.99.20.9:80:ok')" 100
assert_eq "wire: no un-translated leak" \
  "$(hw::sniff_get 'tcp:10.99.20.5>10.99.20.9:80:ok')" 0
assert_eq "wire: reply de-NATed to private addr, checksums valid" \
  "$(hw::sniff_get 'tcp:10.99.20.9>10.99.20.5:41000:ok')" 50
assert_eq "wire: no reply leaked at public addr" \
  "$(hw::sniff_get 'tcp:10.99.20.9>10.99.200.1:41000:ok')" 0

# ---------------------------------------------------------------------
# The acceptance leg: the same `snat to`, on a routed path, proved by a
# far side that took the bytes.
#
# The client and the server are ordinary Linux stacks in their own
# namespaces, NOT promiscuous, so a byte only arrives at a socket if the
# frame was addressed to that host. The server's own kernel reports the
# peer address, which is the snat address — one object, both halves:
# the far side accepted it AND it was translated.
# ---------------------------------------------------------------------
ip addr add "$LAN_ADDR/24" dev "$RECV_IF" 2>/dev/null || true
ip addr add "$SNAT_ADDR/24" dev "$WAN_IF" 2>/dev/null || true

FW2=$(mktemp --suffix=.fw)
cat > "$FW2" <<EOF2
zone t = [$RECV_IF]
zone wanz = [$WAN_IF]

@xdp(t)

count outbound if pkt.src_ip == $GUEST
snat to $SNAT_ADDR if pkt.proto == tcp and pkt.src_ip == $GUEST
redirect to wanz if pkt.src_ip == $GUEST and pkt.dst_ip == $SERVER
allow

@xdp(wanz)

redirect to t if pkt.src_ip == $SERVER
allow
EOF2
hw::deploy l2-02b "$FW2"
hw::host_up sguest "$PARENT" none "$GUEST/24" "$LAN_ADDR"
hw::host_up sserver "$PARENT" "$WAN_VLAN" "$SERVER/24"
FWD_SAVED=$(hw::forwarding 1)
ping -c1 -W2 -I "$RECV_IF" "$GUEST" >/dev/null 2>&1 || true
ping -c1 -W2 -I "$WAN_IF" "$SERVER" >/dev/null 2>&1 || true

hw::server_start sserver "$SERVER" "$PORT" 6 20
SNAT_CLIENT=$(hw::client sguest "$SERVER" "$PORT" 6 4)
hw::server_wait
log "client: $SNAT_CLIENT"
log "server: $(cat "$SERVER_OUT")"

assert_eq "far side ACCEPTED the snatted connections" \
  "$(hw::server_get accepted)" 6
assert_eq "payload round-tripped through the translation" \
  "$(hw::jget "$SNAT_CLIENT" completed)" 6
assert_str "the peer the server's own kernel reports is the snat address" \
  "$(hw::server_get peer_addrs)" "$SNAT_ADDR"
assert_eq "the datapath ROUTED those forwards" \
  "$([ "$(hw::route routed)" -gt 0 ] && echo 1 || echo 0)" 1
