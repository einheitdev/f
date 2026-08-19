#!/usr/bin/env bash
# DNS forwarding, end to end, through the appliance's own forwarder.
#
# This is the user-visible half of finding A4, and it is deliberately
# separate from l12_01. That scenario proves the MECHANISM — an egress
# hook creates a conntrack entry for a flow the box started, and the
# reply survives `default drop`. This one proves the CONSEQUENCE, which
# is the thing the box exists to do: a client on the test LAN asks the
# appliance to resolve a name, the appliance asks upstream across its
# own firewall, the answer crosses back, and the client gets it.
#
# It is a separate scenario because a log line is not the proof, and
# this is the class of defect where a log line was the whole problem.
# Every part of this path can be green with the resolution still
# failing: dnsmasq logs the forward it sent, the datapath counts the
# reply arriving, conntrack shows entries — and the client times out.
# So the assertion is the ANSWER: an address that only the far-side
# responder can produce, for a name minted fresh this run so no cache
# anywhere can have it.
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
CLIENT=10.99.21.5
UPSTREAM=10.99.200.9
# The answer only the far-side responder can produce. Distinctive on
# purpose: an address in any range this bench otherwise uses could be
# synthesised by accident.
ANSWER=203.0.113.77
FWD_SAVED=""
DNSMASQ_PID=/run/l12-02-dnsmasq.pid
DNSMASQ_CONF=/tmp/l12-02-dnsmasq.conf

cleanup() {
  [ -n "$FWD_SAVED" ] && echo "$FWD_SAVED" > /proc/sys/net/ipv4/ip_forward
  [ -f "$DNSMASQ_PID" ] && kill "$(cat "$DNSMASQ_PID")" 2>/dev/null
  rm -f "$DNSMASQ_CONF" "$DNSMASQ_PID"
  pkill -f 'dnsprobe.py server' 2>/dev/null || true
  ip addr del "$LAN_ADDR/24" dev "$LAN_IF" 2>/dev/null || true
  ip addr del "$WAN_ADDR/24" dev "$WAN_IF" 2>/dev/null || true
  hw::finish
}
trap cleanup EXIT

command -v dnsmasq >/dev/null 2>&1 \
  || hw::abort "dnsmasq is not installed; it IS the forwarder under test"

ip addr add "$LAN_ADDR/24" dev "$LAN_IF" 2>/dev/null || true
ip addr add "$WAN_ADDR/24" dev "$WAN_IF" 2>/dev/null || true

# The office policy, as the handbook now says to write it: a stateful
# LAN, and a WAN that admits nothing it did not ask for.
FW=$(mktemp --suffix=.fw)
cat > "$FW" <<EOF
zone lan = [$LAN_IF]
zone wanz = [$WAN_IF]

@xdp(lan)

count lan_seen
count lan_dns_q if pkt.proto == udp and pkt.dst_port == 53
allow if conntrack(pkt).state in [established, related]
allow

@xdp(wanz)

count wan_seen
count wan_dns_r if pkt.proto == udp and pkt.src_port == 53
allow if conntrack(pkt).state in [established, related]
default drop
EOF
hw::deploy l12-02 "$FW"

hw::host_up fupstream "$PARENT" "$WAN_VLAN" "$UPSTREAM/24"
hw::host_up fclient "$PARENT" none "$CLIENT/24" "$LAN_ADDR"
FWD_SAVED=$(hw::forwarding 1)
ping -c1 -W2 -I "$WAN_IF" "$UPSTREAM" >/dev/null 2>&1 || true
ping -c1 -W2 -I "$LAN_IF" "$CLIENT" >/dev/null 2>&1 || true

# The appliance's own forwarder. `no-resolv` + one `server` so the ONLY
# way it can answer is by crossing this firewall to the far host; a
# system resolver, a hosts file or a cache would each let this pass
# without a packet ever leaving the box.
cat > "$DNSMASQ_CONF" <<EOF
port=53
bind-interfaces
listen-address=$LAN_ADDR
no-resolv
no-hosts
cache-size=0
server=$UPSTREAM
EOF
dnsmasq --conf-file="$DNSMASQ_CONF" --pid-file="$DNSMASQ_PID" \
  2>/tmp/l12-02-dnsmasq.err \
  || hw::abort "dnsmasq would not start: $(cat /tmp/l12-02-dnsmasq.err)"
sleep 1
[ -f "$DNSMASQ_PID" ] && kill -0 "$(cat "$DNSMASQ_PID")" 2>/dev/null \
  || hw::abort "dnsmasq is not running"

# ---------------------------------------------------------------------
# 1. The resolution itself.
# ---------------------------------------------------------------------
log "=== a client resolves a name through the appliance ==="
NAME="probe-$$-$(date +%s).f-rig.test"
log "asking for $NAME (minted this run, so no cache can hold it)"

# Exactly one query, so the responder exits the moment it has answered.
# It used to serve up to three and sit out its whole timeout, and the
# report below was read off a file it had not written yet: two red
# assertions about a leg that had worked perfectly.
hw::in fupstream $PY "$HERE/dnsprobe.py" server \
  "$UPSTREAM" 53 "$ANSWER" 1 12 > /tmp/l12-02-upstream.json &
UP_PID=$!
sleep 1

CT_0=$(hw::ct entries)
EG_TRACKED_0=$(hw::egress tracked)
EG_REFRESHED_0=$(hw::egress refreshed)
WAN_DNS_0=$(hw::counter wan_dns_r)
LAN_DNS_0=$(hw::counter lan_dns_q)

RESULT=$(hw::in fclient $PY "$HERE/dnsprobe.py" query \
  "$LAN_ADDR" 53 "$NAME" 6)
log "client result: $RESULT"
ANSWERS=$(hw::jget "$RESULT" answers)
NANS=$(hw::jget "$RESULT" count)

CT_1=$(hw::ct entries)
EG_TRACKED_1=$(hw::egress tracked)
EG_REFRESHED_1=$(hw::egress refreshed)
WAN_DNS_1=$(hw::counter wan_dns_r)
LAN_DNS_1=$(hw::counter lan_dns_q)

# THE assertion. Not "the query returned", not "dnsmasq logged a
# forward": the address, which nothing on this box can produce.
assert_str "the client resolved the name to the address only the \
upstream responder can produce" "$ANSWERS" "$ANSWER"
assert_eq "...as exactly one A record" "$NANS" 1

# The path it took, each hop measured, so a PASS above cannot be
# explained by anything other than the intended route.
log "counters: lan_dns_q +$((LAN_DNS_1 - LAN_DNS_0)), \
wan_dns_r +$((WAN_DNS_1 - WAN_DNS_0)); conntrack $CT_0 -> $CT_1; \
egress tracked +$((EG_TRACKED_1 - EG_TRACKED_0)), \
refreshed +$((EG_REFRESHED_1 - EG_REFRESHED_0))"
assert_eq "the client's query crossed the firewall on the LAN port" \
  "$([ $((LAN_DNS_1 - LAN_DNS_0)) -ge 1 ] && echo 1 || echo 0)" 1
assert_eq "the upstream ANSWER crossed the firewall on the WAN port" \
  "$([ $((WAN_DNS_1 - WAN_DNS_0)) -ge 1 ] && echo 1 || echo 0)" 1
assert_eq "the appliance's own upstream query was tracked at egress \
(this is the entry that admits the answer)" \
  "$([ $((EG_TRACKED_1 - EG_TRACKED_0)) -ge 1 ] && echo 1 || echo 0)" 1
# The far side saw a real question, so "the client got an answer"
# cannot have come from anywhere on this box. Read only after the
# responder has exited and written its report.
wait $UP_PID 2>/dev/null || true
UP_SERVED=$($PY -c "
import json
print(json.load(open('/tmp/l12-02-upstream.json'))['served'])
" 2>/dev/null || echo -1)
UP_NAMES=$($PY -c "
import json
print(','.join(json.load(open('/tmp/l12-02-upstream.json'))['names']))
" 2>/dev/null || echo "")
log "upstream responder served $UP_SERVED query/queries: $UP_NAMES"
assert_eq "the far-side responder was really asked" \
  "$([ "$UP_SERVED" -ge 1 ] && echo 1 || echo 0)" 1
assert_str "...for the name the client asked for" \
  "$(echo "$UP_NAMES" | cut -d, -f1)" "$NAME"

# The occupancy claim, on a real workload rather than a synthetic one.
# One resolution creates TWO conntrack entries: the client's query at
# XDP ingress on the LAN, and the appliance's upstream query at the
# egress hook. The appliance's ANSWER to the client is egress traffic
# too and creates nothing — it refreshes the client's own entry,
# because the tracker probes both directions of the 5-tuple before it
# creates anything. Without that, every served flow would cost two.
assert_eq "one resolution costs exactly two conntrack entries (the \
client's, and the appliance's own upstream flow)" \
  "$((CT_1 - CT_0))" 2
assert_eq "the answer back to the client refreshed the client's entry \
rather than adding its reverse" \
  "$([ $((EG_REFRESHED_1 - EG_REFRESHED_0)) -ge 1 ] && echo 1 || echo 0)" 1

# ---------------------------------------------------------------------
# 2. The control: take the conntrack entry away while the answer is in
#    flight, and the identical exchange fails.
#
# One variable. Same policy, same forwarder, same client, same far-side
# responder — only the entry the egress hook created is gone when the
# answer arrives. If the resolution above had been passing for any
# other reason (a permissive rule, a `default allow` that had crept in,
# the answer never leaving the box), this leg would resolve too.
# ---------------------------------------------------------------------
log "=== control: the same exchange with the entry removed ==="
NAME2="control-$$-$(date +%s).f-rig.test"
# The responder holds the answer for 3 s, which is the window the
# control needs. It serves exactly one query, so a dnsmasq retry
# cannot quietly re-create the state.
hw::in fupstream $PY "$HERE/dnsprobe.py" server \
  "$UPSTREAM" 53 "$ANSWER" 1 15 --delay-s 3 \
  > /tmp/l12-02-upstream2.json &
UP2_PID=$!
sleep 1

WAN_DNS_2=$(hw::counter wan_dns_r)
(sleep 1.2; hw::ct_flush > /tmp/l12-02-flush) &
FLUSH_PID=$!
RESULT2=$(hw::in fclient $PY "$HERE/dnsprobe.py" query \
  "$LAN_ADDR" 53 "$NAME2" 8)
wait $FLUSH_PID 2>/dev/null || true
wait $UP2_PID 2>/dev/null || true
WAN_DNS_3=$(hw::counter wan_dns_r)
FLUSHED=$(cat /tmp/l12-02-flush 2>/dev/null || echo -1)
UP2_SERVED=$($PY -c "
import json
print(json.load(open('/tmp/l12-02-upstream2.json'))['served'])
" 2>/dev/null || echo -1)

log "control result: $RESULT2 (flushed $FLUSHED entries; upstream \
served $UP2_SERVED; wan_dns_r +$((WAN_DNS_3 - WAN_DNS_2)))"
NANS2=$(hw::jget "$RESULT2" count)
# Vacuity guards FIRST, because "the client got no answer" is what a
# broken bench produces too. The control only means something if the
# upstream really answered and its answer really reached the WAN port.
assert_eq "the control removed live state (so it was a control at all)" \
  "$([ "$FLUSHED" -ge 1 ] && echo 1 || echo 0)" 1
assert_eq "the upstream responder DID answer in the control leg" \
  "$UP2_SERVED" 1
assert_eq "and its answer DID arrive at the WAN port" \
  "$([ $((WAN_DNS_3 - WAN_DNS_2)) -ge 1 ] && echo 1 || echo 0)" 1
# Only now the claim.
assert_eq "with the entry gone, the identical answer is dropped and \
the client resolves nothing" "$NANS2" 0

# ---------------------------------------------------------------------
# 3. And the box is back to working, so the control did not break it.
# ---------------------------------------------------------------------
log "=== and it recovers ==="
NAME3="after-$$-$(date +%s).f-rig.test"
hw::in fupstream $PY "$HERE/dnsprobe.py" server \
  "$UPSTREAM" 53 "$ANSWER" 1 12 > /tmp/l12-02-upstream3.json &
UP3_PID=$!
sleep 1
RESULT3=$(hw::in fclient $PY "$HERE/dnsprobe.py" query \
  "$LAN_ADDR" 53 "$NAME3" 6)
wait $UP3_PID 2>/dev/null || true
log "after-control result: $RESULT3"
assert_str "a fresh name resolves again once the tracker has re-made \
the state" "$(hw::jget "$RESULT3" answers)" "$ANSWER"

record "no insert was refused this run: refused=$(hw::egress refused), \
tracked=$(hw::egress tracked), refreshed=$(hw::egress refreshed), \
conntrack entries=$(hw::ct entries)"
