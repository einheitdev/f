#!/usr/bin/env bash
# Two inside zones, TWO uplinks — the masquerade address that was one.
#
# What was wrong
# --------------
# `masquerade` translates the source to "the address of the zone this
# one redirects to". That is a per-zone fact — `deploy/firstboot` gives
# every non-uplink zone its own `masquerade` + `redirect to <uplink>`,
# and nothing says two of them name the same uplink — and it lived in a
# map called `fwl_nat_cfg`, pinned under one bundle-global name, with
# one slot 0. `LoadZoneBundle` wrote that slot once per masquerading
# zone, so the LAST zone loaded decided what EVERY masquerading program
# in the bundle translated to. Measured in fd's own journal, under
# l2_08's own sweep plant:
#
#   zone 'ina' masquerade address 10.99.210.2
#   zone 'inb' masquerade address 10.99.31.1
#
# after which neither zone forwarded. Nothing said so: the policy
# compiled, the bundle loaded, both objects attached, and both zones
# translated to one address.
#
# The map is `fwl_nat_cfg_<zone>` now — MapScope.PRIVATE, on a third
# ground the registry did not have: the CONTENTS are a per-zone fact
# under a bundle-wide name. Its SHAPE was always bundle-wide (one slot,
# one __u32, sized from a constant), so `_check_bundle_pinned_maps`
# saw every zone declaring it identically and had nothing to object to.
# The declarations agreed perfectly and the map was still wrong.
#
# What this asserts
# -----------------
# Not that it loads, and not that a journal line says the right thing:
# two REAL TCP exchanges, one per inside zone, each to a far side on
# its OWN uplink segment, each far side an ordinary Linux stack in its
# own namespace and NOT promiscuous, each reporting the peer address
# its own kernel saw — and that address being ITS OWN uplink's, not the
# other one's. That is the assertion the bug defeats: under one shared
# slot both zones translate to one address, and the far side on the
# other segment has no route back to it at all.
#
# Topology, and the compromise in it
# ----------------------------------
#   netns fua  10.99.31.5   (macvlan on f0, untagged -> vlan 801)
#         |
#      [ EX2300 ]
#         |
#   enp1s0f1  10.99.31.1    zone ina  [XDP: masquerade + redirect wan1]
#         |
#   enp1s0f2  10.99.210.2   zone wan1 [XDP: de-NAT + redirect back]
#         |
#      [ EX2300 vlan 802 ]
#         |
#   netns fus  10.99.210.9  (vlan 802 subinterface of f0)
#
#   netns fub  10.99.32.5 --- fu9b  10.99.32.1   zone inb  (veth)
#                                     [XDP: masquerade + redirect wan2]
#   netns fuw  10.99.211.9 -- fu9w  10.99.211.2  zone wan2 (veth)
#                                     [XDP: de-NAT + redirect back]
#
# Four firewall ports are needed and the i350 has three usable ones (f3
# carries the rig's own SSH and is off limits), so the SECOND gateway
# path is a pair of veths rather than copper. This file says so rather
# than leaving it to be assumed. What that path does not exercise is
# the igb driver's ndo_xdp_xmit; what it does exercise, and what this
# scenario is about, is two masquerading zones resolving two DIFFERENT
# addresses and each translating to its own. The ina/wan1 path is real
# copper through the switch in both directions and covers the driver
# path. A fourth copper port is operator cabling.
#
# A veth pair keeps CHECKSUM_PARTIAL end to end — the header carries
# the pseudo-header sum and never the final one — so a NAT's
# incremental checksum update lands on a base that was never valid and
# the far stack drops the frame with Tcp:InCsumErrors. On copper the
# sending NIC has already computed it. Both veth legs disable TX/RX
# offload for that reason.
#
# Controls
# --------
#   1. `net.ipv4.ip_forward=0`: the FIB answers FWD_DISABLED, the
#      redirect falls back to the L2-adjacent forward, and the
#      IDENTICAL exchanges must fail from BOTH zones while the datapath
#      counters still climb — the frames were on the wire and no socket
#      took one.
#   2. The two inside objects must really declare DIFFERENT masquerade
#      maps, and the WAN objects theirs. If a future emitter gave them
#      one name again, everything below would be measuring the defect.
#   3. No bare `fwl_nat_cfg` may appear in the pin root: one
#      bundle-global pin IS the defect, and its absence is what makes
#      two addresses possible.
#   4. Both zones' addresses named in fd's own journal, and DIFFERENT.
#      The wire assertion is the verdict; this says the daemon reached
#      it by resolving each zone's own destination rather than by luck.
source "$(dirname "$0")/hwlib.sh"
hw::require_root

INA_IF="${RECV_IF}"             # inside zone A — copper
WAN1_IF="${WAN1_IF:-enp1s0f2}"  # uplink 1 — copper
PARENT="${SEND_IF}"             # trunk carrying both copper-side hosts
WAN_VLAN="${WAN_VLAN:-802}"
INB_IF=fu9b                     # inside zone B — veth, root-ns end
INB_PEER=fu9bp                  # its peer, inside netns fub
WAN2_IF=fu9w                    # uplink 2 — veth, root-ns end
WAN2_PEER=fu9wp                 # its peer, inside netns fuw

INA_ADDR=10.99.31.1
INB_ADDR=10.99.32.1
MASQ1_ADDR=10.99.210.2
MASQ2_ADDR=10.99.211.2
GUEST_A=10.99.31.5
GUEST_B=10.99.32.5
SERVER_1=10.99.210.9
SERVER_2=10.99.211.9
PORT=8446

FWD_SAVED=""
SRV1_OUT=""
SRV2_OUT=""
SRV1_PID=""
SRV2_PID=""

cleanup() {
  [ -n "$FWD_SAVED" ] && echo "$FWD_SAVED" > /proc/sys/net/ipv4/ip_forward
  kill "$SRV1_PID" "$SRV2_PID" 2>/dev/null || true
  ip netns exec fub ip link set dev "$INB_PEER" xdp off 2>/dev/null || true
  ip netns exec fuw ip link set dev "$WAN2_PEER" xdp off 2>/dev/null || true
  ip link set dev "$INB_IF" xdp off 2>/dev/null || true
  ip link set dev "$WAN2_IF" xdp off 2>/dev/null || true
  ip link del "$INB_IF" 2>/dev/null || true
  ip link del "$WAN2_IF" 2>/dev/null || true
  ip netns del fub 2>/dev/null || true
  ip netns del fuw 2>/dev/null || true
  ip addr del "$INA_ADDR/24" dev "$INA_IF" 2>/dev/null || true
  ip addr del "$MASQ1_ADDR/24" dev "$WAN1_IF" 2>/dev/null || true
  rm -f "$SRV1_OUT" "$SRV2_OUT"
  hw::finish
}
trap cleanup EXIT

# ---------------------------------------------------------------------
# The veth halves of the topology, built BEFORE the bundle is deployed:
# fd attaches to the interfaces the manifest names, and a zone whose
# interface does not exist yet is warned about and skipped.
# ---------------------------------------------------------------------
XPO=$(mktemp --suffix=.o)
clang -O2 -g -target bpf -I/usr/include/aarch64-linux-gnu \
  -I/usr/include/x86_64-linux-gnu \
  -c "$HERE/../xdp_pass.bpf.c" -o "$XPO" \
  || hw::abort "compile xdp_pass"

# leg <root-dev> <peer-dev> <netns> <far-addr> [gateway]
leg() {
  local dev="$1" peer="$2" ns="$3" addr="$4" gw="${5:-}"
  ip link del "$dev" 2>/dev/null || true
  ip netns del "$ns" 2>/dev/null || true
  ip link add "$dev" type veth peer name "$peer" || hw::abort "veth $dev"
  ip netns add "$ns" || hw::abort "netns $ns"
  ip link set "$peer" netns "$ns"
  ip link set "$dev" up
  ip netns exec "$ns" ip link set lo up
  ip netns exec "$ns" ip link set "$peer" up
  ip netns exec "$ns" ip addr add "$addr/24" dev "$peer"
  [ -n "$gw" ] && ip netns exec "$ns" ip route add default via "$gw" \
    dev "$peer"
  # The far side must not be promiscuous, for the same reason
  # hw::host_up asserts it: a promiscuous witness accepts frames a real
  # host drops.
  ip netns exec "$ns" ip link show "$peer" | grep -q PROMISC \
    && hw::abort "$ns/$peer is PROMISC"
  # See the header: a veth pair keeps CHECKSUM_PARTIAL end to end, so
  # the NAT's incremental update lands on a base that was never valid.
  ethtool -K "$dev" tx off rx off tso off gso off gro off \
    >/dev/null 2>&1 || true
  ip netns exec "$ns" ethtool -K "$peer" tx off rx off tso off gso off \
    gro off >/dev/null 2>&1 || true
  # veth's ndo_xdp_xmit needs an XDP program on the RECEIVING side, or
  # a redirect into this leg is dropped below the peer's stack.
  ip netns exec "$ns" ip link set dev "$peer" xdpdrv obj "$XPO" sec xdp \
    || ip netns exec "$ns" ip link set dev "$peer" xdp obj "$XPO" \
         sec xdp \
    || hw::abort "xdp_pass on $peer"
}

leg "$INB_IF" "$INB_PEER" fub "$GUEST_B" "$INB_ADDR"
leg "$WAN2_IF" "$WAN2_PEER" fuw "$SERVER_2"

# The firewall's own four legs. A router with no addresses is not a
# router: without them there is no route to any segment and no next hop
# can be resolved for anything.
ip addr add "$INA_ADDR/24" dev "$INA_IF" 2>/dev/null || true
ip addr add "$INB_ADDR/24" dev "$INB_IF" 2>/dev/null || true
ip addr add "$MASQ1_ADDR/24" dev "$WAN1_IF" 2>/dev/null || true
ip addr add "$MASQ2_ADDR/24" dev "$WAN2_IF" 2>/dev/null || true

# ---------------------------------------------------------------------
# The policy: the shape firstboot generates for a box with two uplinks.
# ---------------------------------------------------------------------
FW=$(mktemp --suffix=.fw)
cat > "$FW" <<EOF
zone ina = [$INA_IF]
zone inb = [$INB_IF]
zone wan1 = [$WAN1_IF]
zone wan2 = [$WAN2_IF]

@xdp(ina)

count ina_out
masquerade if pkt.src_ip == $GUEST_A
redirect to wan1 if pkt.src_ip == $GUEST_A
allow

@xdp(inb)

count inb_out
masquerade if pkt.src_ip == $GUEST_B
redirect to wan2 if pkt.src_ip == $GUEST_B
allow

@xdp(wan1)

count wan1_in
redirect to ina if pkt.dst_ip == $GUEST_A
allow

@xdp(wan2)

count wan2_in
redirect to inb if pkt.dst_ip == $GUEST_B
allow
EOF
hw::journal_mark
hw::deploy l2-09 "$FW"

# ---------------------------------------------------------------------
# Control 2 and 3: the shape under test, read off the compiled bundle
# rather than off this file's intent.
# ---------------------------------------------------------------------
BDIR=$(readlink -f "$BUNDLE_ROOT/current")
NAMED=0
grep -q 'fwl_nat_cfg_ina SEC(".maps")' "$BDIR/ina.bpf.c" \
  && grep -q 'fwl_nat_cfg_inb SEC(".maps")' "$BDIR/inb.bpf.c" \
  && NAMED=1
assert_eq "each inside zone declares its OWN masquerade map" "$NAMED" 1
# And each program READS the map it declared. A rename that left one
# object reading its neighbour's would put the defect back with two
# maps in the bundle to look at.
READS=0
grep -q 'bpf_map_lookup_elem(&fwl_nat_cfg_ina' "$BDIR/ina.bpf.c" \
  && grep -q 'bpf_map_lookup_elem(&fwl_nat_cfg_inb' "$BDIR/inb.bpf.c" \
  && READS=1
assert_eq "each masquerade reads its own zone's map" "$READS" 1
assert_eq "no object declares a bundle-global fwl_nat_cfg" \
  "$(grep -l '} fwl_nat_cfg SEC(".maps");' "$BDIR"/*.bpf.c 2>/dev/null \
     | wc -l)" 0
assert_eq "no bundle-global fwl_nat_cfg reached the pin root" \
  "$([ -e "$PIN/fwl_nat_cfg" ] && echo 1 || echo 0)" 0

# All four zones attached, which is the load half of the claim.
ATTACHED=$(fctl status 2>/dev/null | $PY -c "
import json, sys
d = json.load(sys.stdin)['interfaces']['interfaces']
want = {'$INA_IF', '$INB_IF', '$WAN1_IF', '$WAN2_IF'}
print(sum(1 for i in d if i['name'] in want and i['xdp_attached']))
")
assert_eq "XDP attached on all four zone interfaces" "$ATTACHED" 4

# Control 4: the daemon resolved each zone's OWN destination.
#
# Under one bundle-wide slot this is where the defect was first seen —
# `zone 'ina' ... 10.99.210.2` then `zone 'inb' ... 10.99.31.1`, one
# overwriting the other. Two lines naming two different addresses, one
# per zone, is the daemon side of the fix; the wire below is the
# verdict.
JOURNAL=$(hw::journal_since)
assert_eq "fd resolved zone ina's uplink address $MASQ1_ADDR" \
  "$(echo "$JOURNAL" \
     | grep -cE "zone 'ina' masquerade address $MASQ1_ADDR\b")" 1
assert_eq "fd resolved zone inb's uplink address $MASQ2_ADDR" \
  "$(echo "$JOURNAL" \
     | grep -cE "zone 'inb' masquerade address $MASQ2_ADDR\b")" 1
# And `fctl status` can SAY both. A report that can hold only one
# address is how a box with two uplinks looked healthy while half its
# traffic was translated to the wrong one.
SOURCES=$(fctl status 2>/dev/null | $PY -c "
import json, sys
d = json.load(sys.stdin).get('nat', {})
s = d.get('masq_sources', [])
print(' '.join(sorted(f\"{e['zone']}={e['address']}\" for e in s)))
" 2>/dev/null)
assert_str "fctl status reports BOTH masquerade sources, by zone" \
  "$SOURCES" "ina=$MASQ1_ADDR inb=$MASQ2_ADDR"

# ---------------------------------------------------------------------
# The copper-side far hosts.
# ---------------------------------------------------------------------
hw::host_up fua "$PARENT" none "$GUEST_A/24" "$INA_ADDR"
hw::host_up fus "$PARENT" "$WAN_VLAN" "$SERVER_1/24"

# XDP cannot ARP; the stack can, and on a live box it already has.
ping -c1 -W2 -I "$INA_IF" "$GUEST_A" >/dev/null 2>&1 || true
ping -c1 -W2 -I "$INB_IF" "$GUEST_B" >/dev/null 2>&1 || true
ping -c1 -W2 -I "$WAN1_IF" "$SERVER_1" >/dev/null 2>&1 || true
ping -c1 -W2 -I "$WAN2_IF" "$SERVER_2" >/dev/null 2>&1 || true
for a in "$GUEST_A" "$GUEST_B" "$SERVER_1" "$SERVER_2"; do
  ip neigh show | grep -qE "^$a .*lladdr" \
    && pass "firewall resolved $a's MAC" \
    || fail "no neighbour entry for $a"
done

# ---------------------------------------------------------------------
# The measurement: forwarding ON, both gateways at once.
#
# Two far sides, so the servers are started here rather than through
# hw::server_start, which keeps one output file and one pid.
# ---------------------------------------------------------------------
FWD_SAVED=$(hw::forwarding 1)
log "net.ipv4.ip_forward was $FWD_SAVED, now 1"
ROUTED_0=$(hw::route routed)

# The servers are started inline, NOT from a `$(...)` helper: a
# background job started inside a command substitution is a child of
# that subshell, so the outer `wait` returns immediately and the report
# is read while the server may still be writing it. hwlib's
# hw::server_start is inline for the same reason; it just cannot be
# used here, because it keeps one output file and one pid and this
# scenario needs two far sides at once.
#
# srv_get prints -1 for a report that is absent or unparseable, the way
# hw::counter and hw::map_sum do. It matters most in the control below,
# where the expected answer is 0: read as 0, a server that never ran
# would satisfy the assertion it exists to make.
srv_get() {  # srv_get <outfile> <key>
  $PY -c "
import json, sys
try:
  with open(sys.argv[1]) as fh:
    d = json.load(fh)
except Exception:
  print(-1)
  sys.exit()
if sys.argv[2] not in d:
  print(-1)
  sys.exit()
v = d[sys.argv[2]]
print(','.join(map(str, v)) if isinstance(v, list) else v)
" "$1" "$2"
}

SRV1_OUT=$(mktemp); SRV2_OUT=$(mktemp)
ip netns exec fus $PY "$HERE/realsock.py" server \
  "$SERVER_1" "$PORT" 5 30 > "$SRV1_OUT" &
SRV1_PID=$!
ip netns exec fuw $PY "$HERE/realsock.py" server \
  "$SERVER_2" "$PORT" 5 30 > "$SRV2_OUT" &
SRV2_PID=$!
sleep 0.5

CLIENT_A=$(hw::client fua "$SERVER_1" "$PORT" 5 4)
CLIENT_B=$(ip netns exec fub $PY "$HERE/realsock.py" client \
  "$SERVER_2" "$PORT" 5 4)
wait "$SRV1_PID" "$SRV2_PID" 2>/dev/null || true
log "guest A -> uplink 1: $CLIENT_A"
log "guest B -> uplink 2: $CLIENT_B"
log "server 1: $(cat "$SRV1_OUT")"
log "server 2: $(cat "$SRV2_OUT")"

assert_eq "zone ina completed every exchange end to end" \
  "$(hw::jget "$CLIENT_A" completed)" 5
assert_eq "zone inb completed every exchange end to end" \
  "$(hw::jget "$CLIENT_B" completed)" 5
assert_eq "uplink 1's far side ACCEPTED all five" \
  "$(srv_get "$SRV1_OUT" accepted)" 5
assert_eq "uplink 2's far side ACCEPTED all five" \
  "$(srv_get "$SRV2_OUT" accepted)" 5
assert_eq "and uplink 1 echoed every one (a real payload round trip)" \
  "$(srv_get "$SRV1_OUT" echoed)" 5
assert_eq "and uplink 2 echoed every one" \
  "$(srv_get "$SRV2_OUT" echoed)" 5

# The whole point, in two fields.
#
# Each far side saw exactly ONE source address and it was ITS OWN
# uplink's. Under one bundle-wide slot both zones translate to whatever
# address was written last: one of these two reads the other's address
# — and the far side on that segment has no route back to it, so the
# exchange above dies as well. Either half alone could pass for the
# wrong reason; together they cannot.
assert_str "uplink 1's far side saw ONE source, its own uplink's" \
  "$(srv_get "$SRV1_OUT" peer_addrs)" "$MASQ1_ADDR"
assert_str "uplink 2's far side saw ONE source, its own uplink's" \
  "$(srv_get "$SRV2_OUT" peer_addrs)" "$MASQ2_ADDR"

assert_eq "the datapath ROUTED (not bridged) those forwards" \
  "$([ "$(hw::route routed)" -gt "$ROUTED_0" ] && echo 1 || echo 0)" 1
assert_eq "counter ina_out moved" \
  "$([ "$(hw::counter ina_out)" -gt 0 ] && echo 1 || echo 0)" 1
assert_eq "counter inb_out moved" \
  "$([ "$(hw::counter inb_out)" -gt 0 ] && echo 1 || echo 0)" 1
assert_eq "counter wan1_in moved (replies came back through uplink 1)" \
  "$([ "$(hw::counter wan1_in)" -gt 0 ] && echo 1 || echo 0)" 1
assert_eq "counter wan2_in moved (replies came back through uplink 2)" \
  "$([ "$(hw::counter wan2_in)" -gt 0 ] && echo 1 || echo 0)" 1

# ---------------------------------------------------------------------
# Control 1: the same everything, forwarding off.
# ---------------------------------------------------------------------
hw::forwarding 0 >/dev/null
log "control: net.ipv4.ip_forward = 0"
INA_0=$(hw::counter ina_out)
INB_0=$(hw::counter inb_out)
BRIDGED_0=$(hw::route bridged)

: > "$SRV1_OUT"; : > "$SRV2_OUT"
ip netns exec fus $PY "$HERE/realsock.py" server \
  "$SERVER_1" "$PORT" 3 14 > "$SRV1_OUT" &
SRV1_PID=$!
ip netns exec fuw $PY "$HERE/realsock.py" server \
  "$SERVER_2" "$PORT" 3 14 > "$SRV2_OUT" &
SRV2_PID=$!
sleep 0.5
CTRL_A=$(hw::client fua "$SERVER_1" "$PORT" 3 2)
CTRL_B=$(ip netns exec fub $PY "$HERE/realsock.py" client \
  "$SERVER_2" "$PORT" 3 2)
wait "$SRV1_PID" "$SRV2_PID" 2>/dev/null || true
log "control guest A: $CTRL_A"
log "control guest B: $CTRL_B"
log "control server 1: $(cat "$SRV1_OUT")"
log "control server 2: $(cat "$SRV2_OUT")"

assert_eq "control: nothing reached uplink 1's far side" \
  "$(srv_get "$SRV1_OUT" accepted)" 0
assert_eq "control: nothing reached uplink 2's far side" \
  "$(srv_get "$SRV2_OUT" accepted)" 0
assert_eq "control: zone ina completed nothing" \
  "$(hw::jget "$CTRL_A" completed)" 0
assert_eq "control: zone inb completed nothing" \
  "$(hw::jget "$CTRL_B" completed)" 0
assert_eq "control: the datapath BRIDGED those forwards" \
  "$([ "$(hw::route bridged)" -gt "$BRIDGED_0" ] && echo 1 || echo 0)" 1
# The frames were on the wire the whole time, from BOTH zones. This is
# what makes the control a control rather than a bench that went quiet.
assert_eq "control: zone ina's frames DID arrive and were forwarded" \
  "$([ "$(hw::counter ina_out)" -gt "$INA_0" ] && echo 1 || echo 0)" 1
assert_eq "control: zone inb's frames DID arrive and were forwarded" \
  "$([ "$(hw::counter inb_out)" -gt "$INB_0" ] && echo 1 || echo 0)" 1

hw::forwarding 1 >/dev/null
rm -f "$FW" "$XPO"
