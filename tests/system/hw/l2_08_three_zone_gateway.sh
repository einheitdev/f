#!/usr/bin/env bash
# Two inside zones behind ONE uplink — the bundle that could not load.
#
# What was wrong
# --------------
# `deploy/firstboot` gives every non-uplink zone `masquerade` +
# `redirect to <uplink>`, so a box with three zones produces two objects
# that each declare `fwl_devmap_<uplink>`. While devmaps carried
# LIBBPF_PIN_BY_NAME the SECOND of those objects failed to load:
#
#   libbpf: couldn't reuse pinned map at '/sys/fs/bpf/f/fwl_devmap_wan':
#           parameter mismatch
#
# The kernel forces BPF_F_RDONLY_PROG inside `dev_map_alloc` — the
# verifier must not let a program write through a devmap lookup — and
# libbpf's `map_is_reuse_compat` compares the object's declared
# `map_flags` (0) against the pinned map's reported flags (128), which
# can never agree. Declaring the flag fails earlier still:
# DEV_CREATE_FLAG_MASK excludes it and creation returns -EINVAL. So the
# devmap is no longer pinned at all; `fd` fills each object's own copy
# from the manifest (`FindMap(obj, "fwl_devmap_" + dest)`).
#
# The rig never hit this because the office policy redirects both ways
# between two zones, so its two devmaps have DIFFERENT names.
#
# What this asserts
# -----------------
# Not that it loads. A load that succeeds and forwards nothing is the
# failure this project keeps finding, so the verdict is a completed TCP
# exchange from BOTH inside zones, witnessed by an ordinary
# non-promiscuous socket on the far side reporting the peer address it
# saw — the uplink's address, for both, or the masquerade did not
# happen. One object proves acceptance AND translation; neither is
# evidence without the other.
#
# Topology, and the one honest compromise in it
# ---------------------------------------------
#   netns fga  10.99.31.5   (macvlan on f0, untagged -> vlan 801)
#         |
#      [ EX2300 ]
#         |
#   enp1s0f1  10.99.31.1   zone ina   [XDP: masquerade + redirect wan]
#   fz3b      10.99.32.1   zone inb   [XDP: masquerade + redirect wan]
#         |                                    (veth, peer in netns fgb)
#   enp1s0f2  10.99.210.2  zone wanz  [XDP: de-NAT + redirect back]
#         |
#      [ EX2300 ]
#         |
#   netns fgs  10.99.210.9  (vlan 802 subinterface of f0)
#
# A three-zone gateway needs three firewall ports plus one port for the
# far hosts, and the i350 has three usable ones — f3 carries the rig's
# own SSH and is off limits. So the SECOND inside zone is a veth pair
# rather than copper, and this file says so rather than leaving it to be
# assumed. What that leg does not exercise is the igb driver's
# ndo_xdp_xmit; what it does exercise, and what this scenario is about,
# is two zone objects declaring one devmap name in one bundle, both
# loading, both attaching, and both forwarding. The `ina` leg is real
# copper through the switch in both directions and covers the driver
# path. Adding a fourth copper port is operator cabling.
#
# One thing this scenario found, recorded and NOT fixed
# -----------------------------------------------------
# `fwl_nat_cfg` holds ONE masquerade address for the whole bundle (key
# 0), and `LoadZoneBundle` writes it once per masquerading zone, so the
# last zone loaded decides what every masquerading program in the
# bundle translates to. A three-zone gateway works because every inside
# zone redirects to the same uplink and so resolves the same address; a
# policy whose masquerading zones redirect to DIFFERENT destinations
# gets one address for all of them, silently. It was invisible while a
# bundle with two same-destination inside zones could not load at all.
# Measured here under this scenario's own sweep plant: `zone 'ina'
# masquerade address 10.99.210.2` then `zone 'inb' masquerade address
# 10.99.31.1`, after which NEITHER zone forwarded. The assertion below
# names both zones for that reason.
#
# Controls
# --------
#   1. `net.ipv4.ip_forward=0`: the FIB answers FWD_DISABLED, the
#      redirect falls back to the L2-adjacent forward, and the IDENTICAL
#      exchange must fail from BOTH zones while the datapath counters
#      still climb — the frames were on the wire and no socket took one.
#   2. Both inside objects must really declare the same devmap name.
#      If a future emitter gave them different names, everything below
#      would pass without the question ever being put.
#   3. No `fwl_devmap_*` may appear in the pin root: the pin is the
#      defect, and its absence is what makes the load possible.
source "$(dirname "$0")/hwlib.sh"
hw::require_root

INA_IF="${RECV_IF}"            # inside zone A — copper
WAN_IF="${WAN_IF:-enp1s0f2}"   # the uplink — copper
PARENT="${SEND_IF}"            # trunk carrying both copper-side hosts
WAN_VLAN="${WAN_VLAN:-802}"
INB_IF=fz3b                    # inside zone B — veth, root-ns end
INB_PEER=fz3bp                 # its peer, inside netns fgb

INA_ADDR=10.99.31.1
INB_ADDR=10.99.32.1
MASQ_ADDR=10.99.210.2
GUEST_A=10.99.31.5
GUEST_B=10.99.32.5
SERVER=10.99.210.9
PORT=8444

FWD_SAVED=""

cleanup() {
  [ -n "$FWD_SAVED" ] && echo "$FWD_SAVED" > /proc/sys/net/ipv4/ip_forward
  ip netns exec fgb ip link set dev "$INB_PEER" xdp off 2>/dev/null || true
  ip link set dev "$INB_IF" xdp off 2>/dev/null || true
  ip link del "$INB_IF" 2>/dev/null || true
  ip netns del fgb 2>/dev/null || true
  ip addr del "$INA_ADDR/24" dev "$INA_IF" 2>/dev/null || true
  ip addr del "$MASQ_ADDR/24" dev "$WAN_IF" 2>/dev/null || true
  hw::finish
}
trap cleanup EXIT

# ---------------------------------------------------------------------
# The second inside zone's wire, built BEFORE the bundle is deployed:
# fd attaches to the interfaces the manifest names, and a zone whose
# interface does not exist yet is warned about and skipped.
# ---------------------------------------------------------------------
ip link del "$INB_IF" 2>/dev/null || true
ip netns del fgb 2>/dev/null || true
ip link add "$INB_IF" type veth peer name "$INB_PEER" \
  || hw::abort "veth $INB_IF"
ip netns add fgb || hw::abort "netns fgb"
ip link set "$INB_PEER" netns fgb
ip link set "$INB_IF" up
ip netns exec fgb ip link set lo up
ip netns exec fgb ip link set "$INB_PEER" up
ip netns exec fgb ip addr add "$GUEST_B/24" dev "$INB_PEER"
ip netns exec fgb ip route add default via "$INB_ADDR" dev "$INB_PEER"
# The far side must not be promiscuous, for the same reason hw::host_up
# asserts it: a promiscuous witness accepts frames a real host drops.
ip netns exec fgb ip link show "$INB_PEER" | grep -q PROMISC \
  && hw::abort "fgb/$INB_PEER is PROMISC"
# A veth pair keeps CHECKSUM_PARTIAL end to end, so the header carries
# the pseudo-header sum and never the final one; the NAT's incremental
# update then lands on a base that was never valid and the far stack
# drops the frame with Tcp:InCsumErrors. On copper the sending NIC has
# already computed it, which is why only this leg needs this.
ethtool -K "$INB_IF" tx off rx off tso off gso off gro off \
  >/dev/null 2>&1 || true
ip netns exec fgb ethtool -K "$INB_PEER" tx off rx off tso off gso off \
  gro off >/dev/null 2>&1 || true
# veth's ndo_xdp_xmit needs an XDP program on the RECEIVING side, or a
# redirect into this leg is dropped below the peer's stack.
XPO=$(mktemp --suffix=.o)
clang -O2 -g -target bpf -I/usr/include/aarch64-linux-gnu \
  -I/usr/include/x86_64-linux-gnu \
  -c "$HERE/../xdp_pass.bpf.c" -o "$XPO" \
  || hw::abort "compile xdp_pass"
ip netns exec fgb ip link set dev "$INB_PEER" xdpdrv obj "$XPO" sec xdp \
  || ip netns exec fgb ip link set dev "$INB_PEER" xdp obj "$XPO" \
       sec xdp \
  || hw::abort "xdp_pass on $INB_PEER"

# The firewall's own three legs. A router with no addresses is not a
# router: without them there is no route to any segment and no next hop
# can be resolved for anything.
ip addr add "$INA_ADDR/24" dev "$INA_IF" 2>/dev/null || true
ip addr add "$INB_ADDR/24" dev "$INB_IF" 2>/dev/null || true
ip addr add "$MASQ_ADDR/24" dev "$WAN_IF" 2>/dev/null || true

# ---------------------------------------------------------------------
# The policy: the shape firstboot generates for a three-zone box.
# ---------------------------------------------------------------------
FW=$(mktemp --suffix=.fw)
cat > "$FW" <<EOF
zone ina = [$INA_IF]
zone inb = [$INB_IF]
zone wanz = [$WAN_IF]

@xdp(ina)

count ina_out
masquerade if pkt.src_ip == $GUEST_A
redirect to wanz if pkt.src_ip == $GUEST_A
allow

@xdp(inb)

count inb_out
masquerade if pkt.src_ip == $GUEST_B
redirect to wanz if pkt.src_ip == $GUEST_B
allow

@xdp(wanz)

count wan_in
redirect to ina if pkt.dst_ip == $GUEST_A
redirect to inb if pkt.dst_ip == $GUEST_B
allow
EOF
hw::journal_mark
hw::deploy l2-08 "$FW"

# ---------------------------------------------------------------------
# Control 2 and 3: the shape under test, and the pin that used to break
# it. Read off the compiled bundle, not off this file's intent.
# ---------------------------------------------------------------------
BDIR=$(readlink -f "$BUNDLE_ROOT/current")
NAMED=0
grep -q 'fwl_devmap_wanz SEC(".maps")' "$BDIR/ina.bpf.c" \
  && grep -q 'fwl_devmap_wanz SEC(".maps")' "$BDIR/inb.bpf.c" \
  && NAMED=1
assert_eq "both inside zone objects declare fwl_devmap_wanz" "$NAMED" 1
PINNED_DEVMAPS=$($PY - "$BDIR" <<'PYEOF'
import pathlib, re, sys
rx = re.compile(
  r'struct\s*\{(?P<body>[^{}]*)\}\s*(?P<name>\w+)\s*SEC\("\.maps"\);')
n = 0
for f in sorted(pathlib.Path(sys.argv[1]).glob("*.bpf.c")):
  for m in rx.finditer(f.read_text()):
    if (m.group("name").startswith("fwl_devmap_")
        and "LIBBPF_PIN_BY_NAME" in m.group("body")):
      n += 1
print(n)
PYEOF
)
assert_eq "no devmap is declared LIBBPF_PIN_BY_NAME" \
  "$PINNED_DEVMAPS" 0
assert_eq "no devmap reached the pin root" \
  "$(ls "$PIN"/fwl_devmap_* 2>/dev/null | wc -l)" 0

# All three zones attached, which is the load half of the claim.
ATTACHED=$(fctl status 2>/dev/null | $PY -c "
import json, sys
d = json.load(sys.stdin)['interfaces']['interfaces']
want = {'$INA_IF', '$INB_IF', '$WAN_IF'}
print(sum(1 for i in d if i['name'] in want and i['xdp_attached']))
")
assert_eq "XDP attached on all three zone interfaces" "$ATTACHED" 3

# BOTH inside zones, by name, and both naming the UPLINK's address.
#
# Not a single grep for the address: `fwl_nat_cfg` is one bundle-wide
# slot written once per masquerading zone, so the LAST zone loaded
# decides what every masquerading program translates to. Two inside
# zones that resolve different addresses therefore take each other
# down, silently — measured, under this scenario's own plant, as
# `zone 'ina' masquerade address 10.99.210.2` followed by `zone 'inb'
# masquerade address 10.99.31.1`, after which NEITHER zone forwarded.
# What makes a three-zone gateway work is that every inside zone
# redirects to the same uplink and so resolves the same address, and
# that is a property worth asserting rather than relying on.
JOURNAL=$(hw::journal_since)
MASQ_ZONES=$(echo "$JOURNAL" \
  | grep -oE "zone '(ina|inb)' masquerade address $MASQ_ADDR\b" \
  | grep -oE "'(ina|inb)'" | sort -u | tr -d "'" | tr '\n' ' ')
assert_str "both inside zones resolved the uplink address $MASQ_ADDR" \
  "$MASQ_ZONES" "ina inb "

# ---------------------------------------------------------------------
# The copper-side far hosts.
# ---------------------------------------------------------------------
hw::host_up fga "$PARENT" none "$GUEST_A/24" "$INA_ADDR"
hw::host_up fgs "$PARENT" "$WAN_VLAN" "$SERVER/24"

# XDP cannot ARP; the stack can, and on a live box it already has.
ping -c1 -W2 -I "$INA_IF" "$GUEST_A" >/dev/null 2>&1 || true
ping -c1 -W2 -I "$INB_IF" "$GUEST_B" >/dev/null 2>&1 || true
ping -c1 -W2 -I "$WAN_IF" "$SERVER" >/dev/null 2>&1 || true
for a in "$GUEST_A" "$GUEST_B" "$SERVER"; do
  ip neigh show | grep -qE "^$a .*lladdr" \
    && pass "firewall resolved $a's MAC" \
    || fail "no neighbour entry for $a"
done

# ---------------------------------------------------------------------
# The measurement: forwarding ON, both inside zones at once.
# ---------------------------------------------------------------------
FWD_SAVED=$(hw::forwarding 1)
log "net.ipv4.ip_forward was $FWD_SAVED, now 1"
ROUTED_0=$(hw::route routed)

hw::server_start fgs "$SERVER" "$PORT" 10 30
CLIENT_A=$(hw::client fga "$SERVER" "$PORT" 5 4)
CLIENT_B=$(hw::client fgb "$SERVER" "$PORT" 5 4)
hw::server_wait
log "guest A: $CLIENT_A"
log "guest B: $CLIENT_B"
log "server:  $(cat "$SERVER_OUT")"

assert_eq "zone ina completed every exchange end to end" \
  "$(hw::jget "$CLIENT_A" completed)" 5
assert_eq "zone inb completed every exchange end to end" \
  "$(hw::jget "$CLIENT_B" completed)" 5
assert_eq "the far side ACCEPTED all ten, from two zones at once" \
  "$(hw::server_get accepted)" 10
assert_eq "and echoed every one (a real payload round trip)" \
  "$(hw::server_get echoed)" 10
# The whole assertion in one field: both zones' flows arrived as the
# uplink address, and as no other address, so nothing leaked
# untranslated alongside them and neither inside zone is visible.
assert_str "the server saw ONE source address, the uplink's" \
  "$(hw::server_get peer_addrs)" "$MASQ_ADDR"

assert_eq "the datapath ROUTED (not bridged) those forwards" \
  "$([ "$(hw::route routed)" -gt "$ROUTED_0" ] && echo 1 || echo 0)" 1
assert_eq "counter ina_out moved" \
  "$([ "$(hw::counter ina_out)" -gt 0 ] && echo 1 || echo 0)" 1
assert_eq "counter inb_out moved" \
  "$([ "$(hw::counter inb_out)" -gt 0 ] && echo 1 || echo 0)" 1
assert_eq "counter wan_in moved (replies came back through the uplink)" \
  "$([ "$(hw::counter wan_in)" -gt 0 ] && echo 1 || echo 0)" 1

# ---------------------------------------------------------------------
# Control 1: the same everything, forwarding off.
# ---------------------------------------------------------------------
hw::forwarding 0 >/dev/null
log "control: net.ipv4.ip_forward = 0"
INA_0=$(hw::counter ina_out)
INB_0=$(hw::counter inb_out)
BRIDGED_0=$(hw::route bridged)

hw::server_start fgs "$SERVER" "$PORT" 6 14
CTRL_A=$(hw::client fga "$SERVER" "$PORT" 3 2)
CTRL_B=$(hw::client fgb "$SERVER" "$PORT" 3 2)
hw::server_wait
log "control guest A: $CTRL_A"
log "control guest B: $CTRL_B"
log "control server:  $(cat "$SERVER_OUT")"

assert_eq "control: nothing reached the far side's socket" \
  "$(hw::server_get accepted)" 0
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
