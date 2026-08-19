#!/usr/bin/env bash
# rate_limit zone scope across a multi-zone bundle (FWL v0.4 § 6.7).
#
# `scope=global` says one bucket per rule for the whole bundle. That is
# a claim about the artifact SET, not about any one program: it means
# two independently-compiled zone objects, loaded under one bpffs pin
# root, resolve one pinned map name to one kernel map and spend one
# budget. BPF_PROG_RUN loads a single object, so no corpus case can see
# it — right or wrong, the .pkt result is identical. Only real libbpf,
# a real pin root and real wire can tell the two apart.
#
# Part 1 — scope=global: a flood into zone za must exhaust the budget
#   that zone zb's copy of the same rule reads.
# Part 2 — scope=zone: the identical traffic must leave zone zb's
#   budget untouched.
#
# Both halves are guarded against vacuity the way l8_07 is: zb's own
# arrival counter is asserted first, so "budget untouched" cannot pass
# because nothing was sent, and "budget consumed" cannot pass because
# zb never saw a packet.
#
# Traffic reaches zone zb through the EX2300: f0 is a trunk with
# f-wan/802 tagged, ge-0/0/26 (f2) is an access port on 802, so a
# VLAN-802-tagged frame out f0 arrives untagged at f2. Both bursts
# therefore leave the SAME interface, which lets one process send them
# back to back inside one rate-limit window.
source "$(dirname "$0")/hwlib.sh"
hw::require_root
trap l8_08::finish EXIT

WAN_IF="${WAN_IF:-enp1s0f2}"
WAN_VLAN="${WAN_VLAN:-802}"
THRESHOLD=50
FLOOD=400
PROBE=30
SRC=10.99.18.1
WARM_SRC=10.99.19.9

l8_08::finish() {
  hw::unpin_irqs
  hw::finish
}

# The rate-limit map is a PERCPU_HASH: a lookup inside XDP returns the
# CURRENT CPU's counter, so two zones share a bucket only when their
# packets are processed on the same CPU. That is a property of the
# rate_limit primitive (v0.1 chose per-CPU state), not of scope, but it
# would make this test measure RSS placement instead of map sharing.
# Pin both data-plane ports' queue interrupts to one CPU so the only
# variable left is the map.
hw::pin_irqs_to_cpu "$RECV_IF" "$WAN_IF"

policy() {
  # $1 = scope keyword. The rate-limit rule is byte-identical in both
  # zones — that is what makes it ONE rule and, under scope=global,
  # one bucket. It deliberately sits at a DIFFERENT rule index in each
  # zone (1 in za, 2 in zb): a bucket shared because two rules happen
  # to occupy the same slot number is the aliasing bug, not this
  # feature.
  cat <<EOF
zone za = [$RECV_IF]
zone zb = [$WAN_IF]

@xdp(za)
count a_seen if pkt.src_ip == $SRC
drop if pkt.src_ip in 10.99.18.0/24
       limited by rate_limit($THRESHOLD, per=src_ip, scope=$1)
count a_passed if pkt.src_ip == $SRC
default allow

@xdp(zb)
count b_warm if pkt.src_ip == $WARM_SRC
count b_seen if pkt.src_ip == $SRC
drop if pkt.src_ip in 10.99.18.0/24
       limited by rate_limit($THRESHOLD, per=src_ip, scope=$1)
count b_passed if pkt.src_ip == $SRC
default allow
EOF
}

# The f0 --tagged 802--> f2 path is not the one hw::deploy probes, and
# an igb link that has just been bounced by an XDP attach needs a
# moment. Warm it with a source OUTSIDE the rate-limited /24 so the
# check cannot spend any of the budget under test.
warm_wan() {
  local i warm
  for i in $(seq 1 20); do
    $PY "$HERE/sendmany.py" "$SEND_IF" 5 \
      "udp(src_ip=\"$WARM_SRC\", dst_port=7777, vlan_id=$WAN_VLAN)" \
      >/dev/null 2>&1
    sleep 0.5
    warm=$(hw::counter b_warm)
    if [ "$warm" -gt 0 ] 2>/dev/null; then
      log "wan path live (b_warm=$warm)"
      return 0
    fi
  done
  return 1
}

# One process, one socket, both bursts pre-built: the zone-zb probe
# lands microseconds after the zone-za flood, well inside the same
# one-second window.
run_bursts() {
  $PY "$HERE/sendmany.py" --burst "$SEND_IF" \
    "$FLOOD" "udp(src_ip=\"$SRC\", dst_port=8100)" \
    "$PROBE" "udp(src_ip=\"$SRC\", dst_port=8100, vlan_id=$WAN_VLAN)"
}

# ==================================================================
# Part 1 — scope=global: one budget for the bundle
# ==================================================================
FW=$(mktemp --suffix=.fw)
policy global > "$FW"
hw::deploy l8-08-global "$FW"
ip link set dev "$WAN_IF" promisc on 2>/dev/null || true

# The map identity, stated at the kernel level before any traffic. One
# pinned name, and no zone-private rate-limit pin beside it.
G_ID=$(hw::map_id fwl_rl_g0)
if [ "$G_ID" -gt 0 ] 2>/dev/null; then
  pass "global bucket pinned as one kernel map (id $G_ID)"
else
  fail "no fwl_rl_g0 pin — the global bucket was never shared"
fi
PRIV=$(ls "$PIN" 2>/dev/null | grep -c '^fwl_rl_z[ab]_' || true)
assert_eq "no zone-private rate-limit pins under scope=global" \
  "$PRIV" 0

warm_wan || hw::abort "no frame ever reached $WAN_IF over VLAN $WAN_VLAN"
run_bursts
sleep 1

A_SEEN=$(hw::counter a_seen)
A_PASSED=$(hw::counter a_passed)
B_SEEN=$(hw::counter b_seen)
B_PASSED=$(hw::counter b_passed)
log "global: a_seen=$A_SEEN a_passed=$A_PASSED b_seen=$B_SEEN \
b_passed=$B_PASSED"

# Vacuity guards first. Without these, "zone zb's budget was spent"
# would also be the reading of a test where zb received nothing.
assert_eq "flood reached zone za" "$A_SEEN" "$FLOOD"
assert_eq "probe reached zone zb over the wire" "$B_SEEN" "$PROBE"
# The rate limit is live at all: za's own traffic was capped.
assert_range "zone za capped its own flood" \
  "$A_PASSED" "$THRESHOLD" $((THRESHOLD * 2))

# The assertion. Zone za spent the budget; zone zb's copy of the rule
# reads the same bucket and finds nothing left.
assert_eq "zone zb's budget consumed by zone za's traffic" \
  "$B_PASSED" 0

# ==================================================================
# Part 2 — scope=zone: the same traffic, two budgets
# ==================================================================
policy zone > "$FW"
hw::deploy l8-08-zone "$FW"
ip link set dev "$WAN_IF" promisc on 2>/dev/null || true

if [ -e "$PIN/fwl_rl_g0" ]; then
  fail "scope=zone still emitted a bundle-global rate-limit pin"
else
  pass "no bundle-global rate-limit pin under scope=zone"
fi

warm_wan || hw::abort "no frame ever reached $WAN_IF over VLAN $WAN_VLAN"
run_bursts
sleep 1

A_SEEN=$(hw::counter a_seen)
A_PASSED=$(hw::counter a_passed)
B_SEEN=$(hw::counter b_seen)
B_PASSED=$(hw::counter b_passed)
log "zone: a_seen=$A_SEEN a_passed=$A_PASSED b_seen=$B_SEEN \
b_passed=$B_PASSED"

assert_eq "flood reached zone za" "$A_SEEN" "$FLOOD"
assert_eq "probe reached zone zb over the wire" "$B_SEEN" "$PROBE"
assert_range "zone za capped its own flood" \
  "$A_PASSED" "$THRESHOLD" $((THRESHOLD * 2))

# The converse assertion, on identical traffic: zone zb kept its own
# budget, so every probe frame passed.
assert_eq "zone zb's budget untouched by zone za's traffic" \
  "$B_PASSED" "$PROBE"

rm -f "$FW"
