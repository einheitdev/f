#!/usr/bin/env bash
# Pinned-map isolation across a multi-zone bundle.
#
# Every zone object in a bundle is loaded under ONE bpffs pin root, so
# a map carrying LIBBPF_PIN_BY_NAME resolves by NAME to a single kernel
# map shared by every zone. That is correct for state which is
# bundle-global by construction (conntrack, fwl_nat, the tallies) and
# wrong for state whose size and index meaning come from one zone's
# own analysis (counters, log-sample accumulators). Sharing the latter
# breaks in two ways, and only one of them is loud:
#
#   different shapes -> libbpf validates the map definition when it
#     reuses a pin, rejects the mismatch with -EINVAL, and the second
#     zone object never loads. The bundle is dead. Loud.
#
#   equal shapes -> every object loads cleanly and shares one map.
#     Slot i in zone A and slot i in zone B are the same cell, so the
#     zones increment each other's counters and advance each other's
#     sampling phase. Wrong numbers, no error, no symptom. Silent.
#
# This is a property of the artifact SET, not of any one program, so
# no single-object oracle can see it: BPF_PROG_RUN loads one object at
# a time. It needs real libbpf, a real pin root, and real wire.
#
# Part 1 covers the loud half, part 2 the silent half. Part 2 is the
# one that matters: it asserts on behaviour, not on loading.
source "$(dirname "$0")/hwlib.sh"
hw::require_root
trap hw::finish EXIT

WAN_IF="${WAN_IF:-enp1s0f2}"
FW=$(mktemp --suffix=.fw)

# ==================================================================
# Part 1 — divergent map shapes must still load
# ==================================================================
# Zone a: 3 counters, 6 rules.  Zone b: 1 counter, 3 rules.
# So fwl_counters wants max_entries 3 vs 1 and fwl_log_sample (sized
# len(rules)) wants 6 vs 3 — both maps diverge, in both directions.
cat > "$FW" <<EOF
zone a = [$RECV_IF]
zone b = [$WAN_IF]

@xdp(a)
count a_one
count a_two
count a_three
log(sample=4) if pkt.proto == udp
drop if pkt.proto == icmp
allow

@xdp(b)
count b_only
log(sample=4) if pkt.proto == tcp
allow
EOF
# A bundle-global name here is fatal at load: hw::deploy aborts the
# test when fd cannot attach, which is the pre-fix outcome.
hw::deploy l8-07a "$FW"

# Independently of the deploy gate, assert every zone's interface is
# actually carrying a program. fd rolls the whole bundle back when one
# object fails, so a partial load cannot masquerade as success.
A_UP=$(fctl status 2>/dev/null | $PY -c "
import json, sys
st = json.load(sys.stdin)
ifs = {i['name']: i['xdp_attached'] for i in st['interfaces']['interfaces']}
print(1 if ifs.get('$RECV_IF') else 0)
")
B_UP=$(fctl status 2>/dev/null | $PY -c "
import json, sys
st = json.load(sys.stdin)
ifs = {i['name']: i['xdp_attached'] for i in st['interfaces']['interfaces']}
print(1 if ifs.get('$WAN_IF') else 0)
")
assert_eq "zone a object loaded and attached ($RECV_IF)" "$A_UP" 1
assert_eq "zone b object loaded and attached ($WAN_IF), \
despite a different map shape" "$B_UP" 1

# The per-zone maps must exist as separate pins with the sizes their
# own zone asked for. This is the direct reading of the defect.
A_CNT_SZ=$(bpftool -j map show pinned "$PIN/fwl_counters_a" 2>/dev/null \
  | $PY -c "import json,sys; print(json.load(sys.stdin)['max_entries'])" \
  2>/dev/null || echo -1)
B_CNT_SZ=$(bpftool -j map show pinned "$PIN/fwl_counters_b" 2>/dev/null \
  | $PY -c "import json,sys; print(json.load(sys.stdin)['max_entries'])" \
  2>/dev/null || echo -1)
assert_eq "zone a counter map sized from zone a's analysis" \
  "$A_CNT_SZ" 3
assert_eq "zone b counter map sized from zone b's analysis" \
  "$B_CNT_SZ" 1

A_LS_SZ=$(bpftool -j map show pinned "$PIN/fwl_log_sample_a" 2>/dev/null \
  | $PY -c "import json,sys; print(json.load(sys.stdin)['max_entries'])" \
  2>/dev/null || echo -1)
B_LS_SZ=$(bpftool -j map show pinned "$PIN/fwl_log_sample_b" 2>/dev/null \
  | $PY -c "import json,sys; print(json.load(sys.stdin)['max_entries'])" \
  2>/dev/null || echo -1)
assert_eq "zone a log-sample map sized from zone a's rules" \
  "$A_LS_SZ" 6
assert_eq "zone b log-sample map sized from zone b's rules" \
  "$B_LS_SZ" 3

# No un-suffixed pin may survive: its existence means some map is
# still claiming a bundle-global name it has no right to.
for GLOBAL in fwl_counters fwl_log_sample; do
  if [ -e "$PIN/$GLOBAL" ]; then
    fail "zone-private map pinned under bundle-global name $GLOBAL"
  else
    pass "no bundle-global $GLOBAL pin"
  fi
done

# The genuinely shared state keeps its global name — the fix must not
# have privatised conntrack along with the rest. It is only emitted by
# a policy that reads it, so check it under a policy that does.
cat > "$FW" <<EOF
zone a = [$RECV_IF]
zone b = [$WAN_IF]

@xdp(a)
allow if conntrack(pkt).state == established
count a_ct
allow

@xdp(b)
allow if conntrack(pkt).state == established
allow
EOF
hw::deploy l8-07b "$FW"
if [ -e "$PIN/conntrack" ]; then
  pass "cross-zone conntrack still pinned under its global name"
else
  fail "conntrack pin missing — shared state lost its sharing"
fi

# ==================================================================
# Part 2 — equal map shapes must still not alias  (the silent half)
# ==================================================================
# Both zones now declare exactly 1 counter and 3 rules, so every map
# shape matches and a bundle-global name loads without complaint.
# Nothing about loading can distinguish right from wrong here; only
# behaviour can. Traffic goes into zone a alone. Zone b must not move.
cat > "$FW" <<EOF
zone a = [$RECV_IF]
zone b = [$WAN_IF]

@xdp(a)
count a_hits
log(sample=4) if pkt.proto == udp
allow

@xdp(b)
count b_hits
log(sample=4) if pkt.proto == udp
allow
EOF
hw::deploy l8-07c "$FW"
ip link set dev "$WAN_IF" promisc on 2>/dev/null || true

# Distinct kernel maps, asserted by id. Two pins sharing an id are one
# map — the aliasing, stated at the kernel level.
A_CNT_ID=$(hw::map_id fwl_counters_a)
B_CNT_ID=$(hw::map_id fwl_counters_b)
A_LS_ID=$(hw::map_id fwl_log_sample_a)
B_LS_ID=$(hw::map_id fwl_log_sample_b)
log "map ids: counters a=$A_CNT_ID b=$B_CNT_ID  log_sample a=$A_LS_ID b=$B_LS_ID"
if [ "$A_CNT_ID" -gt 0 ] && [ "$B_CNT_ID" -gt 0 ] \
   && [ "$A_CNT_ID" -ne "$B_CNT_ID" ]; then
  pass "counter maps are two kernel maps despite equal shapes"
else
  fail "counter maps alias: a=$A_CNT_ID b=$B_CNT_ID"
fi
if [ "$A_LS_ID" -gt 0 ] && [ "$B_LS_ID" -gt 0 ] \
   && [ "$A_LS_ID" -ne "$B_LS_ID" ]; then
  pass "log-sample maps are two kernel maps despite equal shapes"
else
  fail "log-sample maps alias: a=$A_LS_ID b=$B_LS_ID"
fi

# Baseline, so the assertion cannot pass on a map that was never
# touched by anything at all.
assert_eq "zone b counter starts at zero" "$(hw::counter b_hits)" 0
BEFORE_LS_B=$(hw::map_sum fwl_log_sample_b)

# 60 UDP frames into zone a's port only. Nothing is sent into zone b:
# $WAN_IF is an access port on a different test VLAN, so the sender on
# $SEND_IF cannot reach it even by accident.
hw::sniff_start 8
hw::send 60 'udp(src_ip="10.99.176.1", dst_port=5000)'
sleep 1
hw::sniff_wait

# The traffic really did cross the wire and really did reach zone a —
# without this the "zone b is zero" assertion would be vacuous.
assert_eq "frames reached zone a's port" \
  "$(hw::sniff_get udp:10.99.176.1:5000)" 60
assert_eq "zone a counted its own traffic" "$(hw::counter a_hits)" 60

# The silent-aliasing assertion. Under a shared counter map, slot 0 is
# one cell and b_hits reads back zone a's 60.
assert_eq "zone b's counter untouched by zone a's traffic" \
  "$(hw::counter b_hits)" 0

# Same assertion for the sampling accumulator. Zone a's map must have
# advanced (proving the accumulator is live and the check is not
# vacuous); zone b's must be exactly as it started.
AFTER_LS_A=$(hw::map_sum fwl_log_sample_a)
AFTER_LS_B=$(hw::map_sum fwl_log_sample_b)
log "log_sample sums: a=$AFTER_LS_A b=$BEFORE_LS_B->$AFTER_LS_B"
if [ "$AFTER_LS_A" -gt 0 ]; then
  pass "zone a's log-sample accumulator advanced ($AFTER_LS_A)"
else
  fail "zone a's log-sample accumulator did not advance \
($AFTER_LS_A) — the test proves nothing"
fi
assert_eq "zone b's log-sample accumulator untouched by zone a" \
  "$AFTER_LS_B" "$BEFORE_LS_B"

rm -f "$FW"
