#!/usr/bin/env bash
# Cold boot over the pins a previous fd left in bpffs.
#
# A pinned map outlives the process that made it: bpffs holds a
# reference, so every map an fd incarnation pinned is still there for
# the next one. The reload path has always reconciled that; the
# cold-boot path did not, and the consequence was not a wrong number
# but a dead firewall — libbpf refuses to reuse a pin whose definition
# differs (-EINVAL, "parameter mismatch"), fd exits, systemd's Restart=
# turns that into a loop, and no XDP is attached anywhere. Measured
# here before the fix: 11 restarts, 0 programs attached, on a box whose
# only fault was that fd had been restarted rather than rebooted.
#
# A reboot cleared it because bpffs is a fresh mount; a restart did
# not. "Works after a reboot, fails after a restart" is a bad shape to
# meet in the field, and fd restarts are routine — a crash, a service
# restart, a package upgrade.
#
# The fix is not "delete everything under the pin root". Two questions
# decide each pin separately:
#
#   do the CONTENTS still mean anything under the next policy? Only
#     flow-keyed state does — conntrack and fwl_nat, keyed by a tuple
#     no policy defines. Counters, log-sample accumulators, geoip
#     tries, rate-limit buckets, devmaps and the log ring are all
#     numbered, sized or populated by one compilation.
#
#   does the DEFINITION still match what the incoming bundle declares?
#     Adopting without checking would put the -EINVAL back through the
#     one map allowed to persist.
#
# Part 1 covers the discard half, part 2 the adopt half. Part 2 is the
# one that asserts on behaviour rather than on loading.
source "$(dirname "$0")/hwlib.sh"
hw::require_root
trap hw::finish EXIT

WAN_IF="${WAN_IF:-enp1s0f2}"
FW=$(mktemp --suffix=.fw)

# The flow whose survival across the restart is the subject of part 2.
SRC=10.99.61.7
SPORT=41007
DPORT=5061

# ==================================================================
# Policy A — the previous incarnation's policy
# ==================================================================
# Zone a: 3 counters. Zone b: 1 counter. Both read conntrack, so the
# bundle pins a conntrack map as well as the per-zone private ones.
#
# Zone a's `allow if conntrack(...)` rule is load-bearing beyond what
# it matches: a zone program that never READS conntrack does not get
# the entry-creation snippet either, so a policy that only allows
# traffic tracks nothing and there would be no state to preserve. The
# vacuity guard below caught exactly that when this rule was missing.
cat > "$FW" <<EOF
zone a = [$RECV_IF]
zone b = [$WAN_IF]

@xdp(a)
count a_one
count a_two
count a_three
allow if conntrack(pkt).state == established and pkt.src_ip == $SRC
allow if pkt.proto == udp and pkt.src_ip == $SRC
default drop

@xdp(b)
count b_only
allow if conntrack(pkt).state == established
default allow
EOF
hw::deploy l8-09a "$FW"

# Open the flow that must survive the restart. The emitted program
# creates a conntrack entry on an explicit `allow` of a NEW IPv4 flow.
hw::sniff_start 6
hw::send 10 "udp(src_ip=\"$SRC\", src_port=$SPORT, dst_port=$DPORT)"
sleep 1
hw::sniff_wait
assert_eq "flow reached zone a's port" \
  "$(hw::sniff_get udp:$SRC:$DPORT)" 10

# --- vacuity guard -------------------------------------------------
# Everything below asserts that stale pins did not break the next
# load. Without this, "no conflict" would pass just as well on a box
# where nothing was ever pinned. Assert the pins exist, with policy
# A's shapes, and remember their kernel map ids.
A_CNT_SZ_BEFORE=$(bpftool -j map show pinned "$PIN/fwl_counters_a" 2>/dev/null \
  | $PY -c "import json,sys; print(json.load(sys.stdin)['max_entries'])" \
  2>/dev/null || echo -1)
assert_eq "policy A pinned fwl_counters_a, sized from its own analysis" \
  "$A_CNT_SZ_BEFORE" 3
B_CNT_ID_BEFORE=$(hw::map_id fwl_counters_b)
if [ "$B_CNT_ID_BEFORE" -gt 0 ]; then
  pass "policy A pinned fwl_counters_b (id $B_CNT_ID_BEFORE)"
else
  fail "policy A left no fwl_counters_b pin — nothing to go stale"
fi
A_CNT_ID_BEFORE=$(hw::map_id fwl_counters_a)
CT_ID_BEFORE=$(hw::map_id conntrack)
CT_ENTRIES_BEFORE=$(hw::map_entries conntrack)
if [ "$CT_ID_BEFORE" -gt 0 ] && [ "$CT_ENTRIES_BEFORE" -gt 0 ]; then
  pass "conntrack pinned (id $CT_ID_BEFORE) holding \
$CT_ENTRIES_BEFORE entries"
else
  fail "no established conntrack state to preserve \
(id=$CT_ID_BEFORE entries=$CT_ENTRIES_BEFORE)"
fi

# ==================================================================
# Policy B — restart onto a policy that collides with those pins
# ==================================================================
# Zone a keeps its name and changes its counter count (3 -> 2): the
# pinned name is the same, the definition is not, and that is exactly
# what libbpf rejects. Zone b is renamed to c, so fwl_counters_b
# becomes an orphan no incoming object declares at all — the second
# shape of staleness, which leaks kernel memory rather than failing a
# load.
#
# hw::deploy restarts fd WITHOUT clearing bpffs (it used to clear, and
# that workaround is why this defect survived 45 hardware scenarios).
cat > "$FW" <<EOF
zone a = [$RECV_IF]
zone c = [$WAN_IF]

@xdp(a)
count est if conntrack(pkt).state == established and pkt.src_ip == $SRC
count fresh if conntrack(pkt).state == new and pkt.src_ip == $SRC
allow if pkt.proto == udp and pkt.src_ip == $SRC
default drop

@xdp(c)
count c_one
count c_two
count c_three
count c_four
count c_five
allow if conntrack(pkt).state == established
default allow
EOF
# This is the step that used to end the test: fd could not load, so
# hw::deploy aborts on "fd did not attach XDP".
#
# Mark the journal first. The discard assertion below used a 120 s
# window, and l8_07 discards a pin of the same name; run back to back by
# the vacuity sweep, this scenario passed on the OTHER one's log line and
# the next run of the identical plant went red.
hw::journal_mark
hw::deploy l8-09b "$FW"

# ==================================================================
# Part 1 — the stale policy-scoped pins are gone, not adopted
# ==================================================================
A_UP=$(fctl status 2>/dev/null | $PY -c "
import json, sys
st = json.load(sys.stdin)
ifs = {i['name']: i['xdp_attached'] for i in st['interfaces']['interfaces']}
print(1 if ifs.get('$RECV_IF') else 0)
")
C_UP=$(fctl status 2>/dev/null | $PY -c "
import json, sys
st = json.load(sys.stdin)
ifs = {i['name']: i['xdp_attached'] for i in st['interfaces']['interfaces']}
print(1 if ifs.get('$WAN_IF') else 0)
")
assert_eq "fd came up on a dirty pin root: zone a attached" "$A_UP" 1
assert_eq "fd came up on a dirty pin root: zone c attached" "$C_UP" 1

# The counter map is the new policy's, not the old one's. Both halves
# matter: the right SIZE proves the map was recreated, and a different
# kernel ID proves it is a different map rather than one that happened
# to be resized.
A_CNT_SZ=$(bpftool -j map show pinned "$PIN/fwl_counters_a" 2>/dev/null \
  | $PY -c "import json,sys; print(json.load(sys.stdin)['max_entries'])" \
  2>/dev/null || echo -1)
assert_eq "fwl_counters_a re-created at policy B's size" "$A_CNT_SZ" 2
A_CNT_ID=$(hw::map_id fwl_counters_a)
if [ "$A_CNT_ID" -gt 0 ] && [ "$A_CNT_ID" -ne "$A_CNT_ID_BEFORE" ]; then
  pass "fwl_counters_a is a new kernel map \
($A_CNT_ID_BEFORE -> $A_CNT_ID), not the inherited one"
else
  fail "fwl_counters_a id unchanged ($A_CNT_ID) — stale map adopted"
fi

# The orphan: no object in policy B declares fwl_counters_b. It cannot
# collide with anything, which is why leaving it is tempting; it would
# also sit in bpffs holding a kernel map for as long as the box runs.
if [ -e "$PIN/fwl_counters_b" ]; then
  fail "orphan pin fwl_counters_b survived the policy change"
else
  pass "orphan pin fwl_counters_b (zone b is gone) was discarded"
fi
assert_eq "zone c's counter map sized from zone c's analysis" \
  "$(bpftool -j map show pinned "$PIN/fwl_counters_c" 2>/dev/null \
     | $PY -c "import json,sys; print(json.load(sys.stdin)['max_entries'])" \
     2>/dev/null || echo -1)" 5

# fd said what it did, in the journal the operator reads.
if hw::journal_since | grep -q "discarded stale pin 'fwl_counters_b'"; then
  pass "journal names the discarded stale pin"
else
  fail "journal does not report the discard"
fi

# ==================================================================
# Part 2 — the flow-keyed state IS adopted  (the half that matters)
# ==================================================================
# Same kernel map, not a new one that looks similar. This is what
# "adopted" means at the kernel level, and no count of entries can
# stand in for it.
CT_ID=$(hw::map_id conntrack)
if [ "$CT_ID" -gt 0 ] && [ "$CT_ID" -eq "$CT_ID_BEFORE" ]; then
  pass "conntrack survived the restart as the SAME kernel map (id $CT_ID)"
else
  fail "conntrack map id $CT_ID_BEFORE -> $CT_ID: state was discarded"
fi
CT_ENTRIES=$(hw::map_entries conntrack)
if [ "$CT_ENTRIES" -ge "$CT_ENTRIES_BEFORE" ]; then
  pass "conntrack entries preserved ($CT_ENTRIES_BEFORE -> $CT_ENTRIES)"
else
  fail "conntrack entries lost ($CT_ENTRIES_BEFORE -> $CT_ENTRIES)"
fi

# The behavioural reading, which is the only one that proves the
# adopted table is actually consulted by the NEW program. Resume the
# pre-restart flow, same 5-tuple. Under adoption every frame reads
# ESTABLISHED. Had the table been discarded, frame 1 would be NEW
# (creating the entry) and only frames 2..10 ESTABLISHED — so est=10
# and fresh=0 is the discriminator, and est=9/fresh=1 is precisely
# what a wrong answer looks like.
hw::sniff_start 6
hw::send 10 "udp(src_ip=\"$SRC\", src_port=$SPORT, dst_port=$DPORT)"
sleep 1
hw::sniff_wait
assert_eq "resumed flow reached zone a's port" \
  "$(hw::sniff_get udp:$SRC:$DPORT)" 10
assert_eq "every frame of the resumed flow read ESTABLISHED" \
  "$(hw::counter est)" 10
assert_eq "no frame of it read NEW (the table was not rebuilt)" \
  "$(hw::counter fresh)" 0

rm -f "$FW"
