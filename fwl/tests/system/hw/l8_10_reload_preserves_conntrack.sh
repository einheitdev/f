#!/usr/bin/env bash
# Established connections survive a policy reload.
#
# The reload path deliberately keeps the flow-keyed pins (conntrack,
# fwl_nat) while replacing every policy-scoped one. That is not an
# optimisation: a firewall that drops every established connection when
# a rule is edited cannot be reloaded in production, so the operator
# edits nothing and the box drifts. The property was relied on, argued
# about and hardened — l3_01 measures zero packet loss across a reload
# — but never actually asserted, which is a poor state for something
# the cold-boot pin work is under standing orders not to weaken.
#
# So it is asserted here, from both ends:
#
#   the kernel map identity is unchanged across the reload — the same
#     map, not a new one that resembles it;
#
#   the datapath agrees. A flow opened under the OLD policy still reads
#     ESTABLISHED to the program the NEW policy installed, and the
#     counters that report it are the new policy's own (policy-scoped
#     maps ARE replaced, so they start from zero — which is what makes
#     the post-reload count exact rather than a delta).
#
# The reload is the real one: the source file is edited and fd's
# watcher recompiles and applies it, as in l3_01. No fd restart.
source "$(dirname "$0")/hwlib.sh"
hw::require_root

RULES_BAK=$(mktemp)
cp /etc/f/rules.fw "$RULES_BAK"
cleanup() {
  cp "$RULES_BAK" /etc/f/rules.fw
  hw::finish
}
trap cleanup EXIT

SRC=10.99.62.9
SPORT=42009
DPORT=5062
FW=$(mktemp --suffix=.fw)

cat > "$FW" <<EOF
zone t = [$RECV_IF]

@xdp(t)
count est if conntrack(pkt).state == established and pkt.src_ip == $SRC
count fresh if conntrack(pkt).state == new and pkt.src_ip == $SRC
allow if pkt.proto == udp and pkt.src_ip == $SRC
default drop
EOF
# The watched source is put in place BEFORE fd starts, so the watcher
# baselines its fingerprint on this content at init and the only reload
# in this test is the one below. Installing it afterwards (as l3_01
# does, which does not read counters beforehand) makes the watcher fire
# within its 5 s poll and silently zero the pre-reload counters — the
# vacuity guard caught that too.
cp "$FW" /etc/f/rules.fw
hw::deploy l8-10 /etc/f/rules.fw

# Open the connection under the pre-reload policy.
hw::sniff_start 6
hw::send 10 "udp(src_ip=\"$SRC\", src_port=$SPORT, dst_port=$DPORT)"
sleep 1
hw::sniff_wait
assert_eq "flow reached the zone's port" \
  "$(hw::sniff_get udp:$SRC:$DPORT)" 10

# --- vacuity guard -------------------------------------------------
# There must be state to preserve before "preserved" can mean
# anything. Frame 1 was NEW and created the entry; 2..10 were
# ESTABLISHED against it.
assert_eq "the flow was established under the old policy" \
  "$(hw::counter est)" 9
assert_eq "and opened exactly once" "$(hw::counter fresh)" 1
CT_ID_BEFORE=$(hw::map_id conntrack)
CT_ENTRIES_BEFORE=$(hw::map_entries conntrack)
CNT_ID_BEFORE=$(hw::map_id fwl_counters_t)
if [ "$CT_ID_BEFORE" -gt 0 ] && [ "$CT_ENTRIES_BEFORE" -gt 0 ]; then
  pass "conntrack holds $CT_ENTRIES_BEFORE entries (id $CT_ID_BEFORE)"
else
  fail "no conntrack state before the reload"
fi

# Which bundle is ACTIVE, not how many exist. Counting directories is
# not evidence of a reload: the same reload that produces a bundle also
# PRUNES old ones ("pruned 40 old bundle(s), keeping 10"), so on a rig
# where watcher bundles had accumulated the count went DOWN across a
# reload that had worked — and here it also gated the wait loop, so the
# scenario sat out its full 30 s and aborted on a reload that had
# landed at second five. Caught on 2026-08-15; l3_01 carried the same
# defect. The symlink is the claim, and nothing else moves it.
BUNDLE_BEFORE=$(readlink -f "$BUNDLE_ROOT/current")
hw::journal_mark

# The reload: append an unrelated rule to the watched source. The
# watcher recompiles and applies it in place — no restart, no detach.
# The rule count changes, so the policy-scoped maps must be rebuilt
# (fwl_log_sample/fwl_counters are sized from this zone's analysis)
# while the flow-keyed one must not.
sed -i "s/^default drop/drop if pkt.proto == tcp and pkt.dst_port == 12346\ndefault drop/" \
  /etc/f/rules.fw

for i in $(seq 1 30); do
  if [ "$(readlink -f "$BUNDLE_ROOT/current")" != "$BUNDLE_BEFORE" ]; then
    break
  fi
  sleep 1
done
sleep 2
if [ "$(readlink -f "$BUNDLE_ROOT/current")" != "$BUNDLE_BEFORE" ] \
   && hw::journal_since | grep -q "atomic swap"; then
  pass "watcher reloaded the policy in place (atomic swap)"
else
  journalctl -u fd -n 15 --no-pager >&2
  hw::abort "no reload observed — watcher did not fire"
fi

# fd is the same process: a restart here would make the whole test a
# cold-boot test by accident.
assert_eq "fd did not restart (still the reload path)" \
  "$(systemctl show fd -p NRestarts --value)" 0

# --- the property --------------------------------------------------
CT_ID=$(hw::map_id conntrack)
if [ "$CT_ID" -gt 0 ] && [ "$CT_ID" -eq "$CT_ID_BEFORE" ]; then
  pass "conntrack is the SAME kernel map after the reload (id $CT_ID)"
else
  fail "conntrack map id $CT_ID_BEFORE -> $CT_ID: state was dropped"
fi
CT_ENTRIES=$(hw::map_entries conntrack)
if [ "$CT_ENTRIES" -ge "$CT_ENTRIES_BEFORE" ]; then
  pass "conntrack entries preserved ($CT_ENTRIES_BEFORE -> $CT_ENTRIES)"
else
  fail "conntrack entries lost ($CT_ENTRIES_BEFORE -> $CT_ENTRIES)"
fi

# The counters, by contrast, MUST have been replaced: their slots are
# numbered by a compilation. Asserting this in the same test is what
# keeps "preserve conntrack" from being read as "preserve everything".
CNT_ID=$(hw::map_id fwl_counters_t)
if [ "$CNT_ID" -gt 0 ] && [ "$CNT_ID" -ne "$CNT_ID_BEFORE" ]; then
  pass "fwl_counters_t was rebuilt for the new policy \
($CNT_ID_BEFORE -> $CNT_ID)"
else
  fail "fwl_counters_t id unchanged ($CNT_ID) — stale slots carried over"
fi

# The datapath's own answer. Same 5-tuple, new program: every frame
# must read ESTABLISHED. If conntrack had been rebuilt, frame 1 would
# read NEW instead, so est=10/fresh=0 versus est=9/fresh=1 is the
# whole distinction, measured on the wire.
hw::sniff_start 6
hw::send 10 "udp(src_ip=\"$SRC\", src_port=$SPORT, dst_port=$DPORT)"
sleep 1
hw::sniff_wait
assert_eq "the flow still crosses the wire after the reload" \
  "$(hw::sniff_get udp:$SRC:$DPORT)" 10
assert_eq "every frame read ESTABLISHED to the new program" \
  "$(hw::counter est)" 10
assert_eq "none read NEW — the connection was never re-opened" \
  "$(hw::counter fresh)" 0

rm -f "$FW"
