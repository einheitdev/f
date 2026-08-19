#!/usr/bin/env bash
# Tier 2 `rate_limit(...)` limits, and limits like Tier 1 does.
#
# This test was written to assert the opposite. Until 2026-08-19 the
# emitter returned a constant `(0)` for the Tier 2 call form and the
# interpreter returned a constant False, so all three oracles agreed
# and no `.pkt` corpus case could catch it — the exact shape
# ANTI_STUB.md Rule 4 warns about ("a test that only verifies the
# stub's default return"). Only differential testing against the Tier 1
# form, on real traffic, exposed it: 1000/1000 frames passed the Tier 2
# form while the identical flood was capped at ~50 by the modifier.
#
# The gap is closed. The expectation below is flipped accordingly, and
# the two forms are now compared rather than contrasted — which is a
# stronger check than either half alone, because the failure this
# guards against is no longer "no limiter" but "a limiter that
# disagrees with the other tier", and a policy author cannot see which
# tier their rule compiled through.
#
# The filename still says `gap`. Kept deliberately: the vacuity sweep's
# history is keyed by this ID, and renaming it resets the record of
# whether this check has ever gone red.
#
# REQUIRES a compiler at or past the Tier 2 rate_limit implementation.
# Against an older build this fails, and the failure is correct.
source "$(dirname "$0")/hwlib.sh"
hw::require_root
trap hw::finish EXIT

BURST=1000
LIMIT=50

# ---------- Tier 1 control: the modifier form works ----------
FW=$(mktemp --suffix=.fw)
cat > "$FW" <<EOF
zone t = [$RECV_IF]

@xdp(t)

count seen if pkt.src_ip == 10.99.130.1
drop if pkt.proto == udp and pkt.src_ip == 10.99.130.1
       limited by rate_limit($LIMIT, per=src_ip)
default allow
EOF
hw::deploy l7-01a "$FW"

hw::sniff_start 8
hw::send "$BURST" 'udp(src_ip="10.99.130.1", dst_port=5000)'
sleep 1
hw::sniff_wait
T1_SEEN=$(hw::counter seen)
T1_PASSED=$(hw::sniff_get udp:10.99.130.1:5000)

# ---------- Tier 2: the call form, same intent ----------
cat > "$FW" <<EOF
zone t = [$RECV_IF]

@xdp(t)

def filter(pkt):
  if pkt.proto == udp and pkt.src_ip == 10.99.130.2:
    count seen2
    if rate_limit($LIMIT, per=src_ip):
      drop
  allow
EOF
hw::deploy l7-01b "$FW"

hw::sniff_start 8
hw::send "$BURST" 'udp(src_ip="10.99.130.2", dst_port=5000)'
sleep 1
hw::sniff_wait
T2_SEEN=$(hw::counter seen2)
T2_PASSED=$(hw::sniff_get udp:10.99.130.2:5000)

log "Tier 1 modifier : $T1_PASSED/$T1_SEEN passed (limit $LIMIT)"
log "Tier 2 call     : $T2_PASSED/$T2_SEEN passed (limit $LIMIT)"

# Tier 1 must cap the flood.
assert_eq "Tier 1: every frame reached the program" \
  "$T1_SEEN" "$BURST"
assert_range "Tier 1 modifier caps the flood" \
  "$T1_PASSED" "$LIMIT" "$((LIMIT * 2))"

# Tier 2 must see the same traffic...
assert_eq "Tier 2: every frame reached the program" \
  "$T2_SEEN" "$BURST"
# ...and cap it, on the same bar the Tier 1 half is held to.
assert_range "Tier 2 rate_limit() caps the flood" \
  "$T2_PASSED" "$LIMIT" "$((LIMIT * 2))"

# The point is not that each half limits, but that they agree. A Tier 2
# limiter with its own idea of what "rate exceeded" means would pass
# both range checks above and still be a defect -- and a silent one,
# since nothing in the policy shows which tier a rule compiled through.
# Both halves saw identical floods at identical thresholds, so their
# pass counts must land close together.
DELTA=$(( T1_PASSED > T2_PASSED ? T1_PASSED - T2_PASSED \
                                : T2_PASSED - T1_PASSED ))
assert_range "the two tiers limit the same flood the same way" \
  "$DELTA" 0 "$((LIMIT / 2))"

pass "Tier 2 rate_limit() limits: $T2_PASSED/$BURST passed against \
the Tier 1 form's $T1_PASSED/$BURST at threshold $LIMIT. The gap this \
test was written to record is closed."
