#!/usr/bin/env bash
# KNOWN GAP: Tier 2 `rate_limit(...)` never fires.
#
# FWL_V02_SPEC.md:640-647 documents the Tier 2 call form as a live
# boolean — "true when the bucket is at or above the threshold". The
# emitter instead returns a constant:
#
#   emitter.py: `if isinstance(expr, ast.RateLimitCall):`
#               `  # v0.2 minimum-viable: emit a stub that always`
#               `  # returns false. Real rate_limit_call`
#               `  # implementation is deferred to v0.3.`
#               `  return "(0)"`
#
# The interpreter models it the same way, so all three oracles agree
# and no `.pkt` corpus case can ever catch it — the exact shape
# ANTI_STUB.md Rule 4 warns about ("a test that only verifies the
# stub's default return"). Only differential testing against the
# Tier 1 form, on real traffic, exposes it.
#
# This test asserts TODAY'S behavior so the gap is visible and the
# eventual implementation is caught by a failing test rather than
# forgotten. When Tier 2 rate_limit lands, this test SHOULD fail —
# read the header, flip the expectation.
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
# ...and today lets all of it through.
if [ "$T2_PASSED" -eq "$BURST" ]; then
  pass "KNOWN GAP CONFIRMED: Tier 2 rate_limit() is a compile-time \
constant false — $T2_PASSED/$BURST passed, nothing was limited, \
while the Tier 1 form capped the identical flood at $T1_PASSED. \
A Tier 2 policy that rate-limits silently does not."
else
  fail "Tier 2 rate_limit behavior CHANGED: $T2_PASSED/$BURST passed \
(expected all $BURST under the known stub). If Tier 2 rate_limit was \
implemented, this test has done its job — update it to assert real \
limiting (range $LIMIT..$((LIMIT * 2)), like Tier 1 above) and drop \
the KNOWN GAP framing."
fi
