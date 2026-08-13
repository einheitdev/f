#!/usr/bin/env bash
# A logged event identifies the zone that emitted it.
#
# `fwl_log_events` is ONE ring buffer for the whole bundle. That is the
# right shape — it is fixed size and genuinely bundle-wide — but
# `rule_index` is numbered per ZONE, so before the zone tag, zone za's
# rule 1 and zone zb's rule 1 wrote the identical number into the
# identical ring. A consumer reading that ring could not tell them
# apart, and nothing anywhere reported an error: every logged event in
# a multi-zone bundle was ambiguous, and log data you cannot attribute
# to a zone is not analysable.
#
# The policy below is built so that NOTHING BUT the tag can separate
# the two streams:
#   - both zones put their `log` rule at rule index 1 (asserted from
#     the generated C, not assumed);
#   - both zones declare one counter and two rules, so every map shape
#     matches and no size difference distinguishes them either.
# The only thing carrying the difference into userspace is `zone_id`,
# resolved to a name through the bundle's own manifest.json.
#
# Like l8_07, this is a property of the artifact SET: BPF_PROG_RUN
# loads one object at a time, so no single-object oracle can watch two
# zones share one ring. It needs real libbpf, a real pin root, and
# both directions of real wire.
#
# Vacuity: "attributed correctly" passes for free if nothing was
# logged, or if only one of the two zones ever logged. So this asserts,
# BEFORE any attribution claim, that each zone's own counter moved and
# that events actually arrived carrying each zone's traffic — the same
# guard l8_07 puts in front of its silent-aliasing assertion.
source "$(dirname "$0")/hwlib.sh"
hw::require_root
trap hw::finish EXIT

FW=$(mktemp --suffix=.fw)
LOGOUT=$(mktemp)
RLERR=$(mktemp)

# Zone za owns the port that normally SENDS, zone zb the one that
# normally receives, because both zones have to receive here.
cat > "$FW" <<EOF
zone za = [$SEND_IF]
zone zb = [$RECV_IF]

@xdp(za)
count za_hits if pkt.proto == udp and pkt.dst_port == 7801
log if pkt.proto == udp and pkt.dst_port == 7801
default allow

@xdp(zb)
count zb_hits if pkt.proto == udp and pkt.dst_port == 7802
log if pkt.proto == udp and pkt.dst_port == 7802
default allow
EOF
hw::deploy l8-11 "$FW"
hw::open_reverse_path

MANIFEST="$BUNDLE_ROOT/current/manifest.json"

# ------------------------------------------------------------------
# The premise: identical rule numbering in both zones
# ------------------------------------------------------------------
# If these ever differ the test still passes, but it stops being about
# the zone tag — rule_index alone would separate the streams. Read out
# of the emitted C so the premise is verified, not assumed.
ZA_RULE=$(grep -o 'ev->rule_index = [0-9]*' \
  "$BUNDLE_ROOT/current/za.bpf.c" | head -1 | awk '{print $3}')
ZB_RULE=$(grep -o 'ev->rule_index = [0-9]*' \
  "$BUNDLE_ROOT/current/zb.bpf.c" | head -1 | awk '{print $3}')
assert_eq "zone za logs from rule index" "${ZA_RULE:--1}" 1
assert_eq "zone zb logs from the SAME rule index" \
  "${ZB_RULE:--1}" 1

# ------------------------------------------------------------------
# The lookup table ships with the bundle
# ------------------------------------------------------------------
# A numeric id a consumer cannot resolve to a zone name is not an
# improvement on no id at all.
ZA_ID=$($PY -c "
import json
print(json.load(open('$MANIFEST')).get('zone_ids', {}).get('za', -1))
")
ZB_ID=$($PY -c "
import json
print(json.load(open('$MANIFEST')).get('zone_ids', {}).get('zb', -1))
")
log "zone ids: za=$ZA_ID zb=$ZB_ID"
if [ "$ZA_ID" -gt 0 ] && [ "$ZB_ID" -gt 0 ] \
   && [ "$ZA_ID" -ne "$ZB_ID" ]; then
  pass "manifest maps both zone names to distinct ids"
else
  fail "manifest zone_ids unusable: za=$ZA_ID zb=$ZB_ID"
fi

# The zone tag must be in the emitted objects too, not only the
# manifest — the manifest is the table, the object is what writes the
# id a record carries.
if grep -q "ev->zone_id = " "$BUNDLE_ROOT/current/za.bpf.c" \
   && grep -q "ev->zone_id = " "$BUNDLE_ROOT/current/zb.bpf.c"; then
  pass "both zone objects stamp a zone id into every record"
else
  fail "a zone object emits log events with no zone id"
fi

# ------------------------------------------------------------------
# Both zones log, on real wire
# ------------------------------------------------------------------
$PY "$HERE/ringlog.py" 12 "$PIN/fwl_log_events" "$MANIFEST" \
  > "$LOGOUT" 2> "$RLERR" &
RLPID=$!
sleep 1
# Into zone zb: the normal path, SEND_IF -> EX2300 -> RECV_IF.
hw::send 100 'udp(src_ip="10.99.11.1", dst_port=7802)'
# Into zone za: back down the same path with the MACs swapped, so the
# frame unicasts into SEND_IF instead of returning to the port it left.
hw::send_reverse 100 'udp(src_ip="10.99.11.2", dst_port=7801)'
sleep 1
wait "$RLPID"
RL_RC=$?
cat "$RLERR"

# The ring consumer validates the record header (magic + ABI version +
# size) before reading any field, and exits 3 if it ever rejected one.
# A layout mismatch would otherwise read back as plausible wrong data.
assert_eq "every record passed the ABI header check" "$RL_RC" 0

# Independent witness that the traffic really reached both zones. If
# either of these is zero the attribution assertions below would be
# vacuous, so they are asserted first and on a separate mechanism
# (per-zone counter maps, not the ring).
assert_eq "zone za's own counter saw its traffic" \
  "$(hw::counter za_hits)" 100
assert_eq "zone zb's own counter saw its traffic" \
  "$(hw::counter zb_hits)" 100

# ------------------------------------------------------------------
# Attribution
# ------------------------------------------------------------------
# Every record carrying za's traffic signature must name za, and
# likewise zb. Counted per (zone, dst_port) pair, so a record tagged
# with the wrong zone shows up as both a missing hit and a cross hit.
# `src_ip` is a second, independent per-zone signature — the two
# bursts differ in it as well — and reading it also holds down that
# the record's address fields decode the right way round.
read -r ZA_OWN ZB_OWN ZA_CROSS ZB_CROSS UNRESOLVED BADIP \
  < <($PY -c "
import json, sys
za_own = zb_own = za_cross = zb_cross = unresolved = badip = 0
SRC = {7801: '10.99.11.2', 7802: '10.99.11.1'}
for line in open('$LOGOUT'):
  line = line.strip()
  if not line or line.startswith('#'):
    continue
  ev = json.loads(line)
  zone, port = ev['zone'], ev['dst_port']
  if ev['src_ip'] != SRC.get(port):
    badip += 1
  if zone is None:
    unresolved += 1
    continue
  if port == 7801:
    za_own += zone == 'za'
    zb_cross += zone == 'zb'
  elif port == 7802:
    zb_own += zone == 'zb'
    za_cross += zone == 'za'
print(za_own, zb_own, za_cross, zb_cross, unresolved, badip)
")
log "events: za_own=$ZA_OWN zb_own=$ZB_OWN cross(za)=$ZA_CROSS \
cross(zb)=$ZB_CROSS unresolved=$UNRESOLVED bad_src_ip=$BADIP"

# Vacuity guards: both zones must actually have produced events.
if [ "$ZA_OWN" -gt 0 ]; then
  pass "zone za produced log events ($ZA_OWN)"
else
  fail "zone za produced NO log events — attribution unproven"
fi
if [ "$ZB_OWN" -gt 0 ]; then
  pass "zone zb produced log events ($ZB_OWN)"
else
  fail "zone zb produced NO log events — attribution unproven"
fi

assert_eq "every za frame logged, attributed to za" "$ZA_OWN" 100
assert_eq "every zb frame logged, attributed to zb" "$ZB_OWN" 100
assert_eq "no zb traffic attributed to za" "$ZA_CROSS" 0
assert_eq "no za traffic attributed to zb" "$ZB_CROSS" 0
assert_eq "every record's zone id resolved through the manifest" \
  "$UNRESOLVED" 0
assert_eq "every record's src_ip is the address that was sent" \
  "$BADIP" 0

rm -f "$FW" "$LOGOUT" "$RLERR"
