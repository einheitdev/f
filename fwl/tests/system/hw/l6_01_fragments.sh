#!/usr/bin/env bash
# Does a non-first IP fragment match L4 rules?
#
# FWL_V01_SPEC:204 states: "a fragment that does not contain the L4
# header (offset > 0) cannot match rules referencing L4 fields."
#
# A non-first fragment carries no L4 header — its bytes at ihl*4 are
# ordinary payload. If the datapath reads L4 there without checking
# the fragment offset, those payload bytes are parsed as ports, and
# an attacker who controls payload controls what the filter sees.
# That is the classic tiny-fragment firewall bypass.
#
# The control is what makes this conclusive. Two identical fragments
# differing only in their payload bytes:
#   - bytes that look like the ALLOWED port
#   - bytes that look like a BLOCKED port
# If both are dropped, the offset is respected (spec honored).
# If both pass, fragments bypass L4 rules some other way.
# If they diverge, the payload IS being read as an L4 header —
# a spec violation and a bypass primitive.
source "$(dirname "$0")/hwlib.sh"
hw::require_root
trap hw::finish EXIT

FW=$(mktemp --suffix=.fw)
cat > "$FW" <<EOF
zone t = [$RECV_IF]

@xdp(t)

count all_from_test if pkt.src_ip in 10.99.20.0/24
count saw_443 if pkt.proto == tcp and pkt.dst_port == 443
count saw_9999 if pkt.proto == tcp and pkt.dst_port == 9999
allow if pkt.proto == tcp and pkt.dst_port == 443
default drop
EOF
hw::deploy l6-01 "$FW"

hw::sniff_start 10
# Baseline: a well-formed unfragmented packet on each port.
hw::send 50 'tcp(src_ip="10.99.20.1", dst_ip="10.99.20.9", dst_port=443)'
hw::send 50 'tcp(src_ip="10.99.20.1", dst_ip="10.99.20.9", dst_port=9999)'
# First fragment (offset 0, MF): it DOES carry a real L4 header, so
# per spec it may legitimately match L4 rules.
$PY "$HERE/sendraw.py" "$SEND_IF" 50 firstfrag \
  src_ip=10.99.20.2 dport=443
# Non-first fragments (offset 8): no L4 header present. Payload
# bytes mimic an allowed port in one case, a blocked port in the
# other.
$PY "$HERE/sendraw.py" "$SEND_IF" 50 frag \
  src_ip=10.99.20.3 offset=8 dport=443
$PY "$HERE/sendraw.py" "$SEND_IF" 50 frag \
  src_ip=10.99.20.4 offset=8 dport=9999
sleep 1
hw::sniff_wait

assert_eq "baseline: allowed port passed" \
  "$(hw::sniff_get tcp:10.99.20.1:443)" 50
assert_eq "baseline: blocked port dropped" \
  "$(hw::sniff_get tcp:10.99.20.1:9999)" 0
assert_eq "first fragment (has a real L4 header) passed" \
  "$(hw::sniff_get tcp:10.99.20.2:443)" 50

FRAG_ALLOWED=$(hw::sniff_get tcp:10.99.20.3:443)
FRAG_BLOCKED=$(hw::sniff_get tcp:10.99.20.4:9999)
log "non-first fragment mimicking allowed port : $FRAG_ALLOWED/50 passed"
log "non-first fragment mimicking blocked port : $FRAG_BLOCKED/50 passed"

if [ "$FRAG_ALLOWED" -gt 0 ] && [ "$FRAG_BLOCKED" -eq 0 ]; then
  fail "SPEC VIOLATION + BYPASS: a non-first fragment's payload is \
parsed as an L4 header. Payload bytes mimicking the allowed port let \
$FRAG_ALLOWED/50 fragments through a default-drop policy, while the \
same fragment with 'blocked port' bytes was dropped — proving the \
payload, not a header, decided it. FWL_V01_SPEC:204 says offset>0 \
cannot match L4 rules. Fix: gate L4 field reads on \
(frag_off & 0x1fff) == 0."
elif [ "$FRAG_ALLOWED" -eq 0 ] && [ "$FRAG_BLOCKED" -eq 0 ]; then
  pass "non-first fragments cannot match L4 rules (spec honored)"
else
  fail "unexpected fragment behavior: allowed-mimic=$FRAG_ALLOWED \
blocked-mimic=$FRAG_BLOCKED — investigate before trusting either"
fi
assert_eq "fragments still counted at IP level (spec: IPv4 fields \
still match)" "$(hw::counter all_from_test)" 250
