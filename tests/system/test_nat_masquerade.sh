#!/usr/bin/env bash
# System test: masquerade rewrites the source to the WAN address.
#
# Regression for the fwl_nat_cfg seeding bug — the daemon must program
# the masquerade source (the WAN interface address) into fwl_nat_cfg or
# the XDP `masquerade` action no-ops and the internal source IP leaks to
# the WAN. Stub-proof: asserts the captured source is the WAN address
# AND that the rewritten packet's IP + TCP checksums are valid.
#
# Runs a real fd + real XDP on a veth gateway topology; requires root.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

BUNDLE="${FT_BUNDLE:-$HOME/fwtest/bundle}"
WAN_ADDR=203.0.113.1
LAN_SRC=10.0.0.2

fail() { echo "FAIL: $*"; bash "$here/lib/gw_topo.sh" down; exit 1; }

FT_FD="${FT_FD:-$HOME/f-appliance/f/build/fd}" \
  bash "$here/lib/gw_topo.sh" up "$BUNDLE" || fail "topology up failed"

out="$(bash "$here/nat_masquerade_probe.sh" 2>/dev/null)"
echo "$out"

cap_src="$(echo "$out" | sed -n 's/^CAP src=\([0-9.]*\).*/\1/p')"
[ -n "$cap_src" ] || fail "no packet captured on WAN (redirect/masq broke)"
[ "$cap_src" = "$WAN_ADDR" ] || \
  fail "source not masqueraded: saw $cap_src, want $WAN_ADDR" \
       "(internal address leaked)"
[ "$cap_src" != "$LAN_SRC" ] || fail "internal source $LAN_SRC leaked"
echo "$out" | grep -q "ip_ok=True tcp_ok=True" || \
  fail "rewritten packet has invalid checksum"

echo "PASS: masquerade rewrote $LAN_SRC -> $WAN_ADDR, checksums valid"
bash "$here/lib/gw_topo.sh" down
exit 0
