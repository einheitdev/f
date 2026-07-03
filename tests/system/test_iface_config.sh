#!/usr/bin/env bash
# System test: `configure interface` via the CLI actually changes the
# interface (ip) and persists to networkd. Stub-proof: asserts the real
# kernel state changed, not just the command's return. Requires root.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLI="${FT_CLI:-$HOME/f-appliance/f/build/einheit-f}"
IF=ftcfgtest0
NET="/etc/systemd/network/10-f-$IF.network"

cli() { printf '%s\n' "$1" | "$CLI" --socket ipc:///tmp/nofd.sock \
          --ascii --color never --width 80 2>/dev/null; }
cleanup() { ip link del "$IF" 2>/dev/null; rm -f "$NET"; }
fail() { echo "FAIL: $*"; cleanup; exit 1; }
trap cleanup EXIT

ip link del "$IF" 2>/dev/null; ip link add "$IF" type dummy || fail "mk dummy"

cli "set address $IF 10.99.0.1/24" >/dev/null
ip addr show "$IF" | grep -q 'inet 10.99.0.1/24' || fail "address not applied"
grep -q 'Address=10.99.0.1/24' "$NET" 2>/dev/null || fail "address not persisted"
echo "  set address OK (applied + persisted)"

# Second address should merge, not replace.
cli "set address $IF 10.99.0.2/24" >/dev/null
grep -q 'Address=10.99.0.1/24' "$NET" && grep -q 'Address=10.99.0.2/24' "$NET" \
  || fail "second address did not merge in networkd"
echo "  merge address OK"

cli "set mtu $IF 1400" >/dev/null
[ "$(cat /sys/class/net/$IF/mtu)" = 1400 ] || fail "mtu not applied"
grep -q 'MTUBytes=1400' "$NET" || fail "mtu not persisted"
echo "  set mtu OK"

cli "set link $IF up" >/dev/null
ip link show "$IF" | grep -q 'UP' || fail "link not brought up"
echo "  set link up OK"

cli "no address $IF 10.99.0.1/24" >/dev/null
ip addr show "$IF" | grep -q '10.99.0.1/24' && fail "address not removed"
grep -q 'Address=10.99.0.1/24' "$NET" && fail "removed address still persisted"
grep -q 'Address=10.99.0.2/24' "$NET" || fail "other address wrongly dropped"
echo "  no address OK (removed, other kept)"

# Error path: unknown interface must be rejected.
out="$(cli 'set address nope99nope 1.2.3.4/24')"
echo "$out" | grep -qi 'not found' || fail "missing iface not rejected"
echo "  error path OK"

echo "PASS: interface config applies via ip + persists to networkd"
cleanup
trap - EXIT
exit 0
