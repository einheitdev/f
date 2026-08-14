#!/usr/bin/env bash
# System test: `show device` against a real fd behind a real masquerade.
#
# The defect this exists to keep fixed: conntrack is keyed on the
# addresses that are on the wire, and behind a masquerade those are the
# gateway's, not the device's. Filtering conntrack by the device's own
# address therefore finds nothing on exactly the topology the appliance
# is built to run — and the view said "fd is tracking no connections
# for this device" about a device with two. Confidently wrong, which is
# the one thing this CLI may not be.
#
# Stub-proof: the flows only exist because real masqueraded packets
# went through a real XDP program and installed them.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"

BUNDLE="${FT_BUNDLE:-$HOME/fwtest/bundle}"
SOCK="${FT_SOCK:-ipc:///tmp/fdtest.sock}"
CLI="${FT_CLI:-$root/build/einheit-f}"
export FT_SOCK
export FT_FD="${FT_FD:-$root/build/fd}"

work="$(mktemp -d /tmp/f-devflow-XXXXXX)"
fail() {
  echo "FAIL: $*"
  bash "$here/lib/gw_topo.sh" down
  rm -rf "$work"
  exit 1
}

bash "$here/lib/gw_topo.sh" up "$BUNDLE" || fail "topology up failed"
sleep 1

lan_mac="$(cat /sys/class/net/lan0/address)"
wan_mac="$(cat /sys/class/net/wan0/address)"

# Two outbound flows from one guest, both masqueraded.
ip netns exec lanhost python3 - "$lan_mac" >/dev/null 2>&1 <<'PY'
import sys
from scapy.all import Ether, IP, TCP, sendp
mac = sys.argv[1]
sendp(Ether(dst=mac) / IP(src="10.0.0.2", dst="203.0.113.9") /
      TCP(sport=40000, dport=80, flags="S"),
      iface="lan0p", count=4, inter=0.1, verbose=0)
sendp(Ether(dst=mac) / IP(src="10.0.0.2", dst="1.1.1.1") /
      TCP(sport=40001, dport=443, flags="S"),
      iface="lan0p", count=9, inter=0.05, verbose=0)
PY
sleep 0.5

cat > "$work/system.yaml" <<EOF
zones:
  lan:
  wan:
interfaces:
  lan0:
    mac: "$lan_mac"
    address: 10.0.0.1/24
    zone: lan
  wan0:
    mac: "$wan_mac"
    address: 203.0.113.1/24
    zone: wan
services:
  dhcp:
    - zone: lan
      range: 10.0.0.100-10.0.0.200
      lease: 10m
EOF
printf '%s 52:54:00:ab:cd:ef 10.0.0.2 lanhost *\n' \
  "$(( $(date +%s) + 600 ))" > "$work/leases"

cli() {
  "$CLI" --color never --width 140 \
    --system-config "$work/system.yaml" \
    --lease-file "$work/leases" \
    --device-journal "$work/devices.json" \
    --socket "$SOCK" "$@"
}

out="$(cli show device 10.0.0.2 2>&1)"
echo "$out"

echo "$out" | grep -q "tracking no connections" && \
  fail "the device's masqueraded flows were not found"
echo "$out" | grep -q "203.0.113.9:80" || \
  fail "flow to 203.0.113.9:80 missing"
echo "$out" | grep -q "1.1.1.1:443" || \
  fail "flow to 1.1.1.1:443 missing"
# The local port must be the device's own, not the wire's.
echo "$out" | grep -q "40001" || fail "local port 40001 missing"
# And the row must admit it was found through NAT.
echo "$out" | grep -q "nat" || \
  fail "translated flows are not marked as such"
# The NAT half joins on the translated address.
echo "$out" | grep -q "10.0.0.2:40000" || \
  fail "NAT translation for this device missing"

# A device with no flows at all is a different answer from a device
# whose flows could not be looked up.
printf '%s 52:54:00:ab:cd:11 10.0.0.7 quiet *\n' \
  "$(( $(date +%s) + 600 ))" >> "$work/leases"
quiet_out="$(cli show device 10.0.0.7 2>&1)"
echo "$quiet_out" | grep -q "tracking no connections" || \
  fail "a device with no flows should say fd answered and found none"
echo "$quiet_out" | grep -q "could not be asked" && \
  fail "fd was up; the view must not claim it could not be asked"

# With fd gone, the same command must say so rather than report zero.
bash "$here/lib/gw_topo.sh" down
down_out="$(cli show device 10.0.0.2 2>&1)"
echo "$down_out" | grep -q "could not be asked" || \
  fail "with fd down the flow half must say it could not be asked"
echo "$down_out" | grep -q "tracking no connections" && \
  fail "with fd down the view must not claim there are no flows"

rm -rf "$work"
echo "PASS: show device joins conntrack through NAT, and names the "\
"difference between no flows and no answer"
exit 0
