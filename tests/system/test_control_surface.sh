#!/usr/bin/env bash
# System test: the v0.4 control surface (show zones / nat / conntrack).
#
# Brings up the real gateway, sends LAN->WAN traffic, and asserts the
# daemon reports the zone topology, the masquerade source + a live NAT
# reply mapping, over its ZMQ control socket. Stub-proof: the NAT entry
# only exists because a real masqueraded packet installed it.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

BUNDLE="${FT_BUNDLE:-$HOME/fwtest/bundle}"
SOCK="${FT_SOCK:-ipc:///tmp/fdtest.sock}"
ctl() { python3 "$here/lib/fdctl.py" "$1" "$SOCK"; }
fail() { echo "FAIL: $*"; bash "$here/lib/gw_topo.sh" down; exit 1; }

FT_FD="${FT_FD:-$HOME/f-appliance/f/build/fd}" \
  bash "$here/lib/gw_topo.sh" up "$BUNDLE" || fail "topology up failed"

lan_mac="$(cat /sys/class/net/lan0/address)"
ip netns exec lanhost python3 - "$lan_mac" >/dev/null 2>&1 <<'PY'
import sys
from scapy.all import Ether, IP, TCP, sendp
sendp(Ether(dst=sys.argv[1]) / IP(src="10.0.0.2", dst="203.0.113.9") /
      TCP(sport=40000, dport=80, flags="S"),
      iface="lan0p", count=3, inter=0.15, verbose=0)
PY
sleep 0.3

zones="$(ctl 9)"; echo "zones: $zones"
echo "$zones" | grep -q '"zone":"lan"' || fail "show zones missing lan"
echo "$zones" | grep -q '"zone":"wan"' || fail "show zones missing wan"
echo "$zones" | grep -q '"masquerades":true' || fail "lan masq flag missing"

nat="$(ctl 10)"; echo "nat: $nat"
echo "$nat" | grep -q '"masq_source":"203.0.113.1"' || \
  fail "nat masq_source wrong/absent"
echo "$nat" | grep -q '"proto":"tcp"' || \
  fail "no NAT translation installed by masqueraded traffic"

# conntrack is empty for this redirect-only gateway (no explicit allow);
# just assert the command returns a well-formed array.
ct="$(ctl 11)"; echo "conntrack: $ct"
[ "${ct:0:1}" = "[" ] || fail "show conntrack not a JSON array"

echo "PASS: control surface reports zones + NAT translation + masq source"
bash "$here/lib/gw_topo.sh" down
exit 0
