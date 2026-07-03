#!/usr/bin/env bash
# System test: the UI renders the v0.4 surface (zones / NAT / conntrack)
# from a live fd. Brings up the gateway, injects a masqueraded flow,
# starts einheit-f-ui against the test socket, and asserts each route's
# HTML contains the expected live data.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UI="${FT_UI:-$HOME/f-appliance/f/build/einheit-f-ui}"
BUNDLE="${FT_BUNDLE:-$HOME/fwtest/bundle}"
PORT=7542
SOCK=ipc:///tmp/fdtest.sock
PIN=/sys/fs/bpf/ftest

fail() { echo "FAIL: $*"; pkill -f "einheit-f-ui --socket" 2>/dev/null; bash "$here/lib/gw_topo.sh" down; exit 1; }

FT_FD="${FT_FD:-$HOME/f-appliance/f/build/fd}" \
  bash "$here/lib/gw_topo.sh" up "$BUNDLE" || fail "topology up"

# Inject a masqueraded flow so NAT + (potentially) conntrack populate.
lan_mac="$(cat /sys/class/net/lan0/address)"
ip netns exec lanhost python3 - "$lan_mac" <<'PY'
import sys
from scapy.all import Ether, IP, TCP, sendp
sendp(Ether(dst=sys.argv[1]) / IP(src="10.0.0.2", dst="203.0.113.9") /
      TCP(sport=40000, dport=80, flags="S"), iface="lan0p",
      count=3, inter=0.1, verbose=0)
PY
sleep 0.3

pkill -f "einheit-f-ui --socket" 2>/dev/null; sleep 0.5
# Fully detach (setsid + closed stdin/out) so the server never holds a
# parent pipe open — otherwise an SSH-invoked run hangs on the child.
setsid "$UI" --socket "$SOCK" --pin-path "$PIN" --port "$PORT" \
  </dev/null >/tmp/ui.log 2>&1 &
trap 'pkill -f "einheit-f-ui --socket $SOCK" 2>/dev/null' EXIT
# Wait for the server to accept connections.
ready=0
for _ in $(seq 1 20); do
  if curl -s -o /dev/null --max-time 2 "localhost:$PORT/"; then ready=1; break; fi
  sleep 0.5
done
[ "$ready" = 1 ] || fail "UI did not come up on :$PORT ($(tail -2 /tmp/ui.log))"

get() { curl -s --max-time 5 "localhost:$PORT/$1"; }

zones="$(get zones)"
echo "$zones" | grep -q '>lan<' || fail "/zones missing lan zone"
echo "$zones" | grep -q '>wan<' || fail "/zones missing wan zone"
echo "$zones" | grep -qiE '>yes<' || fail "/zones missing masq=yes badge"
echo "  /zones OK"

nat="$(get nat)"
echo "$nat" | grep -qi 'masquerade source' || fail "/nat missing masq source"
echo "$nat" | grep -q '203.0.113.1' || fail "/nat missing WAN source addr"
echo "$nat" | grep -q '10.0.0.2:40000' || fail "/nat missing translation"
echo "  /nat OK"

ct="$(get conntrack)"
echo "$ct" | grep -qiE 'no tracked|established|conntrack' || \
  fail "/conntrack did not render"
echo "  /conntrack OK"

dash="$(get '')"
echo "$dash" | grep -qi 'NAT translations' || fail "dashboard missing NAT summary"
echo "$dash" | grep -qi 'tracked connections' || fail "dashboard missing conntrack summary"
echo "  dashboard OK"

echo "PASS: UI renders v0.4 zones/NAT/conntrack from live fd"
pkill -f "einheit-f-ui --socket $SOCK" 2>/dev/null
bash "$here/lib/gw_topo.sh" down
exit 0
