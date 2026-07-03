#!/usr/bin/env bash
# System test: the configure -> compile -> hot-reload path is bulletproof.
#
#   1. baseline: masquerade rewrites LAN source to the WAN address.
#   2. BROKEN reload: a syntactically invalid source is rejected by
#      kReloadProg AND the running program keeps working (never installs
#      a broken program, never wedges the daemon).
#   3. GOOD reload: a valid new source (snat to a fixed address) is
#      compiled and hot-swapped, and the new rules take effect live.
#
# Requires root (real fd + XDP). Uses the netns gateway topology.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

SOCK="${FT_SOCK:-ipc:///tmp/fdtest.sock}"
FWL="${FT_FWL:-$HOME/.local/bin/fwl}"
SRC=/tmp/ftest-reload-src.fw
BUNDLE=/tmp/ftest-reload-bundle
WAN_ADDR=203.0.113.1
SNAT_ADDR=198.51.100.7

ctl() { python3 "$here/lib/fdctl.py" "$1" "$SOCK"; }
probe_src() {
  bash "$here/nat_masquerade_probe.sh" 2>/dev/null |
    sed -n 's/^CAP src=\([0-9.]*\).*/\1/p'
}
fail() { echo "FAIL: $*"; bash "$here/lib/gw_topo.sh" down; exit 1; }

# Initial masquerade gateway source + prebuilt bundle for cold boot.
cat >"$SRC" <<'FW'
zone wan = [wan0]
zone lan = [lan0]

@xdp(lan)
masquerade
redirect to wan

@xdp(wan)
redirect to lan if conntrack(pkt).state == established
drop
FW
rm -rf "$BUNDLE"
"$FWL" compile "$SRC" --bundle "$BUNDLE" >/dev/null 2>&1 || fail "prebuild"

FT_FD="${FT_FD:-$HOME/f-appliance/f/build/fd}" FT_SOURCE="$SRC" FT_FWL="$FWL" \
  bash "$here/lib/gw_topo.sh" up "$BUNDLE" || fail "topology up failed"

# 1. Baseline.
s="$(probe_src)"
[ "$s" = "$WAN_ADDR" ] || fail "baseline masq wrong: $s (want $WAN_ADDR)"
echo "baseline OK: src=$s"

# 2. Broken source must be rejected; old program must survive.
cat >"$SRC" <<'FW'
zone wan = [wan0]
@xdp(lan)
this is not valid fwl !!!
FW
r="$(ctl 4)"; echo "broken reload reply: $r"
echo "$r" | grep -q '"error"' || fail "broken source was NOT rejected"
s="$(probe_src)"
[ "$s" = "$WAN_ADDR" ] || \
  fail "running program broke after rejected reload: src=$s"
echo "broken-reload OK: rejected, old program intact (src=$s)"

# 3. Good source change must take effect: snat to a fixed address.
cat >"$SRC" <<FW
zone wan = [wan0]
zone lan = [lan0]

@xdp(lan)
snat to $SNAT_ADDR
redirect to wan

@xdp(wan)
redirect to lan if conntrack(pkt).state == established
drop
FW
r="$(ctl 4)"; echo "good reload reply: $r"
echo "$r" | grep -q '"status":"reloaded"' || fail "good reload not applied"
s="$(probe_src)"
[ "$s" = "$SNAT_ADDR" ] || \
  fail "hot-reload did not take effect: src=$s (want $SNAT_ADDR)"
echo "good-reload OK: new rules live (src=$s)"

echo "PASS: reload path bulletproof (baseline, reject-broken, apply-good)"
bash "$here/lib/gw_topo.sh" down
exit 0
