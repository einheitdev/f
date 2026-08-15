#!/usr/bin/env bash
# Test-plan L3 row 6: bad commit safety — a broken policy write must
# not take down the running one.
#
# A syntactically broken rules.fw reaches the watcher; the compile
# fails; the current symlink must not move and the active policy
# keeps enforcing on the wire.
source "$(dirname "$0")/hwlib.sh"
hw::require_root

RULES_BAK=$(mktemp)
cp /etc/f/rules.fw "$RULES_BAK"
cleanup() {
  cp "$RULES_BAK" /etc/f/rules.fw
  hw::finish
}
trap cleanup EXIT

FW=$(mktemp --suffix=.fw)
cat > "$FW" <<EOF
zone t = [$RECV_IF]

@xdp(t)

count good if pkt.src_ip == 10.99.52.5
drop if pkt.proto == udp and pkt.dst_port == 6666
default allow
EOF
hw::deploy l3-06 "$FW"
cp "$FW" /etc/f/rules.fw
# Let the watcher record the good mtime before we break it.
sleep 6

CURRENT_BEFORE=$(readlink "$BUNDLE_ROOT/current")
hw::journal_mark

cat > /etc/f/rules.fw <<EOF
zone t = [$RECV_IF]

@xdp(t)

drop if pkt.thisfield.does.not.exist == 1
default allow
EOF

# Give the watcher a full interval + compile time to trip over it.
sleep 12

CURRENT_AFTER=$(readlink "$BUNDLE_ROOT/current")
if [ "$CURRENT_BEFORE" = "$CURRENT_AFTER" ]; then
  pass "current symlink unmoved after broken commit"
else
  fail "current moved: $CURRENT_BEFORE -> $CURRENT_AFTER"
fi
hw::journal_since \
  | grep -qiE "compile|error|fail" \
  && pass "compile failure surfaced in the journal" \
  || fail "no compile-failure log line"
systemctl is-active fd >/dev/null \
  && pass "fd still active" || fail "fd died on a bad commit"

# The OLD policy still enforces on the wire.
hw::sniff_start 5
hw::send 100 'udp(src_ip="10.99.52.5", dst_port=6666)'
hw::send 100 'udp(src_ip="10.99.52.5", dst_port=7777)'
sleep 1
hw::sniff_wait
assert_eq "counter still counting" "$(hw::counter good)" 200
assert_eq "wire: old drop rule still enforced" \
  "$(hw::sniff_get udp:10.99.52.5:6666)" 0
assert_eq "wire: old allow still passing" \
  "$(hw::sniff_get udp:10.99.52.5:7777)" 100
