#!/usr/bin/env bash
# Test-plan L3 row 1: hot reload under live traffic, zero loss on
# untouched flows.
#
# A steady 200 pps stream runs against the watcher-managed policy
# (/etc/f/rules.fw). Mid-stream the policy is edited (an unrelated
# rule is appended); fd's watcher recompiles and applies the new
# bundle. The untouched flow must not lose a single frame.
#
# Loss accounting: sender reports frames actually handed to the NIC
# (an igb link reset surfaces as send errors, which also count as
# loss — the wire went down); the receiver sniffer counts arrivals
# after XDP. sent==received==2000 is the zero-loss criterion.
source "$(dirname "$0")/hwlib.sh"
hw::require_root

RULES_BAK=$(mktemp)
cp /etc/f/rules.fw "$RULES_BAK"
cleanup() {
  cp "$RULES_BAK" /etc/f/rules.fw
  hw::finish
}
trap cleanup EXIT

# Baseline policy through the normal deploy path (also resets pins),
# then hand the SAME policy to the watcher's source file.
FW=$(mktemp --suffix=.fw)
cat > "$FW" <<EOF
zone t = [$RECV_IF]

@xdp(t)

count stream if pkt.src_ip == 10.99.50.5
allow if pkt.proto == udp and pkt.src_ip == 10.99.50.5
default drop
EOF
hw::deploy l3-01 "$FW"
cp "$FW" /etc/f/rules.fw

# Watcher-produced bundles are timestamp-named (no v- prefix).
BUNDLES_BEFORE=$(ls -d "$BUNDLE_ROOT"/*/ | wc -l)
# Scope the reload evidence to THIS run: every scenario on this rig logs
# "atomic swap", so a 60 s window reads other people's reloads too.
hw::journal_mark

# 2000 frames at 200 pps = a 10 s window.
hw::sniff_start 14
$PY "$HERE/sendmany.py" --pps 200 "$SEND_IF" 2000 \
  'udp(src_ip="10.99.50.5", dst_port=5050)' > /tmp/l3_send.out &
SENDPID=$!
sleep 3

# Mid-stream: insert an unrelated rule; the watcher picks it up.
sed -i 's/^default drop/drop if pkt.proto == tcp and pkt.dst_port == 12345\ndefault drop/' /etc/f/rules.fw

wait "$SENDPID"
hw::sniff_wait
SENT=$(sed -n 's/^sent \([0-9]*\)\/.*/\1/p' /tmp/l3_send.out)
RECEIVED=$(hw::sniff_get udp:10.99.50.5:5050)

# The reload really happened (new bundle dir + atomic-swap journal
# line) while the stream was running.
BUNDLES_AFTER=$(ls -d "$BUNDLE_ROOT"/*/ | wc -l)
if [ "$BUNDLES_AFTER" -gt "$BUNDLES_BEFORE" ] \
   && hw::journal_since | grep -q "atomic swap"; then
  pass "watcher reloaded mid-stream (atomic swap applied)"
else
  fail "no reload observed — watcher did not fire"
fi

assert_eq "frames handed to the NIC" "$SENT" 2000
assert_eq "frames received through XDP (zero loss)" "$RECEIVED" 2000
