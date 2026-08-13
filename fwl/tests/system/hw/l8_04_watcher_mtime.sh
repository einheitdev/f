#!/usr/bin/env bash
# Does the watcher notice a policy change that preserves mtime?
#
# The watcher compares st_mtim only — no size, no inode, no hash. The
# normal editor path (write + rename, fresh mtime) is detected. But
# every mtime-preserving deployment tool is not: `cp -p`, `rsync -a`,
# `tar x`, `install -p`, restoring from a backup. The result is a new
# policy on disk, the old policy in the kernel, and nothing logged.
#
# Both halves are asserted: the positive control (ordinary edit IS
# detected) is what makes the negative meaningful.
source "$(dirname "$0")/hwlib.sh"
hw::require_root

RULES_BAK=$(mktemp)
cp /etc/f/rules.fw "$RULES_BAK"
cleanup() {
  cp "$RULES_BAK" /etc/f/rules.fw
  hw::finish
}
trap cleanup EXIT

BASE=$(mktemp --suffix=.fw)
cat > "$BASE" <<EOF
zone t = [$RECV_IF]

@xdp(t)

count seen if pkt.src_ip == 10.99.143.1
drop if pkt.proto == udp and pkt.dst_port == 6200
default allow
EOF
hw::deploy l8-04 "$BASE"
cp "$BASE" /etc/f/rules.fw
sleep 7

reloads() {
  journalctl -u fd --since "-10min" --no-pager | grep -c "reload: ok" \
    || true
}

# --- positive control: an ordinary in-place edit ---
R0=$(reloads)
sed -i 's/dst_port == 6200/dst_port == 6201/' /etc/f/rules.fw
sleep 9
R1=$(reloads)
if [ "$R1" -gt "$R0" ]; then
  pass "ordinary edit detected and reloaded ($R0 -> $R1)"
else
  fail "ordinary edit was NOT reloaded ($R0 -> $R1) — the watcher is \
not running at all, so the negative case below proves nothing"
fi

# --- the real case: replace content, preserve mtime ---
NEW=$(mktemp --suffix=.fw)
cat > "$NEW" <<EOF
zone t = [$RECV_IF]

@xdp(t)

count seen if pkt.src_ip == 10.99.143.1
drop if pkt.proto == udp and pkt.dst_port == 6202
default allow
EOF
# Give the replacement the SAME mtime as the file it replaces, which
# is exactly what cp -p / rsync -a / tar x do.
touch -r /etc/f/rules.fw "$NEW"
cp -p "$NEW" /etc/f/rules.fw
R2_BEFORE=$(reloads)
sleep 12
R2=$(reloads)

# Ask the wire which policy is actually live: the new file blocks
# 6202, the old one blocks 6201.
ip link set dev "$RECV_IF" promisc on
hw::sniff_start 6
hw::send 50 'udp(src_ip="10.99.143.1", dst_port=6202)'
hw::send 50 'udp(src_ip="10.99.143.1", dst_port=6201)'
sleep 1
hw::sniff_wait
NEW_BLOCKED=$(hw::sniff_get udp:10.99.143.1:6202)
OLD_BLOCKED=$(hw::sniff_get udp:10.99.143.1:6201)

log "mtime-preserving replace: reloads $R2_BEFORE -> $R2"
log "wire: port 6202 (new policy) passed=$NEW_BLOCKED, \
port 6201 (old policy) passed=$OLD_BLOCKED"

if [ "$R2" -eq "$R2_BEFORE" ] && [ "$NEW_BLOCKED" -gt 0 ]; then
  fail "SILENT STALE POLICY: a content change that preserved mtime \
was never noticed — no reload, nothing in the journal, and the wire \
confirms the OLD policy is still enforcing (port 6202 should be \
blocked by the file on disk but $NEW_BLOCKED/50 passed, while 6201 \
from the superseded policy is still being dropped). Any deployment \
using cp -p, rsync -a, tar x or a backup restore lands here. Use an \
editor-style write+rename, or touch the file afterwards."
else
  pass "mtime-preserving replacement was picked up (reloads \
$R2_BEFORE -> $R2, new policy live)"
fi
