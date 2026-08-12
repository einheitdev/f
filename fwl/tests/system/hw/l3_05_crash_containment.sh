#!/usr/bin/env bash
# Test-plan L3 row 5: fd crash containment — kill -9 under load, the
# XDP program keeps enforcing the last-committed policy.
#
# XDP attach outlives the daemon (it hangs off the netdev, maps are
# bpffs-pinned). A drop rule must keep dropping and counters keep
# counting with fd dead; a clean systemd restart then re-adopts.
#
# The measurement window has to be a window in which fd is REALLY
# dead. The unit is Restart=on-failure/RestartUSec=2s, so SIGKILL is
# followed by a fresh daemon two seconds later — measured:
#
#   t=1s ActiveState=activating SubState=auto-restart MainPID=0
#   t=2s ActiveState=activating SubState=start      MainPID=12963
#
# and this test's `is-active` check lands at t=1s, inside the
# auto-restart gap, so it reported "fd is down" and then measured a
# delta across a daemon that had come back. It passed only because
# the cold-boot path used to inherit the pinned counter map silently;
# once cold boot began reconciling bpffs the same test read a fresh
# map and a delta of -200. The property was never the one being
# measured. So systemd's resurrection is now cancelled for the
# duration, and the reset is asserted separately at the end.
source "$(dirname "$0")/hwlib.sh"
hw::require_root
trap hw::finish EXIT

FW=$(mktemp --suffix=.fw)
cat > "$FW" <<EOF
zone t = [$RECV_IF]

@xdp(t)

count seen if pkt.src_ip == 10.99.51.5
drop if pkt.proto == udp and pkt.dst_port == 6666
allow if pkt.proto == udp
default drop
EOF
hw::deploy l3-05 "$FW"

hw::sniff_start 16
# Load before the kill.
hw::send 100 'udp(src_ip="10.99.51.5", dst_port=6666)'
hw::send 100 'udp(src_ip="10.99.51.5", dst_port=7777)'
sleep 1
C_BEFORE=$(hw::counter seen)
CNT_ID_BEFORE=$(hw::map_id fwl_counters_t)

# systemd must not resurrect it mid-measurement. The kill is the
# crash; the stop cancels the auto-restart job it queues, so the
# window below has no daemon in it at all rather than a two-second
# gap followed by a new one.
systemctl kill -s KILL fd
systemctl stop fd
sleep 1
STATE=$(systemctl show fd -p ActiveState --value)
PID=$(systemctl show fd -p MainPID --value)
if [ "$STATE" = "inactive" ] && [ "$PID" = "0" ]; then
  pass "fd is down and staying down (SIGKILL, restart cancelled)"
else
  fail "fd not dead for the measurement: state=$STATE pid=$PID"
fi

# The datapath must not notice.
hw::send 100 'udp(src_ip="10.99.51.5", dst_port=6666)'
hw::send 100 'udp(src_ip="10.99.51.5", dst_port=7777)'
sleep 1
C_AFTER=$(hw::counter seen)
ATTACHED=$(ip -d link show "$RECV_IF" | grep -c " xdp")
DEAD_STATE=$(systemctl show fd -p ActiveState --value)

assert_eq "XDP still attached with fd dead" "$ATTACHED" 1
# Both halves of the delta were taken with no daemon running — this
# is the containment property, and nothing about fd's lifecycle can
# stand in for it.
assert_eq "counters kept counting with no daemon (delta 200)" \
  "$((C_AFTER - C_BEFORE))" 200
if [ "$DEAD_STATE" = "inactive" ]; then
  pass "fd was dead for the whole measurement window"
else
  fail "fd came back mid-window (state=$DEAD_STATE) — delta is not \
evidence of containment"
fi

# Clean recovery.
systemctl start fd
sleep 3
systemctl is-active fd >/dev/null 2>&1 \
  && pass "fd restarted cleanly" \
  || fail "fd did not come back"

# The restart is a cold boot over the pins the dead daemon left, so
# the counter map — whose slots are numbered by a compilation — is
# discarded and re-made. fd cannot cheaply prove the bundle on disk
# is the same compilation that pinned the old one (a path is not an
# identity; hw::restore_smoke and every watcher reload rebuild in
# place), and the cheap approximation "the shapes match, keep it" is
# exactly the silent aliasing l8_07 exists to prevent. So counters
# restart from zero across an fd restart, deliberately, and that is
# asserted here rather than left to be rediscovered.
CNT_ID_AFTER=$(hw::map_id fwl_counters_t)
if [ "$CNT_ID_AFTER" -gt 0 ] && [ "$CNT_ID_AFTER" -ne "$CNT_ID_BEFORE" ]; then
  pass "counter map re-made on restart \
($CNT_ID_BEFORE -> $CNT_ID_AFTER); counters restart from zero"
else
  fail "counter map id unchanged ($CNT_ID_AFTER) — a policy-scoped \
map was inherited across a restart"
fi
hw::sniff_wait

assert_eq "wire: 6666 dropped throughout (incl. while fd dead)" \
  "$(hw::sniff_get udp:10.99.51.5:6666)" 0
assert_eq "wire: 7777 passed throughout" \
  "$(hw::sniff_get udp:10.99.51.5:7777)" 200
