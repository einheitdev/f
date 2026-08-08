#!/usr/bin/env bash
# Test-plan L3 row 5: fd crash containment — kill -9 under load, the
# XDP program keeps enforcing the last-committed policy.
#
# XDP attach outlives the daemon (it hangs off the netdev, maps are
# bpffs-pinned). A drop rule must keep dropping and counters keep
# counting with fd dead; a clean systemd restart then re-adopts.
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

# systemd must not resurrect it mid-measurement.
systemctl kill -s KILL fd
sleep 1
systemctl is-active fd >/dev/null 2>&1 \
  && fail "fd still active after SIGKILL" \
  || pass "fd is down (SIGKILL)"

# The datapath must not notice.
hw::send 100 'udp(src_ip="10.99.51.5", dst_port=6666)'
hw::send 100 'udp(src_ip="10.99.51.5", dst_port=7777)'
sleep 1
C_AFTER=$(hw::counter seen)
ATTACHED=$(ip -d link show "$RECV_IF" | grep -c " xdp")

assert_eq "XDP still attached with fd dead" "$ATTACHED" 1
assert_eq "counters kept counting (delta 200)" \
  "$((C_AFTER - C_BEFORE))" 200

# Clean recovery.
systemctl restart fd
sleep 2
systemctl is-active fd >/dev/null 2>&1 \
  && pass "fd restarted cleanly" \
  || fail "fd did not come back"
hw::sniff_wait

assert_eq "wire: 6666 dropped throughout (incl. while fd dead)" \
  "$(hw::sniff_get udp:10.99.51.5:6666)" 0
assert_eq "wire: 7777 passed throughout" \
  "$(hw::sniff_get udp:10.99.51.5:7777)" 200
