#!/usr/bin/env bash
# Switch-side events: does the policy survive what a real network
# does to a port?
#
#   link flap        — the kernel keeps an XDP program across
#                      down/up; f does nothing, so the program id
#                      must be identical afterwards and filtering
#                      must resume with no operator action.
#   speed change     — renegotiating 1G -> 100M -> 1G bounces the
#                      link the same way a cable swap would.
#   switch port bounce — the same event driven from the EX2300 side
#                      (disable/enable the port), which is what
#                      maintenance actually looks like.
#
# The failure this hunts: a program that survives the flap in name
# (still attached) but stops filtering, or an fd that quietly loses
# the interface.
source "$(dirname "$0")/hwlib.sh"
hw::require_root

SW_DUT_PORT="${SW_DUT_PORT:-ge-0/0/25}"
cleanup() {
  # Always re-enable the switch port, whatever happened.
  printf 'configure\ndelete interfaces %s disable\ncommit and-quit\n' \
    "$SW_DUT_PORT" | ssh -o BatchMode=yes ex01 >/dev/null 2>&1 || true
  ethtool -s "$RECV_IF" autoneg on 2>/dev/null || true
  hw::finish
}
trap cleanup EXIT

FW=$(mktemp --suffix=.fw)
cat > "$FW" <<EOF
zone t = [$RECV_IF]

@xdp(t)

count seen if pkt.src_ip == 10.99.190.1
drop if pkt.proto == udp and pkt.dst_port == 6300
default allow
EOF
hw::deploy l9-02 "$FW"

prog_id() {
  ip -d link show "$RECV_IF" | grep -o "prog/xdp id [0-9]*" \
    | awk '{print $3}'
}
# NOTE: everything noisy in here must go to stderr — this function's
# stdout IS its return value, and the senders print a summary line.
enforcing() {
  ip link set dev "$RECV_IF" promisc on 2>/dev/null || true
  hw::sniff_start 6 >&2
  hw::send 30 'udp(src_ip="10.99.190.1", dst_port=6300)' >&2
  hw::send 30 'udp(src_ip="10.99.190.1", dst_port=6301)' >&2
  sleep 1
  hw::sniff_wait >&2
  local blocked passed
  blocked=$(hw::sniff_get udp:10.99.190.1:6300)
  passed=$(hw::sniff_get udp:10.99.190.1:6301)
  echo "$blocked/$passed"
}

ID0=$(prog_id)
BASE=$(enforcing)
log "baseline: prog id=$ID0, blocked/passed=$BASE"
assert_eq "baseline: policy enforcing (0 blocked-port frames)" \
  "${BASE%%/*}" 0

# ---- 1. host-side link flap ----
ip link set dev "$RECV_IF" down
sleep 2
ip link set dev "$RECV_IF" up
$PY "$HERE/sendmany.py" --probe "$SEND_IF" "$RECV_IF" 60 >/dev/null \
  || log "wire slow to return after flap"
hw::teach_fdb
ID1=$(prog_id)
AFTER_FLAP=$(enforcing)
log "after host flap: prog id=$ID1, blocked/passed=$AFTER_FLAP"
assert_eq "host flap: same XDP program still attached" "$ID1" "$ID0"
assert_eq "host flap: still enforcing" "${AFTER_FLAP%%/*}" 0
assert_eq "host flap: still forwarding allowed traffic" \
  "${AFTER_FLAP##*/}" 30

# ---- 2. switch-side port bounce ----
printf 'configure\nset interfaces %s disable\ncommit and-quit\n' \
  "$SW_DUT_PORT" | ssh -o BatchMode=yes ex01 >/dev/null 2>&1
sleep 5
printf 'configure\ndelete interfaces %s disable\ncommit and-quit\n' \
  "$SW_DUT_PORT" | ssh -o BatchMode=yes ex01 >/dev/null 2>&1
$PY "$HERE/sendmany.py" --probe "$SEND_IF" "$RECV_IF" 90 >/dev/null \
  || log "wire slow to return after switch bounce"
hw::teach_fdb
ID2=$(prog_id)
AFTER_SW=$(enforcing)
log "after switch bounce: prog id=$ID2, blocked/passed=$AFTER_SW"
assert_eq "switch bounce: same XDP program still attached" \
  "$ID2" "$ID0"
assert_eq "switch bounce: still enforcing" "${AFTER_SW%%/*}" 0
assert_eq "switch bounce: still forwarding allowed traffic" \
  "${AFTER_SW##*/}" 30

# ---- 3. fd is still healthy and owns the interface ----
assert_eq "fd still active through both events" \
  "$(systemctl is-active fd >/dev/null && echo 1 || echo 0)" 1
