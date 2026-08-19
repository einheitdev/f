#!/usr/bin/env bash
# Throughput and correctness under sustained load.
#
# Every other test sends hundreds of frames. This one sends as fast
# as the sender can for a fixed window and asks two questions the
# slow tests cannot:
#   - does the program still count EXACTLY, with no lost increments,
#     when frames arrive back to back?
#   - does a split (tail-call) pipeline cost anything measurable
#     against the identical unsplit policy?
#
# The counter is the measurement of record: the AF_PACKET witness
# legitimately drops frames under load (userspace can't keep up),
# which is why the assertions here are counter-based and the sniffer
# is only used for disposition.
source "$(dirname "$0")/hwlib.sh"
hw::require_root
trap hw::finish EXIT

BURST=20000

blast() {
  # Send BURST frames as fast as possible; report sender-side rate.
  $PY - "$SEND_IF" "$BURST" <<'EOF'
import socket
import sys
import time
sys.path.insert(0, "/opt/fwl/tests/system/hw")
from fwl import pkt
iface, n = sys.argv[1], int(sys.argv[2])
frame = pkt.build_packet(pkt.parse_builder(
  'udp(src_ip="10.99.192.1", dst_port=5500)'
)).raw
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind((iface, 0))
sent = 0
t0 = time.monotonic()
for _ in range(n):
  try:
    s.send(frame)
    sent += 1
  except OSError:
    pass
dt = time.monotonic() - t0
s.close()
print(f"{sent} {dt:.3f} {sent / dt:.0f}")
EOF
}

# Frames the NIC never handed to XDP. The exactness claim is about the
# PROGRAM — "no lost increments" — and without this the scenario cannot
# tell a datapath that lost a count from a receive ring that overran, two
# findings with nothing in common. Measured 2026-08-14: the unsplit
# variant counted 20000/20000 while the split one counted 17206, which
# reads as a datapath defect and is a receive-path drop.
nic_missed() {
  ethtool -S "$RECV_IF" \
    | awk '/rx_missed_errors|rx_no_buffer_count/{s+=$2} END{print s+0}'
}

RULES='count total if pkt.src_ip == 10.99.192.1
drop if pkt.proto == udp and pkt.dst_port == 9999
count survivors if pkt.src_ip == 10.99.192.1
default allow'

# ---------- unsplit ----------
FW=$(mktemp --suffix=.fw)
printf 'zone t = [%s]\n\n@xdp(t)\n\n%s\n' "$RECV_IF" "$RULES" > "$FW"
hw::deploy l9-03a "$FW"
BEFORE=$(hw::counter total)
MISS_BEFORE=$(nic_missed)
read -r SENT_A DT_A PPS_A <<< "$(blast)"
sleep 2
DELTA_A=$(( $(hw::counter total) - BEFORE ))
MISS_A=$(( $(nic_missed) - MISS_BEFORE ))
log "unsplit : sent=$SENT_A in ${DT_A}s (${PPS_A} pps), counted=$DELTA_A, \
NIC missed=$MISS_A"

# ---------- split (forced tail-call pipeline) ----------
SPLIT=$(printf '%s' "$RULES" \
  | sed 's/^count survivors/chain stage2\ncount survivors/')
printf 'zone t = [%s]\n\n@xdp(t)\n\n%s\n' "$RECV_IF" "$SPLIT" > "$FW"
hw::deploy l9-03b "$FW"
grep -q "fwl_stage_0" "$BUNDLE_ROOT"/v-hw-l9-03b-*/t.bpf.c \
  && pass "split variant really is a tail-call pipeline" \
  || fail "chain marker did not split the program"
BEFORE=$(hw::counter total)
MISS_BEFORE=$(nic_missed)
read -r SENT_B DT_B PPS_B <<< "$(blast)"
sleep 2
DELTA_B=$(( $(hw::counter total) - BEFORE ))
MISS_B=$(( $(nic_missed) - MISS_BEFORE ))
log "split   : sent=$SENT_B in ${DT_B}s (${PPS_B} pps), counted=$DELTA_B, \
NIC missed=$MISS_B"

# Exactness is the headline: every frame the NIC DELIVERED must be
# counted exactly once, at any rate. Frames the receive ring dropped
# never reached the program and are not its to count — but they are
# reported, because a run where the NIC swallowed thousands is a
# different measurement from one where it swallowed none.
record "receive-ring drops during the bursts: unsplit $MISS_A, \
split $MISS_B (frames the NIC never handed to XDP)"
assert_eq "unsplit: every frame the NIC delivered was counted once" \
  "$((DELTA_A + MISS_A))" "$SENT_A"
assert_eq "split: every frame the NIC delivered was counted once" \
  "$((DELTA_B + MISS_B))" "$SENT_B"

# Both variants must also agree on disposition under load.
assert_eq "split and unsplit saw the same traffic" \
  "$((DELTA_A + MISS_A))" "$((DELTA_B + MISS_B))"
log "sender-side rate: unsplit ${PPS_A} pps vs split ${PPS_B} pps \
(sender-bound, not a datapath ceiling — the i350 link is 1G and a \
64B frame at line rate is ~1.4 Mpps)"
