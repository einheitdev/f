#!/usr/bin/env bash
# Test-plan L1 row 8: log / log(sample=N) — ring-buffer events reach
# userspace; sampling reduces the event rate ~1/N.
source "$(dirname "$0")/hwlib.sh"
hw::require_root
trap hw::finish EXIT

FW=$(mktemp --suffix=.fw)

# Phase A: unsampled log — one event per matching frame.
cat > "$FW" <<EOF
zone t = [$RECV_IF]

@xdp(t)

log if pkt.proto == udp and pkt.dst_port == 7777
default allow
EOF
hw::deploy l1-08a "$FW"

LOGOUT=$(mktemp)
$PY "$HERE/ringlog.py" 6 > "$LOGOUT" &
RLPID=$!
sleep 1
hw::send 100 'udp(src_ip="10.99.9.1", dst_port=7777)'
hw::send 100 'udp(src_ip="10.99.9.1", dst_port=7778)'
wait "$RLPID"
EVENTS=$(grep -c '"dst_port": 7777' "$LOGOUT" || true)
OTHER=$(grep -c '"dst_port": 7778' "$LOGOUT" || true)
assert_eq "log events for matching frames" "$EVENTS" 100
assert_eq "no events for non-matching" "$OTHER" 0

# Phase B: log(sample=10) — ~1/10 event rate.
cat > "$FW" <<EOF
zone t = [$RECV_IF]

@xdp(t)

log(sample=10) if pkt.proto == udp and pkt.dst_port == 7777
default allow
EOF
hw::deploy l1-08b "$FW"

LOGOUT=$(mktemp)
$PY "$HERE/ringlog.py" 6 > "$LOGOUT" &
RLPID=$!
sleep 1
hw::send 200 'udp(src_ip="10.99.9.1", dst_port=7777)'
wait "$RLPID"
SAMPLED=$(grep -c '"dst_port": 7777' "$LOGOUT" || true)
assert_range "sampled events (~200/10)" "$SAMPLED" 10 40
