#!/usr/bin/env bash
# Tier 2 (`def filter(pkt)`) on real wire.
#
# Covers the if/elif/else chain, the implicit fall-through (Tier 2
# has no `default`, so falling off the end is XDP_PASS), terminal
# actions stopping evaluation mid-branch, and refactor invariance —
# hoisting a field into a local must not change the verdict.
source "$(dirname "$0")/hwlib.sh"
hw::require_root
trap hw::finish EXIT

# ---------- chain + fall-through ----------
FW=$(mktemp --suffix=.fw)
cat > "$FW" <<EOF
zone t = [$RECV_IF]

@xdp(t)

def filter(pkt):
  if pkt.proto == tcp:
    if pkt.dst_port == 22:
      count ssh
      drop
    elif pkt.dst_port in [80, 443]:
      count web
      allow
    else:
      count other_tcp
      drop
  elif pkt.proto == udp:
    count udp_seen
    allow
EOF
hw::deploy l7-02a "$FW"

hw::sniff_start 10
hw::send 50 'tcp(src_ip="10.99.160.1", dst_port=22)'
hw::send 50 'tcp(src_ip="10.99.160.2", dst_port=443)'
hw::send 50 'tcp(src_ip="10.99.160.3", dst_port=9999)'
hw::send 50 'udp(src_ip="10.99.160.4", dst_port=53)'
hw::send 50 'icmp(src_ip="10.99.160.5", type=8, code=0)'
sleep 1
hw::sniff_wait

assert_eq "counter ssh" "$(hw::counter ssh)" 50
assert_eq "counter web" "$(hw::counter web)" 50
assert_eq "counter other_tcp" "$(hw::counter other_tcp)" 50
assert_eq "counter udp_seen" "$(hw::counter udp_seen)" 50
assert_eq "if-branch: SSH dropped" \
  "$(hw::sniff_get tcp:10.99.160.1:22)" 0
assert_eq "elif-branch: web allowed" \
  "$(hw::sniff_get tcp:10.99.160.2:443)" 50
assert_eq "else-branch: other TCP dropped" \
  "$(hw::sniff_get tcp:10.99.160.3:9999)" 0
assert_eq "elif proto branch: UDP allowed" \
  "$(hw::sniff_get udp:10.99.160.4:53)" 50
assert_eq "fall-through (no branch matched) is an implicit PASS" \
  "$(hw::sniff_get icmp:10.99.160.5:8)" 50

# ---------- terminal stops evaluation ----------
cat > "$FW" <<EOF
zone t = [$RECV_IF]

@xdp(t)

def filter(pkt):
  if pkt.proto == udp:
    count hits
    drop
  count hits
  allow
EOF
hw::deploy l7-02b "$FW"
hw::sniff_start 6
hw::send 50 'udp(src_ip="10.99.161.1", dst_port=5000)'
sleep 1
hw::sniff_wait
assert_eq "a matched terminal stops evaluation (counted once, not \
twice)" "$(hw::counter hits)" 50
assert_eq "and the drop took effect" \
  "$(hw::sniff_get udp:10.99.161.1:5000)" 0

# ---------- refactor invariance: hoisted local ----------
cat > "$FW" <<EOF
zone t = [$RECV_IF]

@xdp(t)

def filter(pkt):
  if pkt.proto == tcp:
    p = pkt.dst_port
    if p == 22:
      drop
  allow
EOF
hw::deploy l7-02c "$FW"
hw::sniff_start 8
hw::send 50 'tcp(src_ip="10.99.162.1", dst_port=22)'
hw::send 50 'tcp(src_ip="10.99.162.2", dst_port=80)'
hw::send 50 'udp(src_ip="10.99.162.3", dst_port=22)'
sleep 1
hw::sniff_wait
assert_eq "hoisted local: TCP/22 dropped (same as inline form)" \
  "$(hw::sniff_get tcp:10.99.162.1:22)" 0
assert_eq "hoisted local: TCP/80 passed" \
  "$(hw::sniff_get tcp:10.99.162.2:80)" 50
assert_eq "hoisted local: UDP/22 passed (guard still applies)" \
  "$(hw::sniff_get udp:10.99.162.3:22)" 50
