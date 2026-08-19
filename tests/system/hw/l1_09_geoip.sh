#!/usr/bin/env bash
# Test-plan L1 row 9: geoip — blocklist a "country's" range; matched
# sources drop at the wire, unmatched pass.
#
# Uses a test data file mapping DE -> 10.99.77.0/24 (the geoip data
# format is country -> prefixes; the construct under test is the LPM
# trie path: compile --geoip emits bundle geoip.json, fd populates
# the pinned tries at attach — the production path end to end).
source "$(dirname "$0")/hwlib.sh"
hw::require_root
trap hw::finish EXIT

FW=$(mktemp --suffix=.fw)
GEOIP_DATA=$(mktemp --suffix=.json)
cat > "$FW" <<EOF
zone t = [$RECV_IF]

@xdp(t)

count from_de if pkt.src_ip in geoip(DE)
count from_elsewhere if pkt.src_ip in 10.99.76.0/24
drop if pkt.src_ip in geoip(DE)
default allow
EOF
cat > "$GEOIP_DATA" <<EOF
{"DE": ["10.99.77.0/24"]}
EOF

# hw::deploy compiles without --geoip; this policy needs it, so
# deploy manually with the extra flag.
VER=$BUNDLE_ROOT/v-hw-l1-09-$$
fwl check "$FW" >/dev/null
rm -rf "$VER"
fwl compile --bundle "$VER" --geoip "$GEOIP_DATA" "$FW" >/dev/null
systemctl stop fd
rm -f "$PIN"/fwl_* "$PIN"/conntrack 2>/dev/null || true
ln -sfT "$VER" "$BUNDLE_ROOT/current"
systemctl start fd
for i in $(seq 1 20); do
  fctl status 2>/dev/null | grep -q '"xdp_attached":true' && break
  sleep 0.5
done
ip link set dev "$RECV_IF" promisc on
$PY "$HERE/sendmany.py" --probe "$SEND_IF" "$RECV_IF" 45
hw::teach_fdb
log "deployed $VER (with geoip.json)"

# The daemon must have loaded the trie (journal evidence).
journalctl -u fd -n 20 --no-pager | grep -q "geoip trie" \
  && pass "fd journal shows geoip trie population" \
  || fail "no geoip trie log line in fd journal"

hw::sniff_start 6
hw::send 100 'udp(src_ip="10.99.77.5", dst_port=9100)'
hw::send 100 'udp(src_ip="10.99.76.5", dst_port=9200)'
sleep 1
hw::sniff_wait

assert_eq "counter from_de (matched)" "$(hw::counter from_de)" 100
assert_eq "counter from_elsewhere" "$(hw::counter from_elsewhere)" 100
assert_eq "wire blocklisted dropped" \
  "$(hw::sniff_get udp:10.99.77.5:9100)" 0
assert_eq "wire unlisted passed" \
  "$(hw::sniff_get udp:10.99.76.5:9200)" 100
