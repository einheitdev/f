#!/usr/bin/env bash
# Malformed and unusual frames: does the datapath stay correct and
# alive? Nothing here may crash the program, and each case has a
# documented expected disposition.
#
# Cases:
#   ipopt     IPv4 with options (IHL>5) — FWL_V01_SPEC:202 says the
#             L4 offset is computed as ihl*4, so port rules MUST
#             still match. A parser assuming a 20-byte header reads
#             the options as ports and silently misfilters.
#   shortip   IP total_length declares no L4 payload, but trailing
#             bytes are on the wire. XDP bounds-checks against
#             data_end, not tot_len, so those bytes ARE read as an
#             L4 header. Pinned here as observed behavior.
#   xmas/null pathological TCP flag combinations.
#   badcsum   wrong IPv4 header checksum — XDP does not verify it,
#             so rules still match (the NIC/stack drops it later).
#   qinq      802.1ad double tag: the outer EtherType is 0x88A8,
#             which v0.4 does not parse (it handles 0x8100 only), so
#             the frame is non-IP to the program.
source "$(dirname "$0")/hwlib.sh"
hw::require_root
trap hw::finish EXIT

FW=$(mktemp --suffix=.fw)
cat > "$FW" <<EOF
zone t = [$RECV_IF]

@xdp(t)

count seen_ip if pkt.src_ip in 10.99.20.0/24
count saw_443 if pkt.proto == tcp and pkt.dst_port == 443
count saw_syn if pkt.proto == tcp and pkt.tcp.syn
count saw_fin if pkt.proto == tcp and pkt.tcp.fin
count saw_urg if pkt.proto == tcp and pkt.tcp.urg
allow if pkt.proto == tcp and pkt.dst_port == 443
default drop
EOF
hw::deploy l6-02 "$FW"

hw::sniff_start 12
# IP options: 4 bytes of options, port rules must still match.
$PY "$HERE/sendraw.py" "$SEND_IF" 50 ipopt \
  src_ip=10.99.20.10 dport=443 optlen=4
# 12 bytes of options — a different IHL, same expectation.
$PY "$HERE/sendraw.py" "$SEND_IF" 50 ipopt \
  src_ip=10.99.20.11 dport=443 optlen=12
# tot_len says "no L4", trailing bytes look like port 443.
$PY "$HERE/sendraw.py" "$SEND_IF" 50 shortip \
  src_ip=10.99.20.12 dport=443
# XMAS (FIN+PSH+URG) and NULL (no flags) to the allowed port.
$PY "$HERE/sendraw.py" "$SEND_IF" 50 tcpflags \
  src_ip=10.99.20.13 dport=443 flags=0x29
$PY "$HERE/sendraw.py" "$SEND_IF" 50 tcpflags \
  src_ip=10.99.20.14 dport=443 flags=0x00
# Bad IPv4 header checksum, otherwise a valid allowed packet.
$PY "$HERE/sendraw.py" "$SEND_IF" 50 badcsum \
  src_ip=10.99.20.15 dport=443
# QinQ double tag carrying UDP.
$PY "$HERE/sendraw.py" "$SEND_IF" 50 qinq \
  src_ip=10.99.20.16 dport=443
sleep 1
hw::sniff_wait

# --- IP options: the headline correctness case ---
assert_eq "IHL=6 (4B options): port rule still matches" \
  "$(hw::sniff_get tcp:10.99.20.10:443)" 50
assert_eq "IHL=8 (12B options): port rule still matches" \
  "$(hw::sniff_get tcp:10.99.20.11:443)" 50

# --- TCP flag pathologies: flags read correctly, port rule wins ---
assert_eq "XMAS flags: allowed by the port rule" \
  "$(hw::sniff_get tcp:10.99.20.13:443)" 50
assert_eq "NULL flags: allowed by the port rule" \
  "$(hw::sniff_get tcp:10.99.20.14:443)" 50
assert_eq "counter saw_fin (XMAS carries FIN)" \
  "$(hw::counter saw_fin)" 50
assert_eq "counter saw_urg (XMAS carries URG)" \
  "$(hw::counter saw_urg)" 50

# --- bad L3 checksum: XDP does not verify it ---
assert_eq "bad IPv4 checksum: still matched by rules (XDP does not \
verify L3 checksums; the stack drops it later)" \
  "$(hw::sniff_get tcp:10.99.20.15:443)" 50

# --- QinQ: outer 0x88A8 is not parsed by v0.4 ---
# The witness keys QinQ frames by their two tags. It cannot read the
# inner IP — and neither can v0.4, which is the point. Asserting only
# "no IP flow seen" would pass whether the frame was dropped or
# merely unobservable, so assert the frame itself arrived.
QINQ=$(hw::sniff_get qinq100.200)
if [ "$QINQ" -eq 0 ]; then
  log "BLOCKED: no 0x88A8 frame reached $RECV_IF — the EX2300 test \
ports are 802.1Q trunks and drop 802.1ad outer tags. Testing QinQ \
disposition needs dot1q-tunneling on the switch (or a back-to-back \
cable). Skipped rather than asserting something unobservable."
else
  assert_eq "QinQ (0x88A8 outer) is non-IP to the program: it takes \
the non-IP early-out and PASSES rather than hitting default drop" \
    "$QINQ" 50
fi
assert_eq "QinQ inner IP stays invisible to IP rules" \
  "$(hw::sniff_get udp:10.99.20.16:443)" 0

# --- shortip: observed, documented ---
SHORT=$(hw::sniff_get tcp:10.99.20.12:443)
log "shortip (tot_len=20, trailing bytes look like port 443): \
$SHORT/50 passed"
if [ "$SHORT" -eq 50 ]; then
  pass "trailing bytes past tot_len are read as an L4 header \
(data_end-bounded, as designed); the receiving stack ignores them"
else
  fail "shortip disposition changed: $SHORT/50 — re-derive what the \
datapath now does with bytes past ip.tot_len"
fi

# Everything that reached the program was counted: nothing crashed
# the datapath, which is the point of the whole file.
assert_range "all malformed frames were processed, none crashed the \
program" "$(hw::counter seen_ip)" 300 360
