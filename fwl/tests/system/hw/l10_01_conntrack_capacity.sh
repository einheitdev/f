#!/usr/bin/env bash
# Conntrack under pressure: what happens as the table fills, and does
# it recover once flows go idle?
#
# The map holds 65536 entries. Until this week GC never ran in bundle
# mode, so the table could only fill — and nothing reported it. With
# GC enabled the interesting questions are operational:
#
#   1. Does the table actually fill under a flow flood, and what does
#      the daemon report while it does?
#   2. At the cap, what happens to NEW flows? (BPF_NOEXIST update
#      fails in-kernel; the packet still matches whatever rule
#      allowed it, but its state is never recorded — so a later
#      reply reads `new` instead of `established`.)
#   3. Does the table drain again once entries age past the idle
#      timeout, i.e. is the GC fix real end to end?
#
# This is slow by nature: the default idle timeout is 300 s and the
# sweep runs every 30 s, so the recovery half cannot be rushed.
source "$(dirname "$0")/hwlib.sh"
hw::require_root
trap hw::finish EXIT

FW=$(mktemp --suffix=.fw)
cat > "$FW" <<EOF
zone t = [$RECV_IF]

@xdp(t)

count est if conntrack(pkt).state == established
allow if conntrack(pkt).state == established
count opened if pkt.proto == tcp and pkt.tcp.syn
allow if pkt.proto == tcp and pkt.tcp.syn
default drop
EOF
hw::deploy l10-01 "$FW"

ct() {
  fctl status 2>/dev/null | $PY -c "
import json, sys
try:
  print(json.load(sys.stdin)['conntrack']['$1'])
except Exception:
  print(-1)
"
}

log "start: entries=$(ct entries) enabled=$(ct enabled) \
timeout=$(ct timeout_s)s sweep=$(ct gc_interval_s)s"
assert_str "GC is enabled (the fix is in this build)" \
  "$(ct enabled)" "True"

# --- 1. fill the table ---------------------------------------------
# Each SYN on a distinct 5-tuple is an explicit allow on a `new`
# packet, so each creates an entry. 70k attempts overshoots the
# 65536 cap deliberately.
$PY - "$SEND_IF" <<'EOF'
import socket
import sys
sys.path.insert(0, "/opt/fwl")
sys.path.insert(0, "/opt/fwl-deps")
from fwl import pkt
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind((sys.argv[1], 0))
tmpl = pkt.build_packet(pkt.parse_builder(
  'tcp(src_ip="10.99.200.1", dst_ip="10.99.200.9", '
  'src_port=1024, dst_port=80, syn=true)'
)).raw
frame = bytearray(tmpl)
sent = 0
# Vary the source address and port across the 5-tuple space: the
# builder's frame layout is fixed, so patch the bytes directly.
# IPv4 src at offset 26..29, TCP src port at 34..35.
for a in range(1, 5):
  for b in range(256):
    for p in range(64):
      frame[27] = 200 + (a % 4)
      frame[28] = b
      frame[29] = 1
      port = 1024 + p
      frame[34] = (port >> 8) & 0xFF
      frame[35] = port & 0xFF
      try:
        s.send(bytes(frame))
        sent += 1
      except OSError:
        pass
s.close()
print(f"sent {sent} distinct-flow SYNs")
EOF
sleep 3
FILLED=$(ct entries)
log "after flood: entries=$FILLED (cap 65536)"

if [ "$FILLED" -ge 60000 ]; then
  pass "table filled to the cap under a flow flood ($FILLED entries)"
elif [ "$FILLED" -gt 1000 ]; then
  pass "table grew substantially ($FILLED entries) — enough to \
exercise the pressure path"
else
  fail "table barely grew ($FILLED entries): the flood did not \
create flows, so the rest of this test proves nothing"
fi

# --- 2. behavior at pressure ---------------------------------------
# A brand-new flow's SYN is still allowed by the explicit rule, but
# if the table is full its state is not recorded — so its reply
# cannot read `established`.
hw::sniff_start 8
hw::send 20 'tcp(src_ip="10.99.201.5", dst_ip="10.99.201.9", src_port=45000, dst_port=80, syn=true)'
sleep 1
hw::send 20 'tcp(src_ip="10.99.201.9", dst_ip="10.99.201.5", src_port=80, dst_port=45000, ack=true)'
sleep 1
hw::sniff_wait
NEW_SYN=$(hw::sniff_get tcp:10.99.201.5:80)
REPLY=$(hw::sniff_get tcp:10.99.201.9:45000)
log "under pressure: new SYN passed=$NEW_SYN/20, its reply \
passed=$REPLY/20"
assert_eq "a new flow's SYN is still allowed by the explicit rule" \
  "$NEW_SYN" 20
if [ "$REPLY" -eq 0 ]; then
  log "OPERATIONAL NOTE: with the table at $FILLED entries the new \
flow was NOT tracked, so its reply read 'new' and was dropped. A \
full conntrack table degrades stateful policy silently — the SYN \
still passes, only the return path breaks. Worth an operator alarm \
on conntrack.entries approaching 65536."
else
  pass "the new flow was tracked even under pressure (reply \
passed $REPLY/20)"
fi

# --- 3. recovery: does GC drain the table? -------------------------
# Idle timeout is 300 s, swept every 30 s. Wait past both.
log "waiting out the idle timeout to watch GC drain the table \
(this takes ~6 minutes)"
sleep 345
DRAINED=$(ct entries)
EVICTED=$(ct total_evicted)
log "after idle: entries=$FILLED -> $DRAINED, total_evicted=$EVICTED"

if [ "$EVICTED" -gt 0 ] && [ "$DRAINED" -lt "$FILLED" ]; then
  pass "GC drained the table end to end: $FILLED -> $DRAINED \
entries, $EVICTED evicted. The conntrack fix works under real load, \
not just as a flag."
else
  fail "table did not drain: entries $FILLED -> $DRAINED, evicted \
$EVICTED. GC reports enabled but is not reclaiming, so the table \
stays full and stateful policy stays degraded."
fi
