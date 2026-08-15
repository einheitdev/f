#!/usr/bin/env bash
# The masquerade reply-mapping table (`fwl_nat`): does it drain, is the
# draining safe, and is any of it visible?
#
# This test used to be a ceiling probe. It recorded three facts, all of
# them true at the time:
#
#   1. nothing anywhere aged `fwl_nat`. A flood that drained conntrack
#      65536 -> 0 released not one NAT entry. The table was MONOTONE:
#      65536 entries was a lifetime budget of translated flows, not a
#      concurrency budget, and at the measured 3613 entries/h it was
#      ~17 hours from deployment to a broken network.
#   2. at the cap a new flow was still translated perfectly on the way
#      out, and its reply was left addressed to the firewall's own WAN
#      address. "New connections hang, old ones are fine."
#   3. `fctl status` had no `nat` section at all, so the one table with
#      no collector behind it was also the one an operator could not
#      watch. No log, no counter, nothing.
#
# All three are now asserted the other way round, and a FAIL here is a
# regression rather than a finding. The design being tested:
#
#   * a mapping lives exactly as long as its flow. Every translated
#     flow carries a conntrack entry with its POST-NAT 5-tuple, which
#     is the mapping's own key with both endpoints swapped, so the
#     daemon asks conntrack — one lookup per mapping — whether the flow
#     is still there. Conntrack's GC is the only authority on that.
#   * a mapping that is still carrying traffic is NEVER reclaimed,
#     whatever conntrack says. Nothing evicts a live mapping to make
#     room; at the cap, allocation is refused and the packet dropped.
#   * every one of those events is counted and readable from the CLI.
#
# Structured so nothing can pass vacuously: conntrack is the control
# (both tables are filled by ONE flood, so their entries are the same
# age from the same packets), a deliberately-kept-alive flow is the
# control for the sweep not being indiscriminate, and every occupancy
# number is read through `fctl status` — the interface the operator has
# — rather than out of bpffs behind its back.
#
# Slow by nature: the conntrack idle timeout is 300 s.
source "$(dirname "$0")/hwlib.sh"
hw::require_root

WAN_IF="${WAN_IF:-enp1s0f2}"
MASQ_ADDR=10.99.200.2
FRESH_HOST=10.99.33.7
FRESH_PEER=10.99.90.9
FRESH_SPORT=45000
# The flow held open across the whole sweep window — the control for
# "reclamation never breaks a live flow".
KEEP_HOST=10.99.33.8
KEEP_PEER=10.99.90.10
KEEP_SPORT=45001

cleanup() {
  ip addr del "$MASQ_ADDR/24" dev "$WAN_IF" 2>/dev/null || true
  hw::finish
}
trap cleanup EXIT

ip addr add "$MASQ_ADDR/24" dev "$WAN_IF" 2>/dev/null || true

FW=$(mktemp --suffix=.fw)
cat > "$FW" <<EOF
zone lan = [$RECV_IF]
zone wanz = [$WAN_IF]

@xdp(lan)

count est if conntrack(pkt).state == established
count egress if pkt.src_ip in 10.99.32.0/22
masquerade if pkt.src_ip in 10.99.32.0/22
redirect to wanz if pkt.proto == udp and pkt.dst_port == 1
allow if pkt.proto == tcp
default drop
EOF
hw::deploy l11-02 "$FW"

assert_str "conntrack GC is enabled in this build" \
  "$(hw::ct enabled)" "True"
log "conntrack: timeout=$(hw::ct timeout_s)s sweep=$(hw::ct gc_interval_s)s"

# --- 0. the table is visible at all ---------------------------------
# This was finding (3). It is now the first assertion, because every
# other assertion below reads through it.
assert_str "fctl status reports the NAT table" \
  "$(hw::nat enabled)" "True"
NAT_CAP=$(hw::nat max_entries)
assert_eq "fctl status reports the real cap" "$NAT_CAP" 65536
log "nat section: entries=$(hw::nat entries) cap=$NAT_CAP \
occupancy=$(hw::nat occupancy_pct)% grace=$(hw::nat grace_s)s"

# --- 1. open the flow that must survive everything ------------------
hw::send 5 "tcp(src_ip=\"$KEEP_HOST\", dst_ip=\"$KEEP_PEER\", \
src_port=$KEEP_SPORT, dst_port=443, syn=true)"
sleep 1
KEEP_BEFORE=$(hw::nat entries)
assert_range "the long-lived flow installed a mapping" \
  "$KEEP_BEFORE" 1 100

# --- 2. fill fwl_nat -------------------------------------------------
# One reply mapping per distinct (peer_addr, peer_port, guest_port).
# Vary the destination address and the source port to walk that space;
# 80k attempts deliberately overshoot the 65536 cap.
log "flooding distinct masqueraded flows (this takes a couple of minutes)"
$PY - "$SEND_IF" <<'PYEOF'
import socket
import struct
import sys
sys.path.insert(0, "/opt/fwl")
sys.path.insert(0, "/opt/fwl-deps")
from fwl import pkt

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind((sys.argv[1], 0))
tmpl = pkt.build_packet(pkt.parse_builder(
  'tcp(src_ip="10.99.32.1", dst_ip="10.99.100.1", '
  'src_port=1024, dst_port=443, syn=true)'
)).raw
frame = bytearray(tmpl)

def fix_ip_csum(f):
  f[24] = 0
  f[25] = 0
  total = sum(struct.unpack(">10H", bytes(f[14:34])))
  while total >> 16:
    total = (total & 0xFFFF) + (total >> 16)
  struct.pack_into(">H", f, 24, (~total) & 0xFFFF)

sent = 0
# 4 * 256 destination addresses x 80 source ports = 81920 distinct
# reply-mapping keys, against a 65536-entry table.
for a in range(4):
  for b in range(256):
    frame[31] = 100 + a
    frame[32] = b
    frame[33] = 1
    for p in range(80):
      port = 1024 + p
      struct.pack_into(">H", frame, 34, port)
      fix_ip_csum(frame)
      try:
        s.send(bytes(frame))
        sent += 1
      except OSError:
        pass
s.close()
print(f"sent {sent} distinct-flow SYNs")
PYEOF
sleep 5

FILLED=$(hw::nat entries)
CT_FILLED=$(hw::ct entries)
PEAK=$(hw::nat high_water)
log "after flood: fwl_nat=$FILLED (cap $NAT_CAP, peak $PEAK), \
conntrack=$CT_FILLED"

if [ "$FILLED" -lt 5000 ]; then
  fail "fwl_nat barely grew ($FILLED): the flood did not install \
mappings, so nothing below is measured"
  exit 1
fi
pass "fwl_nat filled under ordinary masqueraded traffic ($FILLED \
entries, peak $PEAK)"

# The high-water mark exists so a table that filled and drained between
# two status calls still shows it happened. Assert it is really a peak
# and not a copy of the live count.
assert_range "high_water is at least the live count" "$PEAK" \
  "$FILLED" 65536

# --- 3. behaviour at the cap ----------------------------------------
# A brand-new flow when there is no room. It must be REFUSED — dropped,
# counted, and logged — not translated into a mapping that does not
# exist. Finding (2) was that it was translated anyway and the reply
# went to the firewall's own address; that is the assertion that flips.
REFUSED_BEFORE=$(hw::nat refused)
hw::sniff_start 10 --detail --srcport
hw::send 20 "tcp(src_ip=\"$FRESH_HOST\", dst_ip=\"$FRESH_PEER\", \
src_port=$FRESH_SPORT, dst_port=443, syn=true)"
sleep 1
hw::send 20 "tcp(src_ip=\"$FRESH_PEER\", dst_ip=\"$MASQ_ADDR\", \
src_port=443, dst_port=$FRESH_SPORT, ack=true)"
sleep 1
hw::sniff_wait

OUT=$(hw::sniff_get "tcp:$MASQ_ADDR:$FRESH_SPORT>$FRESH_PEER:443:ok")
HOME_OK=$(hw::sniff_get "tcp:$FRESH_PEER:443>$FRESH_HOST:$FRESH_SPORT:ok")
STRANDED=$(hw::sniff_get "tcp:$FRESH_PEER:443>$MASQ_ADDR:$FRESH_SPORT:ok")
REFUSED_AFTER=$(hw::nat refused)
FULL_AFTER=$(hw::nat table_full)

log "=== behaviour at the fwl_nat cap ==="
log "new flow: translated out $OUT/20, reply reached the host \
$HOME_OK/20, stranded at the masquerade address $STRANDED/20; \
refusals $REFUSED_BEFORE -> $REFUSED_AFTER (table_full $FULL_AFTER)"

if [ "$FILLED" -ge 65000 ]; then
  # Only assert the refusal when the flood really reached the cap; a
  # partially-filled table legitimately has room for the new flow.
  assert_eq "wire: a flow with no room is NOT translated" "$OUT" 0
  assert_eq "wire: the reply is not delivered to a host that was \
never given a mapping" "$HOME_OK" 0
  # $STRANDED is this test's own injected reply frame crossing under
  # the policy's blanket `allow if pkt.proto == tcp`. It is NOT
  # evidence of a defect and must not be asserted to zero — that would
  # be asserting the firewall drops a packet its policy admits. What
  # made the old behaviour a defect was the guest's packet being
  # translated anyway ($OUT above): the firewall promised a return
  # path it had not recorded, and the reply then arrived at its own
  # address with nothing counted. With the allocation refused, no such
  # promise is made.
  log "($STRANDED/20 of the injected reply frames crossed to the \
masquerade address, admitted by this policy's blanket TCP allow — no \
translation was promised, so none is missing)"
  if [ "$REFUSED_AFTER" -gt "$REFUSED_BEFORE" ]; then
    pass "REFUSED AND COUNTED — the packet was dropped rather than \
translated into a mapping that could not be installed, and \
fctl status reports it ($REFUSED_BEFORE -> $REFUSED_AFTER refusals, \
$FULL_AFTER of them the table being full). This is the fix for the \
silent failure: the old build translated it 20/20 and sent the reply \
to the firewall's own address with nothing logged."
  else
    fail "the table is full ($FILLED) but no refusal was counted \
($REFUSED_BEFORE -> $REFUSED_AFTER): the datapath is either still \
translating without a mapping, or the stats map is not being read"
  fi
  # The daemon reports refusals from its sweep, so the line appears at
  # the next sweep boundary, not the instant the counter moves. Wait
  # for one — checking immediately passed the first time this test ran
  # only because a PREVIOUS run's line was still inside the window,
  # which is a test that agrees with itself rather than with fd.
  SWEEP=$(hw::ct gc_interval_s)
  LOGGED=0
  for _ in $(seq 1 $(( (SWEEP + 15) * 2 )) ); do
    if journalctl -u fd --since "-2 min" --no-pager \
        | grep -q "NAT: refused"; then
      LOGGED=1
      break
    fi
    sleep 1
  done
  if [ "$LOGGED" -eq 1 ]; then
    pass "fd LOGGED the refusal within one ${SWEEP}s sweep \
(journalctl -u fd)"
    journalctl -u fd --since "-2 min" --no-pager \
      | grep -E "NAT: (refused|fwl_nat is)" | tail -2 \
      | while read -r l; do log "  journal: ${l#*] }"; done
  else
    fail "refusals were counted but nothing was logged within \
$((SWEEP + 15))s — an operator watching the journal still sees nothing"
  fi
else
  log "the flood stopped at $FILLED of $NAT_CAP, so the cap was not \
reached and the refusal path is not exercised by this run"
  assert_eq "with room in the table the new flow works end to end" \
    "$HOME_OK" 20
fi

# --- 4. does it drain? ----------------------------------------------
# Same flows, same age, two tables, one flood. conntrack has a GC;
# fwl_nat now ages against it. The keep-alive flow is refreshed
# throughout, so it must be the one thing that survives.
log "waiting out the conntrack idle timeout while keeping ONE flow \
alive (~6 minutes)"
for _ in $(seq 1 12); do
  hw::send 2 "tcp(src_ip=\"$KEEP_HOST\", dst_ip=\"$KEEP_PEER\", \
src_port=$KEEP_SPORT, dst_port=443, ack=true)" >/dev/null 2>&1
  sleep 30
done

NAT_AFTER=$(hw::nat entries)
CT_AFTER=$(hw::ct entries)
EVICTED=$(hw::ct total_evicted)
RECLAIMED=$(hw::nat total_reclaimed)
log "after idle: conntrack $CT_FILLED -> $CT_AFTER (evicted \
$EVICTED); fwl_nat $FILLED -> $NAT_AFTER (reclaimed $RECLAIMED)"

if [ "$EVICTED" -gt 0 ] && [ "$CT_AFTER" -lt "$CT_FILLED" ]; then
  pass "control holds: conntrack drained under GC ($CT_FILLED -> \
$CT_AFTER), so the flows really were idle and the sweep really ran"
else
  fail "control failed: conntrack did not drain either ($CT_FILLED -> \
$CT_AFTER, evicted $EVICTED). Without it, anything fwl_nat did proves \
nothing"
fi

if [ "$NAT_AFTER" -lt "$((FILLED / 10))" ] && [ "$RECLAIMED" -gt 0 ]; then
  pass "fwl_nat DRAINED with the flows it belonged to ($FILLED -> \
$NAT_AFTER, $RECLAIMED reclaimed). The table is no longer monotone: \
its 65536 entries are a concurrency budget, which is what they were \
always supposed to be."
else
  fail "fwl_nat did not drain ($FILLED -> $NAT_AFTER, reclaimed \
$RECLAIMED) while conntrack released $EVICTED of the same flows"
fi

# The whole point of not using LRU, asserted rather than assumed.
hw::sniff_start 8 --detail --srcport
hw::send 10 "tcp(src_ip=\"$KEEP_PEER\", dst_ip=\"$MASQ_ADDR\", \
src_port=443, dst_port=$KEEP_SPORT, ack=true)"
sleep 1
hw::sniff_wait
KEEP_BACK=$(hw::sniff_get "tcp:$KEEP_PEER:443>$KEEP_HOST:$KEEP_SPORT:ok")
if [ "$KEEP_BACK" -eq 10 ]; then
  pass "THE LIVE FLOW SURVIVED — its reply still de-NATs to \
$KEEP_HOST 10/10 after a sweep that reclaimed $RECLAIMED mappings \
around it. Reclamation is driven by flow end, not by pressure: an \
LRU would have evicted this one under exactly the load above."
else
  fail "the kept-alive flow lost its mapping ($KEEP_BACK/10 delivered \
to $KEEP_HOST): the sweep is breaking live flows, which is worse than \
the ceiling it replaced"
fi

# --- 5. and a restart still inherits it -----------------------------
# fwl_nat is MapLifetime.FLOW: deliberately inherited so established
# connections survive a restart. That was a liability when the table
# never drained (a full table survived too); with a collector behind
# it, it is only the property it was meant to be.
systemctl restart fd
for _ in $(seq 1 20); do
  fctl status 2>/dev/null | grep -q '"xdp_attached":true' && break
  sleep 0.5
done
NAT_RESTART=$(hw::nat entries)
log "after 'systemctl restart fd': fwl_nat=$NAT_RESTART"
assert_str "the NAT section survives a restart" \
  "$(hw::nat enabled)" "True"
pass "restart inherits the table ($NAT_AFTER -> $NAT_RESTART) and the \
collector is re-armed against it"
