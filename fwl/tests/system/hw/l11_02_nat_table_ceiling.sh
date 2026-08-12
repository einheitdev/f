#!/usr/bin/env bash
# CEILING PROBE: the masquerade reply-mapping table (`fwl_nat`).
#
# `fwl_nat` is a 65536-entry BPF hash holding one reply mapping per
# translated flow. It is what makes return traffic find its way home.
# Two properties of it are worth measuring rather than assuming:
#
#   1. What happens to a NEW flow once the table is full? The BPF
#      helper ignores bpf_map_update_elem's return value, so a failed
#      insert is invisible in the datapath.
#   2. Does it ever drain? `conntrack` has a daemon-side GC (idle
#      timeout + sweep, ConntrackMgr::RunGc). Nothing in the daemon
#      touches `fwl_nat` — and it is declared MapLifetime.FLOW, i.e.
#      INHERITED across an fd restart and across a policy reload.
#
# The two are measured side by side from ONE flood, so both tables
# hold entries of the same age created by the same packets. That is
# the control: if only one of them drains, the difference is the GC,
# not the traffic.
#
# Slow by nature: the conntrack idle timeout is 300 s.
source "$(dirname "$0")/hwlib.sh"
hw::require_root

WAN_IF="${WAN_IF:-enp1s0f2}"
MASQ_ADDR=10.99.200.2
FRESH_HOST=10.99.33.7
FRESH_PEER=10.99.90.9
FRESH_SPORT=45000

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

ct() {
  fctl status 2>/dev/null | $PY -c "
import json, sys
try:
  print(json.load(sys.stdin)['conntrack']['$1'])
except Exception:
  print(-1)
"
}

assert_str "conntrack GC is enabled in this build" "$(ct enabled)" "True"
log "conntrack: timeout=$(ct timeout_s)s sweep=$(ct gc_interval_s)s"

# fctl does not report fwl_nat at all — there is no 'nat' section in
# status. That is itself part of the finding, so read the map the only
# way an operator could: straight out of bpffs.
nat_entries() { hw::map_entries fwl_nat; }

fctl status 2>/dev/null | grep -q '"nat"' \
  && pass "fctl status reports the NAT table" \
  || log "OBSERVABILITY: fctl status has no 'nat' section. conntrack \
is reported (entries, evicted, timeout); the NAT mapping table — the \
one with no GC behind it — is not visible to the operator at all."

# --- 1. fill fwl_nat -------------------------------------------------
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

FILLED=$(nat_entries)
CT_FILLED=$(ct entries)
log "after flood: fwl_nat=$FILLED (cap 65536), conntrack=$CT_FILLED \
(cap 65536)"

if [ "$FILLED" -ge 60000 ]; then
  pass "fwl_nat filled to its cap under ordinary masqueraded traffic \
($FILLED entries)"
elif [ "$FILLED" -gt 5000 ]; then
  pass "fwl_nat grew to $FILLED entries — enough to exercise the \
pressure path, though the flood did not reach the cap"
else
  fail "fwl_nat barely grew ($FILLED): the flood did not install \
mappings, so nothing below is measured"
fi

# --- 2. behaviour at the cap ----------------------------------------
# A brand-new flow. Its egress packet is still translated (the rewrite
# does not depend on the map), but if the insert failed there is no
# mapping for the reply, and the reply is delivered to the masquerade
# address instead of to the host that asked for it.
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

assert_eq "wire: a new flow is STILL translated on the way out" \
  "$OUT" 20
log "=== behaviour at the fwl_nat ceiling ==="
log "new flow's reply: reached the host $HOME_OK/20, stranded at the \
masquerade address $STRANDED/20"

if [ "$STRANDED" -gt 0 ] && [ "$HOME_OK" -eq 0 ]; then
  pass "CEILING MEASURED — with the table full the outbound half of \
a new flow works perfectly and the return half is never translated \
back. The reply is delivered to the firewall's own WAN address, not \
to the host that opened the connection. Egress counters keep rising, \
no error is logged, no counter records the failed insert: the \
observable symptom is 'new connections hang, old ones are fine'."
elif [ "$HOME_OK" -gt 0 ]; then
  pass "the table had room for the new flow (reply reached the host \
$HOME_OK/20) — the cap was not actually reached by the flood"
else
  fail "the reply reached neither the host nor the masquerade address \
(home=$HOME_OK stranded=$STRANDED): unreadable evidence"
fi

# --- 3. does it drain? ----------------------------------------------
# Same flows, same age, two tables. conntrack has a GC; fwl_nat has
# none anywhere in the daemon. Wait past the 300 s idle timeout and a
# couple of 30 s sweeps and read both again.
log "waiting out the conntrack idle timeout to compare the two tables \
(~6 minutes)"
sleep 345
NAT_AFTER=$(nat_entries)
CT_AFTER=$(ct entries)
EVICTED=$(ct total_evicted)
log "after idle: conntrack $CT_FILLED -> $CT_AFTER (evicted \
$EVICTED); fwl_nat $FILLED -> $NAT_AFTER"

if [ "$EVICTED" -gt 0 ] && [ "$CT_AFTER" -lt "$CT_FILLED" ]; then
  pass "control holds: conntrack drained under GC ($CT_FILLED -> \
$CT_AFTER), so the flows really were idle and the sweep really ran"
else
  fail "control failed: conntrack did not drain either ($CT_FILLED -> \
$CT_AFTER, evicted $EVICTED). Without it, fwl_nat not draining proves \
nothing"
fi

if [ "$NAT_AFTER" -ge "$FILLED" ]; then
  pass "CEILING MEASURED — fwl_nat did not release a single entry \
($FILLED -> $NAT_AFTER) while conntrack released $EVICTED of the same \
flows. There is no aging path for NAT mappings anywhere in the \
daemon, so the table is MONOTONE: it only ever fills. Its 65536 \
entries are a lifetime budget of translated flows, not a concurrency \
budget."
else
  pass "fwl_nat drained $((FILLED - NAT_AFTER)) entries ($FILLED -> \
$NAT_AFTER) — something is reclaiming NAT mappings after all"
fi

# --- 4. does a restart clear it? ------------------------------------
# fwl_nat is MapLifetime.FLOW: deliberately inherited so established
# connections survive a restart. The cost of that decision is that a
# full table also survives one.
systemctl restart fd
for _ in $(seq 1 20); do
  fctl status 2>/dev/null | grep -q '"xdp_attached":true' && break
  sleep 0.5
done
NAT_RESTART=$(nat_entries)
log "after 'systemctl restart fd': fwl_nat=$NAT_RESTART"
if [ "$NAT_RESTART" -ge "$NAT_AFTER" ]; then
  pass "RECOVERY MEASURED — restarting fd does NOT clear the table \
($NAT_AFTER -> $NAT_RESTART). The map is inherited by design so \
established flows survive a restart; the consequence is that the one \
obvious operator remedy for 'new connections hang' does not work. \
Clearing it needs a reboot or an explicit unpin of \
/sys/fs/bpf/f/fwl_nat."
else
  pass "the restart cleared the table ($NAT_AFTER -> $NAT_RESTART)"
fi
