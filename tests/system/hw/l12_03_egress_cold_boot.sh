#!/usr/bin/env bash
# The egress tracker across a REAL reboot.
#
# Run from ksys, not on the rig — it reboots the rig, so running it
# there would pull the machine out from under itself. `l3_03_cold_boot`
# has the same shape and the same restriction.
#
# Why it needs a reboot of its own rather than riding on l3_03: the
# operator's smoke policy never reads conntrack, so a bundle compiled
# from it carries no egress tracker at all and a reboot on it would
# prove nothing about this attach point. This stages a stateful policy,
# reboots, and asks whether flows the box originates are tracked when
# the box comes back — the state a deployed appliance is actually in.
#
# What a reboot adds over the `systemctl stop; start` cycle every other
# scenario performs: bpffs is a FRESH mount, so there is no pin to
# adopt, and the clsact qdiscs the previous incarnation created are
# gone with the interfaces. The dirty-pin-root direction is l8_09's
# subject and is not repeated here.
#
# Restores the operator's own /etc/f/rules.fw and the smoke policy
# before it exits, whatever the verdict.
set -u

RIG="${RIG:-f-rig}"
WAN_IF="${WAN_IF:-enp1s0f2}"
LAN_IF="${LAN_IF:-enp1s0f1}"
TEST_NAME="l12_03_egress_cold_boot"
FAILURES=0
EVIDENCE=()

log() { echo "[$TEST_NAME] $*"; }
pass() { log "PASS: $*"; EVIDENCE+=("PASS: $*"); }
fail() { log "FAIL: $*"; EVIDENCE+=("FAIL: $*"); FAILURES=$((FAILURES+1)); }
record() { log "NOTE: $*"; EVIDENCE+=("NOTE: $*"); }

on_rig() { ssh -o BatchMode=yes "$RIG" "$@"; }

if [ "$(hostname)" = "f-rig" ]; then
  echo "$TEST_NAME drives the rig over ssh and REBOOTS it; running it" >&2
  echo "on the rig would reboot the machine under its own feet." >&2
  echo "Run it from ksys: bash $0" >&2
  exit 2
fi

restore() {
  log "restoring the operator's policy"
  on_rig "ip neigh del 10.99.240.9 dev $WAN_IF 2>/dev/null || true;
    ip addr del 10.99.240.1/24 dev $WAN_IF 2>/dev/null || true" \
    >/dev/null 2>&1 || true
  on_rig 'set -e
    [ -f /etc/f/rules.fw.l12-03-bak ] && \
      mv -f /etc/f/rules.fw.l12-03-bak /etc/f/rules.fw
    V=/usr/share/f/compiled/v-smoke
    rm -rf "$V"
    PYTHONPATH=/opt/fwl:/opt/fwl-deps fwl compile --bundle "$V" \
      /etc/f/rules.fw >/dev/null 2>&1
    systemctl stop fd
    rm -f /sys/fs/bpf/f/fwl_* /sys/fs/bpf/f/conntrack 2>/dev/null || true
    ln -sfT "$V" /usr/share/f/compiled/current
    systemctl reset-failed fd 2>/dev/null || true
    systemctl start fd
    rm -rf /usr/share/f/compiled/v-hw-* 2>/dev/null || true' \
    >/dev/null 2>&1 || true
  echo
  log "==== evidence ===="
  local line
  for line in "${EVIDENCE[@]}"; do echo "  $line"; done
  if [ "$FAILURES" -eq 0 ]; then
    log "RESULT: PASS"
    exit 0
  fi
  log "RESULT: FAIL ($FAILURES)"
  exit 1
}
trap restore EXIT

# ---------------------------------------------------------------------
# Stage a stateful policy as the boot-time source AND the active bundle.
# Both, because the watcher recompiles /etc/f/rules.fw within seconds of
# boot: if only the bundle were staged, what came up would be replaced
# by a recompilation of the operator's smoke policy and the measurement
# would be of the wrong thing.
# ---------------------------------------------------------------------
log "staging a stateful policy and rebooting the rig"
on_rig "set -e
  cp /etc/f/rules.fw /etc/f/rules.fw.l12-03-bak
  cat > /etc/f/rules.fw <<'EOF'
zone lan = [$LAN_IF]
zone wanz = [$WAN_IF]

@xdp(lan)

count lan_seen
allow if conntrack(pkt).state in [established, related]
allow

@xdp(wanz)

count wan_seen
allow if conntrack(pkt).state in [established, related]
default drop
EOF
  V=/usr/share/f/compiled/v-hw-l12-03
  rm -rf \"\$V\"
  PYTHONPATH=/opt/fwl:/opt/fwl-deps fwl compile --bundle \"\$V\" \
    /etc/f/rules.fw >/dev/null
  grep -q '\"object\": null' \"\$V/manifest.json\" && exit 3
  ln -sfT \"\$V\" /usr/share/f/compiled/current" \
  || { fail "ABORT: could not stage the policy"; exit 1; }

# The bundle must actually declare a tracker, or the reboot below
# measures nothing. Asserted before the reboot, when saying so is still
# cheap.
DECLARED=$(on_rig "python3 -c \"
import json
m = json.load(open('/usr/share/f/compiled/current/manifest.json'))
e = m.get('egress_tracker')
print(1 if e and e.get('object') else 0)\"")
if [ "$DECLARED" != "1" ]; then
  fail "ABORT: the staged bundle declares no egress tracker, so a reboot would measure nothing"
  exit 1
fi
pass "the staged bundle declares a compiled egress tracker"

on_rig 'systemctl reboot' >/dev/null 2>&1 || true
log "rebooting; waiting for the rig to come back"
sleep 20
UP=0
for _ in $(seq 1 60); do
  if on_rig 'systemctl is-system-running --wait >/dev/null 2>&1; true' \
      >/dev/null 2>&1; then
    UP=1
    break
  fi
  sleep 5
done
if [ "$UP" != "1" ]; then
  fail "ABORT: the rig did not come back"
  exit 1
fi
# The daemon may still be settling; give it the same 10 s any of these
# scenarios gives an attach.
sleep 10
pass "the rig came back after a reboot"

# ---------------------------------------------------------------------
# What came up.
# ---------------------------------------------------------------------
STATUS=$(on_rig 'fctl status 2>/dev/null')
read_field() {
  echo "$STATUS" | python3 -c "
import json, sys
try:
  d = json.load(sys.stdin)
  for k in '$1'.split('.'):
    d = d[k]
  print(len(d) if isinstance(d, list) else (int(d) if isinstance(d, bool) else d))
except Exception:
  print(-1)
"
}
XDP_N=$(echo "$STATUS" | python3 -c "
import json, sys
try:
  d = json.load(sys.stdin)['interfaces']['interfaces']
  print(sum(1 for i in d if i.get('xdp_attached')))
except Exception:
  print(-1)
")
EG_ATTACHED=$(read_field egress.attached)
EG_ENABLED=$(read_field egress.enabled)
log "after the reboot: XDP on $XDP_N interface(s), egress hook live on \
$EG_ATTACHED"
if [ "$XDP_N" -lt 1 ] 2>/dev/null; then
  fail "the datapath did not come up at all (XDP on $XDP_N interfaces)"
else
  pass "the datapath came up (XDP on $XDP_N interfaces)"
fi
if [ "$EG_ENABLED" = "1" ]; then
  pass "the egress tracker came up with it"
else
  fail "the egress tracker did NOT come up (enabled=$EG_ENABLED)"
fi
if [ "$EG_ATTACHED" = "$XDP_N" ]; then
  pass "and is live on every interface the datapath is on ($EG_ATTACHED)"
else
  fail "egress hook live on $EG_ATTACHED interface(s), XDP on $XDP_N"
fi

# ---------------------------------------------------------------------
# And it works, which the counters alone do not say. bpffs was a fresh
# mount, so this is the first conntrack entry of this boot: if the
# tracker had come up attached but broken, every number above would
# still read correctly.
# ---------------------------------------------------------------------
TRACKED_0=$(read_field egress.tracked)
# The flow has to actually LEAVE, and after a reboot the data ports
# carry no addresses and no neighbours: a bare sendto() to an
# unreachable address is discarded by the routing lookup and never
# reaches the qdisc at all, so this assertion read "tracked nothing"
# for a hook that was working. Give the WAN port an address and a
# static neighbour for the destination, so the datagram is transmitted
# rather than queued behind an ARP that nobody answers.
on_rig "set -e
  ip addr add 10.99.240.1/24 dev $WAN_IF 2>/dev/null || true
  ip neigh replace 10.99.240.9 lladdr 02:00:00:00:00:09 dev $WAN_IF
  python3 -c \"
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('10.99.240.1', 0))
s.sendto(b'x', ('10.99.240.9', 9999))
\" 2>/dev/null || true"
sleep 1
STATUS=$(on_rig 'fctl status 2>/dev/null')
TRACKED_1=$(read_field egress.tracked)
log "a flow the box originated after the reboot: tracked \
$TRACKED_0 -> $TRACKED_1"
if [ "$TRACKED_1" -gt "$TRACKED_0" ] 2>/dev/null; then
  pass "a flow the box originates after a cold boot IS tracked"
else
  fail "the hook is attached but tracked nothing ($TRACKED_0 -> $TRACKED_1)"
fi

JOURNAL=$(on_rig 'journalctl -u fd -b --no-pager 2>/dev/null | \
  grep -c "egress conntrack tracker attached"')
if [ "${JOURNAL:-0}" -ge 1 ] 2>/dev/null; then
  pass "fd logged the attach on this boot ($JOURNAL line(s))"
else
  fail "no attach line in this boot's journal"
fi

record "bpffs is a fresh mount after a reboot, so nothing was adopted \
and no clsact qdisc survived: this is the empty-state cold boot. The \
DIRTY pin root — a restart with the previous policy's pins still in \
bpffs — is l8_09's subject and is not repeated here."
