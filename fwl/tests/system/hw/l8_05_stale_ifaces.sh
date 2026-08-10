#!/usr/bin/env bash
# After a reload changes zone membership, does shutdown detach the
# right interfaces?
#
# EngineStop iterates e.ifaces, which is populated only in
# EngineInit. The multi-zone reload path replaces e.zone_bundle and
# never touches e.ifaces. So an interface that a later reload ADDED
# to a zone is not in that list: a clean `systemctl stop` leaves an
# XDP program attached to a NIC after the daemon is gone. The
# operator's mental model ("stopping the firewall removes it") is
# wrong, and the leftover program keeps filtering with no daemon.
source "$(dirname "$0")/hwlib.sh"
hw::require_root

WAN_IF="${WAN_IF:-enp1s0f2}"
RULES_BAK=$(mktemp)
cp /etc/f/rules.fw "$RULES_BAK"
cleanup() {
  cp "$RULES_BAK" /etc/f/rules.fw
  # Whatever the outcome, leave no stray programs behind.
  ip link set dev "$WAN_IF" xdp off 2>/dev/null || true
  hw::finish
}
trap cleanup EXIT

# Boot with ONE interface in the zone.
FW=$(mktemp --suffix=.fw)
cat > "$FW" <<EOF
zone t = [$RECV_IF]

@xdp(t)

count seen if pkt.src_ip == 10.99.144.1
default allow
EOF
hw::deploy l8-05 "$FW"
cp "$FW" /etc/f/rules.fw
sleep 7

assert_eq "boot: $RECV_IF attached" \
  "$(ip -d link show "$RECV_IF" | grep -c ' xdp' || true)" 1
assert_eq "boot: $WAN_IF not attached" \
  "$(ip -d link show "$WAN_IF" | grep -c ' xdp' || true)" 0

# Reload: ADD the second interface to the zone.
cat > /etc/f/rules.fw <<EOF
zone t = [$RECV_IF, $WAN_IF]

@xdp(t)

count seen if pkt.src_ip == 10.99.144.1
default allow
EOF
sleep 12

ADDED=$(ip -d link show "$WAN_IF" | grep -c ' xdp' || true)
assert_eq "reload attached the newly added interface" "$ADDED" 1

# Now stop the daemon cleanly and see what is left behind.
systemctl stop fd
sleep 2
LEFT_RECV=$(ip -d link show "$RECV_IF" | grep -c ' xdp' || true)
LEFT_WAN=$(ip -d link show "$WAN_IF" | grep -c ' xdp' || true)
log "after clean stop: $RECV_IF attached=$LEFT_RECV, \
$WAN_IF attached=$LEFT_WAN"

if [ "$LEFT_WAN" -gt 0 ]; then
  fail "ORPHANED XDP PROGRAM: after a clean 'systemctl stop fd', the \
interface added by a reload ($WAN_IF) still has an XDP program \
attached — it keeps filtering with no daemon to manage it, survives \
until reboot or a manual detach, and can collide with the next \
start. EngineStop walks e.ifaces, which reloads never update."
else
  pass "clean stop detached every interface, including reload-added \
ones"
fi
assert_eq "the originally-attached interface was detached" \
  "$LEFT_RECV" 0

systemctl start fd
sleep 3
