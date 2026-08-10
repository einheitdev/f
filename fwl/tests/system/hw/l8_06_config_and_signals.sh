#!/usr/bin/env bash
# Config handling and signal handling — two places where "it started
# fine" can mean the opposite of what the operator intended.
#
# 1. A YAML syntax error discards the ENTIRE config: one warn line,
#    then the daemon runs on compiled-in defaults. Since the watch
#    block lives in that config, a stray tab silently turns hot
#    reload off while everything looks healthy.
# 2. SIGTERM must detach XDP on the way out (the documented clean
#    shutdown). SIGHUP is NOT handled — operators reflexively send it
#    to reload config, and here it kills the process instead, leaving
#    the program attached with no daemon.
source "$(dirname "$0")/hwlib.sh"
hw::require_root

CFG=/etc/f/fd.yaml
CFG_BAK=$(mktemp)
cp "$CFG" "$CFG_BAK"
cleanup() {
  cp "$CFG_BAK" "$CFG"
  systemctl start fd 2>/dev/null || true
  sleep 3
  hw::finish
}
trap cleanup EXIT

FW=$(mktemp --suffix=.fw)
cat > "$FW" <<EOF
zone t = [$RECV_IF]

@xdp(t)

count seen if pkt.src_ip == 10.99.191.1
default allow
EOF
hw::deploy l8-06 "$FW"

# ---------- 1. broken YAML ----------
# A tab in an indented block is the classic YAML error.
printf 'interfaces: []\nsocket: ipc:///run/f/control.sock\nwatch:\n\tenabled: true\n' \
  > "$CFG"
systemctl restart fd
sleep 4

FD_STATE=$(systemctl is-active fd || true)
WATCHING=$(journalctl -u fd --since "-1min" --no-pager \
  | grep -c "Watching" || true)
CFG_WARN=$(journalctl -u fd --since "-1min" --no-pager \
  | grep -ci "config.*:" || true)
log "broken YAML: fd=$FD_STATE watching_lines=$WATCHING \
config_warnings=$CFG_WARN"

if [ "$FD_STATE" = "active" ] && [ "$WATCHING" -eq 0 ]; then
  fail "SILENT CONFIG LOSS: one YAML syntax error discarded the whole \
config. fd is active and looks healthy, but hot reload is OFF (no \
'Watching' line) because the watch block went with it. Everything \
else silently reverted to compiled-in defaults too — including the \
pin path and socket. A single stray tab disables policy reloading \
with no error beyond one warn line."
else
  pass "broken YAML handled loudly (fd=$FD_STATE, watcher lines=\
$WATCHING)"
fi

# Restore a good config for the signal tests.
cp "$CFG_BAK" "$CFG"
systemctl restart fd
sleep 4
assert_eq "recovered: XDP attached again after a good config" \
  "$(ip -d link show "$RECV_IF" | grep -c ' xdp' || true)" 1

# ---------- 2. SIGTERM detaches ----------
systemctl stop fd
sleep 2
AFTER_TERM=$(ip -d link show "$RECV_IF" | grep -c ' xdp' || true)
assert_eq "SIGTERM (systemctl stop): XDP detached on the way out" \
  "$AFTER_TERM" 0

systemctl start fd
sleep 4
assert_eq "restarted cleanly" \
  "$(ip -d link show "$RECV_IF" | grep -c ' xdp' || true)" 1

# ---------- 3. SIGHUP is not a reload ----------
PID_BEFORE=$(pidof fd || echo 0)
kill -HUP "$PID_BEFORE" 2>/dev/null || true
sleep 4
PID_AFTER=$(pidof fd || echo 0)
STATE=$(systemctl is-active fd || true)
log "SIGHUP: pid $PID_BEFORE -> $PID_AFTER, unit=$STATE"

if [ "$PID_AFTER" != "$PID_BEFORE" ]; then
  pass "SIGHUP killed the daemon (pid changed $PID_BEFORE -> \
$PID_AFTER); systemd restarted it. Worth knowing: HUP is the reflex \
for 'reload config' on most daemons, and here it is not handled — \
edit the policy file instead, or use systemctl reload-or-restart."
else
  pass "SIGHUP was ignored, daemon survived (pid $PID_AFTER)"
fi
assert_eq "after SIGHUP the firewall is attached and running" \
  "$(ip -d link show "$RECV_IF" | grep -c ' xdp' || true)" 1
