# Shared plumbing for the hardware system tests. Source, don't run.
#
# Contract: runs on the rig as root. fd is installed as a systemd
# service, fwl is on PATH, the FWL package importable via
# PYTHONPATH=/opt/fwl:/opt/fwl-deps.
set -u

SEND_IF="${SEND_IF:-enp1s0f0}"
RECV_IF="${RECV_IF:-enp1s0f1}"
BUNDLE_ROOT=/usr/share/f/compiled
PIN=/sys/fs/bpf/f
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PYTHONPATH=/opt/fwl:/opt/fwl-deps
PY=python3

TEST_NAME="${TEST_NAME:-$(basename "${0%.sh}")}"
FAILURES=0
EVIDENCE=()

log() { echo "[$TEST_NAME] $*"; }

pass() { log "PASS: $*"; EVIDENCE+=("PASS: $*"); }

fail() { log "FAIL: $*"; EVIDENCE+=("FAIL: $*"); FAILURES=$((FAILURES+1)); }

# assert_eq <label> <actual> <expected>
assert_eq() {
  if [ "$2" -eq "$3" ] 2>/dev/null; then
    pass "$1 = $2"
  else
    fail "$1 = $2, expected $3"
  fi
}

# assert_range <label> <actual> <min> <max>
assert_range() {
  if [ "$2" -ge "$3" ] 2>/dev/null && [ "$2" -le "$4" ] 2>/dev/null; then
    pass "$1 = $2 (allowed $3..$4)"
  else
    fail "$1 = $2, expected $3..$4"
  fi
}

hw::require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "must run as root (on the rig)" >&2
    exit 2
  fi
}

# hw::deploy <bundle-tag> <policy-file>
# Compile the policy into a fresh versioned bundle, restart fd on it,
# wait for the XDP attach, set up promisc + switch FDB.
hw::deploy() {
  local tag="$1" fw="$2"
  local ver="$BUNDLE_ROOT/v-hw-$tag-$$"
  fwl check "$fw" >/dev/null || { echo "policy rejected"; exit 2; }
  rm -rf "$ver"
  fwl compile --bundle "$ver" "$fw" >/dev/null
  # Every zone object must have compiled (clang present on the rig).
  if grep -q '"object": null' "$ver/manifest.json"; then
    echo "bundle has uncompiled zone objects" >&2
    exit 2
  fi
  systemctl stop fd
  # Pinned maps persist across fd restarts; stale shapes from the
  # previous policy would collide with the new object's maps.
  rm -f "$PIN"/fwl_* "$PIN"/conntrack 2>/dev/null || true
  ln -sfT "$ver" "$BUNDLE_ROOT/current"
  systemctl start fd
  local i
  for i in $(seq 1 20); do
    if fctl status 2>/dev/null | grep -q '"xdp_attached":true'; then
      break
    fi
    sleep 0.5
  done
  fctl status 2>/dev/null | grep -q '"xdp_attached":true' \
    || { echo "fd did not attach XDP" >&2; journalctl -u fd -n 10 \
         --no-pager >&2; exit 2; }
  ip link set dev "$RECV_IF" promisc on
  # XDP attach resets the igb links; wait until frames actually cross
  # the switch again before any test traffic.
  $PY "$HERE/sendmany.py" --probe "$SEND_IF" "$RECV_IF" 45 \
    || { echo "wire never came back after attach" >&2; exit 2; }
  hw::teach_fdb
  log "deployed $ver"
}

# Teach the EX2300 where the builder MACs live so test frames unicast
# port-to-port instead of flooding.
hw::teach_fdb() {
  $PY "$HERE/sendmany.py" --teach "$RECV_IF" "$SEND_IF"
}

# hw::counter <name> — summed per-CPU value of a named FWL counter.
# Name->slot comes from the fwl_counter_table comment in the bundle's
# generated C.
hw::counter() {
  local name="$1"
  local src slot
  src=$(ls "$BUNDLE_ROOT"/current/*.bpf.c | head -1)
  slot=$(awk -v n="$name" \
    '/fwl_counter_table:/{t=1; next} t && $3==n {print $2; exit}' \
    "$src")
  if [ -z "$slot" ]; then
    echo "unknown counter $name" >&2
    echo 0
    return 1
  fi
  bpftool map dump pinned "$PIN/fwl_counters" 2>/dev/null | $PY -c "
import json, sys
entries = json.load(sys.stdin)
for e in entries:
  if e['key'] == $slot:
    print(sum(v['value'] for v in e['values']))
    break
else:
  print(0)
"
}

# hw::send <count> '<builder>' — batch-send builder frames out SEND_IF.
hw::send() {
  $PY "$HERE/sendmany.py" "$SEND_IF" "$1" "$2"
}

# hw::sniff_start <seconds> — start the receiver witness in the
# background; hw::sniff_get <key> reads a tally after hw::sniff_wait.
SNIFF_OUT=""
SNIFF_PID=""
hw::sniff_start() {
  SNIFF_OUT=$(mktemp)
  $PY "$HERE/sniff.py" "$RECV_IF" "$1" > "$SNIFF_OUT" &
  SNIFF_PID=$!
  # Give the socket a beat to bind before traffic starts.
  sleep 0.5
}

hw::sniff_wait() {
  wait "$SNIFF_PID" 2>/dev/null || true
}

# hw::sniff_get <key> — tally for "proto:src_ip:dst_port_or_type".
hw::sniff_get() {
  $PY -c "
import json, sys
with open('$SNIFF_OUT') as fh:
  print(json.load(fh).get('$1', 0))
"
}

# Recompile the operator smoke policy and leave fd running on it.
hw::restore_smoke() {
  local ver="$BUNDLE_ROOT/v-smoke"
  rm -rf "$ver"
  fwl compile --bundle "$ver" /etc/f/rules.fw >/dev/null 2>&1 || return
  systemctl stop fd
  rm -f "$PIN"/fwl_* "$PIN"/conntrack 2>/dev/null || true
  ln -sfT "$ver" "$BUNDLE_ROOT/current"
  systemctl start fd
  # Drop the per-test bundle dirs; `current` points at v-smoke now.
  rm -rf "$BUNDLE_ROOT"/v-hw-* 2>/dev/null || true
}

hw::finish() {
  hw::restore_smoke
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
