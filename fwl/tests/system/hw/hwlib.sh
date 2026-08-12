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

# assert_str <label> <actual> <expected> — string equality.
#
# assert_eq is NUMERIC (`[ -eq ]`), so feeding it a word silently
# routes every comparison to fail: `[ True -eq True ]` is an error, the
# error is swallowed by 2>/dev/null, and the test reports
# "= True, expected True" as a FAILURE. l10_01 has been carrying
# exactly that since it was written. Use this for anything that is not
# an integer.
assert_str() {
  if [ "$2" = "$3" ]; then
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

# Abort the test as FAILED (deploy/setup error). Never exit 0 from a
# setup failure — a test that could not run has not passed.
hw::abort() {
  fail "ABORT: $*"
  exit 1
}

# hw::deploy <bundle-tag> <policy-file>
# Compile the policy into a fresh versioned bundle, restart fd on it,
# wait for the XDP attach, set up promisc + switch FDB.
hw::deploy() {
  local tag="$1" fw="$2"
  local ver="$BUNDLE_ROOT/v-hw-$tag-$$"
  fwl check "$fw" >/dev/null || hw::abort "policy rejected"
  rm -rf "$ver"
  fwl compile --bundle "$ver" "$fw" >/dev/null \
    || hw::abort "bundle compile failed"
  # Every zone object must have compiled (clang present on the rig).
  if grep -q '"object": null' "$ver/manifest.json"; then
    hw::abort "bundle has uncompiled zone objects"
  fi
  systemctl stop fd
  # Pinned maps persist across an fd restart (bpffs holds a reference;
  # only a reboot clears it). Clearing them here used to be this
  # function's job, and that workaround is exactly why no test could
  # see the cold-boot stale-pin defect: every deploy handed fd a clean
  # bpffs that the field never has. Reconciling the pin root against
  # the incoming bundle is the daemon's job — see ReconcilePinnedMaps —
  # so the harness now hands it the same dirty state a restart does.
  # (hw::restore_smoke still clears, as a recovery path; see there.)
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
    || { journalctl -u fd -n 12 --no-pager >&2
         hw::abort "fd did not attach XDP"; }
  ip link set dev "$RECV_IF" promisc on
  # The i350 strips 802.1Q tags in hardware before XDP sees them;
  # FWL vlan_id matching needs the tag on the wire frame.
  ethtool -K "$RECV_IF" rxvlan off 2>/dev/null || true
  # XDP attach resets the igb links; wait until frames actually cross
  # the switch again before any test traffic.
  $PY "$HERE/sendmany.py" --probe "$SEND_IF" "$RECV_IF" 45 \
    || hw::abort "wire never came back after attach"
  hw::teach_fdb
  log "deployed $ver"
}

# Teach the EX2300 where the builder MACs live so test frames unicast
# port-to-port instead of flooding.
hw::teach_fdb() {
  $PY "$HERE/sendmany.py" --teach "$RECV_IF" "$SEND_IF"
}

# hw::counter <name> — summed per-CPU value of a named FWL counter.
# Name->slot comes from the fwl_counter_table comment in the zone's
# generated C; counters are zone-private, so the pinned map is
# fwl_counters_<zone> (zone = the .bpf.c basename).
hw::counter() {
  local name="$1"
  local src slot zone=""
  for src in "$BUNDLE_ROOT"/current/*.bpf.c; do
    slot=$(awk -v n="$name" \
      '/fwl_counter_table:/{t=1; next} t && $3==n {print $2; exit}' \
      "$src")
    if [ -n "$slot" ]; then
      zone=$(basename "$src" .bpf.c)
      break
    fi
  done
  if [ -z "$zone" ]; then
    echo "unknown counter $name" >&2
    echo 0
    return 1
  fi
  bpftool map dump pinned "$PIN/fwl_counters_$zone" 2>/dev/null \
    | $PY -c "
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

# hw::map_sum <pin-name> — total of every value in a pinned (per-CPU)
# array, summed over all keys and all CPUs. Prints -1 when the pin
# does not exist, so a missing map fails an assertion instead of
# silently reading as zero.
hw::map_sum() {
  local pin="$PIN/$1"
  if [ ! -e "$pin" ]; then
    echo -1
    return
  fi
  bpftool map dump pinned "$pin" 2>/dev/null | $PY -c "
import json, sys
total = 0
for e in json.load(sys.stdin):
  vals = e.get('values')
  total += sum(v['value'] for v in vals) if vals else e.get('value', 0)
print(total)
"
}

# hw::map_id <pin-name> — kernel map id behind a pin, or -1. Two pins
# resolving to the SAME id are one kernel map: that is what pin-by-name
# sharing means, and what zone-private maps must never do. The kernel
# map NAME cannot answer this — BPF_OBJ_NAME_LEN truncates it to 15
# chars, so fwl_log_sample_a and fwl_log_sample_b both show as
# 'fwl_log_sample_'. The id is the identity.
hw::map_id() {
  local pin="$PIN/$1"
  if [ ! -e "$pin" ]; then
    echo -1
    return
  fi
  bpftool -j map show pinned "$pin" 2>/dev/null \
    | $PY -c "import json,sys; print(json.load(sys.stdin)['id'])" \
    2>/dev/null || echo -1
}

# hw::send <count> '<builder>' — batch-send builder frames out SEND_IF.
hw::send() {
  $PY "$HERE/sendmany.py" "$SEND_IF" "$1" "$2"
}

# hw::send_reverse <count> '<builder>' — the same burst the other way:
# out of RECV_IF, into SEND_IF, MACs swapped so it unicasts rather
# than being addressed at the port it just left. For a test where BOTH
# interfaces must receive traffic — a multi-zone bundle in which every
# zone has to log something of its own. Call hw::open_reverse_path
# first; SEND_IF needs promisc and the wire needs to be proven in that
# direction, the same way hw::deploy proves the forward one.
hw::send_reverse() {
  $PY "$HERE/sendmany.py" --reverse "$RECV_IF" "$1" "$2"
}

# hw::open_reverse_path — make SEND_IF a usable receiver.
hw::open_reverse_path() {
  ip link set dev "$SEND_IF" promisc on
  ethtool -K "$SEND_IF" rxvlan off 2>/dev/null || true
  $PY "$HERE/sendmany.py" --probe-rev "$RECV_IF" "$SEND_IF" 45 \
    || hw::abort "reverse wire never came up ($RECV_IF -> $SEND_IF)"
}

# hw::sniff_start <seconds> — start the receiver witness in the
# background; hw::sniff_get <key> reads a tally after hw::sniff_wait.
SNIFF_OUT=""
SNIFF_PID=""
hw::sniff_start() {
  SNIFF_OUT=$(mktemp)
  $PY "$HERE/sniff.py" "$RECV_IF" "$@" > "$SNIFF_OUT" &
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

# hw::map_entries <pin-name> — number of entries in a pinned map, or
# -1 when the pin does not exist (so a missing map fails an assertion
# instead of reading as an empty one).
hw::map_entries() {
  local pin="$PIN/$1"
  if [ ! -e "$pin" ]; then
    echo -1
    return
  fi
  bpftool -j map dump pinned "$pin" 2>/dev/null \
    | $PY -c "import json,sys; print(len(json.load(sys.stdin)))" \
    2>/dev/null || echo -1
}

# Recompile the operator smoke policy and leave fd running on it.
#
# This is the recovery path, not a measurement path: it runs from the
# EXIT trap of every test, including ones that failed with fd in a
# restart loop. Wiping the pin root here is deliberate belt-and-braces
# so a walk-up operator always finds a working rig — unlike hw::deploy,
# where clearing pins hid a real defect from every test that used it.
hw::restore_smoke() {
  local ver="$BUNDLE_ROOT/v-smoke"
  rm -rf "$ver"
  fwl compile --bundle "$ver" /etc/f/rules.fw >/dev/null 2>&1 || return
  systemctl stop fd
  rm -f "$PIN"/fwl_* "$PIN"/conntrack 2>/dev/null || true
  ln -sfT "$ver" "$BUNDLE_ROOT/current"
  systemctl reset-failed fd 2>/dev/null || true
  systemctl start fd
  # Drop the per-test bundle dirs; `current` points at v-smoke now.
  rm -rf "$BUNDLE_ROOT"/v-hw-* 2>/dev/null || true
}

# hw::pin_irqs_to_cpu <iface> [<iface> ...] — put every queue IRQ of
# the named interfaces on one CPU (0 by default, override with
# PIN_CPU). For tests whose subject is a PERCPU map: XDP runs in the
# NAPI poll of the RX queue, i.e. on whichever CPU takes that queue's
# interrupt, so two interfaces landing on different CPUs read different
# cells of the same per-CPU map. Without this, such a test measures RSS
# placement rather than the thing it claims to. Affinities are saved
# and restored by hw::unpin_irqs.
PINNED_IRQS=()
PINNED_IRQ_SAVED=()
hw::pin_irqs_to_cpu() {
  local cpu="${PIN_CPU:-0}" iface irq old
  for iface in "$@"; do
    for irq in $(awk -v n="$iface" \
        '$NF ~ "^"n"(-|$)" {sub(":","",$1); print $1}' \
        /proc/interrupts); do
      old=$(cat "/proc/irq/$irq/smp_affinity_list" 2>/dev/null) || continue
      if echo "$cpu" > "/proc/irq/$irq/smp_affinity_list" 2>/dev/null; then
        PINNED_IRQS+=("$irq")
        PINNED_IRQ_SAVED+=("$old")
      fi
    done
  done
  log "pinned ${#PINNED_IRQS[@]} queue IRQs to CPU $cpu"
}

hw::unpin_irqs() {
  local i
  for i in "${!PINNED_IRQS[@]}"; do
    echo "${PINNED_IRQ_SAVED[$i]}" \
      > "/proc/irq/${PINNED_IRQS[$i]}/smp_affinity_list" 2>/dev/null || true
  done
  PINNED_IRQS=()
  PINNED_IRQ_SAVED=()
}

# EX2300 port-mirror witness: the (pre-configured, deactivated)
# analyzer `fmon` mirrors both directions of the DUT port ge-0/0/25
# into VLAN f-mirror, whose only member is f0 — switch-made copies
# the DUT cannot influence. Toggle per test; always off afterwards
# (an active mirror double-counts flows on the f0 sniffer).
hw::mirror_on() {
  printf 'configure\nactivate forwarding-options analyzer fmon\ncommit and-quit\n' \
    | ssh -o BatchMode=yes ex01 >/dev/null 2>&1
}

hw::mirror_off() {
  printf 'configure\ndeactivate forwarding-options analyzer fmon\ncommit and-quit\n' \
    | ssh -o BatchMode=yes ex01 >/dev/null 2>&1
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
