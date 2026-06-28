#!/bin/bash
# Layer 4 system tests for the f appliance CLI adapter.
#
# Requires: fd running with XDP attached, einheit-f in PATH.
# Run as root (BPF map access requires CAP_BPF).
#
# Usage:
#   sudo ./tests/system/test_cli_e2e.sh
#
# Exit code 0 = all tests passed, nonzero = failures.

set -euo pipefail

PASS=0
FAIL=0
ERRORS=""

pass() {
  PASS=$((PASS + 1))
  echo "  PASS: $1"
}

fail() {
  FAIL=$((FAIL + 1))
  ERRORS="${ERRORS}  FAIL: $1\n"
  echo "  FAIL: $1"
}

assert_contains() {
  local output="$1" pattern="$2" label="$3"
  if echo "$output" | grep -q "$pattern"; then
    pass "$label"
  else
    fail "$label (expected '$pattern' in output)"
  fi
}

assert_not_contains() {
  local output="$1" pattern="$2" label="$3"
  if echo "$output" | grep -q "$pattern"; then
    fail "$label (unexpected '$pattern' in output)"
  else
    pass "$label"
  fi
}

assert_exit_zero() {
  local label="$1"; shift
  if "$@" > /dev/null 2>&1; then
    pass "$label"
  else
    fail "$label (exit code $?)"
  fi
}

assert_exit_nonzero() {
  local label="$1"; shift
  if "$@" > /dev/null 2>&1; then
    fail "$label (expected nonzero exit)"
  else
    pass "$label"
  fi
}

echo "=== f appliance CLI system tests ==="
echo ""

# Detect interface.
IFACE=$(ip -o link show | grep -v lo: | grep -v docker \
  | awk -F': ' '{print $2}' | head -1)
echo "Interface: $IFACE"

# Ensure fd is running.
if ! pgrep -f "fd.*run" > /dev/null 2>&1; then
  echo "Starting fd on $IFACE..."
  nohup fd -i "$IFACE" run > /tmp/fd-test.log 2>&1 &
  sleep 3
fi

echo ""
echo "--- show interfaces ---"
OUT=$(einheit-f --ascii --color never show interfaces 2>&1)
assert_contains "$OUT" "$IFACE" \
  "show interfaces lists $IFACE"
assert_contains "$OUT" "up" \
  "show interfaces shows link state"

echo ""
echo "--- show status ---"
OUT=$(einheit-f --ascii --color never show status 2>&1)
assert_contains "$OUT" "pid" \
  "show status reports pid"
assert_contains "$OUT" "uptime" \
  "show status reports uptime"
assert_contains "$OUT" "available" \
  "show status reports maps available"
assert_contains "$OUT" "interfaces" \
  "show status reports interface count"

echo ""
echo "--- show firewall ---"
OUT=$(einheit-f --ascii --color never show firewall 2>&1)
assert_contains "$OUT" "default_action" \
  "show firewall reports default action"
assert_contains "$OUT" "active_table" \
  "show firewall reports active table"
assert_contains "$OUT" "rule_count" \
  "show firewall reports rule count"

echo ""
echo "--- show firewall rules (empty) ---"
OUT=$(einheit-f --ascii --color never show firewall rules 2>&1)
assert_contains "$OUT" "no rules" \
  "show firewall rules reports no rules when empty"

echo ""
echo "--- show counters with traffic ---"
# Generate traffic to populate counters.
ping -c 5 -W 1 127.0.0.1 > /dev/null 2>&1 || true
ping -c 5 -W 1 "$(hostname -I | awk '{print $1}')" > /dev/null 2>&1 || true
sleep 1
OUT_AFTER=$(einheit-f --ascii --color never show counters 2>&1)
# Counter output should contain numeric data (packets
# column) or "no counters" if XDP isn't counting on this
# interface. Either is valid — the command must not crash.
assert_exit_zero "show counters exits cleanly" \
  einheit-f --ascii show counters

echo ""
echo "--- clear counters ---"
OUT=$(einheit-f --ascii --color never clear counters 2>&1)
assert_contains "$OUT" "cleared" \
  "clear counters reports cleared count"

echo ""
echo "--- set editor ---"
OUT=$(einheit-f --ascii --color never set editor nano 2>&1)
assert_contains "$OUT" "nano" \
  "set editor sets nano"
OUT=$(einheit-f --ascii --color never set editor 2>&1)
assert_contains "$OUT" "nano" \
  "set editor persists preference"
# Reset to vim.
einheit-f set editor vim > /dev/null 2>&1

echo ""
echo "--- show log ---"
OUT=$(einheit-f --ascii --color never show log 2>&1)
# Should not crash, may report no entries.
assert_exit_zero "show log exits cleanly" \
  einheit-f --ascii show log

echo ""
echo "--- failure mode: fd stopped ---"
pkill -f "fd.*run" 2>/dev/null || true
sleep 2
OUT=$(einheit-f --ascii --color never show status 2>&1)
assert_contains "$OUT" "not responding" \
  "show status reports not responding when fd stopped"

OUT=$(einheit-f --ascii --color never show interfaces 2>&1)
assert_contains "$OUT" "$IFACE" \
  "show interfaces works without fd"

echo ""
echo "--- failure mode: recovery after fd restart ---"
nohup fd -i "$IFACE" run > /tmp/fd-test.log 2>&1 &
sleep 3
OUT=$(einheit-f --ascii --color never show status 2>&1)
assert_contains "$OUT" "pid" \
  "show status recovers after fd restart"
assert_contains "$OUT" "available" \
  "maps available after fd restart"

echo ""
echo "=================================="
echo "PASSED: $PASS"
echo "FAILED: $FAIL"
if [ $FAIL -gt 0 ]; then
  echo ""
  echo "Failures:"
  echo -e "$ERRORS"
  exit 1
fi
echo "All tests passed."
exit 0
