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

# Ensure fd is running. `-i <iface>` is gone with the v0.1 attach
# list: fd attaches to the interfaces the staged bundle's zones name,
# and refuses to start without a bundle at all. This test therefore
# needs a box with `/usr/share/f/compiled/current` already staged.
if ! pgrep -f "fd.*run" > /dev/null 2>&1; then
  echo "Starting fd..."
  nohup fd run > /tmp/fd-test.log 2>&1 &
  sleep 3
fi
if ! pgrep -f "fd.*run" > /dev/null 2>&1; then
  echo "fd did not start; is a bundle staged under" \
       "/usr/share/f/compiled/current? See /tmp/fd-test.log" >&2
  exit 1
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
assert_contains "$OUT" "interfaces" \
  "show status reports interface count"

echo ""
echo "--- the v0.1 verbs are gone, not empty ---"
# `show firewall`, `show firewall rules`, `show counters` and
# `clear counters` addressed the single-program datapath. The first
# answered a fabrication from an FwConfig nothing wrote; the rest were
# refused by fd. They must not be registered, and the CLI must say so
# by name rather than printing an empty table.
for gone in "show firewall" "show firewall rules" "show counters" \
            "clear counters"; do
  # shellcheck disable=SC2086
  if einheit-f --ascii --color never $gone > /dev/null 2>&1; then
    assert_contains "registered" "gone" \
      "\`$gone\` still answers; it has no datapath to ask"
  else
    assert_contains "gone" "gone" "\`$gone\` is not a command"
  fi
done

echo ""
echo "--- show zones is where the loaded policy is ---"
assert_exit_zero "show zones exits cleanly" \
  einheit-f --ascii show zones

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
nohup fd run > /tmp/fd-test.log 2>&1 &
sleep 3
OUT=$(einheit-f --ascii --color never show status 2>&1)
assert_contains "$OUT" "pid" \
  "show status recovers after fd restart"

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
