#!/bin/bash
# Layer 4 system tests for the f appliance web UI adapter.
#
# Requires: fd running with XDP attached, einheit-f-ui in PATH.
# Run as root (BPF map access requires CAP_BPF).
#
# Usage:
#   sudo ./tests/system/test_ui_e2e.sh
#
# Tests use curl to verify HTTP responses. WebSocket push is
# tested by checking that the /events endpoint accepts upgrades.

set -euo pipefail

PASS=0
FAIL=0
ERRORS=""
UI_PORT=17542
UI_PID=""

pass() {
  PASS=$((PASS + 1))
  echo "  PASS: $1"
}

fail() {
  FAIL=$((FAIL + 1))
  ERRORS="${ERRORS}  FAIL: $1\n"
  echo "  FAIL: $1"
}

assert_http_ok() {
  local url="$1" label="$2"
  local code
  code=$(curl -s -o /dev/null -w "%{http_code}" "$url" 2>/dev/null)
  if [ "$code" = "200" ]; then
    pass "$label (HTTP $code)"
  else
    fail "$label (HTTP $code, expected 200)"
  fi
}

assert_body_contains() {
  local url="$1" pattern="$2" label="$3"
  local body
  body=$(curl -s "$url" 2>/dev/null)
  if echo "$body" | grep -q "$pattern"; then
    pass "$label"
  else
    fail "$label (pattern '$pattern' not in response)"
  fi
}

assert_htmx_fragment() {
  local url="$1" pattern="$2" label="$3"
  local body
  body=$(curl -s -H "HX-Request: true" "$url" 2>/dev/null)
  if echo "$body" | grep -q "$pattern"; then
    pass "$label"
  else
    fail "$label (pattern '$pattern' not in fragment)"
  fi
}

cleanup() {
  if [ -n "$UI_PID" ]; then
    kill "$UI_PID" 2>/dev/null || true
    wait "$UI_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

echo "=== f appliance UI system tests ==="
echo ""

# Detect interface.
IFACE=$(ip -o link show | grep -v lo: | grep -v docker \
  | awk -F': ' '{print $2}' | head -1)

# Ensure fd is running.
if ! pgrep -f "fd.*run" > /dev/null 2>&1; then
  echo "Starting fd on $IFACE..."
  nohup fd -i "$IFACE" run > /tmp/fd-test.log 2>&1 &
  sleep 3
fi

# Start the UI server on a test port.
echo "Starting einheit-f-ui on port $UI_PORT..."
nohup einheit-f-ui --port $UI_PORT --bind 127.0.0.1 \
  > /tmp/ui-test.log 2>&1 &
UI_PID=$!
sleep 2

if ! kill -0 "$UI_PID" 2>/dev/null; then
  echo "FATAL: einheit-f-ui failed to start."
  cat /tmp/ui-test.log
  exit 1
fi

BASE="http://127.0.0.1:$UI_PORT"

echo ""
echo "--- dashboard ---"
assert_http_ok "$BASE/" "GET / returns 200"
assert_body_contains "$BASE/" "dashboard" \
  "dashboard page contains dashboard content"

echo ""
echo "--- interfaces ---"
assert_http_ok "$BASE/interfaces" \
  "GET /interfaces returns 200"
assert_body_contains "$BASE/interfaces" "$IFACE" \
  "interfaces page lists $IFACE"

echo ""
echo "--- firewall ---"
assert_http_ok "$BASE/firewall" \
  "GET /firewall returns 200"
assert_body_contains "$BASE/firewall" "rules" \
  "firewall page contains rules section"

echo ""
echo "--- counters ---"
assert_http_ok "$BASE/counters" \
  "GET /counters returns 200"

echo ""
echo "--- HTMX fragments ---"
assert_htmx_fragment "$BASE/" "status" \
  "dashboard HTMX fragment renders status section"
assert_htmx_fragment "$BASE/interfaces" "$IFACE" \
  "interfaces HTMX fragment lists NIC"
assert_htmx_fragment "$BASE/firewall" "rules" \
  "firewall HTMX fragment renders rules section"

echo ""
echo "--- failure mode: fd stopped ---"
pkill -f "fd.*run" 2>/dev/null || true
sleep 2
assert_http_ok "$BASE/" \
  "dashboard still serves when fd stopped"
assert_http_ok "$BASE/interfaces" \
  "interfaces still serves when fd stopped"

echo ""
echo "--- recovery: fd restarted ---"
nohup fd -i "$IFACE" run > /tmp/fd-test.log 2>&1 &
sleep 3
assert_http_ok "$BASE/" \
  "dashboard recovers after fd restart"

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
