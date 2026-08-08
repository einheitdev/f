#!/usr/bin/env bash
# Test-plan L3 row 3: cold-boot auto-load. REBOOTS THE RIG.
#
# Run from ksys (not via hw.sh — the rig connection dies mid-test):
#   f/fwl/tests/system/hw/l3_03_cold_boot.sh
# Validated 2026-08-08 during Layer 0; keep for re-runs.
set -u
echo "[l3-03] rebooting the rig..."
ssh f-rig 'systemctl reboot' || true
sleep 75
for i in $(seq 1 8); do
  if ssh -o ConnectTimeout=10 f-rig 'true' 2>/dev/null; then
    break
  fi
  sleep 15
done
ssh f-rig '
set -e
systemctl is-active fd
journalctl -u fd -b --no-pager | grep "Cold-boot"
fctl status | grep -o "\"xdp_attached\":true" | wc -l
' && echo "[l3-03] PASS: fd active, bundle cold-booted, XDP attached" \
  || { echo "[l3-03] FAIL"; exit 1; }
