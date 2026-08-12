#!/usr/bin/env bash
# Test-plan L3 row 3: cold-boot auto-load. REBOOTS THE RIG.
#
# Run from ksys (not via hw.sh — the rig connection dies mid-test):
#   f/fwl/tests/system/hw/l3_03_cold_boot.sh
# Validated 2026-08-08 during Layer 0; keep for re-runs.
set -u

# This script drives the rig FROM KSYS. Run on the rig itself it would
# ssh to its own address, reboot the machine under its own feet, and
# then report whatever the truncated connection left behind — which is
# how it got into a sweep, no-oped, and was counted as coverage it
# never provided (reported 2026-08-12). Refuse loudly instead: a test
# that cannot run has not passed.
if [ -d /usr/share/f/compiled ] || [ "$(hostname)" = "f-rig" ]; then
  echo "[l3-03] FAIL: this script must run on ksys, not on the rig." \
       "It reboots the target over ssh, so running it on the target" \
       "cannot work. Invoke it directly:" \
       "f/fwl/tests/system/hw/l3_03_cold_boot.sh" >&2
  exit 2
fi

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
