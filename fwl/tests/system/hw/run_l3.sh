#!/usr/bin/env bash
# Run the Layer-3 daemon-behavior tests (excluding l3_03_cold_boot,
# which reboots the rig — run that one from ksys directly).
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
declare -a RESULTS=()
RC=0
for script in "$HERE"/l3_*.sh; do
  name=$(basename "$script" .sh)
  [ "$name" = "l3_03_cold_boot" ] && continue
  echo
  echo "================ $name ================"
  if bash "$script"; then
    RESULTS+=("PASS  $name")
  else
    RESULTS+=("FAIL  $name")
    RC=1
  fi
done
echo
echo "================ Layer 3 summary ================"
for line in "${RESULTS[@]}"; do echo "  $line"; done
exit $RC
