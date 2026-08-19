#!/usr/bin/env bash
# Run every Layer-2 hardware test in sequence; print a summary table.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
declare -a RESULTS=()
RC=0
for script in "$HERE"/l2_*.sh; do
  name=$(basename "$script" .sh)
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
echo "================ Layer 2 summary ================"
for line in "${RESULTS[@]}"; do echo "  $line"; done
exit $RC
