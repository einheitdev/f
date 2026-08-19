#!/usr/bin/env bash
# Adversarial / malformed-frame suite (Layer 6) + known-gap pins.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
declare -a RESULTS=()
RC=0
for script in "$HERE"/l6_*.sh "$HERE"/l7_*.sh; do
  name=$(basename "$script" .sh)
  echo
  echo "================ $name ================"
  if bash "$script"; then RESULTS+=("PASS  $name")
  else RESULTS+=("FAIL  $name"); RC=1; fi
done
echo
echo "================ adversarial summary ================"
for line in "${RESULTS[@]}"; do echo "  $line"; done
exit $RC
