#!/usr/bin/env bash
# The batches added 2026-08-10: boundaries (l5), Tier2/helpers/zones
# and known-gap pins (l7), daemon silent-failure probes (l8), and
# performance/correctness (l9).
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
declare -a RESULTS=()
RC=0
for script in "$HERE"/l5_*.sh "$HERE"/l7_*.sh "$HERE"/l8_*.sh \
              "$HERE"/l9_*.sh; do
  name=$(basename "$script" .sh)
  echo
  echo "================ $name ================"
  if bash "$script"; then RESULTS+=("PASS  $name")
  else RESULTS+=("FAIL  $name"); RC=1; fi
done
echo
echo "================ new-batch summary ================"
for line in "${RESULTS[@]}"; do echo "  $line"; done
exit $RC
