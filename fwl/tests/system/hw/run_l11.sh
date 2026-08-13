#!/usr/bin/env bash
# The NAT/masquerade ceiling probes and the ICMP/path-MTU check.
#
# These are deliberately SLOW — three of them wait out the 300 s
# conntrack idle timeout, and l11_05 moves 200 MB of real TCP over the
# wire twice. Budget ~50 minutes for the set.
#
# Unlike the l1-l9 suites these are not pass/fail tests of a feature.
# They exist to MEASURE where the system stops working and to record
# the behaviour there; several of them end in FAIL by design, because
# the ceiling they found is a real one. Read the evidence block, not
# just the exit code.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
declare -a RESULTS=()
RC=0
for script in "$HERE"/l10_*.sh "$HERE"/l11_*.sh; do
  name=$(basename "$script" .sh)
  echo
  echo "================ $name ================"
  if bash "$script"; then RESULTS+=("PASS  $name")
  else RESULTS+=("FAIL  $name"); RC=1; fi
done
echo
echo "================ ceiling-probe summary ================"
for line in "${RESULTS[@]}"; do echo "  $line"; done
echo
echo "A FAIL here may be the finding rather than a regression:"
echo "  l11_05 FAILs because ICMP unreachables are dropped by a"
echo "         stateful policy and cannot be de-NAT'd under any."
echo
echo "l11_04 used to be on that list — masquerade and 'allow if"
echo "established' did not compose. fwl_snat_egress now tracks the"
echo "post-NAT tuple, so it passes; a FAIL there is a regression."
exit $RC
