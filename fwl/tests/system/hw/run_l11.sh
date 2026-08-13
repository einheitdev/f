#!/usr/bin/env bash
# The NAT/masquerade ceiling probes and the ICMP/path-MTU check.
#
# These are deliberately SLOW — three of them wait out the 300 s
# conntrack idle timeout, and l11_05 moves 200 MB of real TCP over the
# wire twice. Budget ~50 minutes for the set.
#
# These began as ceiling probes — measurements of where the system
# stopped working, several of which ended in FAIL by design. Most of
# those ceilings have since been closed, and when one is, the probe is
# tightened to assert the new behaviour exactly rather than loosened to
# tolerate it, and taken off the by-design list below. A FAIL in a test
# that is not named there is a regression.
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
echo "  l11_05 FAILs because an ICMP error names its flow in its"
echo "         PAYLOAD (the embedded datagram), which nothing reads:"
echo "         a frag-needed is dropped by a stateful policy (no"
echo "         ports, so it reads NEW) and cannot be steered to a"
echo "         masqueraded host under any policy. Path-MTU discovery"
echo "         is structurally broken for a NAT'd flow. Both halves"
echo "         are needed — RFC 5508 translation AND a 'related'"
echo "         state — so fixing either alone changes nothing."
echo
echo "Closed, and now regressions if they fail:"
echo "  l11_04 — masquerade and 'allow if established' did not"
echo "         compose. fwl_snat_egress tracks the post-NAT tuple."
echo "  l11_01 — a source-port collision silently overwrote another"
echo "         host's mapping and misdelivered its inbound payload."
echo "         Mappings are claimed with BPF_NOEXIST and the port is"
echo "         reallocated from 49152-65535 instead."
echo "  l11_02 — fwl_nat had no collector and never drained. A"
echo "         mapping is now freed when its flow's conntrack entry"
echo "         is gone, and occupancy/refusals are in fctl status."
echo "  l11_06 — new: the occupancy curve under a steady workload."
echo "         Flat means freeing keeps up; monotone means it does"
echo "         not, whatever the cap says."
exit $RC
