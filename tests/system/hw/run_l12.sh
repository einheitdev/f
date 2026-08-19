#!/usr/bin/env bash
# Flows the appliance itself originates (finding A4, FWL v0.4 § 6.9).
#
# XDP conntrack only ever sees INGRESS, so a flow the box starts — the
# DNS query its forwarder sends upstream, NTP, updates — created no
# conntrack entry at all, its reply read NEW, and `default drop` ate it.
# A firewall that cannot resolve a name or set its own clock is not
# deployable, so this is not an edge case: it is the language's default
# policy being unusable on the box that runs it.
#
# `l12_01` is the mechanism; `l12_02` is the consequence and the only
# proof a person can see. Neither FAILs by design. Budget ~10 minutes.
#
# `l12_03` is NOT run here: it reboots the rig, so it is driven from
# ksys like l3_03. Run it by hand after a change to the attach path:
#
#   bash fwl/tests/system/hw/l12_03_egress_cold_boot.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
declare -a RESULTS=()
RC=0
for script in "$HERE"/l12_01_*.sh "$HERE"/l12_02_*.sh; do
  name=$(basename "$script" .sh)
  echo
  echo "================ $name ================"
  if bash "$script"; then RESULTS+=("PASS  $name")
  else RESULTS+=("FAIL  $name"); RC=1; fi
done
echo
echo "================ summary ================"
for line in "${RESULTS[@]}"; do echo "  $line"; done
echo
echo "l12_01 used to FAIL by design — it was the reproduction of A4."
echo "It now asserts the behaviour that replaced it (5/5 replies, one"
echo "conntrack entry for the flow, the tracked counter moving) with"
echo "three controls: an unsolicited datagram to a bound port is still"
echo "dropped, a FORWARDED burst is seen at the hook and tracked 0,"
echo "and the box's own fresh flow is still tracked +1."
echo
echo "l12_02 is the user-visible half: a client resolving a name"
echo "through the appliance's own dnsmasq, asserted on the ANSWER."
echo "If it fails, read fctl status's egress section first — 'refused'"
echo "and 'attached' are the two fields that explain it."
exit $RC
