#!/usr/bin/env bash
# Was the datapath armed before the network came up?
#
# Reads the CURRENT boot's journal, so it costs nothing and can be
# run after any real reboot (including one the operator did). Run
# l3_03_cold_boot.sh first if you want it to reboot for you.
#
# The property: XDP must be attached before network.target is
# reached, and before any data-plane link comes up. fd.service
# declares Before=network.target, but under Type=simple that ordered
# only the exec() — measured on this rig, network.target was reached
# 17 ms BEFORE fd logged its first line, and nothing passed
# unfiltered purely because PHY autonegotiation is slower than
# loading a BPF program. Type=notify plus an sd_notify after the
# attach loop turns that coincidence into an ordering constraint;
# this test is what notices if it ever comes undone.
source "$(dirname "$0")/hwlib.sh"
hw::require_root
trap hw::finish EXIT

ts_of() {
  # First monotonic timestamp of a matching journal line, in ms.
  journalctl -b -o short-monotonic --no-pager \
    | grep -iE "$1" | head -1 \
    | sed -n 's/^\[ *\([0-9]*\)\.\([0-9]\{6\}\)\].*/\1\2/p' \
    | sed 's/\([0-9]*\)\([0-9]\{3\}\)$/\1/'
}

ATTACH=$(ts_of "fd\[.*loaded zone .* on [0-9]+ interface")
NETTGT=$(ts_of "Reached target network\.target")
FIRSTLINK=$(ts_of "igb .*enp1s0f[0-9]: igb: .*Link is Up")

log "XDP attached at      ${ATTACH:-?} ms"
log "network.target at    ${NETTGT:-?} ms"
log "first data link up   ${FIRSTLINK:-?} ms"

if [ -z "$ATTACH" ] || [ -z "$NETTGT" ] || [ -z "$FIRSTLINK" ]; then
  fail "could not read all three timestamps from this boot's \
journal — if the rig has been up a long time the lines may have \
rotated; reboot and re-run"
  exit 1
fi

# The unit must be the notify type, or the ordering below is
# coincidence rather than a guarantee.
TYPE=$(systemctl show fd -p Type --value)
if [ "$TYPE" = "notify" ]; then
  pass "fd.service is Type=notify, so systemd holds network.target \
until fd reports the datapath armed"
else
  fail "fd.service is Type=$TYPE: systemd treats the unit as started \
at exec(), so Before=network.target orders the spawn and not the \
attach. Any ordering seen below is luck, not enforcement."
fi

STATUS=$(systemctl show fd -p StatusText --value)
case "$STATUS" in
  *"datapath armed"*)
    pass "unit reports its real state: \"$STATUS\"" ;;
  *)
    fail "unit status does not report an armed datapath: \"$STATUS\"" ;;
esac

if [ "$ATTACH" -le "$NETTGT" ]; then
  pass "XDP attached ${ATTACH} ms <= network.target ${NETTGT} ms \
(margin $((NETTGT - ATTACH)) ms)"
else
  fail "network.target was reached $((ATTACH - NETTGT)) ms BEFORE \
XDP was attached — the network was declared up while the firewall \
was still loading"
fi

if [ "$ATTACH" -le "$FIRSTLINK" ]; then
  pass "XDP attached $((FIRSTLINK - ATTACH)) ms before the first \
data-plane link came up: no frame can arrive unfiltered"
else
  fail "a data-plane link came up $((ATTACH - FIRSTLINK)) ms BEFORE \
the program was attached — traffic could pass unfiltered during \
that window"
fi
