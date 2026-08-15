#!/usr/bin/env bash
# The occupancy curve of `fwl_nat` under a steady, realistic workload.
#
# The cap is a backstop, not the mechanism. Refusing an allocation
# loudly is the right behaviour at 100 %, but if a normal workload ever
# gets there the freeing is not good enough — the failure was never
# capacity, it was that nothing freed anything, so the table filled
# regardless of load. l11_02 proves that a table which has been filled
# will drain; this proves the shape of the curve while flows are
# arriving continuously, which is the thing an operator actually lives
# with.
#
# What a correct curve looks like: occupancy rises for about one
# conntrack idle timeout and then FLATTENS at roughly
# (new flows/s) x (idle timeout), because at that point flows are
# expiring as fast as they arrive. What the old build did was rise at
# 3613 entries/h and never stop — 17 hours from deployment to a broken
# network at ~1 new flow/s.
#
# The assertion is on the SHAPE, not on a number: the last third of the
# run must not be climbing. Vacuity is guarded three ways — the table
# must actually have grown first, reclamation must actually have
# happened, and a control flow kept alive throughout must still work at
# the end, so "flat" cannot be achieved by the datapath having stopped.
source "$(dirname "$0")/hwlib.sh"
hw::require_root

WAN_IF="${WAN_IF:-enp1s0f2}"
MASQ_ADDR=10.99.200.2
# Flows per second and how long to run. The default is one conntrack
# idle timeout of climb plus half of one of plateau; override RUN_S to
# watch it longer.
RATE="${RATE:-5}"
RUN_S="${RUN_S:-480}"
SAMPLE_S="${SAMPLE_S:-15}"
KEEP_HOST=10.99.34.9
KEEP_PEER=10.99.91.9
KEEP_SPORT=46000
CURVE=/tmp/l11_06_curve.tsv

cleanup() {
  ip addr del "$MASQ_ADDR/24" dev "$WAN_IF" 2>/dev/null || true
  hw::finish
}
trap cleanup EXIT

ip addr add "$MASQ_ADDR/24" dev "$WAN_IF" 2>/dev/null || true

FW=$(mktemp --suffix=.fw)
cat > "$FW" <<EOF
zone lan = [$RECV_IF]
zone wanz = [$WAN_IF]

@xdp(lan)

count egress if pkt.src_ip in 10.99.32.0/22
masquerade if pkt.src_ip in 10.99.32.0/22
redirect to wanz if pkt.proto == udp and pkt.dst_port == 1
allow if pkt.proto == tcp
default drop
EOF
hw::deploy l11-06 "$FW"

assert_str "the NAT table is reported at all" "$(hw::nat enabled)" "True"
CT_TIMEOUT=$(hw::ct timeout_s)
log "conntrack idle timeout ${CT_TIMEOUT}s, sweep $(hw::ct gc_interval_s)s"
log "workload: ~${RATE} new masqueraded flows/s for ${RUN_S}s, sampled \
every ${SAMPLE_S}s"
log "predicted plateau if freeing works: ~$((RATE * CT_TIMEOUT)) mappings"

# The control flow: opened before the run and refreshed throughout, so
# a flat curve produced by the datapath dying is distinguishable from a
# flat curve produced by flows expiring on schedule.
hw::send 5 "tcp(src_ip=\"$KEEP_HOST\", dst_ip=\"$KEEP_PEER\", \
src_port=$KEEP_SPORT, dst_port=443, syn=true)"
sleep 1

# Steady arrival of distinct flows. Each is one SYN — a flow that opens
# and is never spoken of again, which is the worst case for a collector
# and the common case for a browser tab that was closed.
$PY - "$SEND_IF" "$RATE" "$RUN_S" <<'PYEOF' &
import socket
import struct
import sys
import time
sys.path.insert(0, "/opt/fwl")
sys.path.insert(0, "/opt/fwl-deps")
from fwl import pkt

iface, rate, run_s = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind((iface, 0))
frame = bytearray(pkt.build_packet(pkt.parse_builder(
  'tcp(src_ip="10.99.32.1", dst_ip="10.99.100.1", '
  'src_port=1024, dst_port=443, syn=true)'
)).raw)


def fix_ip_csum(f):
  f[24] = 0
  f[25] = 0
  total = sum(struct.unpack(">10H", bytes(f[14:34])))
  while total >> 16:
    total = (total & 0xFFFF) + (total >> 16)
  struct.pack_into(">H", f, 24, (~total) & 0xFFFF)


deadline = time.monotonic() + run_s
n = 0
while time.monotonic() < deadline:
  start = time.monotonic()
  for _ in range(rate):
    # Walk the destination address and the source port together so
    # every flow is a distinct reply-mapping key.
    frame[31] = 100 + ((n >> 16) & 0x03)
    frame[32] = (n >> 8) & 0xFF
    frame[33] = 1 + (n & 0x7F)
    struct.pack_into(">H", frame, 34, 1024 + (n % 60000))
    fix_ip_csum(frame)
    try:
      s.send(bytes(frame))
    except OSError:
      pass
    n += 1
  time.sleep(max(0.0, 1.0 - (time.monotonic() - start)))
s.close()
print(f"[l11_06] generator sent {n} flow-opening SYNs")
PYEOF
GEN_PID=$!

: > "$CURVE"
printf 't_s\tentries\tpct\treclaimed\trefused\n' >> "$CURVE"
T0=$(date +%s)
while kill -0 "$GEN_PID" 2>/dev/null; do
  NOW=$(( $(date +%s) - T0 ))
  printf '%s\t%s\t%s\t%s\t%s\n' "$NOW" "$(hw::nat entries)" \
    "$(hw::nat occupancy_pct)" "$(hw::nat total_reclaimed)" \
    "$(hw::nat refused)" >> "$CURVE"
  # Keep the control flow alive across the whole run.
  hw::send 1 "tcp(src_ip=\"$KEEP_HOST\", dst_ip=\"$KEEP_PEER\", \
src_port=$KEEP_SPORT, dst_port=443, ack=true)" >/dev/null 2>&1
  sleep "$SAMPLE_S"
done
wait "$GEN_PID" 2>/dev/null || true

log "=== occupancy curve ($CURVE) ==="
cat "$CURVE"

VERDICT=$($PY - "$CURVE" "$RATE" "$CT_TIMEOUT" <<'PYEOF'
import sys

path, rate, timeout = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
rows = []
with open(path) as fh:
  next(fh)
  for line in fh:
    t, e, pct, rec, ref = line.split()
    rows.append((int(t), int(e), int(pct), int(rec), int(ref)))

peak = max(r[1] for r in rows)
last = rows[-1][1]
reclaimed = rows[-1][3]
refused = rows[-1][4]
# The shape test: over the final third of the run, is the table still
# climbing? A monotone table has only had its fill rate changed; a
# collected one wanders around a plateau.
tail = rows[len(rows) * 2 // 3:]
if len(tail) >= 3:
  first_half = tail[: len(tail) // 2]
  second_half = tail[len(tail) // 2:]
  a = sum(r[1] for r in first_half) / len(first_half)
  b = sum(r[1] for r in second_half) / len(second_half)
  drift = (b - a) / max(a, 1)
else:
  drift = 1.0
predicted = rate * timeout
print(f"peak={peak} final={last} reclaimed={reclaimed} "
      f"refused={refused} predicted_plateau={predicted} "
      f"tail_drift={drift:.3f}")
PYEOF
)
log "$VERDICT"

PEAK=$(echo "$VERDICT" | sed 's/.*peak=\([0-9]*\).*/\1/')
FINAL=$(echo "$VERDICT" | sed 's/.*final=\([0-9]*\).*/\1/')
RECLAIMED=$(echo "$VERDICT" | sed 's/.*reclaimed=\([0-9]*\).*/\1/')
REFUSED=$(echo "$VERDICT" | sed 's/.*refused=\([0-9]*\).*/\1/')
PREDICTED=$(echo "$VERDICT" | sed 's/.*predicted_plateau=\([0-9]*\).*/\1/')
DRIFT_MILLI=$($PY -c "
import sys
v = '''$VERDICT'''
d = float(v.split('tail_drift=')[1])
print(int(d * 1000))
")

# --- vacuity guards first -------------------------------------------
if [ "$PEAK" -lt "$((PREDICTED / 4))" ]; then
  fail "the table never grew ($PEAK entries against a predicted \
plateau of $PREDICTED): the generator did not install mappings, so \
the curve measures nothing"
  exit 1
fi
pass "the workload really loaded the table (peak $PEAK mappings)"
if [ "$RECLAIMED" -gt 0 ]; then
  pass "reclamation ran during the workload ($RECLAIMED mappings freed)"
else
  fail "nothing was reclaimed during the run: any flatness in the \
curve is not the collector's doing"
fi

# --- the shape ------------------------------------------------------
# ±15 % over the final third is flat enough; a monotone table climbing
# at RATE/s would drift by far more than that over the same window.
if [ "$DRIFT_MILLI" -le 150 ]; then
  pass "CURVE IS FLAT — occupancy over the final third of the run \
drifts by ${DRIFT_MILLI}/1000, settling near $FINAL against a \
predicted plateau of $PREDICTED (rate x idle timeout). Mappings are \
being freed as fast as flows arrive, which is what makes the cap \
unreachable in normal operation rather than a matter of time."
else
  fail "CURVE IS STILL CLIMBING — occupancy drifts ${DRIFT_MILLI}/1000 \
upward over the final third (peak $PEAK, final $FINAL). Freeing is \
not keeping up with a workload of ${RATE} flows/s, so the cap is \
reachable and the refusal path is papering over a collector that is \
not doing its job."
fi

assert_range "occupancy stayed well clear of the cap" \
  "$(hw::nat occupancy_pct)" 0 50
assert_eq "no allocation was refused at this load" "$REFUSED" 0

# --- and the datapath is still alive --------------------------------
hw::sniff_start 8 --detail --srcport
hw::send 10 "tcp(src_ip=\"$KEEP_PEER\", dst_ip=\"$MASQ_ADDR\", \
src_port=443, dst_port=$KEEP_SPORT, ack=true)"
sleep 1
hw::sniff_wait
KEEP_BACK=$(hw::sniff_get "tcp:$KEEP_PEER:443>$KEEP_HOST:$KEEP_SPORT:ok")
assert_eq "the flow kept alive across the whole run still de-NATs" \
  "$KEEP_BACK" 10
log "curve saved to $CURVE"
