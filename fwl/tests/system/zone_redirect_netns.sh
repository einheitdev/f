#!/usr/bin/env bash
# Netns system test: a packet redirected across FWL zones must
# *physically* cross interfaces (TESTING_STRATEGY.md Layer 4).
#
# Topology (root ns holds the two firewall-facing veth ends):
#
#   ns lansrc          root ns                         ns wandst
#   ----------         -------                         ---------
#   lan0p  <=========> lan0  --[XDP: from_lan]         wan0p <== capture
#                        |  redirect to wan -> devmap   ^
#                      wan0 --[ndo_xdp_xmit]============/
#
# A TCP/80 frame sent from lansrc arrives (RX) on lan0, the firewall's
# lan program redirects it to the wan zone via bpf_redirect_map, the
# kernel xmits it out wan0, and it lands on wan0p where tcpdump proves
# the crossing. A stub returning XDP_PASS could not move the frame.
#
# Requires root (netns, veth, XDP attach, map update). Run on the VM:
#   sudo bash zone_redirect_netns.sh
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
WS="$(cd "$HERE/../.." && pwd)"          # the fwl package root
WORK="$(mktemp -d)"
PIN=/sys/fs/bpf/zt
RC=0

log() { echo "[netns] $*"; }
fail() { echo "[netns] FAIL: $*"; RC=1; }

cleanup() {
  ip link set dev lan0 xdp off 2>/dev/null
  ip netns exec wandst ip link set dev wan0p xdp off 2>/dev/null
  ip link del lan0 2>/dev/null
  ip link del wan0 2>/dev/null
  ip netns del lansrc 2>/dev/null
  ip netns del wandst 2>/dev/null
  rm -rf "$PIN" "$WORK" 2>/dev/null
  # PIN_BY_NAME maps self-pin at the bpffs root; clear them too.
  # A devmap is not one of them any more, but a run from before
  # that change may have left one behind.
  rm -f /sys/fs/bpf/fwl_devmap_wan /sys/fs/bpf/conntrack \
        /sys/fs/bpf/fwl_route_stats 2>/dev/null
}
trap cleanup EXIT
cleanup  # idempotent: clear any prior run
mkdir -p "$WORK"  # cleanup just removed it; recreate the scratch dir

mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf
mkdir -p "$PIN"

# --- 1. Emit + compile the firewall's lan zone program --------------
cat > "$WORK/gw.fw" <<'EOF'
zone wan = [wan0]
zone lan = [lan0]
@xdp(wan)
drop
@xdp(lan)
redirect to wan if pkt.proto == tcp and pkt.dst_port == 80
drop
EOF

cd "$WS"
PYTHONPATH="$WS${PYTHONPATH:+:$PYTHONPATH}" python3 -c "
from fwl import analyzer, parser, emitter
prog = analyzer.analyze(parser.parse(open('$WORK/gw.fw').read()))
files = emitter.emit_bundle(prog)
open('$WORK/lan.bpf.c','w').write(files['lan.bpf.c'])
" || { fail "emit"; exit 1; }

# Match the include paths fwl's bpf_runner uses (multiarch asm/ headers).
CINC="-I/usr/include/x86_64-linux-gnu -I/usr/include/aarch64-linux-gnu"
clang -O2 -g -target bpf $CINC -c "$WORK/lan.bpf.c" -o "$WORK/lan.bpf.o" \
  || { fail "compile lan.bpf.o"; exit 1; }
clang -O2 -g -target bpf $CINC -c "$HERE/xdp_pass.bpf.c" \
  -o "$WORK/xdp_pass.bpf.o" \
  || { fail "compile xdp_pass"; exit 1; }
log "compiled lan.bpf.o (real bpf_redirect_map):"
grep -c "bpf_redirect_map" "$WORK/lan.bpf.c" >/dev/null \
  && log "  -> source uses bpf_redirect_map"

# --- 2. Build the netns topology ------------------------------------
ip netns add lansrc
ip netns add wandst
ip link add lan0 type veth peer name lan0p
ip link add wan0 type veth peer name wan0p
ip link set lan0p netns lansrc
ip link set wan0p netns wandst
ip link set lan0 up
ip link set wan0 up
ip netns exec lansrc ip link set lo up
ip netns exec lansrc ip link set lan0p up
ip netns exec wandst ip link set lo up
ip netns exec wandst ip link set wan0p up
WAN_IFINDEX=$(cat /sys/class/net/wan0/ifindex)
log "wan0 ifindex=$WAN_IFINDEX"

# --- 3. Load the program, populate the devmap, attach ---------------
# The devmap does NOT self-pin. It used to carry LIBBPF_PIN_BY_NAME,
# and that is exactly what could not work: the kernel forces
# BPF_F_RDONLY_PROG inside dev_map_alloc, libbpf's pin-reuse check
# compares the pinned map's flags (128) against the object's declared
# map_flags (0), and the SECOND zone object of a bundle to declare
# fwl_devmap_<dest> failed to load. fd fills each object's own copy
# instead (see three_zone_gateway_netns.py). This test loads by hand
# and has no fd, so it addresses the map by ID — the loaded program
# holds a reference to it, which is all a devmap ever needs.
bpftool prog loadall "$WORK/lan.bpf.o" "$PIN" \
  || { fail "bpftool loadall"; exit 1; }
log "pinned program:"; ls "$PIN"

DEVMAP_ID=$(bpftool -j map show 2>/dev/null | python3 -c "
import json, sys
ids = [m['id'] for m in json.load(sys.stdin)
       if m.get('name') == 'fwl_devmap_wan']
print(ids[-1] if ids else '')
")
[ -n "$DEVMAP_ID" ] || { fail "no fwl_devmap_wan map after load"; exit 1; }

# devmap value is a __u32 ifindex (4 bytes, little-endian).
b0=$(( WAN_IFINDEX & 0xff )); b1=$(( (WAN_IFINDEX>>8) & 0xff ))
b2=$(( (WAN_IFINDEX>>16) & 0xff )); b3=$(( (WAN_IFINDEX>>24) & 0xff ))
bpftool map update id "$DEVMAP_ID" \
  key 0 0 0 0 value "$b0" "$b1" "$b2" "$b3" \
  || { fail "devmap update"; exit 1; }
log "fwl_devmap_wan[0] = wan0 ($WAN_IFINDEX), map id $DEVMAP_ID"

# Native XDP: firewall on lan0, dummy pass on wan0p (veth redirect
# target needs XDP on the receiving peer for ndo_xdp_xmit).
ip link set dev lan0 xdpdrv pinned "$PIN/fwl_prog" \
  || ip link set dev lan0 xdp pinned "$PIN/fwl_prog" \
  || { fail "attach firewall to lan0"; exit 1; }
ip netns exec wandst ip link set dev wan0p xdpdrv \
  obj "$WORK/xdp_pass.bpf.o" sec xdp \
  || ip netns exec wandst ip link set dev wan0p xdp \
  obj "$WORK/xdp_pass.bpf.o" sec xdp \
  || { fail "attach xdp_pass to wan0p"; exit 1; }
log "attached: firewall->lan0, xdp_pass->wan0p"

# --- 4. Capture on wan0p, send TCP/80 from lansrc -------------------
CAP="$WORK/cap.txt"
ip netns exec wandst timeout 6 tcpdump -i wan0p -c 1 -nn \
  'tcp and dst port 80' > "$CAP" 2>/dev/null &
CAPPID=$!
sleep 1

ip netns exec lansrc env PYTHONPATH="$WS${PYTHONPATH:+:$PYTHONPATH}" python3 "$HERE/send_frame.py" \
  lan0p 'tcp(src_ip="10.0.0.5", dst_ip="93.184.216.34", dst_port=80, syn=true)' \
  || fail "send frame"

# Send a second, non-matching frame (udp) to show it does NOT cross.
ip netns exec lansrc env PYTHONPATH="$WS${PYTHONPATH:+:$PYTHONPATH}" python3 "$HERE/send_frame.py" \
  lan0p 'udp(src_ip="10.0.0.5", dst_ip="93.184.216.34", dst_port=53)' \
  2>/dev/null

wait $CAPPID 2>/dev/null

# --- 5. Verdict ------------------------------------------------------
# tcpdump prints e.g. "IP 10.0.0.5.12345 > 93.184.216.34.80: Flags [S]".
if grep -qE '\.80:' "$CAP"; then
  log "PASS: redirected TCP/80 frame crossed lan0 -> wan0 -> wan0p"
  cat "$CAP" | sed 's/^/[netns]   /'
else
  fail "redirected frame did NOT appear on wan0p"
  log "tcpdump output:"; cat "$CAP" | sed 's/^/[netns]   /'
fi

exit $RC
