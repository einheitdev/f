#!/usr/bin/env bash
# fd-driven system test: the *daemon* (not bpftool) must load a
# multi-zone bundle, attach each zone program, populate the redirect
# devmap, and physically move a frame across zones
# (DAEMON_ZONE_WIRING.md acceptance: "System test driving fd").
#
# This is the integration analogue of zone_redirect_netns.sh: there the
# load/attach/devmap steps were driven by raw bpftool; here the real
# `fd` binary cold-boots a staged bundle through EngineInit ->
# IsMultiZoneBundle -> LoadZoneBundle. A stub fd (or a daemon that
# ignored the zone structure) could not move the frame.
#
# Topology (root ns holds the two firewall-facing veth ends):
#
#   ns lansrc          root ns                         ns wandst
#   ----------         -------                         ---------
#   lan0p  <=========> lan0  --[XDP: from_lan]         wan0p <== capture
#                        |  redirect to wan -> devmap   ^
#                      wan0 --[ndo_xdp_xmit]============/
#
# Requires root. Run on the VM:  sudo bash zone_redirect_fd.sh /path/to/fd
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
WS="$(cd "$HERE/../.." && pwd)"          # the fwl package root
FD="${1:-}"
# `fwl` compiler entry and a python with the fwl package importable.
# Override for a venv install: FWL=~/venv/bin/fwl PYBIN=~/venv/bin/python3
FWL="${FWL:-fwl}"
PYBIN="${PYBIN:-python3}"
WORK="$(mktemp -d)"
BUNDLE="$WORK/bundle"
PIN=/sys/fs/bpf/zfd
SOCK="ipc://$WORK/fd.sock"
RC=0
FDPID=

log() { echo "[fd-test] $*"; }
fail() { echo "[fd-test] FAIL: $*"; RC=1; }

cleanup() {
  [ -n "$FDPID" ] && kill "$FDPID" 2>/dev/null
  wait "$FDPID" 2>/dev/null
  ip link set dev lan0 xdp off 2>/dev/null
  ip link set dev wan0 xdp off 2>/dev/null
  ip netns exec wandst ip link set dev wan0p xdp off 2>/dev/null
  ip link del lan0 2>/dev/null
  ip link del wan0 2>/dev/null
  ip netns del lansrc 2>/dev/null
  ip netns del wandst 2>/dev/null
  rm -rf "$PIN" "$WORK" 2>/dev/null
  # PIN_BY_NAME maps self-pin at the bpffs root; clear them too.
  rm -f /sys/fs/bpf/fwl_devmap_wan /sys/fs/bpf/fwl_devmap_lan \
        /sys/fs/bpf/conntrack 2>/dev/null
}
trap cleanup EXIT
cleanup  # idempotent: clear any prior run
mkdir -p "$WORK"

if [ -z "$FD" ] || [ ! -x "$FD" ]; then
  fail "fd binary not given or not executable: '$FD'"
  echo "usage: sudo bash $0 /path/to/build/fd"
  exit 1
fi

mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf
mkdir -p "$PIN"

# --- 1. Emit + compile the multi-zone bundle via fwl ----------------
# `current/` is the directory fd's cold-boot reads (it is normally a
# symlink maintained by the reload pipeline; a plain dir works too).
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
PYTHONPATH="$WS" "$FWL" compile "$WORK/gw.fw" \
  --bundle "$BUNDLE/current" || { fail "fwl compile --bundle"; exit 1; }

# The bundle must carry real compiled objects (clang available) or fd
# has nothing to load.
if [ ! -f "$BUNDLE/current/lan.bpf.o" ] || \
   [ ! -f "$BUNDLE/current/wan.bpf.o" ]; then
  fail "bundle missing compiled .bpf.o (clang unavailable?)"
  ls -la "$BUNDLE/current" || true
  exit 1
fi
log "bundle compiled:"; ls "$BUNDLE/current" | sed 's/^/[fd-test]   /'
grep -q '"zones"' "$BUNDLE/current/manifest.json" \
  && log "manifest declares zones (multi-zone bundle)"

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

# Veth redirect target needs an XDP program on the receiving peer for
# ndo_xdp_xmit. This is the test rig, not part of the firewall.
clang -O2 -g -target bpf -I/usr/include/x86_64-linux-gnu \
  -I/usr/include/aarch64-linux-gnu \
  -c "$HERE/xdp_pass.bpf.c" -o "$WORK/xdp_pass.bpf.o" \
  || { fail "compile xdp_pass"; exit 1; }
ip netns exec wandst ip link set dev wan0p xdpdrv \
  obj "$WORK/xdp_pass.bpf.o" sec xdp \
  || ip netns exec wandst ip link set dev wan0p xdp \
  obj "$WORK/xdp_pass.bpf.o" sec xdp \
  || { fail "attach xdp_pass to wan0p"; exit 1; }

# --- 3. Cold-boot fd against the staged bundle ----------------------
# fd reads $BUNDLE/current/manifest.json, sees the zones, calls
# LoadZoneBundle: loads lan.bpf.o + wan.bpf.o under $PIN, populates
# fwl_devmap_wan with wan0's ifindex, attaches from_lan->lan0 and
# from_wan->wan0. No bpftool, no manual devmap poke.
log "starting fd (cold-boot multi-zone)..."
"$FD" run --bundle-dir "$BUNDLE" --pin-path "$PIN" \
  --socket "$SOCK" -i lan0 -l debug > "$WORK/fd.log" 2>&1 &
FDPID=$!

# Wait for fd to attach (poll for the XDP program on lan0).
attached=0
for _ in $(seq 1 20); do
  if ip link show lan0 | grep -q xdp; then attached=1; break; fi
  sleep 0.5
done
if [ "$attached" != 1 ]; then
  fail "fd did not attach XDP to lan0 within 10s"
  log "fd.log:"; sed 's/^/[fd-test]   /' "$WORK/fd.log"
  exit 1
fi
log "fd attached XDP to lan0; fd.log highlights:"
grep -iE "zone|devmap|loaded|attach" "$WORK/fd.log" \
  | sed 's/^/[fd-test]   /'

# Confirm fd (not the test) populated the redirect devmap.
DEVMAP=/sys/fs/bpf/fwl_devmap_wan
if [ -e "$DEVMAP" ]; then
  val=$(bpftool map lookup pinned "$DEVMAP" key 0 0 0 0 2>/dev/null)
  log "fwl_devmap_wan[0] = $val"
else
  log "note: fwl_devmap_wan not at bpffs root (pinned under $PIN)"
fi

# --- 4. Capture on wan0p, send TCP/80 from lansrc -------------------
CAP="$WORK/cap.txt"
ip netns exec wandst timeout 6 tcpdump -i wan0p -c 1 -nn \
  'tcp and dst port 80' > "$CAP" 2>/dev/null &
CAPPID=$!
sleep 1

ip netns exec lansrc env PYTHONPATH="$WS" "$PYBIN" "$HERE/send_frame.py" \
  lan0p 'tcp(src_ip="10.0.0.5", dst_ip="93.184.216.34", dst_port=80, syn=true)' \
  || fail "send frame"

# A non-matching UDP frame must NOT cross.
ip netns exec lansrc env PYTHONPATH="$WS" "$PYBIN" "$HERE/send_frame.py" \
  lan0p 'udp(src_ip="10.0.0.5", dst_ip="93.184.216.34", dst_port=53)' \
  2>/dev/null

wait $CAPPID 2>/dev/null

# --- 5. Verdict ------------------------------------------------------
if grep -qE '\.80:' "$CAP"; then
  log "PASS: fd-loaded bundle redirected TCP/80 lan0 -> wan0 -> wan0p"
  sed 's/^/[fd-test]   /' "$CAP"
else
  fail "redirected frame did NOT appear on wan0p"
  log "tcpdump output:"; sed 's/^/[fd-test]   /' "$CAP"
  log "fd.log:"; sed 's/^/[fd-test]   /' "$WORK/fd.log"
fi

exit $RC
