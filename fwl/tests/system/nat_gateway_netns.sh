#!/usr/bin/env bash
# End-to-end NAT gateway proof on a real kernel (the Phase 5 acceptance
# gate). A TCP frame from the LAN host crosses the firewall, exits the
# WAN interface with its source rewritten to the WAN address AND valid
# IP + TCP checksums; a reply to that WAN address:port is de-NAT'd and
# physically reaches the original LAN host. A stub (or a wrong checksum)
# cannot pass this — it is observed with tcpdump + scapy on real veths.
#
# KNOWN LIMIT OF THIS WITNESS (2026-08-14). tcpdump is promiscuous, so
# this proves the frame reached the peer's cable and NOT that the peer's
# stack would accept it. A frame addressed to the wrong destination MAC
# is captured here and dropped by a real host as PACKET_OTHERHOST — which
# is exactly the defect `redirect` carried until it learned to resolve
# its next hop (v0.4 6.3), and exactly why this test and eleven hardware
# scenarios all stayed green through it. The acceptance question is asked
# on the rig instead, with real non-promiscuous sockets either side:
# tests/system/hw/l2_03_masquerade.sh. Bringing that witness down here
# would need addresses on lan0/wan0 in the root namespace plus
# ip_forward, and is worth doing: it would make the routed path
# CI-testable, which today it is not. DONE — three_zone_gateway_netns.py
# in this directory is that witness, with real non-promiscuous sockets
# either side and ip_forward=0 as its control.
#
#   ns lansrc                 root ns                    ns wandst
#   --------                  -------                    --------
#   lan0p(10.0.0.5) <=======> lan0 [XDP from_lan]        wan0p(EXT) <= cap
#                               | snat->WANIP             ^
#                             wan0 [XDP from_wan] ========/  (redirect)
#   cap <= lan0p <============ (de-NAT reply -> 10.0.0.5, redirect to lan)
#
# Requires root. Run on the VM:
#   sudo env FWL=~/venv/bin/fwl PYBIN=~/venv/bin/python3 \
#       bash nat_gateway_netns.sh /path/to/build/fd
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
WS="$(cd "$HERE/../.." && pwd)"
FD="${1:-}"
FWL="${FWL:-fwl}"; PYBIN="${PYBIN:-python3}"
WORK="$(mktemp -d)"; BUNDLE="$WORK/bundle"; PIN=/sys/fs/bpf/znat
SOCK="ipc://$WORK/fd.sock"; RC=0; FDPID=
WANIP=198.51.100.9
EXT=93.184.216.34
LANIP=10.0.0.5

log(){ echo "[nat-gw] $*"; }
fail(){ echo "[nat-gw] FAIL: $*"; RC=1; }
cleanup(){
  [ -n "$FDPID" ] && kill "$FDPID" 2>/dev/null; wait "$FDPID" 2>/dev/null
  for d in lan0 wan0; do ip link set dev $d xdp off 2>/dev/null; done
  ip netns exec lansrc ip link set dev lan0p xdp off 2>/dev/null
  ip netns exec wandst ip link set dev wan0p xdp off 2>/dev/null
  ip link del lan0 2>/dev/null; ip link del wan0 2>/dev/null
  ip netns del lansrc 2>/dev/null; ip netns del wandst 2>/dev/null
  rm -rf "$PIN" "$WORK" 2>/dev/null
  # The devmaps are no longer pinned (the kernel's BPF_F_RDONLY_PROG
  # makes a devmap pin unreusable, so the second zone object of a
  # bundle could not load); a run from before that change may still
  # have left one at the bpffs root.
  rm -f /sys/fs/bpf/fwl_devmap_wan /sys/fs/bpf/fwl_devmap_lan \
        /sys/fs/bpf/fwl_nat /sys/fs/bpf/fwl_nat_cfg /sys/fs/bpf/conntrack \
        2>/dev/null
}
trap cleanup EXIT
cleanup; mkdir -p "$WORK"
[ -x "$FD" ] || { fail "fd binary not executable: '$FD'"; exit 1; }
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf
mkdir -p "$PIN"

# --- 1. The gateway bundle: LAN snats + redirects out; WAN de-NATs
#        (automatic, pre-rule) and redirects the reply back to LAN. ---
cat > "$WORK/gw.fw" <<EOF
zone wan = [wan0]
zone lan = [lan0]
@xdp(lan)
snat to $WANIP if pkt.proto == tcp
redirect to wan
@xdp(wan)
redirect to lan
EOF
PYTHONPATH="$WS${PYTHONPATH:+:$PYTHONPATH}" "$FWL" compile "$WORK/gw.fw" --bundle "$BUNDLE/current" \
  || { fail "fwl compile"; exit 1; }
[ -f "$BUNDLE/current/lan.bpf.o" ] && [ -f "$BUNDLE/current/wan.bpf.o" ] \
  || { fail "objects missing"; ls -la "$BUNDLE/current"; exit 1; }
grep -q fwl_nat "$BUNDLE/current/lan.bpf.c" && log "lan program carries NAT"
grep -q fwl_nat_denat "$BUNDLE/current/wan.bpf.c" \
  && log "wan program carries de-NAT pass"

# --- 2. Topology --------------------------------------------------
ip netns add lansrc; ip netns add wandst
ip link add lan0 type veth peer name lan0p
ip link add wan0 type veth peer name wan0p
ip link set lan0p netns lansrc; ip link set wan0p netns wandst
ip link set lan0 up; ip link set wan0 up
ip netns exec lansrc ip link set lo up
ip netns exec lansrc ip link set lan0p up
ip netns exec lansrc ip addr add $LANIP/24 dev lan0p
ip netns exec wandst ip link set lo up
ip netns exec wandst ip link set wan0p up
ip netns exec wandst ip addr add $EXT/24 dev wan0p
# Redirect target peers need an XDP program for veth ndo_xdp_xmit.
clang -O2 -g -target bpf -I/usr/include/x86_64-linux-gnu \
  -I/usr/include/aarch64-linux-gnu -c "$HERE/xdp_pass.bpf.c" \
  -o "$WORK/xp.bpf.o" || { fail "compile xdp_pass"; exit 1; }
ip netns exec wandst ip link set dev wan0p xdpdrv obj "$WORK/xp.bpf.o" \
  sec xdp || ip netns exec wandst ip link set dev wan0p xdp \
  obj "$WORK/xp.bpf.o" sec xdp || { fail "xdp_pass wan0p"; exit 1; }
ip netns exec lansrc ip link set dev lan0p xdpdrv obj "$WORK/xp.bpf.o" \
  sec xdp || ip netns exec lansrc ip link set dev lan0p xdp \
  obj "$WORK/xp.bpf.o" sec xdp || { fail "xdp_pass lan0p"; exit 1; }

# --- 3. Cold-boot fd against the bundle ---------------------------
"$FD" --bundle-dir "$BUNDLE" --pin-path "$PIN" --socket "$SOCK" \
  -l debug run > "$WORK/fd.log" 2>&1 &
FDPID=$!
ok=0; for _ in $(seq 1 20); do
  ip link show lan0 | grep -q xdp && ip link show wan0 | grep -q xdp \
    && { ok=1; break; }; sleep 0.5; done
[ "$ok" = 1 ] || { fail "fd did not attach both zones"; \
  sed 's/^/[nat-gw]   /' "$WORK/fd.log"; exit 1; }
log "fd attached both zone programs:"
grep -iE "loaded zone|devmap" "$WORK/fd.log" | sed 's/^/[nat-gw]   /'

# --- 4. Forward: LAN host -> EXT:80, capture on wan0p -------------
FCAP="$WORK/fwd.pcap"
ip netns exec wandst timeout 6 tcpdump -i wan0p -c1 -w "$FCAP" \
  'tcp and dst port 80' 2>/dev/null &
fpid=$!; sleep 1
ip netns exec lansrc env PYTHONPATH="$WS${PYTHONPATH:+:$PYTHONPATH}" "$PYBIN" "$HERE/send_scapy.py" \
  lan0p "$LANIP" "$EXT" 40000 80 S || fail "send forward frame"
wait $fpid 2>/dev/null

# --- 5. Reply: EXT:80 -> WANIP:40000, capture on lan0p -----------
RCAP="$WORK/ret.pcap"
ip netns exec lansrc timeout 6 tcpdump -i lan0p -c1 -w "$RCAP" \
  'tcp and src port 80' 2>/dev/null &
rpid=$!; sleep 1
ip netns exec wandst env PYTHONPATH="$WS${PYTHONPATH:+:$PYTHONPATH}" "$PYBIN" "$HERE/send_scapy.py" \
  wan0p "$EXT" "$WANIP" 80 40000 SA || fail "send reply frame"
wait $rpid 2>/dev/null

# --- 6. Verdict: scapy validates rewrite + checksums -------------
"$PYBIN" - "$FCAP" "$RCAP" "$WANIP" "$EXT" "$LANIP" <<'PY'
import sys
from scapy.all import rdpcap, IP, TCP
fcap, rcap, wanip, ext, lanip = sys.argv[1:6]
rc = 0


def csum_ok(p):
    raw = bytes(p[IP])
    p2 = IP(raw); del p2.chksum
    if p2.haslayer(TCP):
        del p2[TCP].chksum
    p2 = IP(bytes(p2))
    a = p[IP].chksum == p2.chksum
    b = (not p.haslayer(TCP)) or p[TCP].chksum == p2[TCP].chksum
    return a and b


try:
    f = rdpcap(fcap)
except Exception:
    f = []
if not f:
    print("[nat-gw] FAIL: no forward frame captured on wan0p"); rc = 1
else:
    p = f[0]
    src, dst = p[IP].src, p[IP].dst
    ok = src == wanip and dst == ext and csum_ok(p)
    print(f"[nat-gw] forward: src={src} dst={dst} csum={'OK' if csum_ok(p) else 'BAD'} "
          f"-> {'PASS' if ok else 'FAIL'}")
    rc |= 0 if ok else 1

try:
    r = rdpcap(rcap)
except Exception:
    r = []
if not r:
    print("[nat-gw] FAIL: no reply frame reached lan0p"); rc = 1
else:
    p = r[0]
    src, dst = p[IP].src, p[IP].dst
    ok = dst == lanip and src == ext and csum_ok(p)
    print(f"[nat-gw] reply:   src={src} dst={dst} csum={'OK' if csum_ok(p) else 'BAD'} "
          f"-> {'PASS' if ok else 'FAIL'}")
    rc |= 0 if ok else 1

print("[nat-gw] PASS: gateway SNAT + de-NAT verified end to end"
      if rc == 0 else "[nat-gw] FAIL")
sys.exit(rc)
PY
[ $? -ne 0 ] && RC=1
exit $RC
