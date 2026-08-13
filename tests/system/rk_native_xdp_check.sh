#!/usr/bin/env bash
# RK3588 hardware check: does XDP attach in NATIVE (driver) mode on the
# RTL8125 2.5GbE ports? This is the gating question for whether zones +
# NAT run in native XDP on real hardware (generic/SKB mode is a fallback
# that defeats the point). Run ON the board (needs root + bpftool/clang).
#
# It (1) finds the RTL8125 interfaces by driver, (2) tries a forced
# native (xdpdrv) attach of a trivial pass program, (3) falls back to
# generic and reports which mode the driver actually supports, and
# (4) attempts an XDP_REDIRECT between the two 2.5G ports.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PASS_C="$here/lib/xdp_pass.bpf.c"
PASS_O=/tmp/xdp_pass.bpf.o
REDIR_C=/tmp/xdp_redir.bpf.c
REDIR_O=/tmp/xdp_redir.bpf.o

echo "=== RTL8125 / r8169 interfaces ==="
mapfile -t IFS8125 < <(
  for d in /sys/class/net/*; do
    n="$(basename "$d")"; [ "$n" = "lo" ] && continue
    drv="$(ethtool -i "$n" 2>/dev/null | awk '/^driver:/{print $2}')"
    if [ "$drv" = "r8169" ] || [ "$drv" = "r8125" ]; then
      spd="$(cat "$d/speed" 2>/dev/null || echo '?')"
      echo "  $n driver=$drv speed=$spd"
      echo "$n"
    fi
  done | awk '/^[a-z]/{print $1}' | grep -vE 'driver=' || true
)
# The awk above is finicky across shells; re-derive cleanly:
mapfile -t IFS8125 < <(for d in /sys/class/net/*; do n="$(basename "$d")";
  [ "$n" = "lo" ] && continue
  drv="$(ethtool -i "$n" 2>/dev/null | awk -F': ' '/^driver:/{print $2}')"
  [ "$drv" = "r8169" ] || [ "$drv" = "r8125" ] && echo "$n"; done)
echo "detected: ${IFS8125[*]:-none}"
[ "${#IFS8125[@]}" -ge 1 ] || { echo "no RTL8125 ports found"; exit 1; }

# Build the pass program.
arch="$(uname -m)"
clang -O2 -g -target bpf -D__TARGET_ARCH_arm64 \
  -I"/usr/include/${arch}-linux-gnu" -c "$PASS_C" -o "$PASS_O" \
  || { echo "clang build failed"; exit 1; }

IF0="${IFS8125[0]}"
echo
echo "=== native (xdpdrv) attach on $IF0 ==="
if ip link set "$IF0" xdpdrv obj "$PASS_O" sec xdp 2>/tmp/xdperr; then
  mode="$(ip -d link show "$IF0" | grep -oE 'xdp(generic|drv)?' | head -1)"
  echo "RESULT: NATIVE XDP SUPPORTED on $IF0 (mode=$mode)"
  ip link set "$IF0" xdp off 2>/dev/null
  NATIVE=1
else
  echo "native attach failed: $(cat /tmp/xdperr)"
  echo "--- trying generic (xdpgeneric) ---"
  if ip link set "$IF0" xdpgeneric obj "$PASS_O" sec xdp 2>/tmp/xdperr; then
    echo "RESULT: only GENERIC XDP on $IF0 (native NOT supported by driver)"
    ip link set "$IF0" xdp off 2>/dev/null
  else
    echo "RESULT: XDP attach failed entirely: $(cat /tmp/xdperr)"
  fi
  NATIVE=0
fi

# XDP_REDIRECT between the two 2.5G ports (only meaningful with two).
if [ "${#IFS8125[@]}" -ge 2 ] && [ "${NATIVE:-0}" = "1" ]; then
  IF1="${IFS8125[1]}"
  echo
  echo "=== XDP_REDIRECT $IF0 -> $IF1 (native) ==="
  cat > "$REDIR_C" <<EOF
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
struct { __uint(type, BPF_MAP_TYPE_DEVMAP); __uint(key_size,4);
  __uint(value_size,4); __uint(max_entries,1); } tx SEC(".maps");
SEC("xdp") int redir(struct xdp_md *ctx){ return bpf_redirect_map(&tx,0,0); }
char _license[] SEC("license") = "GPL";
EOF
  clang -O2 -g -target bpf -D__TARGET_ARCH_arm64 \
    -I"/usr/include/${arch}-linux-gnu" -c "$REDIR_C" -o "$REDIR_O" 2>/dev/null
  if ip link set "$IF0" xdpdrv obj "$REDIR_O" sec xdp 2>/tmp/xdperr; then
    echo "RESULT: native XDP_REDIRECT program attached to $IF0 (egress $IF1)"
    echo "  (devmap egress ifindex must be populated by fd/loader at runtime)"
    ip link set "$IF0" xdp off 2>/dev/null
  else
    echo "RESULT: native redirect attach failed: $(cat /tmp/xdperr)"
  fi
fi
echo
echo "=== kernel / driver info ==="
uname -r
ethtool -i "$IF0" 2>/dev/null | grep -E '^(driver|version|firmware)'
