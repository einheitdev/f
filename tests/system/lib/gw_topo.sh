#!/usr/bin/env bash
# Gateway netns topology for system tests.
#
# Builds a two-zone gateway around a real fd + real XDP:
#
#   lanhost(10.0.0.2) ==lan0p==|==lan0(10.0.0.1)   [main ns: fd XDP ingress]
#                                    fd (masq + redirect)
#   wanhost(203.0.113.2)==wan0p==|==wan0(203.0.113.1) [main ns: fd XDP egress]
#
# wan0's address (203.0.113.1) is the masquerade source the daemon must
# program into fwl_nat_cfg. Traffic is injected/captured with scapy on
# the peer veths inside the netns, so ARP/routing never interfere.
#
# Usage:
#   gw_topo.sh up <bundle_dir>   # stage bundle, bring up topo, start fd
#   gw_topo.sh down              # tear everything down
#   gw_topo.sh macs              # print lan0/wan0 MACs (for scapy)
set -uo pipefail

PIN="${FT_PIN:-/sys/fs/bpf/ftest}"
SOCK="${FT_SOCK:-ipc:///tmp/fdtest.sock}"
ROOT="${FT_ROOT:-/tmp/ftest-gwroot}"
FD="${FT_FD:-$HOME/f-appliance/f/build/fd}"
FDLOG="${FT_FDLOG:-/tmp/ftest-fd.log}"
FDPID="${FT_FDPID:-/tmp/ftest-fd.pid}"

WAN_ADDR=203.0.113.1
LAN_ADDR=10.0.0.1

down() {
  # Stop any packaged fd first: it shares the /tmp/fd.pid lock and the
  # default pin root, and would otherwise attach to enp1s0 and collide
  # with the isolated test instance.
  systemctl stop fd.service >/dev/null 2>&1 || true
  if [ -f "$FDPID" ]; then
    kill "$(cat "$FDPID")" 2>/dev/null || true
    rm -f "$FDPID"
  fi
  # Fallback: match the exact test invocation ("<fd> -c"), never the
  # wrapper process whose cmdline merely mentions the fd path.
  pkill -f "$FD -c" 2>/dev/null || true
  sleep 0.3
  rm -f /tmp/fd.pid 2>/dev/null || true
  ip netns del lanhost 2>/dev/null || true
  ip netns del wanhost 2>/dev/null || true
  ip link del lan0 2>/dev/null || true
  ip link del wan0 2>/dev/null || true
  rm -rf "$ROOT" 2>/dev/null || true
  # Best-effort unpin of the isolated test pin root and the packaged
  # default (fd falls back to it when a config is missing).
  rm -rf "$PIN" /sys/fs/bpf/f 2>/dev/null || true
}

up() {
  local bundle="$1"
  down
  set -e
  ip netns add lanhost
  ip netns add wanhost
  ip link add lan0 type veth peer name lan0p
  ip link add wan0 type veth peer name wan0p
  ip link set lan0p netns lanhost
  ip link set wan0p netns wanhost

  ip addr add "$LAN_ADDR/24" dev lan0
  ip addr add "$WAN_ADDR/24" dev wan0
  ip link set lan0 up
  ip link set wan0 up

  ip -n lanhost addr add 10.0.0.2/24 dev lan0p
  ip -n lanhost link set lan0p up
  ip -n lanhost link set lo up
  ip -n wanhost addr add 203.0.113.2/24 dev wan0p
  ip -n wanhost link set wan0p up
  ip -n wanhost link set lo up

  # XDP_REDIRECT into a veth is only delivered when the target veth has
  # an XDP program; the peers (lan0p/wan0p) therefore need an xdp-pass
  # stub or redirected frames are dropped before reaching the stack.
  local here; here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  local pass_o="$here/xdp_pass.bpf.o"
  if [ ! -f "$pass_o" ]; then
    local arch; arch="$(uname -m)"
    clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
      -I"/usr/include/${arch}-linux-gnu" \
      -c "$here/xdp_pass.bpf.c" -o "$pass_o"
  fi
  ip -n lanhost link set lan0p xdpdrv obj "$pass_o" sec xdp
  ip -n wanhost link set wan0p xdpdrv obj "$pass_o" sec xdp

  mkdir -p "$ROOT"
  ln -sfn "$bundle" "$ROOT/current"
  mkdir -p "$PIN"

  # Explicit test config so fd does not fall back to /etc/f/fd.yaml
  # (which would force the packaged pin path + enp1s0). Zone bundles
  # attach per-manifest, so no interface list is needed here.
  # When FT_SOURCE names a .fw file, configure the reload pipeline so
  # kReloadProg recompiles it into $ROOT and hot-swaps. compiled_dir is
  # $ROOT so the reload updates the same `current` cold-boot reads.
  {
    printf 'pin_path: %s\nsocket: %s\nlog_level: debug\n' "$PIN" "$SOCK"
    printf 'watch:\n  enabled: false\n'
    if [ -n "${FT_SOURCE:-}" ]; then
      printf '  source: %s\n  compiled_dir: %s\n  fwl: %s\n' \
        "$FT_SOURCE" "$ROOT" "${FT_FWL:-$HOME/.local/bin/fwl}"
    fi
  } >"$ROOT/fd.yaml"

  "$FD" -c "$ROOT/fd.yaml" --bundle-dir "$ROOT" run >"$FDLOG" 2>&1 &
  echo $! >"$FDPID"
  # Wait for both zone programs to attach.
  local i
  for i in $(seq 1 40); do
    if grep -q "zone program(s)" "$FDLOG" 2>/dev/null; then break; fi
    sleep 0.25
  done
  set +e
}

macs() {
  echo "lan0 $(cat /sys/class/net/lan0/address)"
  echo "wan0 $(cat /sys/class/net/wan0/address)"
}

case "${1:-}" in
  up) up "${2:?usage: gw_topo.sh up <bundle_dir>}";;
  down) down;;
  macs) macs;;
  *) echo "usage: gw_topo.sh {up <bundle>|down|macs}"; exit 2;;
esac
