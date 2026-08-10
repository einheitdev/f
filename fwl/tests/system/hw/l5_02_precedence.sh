#!/usr/bin/env bash
# Operator precedence on the wire: `and` binds tighter than `or`.
#
# FWL_V01_SPEC:184-190 calls this out as the trap readers fall into.
# The two files below differ only in parentheses; the difference is
# observable as a different verdict for the same frame, which is the
# only way to prove the compiler agrees with the spec rather than
# with the reader's intuition.
source "$(dirname "$0")/hwlib.sh"
hw::require_root
trap hw::finish EXIT

run_variant() {
  local tag="$1" cond="$2" var="$3"
  local fw
  fw=$(mktemp --suffix=.fw)
  cat > "$fw" <<EOF
zone t = [$RECV_IF]

@xdp(t)

allow if $cond
default drop
EOF
  hw::deploy "$tag" "$fw"
  hw::sniff_start 8
  hw::send 50 'tcp(src_ip="10.99.151.1", dst_port=80)'
  hw::send 50 'udp(src_ip="10.99.151.2", dst_port=443)'
  hw::send 50 'udp(src_ip="10.99.151.3", dst_port=53)'
  sleep 1
  hw::sniff_wait
  eval "${var}_TCP80=\$(hw::sniff_get tcp:10.99.151.1:80)"
  eval "${var}_UDP443=\$(hw::sniff_get udp:10.99.151.2:443)"
  eval "${var}_UDP53=\$(hw::sniff_get udp:10.99.151.3:53)"
}

# A: no parens -> tcp OR (udp AND 443)
run_variant l5-02a \
  "pkt.proto == tcp or pkt.proto == udp and pkt.dst_port == 443" A
# B: parens   -> (tcp OR udp) AND 443
run_variant l5-02b \
  "(pkt.proto == tcp or pkt.proto == udp) and pkt.dst_port == 443" B

log "unparenthesised: tcp80=$A_TCP80 udp443=$A_UDP443 udp53=$A_UDP53"
log "parenthesised  : tcp80=$B_TCP80 udp443=$B_UDP443 udp53=$B_UDP53"

# A: tcp/80 allowed (matches the bare `tcp` branch).
assert_eq "no parens: TCP/80 allowed (and binds tighter)" \
  "$A_TCP80" 50
assert_eq "no parens: UDP/443 allowed" "$A_UDP443" 50
assert_eq "no parens: UDP/53 dropped" "$A_UDP53" 0
# B: tcp/80 dropped — the port test now applies to both protocols.
assert_eq "parens: TCP/80 DROPPED (port test applies to both)" \
  "$B_TCP80" 0
assert_eq "parens: UDP/443 allowed" "$B_UDP443" 50
assert_eq "parens: UDP/53 dropped" "$B_UDP53" 0
