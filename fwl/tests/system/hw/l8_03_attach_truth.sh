#!/usr/bin/env bash
# Does `fctl status` tell the truth about XDP attachment?
#
# The status serializer emits {"xdp_attached", true} as a literal for
# every tracked interface — it never queries the kernel. Nothing in
# the daemon re-verifies attachment either. So if a program is
# detached out from under fd (another tool, an `ip link set xdp off`,
# an interface flap), the daemon keeps reporting a healthy firewall
# while traffic flows unfiltered.
#
# Ground truth here is the kernel (`ip -d link show`) and the wire.
source "$(dirname "$0")/hwlib.sh"
hw::require_root
trap hw::finish EXIT

FW=$(mktemp --suffix=.fw)
cat > "$FW" <<EOF
zone t = [$RECV_IF]

@xdp(t)

count seen if pkt.src_ip == 10.99.142.1
drop if pkt.proto == udp and pkt.dst_port == 6100
default allow
EOF
hw::deploy l8-03 "$FW"

status_says() {
  fctl status 2>/dev/null | grep -c '"xdp_attached":true' || true
}
kernel_says() {
  ip -d link show "$RECV_IF" | grep -c " xdp" || true
}

assert_eq "before: kernel confirms XDP attached" "$(kernel_says)" 1
S_BEFORE=$(status_says)
log "fctl status xdp_attached:true count = $S_BEFORE"

hw::sniff_start 5
hw::send 50 'udp(src_ip="10.99.142.1", dst_port=6100)'
sleep 1
hw::sniff_wait
assert_eq "before: policy enforced on wire" \
  "$(hw::sniff_get udp:10.99.142.1:6100)" 0

# Detach behind the daemon's back — exactly what a stray tool or a
# careless operator does.
ip link set dev "$RECV_IF" xdp off
sleep 1
K_AFTER=$(kernel_says)
S_AFTER=$(status_says)
assert_eq "kernel: program really is gone" "$K_AFTER" 0

ip link set dev "$RECV_IF" promisc on
$PY "$HERE/sendmany.py" --probe "$SEND_IF" "$RECV_IF" 45 >/dev/null \
  || true
hw::sniff_start 6
hw::send 50 'udp(src_ip="10.99.142.1", dst_port=6100)'
sleep 1
hw::sniff_wait
LEAK=$(hw::sniff_get udp:10.99.142.1:6100)

log "after external detach: kernel=$K_AFTER fctl_true_count=$S_AFTER \
wire_leak=$LEAK/50"

if [ "$LEAK" -gt 0 ] && [ "$S_AFTER" -ge "$S_BEFORE" ]; then
  fail "STATUS LIES ABOUT ATTACHMENT: the program is detached and \
$LEAK/50 previously-dropped frames now pass, yet fctl status still \
reports xdp_attached:true for every interface ($S_AFTER). The field \
is a hard-coded literal and nothing re-verifies or re-attaches. Any \
health check built on fctl status cannot detect a detached firewall \
— use 'ip -d link show' or bpftool as ground truth."
else
  pass "status tracked the detach (fctl true-count $S_BEFORE -> \
$S_AFTER, wire leak $LEAK/50)"
fi

# Restore for the next test.
systemctl restart fd
sleep 3
