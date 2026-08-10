#!/usr/bin/env bash
# Does a reload to a bundle with no compiled objects silently take
# the whole firewall down?
#
# LoadZoneBundle skips manifest entries whose "object" is null with a
# warning, then returns success. ApplyBundle detaches every interface
# the old bundle held that the new one does not "cover" — and an
# empty program list covers nothing. So the reload path can:
#   - detach every XDP program,
#   - log "reload: multi-zone bundle, 0 zone program(s), atomic swap"
#     and "reload: ok" at INFO,
#   - move the `current` symlink to the empty bundle, so the next
#     reboot cold-boots into no policy either.
#
# Realistic trigger: compiling a bundle on a host without clang. The
# operator sees "ok" in the journal and a healthy systemd unit while
# the box forwards everything.
#
# This test does not assert a fix — it establishes ground truth.
source "$(dirname "$0")/hwlib.sh"
hw::require_root

RULES_BAK=$(mktemp)
cp /etc/f/rules.fw "$RULES_BAK"
cleanup() {
  cp "$RULES_BAK" /etc/f/rules.fw
  rm -rf "$BUNDLE_ROOT"/v-objectless 2>/dev/null || true
  hw::finish
}
trap cleanup EXIT

FW=$(mktemp --suffix=.fw)
cat > "$FW" <<EOF
zone t = [$RECV_IF]

@xdp(t)

count seen if pkt.src_ip == 10.99.140.1
drop if pkt.proto == udp and pkt.dst_port == 6000
default allow
EOF
hw::deploy l8-01 "$FW"

# Confirm the policy is live before we break it.
hw::sniff_start 5
hw::send 50 'udp(src_ip="10.99.140.1", dst_port=6000)'
sleep 1
hw::sniff_wait
assert_eq "before: drop rule enforced" \
  "$(hw::sniff_get udp:10.99.140.1:6000)" 0

XDP_BEFORE=$(ip -d link show "$RECV_IF" | grep -c " xdp" || true)
CURRENT_BEFORE=$(readlink "$BUNDLE_ROOT/current")

# Build a bundle whose manifest declares a zone but no object — what
# a clang-less compile host produces.
VER=$BUNDLE_ROOT/v-objectless
rm -rf "$VER"; mkdir -p "$VER"
cat > "$VER/manifest.json" <<EOF
{
  "version": "0.4",
  "zones": [{"name": "t", "interfaces": ["$RECV_IF"]}],
  "programs": [
    {"zone": "t", "source": "t.bpf.c", "object": null,
     "redirects_to": []}
  ],
  "shared_pinned_maps": ["conntrack"]
}
EOF

# Drive it through the reload path exactly as the watcher would.
ln -sfT "$VER" "$BUNDLE_ROOT/current"
systemctl reload-or-restart fd 2>/dev/null || systemctl restart fd
sleep 4

FD_STATE=$(systemctl is-active fd || true)
XDP_AFTER=$(ip -d link show "$RECV_IF" | grep -c " xdp" || true)

log "fd after objectless bundle : $FD_STATE"
log "XDP attached on $RECV_IF    : before=$XDP_BEFORE after=$XDP_AFTER"

if [ "$FD_STATE" = "active" ] && [ "$XDP_AFTER" -eq 0 ]; then
  fail "SILENT FIREWALL LOSS: a bundle with no compiled objects left \
fd active and reporting healthy while every XDP program was detached \
— the box now forwards all traffic. Journal says 'ok'. An operator \
polling systemd or fctl sees nothing wrong."
elif [ "$FD_STATE" != "active" ]; then
  pass "objectless bundle refused: fd did not stay up ($FD_STATE), \
which is loud and therefore safe"
else
  pass "objectless bundle did not detach the datapath (XDP still \
attached: $XDP_AFTER)"
fi

# Whatever happened, prove it on the wire rather than trusting state.
ip link set dev "$RECV_IF" promisc on 2>/dev/null || true
hw::sniff_start 5
hw::send 50 'udp(src_ip="10.99.140.1", dst_port=6000)'
sleep 1
hw::sniff_wait
LEAK=$(hw::sniff_get udp:10.99.140.1:6000)
if [ "$LEAK" -gt 0 ]; then
  fail "wire confirms the loss: $LEAK/50 frames that the previous \
policy dropped now pass"
else
  pass "wire: previously-dropped traffic is still blocked ($LEAK/50)"
fi

# Did `current` get moved to the broken bundle (survives reboot)?
CURRENT_AFTER=$(readlink "$BUNDLE_ROOT/current")
log "current: $CURRENT_BEFORE -> $CURRENT_AFTER"
