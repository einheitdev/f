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
CFG_BAK=$(mktemp)
cp /etc/f/fd.yaml "$CFG_BAK"
cleanup() {
  cp "$RULES_BAK" /etc/f/rules.fw
  cp "$CFG_BAK" /etc/f/fd.yaml
  rm -f /usr/local/bin/fwl-objectless
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
hw::journal_mark
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

# NOTE ON SCOPE: this drives the COLD-BOOT path (a restart onto the
# staged bundle). If the bundle is refused there, the process exits
# and the port is genuinely unprotected until an operator fixes the
# symlink — that is unavoidable, and precisely why the refusal must
# be loud. What must never happen is the third state: fd alive,
# reporting healthy, firewall gone.
#
# The reload path is where the fix protects traffic: LoadZoneBundle
# fails, ApplyBundle propagates the error, and the previously
# attached bundle keeps running. That half is covered below.
if hw::journal_since | grep -q "no loadable zone programs"; then
  pass "the refusal is diagnosable: the journal names the cause \
(no loadable zone programs) rather than a generic load error"
else
  fail "no journal line explains why the bundle was refused — an \
operator has to guess"
fi

# Did `current` get moved to the broken bundle (survives reboot)?
CURRENT_AFTER=$(readlink "$BUNDLE_ROOT/current")
log "current: $CURRENT_BEFORE -> $CURRENT_AFTER"

# ---------- the reload path: running traffic must survive ----------
# A watcher reload recompiles from source, so staging a bundle by
# hand never reaches it. The faithful trigger is a COMPILER that
# emits an unusable bundle — exactly what a host without clang
# produces: manifest written, every "object" null. Point the
# watcher at such a compiler and let it fire.
FAKE=/usr/local/bin/fwl-objectless
cat > "$FAKE" <<'WRAP'
#!/bin/sh
# Emit a manifest with no compiled objects, mimicking a compile host
# that lacks clang. Args: compile <src> --bundle <dir> [--geoip f]
DIR=""
while [ $# -gt 0 ]; do
  case "$1" in --bundle) DIR="$2"; shift 2;; *) shift;; esac
done
[ -n "$DIR" ] || exit 1
mkdir -p "$DIR"
cat > "$DIR/manifest.json" <<JSON
{"version":"0.4",
 "zones":[{"name":"t","interfaces":["IFACE"]}],
 "programs":[{"zone":"t","source":"t.bpf.c","object":null,
              "redirects_to":[]}],
 "shared_pinned_maps":["conntrack"]}
JSON
exit 0
WRAP
sed -i "s/IFACE/$RECV_IF/" "$FAKE"
chmod +x "$FAKE"

hw::deploy l8-01b "$FW"
cp "$FW" /etc/f/rules.fw
hw::sniff_start 6
hw::send 50 'udp(src_ip="10.99.140.1", dst_port=6000)'
sleep 1
hw::sniff_wait
assert_eq "reload phase: policy enforcing before the bad adopt" \
  "$(hw::sniff_get udp:10.99.140.1:6000)" 0
PROG_BEFORE=$(ip -d link show "$RECV_IF" \
  | grep -o "prog/xdp id [0-9]*" | awk '{print $3}')

# Swap the watcher's compiler for the broken one, then trigger it.
sed -i "s|^  fwl: .*|  fwl: $FAKE|" /etc/f/fd.yaml
systemctl restart fd
sleep 4
touch /etc/f/rules.fw
sleep 10

PROG_AFTER=$(ip -d link show "$RECV_IF" \
  | grep -o "prog/xdp id [0-9]*" | awk '{print $3}')
log "reload phase: prog id $PROG_BEFORE -> ${PROG_AFTER:-none}"
$PY "$HERE/sendmany.py" --probe "$SEND_IF" "$RECV_IF" 45 >/dev/null \
  2>&1 || true
hw::teach_fdb
hw::sniff_start 6
hw::send 50 'udp(src_ip="10.99.140.1", dst_port=6000)'
sleep 1
hw::sniff_wait
RELOAD_LEAK=$(hw::sniff_get udp:10.99.140.1:6000)
if [ "$RELOAD_LEAK" -eq 0 ] && [ -n "$PROG_AFTER" ]; then
  pass "reload path contained the unusable bundle: the running \
policy kept enforcing (0/50 leaked) and its program stayed attached"
else
  fail "reload path lost the policy: $RELOAD_LEAK/50 frames leaked, \
prog id now '${PROG_AFTER:-none}' — adopting an unusable bundle must \
leave the previous one running"
fi
rm -f "$FAKE"
