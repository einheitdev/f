#!/usr/bin/env bash
# START THE NAT/MASQUERADE SOAK. On the rig:
#
#   bash /opt/fwl/tests/system/hw/natsoak_start.sh [hours]
#
# The 48 h soak of 2026-08-08 contained no NAT. This one is the same
# discipline pointed at the code path the office deployment actually
# depends on: masquerade out, de-NAT back, DNAT in, with a wire
# assertion in every sample rather than counters alone.
#
# What it does:
#   1. Deploys natsoak_policy.fw as a two-zone bundle through the
#      normal path, with a transient address on the wan port for
#      masquerade to resolve.
#   2. Installs the long-lived NAT mapping the samples will keep
#      checking.
#   3. Starts the traffic generator (f-natsoak-traffic) and a 1-minute
#      sampler (f-natsoak-sample) writing /var/log/f/natsoak.jsonl.
#
# Watch:  bash natsoak_status.sh     Stop:  bash natsoak_stop.sh
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
export PYTHONPATH=/opt/fwl:/opt/fwl-deps
WAN_IF=enp1s0f2
MASQ_ADDR=10.99.200.2

if systemctl is-active --quiet f-natsoak-traffic; then
  echo "NAT soak already running"; exit 1
fi

echo "== wan-side address for masquerade to resolve =="
ip addr add "$MASQ_ADDR/24" dev "$WAN_IF" 2>/dev/null || true

echo "== deploying the NAT soak policy =="
V=/usr/share/f/compiled/v-natsoak
rm -rf "$V"
fwl compile --bundle "$V" "$HERE/natsoak_policy.fw"
systemctl stop fd
# Start from a clean pin root so the fwl_nat slope measured over the
# run is this run's, not a leftover from a ceiling probe.
rm -f /sys/fs/bpf/f/fwl_* /sys/fs/bpf/f/conntrack
ln -sfT "$V" /usr/share/f/compiled/current
cp "$HERE/natsoak_policy.fw" /etc/f/rules.fw
systemctl start fd
sleep 3
fctl status | grep -q '"xdp_attached":true' \
  || { echo "fd did not attach"; exit 1; }
journalctl -u fd -n 20 --no-pager | grep -q "masquerade address" \
  || { echo "fd did not resolve a masquerade address"; exit 1; }

ip link set dev enp1s0f1 promisc on
ethtool -K enp1s0f1 rxvlan off 2>/dev/null || true
python3 "$HERE/sendmany.py" --probe enp1s0f0 enp1s0f1 45
python3 "$HERE/sendmany.py" --teach enp1s0f1 enp1s0f0

echo "== installing the long-lived NAT mapping =="
python3 "$HERE/natsoak_probe.py" --install enp1s0f0

echo "== starting traffic + sampler =="
mkdir -p /var/log/f
: > /var/log/f/natsoak.jsonl
systemd-run --unit=f-natsoak-traffic --property=Restart=always \
  --setenv=PYTHONPATH=/opt/fwl:/opt/fwl-deps \
  python3 "$HERE/natsoak_traffic.py"
systemd-run --unit=f-natsoak-sample --on-calendar='*:*:00' \
  bash "$HERE/natsoak_sample.sh"
bash "$HERE/natsoak_sample.sh"

HOURS="${1:-12}"
echo
echo "NAT SOAK RUNNING. Started $(date -u +%FT%TZ)."
echo "${HOURS} h ends: $(date -u -d "+${HOURS} hours" +%FT%TZ)"
echo "Status:    bash $HERE/natsoak_status.sh"
echo "Verdict:   python3 $HERE/natsoak_report.py \
/var/log/f/natsoak.jsonl"
echo "Stop:      bash $HERE/natsoak_stop.sh"
