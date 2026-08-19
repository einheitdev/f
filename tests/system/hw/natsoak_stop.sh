#!/usr/bin/env bash
# Stop the NAT soak, keep the log, restore the walk-up smoke policy.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
systemctl stop f-natsoak-traffic 2>/dev/null || true
systemctl stop f-natsoak-sample.timer 2>/dev/null || true
systemctl stop f-natsoak-sample 2>/dev/null || true
echo "soak stopped; log kept at /var/log/f/natsoak.jsonl"
echo "== verdict =="
python3 "$HERE/natsoak_report.py" /var/log/f/natsoak.jsonl || true

export PYTHONPATH=/opt/fwl:/opt/fwl-deps
ip addr del 10.99.200.2/24 dev enp1s0f2 2>/dev/null || true
V=/usr/share/f/compiled/v-smoke
cat > /etc/f/rules.fw <<'EOF'
# Layer-0 smoke policy: attach to all three data-plane ports, count
# every frame, pass everything. Proves load+attach+counters only.
zone data = [enp1s0f0, enp1s0f1, enp1s0f2]

@xdp(data)

count data_total
default allow
EOF
rm -rf "$V"
fwl compile --bundle "$V" /etc/f/rules.fw
systemctl stop fd
rm -f /sys/fs/bpf/f/fwl_* /sys/fs/bpf/f/conntrack
ln -sfT "$V" /usr/share/f/compiled/current
systemctl reset-failed fd 2>/dev/null || true
systemctl start fd
echo "smoke policy restored; fd $(systemctl is-active fd)"
