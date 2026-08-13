#!/usr/bin/env bash
# Stop the soak (traffic + sampler), keep the log, restore the smoke
# policy so the rig is back in the walk-up state.
set -u
systemctl stop f-soak-traffic 2>/dev/null || true
systemctl stop f-soak-sample.timer 2>/dev/null || true
systemctl stop f-soak-sample 2>/dev/null || true
echo "soak stopped; log kept at /var/log/f/soak.jsonl"
echo "== final status =="
bash "$(dirname "$0")/soak_status.sh" || true
# Back to the smoke policy.
V=/usr/share/f/compiled/v-smoke
export PYTHONPATH=/opt/fwl:/opt/fwl-deps
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
systemctl start fd
echo "smoke policy restored; fd $(systemctl is-active fd)"
