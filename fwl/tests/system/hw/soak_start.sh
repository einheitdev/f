#!/usr/bin/env bash
# START THE 48H SOAK. Operator-run, on the rig:
#
#   bash /opt/fwl/tests/system/hw/soak_start.sh
#
# Before starting (rig.md thermals): point a USB fan at the i350 —
# 48 h sustained on the open bench without airflow runs the NIC hot.
#
# What it does:
#   1. Deploys the soak policy (soak_policy.fw) via the normal bundle
#      path and restarts fd on it.
#   2. Starts the traffic generator as transient unit f-soak-traffic.
#   3. Starts a 5-min sampler timer f-soak-sample writing
#      /var/log/f/soak.jsonl.
#
# Watch:  bash soak_status.sh        Stop:  bash soak_stop.sh
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
export PYTHONPATH=/opt/fwl:/opt/fwl-deps

if systemctl is-active --quiet f-soak-traffic; then
  echo "soak already running (f-soak-traffic active)"; exit 1
fi

echo "== deploying soak policy =="
V=/usr/share/f/compiled/v-soak
rm -rf "$V"
fwl compile --bundle "$V" "$HERE/soak_policy.fw"
systemctl stop fd
rm -f /sys/fs/bpf/f/fwl_* /sys/fs/bpf/f/conntrack
ln -sfT "$V" /usr/share/f/compiled/current
cp "$HERE/soak_policy.fw" /etc/f/rules.fw
systemctl start fd
sleep 3
fctl status | grep -q '"xdp_attached":true' \
  || { echo "fd did not attach"; exit 1; }
ip link set dev enp1s0f1 promisc on
python3 "$HERE/sendmany.py" --probe enp1s0f0 enp1s0f1 45
python3 "$HERE/sendmany.py" --teach enp1s0f1 enp1s0f0

echo "== starting traffic + sampler =="
mkdir -p /var/log/f
: > /var/log/f/soak.jsonl
systemd-run --unit=f-soak-traffic --property=Restart=always \
  --setenv=PYTHONPATH=/opt/fwl:/opt/fwl-deps \
  python3 "$HERE/soak_traffic.py"
systemd-run --unit=f-soak-sample --on-calendar='*:0/5' \
  bash "$HERE/soak_sample.sh"
bash "$HERE/soak_sample.sh"

echo
echo "SOAK RUNNING. Started $(date -u +%FT%TZ)."
echo "48 h ends:  $(date -u -d '+48 hours' +%FT%TZ)"
echo "Status:     bash $HERE/soak_status.sh"
echo "Stop:       bash $HERE/soak_stop.sh"
