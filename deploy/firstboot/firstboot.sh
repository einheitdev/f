#!/bin/bash
# First-boot provisioning for the f firewall appliance.
#
# Runs once on initial power-up. Reads optional provisioning
# data from /boot/f-provision.yaml (USB or SD card) or falls
# back to sensible defaults.
#
# After completion, creates /etc/f/.provisioned to prevent
# re-running on subsequent boots.

set -euo pipefail

MARKER=/etc/f/.provisioned
PROVISION_FILE=/boot/f-provision.yaml
FD_CONFIG=/etc/f/fd.yaml
FW_SOURCE=/etc/f/rules.fw

if [ -f "$MARKER" ]; then
  echo "Already provisioned, skipping."
  exit 0
fi

echo "=== f appliance first-boot provisioning ==="

mkdir -p /etc/f
mkdir -p /usr/share/f/compiled
mkdir -p /run/f

# Hostname.
HOSTNAME="f-appliance"
if [ -f "$PROVISION_FILE" ]; then
  PROV_HOST=$(python3 -c "
import yaml, sys
with open('$PROVISION_FILE') as f:
  d = yaml.safe_load(f)
  print(d.get('hostname', ''))
" 2>/dev/null || true)
  if [ -n "$PROV_HOST" ]; then
    HOSTNAME="$PROV_HOST"
  fi
fi
hostnamectl set-hostname "$HOSTNAME"
echo "Hostname: $HOSTNAME"

# Management IP (eth0).
if [ -f "$PROVISION_FILE" ]; then
  python3 -c "
import yaml
with open('$PROVISION_FILE') as f:
  d = yaml.safe_load(f)
mgmt = d.get('management', {})
addr = mgmt.get('address')
gw = mgmt.get('gateway')
dns = mgmt.get('dns', [])
if addr:
  lines = ['[Match]', 'Name=eth0', '', '[Network]']
  lines.append(f'Address={addr}')
  if gw:
    lines.append(f'Gateway={gw}')
  for d in dns:
    lines.append(f'DNS={d}')
  lines.append('LinkLocalAddressing=ipv6')
  with open('/etc/systemd/network/10-eth0.network', 'w') as nf:
    nf.write('\n'.join(lines) + '\n')
  print(f'Management IP: {addr}')
" 2>/dev/null || true
fi

# SSH keys.
mkdir -p /root/.ssh
chmod 700 /root/.ssh
if [ -f "$PROVISION_FILE" ]; then
  python3 -c "
import yaml
with open('$PROVISION_FILE') as f:
  d = yaml.safe_load(f)
keys = d.get('ssh_keys', [])
if keys:
  with open('/root/.ssh/authorized_keys', 'a') as ak:
    for k in keys:
      ak.write(k.strip() + '\n')
  print(f'Added {len(keys)} SSH key(s)')
" 2>/dev/null || true
fi
chmod 600 /root/.ssh/authorized_keys 2>/dev/null || true

# Interfaces for fd.
if [ -f "$PROVISION_FILE" ]; then
  python3 -c "
import yaml
with open('$PROVISION_FILE') as f:
  d = yaml.safe_load(f)
ifaces = d.get('interfaces', [])
if ifaces:
  with open('$FD_CONFIG') as fc:
    cfg = yaml.safe_load(fc)
  cfg['interfaces'] = ifaces
  with open('$FD_CONFIG', 'w') as fc:
    yaml.dump(cfg, fc, default_flow_style=False)
  print(f'Firewall interfaces: {ifaces}')
" 2>/dev/null || true
fi

# Install default fd config if not present.
if [ ! -f "$FD_CONFIG" ]; then
  cp /usr/share/f/fd.yaml "$FD_CONFIG"
  echo "Installed default fd.yaml"
fi

# Install default firewall rules if not present.
if [ ! -f "$FW_SOURCE" ]; then
  cat > "$FW_SOURCE" << 'RULES'
# f firewall rules
# Default policy: allow all traffic.
# Edit with: einheit-f configure firewall

default allow
RULES
  echo "Installed default rules.fw"
fi

# Enable and start services.
systemctl daemon-reload
systemctl enable fd.service
systemctl enable einheit-f-ui.service
systemctl restart systemd-networkd
systemctl start fd.service
systemctl start einheit-f-ui.service

# Mark provisioned.
date -Iseconds > "$MARKER"
echo "=== First-boot complete ==="
