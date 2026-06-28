#!/bin/bash
# Build a flashable rootfs image for the f firewall appliance.
#
# Produces a compressed tarball containing a Debian rootfs with:
#   - fd (BPF firewall engine)
#   - einheit-f (CLI)
#   - einheit-f-ui (web dashboard)
#   - fwl (FWL compiler)
#   - systemd units + networkd config + first-boot provisioning
#
# Target: aarch64 (Allwinner A733 / Cubie A7S SoM)
#
# Prerequisites:
#   - aarch64 cross-compiled binaries in build-aarch64/
#   - debootstrap, qemu-user-static
#
# Usage:
#   ./deploy/image/build-image.sh [output-dir]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="$REPO_ROOT/build-aarch64"
OUTPUT_DIR="${1:-$REPO_ROOT/build-aarch64/image}"
ROOTFS="$OUTPUT_DIR/rootfs"

if [ ! -f "$BUILD_DIR/fd" ]; then
  echo "error: aarch64 binaries not found."
  echo "Run: cmake --preset aarch64 && cmake --build build-aarch64"
  exit 1
fi

echo "=== Building f appliance image ==="
echo "Build dir:  $BUILD_DIR"
echo "Output dir: $OUTPUT_DIR"

mkdir -p "$OUTPUT_DIR"

# Create rootfs with debootstrap.
if [ ! -d "$ROOTFS" ]; then
  echo "--- debootstrap ---"
  sudo debootstrap \
    --arch=arm64 \
    --foreign \
    --include=systemd,systemd-networkd,openssh-server,python3,python3-pip,python3-yaml,sudo,curl,ca-certificates \
    trixie \
    "$ROOTFS" \
    http://deb.debian.org/debian
  sudo cp /usr/bin/qemu-aarch64-static "$ROOTFS/usr/bin/"
  sudo chroot "$ROOTFS" /debootstrap/debootstrap --second-stage
else
  echo "Rootfs already exists, reusing."
fi

echo "--- Installing binaries ---"
sudo install -m 755 "$BUILD_DIR/fd" "$ROOTFS/usr/local/bin/"
sudo install -m 755 "$BUILD_DIR/einheit-f" "$ROOTFS/usr/local/bin/"
sudo install -m 755 "$BUILD_DIR/einheit-f-ui" "$ROOTFS/usr/local/bin/"
sudo install -m 755 "$BUILD_DIR/fctl" "$ROOTFS/usr/local/bin/"

echo "--- Installing FWL compiler ---"
if [ -d "$REPO_ROOT/fwl" ]; then
  sudo mkdir -p "$ROOTFS/usr/local/lib/fwl"
  sudo cp -r "$REPO_ROOT/fwl/fwl" "$ROOTFS/usr/local/lib/fwl/"
  sudo cp "$REPO_ROOT/fwl/setup.py" "$ROOTFS/usr/local/lib/fwl/" 2>/dev/null || true
  sudo cp "$REPO_ROOT/fwl/pyproject.toml" "$ROOTFS/usr/local/lib/fwl/" 2>/dev/null || true
  sudo chroot "$ROOTFS" pip3 install --break-system-packages /usr/local/lib/fwl/ 2>/dev/null || \
    echo "FWL pip install deferred to first boot"
fi

echo "--- Installing systemd units ---"
sudo install -m 644 \
  "$REPO_ROOT/deploy/systemd/fd.service" \
  "$ROOTFS/etc/systemd/system/"
sudo install -m 644 \
  "$REPO_ROOT/deploy/systemd/einheit-f-ui.service" \
  "$ROOTFS/etc/systemd/system/"
sudo install -m 644 \
  "$REPO_ROOT/deploy/systemd/f-firstboot.service" \
  "$ROOTFS/etc/systemd/system/"

echo "--- Installing networkd config ---"
sudo mkdir -p "$ROOTFS/etc/systemd/network"
sudo install -m 644 \
  "$REPO_ROOT/deploy/networkd/"*.network \
  "$ROOTFS/etc/systemd/network/"

echo "--- Installing config + first-boot ---"
sudo mkdir -p "$ROOTFS/etc/f"
sudo mkdir -p "$ROOTFS/usr/share/f/compiled"
sudo mkdir -p "$ROOTFS/usr/local/share/f"
sudo install -m 644 \
  "$REPO_ROOT/deploy/fd.yaml" \
  "$ROOTFS/usr/share/f/fd.yaml"
sudo install -m 755 \
  "$REPO_ROOT/deploy/firstboot/firstboot.sh" \
  "$ROOTFS/usr/local/share/f/firstboot.sh"

echo "--- Installing UI assets ---"
UI_DIR="$REPO_ROOT/../ui"
if [ -d "$UI_DIR/templates" ]; then
  sudo mkdir -p "$ROOTFS/usr/share/einheit-ui/templates"
  sudo cp -r "$UI_DIR/templates/"* \
    "$ROOTFS/usr/share/einheit-ui/templates/"
fi
if [ -d "$UI_DIR/assets" ]; then
  sudo mkdir -p "$ROOTFS/usr/share/einheit-ui/assets"
  sudo cp -r "$UI_DIR/assets/"* \
    "$ROOTFS/usr/share/einheit-ui/assets/"
fi
ADAPTER_TPL="$REPO_ROOT/adapters/ui/templates"
if [ -d "$ADAPTER_TPL" ]; then
  sudo cp -r "$ADAPTER_TPL/"* \
    "$ROOTFS/usr/share/einheit-ui/templates/"
fi

echo "--- Enabling services ---"
sudo chroot "$ROOTFS" systemctl enable \
  systemd-networkd fd f-firstboot einheit-f-ui \
  2>/dev/null || true

echo "--- Setting up login shell ---"
sudo chroot "$ROOTFS" bash -c '
  useradd -m -s /usr/local/bin/einheit-f operator 2>/dev/null || true
  echo "operator:operator" | chpasswd
  echo "operator ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/operator
'

echo "--- Enabling SSH ---"
sudo chroot "$ROOTFS" systemctl enable ssh 2>/dev/null || true

echo "--- Creating archive ---"
ARCHIVE="$OUTPUT_DIR/f-appliance-$(date +%Y%m%d).tar.gz"
sudo tar czf "$ARCHIVE" -C "$ROOTFS" .
echo "=== Image built: $ARCHIVE ==="
ls -lh "$ARCHIVE"
