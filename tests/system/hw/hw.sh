#!/usr/bin/env bash
# ksys-side wrapper: sync the FWL tree to the rig and run one hardware
# test there.
#
#   hw.sh l1_01_proto_port_cidr     # or any l1_* name, or run_l1
#
# Assumes `ssh f-rig` works (see workspace context/rig.md).
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
FWL_ROOT="$(cd "$HERE/../../.." && pwd)"
NAME="${1:?usage: hw.sh <script-name-without-.sh>}"
rsync -a --delete --exclude '__pycache__' --exclude '.venv' \
  "$FWL_ROOT/" f-rig:/opt/fwl/
ssh f-rig "bash /opt/fwl/tests/system/hw/${NAME}.sh"
