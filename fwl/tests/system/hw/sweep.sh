#!/usr/bin/env bash
# ksys-side wrapper for the vacuity sweep: sync the tree to the rig and
# drive it there.
#
#   sweep.sh preflight              # static: do the plants match?
#   sweep.sh run                    # the whole sweep (hours)
#   sweep.sh run --only l2_03_masquerade
#   sweep.sh report                 # render from the rig's results
#   sweep.sh restore                # smoke policy, walk-up ready
#   sweep.sh pull <dir>             # copy results/history/logs to <dir>
#
# The sweep runs ON the rig because it restarts fd, edits units and
# reads bpffs. Assumes `ssh f-rig` works (workspace context/rig.md).
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
FWL_ROOT="$(cd "$HERE/../../.." && pwd)"
STATE=/var/lib/f-hw-sweep

if [ "${1:-}" = "pull" ]; then
  DEST="${2:?usage: sweep.sh pull <dir>}"
  mkdir -p "$DEST"
  rsync -a "f-rig:$STATE/results.jsonl" "f-rig:$STATE/history.jsonl" \
    "$DEST/" 2>/dev/null || true
  rsync -a "f-rig:$STATE/logs/" "$DEST/logs/" 2>/dev/null || true
  echo "pulled to $DEST"
  exit 0
fi

rsync -a --delete --exclude '__pycache__' --exclude '.venv' \
  "$FWL_ROOT/" f-rig:/opt/fwl/
ssh f-rig "python3 /opt/fwl/tests/system/hw/vacuity_sweep.py $*"
