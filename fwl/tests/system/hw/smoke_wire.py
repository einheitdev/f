"""Walk-up smoke test: prove the rig forwards and counts.

Sends N IPv4 UDP frames from the send port through the EX2300 into
the XDP-attached port, and reports the FWL counter delta. This is
the 30-second "is the rig alive" check.

IPv4, not an inert L2 EtherType, on purpose: FWL programs gate
non-IP frames (ARP/STP/LLDP) out before any rule — including
unconditional `count` — because the language has no L2 fields and
must never act on L2 control traffic. A non-IP smoke frame crosses
the wire but is invisible to every counter, which looks exactly
like a broken datapath. Test traffic lives in 10.99.0.0/16 on the
isolated f-* VLANs.

Usage (on the rig):
  PYTHONPATH=/opt/fwl:/opt/fwl-deps python3 smoke_wire.py [count]
"""
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SEND_IF = "enp1s0f0"
RECV_IF = "enp1s0f1"
PIN_DIR = Path("/sys/fs/bpf/f")


def counter_total() -> int:
  """Sum every slot of every pinned FWL counter map."""
  total = 0
  for pin in PIN_DIR.glob("fwl_counters_*"):
    out = subprocess.run(
      ["bpftool", "map", "dump", "pinned", str(pin)],
      capture_output=True, text=True,
    )
    if out.returncode != 0:
      continue
    for entry in json.loads(out.stdout):
      total += sum(v["value"] for v in entry["values"])
  return total


def main() -> int:
  count = int(sys.argv[1]) if len(sys.argv) > 1 else 500
  pins = list(PIN_DIR.glob("fwl_counters_*"))
  if not pins:
    print(f"no FWL counter maps pinned under {PIN_DIR} — is fd "
          f"running with a bundle loaded?")
    return 2

  subprocess.run(
    [sys.executable, str(HERE / "sendmany.py"), "--teach",
     RECV_IF, SEND_IF], check=True, capture_output=True,
  )
  before = counter_total()
  subprocess.run(
    [sys.executable, str(HERE / "sendmany.py"), SEND_IF,
     str(count), 'udp(src_ip="10.99.0.1", dst_port=9999)'],
    check=True, capture_output=True,
  )
  after = counter_total()
  delta = after - before

  print(f"sent {count} IPv4 frames {SEND_IF} -> EX2300 -> {RECV_IF}")
  print(f"counter delta: {delta} "
        f"(maps: {', '.join(p.name for p in pins)})")
  if delta >= count:
    print("SMOKE OK: frames crossed the wire and the XDP program "
          "counted them")
    return 0
  print(f"SMOKE FAIL: expected at least {count}. Check "
        f"'fctl status', the link state, and that the loaded policy "
        f"has a counter on the receiving zone.")
  return 1


if __name__ == "__main__":
  sys.exit(main())
