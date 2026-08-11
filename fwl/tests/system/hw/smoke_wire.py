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

  # An XDP attach resets the igb links and the switch port needs
  # seconds to forward again — every fd restart (including the one
  # each hw.sh scenario does on exit) lands here. Without this wait
  # the smoke test reports a false failure on a perfectly healthy
  # rig. Bounded: if the wire is genuinely dead, say so.
  # The receiving NIC needs two settings the scenario harness sets
  # in hw::deploy and this tool previously assumed: promiscuous mode
  # (test frames carry a foreign destination MAC, which the i350
  # filters in hardware otherwise) and VLAN offload off (the NIC
  # strips 802.1Q before XDP sees it). NEITHER survives a reboot —
  # so this check, the first thing an operator runs after a restart,
  # reported "wire dead" and pointed at the link and the switch when
  # the real cause was a NIC flag it had not set. Set them here.
  subprocess.run(["ip", "link", "set", "dev", RECV_IF, "promisc", "on"],
                 capture_output=True)
  subprocess.run(["ethtool", "-K", RECV_IF, "rxvlan", "off"],
                 capture_output=True)

  probe = subprocess.run(
    [sys.executable, str(HERE / "sendmany.py"), "--probe",
     SEND_IF, RECV_IF, "45"], capture_output=True, text=True,
  )
  if probe.returncode != 0:
    print(f"wire dead: no frame crossed {SEND_IF} -> {RECV_IF} in "
          f"45 s.\n  Checked already: {RECV_IF} promisc + rxvlan.\n"
          f"  Next: 'ip -br link show' for carrier, then the EX2300 "
          f"port/VLAN config for {SEND_IF} and {RECV_IF}.")
    return 1

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
