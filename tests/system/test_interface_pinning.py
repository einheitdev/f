#!/usr/bin/env python3
"""Durable interface names follow the hardware, not the probe order.

A firewall pointing at the wrong port is a bypass, not an outage, so
"the name is stable" needs a test rather than a comment. The mechanism
is a systemd `.link` unit generated from the model; what this checks is
that the mechanism actually bites.

The discriminating case is the second one. Two ports are created in one
order, named, torn down, and created again in the *opposite* order. If
names came from probe order they would swap. They must not.

Run on the target, as root:
  sudo ./test_interface_pinning.py --f-sysconf /path/to/f-sysconf
"""
import argparse
import os
import subprocess
import sys
import tempfile
import time

PASS = 0
FAIL = 0

# Two ports, each with a permanent identity and a durable name.
PORTS = [
  ("52:54:00:f1:00:01", "uplink0"),
  ("52:54:00:f1:00:02", "bench0"),
]
# The names the kernel would give them, which nothing may depend on.
KERNEL_NAMES = ["ftmpa", "ftmpb"]
PEER_NAMES = ["ftmpa-p", "ftmpb-p"]

MODEL = """\
zones:
  wan:
  bench:

interfaces:
  uplink0:
    mac: "52:54:00:f1:00:01"
    address: dhcp
    zone: wan
  bench0:
    mac: "52:54:00:f1:00:02"
    address: 10.30.0.1/24
    zone: bench
"""


def check(desc, cond, detail=""):
  global PASS, FAIL
  if cond:
    PASS += 1
    print("PASS  %s" % desc)
  else:
    FAIL += 1
    print("FAIL  %s" % desc)
    if detail:
      for line in str(detail)[:400].splitlines():
        print("        %s" % line)


def run(cmd, check_rc=False):
  p = subprocess.run(cmd, shell=isinstance(cmd, str),
                     capture_output=True, text=True)
  out = p.stdout + p.stderr
  if check_rc and p.returncode != 0:
    raise RuntimeError("failed: %s\n%s" % (cmd, out))
  return p.returncode, out


def quiet(cmd):
  subprocess.run(cmd, shell=True, capture_output=True)


def name_for_mac(mac):
  """The kernel's current name for the port carrying `mac`."""
  _, out = run(["ip", "-o", "link"])
  for line in out.splitlines():
    if mac in line.lower():
      # "3: bench0@ftmpb-p: <BROADCAST,...>"
      return line.split(":")[1].strip().split("@")[0]
  return None


def teardown():
  for name in KERNEL_NAMES + PEER_NAMES + [n for _, n in PORTS]:
    quiet("ip link del %s" % name)
  time.sleep(0.2)


def create_ports(order):
  """Create the veths in `order` (indices into PORTS)."""
  for i in order:
    mac, _ = PORTS[i]
    run(["ip", "link", "add", KERNEL_NAMES[i], "address", mac,
         "type", "veth", "peer", "name", PEER_NAMES[i]],
        check_rc=True)
    # udev renames on device add; give it a moment to land.
  run(["udevadm", "settle"])
  time.sleep(0.6)


def main():
  ap = argparse.ArgumentParser(description=__doc__)
  ap.add_argument("--f-sysconf", default="f-sysconf")
  ap.add_argument("--networkd-dir", default="/etc/systemd/network")
  args = ap.parse_args()

  if os.geteuid() != 0:
    print("this test needs root", file=sys.stderr)
    return 2

  work = tempfile.mkdtemp(prefix="f-pin-")
  model_path = os.path.join(work, "system.yaml")
  with open(model_path, "w") as fh:
    fh.write(MODEL)

  written = []
  teardown()
  try:
    rc, out = run([args.f_sysconf, "-c", model_path,
                   "--networkd-dir", args.networkd_dir,
                   "--dnsmasq-conf", os.path.join(work, "dm.conf"),
                   "apply"])
    check("apply installs the networkd units", rc == 0, out)
    for _, name in PORTS:
      p = os.path.join(args.networkd_dir, "10-f-%s.link" % name)
      written.append(p)
      written.append(
        os.path.join(args.networkd_dir, "10-f-%s.network" % name))
      check("a .link unit was written for %s" % name,
            os.path.exists(p))

    run(["udevadm", "control", "--reload"])

    # ---- 1. the pin renames the port -----------------------------
    create_ports([0, 1])
    first = {mac: name_for_mac(mac) for mac, _ in PORTS}
    for mac, want in PORTS:
      check("%s is named %s, not its kernel name"
            % (mac, want), first[mac] == want,
            "got %r" % first[mac])

    # ---- 2. the discriminating case: reversed probe order --------
    teardown()
    create_ports([1, 0])
    second = {mac: name_for_mac(mac) for mac, _ in PORTS}
    for mac, want in PORTS:
      check("%s is still named %s after the ports came up in the "
            "opposite order" % (mac, want), second[mac] == want,
            "got %r" % second[mac])
    check("names did not swap with probe order", first == second,
          "%r vs %r" % (first, second))

    # ---- 3. the model is what says so ----------------------------
    rc, out = run([args.f_sysconf, "-c", model_path,
                   "--networkd-dir", args.networkd_dir,
                   "--dnsmasq-conf", os.path.join(work, "dm.conf"),
                   "show"])
    check("the model names the same ports the kernel now shows",
          "uplink0" in out and "bench0" in out, out)

  finally:
    teardown()
    for p in written:
      try:
        os.unlink(p)
      except OSError:
        pass
    run(["udevadm", "control", "--reload"])

  print("\n%d passed, %d failed" % (PASS, FAIL))
  return 1 if FAIL else 0


if __name__ == "__main__":
  sys.exit(main())
