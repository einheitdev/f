#!/usr/bin/env python3
"""`set address` changes the system configuration, and only that.

The CLI used to hand-write `/etc/systemd/network/10-f-<if>.network`
itself, which is the same file the system-configuration model
generates. Two writers on one file is how a box ends up with a running
address that no configuration explains — and the model, correctly,
reported the CLI's own writes as drift and refused to apply.

So the test is about provenance, not just about the address landing:
after `set address`, the address must be in the system configuration,
the generated unit must be the model's (digest header and all), and
`apply system` must not see drift.

Run on the target, as root:
  sudo ./test_iface_address.py --cli /path/to/einheit-f
"""
import argparse
import os
import subprocess
import sys
import tempfile

PASS = 0
FAIL = 0
IFACE = "ftaddr0"

BASE_CONFIG = """zones:
  bench:
interfaces:
  # a comment the operator wrote, which must survive every edit
  {iface}:
    mac: "{mac}"
    zone: bench
"""

def check(name, ok, detail=""):
  global PASS, FAIL
  if ok:
    PASS += 1
    print(f"  ok   {name}")
  else:
    FAIL += 1
    print(f"  FAIL {name}{(': ' + detail) if detail else ''}")

def run(argv, **kw):
  return subprocess.run(argv, capture_output=True, text=True, **kw)

def cli(binary, workdir, command):
  return run([
      binary, "--ascii", "--color", "never", "--width", "100",
      "--socket", "ipc:///tmp/nofd.sock",
      "--confd-socket", "ipc:///tmp/noconfd.sock",
      "--system-config", os.path.join(workdir, "system.yaml"),
      "--networkd-dir", os.path.join(workdir, "network"),
      "--dnsmasq-conf", os.path.join(workdir, "dnsmasq.conf"),
      command,
  ])

def read(path):
  try:
    with open(path) as fh:
      return fh.read()
  except OSError:
    return ""

def main():
  ap = argparse.ArgumentParser()
  ap.add_argument("--cli", default="./build/einheit-f")
  args = ap.parse_args()

  if os.geteuid() != 0:
    print("must run as root (creates a dummy interface)")
    return 2

  run(["ip", "link", "del", IFACE])
  if run(["ip", "link", "add", IFACE, "type", "dummy"]).returncode:
    print(f"could not create {IFACE}")
    return 2

  try:
    mac = read(f"/sys/class/net/{IFACE}/address").strip()
    with tempfile.TemporaryDirectory() as workdir:
      cfg_path = os.path.join(workdir, "system.yaml")
      unit = os.path.join(workdir, "network", f"10-f-{IFACE}.network")
      with open(cfg_path, "w") as fh:
        fh.write(BASE_CONFIG.format(iface=IFACE, mac=mac))

      out = cli(args.cli, workdir, f"set address {IFACE} 10.99.0.1/24")
      cfg = read(cfg_path)
      check("address is in the system configuration",
            "10.99.0.1/24" in cfg, cfg)
      check("the operator's comment survived",
            "a comment the operator wrote" in cfg)
      check("the generated unit carries the address",
            "10.99.0.1/24" in read(unit), read(unit))
      check("the unit is the model's, not hand-written",
            "GENERATED FROM THE f SYSTEM CONFIGURATION MODEL"
            in read(unit))
      check("the address is live on the link",
            "10.99.0.1/24" in run(
                ["ip", "addr", "show", IFACE]).stdout,
            out.stdout + out.stderr)

      # The whole point: the model no longer sees a rival writer.
      applied = cli(args.cli, workdir, "apply system")
      body = applied.stdout + applied.stderr
      check("apply system reports no drift",
            "edited by hand" not in body, body)

      # Setting a different address replaces it; the configuration has
      # one address per interface, and says so.
      cli(args.cli, workdir, f"set address {IFACE} 10.99.0.2/24")
      cfg = read(cfg_path)
      check("a new address replaces the old one",
            "10.99.0.2/24" in cfg and "10.99.0.1/24" not in cfg, cfg)

      cli(args.cli, workdir, f"no address {IFACE}")
      cfg = read(cfg_path)
      check("no address leaves the interface declared",
            IFACE in cfg and "10.99.0.2/24" not in cfg, cfg)

      unknown = cli(args.cli, workdir, "set address nope99nope 1.2.3.4/24")
      check("an unknown interface is refused",
            "not found" in (unknown.stdout + unknown.stderr).lower())
  finally:
    run(["ip", "link", "del", IFACE])

  print(f"\n{PASS} passed, {FAIL} failed")
  return 1 if FAIL else 0

if __name__ == "__main__":
  sys.exit(main())
