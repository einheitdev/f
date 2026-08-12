#!/usr/bin/env python3
"""Hard gate: DHCP must stay silent on the uplink.

Becoming the rogue DHCP server on a corporate network is the one
outcome that must not happen, so this is a behavioural test against a
real dnsmasq, not a review of the generated file.

The topology is deliberately adversarial. The uplink and the testnet
are put on the *same subnet* as the DHCP pool, so a subnet mismatch
cannot be what saves us — the only thing standing between the pool and
the uplink is the interface containment the model derives from zone
membership.

    netns office            root netns (the appliance)      netns testnet
    up0 -------------------- wan0  zone wan   10.10.0.2/24
                             lan0  zone testnet 10.10.0.1/24 -------- tn0
                                   dhcp pool 10.10.0.100-200

Two runs, and both matter:

  1. POSITIVE CONTROL. dnsmasq with a config written the way you would
     if services bound to a hand-maintained interface list and somebody
     forgot the uplink. The probe must see an offer on *both* ports. If
     it does not, the probe or the topology is broken and every result
     below it is vacuous.

  2. THE GATE. dnsmasq with the config the model generates. An offer on
     the testnet, silence on the uplink.

Run on the target, as root:
  sudo ./test_dhcp_zone_containment.py --f-sysconf /path/to/f-sysconf
"""
import argparse
import os
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))

PASS = 0
FAIL = 0

# The appliance's own ports, and the far end of each cable.
WAN_IF = "wan0"
LAN_IF = "lan0"
OFFICE_NS = "f-office"
OFFICE_IF = "up0"
TESTNET_NS = "f-testnet"
TESTNET_IF = "tn0"

WAN_ADDR = "10.10.0.2/24"
LAN_ADDR = "10.10.0.1/24"

MODEL = """\
zones:
  wan:
  testnet:

interfaces:
  wan0:
    mac: "52:54:00:f0:00:01"
    address: dhcp
    zone: wan
  lan0:
    mac: "52:54:00:f0:00:02"
    address: 10.10.0.1/24
    zone: testnet

services:
  dhcp:
    - zone: testnet
      range: 10.10.0.100-10.10.0.200
      lease: 10m
  dns:
    - zone: testnet
      upstream: [9.9.9.9]
"""

# What the generated config replaces: a dnsmasq that answers wherever
# it happens to be reachable. Nothing about it is malformed; it is just
# missing the one line somebody has to remember to write.
NAIVE_CONF = """\
dhcp-authoritative
dhcp-range=10.10.0.100,10.10.0.200,255.255.255.0,600
dhcp-option=option:router,10.10.0.1
port=0
"""


def check(desc, cond, detail=""):
  """Record one assertion, s5-style: PASS/FAIL with truncated detail."""
  global PASS, FAIL
  if cond:
    PASS += 1
    print("PASS  %s" % desc)
  else:
    FAIL += 1
    print("FAIL  %s" % desc)
    if detail:
      text = detail if len(detail) < 400 else detail[:400] + "..."
      for line in text.splitlines():
        print("        %s" % line)


def run(cmd, check_rc=False):
  """Run a command, returning (rc, combined output)."""
  p = subprocess.run(cmd, shell=isinstance(cmd, str),
                     capture_output=True, text=True)
  out = p.stdout + p.stderr
  if check_rc and p.returncode != 0:
    raise RuntimeError("command failed: %s\n%s" % (cmd, out))
  return p.returncode, out


def quiet(cmd):
  """Best-effort teardown step."""
  subprocess.run(cmd, shell=True, capture_output=True)


def teardown():
  """Remove everything a previous run may have left behind."""
  quiet("pkill -x dnsmasq")
  for ns in (OFFICE_NS, TESTNET_NS):
    quiet("ip netns del %s" % ns)
  for link in (WAN_IF, LAN_IF):
    quiet("ip link del %s" % link)
  time.sleep(0.3)


def build_topology():
  """Two cables into the appliance, each with a host on the far end."""
  run(["ip", "netns", "add", OFFICE_NS], check_rc=True)
  run(["ip", "netns", "add", TESTNET_NS], check_rc=True)

  for local, peer, ns, mac in (
      (WAN_IF, OFFICE_IF, OFFICE_NS, "52:54:00:f0:00:01"),
      (LAN_IF, TESTNET_IF, TESTNET_NS, "52:54:00:f0:00:02"),
  ):
    run(["ip", "link", "add", local, "address", mac,
         "type", "veth", "peer", "name", peer], check_rc=True)
    run(["ip", "link", "set", peer, "netns", ns], check_rc=True)
    run(["ip", "link", "set", local, "up"], check_rc=True)
    run(["ip", "netns", "exec", ns, "ip", "link", "set", peer, "up"],
        check_rc=True)

  run(["ip", "addr", "add", WAN_ADDR, "dev", WAN_IF], check_rc=True)
  run(["ip", "addr", "add", LAN_ADDR, "dev", LAN_IF], check_rc=True)
  time.sleep(0.5)


def start_dnsmasq(dnsmasq, conf_path, log):
  """Start dnsmasq in the foreground and wait for it to settle."""
  quiet("pkill -x dnsmasq")
  time.sleep(0.3)
  handle = subprocess.Popen(
    [dnsmasq, "--keep-in-foreground", "--log-facility=" + log,
     "--conf-file=" + conf_path, "--pid-file="],
    stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
  time.sleep(1.5)
  return handle


def probe(ns, iface, probe_path):
  """Ask one port whether anything will hand it a lease."""
  rc, out = run(["ip", "netns", "exec", ns, "python3", probe_path,
                 iface, "--timeout", "4", "--tries", "3"])
  return out.strip()


def sockets_on(addr):
  """UDP listeners on `addr`, as the kernel sees them."""
  _, out = run(["ss", "-ulnH"])
  return [ln for ln in out.splitlines() if addr in ln]


def main():
  ap = argparse.ArgumentParser(description=__doc__)
  ap.add_argument("--f-sysconf", default="f-sysconf",
                  help="Path to the f-sysconf binary")
  ap.add_argument("--dnsmasq", default="/usr/sbin/dnsmasq")
  ap.add_argument("--probe",
                  default=os.path.join(HERE, "dhcp_probe.py"))
  args = ap.parse_args()

  if os.geteuid() != 0:
    print("this test needs root", file=sys.stderr)
    return 2

  work = tempfile.mkdtemp(prefix="f-dhcp-gate-")
  model_path = os.path.join(work, "system.yaml")
  with open(model_path, "w") as fh:
    fh.write(MODEL)
  naive_path = os.path.join(work, "naive.conf")
  with open(naive_path, "w") as fh:
    fh.write(NAIVE_CONF)
  generated_path = os.path.join(work, "generated.conf")
  log_path = os.path.join(work, "dnsmasq.log")
  os.makedirs("/var/lib/f", exist_ok=True)

  teardown()
  try:
    build_topology()

    # ---- the model refuses the leak before anything runs ----------
    rc, out = run([args.f_sysconf, "-c", model_path, "check"])
    check("the model validates", rc == 0, out)

    leaky_path = os.path.join(work, "leaky.yaml")
    with open(leaky_path, "w") as fh:
      fh.write(MODEL.replace("zone: testnet\n      range",
                             "zone: wan\n      range"))
    rc, out = run([args.f_sysconf, "-c", leaky_path, "check"])
    check("binding dhcp to the uplink zone is refused", rc != 0, out)
    check("...and the refusal names the rule and the interface",
          "SC022" in out and "wan0" in out, out)

    rc, out = run([args.f_sysconf, "-c", model_path,
                   "--dnsmasq-conf", generated_path,
                   "--networkd-dir", os.path.join(work, "networkd"),
                   "apply"])
    check("apply generates and installs the artifact", rc == 0, out)
    check("apply states where dhcp will answer",
          "dhcp answers on: lan0" in out, out)
    check("the artifact exists", os.path.exists(generated_path))

    # ---- 1. positive control --------------------------------------
    # If the probe cannot see a leak that is genuinely there, its
    # silence in the next section means nothing.
    start_dnsmasq(args.dnsmasq, naive_path, log_path)
    naive_uplink = probe(OFFICE_NS, OFFICE_IF, args.probe)
    naive_testnet = probe(TESTNET_NS, TESTNET_IF, args.probe)
    print("  control: uplink=%r testnet=%r"
          % (naive_uplink, naive_testnet))
    check("CONTROL: an unbound dnsmasq answers on the testnet",
          naive_testnet.startswith("OFFER"), naive_testnet)
    check("CONTROL: an unbound dnsmasq LEAKS onto the uplink "
          "(so the probe can see a leak)",
          naive_uplink.startswith("OFFER"), naive_uplink)
    quiet("pkill -x dnsmasq")
    time.sleep(0.5)

    # ---- 2. the gate ----------------------------------------------
    start_dnsmasq(args.dnsmasq, generated_path, log_path)
    gate_uplink = probe(OFFICE_NS, OFFICE_IF, args.probe)
    gate_testnet = probe(TESTNET_NS, TESTNET_IF, args.probe)
    print("  gate:    uplink=%r testnet=%r"
          % (gate_uplink, gate_testnet))

    check("GATE: the testnet is served", gate_testnet.startswith("OFFER"),
          gate_testnet)
    check("GATE: the testnet lease comes from the model's pool",
          "yiaddr=10.10.0.1" in gate_testnet or
          "yiaddr=10.10.0.2" in gate_testnet, gate_testnet)
    # Asserted positively: "NO_OFFER" is the whole string, whereas
    # `not startswith("OFFER")` would also pass on a crashed probe.
    check("GATE: DHCP IS SILENT ON THE UPLINK",
          gate_uplink == "NO_OFFER", gate_uplink)

    # DNS containment rides on the same derivation.
    uplink_dns = sockets_on("10.10.0.2:53")
    testnet_dns = sockets_on("10.10.0.1:53")
    check("GATE: DNS listens on the testnet address",
          len(testnet_dns) > 0, str(testnet_dns))
    check("GATE: DNS does not listen on the uplink address",
          len(uplink_dns) == 0, str(uplink_dns))

    quiet("pkill -x dnsmasq")
    time.sleep(0.3)

    # ---- 3. the artifact is derived, and stays that way -----------
    rc, out = run([args.f_sysconf, "-c", model_path,
                   "--dnsmasq-conf", generated_path,
                   "--networkd-dir", os.path.join(work, "networkd"),
                   "status"])
    check("status reports no drift right after apply",
          "hand-edited" not in out and "stale" not in out, out)

    # Failure semantics, on a real box. This harness starts dnsmasq by
    # hand, so the systemd unit is genuinely absent. systemd answers
    # `is-active` for a missing unit with a stale `failed`, which would
    # send an operator hunting a crash that never happened — so the
    # state must name the real problem, and say it in the exit code so
    # a script can notice.
    check("a service the box has no unit for is named, not blank",
          "NOT INSTALLED" in out, out)
    check("...and the reason names the unit, not a phantom crash",
          "f-dnsmasq.service is not installed" in out, out)
    check("...and status exits non-zero on a service fault",
          rc == 4, "rc=%d\n%s" % (rc, out))

    with open(generated_path, "a") as fh:
      fh.write("interface=wan0\n")
    rc, out = run([args.f_sysconf, "-c", model_path,
                   "--dnsmasq-conf", generated_path,
                   "--networkd-dir", os.path.join(work, "networkd"),
                   "status"])
    check("a hand edit to the artifact is reported as drift",
          rc == 3 and "hand-edited" in out, out)

    rc, out = run([args.f_sysconf, "-c", model_path,
                   "--dnsmasq-conf", generated_path,
                   "--networkd-dir", os.path.join(work, "networkd"),
                   "apply"])
    check("apply refuses to silently overwrite the edit", rc != 0, out)
    with open(generated_path) as fh:
      still_there = "interface=wan0" in fh.read()
    check("...and the edit is still there to be reconciled",
          still_there)

  finally:
    teardown()

  print("\n%d passed, %d failed" % (PASS, FAIL))
  return 1 if FAIL else 0


if __name__ == "__main__":
  sys.exit(main())
