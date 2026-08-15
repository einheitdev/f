#!/usr/bin/env python3
"""Hard gate: an office router advertisement must not reach a testnet.

This is the bypass that looks like a working network. The office is
flat L2 and has RAs on it. A testnet device that autoconfigures IPv6
from one acquires a globally routable address and a default route that
have nothing to do with `f` — it routes around the v4 NAT and the
entire firewall while every v4 counter on the box keeps climbing and
everything appears to work perfectly.

So `ipv6: off` is tested as a claim about *inbound* traffic, not about
what we choose to send.

    netns f-v6-office     netns f-v6-appliance      netns f-v6-testnet
    up0 =============== wan0   zone wan  192.0.2.2/24
                        lan0   zone testnet 10.10.0.1/24 ======= tn0

The appliance is itself a namespace, so the sysctls this test writes
are contained and the host's own configuration is never touched.

Four legs, and the first two are what stop the rest from being
vacuous:

  1. CONTROL A — the RA is real and this exact port accepts it. With
     stock settings the *appliance's own uplink* autoconfigures from
     the injected advertisement. A quiet client later means the gate
     worked; without this leg it might only mean the injector is
     broken.
  2. CONTROL B — the probe can see a leak. With the appliance bridging
     its two ports, the advertisement crosses to the testnet and the
     client there autoconfigures. This is the leak the gate exists to
     prevent, demonstrated actually happening.
  3. THE GATE — with the model applied, nothing autoconfigures on
     either side, AND the kernel's RA counter still moved. Both halves
     are asserted: a zero counter would mean the frame never arrived,
     which proves nothing about the stance.
  4. THE VIOLATION IS LOUD — flip accept_ra back by hand, let a port
     autoconfigure, and require the box to say so and exit non-zero.
     A gate that cannot report its own failure is a gate nobody will
     notice has come off.

Run on the target, as root:
  sudo ./test_ipv6_ra_gate.py --f-sysconf /path/to/f-sysconf
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

OFFICE_NS = "f-v6-office"
APPLIANCE_NS = "f-v6-appliance"
TESTNET_NS = "f-v6-testnet"

OFFICE_IF = "up0"
WAN_IF = "wan0"
LAN_IF = "lan0"
TESTNET_IF = "tn0"

WAN_MAC = "52:54:00:f6:00:01"
LAN_MAC = "52:54:00:f6:00:02"

WAN_ADDR = "192.0.2.2/24"
LAN_ADDR = "10.10.0.1/24"

# The prefix the "office router" advertises. 2001:db8::/32 is the
# documentation range, so nothing here can collide with a real one.
RA_PREFIX = "2001:db8:dead::"
RA_COUNT = 3

MODEL = """\
zones:
  wan:
    ipv6: off
  testnet:
    ipv6: off

interfaces:
  wan0:
    mac: "%s"
    address: 192.0.2.2/24
    zone: wan
  lan0:
    mac: "%s"
    address: 10.10.0.1/24
    zone: testnet

services:
  dhcp:
    - zone: testnet
      range: 10.10.0.100-10.10.0.200
      lease: 10m
""" % (WAN_MAC, LAN_MAC)


def check(desc, cond, detail=""):
  """Record one assertion: PASS/FAIL with truncated detail."""
  global PASS, FAIL
  if cond:
    PASS += 1
    print("PASS  %s" % desc)
  else:
    FAIL += 1
    print("FAIL  %s" % desc)
    if detail:
      text = detail if len(detail) < 600 else detail[:600] + "..."
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


def nsrun(ns, cmd, check_rc=False):
  """Run inside a namespace."""
  return run("ip netns exec %s %s" % (ns, cmd), check_rc)


def teardown():
  """Remove everything a previous run may have left behind."""
  for ns in (OFFICE_NS, APPLIANCE_NS, TESTNET_NS):
    quiet("ip netns del %s" % ns)
  for link in (WAN_IF, LAN_IF, OFFICE_IF, TESTNET_IF):
    quiet("ip link del %s" % link)
  time.sleep(0.3)


def build_topology():
  """Three namespaces, two cables, the appliance in the middle."""
  for ns in (OFFICE_NS, APPLIANCE_NS, TESTNET_NS):
    run(["ip", "netns", "add", ns], check_rc=True)

  # office --- appliance
  run("ip link add %s type veth peer name %s address %s"
      % (OFFICE_IF, WAN_IF, WAN_MAC), check_rc=True)
  run("ip link set %s netns %s" % (OFFICE_IF, OFFICE_NS),
      check_rc=True)
  run("ip link set %s netns %s" % (WAN_IF, APPLIANCE_NS),
      check_rc=True)

  # appliance --- testnet
  run("ip link add %s type veth peer name %s address %s"
      % (TESTNET_IF, LAN_IF, LAN_MAC), check_rc=True)
  run("ip link set %s netns %s" % (TESTNET_IF, TESTNET_NS),
      check_rc=True)
  run("ip link set %s netns %s" % (LAN_IF, APPLIANCE_NS),
      check_rc=True)

  for ns, iface in ((OFFICE_NS, OFFICE_IF),
                    (APPLIANCE_NS, WAN_IF),
                    (APPLIANCE_NS, LAN_IF),
                    (TESTNET_NS, TESTNET_IF)):
    nsrun(ns, "ip link set %s up" % iface, check_rc=True)
    nsrun(ns, "ip link set lo up")

  nsrun(APPLIANCE_NS, "ip addr add %s dev %s" % (WAN_ADDR, WAN_IF),
        check_rc=True)
  nsrun(APPLIANCE_NS, "ip addr add %s dev %s" % (LAN_ADDR, LAN_IF),
        check_rc=True)
  time.sleep(1.0)


def stock_v6(ns, iface):
  """Put one port back to what a distribution ships."""
  for knob, value in (("accept_ra", "1"), ("autoconf", "1"),
                      ("accept_ra_pinfo", "1"),
                      ("accept_ra_defrtr", "1"),
                      ("disable_ipv6", "0")):
    nsrun(ns, "sysctl -qw net.ipv6.conf.%s.%s=%s"
          % (iface, knob, value))


def global_v6(ns, iface):
  """Global-scope v6 addresses on a port, as strings."""
  _, out = nsrun(ns, "ip -6 -o addr show dev %s scope global" % iface)
  return [ln.strip() for ln in out.splitlines() if "inet6" in ln]


def has_prefix(addrs, prefix):
  """True when any address came from the advertised prefix."""
  head = prefix.rstrip(":")
  return any(head in a for a in addrs)


def ra_counter(ns, iface):
  """Router advertisements the kernel has counted on a port."""
  _, out = nsrun(ns, "cat /proc/net/dev_snmp6/%s" % iface)
  for line in out.splitlines():
    parts = line.split()
    if len(parts) == 2 and parts[0] == "Icmp6InRouterAdvertisements":
      return int(parts[1])
  return -1


def inject(injector, count=RA_COUNT):
  """One office router, shouting down the uplink."""
  rc, out = nsrun(OFFICE_NS,
                  "python3 %s %s --prefix %s --count %d"
                  % (injector, OFFICE_IF, RA_PREFIX, count))
  return rc, out.strip()


def main():
  ap = argparse.ArgumentParser(description=__doc__)
  ap.add_argument("--f-sysconf", default="f-sysconf",
                  help="Path to the f-sysconf binary")
  ap.add_argument("--injector",
                  default=os.path.join(HERE, "ra_inject.py"))
  args = ap.parse_args()

  if os.geteuid() != 0:
    print("this test needs root", file=sys.stderr)
    return 2

  work = tempfile.mkdtemp(prefix="f-v6-gate-")
  model_path = os.path.join(work, "system.yaml")
  with open(model_path, "w") as fh:
    fh.write(MODEL)
  sysctl_path = os.path.join(work, "10-f-ipv6.conf")

  def sysconf(*extra):
    cmd = [args.f_sysconf, "-c", model_path,
           "--ipv6-sysctl", sysctl_path,
           "--dnsmasq-conf", os.path.join(work, "dnsmasq.conf"),
           "--networkd-dir", os.path.join(work, "networkd"),
           "--proc-sys", "/proc/sys"]
    return run("ip netns exec %s %s"
               % (APPLIANCE_NS, " ".join(cmd + list(extra))))

  teardown()
  try:
    build_topology()

    # ---- the model refuses what it cannot deliver ------------------
    rc, out = sysconf("check")
    check("the model validates", rc == 0, out)

    full_path = os.path.join(work, "full.yaml")
    with open(full_path, "w") as fh:
      fh.write(MODEL.replace("  wan:\n    ipv6: off",
                             "  wan:\n    ipv6: full"))
    rc, out = run([args.f_sysconf, "-c", full_path, "check"])
    check("`ipv6: full` is refused rather than half-delivered",
          rc != 0 and "SC030" in out, out)
    check("...and the refusal names the mechanism, not just a "
          "feature gap",
          "related" in out and "Packet Too Big" in out, out)

    ra_path = os.path.join(work, "ra.yaml")
    with open(ra_path, "w") as fh:
      fh.write(MODEL.replace("  testnet:\n    ipv6: off",
                             "  testnet:\n    ipv6: ra"))
    rc, out = run([args.f_sysconf, "-c", ra_path, "check"])
    check("`ipv6: ra` with no prefix is refused (it would advertise "
          "nothing)",
          rc != 0 and "SC031" in out, out)

    # ---- 1. CONTROL A: the RA is real, and this port accepts it ----
    # Everything below rests on the injector actually producing an
    # advertisement a kernel will act on. Prove it on the very port
    # the gate protects, before the gate is applied.
    stock_v6(APPLIANCE_NS, WAN_IF)
    stock_v6(APPLIANCE_NS, LAN_IF)
    stock_v6(TESTNET_NS, TESTNET_IF)
    time.sleep(0.5)

    before = ra_counter(APPLIANCE_NS, WAN_IF)
    rc, out = inject(args.injector)
    check("CONTROL: the injector sent the advertisements",
          rc == 0 and out.startswith("SENT"), out)
    time.sleep(2.0)
    after = ra_counter(APPLIANCE_NS, WAN_IF)
    wan_addrs = global_v6(APPLIANCE_NS, WAN_IF)
    print("  control A: wan0 ras %d->%d addrs=%s"
          % (before, after, wan_addrs))
    check("CONTROL: the kernel counted the advertisements on wan0",
          after - before == RA_COUNT,
          "counter went %d -> %d, expected +%d"
          % (before, after, RA_COUNT))
    check("CONTROL: an unprotected uplink AUTOCONFIGURES from the "
          "office RA (so a quiet port later means something)",
          has_prefix(wan_addrs, RA_PREFIX), str(wan_addrs))

    # ---- 2. CONTROL B: the leak, actually happening ----------------
    # A bridging appliance is the shape this fails in: the office
    # segment and the testnet become one, and the advertisement
    # crosses. It also proves the client-side probe can see a leak.
    nsrun(APPLIANCE_NS, "ip link add br0 type bridge")
    # MLD snooping would otherwise decide whether ff02::1 floods, and
    # the leak must not depend on a bridge tuning parameter.
    nsrun(APPLIANCE_NS,
          "sh -c 'echo 0 > /sys/class/net/br0/bridge/"
          "multicast_snooping'")
    nsrun(APPLIANCE_NS, "ip link set %s master br0" % WAN_IF)
    nsrun(APPLIANCE_NS, "ip link set %s master br0" % LAN_IF)
    nsrun(APPLIANCE_NS, "ip link set br0 up")
    time.sleep(1.5)

    client_before = ra_counter(TESTNET_NS, TESTNET_IF)
    rc, out = inject(args.injector)
    time.sleep(2.5)
    client_addrs = global_v6(TESTNET_NS, TESTNET_IF)
    client_after = ra_counter(TESTNET_NS, TESTNET_IF)
    print("  control B: tn0 ras %d->%d addrs=%s"
          % (client_before, client_after, client_addrs))
    check("CONTROL: a bridging appliance LEAKS the RA into the "
          "testnet",
          client_after > client_before,
          "tn0 RA counter %d -> %d" % (client_before, client_after))
    check("CONTROL: and the testnet client AUTOCONFIGURES from it — "
          "this is the bypass",
          has_prefix(client_addrs, RA_PREFIX), str(client_addrs))

    nsrun(APPLIANCE_NS, "ip link set %s nomaster" % WAN_IF)
    nsrun(APPLIANCE_NS, "ip link set %s nomaster" % LAN_IF)
    nsrun(APPLIANCE_NS, "ip link del br0")
    # Clear what the controls left behind, so the gate is measured
    # against a clean slate rather than against decayed lifetimes.
    for ns, iface in ((APPLIANCE_NS, WAN_IF), (TESTNET_NS,
                                               TESTNET_IF)):
      for a in global_v6(ns, iface):
        addr = a.split("inet6")[1].split()[0]
        nsrun(ns, "ip -6 addr del %s dev %s" % (addr, iface))
    nsrun(APPLIANCE_NS, "ip addr add %s dev %s" % (WAN_ADDR, WAN_IF))
    nsrun(APPLIANCE_NS, "ip addr add %s dev %s" % (LAN_ADDR, LAN_IF))
    time.sleep(1.0)

    # ---- 3. THE GATE ----------------------------------------------
    rc, out = sysconf("apply")
    check("apply installs the stance", rc == 0, out)
    check("...and says, per port, that it accepts no advertisement",
          "wan0 accepts no router advertisement" in out and
          "lan0 accepts no router advertisement" in out, out)
    check("the sysctl artifact was written",
          os.path.exists(sysctl_path))

    _, live = nsrun(APPLIANCE_NS,
                    "sysctl -n net.ipv6.conf.%s.accept_ra" % WAN_IF)
    check("the stance is live in the kernel, not only on disk",
          live.strip() == "0", live)
    _, fwd = nsrun(APPLIANCE_NS,
                   "sysctl -n net.ipv6.conf.all.forwarding")
    check("no zone asks for v6, so the box is not a v6 router",
          fwd.strip() == "0", fwd)

    wan_before = ra_counter(APPLIANCE_NS, WAN_IF)
    client_before = ra_counter(TESTNET_NS, TESTNET_IF)
    rc, out = inject(args.injector)
    check("the same advertisements are sent again", rc == 0, out)
    time.sleep(2.5)
    wan_after = ra_counter(APPLIANCE_NS, WAN_IF)
    client_after = ra_counter(TESTNET_NS, TESTNET_IF)
    wan_addrs = global_v6(APPLIANCE_NS, WAN_IF)
    client_addrs = global_v6(TESTNET_NS, TESTNET_IF)
    print("  gate: wan0 ras %d->%d addrs=%s | tn0 ras %d->%d addrs=%s"
          % (wan_before, wan_after, wan_addrs, client_before,
             client_after, client_addrs))

    # The load-bearing pair. Either half alone is worthless: a moved
    # counter with no address is the gate holding; a still counter
    # with no address is a frame that never arrived.
    check("GATE: the advertisements DID arrive at the uplink",
          wan_after - wan_before == RA_COUNT,
          "counter went %d -> %d, expected +%d"
          % (wan_before, wan_after, RA_COUNT))
    check("GATE: THE UPLINK DID NOT AUTOCONFIGURE",
          not has_prefix(wan_addrs, RA_PREFIX), str(wan_addrs))
    check("GATE: THE RA NEVER REACHED THE TESTNET",
          client_after == client_before,
          "tn0 RA counter %d -> %d" % (client_before, client_after))
    check("GATE: THE TESTNET CLIENT DID NOT AUTOCONFIGURE",
          not has_prefix(client_addrs, RA_PREFIX),
          str(client_addrs))

    # ---- the refusal is visible ------------------------------------
    rc, out = sysconf("status")
    check("status reports the advertisements it refused",
          "router advertisement(s) arrived" in out and
          "were refused" in out, out)
    check("...and names the count it actually saw",
          str(wan_after) in out, out)
    check("...and does not claim a clean exit is proof",
          "quiet network" not in out or "not proof" in out, out)

    # ---- 4. THE VIOLATION IS LOUD ----------------------------------
    # Somebody, or something, puts accept_ra back. The stance is now
    # being violated on a live box and the only thing standing between
    # that and a silent bypass is whether we say so.
    nsrun(APPLIANCE_NS,
          "sysctl -qw net.ipv6.conf.%s.accept_ra=1" % WAN_IF)
    nsrun(APPLIANCE_NS,
          "sysctl -qw net.ipv6.conf.%s.autoconf=1" % WAN_IF)
    nsrun(APPLIANCE_NS,
          "sysctl -qw net.ipv6.conf.%s.accept_ra_pinfo=1" % WAN_IF)
    inject(args.injector)
    time.sleep(2.5)
    wan_addrs = global_v6(APPLIANCE_NS, WAN_IF)
    check("a port whose accept_ra was put back does autoconfigure "
          "(the violation is real, not simulated)",
          has_prefix(wan_addrs, RA_PREFIX), str(wan_addrs))

    rc, out = sysconf("status")
    check("VIOLATION: the box says the stance is being violated",
          "IPv6 STANCE VIOLATED" in out, out)
    check("...and names the port and the address",
          "wan0" in out and "2001:0db8" in out, out)
    check("...and exits non-zero so a script notices",
          rc == 5, "rc=%d\n%s" % (rc, out))

    # ---- re-applying puts it back ----------------------------------
    rc, out = sysconf("apply")
    check("re-applying the stance succeeds", rc == 0, out)
    _, live = nsrun(APPLIANCE_NS,
                    "sysctl -n net.ipv6.conf.%s.accept_ra" % WAN_IF)
    check("...and the port refuses advertisements again",
          live.strip() == "0", live)

  finally:
    teardown()

  print("\n%d passed, %d failed" % (PASS, FAIL))
  return 1 if FAIL else 0


if __name__ == "__main__":
  sys.exit(main())
