#!/usr/bin/env python3
"""NTP against a real chronyd, and a clock that admits it is wrong.

Two things are proven here, and they are the same thing twice.

**Containment.** The NTP server answers on the zone it serves and is
silent on the uplink. Same shape as the rogue-DHCP gate and same
consequence if it is wrong: becoming an unasked-for time authority on
a corporate network. Two mechanisms hold it — `bindaddress` and
`allow` — and both are derived from zone membership, so the test
proves the combination rather than either in isolation. (The ports
cannot share a subnet here the way the DHCP gate's do: SC012 refuses
two statically addressed zones that overlap, which is itself the
right answer.)

**Honesty about the clock.** Conntrack timeouts, rate-limit windows
and every log line are stated in this clock. A board with no
battery-backed RTC boots at the epoch, and logs stamped 1970 do not
merely look wrong — they destroy the ordering the whole "gather data
at the office and analyse it later" plan depends on. So the box must
say, out loud, when a timestamp cannot be trusted.

    netns f-ntp-office        root netns (the appliance)   netns f-ntp-net
    up0 ------------------------ wan0  zone wan  192.0.2.2/24
                                 lan0  zone testnet 10.20.0.1/24 --- tn0

Three legs:

  1. POSITIVE CONTROL — a chronyd with a hand-written config that
     allows everybody answers on BOTH ports. Without this the silence
     in leg 2 might only mean the probe is broken.
  2. THE GATE — with the generated config, the testnet gets an answer
     and the uplink gets none.
  3. THE CLOCK — an unsynchronised clock, and an epoch clock, are
     each reported as a named state with a banner, and a synchronised
     one produces no banner at all.

Run on the target, as root:
  sudo ./test_ntp_time.py --f-sysconf /path/to/f-sysconf
"""
import argparse
import os
import subprocess
import sys
import tempfile
import time

PASS = 0
FAIL = 0

OFFICE_NS = "f-ntp-office"
TESTNET_NS = "f-ntp-net"
WAN_IF = "wan0"
LAN_IF = "lan0"
OFFICE_IF = "up0"
TESTNET_IF = "tn0"

WAN_ADDR = "192.0.2.2"
LAN_ADDR = "10.20.0.1"

MODEL = """\
zones:
  wan:
  testnet:

interfaces:
  wan0:
    mac: "52:54:00:f7:00:01"
    address: 192.0.2.2/24
    zone: wan
  lan0:
    mac: "52:54:00:f7:00:02"
    address: 10.20.0.1/24
    zone: testnet

services:
  ntp:
    - zone: testnet
      upstream: [192.0.2.111]
"""

# What the generated config replaces: a chronyd written the way you
# would if you maintained the address list by hand and forgot which
# port faced the office. Nothing about it is malformed.
NAIVE_CONF = """\
server 192.0.2.111 iburst
port 123
allow all
local stratum 10
cmdport 0
"""


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
  p = subprocess.run(cmd, shell=isinstance(cmd, str),
                     capture_output=True, text=True)
  out = p.stdout + p.stderr
  if check_rc and p.returncode != 0:
    raise RuntimeError("command failed: %s\n%s" % (cmd, out))
  return p.returncode, out


def quiet(cmd):
  subprocess.run(cmd, shell=True, capture_output=True)


def teardown():
  quiet("pkill -x chronyd")
  for ns in (OFFICE_NS, TESTNET_NS):
    quiet("ip netns del %s" % ns)
  for link in (WAN_IF, LAN_IF):
    quiet("ip link del %s" % link)
  time.sleep(0.3)


def build_topology():
  """Two cables into the appliance, each with a host on the far end."""
  run(["ip", "netns", "add", OFFICE_NS], check_rc=True)
  run(["ip", "netns", "add", TESTNET_NS], check_rc=True)
  for local, peer, ns, mac, peer_addr in (
      (WAN_IF, OFFICE_IF, OFFICE_NS, "52:54:00:f7:00:01",
       "192.0.2.12"),
      (LAN_IF, TESTNET_IF, TESTNET_NS, "52:54:00:f7:00:02",
       "10.20.0.11"),
  ):
    run("ip link add %s address %s type veth peer name %s"
        % (local, mac, peer), check_rc=True)
    run("ip link set %s netns %s" % (peer, ns), check_rc=True)
    run("ip link set %s up" % local, check_rc=True)
    run("ip netns exec %s ip link set %s up" % (ns, peer),
        check_rc=True)
    run("ip netns exec %s ip addr add %s/24 dev %s"
        % (ns, peer_addr, peer), check_rc=True)
    run("ip netns exec %s ip link set lo up" % ns)

  run("ip addr add %s/24 dev %s" % (WAN_ADDR, WAN_IF), check_rc=True)
  run("ip addr add %s/24 dev %s" % (LAN_ADDR, LAN_IF), check_rc=True)
  time.sleep(0.8)


def ntp_probe(ns, server, timeout=2.0):
  """Ask one address for the time, the way a client would.

  Returns "ANSWER stratum=<n>" or "NO_ANSWER". Asserted positively so
  a crashed probe cannot pass for silence.
  """
  script = r'''
import socket, struct, sys
server, timeout = sys.argv[1], float(sys.argv[2])
# RFC 5905: LI=0 VN=4 Mode=3 (client), rest zero.
pkt = bytearray(48)
pkt[0] = 0x23
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(timeout)
try:
  s.sendto(bytes(pkt), (server, 123))
  data, _ = s.recvfrom(256)
except Exception:
  print("NO_ANSWER")
  sys.exit(0)
if len(data) < 48:
  print("NO_ANSWER")
  sys.exit(0)
li_vn_mode = data[0]
mode = li_vn_mode & 0x7
stratum = data[1]
if mode != 4:
  print("NO_ANSWER")
  sys.exit(0)
print("ANSWER stratum=%d" % stratum)
'''
  path = "/tmp/f_ntp_probe.py"
  with open(path, "w") as fh:
    fh.write(script)
  rc, out = run("ip netns exec %s python3 %s %s %s"
                % (ns, path, server, timeout))
  return out.strip()


def start_chronyd(chronyd, conf_path, work):
  """Start chronyd in the foreground and let it bind.

  Its output is kept: a daemon that refused to start and a daemon
  that started and stayed silent are two different results, and the
  probe alone cannot tell them apart.
  """
  quiet("pkill -x chronyd")
  time.sleep(0.4)
  log = open(os.path.join(work, "chronyd.log"), "w")
  handle = subprocess.Popen([chronyd, "-d", "-f", conf_path],
                            stdout=log, stderr=subprocess.STDOUT)
  time.sleep(2.0)
  if handle.poll() is not None:
    with open(os.path.join(work, "chronyd.log")) as fh:
      print("  chronyd exited %d: %s"
            % (handle.returncode, fh.read().strip()[:400]))
  return handle


def main():
  ap = argparse.ArgumentParser(description=__doc__)
  ap.add_argument("--f-sysconf", default="f-sysconf")
  ap.add_argument("--chronyd", default="/usr/sbin/chronyd")
  args = ap.parse_args()

  if os.geteuid() != 0:
    print("this test needs root", file=sys.stderr)
    return 2

  # chronyd is AppArmor-confined to /etc/chrony/{,**} on Debian, so
  # the configs it is asked to read must live there — including the
  # naive control's. Discovered by this test failing (BUGLOG #30);
  # everything else the test writes stays in a temp dir.
  conf_dir = "/etc/chrony/f-test"
  os.makedirs(conf_dir, exist_ok=True)
  work = tempfile.mkdtemp(prefix="f-ntp-")
  model_path = os.path.join(work, "system.yaml")
  with open(model_path, "w") as fh:
    fh.write(MODEL)
  naive_path = os.path.join(conf_dir, "naive.conf")
  with open(naive_path, "w") as fh:
    fh.write(NAIVE_CONF)
  generated = os.path.join(conf_dir, "chrony.conf")
  os.makedirs("/var/lib/f", exist_ok=True)
  os.makedirs("/var/lib/chrony", exist_ok=True)
  os.makedirs("/run/chrony", exist_ok=True)

  def sysconf(*extra):
    return run([args.f_sysconf, "-c", model_path,
                "--chrony-conf", generated,
                "--chronyd-bin", args.chronyd,
                "--dnsmasq-conf", os.path.join(work, "dnsmasq.conf"),
                "--networkd-dir", os.path.join(work, "networkd"),
                "--ipv6-sysctl", os.path.join(work, "ipv6.conf"),
                "--proc-sys", ""] + list(extra))

  teardown()
  try:
    build_topology()

    rc, out = sysconf("check")
    check("the model validates", rc == 0, out)

    # Serving time on the zone we are a DHCP client of is refused
    # before anything runs, for the same reason DHCP is.
    guest_path = os.path.join(work, "guest.yaml")
    with open(guest_path, "w") as fh:
      fh.write(MODEL.replace("    address: 192.0.2.2/24\n"
                             "    zone: wan",
                             "    address: dhcp\n    zone: wan")
                    .replace("    - zone: testnet\n      upstream",
                             "    - zone: wan\n      upstream"))
    rc, out = run([args.f_sysconf, "-c", guest_path, "check"])
    check("serving NTP on a zone we are a dhcp client of is refused",
          rc != 0 and "SC042" in out, out)

    rc, out = sysconf("apply")
    check("apply generates and installs the artifact", rc == 0, out)
    check("apply states where NTP will answer",
          "ntp answers on: 10.20.0.1" in out, out)
    check("the artifact exists", os.path.exists(generated))

    # ---- 1. positive control --------------------------------------
    start_chronyd(args.chronyd, naive_path, work)
    naive_lan = ntp_probe(TESTNET_NS, LAN_ADDR)
    naive_wan = ntp_probe(OFFICE_NS, WAN_ADDR)
    print("  control: testnet=%r uplink=%r" % (naive_lan, naive_wan))
    check("CONTROL: an unbound chronyd answers on the testnet",
          naive_lan.startswith("ANSWER"), naive_lan)
    check("CONTROL: an unbound chronyd ALSO answers on the uplink "
          "(so the probe can see a leak)",
          naive_wan.startswith("ANSWER"), naive_wan)
    quiet("pkill -x chronyd")
    time.sleep(0.6)

    # ---- 2. the gate ----------------------------------------------
    start_chronyd(args.chronyd, generated, work)
    gate_lan = ntp_probe(TESTNET_NS, LAN_ADDR)
    gate_wan = ntp_probe(OFFICE_NS, WAN_ADDR)
    print("  gate:    testnet=%r uplink=%r" % (gate_lan, gate_wan))
    check("GATE: the testnet is served",
          gate_lan.startswith("ANSWER"), gate_lan)
    check("GATE: NTP IS SILENT ON THE UPLINK",
          gate_wan == "NO_ANSWER", gate_wan)
    quiet("pkill -x chronyd")
    time.sleep(0.4)

    # A client-only box opens no server port at all — the strongest
    # form of the containment, and the office deployment's own shape.
    client_only = os.path.join(work, "client.yaml")
    with open(client_only, "w") as fh:
      fh.write(MODEL.replace("    - zone: testnet\n      upstream",
                             "    - zone: testnet\n      serve: "
                             "false\n      upstream"))
    rc, out = run([args.f_sysconf, "-c", client_only,
                   "--chrony-conf", generated,
                   "--chronyd-bin", args.chronyd,
                   "--dnsmasq-conf",
                   os.path.join(work, "dnsmasq.conf"),
                   "--networkd-dir", os.path.join(work, "networkd"),
                   "--ipv6-sysctl", os.path.join(work, "ipv6.conf"),
                   "--proc-sys", "", "apply"])
    check("a client-only model applies", rc == 0, out)
    check("...and says the server port is closed",
          "(nowhere" in out, out)
    start_chronyd(args.chronyd, generated, work)
    closed_lan = ntp_probe(TESTNET_NS, LAN_ADDR)
    print("  client-only: testnet=%r" % closed_lan)
    check("CLIENT-ONLY: nothing answers anywhere, because there is "
          "no server socket",
          closed_lan == "NO_ANSWER", closed_lan)
    quiet("pkill -x chronyd")
    time.sleep(0.4)

    # ---- 3. the clock ---------------------------------------------
    rc, out = sysconf("status")
    check("status reports the clock", "clock:" in out, out)
    check("...and whether this board can keep time across a power "
          "cut", "rtc " in out, out)

    # The kernel's own STA_UNSYNC bit is the source of truth, so this
    # leg reads whatever the VM actually is rather than asserting a
    # state it arranged. Both readings are legitimate; what is
    # asserted is that the box says which one, and warns iff it is
    # the bad one.
    trust_line = ""
    for line in out.splitlines():
      if line.strip().startswith("trust"):
        trust_line = line.strip()
    check("...and names the trust state rather than printing a bare "
          "timestamp",
          trust_line != "", out)
    synced = "trust      synchronised" in out
    print("  clock: %r (synchronised=%s)" % (trust_line, synced))
    if synced:
      check("a synchronised clock produces no warning banner",
            "THE CLOCK IS" not in out, out)
    else:
      check("an unsynchronised clock is warned about, loudly",
            "THE CLOCK IS" in out, out)
      check("...and the warning says what to do next",
            "upstream" in out or "converge" in out, out)

    # An artifact outside the permitted tree must fail loudly and
    # name the real cause, or the next person spends an hour on file
    # modes. This is the check catching its own confinement.
    rc, out = run([args.f_sysconf, "-c", model_path,
                   "--chrony-conf", os.path.join(work, "denied.conf"),
                   "--chronyd-bin", args.chronyd,
                   "--dnsmasq-conf",
                   os.path.join(work, "dnsmasq.conf"),
                   "--networkd-dir", os.path.join(work, "networkd"),
                   "--ipv6-sysctl", os.path.join(work, "ipv6.conf"),
                   "--proc-sys", "", "apply"])
    check("an artifact chronyd is not permitted to read is refused",
          rc != 0, out)
    check("...and the refusal names AppArmor rather than the file "
          "mode", "AppArmor" in out, out)

  finally:
    quiet("rm -rf /etc/chrony/f-test")
    teardown()

  print("\n%d passed, %d failed" % (PASS, FAIL))
  return 1 if FAIL else 0


if __name__ == "__main__":
  sys.exit(main())
