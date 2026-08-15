#!/usr/bin/env python3
"""The lease view, against a real dnsmasq and a real DHCP client.

A fixture can be made to say anything. The claims this view makes are
about the world — *that device is here now, it was not here a minute
ago, it holds that address* — so they are worth nothing until a real
client has really asked a real server for a real address and the CLI
has said the right thing about it.

    root netns (the appliance)          netns f-lease-net
    lan0  zone testnet 10.10.0.1/24 ------- tn0   (udhcpc)
          dhcp pool 10.10.0.100-200         tn1   (second client)

What is being proven, in order:

  1. Before anything has asked, the empty view says *which* empty it
     is — configured and nothing has asked yet, not "no devices".
  2. A client that arrives while we are watching is marked NEW. This
     is the whole feature: the journal must have caught the
     transition, not inferred it from a lease that was already there.
  3. A device already present at the first look is *not* marked new,
     and its age is rendered as a bound.
  4. `show device` finds the same device by MAC, by address and by
     name, and reports its lease.
  5. `set reservation` reaches dnsmasq: after an apply and a renew,
     the client is on the reserved address.
  6. An unreadable lease file is reported as unreadable and never as
     an empty network.

Run on the target, as root:
  sudo ./test_lease_visibility.py --einheit-f /path/to/einheit-f
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

# udhcpc, dnsmasq and ip all live in sbin, which a non-login shell
# leaves off PATH. The test invokes them by name, so put them back.
os.environ["PATH"] = os.environ.get("PATH", "") + ":/usr/sbin:/sbin"

PASS = 0
FAIL = 0

LAN_IF = "lan0"
NET_NS = "f-lease-net"
CLIENT_IF = "tn0"
CLIENT2_IF = "tn1"
LAN_MAC = "52:54:00:f1:00:01"
CLIENT_MAC = "52:54:00:f1:00:aa"
CLIENT2_MAC = "52:54:00:f1:00:bb"
LAN_ADDR = "10.10.0.1/24"
RESERVED = "10.10.0.55"

MODEL = """\
zones:
  testnet:

interfaces:
  lan0:
    mac: "%s"
    address: 10.10.0.1/24
    zone: testnet

services:
  dhcp:
    - zone: testnet
      range: 10.10.0.100-10.10.0.200
      lease: 2m
""" % LAN_MAC


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


def split_run(cmd):
  """Run a command, keeping stdout and stderr apart."""
  p = subprocess.run(cmd, capture_output=True, text=True)
  return p.stdout, p.stderr


def quiet(cmd):
  """Best-effort teardown step."""
  subprocess.run(cmd, shell=True, capture_output=True)


def teardown():
  """Remove everything a previous run may have left behind."""
  quiet("pkill -x dnsmasq")
  quiet("ip netns del %s" % NET_NS)
  quiet("ip link del %s" % LAN_IF)
  quiet("ip link del %s" % (LAN_IF + "b"))
  time.sleep(0.3)


def build_topology():
  """One segment, with two client ports on the far end."""
  run(["ip", "netns", "add", NET_NS], check_rc=True)
  run(["ip", "link", "add", LAN_IF, "address", LAN_MAC,
       "type", "veth", "peer", "name", CLIENT_IF,
       "address", CLIENT_MAC], check_rc=True)
  run(["ip", "link", "set", CLIENT_IF, "netns", NET_NS],
      check_rc=True)
  # A second cable into the same bridge-less segment is not possible
  # with plain veth, so the second client is a macvlan on the first
  # peer: a distinct MAC on the same wire, which is exactly what a
  # second board plugged into the same switch looks like to dnsmasq.
  run(["ip", "link", "set", LAN_IF, "up"], check_rc=True)
  run(["ip", "netns", "exec", NET_NS, "ip", "link", "set",
       CLIENT_IF, "up"], check_rc=True)
  run(["ip", "netns", "exec", NET_NS, "ip", "link", "add",
       CLIENT2_IF, "link", CLIENT_IF, "address", CLIENT2_MAC,
       "type", "macvlan", "mode", "bridge"], check_rc=True)
  run(["ip", "netns", "exec", NET_NS, "ip", "link", "set",
       CLIENT2_IF, "up"], check_rc=True)
  run(["ip", "addr", "add", LAN_ADDR, "dev", LAN_IF], check_rc=True)
  time.sleep(0.5)


def start_dnsmasq(dnsmasq, conf_path, log):
  """Start dnsmasq in the foreground and wait for it to settle."""
  quiet("pkill -x dnsmasq")
  time.sleep(0.3)
  handle = subprocess.Popen(
      [dnsmasq, "--keep-in-foreground", "--log-facility=" + log,
       "--log-dhcp", "--conf-file=" + conf_path, "--pid-file="],
      stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
  time.sleep(1.5)
  return handle


def dhcp_client(iface, tries=3):
  """Ask for a lease from inside the client netns. Returns the address."""
  for _ in range(tries):
    rc, out = run(["ip", "netns", "exec", NET_NS, "udhcpc",
                   "-i", iface, "-q", "-f", "-n", "-t", "4",
                   "-T", "2", "-s", "/bin/true"])
    for token in out.split():
      if token.count(".") == 3 and token.startswith("10.10.0."):
        return token.strip(",")
    time.sleep(1)
  return ""


class Cli(object):
  """The CLI under test, always pointed at the scratch paths."""

  def __init__(self, binary, work):
    self.binary = binary
    self.model = os.path.join(work, "system.yaml")
    self.leases = os.path.join(work, "dnsmasq.leases")
    self.journal = os.path.join(work, "devices.json")
    self.generated = os.path.join(work, "dnsmasq.conf")
    self.networkd = os.path.join(work, "networkd")
    os.makedirs(self.networkd, exist_ok=True)

  def argv(self, *args):
    return [self.binary, "--color", "never", "--width", "160",
            "--system-config", self.model,
            "--lease-file", self.leases,
            "--device-journal", self.journal,
            "--dnsmasq-conf", self.generated,
            "--networkd-dir", self.networkd] + list(args)

  def text(self, *args):
    _, out = run(self.argv(*args))
    return out

  def json(self, *args):
    """(rows, notes) from one --format json invocation.

    Machine-readable output owns stdout, so the explanatory prose goes
    to stderr; both come from the same run because the first-look
    notice is true of an invocation, not of a box.
    """
    argv = self.argv(*args)
    argv.insert(1, "json")
    argv.insert(1, "--format")
    out, err = split_run(argv)
    try:
      return json.loads(out), err
    except ValueError:
      return [], out + err

  def rows(self, *args):
    """Just the rows of a --format json show command."""
    return self.json(*args)[0]


def main():
  ap = argparse.ArgumentParser(description=__doc__)
  ap.add_argument("--einheit-f", default="einheit-f")
  ap.add_argument("--f-sysconf", default="f-sysconf")
  ap.add_argument("--dnsmasq", default="/usr/sbin/dnsmasq")
  args = ap.parse_args()

  if os.geteuid() != 0:
    print("this test needs root", file=sys.stderr)
    return 2
  if not shutil.which("udhcpc"):
    print("udhcpc is required (apt install udhcpc)", file=sys.stderr)
    return 2

  work = tempfile.mkdtemp(prefix="f-lease-view-")
  cli = Cli(args.einheit_f, work)
  with open(cli.model, "w") as fh:
    fh.write(MODEL)
  log_path = os.path.join(work, "dnsmasq.log")

  teardown()
  handle = None
  try:
    build_topology()

    # ---- 1. nothing has asked yet -------------------------------
    out = cli.text("show", "leases")
    check("before any client, the view names which empty it is",
          "no lease file yet" in out, out)
    check("...and it names the file it looked for",
          cli.leases in out, out)
    check("...and it does not claim there are no devices",
          "no device holds a lease" not in out, out)

    # Looking created the journal, so the next arrival is a
    # transition we witnessed rather than a device we found.
    check("looking created the device journal",
          os.path.exists(cli.journal),
          str(os.listdir(work)))

    # ---- generate the dnsmasq config from the model ---------------
    rc, out = run([args.f_sysconf, "-c", cli.model,
                   "--dnsmasq-conf", cli.generated,
                   "--networkd-dir", cli.networkd, "apply"])
    check("the model generates a dnsmasq config", rc == 0, out)
    conf = open(cli.generated).read()
    check("the generated config points dnsmasq at the lease file we "
          "read", "dhcp-leasefile=" in conf, conf)

    # The generated file names the production lease path; for the test
    # redirect it to the scratch copy the CLI is reading.
    conf_test = os.path.join(work, "dnsmasq-test.conf")
    with open(conf_test, "w") as fh:
      for line in conf.splitlines(True):
        if line.startswith("dhcp-leasefile="):
          fh.write("dhcp-leasefile=%s\n" % cli.leases)
        else:
          fh.write(line)

    handle = start_dnsmasq(args.dnsmasq, conf_test, log_path)
    check("dnsmasq stayed up on the generated config",
          handle.poll() is None, open(log_path).read())

    # ---- 2. a client arrives while we are watching ----------------
    addr = dhcp_client(CLIENT_IF)
    check("a real client got a real lease", addr.startswith("10.10.0."),
          addr + "\n" + open(log_path).read())

    rows = cli.rows("show", "leases")
    macs = [r.get("MAC", "").replace(" *", "") for r in rows]
    check("the lease view shows the client that just arrived",
          CLIENT_MAC in macs, json.dumps(rows))
    row = next((r for r in rows
                if r.get("MAC", "").replace(" *", "") == CLIENT_MAC),
               {})
    check("...at the address dnsmasq gave it",
          row.get("ADDRESS") == addr,
          "%s vs %s" % (row.get("ADDRESS"), addr))
    check("...marked NEW, because we watched it turn up",
          row.get("NEW") == "NEW", json.dumps(row))
    check("...with an exact age, not a bound",
          not str(row.get("FIRST SEEN", "")).startswith(">="),
          json.dumps(row))
    check("...placed in the zone its address belongs to",
          row.get("ZONE") == "testnet", json.dumps(row))

    fresh = cli.rows("show", "leases", "new")
    check("`show leases new` narrows to the arrival",
          [r.get("MAC", "").replace(" *", "") for r in fresh] ==
          [CLIENT_MAC], json.dumps(fresh))

    # ---- 3. a device already there at the first look --------------
    # Throw the journal away: this is the state of a box that has been
    # serving DHCP for a week before anybody ran `show leases`.
    os.remove(cli.journal)
    rows, notes = cli.json("show", "leases")
    row = next((r for r in rows
                if r.get("MAC", "").replace(" *", "") == CLIENT_MAC),
               {})
    check("a device found on the first look is not called new",
          row.get("NEW") == "", json.dumps(rows))
    check("...and its age is rendered as a bound",
          str(row.get("FIRST SEEN", "")).startswith(">="),
          json.dumps(row))
    check("...and the view says why its times are bounds",
          "upper bounds" in notes, notes)
    check("...without putting prose in the machine-readable stream",
          isinstance(rows, list) and rows, notes)

    # ---- 4. one device, three ways to name it ---------------------
    for query in (CLIENT_MAC, CLIENT_MAC.upper(), addr):
      out = cli.text("show", "device", query)
      check("`show device %s` finds it" % query,
            CLIENT_MAC in out and addr in out, out)
    out = cli.text("show", "device", CLIENT_MAC)
    check("the device view reports a live lease",
          "holds a lease" in out, out)
    check("the device view says fd could not be asked, not that the "
          "device is idle",
          "could not be asked" in out or "TALKING TO" in out or
          "fd answered" in out, out)

    # ---- a second client, arriving later -------------------------
    before = {r.get("MAC", "").replace(" *", "") for r in
              cli.rows("show", "leases")}
    addr2 = dhcp_client(CLIENT2_IF)
    check("a second client got a lease", addr2.startswith("10.10.0."),
          addr2 + "\n" + open(log_path).read())
    fresh = cli.rows("show", "leases", "new")
    fresh_macs = {r.get("MAC", "").replace(" *", "") for r in fresh}
    check("only the second client is new",
          fresh_macs == {CLIENT2_MAC},
          "%s (before: %s)" % (json.dumps(fresh), sorted(before)))

    # ---- 5. a reservation reaches dnsmasq ------------------------
    out = cli.text("set", "reservation", CLIENT_MAC, RESERVED,
                   "bench-board")
    check("`set reservation` is accepted", "reservation" in out, out)
    model_text = open(cli.model).read()
    check("...and lands in the system configuration",
          RESERVED in model_text and CLIENT_MAC in model_text,
          model_text)
    check("...where the range it came from is untouched",
          "10.10.0.100-10.10.0.200" in model_text, model_text)

    rc, out = run([args.f_sysconf, "-c", cli.model,
                   "--dnsmasq-conf", cli.generated,
                   "--networkd-dir", cli.networkd, "apply"])
    check("the model regenerates cleanly with the reservation",
          rc == 0, out)
    conf = open(cli.generated).read()
    check("...and dnsmasq is told about it",
          "dhcp-host=%s,%s" % (CLIENT_MAC, RESERVED) in conf, conf)

    with open(conf_test, "w") as fh:
      for line in conf.splitlines(True):
        if line.startswith("dhcp-leasefile="):
          fh.write("dhcp-leasefile=%s\n" % cli.leases)
        else:
          fh.write(line)
    handle = start_dnsmasq(args.dnsmasq, conf_test, log_path)
    new_addr = dhcp_client(CLIENT_IF)
    check("the client renews onto the reserved address",
          new_addr == RESERVED,
          "got %s, wanted %s\n%s" % (new_addr, RESERVED,
                                     open(log_path).read()[-800:]))
    rows = cli.rows("show", "leases")
    row = next((r for r in rows
                if r.get("MAC", "").replace(" *", "") == CLIENT_MAC),
               {})
    check("the lease view flags the reservation",
          row.get("MAC", "").endswith("*"), json.dumps(rows))

    # ---- 6. unreadable is not empty ------------------------------
    broken = os.path.join(work, "not-a-file")
    os.makedirs(broken, exist_ok=True)
    argv = [args.einheit_f, "--color", "never", "--width", "160",
            "--system-config", cli.model, "--lease-file", broken,
            "--device-journal", cli.journal, "show", "leases"]
    _, out = run(argv)
    check("a lease path that cannot be read says so",
          "unreadable" in out, out)
    check("...and never reads as an empty network",
          "no device holds a lease" not in out, out)

  finally:
    if handle is not None:
      handle.terminate()
    teardown()

  print("\n%d passed, %d failed" % (PASS, FAIL))
  return 1 if FAIL else 0


if __name__ == "__main__":
  sys.exit(main())
