#!/usr/bin/env python3
"""Green while broken, against a real dnsmasq under a real systemd.

Five of the twenty-three rehearsal findings were one defect: the CLI
restating intent instead of observing reality. A column re-derived from
the model that generated the config can only ever agree with it, so it
is structurally incapable of reporting the thing it appears to report.

Nothing here can be proved with fixtures, because the whole claim is
about the world:

  1. `interface=lan0` naming a port that does not exist. dnsmasq starts
     cleanly, systemd says `active`, DNS lands on 127.0.0.1 and DHCP on
     the wildcard socket. `show services` must NOT say it answers on
     lan0 — it must say where it actually is, and say the two disagree.
  2. The same box with lan0 present. Now it must say lan0, and the two
     runs must not print the same thing.
  3. The port present under its kernel name, pinned by MAC to another:
     `show system` PRESENT must read the rename as pending, not `no`.
  4. `apply system` must state a pending rename and give the recovery.
  5. A stale `10-f-<old>.link` must be removed by an apply, because
     udev applies .link units in filename order and the leftover wins.
  6. `stop-dns-rebind` must make an internal, private-addressed name
     resolve to an empty answer — the behaviour the default now
     refuses — and the default must resolve it.

Run on the target, as root:
  sudo ./test_service_binding.py --einheit-f /path/to/einheit-f \\
      --unit-dir /path/to/deploy/systemd
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

os.environ["PATH"] = os.environ.get("PATH", "") + ":/usr/sbin:/sbin"

PASS = 0
FAIL = 0

LAN_IF = "lan0"
KERNEL_IF = "enp9s0f1"
PEER_IF = "tnpeer"
LAN_MAC = "52:54:00:f2:00:01"
LAN_ADDR = "10.10.0.1/24"
UPSTREAM_ADDR = "127.0.0.2"
# The model's `upstream:` takes a bare address, so dnsmasq forwards
# to port 53. The stand-in office resolver has to be there.
UPSTREAM_PORT = 53
INTERNAL_NAME = "intranet.corp"
INTERNAL_ADDR = "10.99.82.9"

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
  dns:
    - zone: testnet
      upstream: [%s]
%%s
""" % (LAN_MAC, UPSTREAM_ADDR)


def check(desc, cond, detail=""):
  global PASS, FAIL
  if cond:
    PASS += 1
    print("PASS  %s" % desc)
  else:
    FAIL += 1
    print("FAIL  %s" % desc)
    if detail:
      text = detail if len(detail) < 900 else detail[:900] + "..."
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
  quiet("systemctl stop f-dnsmasq.service")
  quiet("pkill -f 'dnsmasq.*%s'" % UPSTREAM_ADDR)
  quiet("ip link del %s" % LAN_IF)
  quiet("ip link del %s" % KERNEL_IF)
  quiet("ip link del %s" % PEER_IF)
  time.sleep(0.3)


def make_port(name):
  """A veth pair whose near end carries the pinned MAC and address."""
  quiet("ip link del %s" % name)
  quiet("ip link del %s" % PEER_IF)
  run(["ip", "link", "add", name, "address", LAN_MAC, "type", "veth",
       "peer", "name", PEER_IF], check_rc=True)
  run(["ip", "link", "set", name, "up"], check_rc=True)
  run(["ip", "link", "set", PEER_IF, "up"], check_rc=True)
  run(["ip", "addr", "add", LAN_ADDR, "dev", name], check_rc=True)
  time.sleep(0.5)


def start_upstream(work):
  """A resolver that answers an internal name with a private address.

  This is the office file server, in one line of config. dnsmasq's own
  `address=` answers are local and not subject to the rebind check; the
  appliance forwarding to *this* process is, which is the real path.
  """
  conf = os.path.join(work, "upstream.conf")
  with open(conf, "w") as f:
    f.write("port=%d\n" % UPSTREAM_PORT)
    f.write("listen-address=%s\n" % UPSTREAM_ADDR)
    f.write("bind-interfaces\n")
    f.write("no-resolv\n")
    f.write("no-hosts\n")
    f.write("address=/%s/%s\n" % (INTERNAL_NAME, INTERNAL_ADDR))
  handle = subprocess.Popen(
      ["/usr/sbin/dnsmasq", "--keep-in-foreground",
       "--conf-file=" + conf, "--pid-file="],
      stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
  time.sleep(1.0)
  return handle


def resolve(name, server, port=53):
  rc, out = run(["host", "-W", "3", "-p", str(port), name, server])
  return rc, out


class Cli(object):
  def __init__(self, binary, work):
    self.binary = binary
    self.model = "/etc/f/system.yaml"
    self.generated = "/etc/f/generated/dnsmasq.conf"
    self.networkd = os.path.join(work, "networkd")
    self.leases = os.path.join(work, "dnsmasq.leases")
    self.journal = os.path.join(work, "devices.json")
    os.makedirs(self.networkd, exist_ok=True)
    os.makedirs("/etc/f/generated", exist_ok=True)

  def argv(self, *args):
    return [self.binary, "--color", "never", "--width", "200",
            "--system-config", self.model,
            "--lease-file", self.leases,
            "--device-journal", self.journal,
            "--dnsmasq-conf", self.generated,
            "--networkd-dir", self.networkd] + list(args)

  def text(self, *args):
    _, out = run(self.argv(*args))
    return out

  def rows(self, *args):
    """Every JSON table the command emitted, flattened."""
    p = subprocess.run(self.argv("--format", "json", *args),
                       capture_output=True, text=True)
    out = []
    for block in p.stdout.split("\n\n"):
      block = block.strip()
      if not block:
        continue
      try:
        parsed = json.loads(block)
      except ValueError:
        continue
      if isinstance(parsed, list):
        out.extend(parsed)
    return out

  def write_model(self, extra=""):
    with open(self.model, "w") as f:
      f.write(MODEL % extra)


def install_unit(unit_dir):
  src = os.path.join(unit_dir, "f-dnsmasq.service")
  if not os.path.exists(src):
    raise RuntimeError("no f-dnsmasq.service under %s" % unit_dir)
  shutil.copy(src, "/etc/systemd/system/f-dnsmasq.service")
  run(["systemctl", "daemon-reload"], check_rc=True)


def restart_service():
  quiet("systemctl reset-failed f-dnsmasq.service")
  run(["systemctl", "restart", "f-dnsmasq.service"])
  time.sleep(1.5)


def service_row(cli):
  for row in cli.rows("show", "services"):
    if "dnsmasq" in str(row.get("SERVICE", "")):
      return row
  return {}


def main():
  ap = argparse.ArgumentParser()
  ap.add_argument("--einheit-f", required=True)
  ap.add_argument("--unit-dir", required=True)
  args = ap.parse_args()

  if os.geteuid() != 0:
    print("must run as root: /proc/<pid>/fd is how the binding is "
          "observed, and that is exactly the read a non-root CLI "
          "cannot make")
    return 2

  teardown()
  work = tempfile.mkdtemp(prefix="f-binding-")
  cli = Cli(args.einheit_f, work)
  upstream = None
  try:
    install_unit(args.unit_dir)
    upstream = start_upstream(work)
    rc, out = resolve(INTERNAL_NAME, UPSTREAM_ADDR, UPSTREAM_PORT)
    check("control: the upstream really answers the internal name",
          INTERNAL_ADDR in out, out)

    # -- 1. the config names a port that does not exist ---------------
    cli.write_model()
    applied = cli.text("apply", "system")
    check("apply writes the dnsmasq artifact",
          os.path.exists(cli.generated), applied)
    conf = open(cli.generated).read()
    check("the artifact names lan0", "interface=lan0" in conf, conf)
    restart_service()
    _, active = run(["systemctl", "is-active", "f-dnsmasq.service"])
    check("systemd calls the unit active with no port to bind to",
          active.strip() == "active", active)

    blind = cli.text("show", "services")
    blind_row = service_row(cli)
    answers_blind = str(blind_row.get("ANSWERS ON", ""))
    check("ANSWERS ON does not claim lan0 when lan0 does not exist",
          "lan0" not in answers_blind, blind)
    check("...and says where it actually is",
          "LOOPBACK" in answers_blind.upper(), blind)
    check("...and the disagreement is spelled out",
          "answering nobody" in blind, blind)

    # -- 2. the same box, with the port present -----------------------
    make_port(LAN_IF)
    restart_service()
    bound = cli.text("show", "services")
    bound_row = service_row(cli)
    check("ANSWERS ON is lan0 once lan0 exists",
          "lan0" in str(bound_row.get("ANSWERS ON", "")), bound)
    check("the two runs do not print the same thing",
          answers_blind != str(bound_row.get("ANSWERS ON", "")),
          "%r vs %r" % (answers_blind,
                        bound_row.get("ANSWERS ON", "")))
    check("a bound service is not reported as a mismatch",
          "answering nobody" not in bound, bound)

    # -- 3. present, correctly identified, under another name ---------
    quiet("ip link del %s" % LAN_IF)
    make_port(KERNEL_IF)
    sysrows = cli.rows("show", "system")
    iface = [r for r in sysrows
             if r.get("INTERFACE") == LAN_IF]
    check("show system has a row for the configured interface",
          bool(iface), json.dumps(sysrows))
    present = str(iface[0].get("PRESENT", "")) if iface else ""
    check("PRESENT reads a pending rename, not 'no'",
          "pending" in present.lower(), present)
    check("...and names the port it is looking at",
          KERNEL_IF in present, present)

    # -- 4. apply must say the rename has not happened ----------------
    applied = cli.text("apply", "system")
    check("apply states the pending rename",
          "PENDING RENAME" in applied, applied)
    check("...and gives the recovery, which is not 'edit the file'",
          "udevadm trigger --action=add" in applied, applied)

    # -- 5. the stale unit an earlier name left behind ----------------
    stale = os.path.join(cli.networkd, "10-f-%s.link" % KERNEL_IF)
    body = ("[Match]\nMACAddress=%s\n\n[Link]\nName=%s\n"
            "NamePolicy=\n" % (LAN_MAC, KERNEL_IF))
    # Written the way a previous apply would have written it: with the
    # digest header that marks it as ours to remove.
    with open(stale, "w") as f:
      f.write("# model-digest: %s\n\n%s" % (fnv1a64(body), body))
    applied = cli.text("apply", "system")
    check("the stale .link is removed",
          not os.path.exists(stale), applied)
    check("...and the removal is named, not silent",
          "removed" in applied and "10-f-%s.link" % KERNEL_IF
          in applied, applied)

    # -- 6. rebind protection, both ways ------------------------------
    quiet("ip link del %s" % KERNEL_IF)
    make_port(LAN_IF)
    cli.write_model()
    cli.text("apply", "system")
    restart_service()
    rc, out = resolve(INTERNAL_NAME, "10.10.0.1")
    check("default: an internal, private-addressed name resolves",
          INTERNAL_ADDR in out, out)

    cli.write_model("      stop_dns_rebind: true\n")
    cli.text("apply", "system")
    restart_service()
    rc, out = resolve(INTERNAL_NAME, "10.10.0.1")
    check("with protection on, the same name resolves to nothing",
          INTERNAL_ADDR not in out, out)
    _, jrnl = run(["journalctl", "-u", "f-dnsmasq.service",
                   "-n", "50", "--no-pager", "-o", "cat"])
    check("...and the only trace is the journal line nobody reads",
          "rebind" in jrnl.lower(), jrnl)
    services = cli.text("show", "services")
    check("show services states the stance so the operator can find it",
          "rebind protection is ON" in services, services)

    cli.write_model("      stop_dns_rebind: true\n"
                    "      rebind_ok: [corp]\n")
    cli.text("apply", "system")
    restart_service()
    rc, out = resolve(INTERNAL_NAME, "10.10.0.1")
    check("an exempted domain resolves again with protection on",
          INTERNAL_ADDR in out, out)
  finally:
    if upstream is not None:
      upstream.terminate()
    teardown()
    shutil.rmtree(work, ignore_errors=True)

  print("\n%d passed, %d failed" % (PASS, FAIL))
  return 1 if FAIL else 0


def fnv1a64(body):
  """The same digest the C++ side writes, so a file we fabricate here
  is recognised as one of ours."""
  h = 1469598103934665603
  for byte in body.encode():
    h ^= byte
    h = (h * 1099511628211) & 0xFFFFFFFFFFFFFFFF
  return "%016x" % h


if __name__ == "__main__":
  sys.exit(main())
