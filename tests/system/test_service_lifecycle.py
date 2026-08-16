#!/usr/bin/env python3
"""Who starts the service, against a real systemd and a real dnsmasq.

The finding: a service bound through the CLI was started by nobody.
`set dhcp` edited the model, regenerated `/etc/f/generated/dnsmasq.conf`
and reported success, and `systemctl enable --now` occurred in
`deploy/firstboot/firstboot.py` and nowhere else in the tree — so the
unit set was a snapshot of whatever the model bound at provisioning
time, and the box told the operator otherwise in two places.

The decision taken is that **the apply path owns it**, and everything
below is the evidence, on a box where systemd and dnsmasq are the real
ones. Nothing here can be proved with fixtures, because every claim is
about what a daemon is doing.

Every scenario starts from a KNOWN unit state and asserts a
transition. That is the vacuity guard stated as a method: a scenario
that began with `f-dnsmasq` already running and ended with it running
would be green on the broken box too, and would have proved nothing
about the code that is supposed to start it. So each one is set up by
stopping and disabling the unit first, and the `before` state is
asserted, not assumed.

The five endings, each measured rather than argued:

  1. STARTED       — stopped and disabled, then bound. It runs, it is
                     enabled, and the reply says STARTED.
  2. ALREADY UP    — bound again while running. No command is run, and
                     the reply must NOT say STARTED.
  3. WILL NOT START— something else holds the port. The verb is an
                     ERROR naming systemd's state, and the edit is
                     still on disk.
  4. NOT INSTALLED — the unit file is gone. A different word from
                     `failed`, and nothing is run.
  5. STOPPED       — `no dhcp` on the last binding. The server stops
                     and is disabled, so the box is not still
                     answering DHCP after being told not to.

Run on the target, as root:
  sudo ./test_service_lifecycle.py --einheit-f /usr/local/bin/einheit-f
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

UNIT = "f-dnsmasq.service"
UNIT_PATH = "/usr/lib/systemd/system/f-dnsmasq.service"
LAN_IF = "lan0"
PEER_IF = "slpeer"
LAN_MAC = "52:54:00:f2:00:01"
LAN_ADDR = "10.10.0.1"
DHCP_RANGE = "10.10.0.100-10.10.0.200"

MODEL = """\
zones:
  testnet:

interfaces:
  lan0:
    mac: "%s"
    address: %s/24
    zone: testnet
""" % (LAN_MAC, LAN_ADDR)


def check(desc, cond, detail=""):
  """Record one verdict."""
  global PASS, FAIL
  if cond:
    PASS += 1
    print("PASS  %s" % desc)
  else:
    FAIL += 1
    print("FAIL  %s" % desc)
    if detail:
      text = detail if len(detail) < 1200 else detail[:1200] + "..."
      for line in text.splitlines():
        print("        %s" % line)


def run(cmd, check_rc=False):
  """Run a command and return (rc, combined output)."""
  p = subprocess.run(cmd, shell=isinstance(cmd, str),
                     capture_output=True, text=True)
  out = p.stdout + p.stderr
  if check_rc and p.returncode != 0:
    raise RuntimeError("command failed: %s\n%s" % (cmd, out))
  return p.returncode, out


def quiet(cmd):
  """Run a command and ignore everything about it."""
  subprocess.run(cmd, shell=True, capture_output=True)


def flatten(text):
  """One line, with the error box's rules and borders taken out.

  The CLI wraps an error into a drawn box, so a sentence under test is
  split across lines by border characters. Searching the raw text for
  a phrase would fail on the width of the terminal rather than on
  anything about the box.
  """
  for ch in "\u2502\u256d\u256e\u2570\u256f\u2500":
    text = text.replace(ch, " ")
  return " ".join(text.split())


def unit_property(unit, name):
  """One systemd property, straight from systemctl."""
  _, out = run(["systemctl", "show", unit, "-p", name, "--value"])
  return out.strip()


def unit_state(unit=UNIT):
  """(ActiveState, UnitFileState) — the two facts under test."""
  return (unit_property(unit, "ActiveState"),
          unit_property(unit, "UnitFileState"))


def wait_for(unit, want, timeout=20):
  """Block until a unit reaches an ActiveState, and say what it got."""
  deadline = time.time() + timeout
  state = "(never answered)"
  while time.time() < deadline:
    state = unit_property(unit, "ActiveState")
    if state == want:
      return state
    time.sleep(0.5)
  return state


def make_port():
  """A veth pair whose near end carries the pinned MAC and address."""
  quiet("ip link del %s" % LAN_IF)
  quiet("ip link del %s" % PEER_IF)
  run(["ip", "link", "add", LAN_IF, "address", LAN_MAC, "type",
       "veth", "peer", "name", PEER_IF], check_rc=True)
  run(["ip", "link", "set", LAN_IF, "up"], check_rc=True)
  run(["ip", "link", "set", PEER_IF, "up"], check_rc=True)
  run(["ip", "addr", "add", LAN_ADDR + "/24", "dev", LAN_IF],
      check_rc=True)
  time.sleep(0.5)


class Cli(object):
  """The CLI under test, pointed at a scratch model and artifacts."""

  def __init__(self, binary, work):
    self.binary = binary
    self.model = "/etc/f/system.yaml"
    self.generated = "/etc/f/generated/dnsmasq.conf"
    self.networkd = os.path.join(work, "networkd")
    os.makedirs(self.networkd, exist_ok=True)
    os.makedirs("/etc/f/generated", exist_ok=True)

  def argv(self, *args):
    return [self.binary, "--color", "never", "--width", "200",
            "--system-config", self.model,
            "--dnsmasq-conf", self.generated,
            "--networkd-dir", self.networkd] + list(args)

  def run(self, *args):
    """(rc, text) for the human rendering."""
    return run(self.argv(*args))

  def json(self, *args):
    """The machine document: the rendered table, as FIELD/VALUE rows.

    That is what `--format json` gives for these verbs, and it is the
    right thing to assert on here — it is the surface an operator or a
    script actually reads. The reply's raw per-unit fields are pinned
    in `tests/test_fw_config_verbs.cc`; this file is about the box.
    """
    p = subprocess.run(self.argv("--format", "json", *args),
                       capture_output=True, text=True)
    for block in p.stdout.split("\n\n"):
      block = block.strip()
      if not block:
        continue
      try:
        return p.returncode, json.loads(block)
      except ValueError:
        continue
    return p.returncode, None

  def reset_model(self):
    """A box with a zone and a port and no service bound."""
    with open(self.model, "w") as f:
      f.write(MODEL)


def service_lines(doc, unit=UNIT):
  """Every `service` row of a rendered reply that names `unit`."""
  out = []
  if not isinstance(doc, list):
    return out
  for row in doc:
    if not isinstance(row, dict):
      continue
    if row.get("FIELD") == "service" and unit in (row.get("VALUE")
                                                  or ""):
      out.append(row["VALUE"])
  return out


def service_line(doc, unit=UNIT):
  """The one `service` row for `unit`, or an empty string."""
  lines = service_lines(doc, unit)
  return lines[0] if lines else ""


def stop_and_disable():
  """Put the unit in the state a factory box is in."""
  quiet("systemctl disable --now %s" % UNIT)
  quiet("systemctl reset-failed %s" % UNIT)
  time.sleep(0.5)


# -- the scenarios -----------------------------------------------------


def scenario_started(cli):
  """1. A service bound through the CLI is started, from stopped."""
  print("\n=== 1. bound, and started from stopped ===")
  cli.reset_model()
  stop_and_disable()
  active, enabled = unit_state()
  check("1.before: the unit is not running",
        active in ("inactive", "failed"), "ActiveState=%s" % active)
  check("1.before: the unit is not enabled", enabled != "enabled",
        "UnitFileState=%s" % enabled)

  rc, doc = cli.json("set", "dhcp", "testnet", DHCP_RANGE, "2m")
  check("1: `set dhcp` succeeded", rc == 0, json.dumps(doc, indent=2))

  active, enabled = unit_state()
  check("1: systemd says the unit is active now", active == "active",
        "ActiveState=%s  %s" % (active, unit_property(UNIT,
                                                      "SubState")))
  check("1: and enabled, so it survives a reboot",
        enabled == "enabled", "UnitFileState=%s" % enabled)

  line = service_line(doc)
  check("1: the reply carries a service row for the unit",
        bool(line), json.dumps(doc, indent=2))
  check("1: it says STARTED, which is not `already running`",
        "STARTED" in line, line)
  check("1: and says the state it came from, not just the one it is "
        "in", "was not running" in line, line)

  _, text = cli.run("set", "dns", "testnet", "127.0.0.53")
  check("1: `set dns` on the same unit keeps it up",
        unit_property(UNIT, "ActiveState") == "active", text)

  # The second witness, which reads the kernel rather than the model.
  _, services = cli.run("show", "services")
  check("1: `show services` does not report it STOPPED",
        "STOPPED" not in services, services)
  return services


def scenario_already_running(cli):
  """2. Already running is not the same as started, and says so.

  Two halves, because the reconcile has two answers here and the
  vacuity sweep found that only one of them was ever reached: an
  identical binding changes no artifact and needs no command at all,
  while a changed one restarts the daemon onto the new file. A
  scenario that only ever exercised the second left the "already
  running, nothing to do" wording untested — and a renderer that had
  written STARTED there would have passed.
  """
  print("\n=== 2. already running ===")
  before = unit_property(UNIT, "ActiveState")
  check("2.before: the unit is already running", before == "active",
        "ActiveState=%s" % before)

  # (a) The same binding again. Nothing derived from the model
  # changes, so nothing should be run and nothing should be claimed.
  since = unit_property(UNIT, "ExecMainStartTimestampMonotonic")
  rc, doc = cli.json("set", "dhcp", "testnet", DHCP_RANGE, "2m")
  check("2a: the verb succeeded", rc == 0, json.dumps(doc, indent=2))
  line = service_line(doc)
  check("2a: it does not claim to have STARTED anything",
        "STARTED" not in line, line or json.dumps(doc, indent=2))
  check("2a: it says the unit was already running",
        "already running" in line, line or json.dumps(doc, indent=2))
  check("2a: and the daemon was not restarted under the operator",
        unit_property(UNIT, "ExecMainStartTimestampMonotonic") ==
        since,
        "start timestamp moved: %s -> %s" % (
            since,
            unit_property(UNIT, "ExecMainStartTimestampMonotonic")))

  # (b) A changed binding. Now the daemon has to be restarted, and
  # that is a different word from either of the other two.
  rc, doc = cli.json("set", "dhcp", "testnet", DHCP_RANGE, "3m")
  check("2b: the verb succeeded", rc == 0, json.dumps(doc, indent=2))
  line = service_line(doc)
  check("2b: a changed configuration restarts the daemon",
        "restarted" in line, line or json.dumps(doc, indent=2))
  check("2b: and still does not claim to have STARTED it",
        "STARTED" not in line, line)
  check("2b: it really did restart",
        unit_property(UNIT, "ExecMainStartTimestampMonotonic") !=
        since,
        "start timestamp did not move from %s" % since)
  check("2: the unit is still up", wait_for(UNIT, "active") ==
        "active", unit_property(UNIT, "SubState"))


def scenario_will_not_start(cli, work):
  """3. A unit that will not come up makes the verb an error.

  The failure is the one `f-dnsmasq.service` documents about itself:
  `AssertPathExists=/etc/f/generated/dnsmasq.conf`. Its absence is a
  fault the unit reports by refusing to start, "never a silent no-op".
  A box gets into that state by having its generated artifact removed
  — which is what the CLI's own `--dnsmasq-conf` override arranges
  here, by writing the derived config somewhere else. Everything after
  the arrangement is the real thing: real systemd, real assert, real
  refusal.
  """
  print("\n=== 3. bound, and will not start ===")
  cli.reset_model()
  stop_and_disable()
  elsewhere = os.path.join(work, "dnsmasq.conf")
  quiet("rm -f /etc/f/generated/dnsmasq.conf")
  saved_conf = cli.generated
  cli.generated = elsewhere
  try:
    rc, text = cli.run("set", "dhcp", "testnet", DHCP_RANGE, "2m")
    check("3: the verb is an ERROR, not a success with a note",
          rc != 0, text)
    flat = flatten(text)
    check("3: the error names the unit", UNIT in flat, text)
    check("3: and reports the state systemd is in, not the exit code",
          "STOPPED" in flat, text)
    check("3: and carries systemd's own reason, not a paraphrase",
          "Assertion failed" in flat, text)
    check("3: and names the command that was run",
          "systemctl enable --now" in flat, text)
    active = unit_property(UNIT, "ActiveState")
    check("3: systemd agrees the unit is not running",
          active != "active",
          "ActiveState=%s SubState=%s Result=%s" % (
              active, unit_property(UNIT, "SubState"),
              unit_property(UNIT, "Result")))
    # The edit is on disk. Telling the operator otherwise would send
    # them to re-run a command that already worked.
    with open(cli.model) as f:
      model = f.read()
    check("3: the edit is still in the model",
          "dhcp" in model and DHCP_RANGE.split("-")[0] in model,
          model)
    _, services = cli.run("show", "services")
    check("3: `show services` reads it as broken too",
          ("STOPPED" in services or "FAILED" in services or
           "RESTARTING" in services), services)
  finally:
    cli.generated = saved_conf
    stop_and_disable()


def scenario_not_installed(cli, work):
  """4. Not installed is a different word from failed."""
  print("\n=== 4. bound, and the unit is not installed ===")
  cli.reset_model()
  stop_and_disable()
  saved = os.path.join(work, "f-dnsmasq.service")
  shutil.copy2(UNIT_PATH, saved)
  os.unlink(UNIT_PATH)
  run(["systemctl", "daemon-reload"])
  try:
    rc, doc = cli.json("set", "dhcp", "testnet", DHCP_RANGE, "2m")
    check("4: the verb is an error", rc != 0,
          json.dumps(doc, indent=2))
    text = json.dumps(doc) if doc else ""
    _, err = cli.run("set", "dhcp", "testnet", DHCP_RANGE, "2m")
    check("4: the state is NOT INSTALLED, not FAILED",
          "NOT INSTALLED" in err, err)
    check("4: and it does not say the unit failed",
          "FAILED" not in err, err)
    del text
    _, human = cli.run("show", "services")
    check("4: `show services` says the same word",
          "NOT INSTALLED" in human, human)
  finally:
    shutil.copy2(saved, UNIT_PATH)
    run(["systemctl", "daemon-reload"])


def scenario_stopped(cli):
  """5. `no dhcp` on the last binding stops the server."""
  print("\n=== 5. unbound, and stopped ===")
  cli.reset_model()
  stop_and_disable()
  rc, _ = cli.json("set", "dhcp", "testnet", DHCP_RANGE, "2m")
  check("5.before: it is running again", rc == 0 and
        wait_for(UNIT, "active") == "active",
        unit_property(UNIT, "SubState"))

  rc, doc = cli.json("no", "dhcp", "testnet")
  check("5: `no dhcp` succeeded", rc == 0, json.dumps(doc, indent=2))
  active, enabled = unit_state()
  check("5: the DHCP server is not running any more",
        active == "inactive", "ActiveState=%s" % active)
  check("5: and is disabled, so a reboot does not bring it back",
        enabled != "enabled", "UnitFileState=%s" % enabled)
  line = service_line(doc)
  check("5: the reply says it stopped and disabled it",
        "stopped and disabled" in line,
        line or json.dumps(doc, indent=2))


def scenario_dns_keeps_it_up(cli):
  """6. One daemon, two services: DNS alone still needs it."""
  print("\n=== 6. one daemon, two services ===")
  cli.reset_model()
  stop_and_disable()
  cli.json("set", "dhcp", "testnet", DHCP_RANGE, "2m")
  cli.json("set", "dns", "testnet", "127.0.0.53")
  check("6.before: it is running", wait_for(UNIT, "active") ==
        "active", unit_property(UNIT, "SubState"))
  rc, doc = cli.json("no", "dhcp", "testnet")
  check("6: `no dhcp` succeeded", rc == 0, json.dumps(doc, indent=2))
  check("6: the resolver is STILL running, because dns is bound",
        unit_property(UNIT, "ActiveState") == "active",
        json.dumps(doc, indent=2))
  line = service_line(doc)
  check("6: and it was restarted onto the new configuration",
        "restarted" in line, line or json.dumps(doc, indent=2))
  rc, doc = cli.json("no", "dns", "testnet")
  check("6: removing the last binding stops it",
        rc == 0 and wait_for(UNIT, "inactive") == "inactive",
        json.dumps(doc, indent=2))


def scenario_screens_differ(screens):
  """7. The endings are different words on the screen."""
  print("\n=== 7. the endings differ ===")
  names = sorted(screens)
  for i in range(len(names)):
    for k in range(i + 1, len(names)):
      a, b = names[i], names[k]
      check("7: `%s` and `%s` do not read alike" % (a, b),
            screens[a].strip() != screens[b].strip(),
            screens[a])


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument("--einheit-f", default="/usr/local/bin/einheit-f")
  parser.add_argument("--only", action="append", metavar="SCENARIO",
                      help="run only these scenarios; the vacuity "
                           "sweep uses it to ask one question at a "
                           "time")
  args = parser.parse_args()
  only = set(args.only or [])

  if os.geteuid() != 0:
    print("must run as root: it changes unit state and adds a veth")
    return 2
  if not os.path.exists(UNIT_PATH):
    print("%s is not installed; install the deployable set first"
          % UNIT_PATH)
    return 2

  work = tempfile.mkdtemp(prefix="f-svclife-")
  saved_model = None
  if os.path.exists("/etc/f/system.yaml"):
    saved_model = os.path.join(work, "system.yaml.saved")
    shutil.copy2("/etc/f/system.yaml", saved_model)
  try:
    make_port()
    cli = Cli(args.einheit_f, work)
    screens = {}

    def wanted(name):
      return not only or name in only

    # `already` reads the state `started` leaves behind, so it runs
    # its own setup when asked for alone.
    if wanted("started") or wanted("already"):
      screens["running"] = scenario_started(cli)
    if wanted("already"):
      scenario_already_running(cli)
    if wanted("willnot") or wanted("screens"):
      scenario_will_not_start(cli, work)
      _, screens["failed"] = cli.run("show", "services")
    if wanted("notinstalled"):
      scenario_not_installed(cli, work)
    if wanted("stopped") or wanted("screens"):
      scenario_stopped(cli)
      _, screens["stopped"] = cli.run("show", "services")
    if wanted("dns"):
      scenario_dns_keeps_it_up(cli)
    if wanted("screens") and len(screens) > 1:
      scenario_screens_differ(screens)
  finally:
    quiet("systemctl disable --now %s" % UNIT)
    quiet("systemctl reset-failed %s" % UNIT)
    quiet("ip link del %s" % LAN_IF)
    quiet("ip link del %s" % PEER_IF)
    if saved_model:
      shutil.copy2(saved_model, "/etc/f/system.yaml")
    shutil.rmtree(work, ignore_errors=True)

  print("\n%d passed, %d failed" % (PASS, FAIL))
  return 1 if FAIL else 0


if __name__ == "__main__":
  sys.exit(main())
