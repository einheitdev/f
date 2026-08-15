#!/usr/bin/env python3
"""First-boot provisioning for the f firewall appliance.

This runs once per device and decides what a new box is. Everything
after it is the operator changing something; this is the thing being
changed. It is therefore the least-exercised code in the tree and the
code with the most leverage over the box, and it is written on the
assumption that both of those stay true.

What it produces:

  * `/etc/f/system.yaml` — zones, and interfaces pinned to the MAC
    they were found on, so a name means the same port after every
    reboot and after every udev reordering.
  * the derived artifacts — networkd `.link`/`.network` units, the
    forwarding sysctl, the IPv6 stance, and the dnsmasq/chrony configs
    for whatever services the model binds — via `f-sysconf apply`.
  * `/etc/f/rules.fw` and a compiled bundle under
    `/usr/share/f/compiled`, with `current` pointing at it, so `fd`
    cold-boots into a policy rather than into the built-in fallback.
  * the services that model needs, enabled and started.

The starting policy is `default drop`. The v0.1 provisioner wrote
`default allow`, which is a box that passes everything while every
counter and every dashboard says the firewall is up.

Three rules this file is built on:

  1. **Check the install before provisioning it.** A box missing
     `f-confd` cannot arm an anti-lockout timer, and finding that out
     during the change that locks you out is too late. `f-install
     verify` runs first and a missing required item stops the run.
  2. **Never mark provisioned after a failure.** The marker means "this
     box is what firstboot makes"; writing it after a half-run means
     the next boot skips the repair.
  3. **A step that could not do its job says so by name.** There is no
     `2>/dev/null || true` in this file. The version it replaces had
     six.
"""

import argparse
import dataclasses
import datetime
import enum
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
import yaml

# Keys the v0.1 provisioning file used. They describe a box that no
# longer exists, and silently ignoring them would produce exactly the
# wrong box while looking like it worked.
SUPERSEDED_KEYS = {
  "management": "use `system.interfaces.<name>.address` and give the "
                "interface a zone",
  "interfaces": "use `system.interfaces`, which pins each name to a "
                "MAC and names its zone",
  "dns": "use `system.services.dns`, which binds to a zone",
}
DEFAULT_MANAGEMENT_PORTS = [22, 443]
class Outcome(enum.Enum):
  """What one provisioning step did.

  SKIPPED and FAILED are different answers, and so are FAILED and
  DEGRADED: "there was nothing to do", "I could not do it" and "I did
  part of it" lead an operator to three different places.
  """
  DONE = "done"
  SKIPPED = "skipped"
  DEGRADED = "degraded"
  FAILED = "failed"
@dataclasses.dataclass
class Step:
  """One step's name, result and the sentence that explains it."""
  name: str
  outcome: Outcome
  detail: str = ""
  hint: str = ""

  @property
  def fatal(self):
    """True when the run must not continue past this step."""
    return self.outcome is Outcome.FAILED
class Firstboot:
  """The provisioner.

  Every path and every external command is a constructor argument, so
  the whole thing can be run against a temporary directory and a fake
  command runner. That is not a testing convenience: it is the only
  way code that runs once per device gets exercised more than once.
  """

  def __init__(self, root="/", provision_file=None, run=None,
               sysfs_net=None, now=None, env=None, force=False):
    """Build a provisioner.

    Args:
      root: Filesystem root to write into. "/" is a real box.
      provision_file: Where the operator's provisioning data is.
      run: subprocess.run-compatible callable.
      sysfs_net: The kernel's network device directory.
      now: Callable returning the current time, for reproducible
        bundle names in tests.
      env: The process environment, read for SSH_CONNECTION.
      force: Provision anyway over a remote session.
    """
    self.env = os.environ if env is None else env
    self.force = force
    self.root = Path(root)
    self.run = run or subprocess.run
    self.now = now or datetime.datetime.now
    self.provision_file = Path(
      provision_file or self._at("/boot/f-provision.yaml"))
    self.sysfs_net = Path(sysfs_net or self._at("/sys/class/net"))
    self.etc_f = self._at("/etc/f")
    self.system_yaml = self.etc_f / "system.yaml"
    self.fd_yaml = self.etc_f / "fd.yaml"
    self.fd_yaml_template = self._at(
      "/usr/local/share/f/fd.yaml")
    self.rules = self.etc_f / "rules.fw"
    self.compiled = self._at("/usr/share/f/compiled")
    self.marker = self.etc_f / ".provisioned"
    self.report_path = self._at("/var/lib/f/firstboot.json")
    self.f_install = self._at("/usr/local/bin/f-install")
    self.f_sysconf = "f-sysconf"
    self.fwl = "fwl"
    self.steps = []
    self.provision = {}
    self.model = {}
    self.units = []

  def _at(self, absolute):
    """Resolve an absolute appliance path under this run's root."""
    return self.root / Path(absolute).relative_to("/")

  # -- step plumbing --------------------------------------------------

  def record(self, name, outcome, detail="", hint=""):
    """Append a step result and print it as it happens.

    Printed rather than buffered because f-firstboot.service sends
    stdout to the console, and an operator watching a board come up
    for the first time should see where it stopped.
    """
    step = Step(name, outcome, detail, hint)
    self.steps.append(step)
    print(f"[{outcome.value:>8}] {name}"
          f"{': ' + detail if detail else ''}", flush=True)
    if hint:
      print(f"           {hint}", flush=True)
    return step

  def _exec(self, argv, **kwargs):
    """Run a command, returning a CompletedProcess."""
    return self.run(argv, capture_output=True, text=True, **kwargs)

  @staticmethod
  def _tail(proc):
    """The last useful line of a failed command."""
    text = (proc.stderr or proc.stdout or "").strip()
    return text.splitlines()[-1] if text else f"exit {proc.returncode}"

  # -- steps ----------------------------------------------------------

  def check_install(self):
    """Refuse to provision a box that is missing pieces.

    The failure this prevents is the one the deployment rehearsal
    found: a box with `fd` and no `f-confd`, which starts, filters,
    and has no way to undo a change that cuts your access.
    """
    if not self.f_install.exists():
      return self.record(
        "verify install", Outcome.FAILED,
        f"{self.f_install} is not installed",
        "It is part of the deployable set. Without it this box "
        "cannot say what else it is missing.")
    proc = self._exec([str(self.f_install), "verify", "--format",
                       "json", "--root", str(self.root)])
    try:
      report = json.loads(proc.stdout)
    except ValueError:
      return self.record("verify install", Outcome.FAILED,
                         f"f-install produced no report: "
                         f"{self._tail(proc)}")
    # `unusable` belongs in this list and was not in it, so a required
    # binary that is present, executable, the right size and dies at
    # exec did not stop provisioning. That is not hypothetical: the
    # first image ever built had six of them, because the package list
    # had no libzmq5 and no libyaml-cpp0.8, and this step passed it.
    # `Report.missing_required` has always counted the four states
    # together; this is the same list, and the message below names
    # which one each item is rather than calling them all missing.
    missing = [i for i in report["items"]
               if i["requirement"] == "required"
               and i["state"] in ("missing", "wrong-kind", "empty",
                                  "unusable")]
    if missing:
      lines = "; ".join(
        f"{i['id']} ({i['state']}: {i['dest']}"
        + (f" — {i['detail']}" if i.get("detail") else "")
        + f", needed by {i.get('needed_by', 'nothing named')})"
        for i in missing)
      return self.record(
        "verify install", Outcome.FAILED,
        f"{len(missing)} required item(s) unusable or missing: "
        f"{lines}",
        "Nothing was provisioned and the box is not marked "
        "provisioned, so fixing the install and rebooting runs this "
        "again. `f-install verify` prints the full list.")
    unchecked = [i for i in report["items"]
                 if i["state"] in ("not-checked", "unreadable")]
    if unchecked:
      return self.record(
        "verify install", Outcome.DEGRADED,
        f"{len(unchecked)} item(s) could not be checked: "
        f"{', '.join(i['id'] for i in unchecked)}",
        "Provisioning continues; these are not known to be missing, "
        "only unproven.")
    return self.record("verify install", Outcome.DONE,
                       f"{len(report['items'])} items present")

  def check_console(self):
    """Refuse to provision a box down the wire that it is provisioning.

    firstboot assigns every port an address. On a real first boot that
    is free — nothing is connected yet and the box has no address to
    lose. Run by hand over SSH it is a lockout with no timer behind
    it: `apply system confirmed` exists precisely because a network
    change can sever the session making it, and this script does not
    use it.

    Measured, not theorised. A run over SSH on a box with a static
    management address wrote `address: dhcp` for the port that address
    was on, reloaded networkd, and the session died mid-step. The box
    came back on a different address off a DHCP server that happened
    to exist; on a bench with no DHCP it would have needed a console.
    """
    remote = self.env.get("SSH_CONNECTION") or self.env.get("SSH_TTY")
    if not remote:
      return self.record("session", Outcome.DONE,
                         "local console; nothing to cut")
    if not self.force:
      return self.record(
        "session", Outcome.FAILED,
        "this is an SSH session, and provisioning assigns every "
        "port an address",
        "Nothing was written. Run it from the console, or pass "
        "--force if you can reach the box another way. A first boot "
        "on a factory board has no session to lose, which is why "
        "there is no revert timer here — `apply system confirmed` is "
        "the command that has one.")
    return self.record(
      "session", Outcome.DEGRADED,
      "provisioning over SSH because --force was given",
      "If the address of the port you are connected on changes, this "
      "session ends and nothing puts it back.")

  def read_provisioning(self):
    """Load /boot/f-provision.yaml, refusing superseded keys."""
    if not self.provision_file.exists():
      return self.record(
        "read provisioning", Outcome.SKIPPED,
        f"no {self.provision_file}",
        "The box will be given the safe default shape: every port in "
        "one zone, DHCP, and a policy that drops what it is not "
        "asked for.")
    try:
      with open(self.provision_file, "r", encoding="utf-8") as handle:
        doc = yaml.safe_load(handle) or {}
    except (OSError, yaml.YAMLError) as exc:
      return self.record("read provisioning", Outcome.FAILED, str(exc))
    if not isinstance(doc, dict):
      return self.record("read provisioning", Outcome.FAILED,
                         "the provisioning file is not a mapping")
    stale = [k for k in SUPERSEDED_KEYS if k in doc]
    if stale:
      lines = "; ".join(f"`{k}`: {SUPERSEDED_KEYS[k]}" for k in stale)
      return self.record(
        "read provisioning", Outcome.FAILED,
        f"the provisioning file uses key(s) this appliance no longer "
        f"has: {lines}",
        "Refused rather than ignored: a file describing a v0.1 box "
        "would otherwise provision a box that is not the one it "
        "describes. /usr/local/share/f/f-provision.yaml.example is "
        "the current shape.")
    self.provision = doc
    return self.record("read provisioning", Outcome.DONE,
                       f"read {self.provision_file}")

  def set_hostname(self):
    """Apply the provisioned hostname, if there is one."""
    name = self.provision.get("hostname")
    if not name:
      return self.record("hostname", Outcome.SKIPPED,
                         "none in the provisioning data")
    proc = self._exec(["hostnamectl", "set-hostname", str(name)])
    if proc.returncode != 0:
      return self.record("hostname", Outcome.DEGRADED,
                         f"hostnamectl: {self._tail(proc)}")
    return self.record("hostname", Outcome.DONE, str(name))

  def install_ssh_keys(self):
    """Append the provisioned authorized keys for root."""
    keys = self.provision.get("ssh_keys") or []
    if not keys:
      return self.record("ssh keys", Outcome.SKIPPED,
                         "none in the provisioning data")
    ssh_dir = self._at("/root/.ssh")
    ssh_dir.mkdir(parents=True, exist_ok=True)
    ssh_dir.chmod(0o700)
    authorized = ssh_dir / "authorized_keys"
    existing = (authorized.read_text(encoding="utf-8")
                if authorized.exists() else "")
    added = [k.strip() for k in keys if k.strip() not in existing]
    with open(authorized, "a", encoding="utf-8") as handle:
      for key in added:
        handle.write(key + "\n")
    authorized.chmod(0o600)
    return self.record("ssh keys", Outcome.DONE,
                       f"{len(added)} added, {len(keys) - len(added)} "
                       f"already present")

  def install_fd_config(self):
    """Put the daemon's own config in place from the shipped one."""
    self.etc_f.mkdir(parents=True, exist_ok=True)
    if self.fd_yaml.exists():
      return self.record("fd.yaml", Outcome.SKIPPED,
                         f"{self.fd_yaml} already exists")
    if not self.fd_yaml_template.exists():
      return self.record("fd.yaml", Outcome.FAILED,
                         f"no template at {self.fd_yaml_template}")
    shutil.copy2(self.fd_yaml_template, self.fd_yaml)
    return self.record("fd.yaml", Outcome.DONE,
                       f"from {self.fd_yaml_template}")

  def build_system_config(self):
    """Write /etc/f/system.yaml and validate it.

    Either the provisioning file's `system:` block verbatim, or the
    safe default derived from the ports this box actually has.
    """
    self.etc_f.mkdir(parents=True, exist_ok=True)
    if self.system_yaml.exists():
      try:
        self.model = yaml.safe_load(
          self.system_yaml.read_text(encoding="utf-8")) or {}
      except yaml.YAMLError as exc:
        return self.record("system.yaml", Outcome.FAILED, str(exc))
      return self.record("system.yaml", Outcome.SKIPPED,
                         f"{self.system_yaml} already exists")

    supplied = self.provision.get("system")
    if supplied:
      self.model = supplied
      text = render_supplied_system(supplied, self.provision_file)
      note = f"from {self.provision_file}"
    else:
      ports = read_ports(self.sysfs_net)
      if not ports:
        return self.record(
          "system.yaml", Outcome.FAILED,
          f"no ethernet ports found under {self.sysfs_net}",
          "A firewall with no ports is not a box that can be "
          "provisioned into anything. Check the driver loaded.")
      self.model = default_model(ports)
      text = render_default_system(ports, self.now())
      note = (f"default shape for {len(ports)} port(s): "
              f"{', '.join(p.name for p in ports)}")

    self.system_yaml.write_text(text, encoding="utf-8")
    proc = self._exec([self.f_sysconf, "-c", str(self.system_yaml),
                       "check"])
    if proc.returncode != 0:
      return self.record(
        "system.yaml", Outcome.FAILED,
        f"f-sysconf check refused it: {self._tail(proc)}",
        f"The file is left at {self.system_yaml} so the message can "
        f"be acted on.")
    return self.record("system.yaml", Outcome.DONE, note)

  def apply_system_config(self):
    """Generate and install every artifact the model implies."""
    proc = self._exec([self.f_sysconf, "-c", str(self.system_yaml),
                       "apply"])
    if proc.returncode != 0:
      return self.record(
        "apply system", Outcome.FAILED,
        f"f-sysconf apply: {self._tail(proc)}",
        "Nothing downstream of the network configuration can be "
        "right if this failed, so the run stops here.")
    wrote = [line for line in proc.stdout.splitlines()
             if line.startswith("wrote ")]
    return self.record("apply system", Outcome.DONE,
                       f"{len(wrote)} artifact(s) written")

  def reload_networkd(self):
    """Make the generated units take effect now, not at next boot."""
    proc = self._exec(["networkctl", "reload"])
    if proc.returncode != 0:
      proc = self._exec(["systemctl", "restart",
                         "systemd-networkd.service"])
    if proc.returncode != 0:
      return self.record("network", Outcome.DEGRADED,
                         f"could not reload networkd: "
                         f"{self._tail(proc)}",
                         "The units are written; a reboot applies "
                         "them.")
    return self.record("network", Outcome.DONE, "networkd reloaded")

  def write_policy(self):
    """Write the starting firewall policy."""
    supplied = (self.provision.get("policy") or {}).get("source")
    if self.rules.exists():
      return self.record("policy", Outcome.SKIPPED,
                         f"{self.rules} already exists")
    if supplied:
      source = Path(supplied)
      if not source.is_absolute():
        source = self.provision_file.parent / source
      if not source.exists():
        return self.record(
          "policy", Outcome.FAILED,
          f"the provisioning file names a policy at {source} and "
          f"there is nothing there")
      self.rules.write_text(source.read_text(encoding="utf-8"),
                            encoding="utf-8")
      note = f"from {source}"
    else:
      policy = self.provision.get("policy") or {}
      self.rules.write_text(
        render_policy(self.model,
                      uplink_zone=policy.get("uplink_zone"),
                      management_ports=policy.get(
                        "management_ports",
                        DEFAULT_MANAGEMENT_PORTS),
                      when=self.now()),
        encoding="utf-8")
      note = "generated from the zones in system.yaml"
    proc = self._exec([self.fwl, "check", str(self.rules)])
    if proc.returncode != 0:
      return self.record(
        "policy", Outcome.FAILED,
        f"fwl refused the starting policy: {self._tail(proc)}",
        f"The source is at {self.rules}. The box is reachable and is "
        f"NOT filtering: no bundle was compiled and fd was not "
        f"started.")
    return self.record("policy", Outcome.DONE, note)

  def compile_policy(self):
    """Compile the policy into a bundle and point `current` at it."""
    stamp = self.now().strftime("v-%Y%m%dT%H%M%SZ")
    bundle = self.compiled / stamp
    bundle.mkdir(parents=True, exist_ok=True)
    proc = self._exec([self.fwl, "compile", str(self.rules),
                       "--bundle", str(bundle)])
    if proc.returncode != 0:
      return self.record(
        "compile", Outcome.FAILED,
        f"fwl compile: {self._tail(proc)}",
        "fd will not be started: a daemon that cold-boots into its "
        "built-in fallback is running a policy nobody wrote.")
    objects = sorted(bundle.glob("*.bpf.o"))
    if not objects:
      return self.record(
        "compile", Outcome.FAILED,
        f"{bundle} has a manifest and no .bpf.o in it",
        "That is what a compile without clang produces. `f-install "
        "verify` names clang as required for exactly this reason.")
    link = self.compiled / "current"
    tmp = self.compiled / ".current.new"
    if tmp.exists() or tmp.is_symlink():
      tmp.unlink()
    tmp.symlink_to(bundle.name)
    os.replace(tmp, link)
    return self.record("compile", Outcome.DONE,
                       f"{len(objects)} program(s) in {bundle.name}, "
                       f"current -> {bundle.name}")

  def plan_units(self):
    """Decide which units this box needs, from its own model."""
    units = ["fd.service", "f-confd.service", "einheit-f-ui.service"]
    services = (self.model or {}).get("services") or {}
    if services.get("dhcp") or services.get("dns"):
      units.append("f-dnsmasq.service")
    if services.get("ntp"):
      units.append("f-chrony.service")
    self.units = units
    bound = [u for u in units if u.startswith("f-dnsmasq")
             or u.startswith("f-chrony")]
    return self.record(
      "plan services", Outcome.DONE,
      f"{', '.join(units)}",
      "" if bound else
      "No zone binds dhcp, dns or ntp, so neither f-dnsmasq nor "
      "f-chrony is enabled. Their units are installed. Binding a "
      "service later — `set dhcp`, `set dns`, or editing "
      "system.yaml and applying it — writes the config and does NOT "
      "start the unit: this step is the only thing in the system "
      "that enables one, and it runs once. After binding a service, "
      "`systemctl enable --now f-dnsmasq` (or f-chrony), then "
      "`einheit-f show services` to check ANSWERS ON.")

  def unit_state(self, unit):
    """What systemd says this unit is actually doing.

    Not what `systemctl enable --now` returned. That command exits 0
    for a unit that started, crashed, and entered auto-restart — and a
    unit in auto-restart reports `activating`, not `failed`. The
    dashboard on the first box this provisioner built had restarted
    sixty-seven times before anybody looked, and every line of output
    up to that point said it had started.

    Returns:
      An (ok, description) pair.
    """
    proc = self._exec([
        "systemctl", "show", unit, "--property=ActiveState",
        "--property=SubState", "--property=NRestarts",
        "--property=Result"])
    fields = {}
    for line in proc.stdout.splitlines():
      key, _, value = line.partition("=")
      fields[key] = value
    active = fields.get("ActiveState", "?")
    sub = fields.get("SubState", "?")
    restarts = fields.get("NRestarts", "0")
    result = fields.get("Result", "?")
    if sub == "auto-restart" or active == "failed":
      return False, (f"{active}/{sub} after {restarts} restart(s), "
                     f"result={result}")
    if active in ("active", "activating") and sub != "auto-restart":
      if active == "activating":
        return False, f"still {active}/{sub} — it has not come up"
      if restarts not in ("0", ""):
        return False, (f"active, but only after {restarts} "
                       f"restart(s); it is crashing and recovering")
      return True, f"{active}/{sub}"
    return False, f"{active}/{sub}, result={result}"

  def start_units(self):
    """Enable and start the planned units, naming any that failed.

    Two questions, asked separately: did the command work, and is the
    service running. The second one is the one an operator meant.
    """
    self._exec(["systemctl", "daemon-reload"])
    failed = []
    for unit in self.units:
      proc = self._exec(["systemctl", "enable", "--now", unit])
      if proc.returncode != 0:
        failed.append(f"{unit} ({self._tail(proc)})")
        continue
      ok, detail = self.unit_state(unit)
      if not ok:
        failed.append(f"{unit} ({detail})")
    if failed:
      return self.record(
        "start services", Outcome.DEGRADED,
        f"{len(failed)} of {len(self.units)} are not running: "
        f"{'; '.join(failed)}",
        "`systemctl status <unit>` and `journalctl -u <unit>` say "
        "why. The rest of the box is provisioned.")
    return self.record("start services", Outcome.DONE,
                       f"{len(self.units)} unit(s) enabled and "
                       f"running")

  # -- the run --------------------------------------------------------

  def run_all(self):
    """Execute every step in order, stopping at the first fatal one.

    Returns:
      A process exit code: 0 provisioned, 1 stopped at a failure,
      2 provisioned with something degraded.
    """
    if self.marker.exists():
      print(f"Already provisioned on "
            f"{self.marker.read_text(encoding='utf-8').strip()}; "
            f"nothing to do.")
      return 0
    print("=== f appliance first boot ===", flush=True)
    for step in (self.check_install,
                 self.check_console,
                 self.read_provisioning,
                 self.set_hostname,
                 self.install_ssh_keys,
                 self.install_fd_config,
                 self.build_system_config,
                 self.apply_system_config,
                 self.reload_networkd,
                 self.write_policy,
                 self.compile_policy,
                 self.plan_units,
                 self.start_units):
      if step().fatal:
        return self._finish(provisioned=False)
    return self._finish(provisioned=True)

  def _finish(self, provisioned):
    """Write the report, and the marker only if the run succeeded."""
    degraded = [s for s in self.steps
                if s.outcome is Outcome.DEGRADED]
    failed = [s for s in self.steps if s.outcome is Outcome.FAILED]
    report = {
      "provisioned": provisioned,
      "when": self.now().isoformat(),
      "steps": [dataclasses.asdict(s) | {"outcome": s.outcome.value}
                for s in self.steps],
    }
    self.report_path.parent.mkdir(parents=True, exist_ok=True)
    self.report_path.write_text(json.dumps(report, indent=2),
                                encoding="utf-8")
    print("")
    if not provisioned:
      print(f"=== first boot STOPPED at: {failed[-1].name} ===")
      print(f"    {failed[-1].detail}")
      print("    The box is NOT marked provisioned. Fix the cause "
            "and reboot, or run this script again by hand.")
      print(f"    Full report: {self.report_path}")
      return 1
    self.marker.write_text(self.now().isoformat() + "\n",
                           encoding="utf-8")
    if degraded:
      print(f"=== first boot complete, {len(degraded)} step(s) "
            f"degraded ===")
      for step in degraded:
        print(f"    {step.name}: {step.detail}")
      print(f"    Full report: {self.report_path}")
      return 2
    print("=== first boot complete ===")
    print(f"    Full report: {self.report_path}")
    return 0
@dataclasses.dataclass
class Port:
  """A physical ethernet port as the kernel currently presents it."""
  name: str
  mac: str
  carrier: bool
def read_ports(sysfs_net):
  """Enumerate the box's physical ethernet ports.

  Only ports backed by a device are returned: `lo`, bridges, veths and
  every other virtual interface are not things a firewall zone can be
  pinned to.

  Args:
    sysfs_net: Path to /sys/class/net or a fake of it.

  Returns:
    Ports sorted by name, so the same hardware produces the same file
    every time.
  """
  ports = []
  root = Path(sysfs_net)
  if not root.is_dir():
    return ports
  for entry in sorted(root.iterdir()):
    if not (entry / "device").exists():
      continue
    try:
      if (entry / "type").read_text(encoding="utf-8").strip() != "1":
        continue
      mac = (entry / "address").read_text(encoding="utf-8").strip()
    except OSError:
      continue
    if not mac or mac == "00:00:00:00:00:00":
      continue
    carrier = False
    try:
      carrier = (entry / "carrier").read_text(
        encoding="utf-8").strip() == "1"
    except OSError:
      # EINVAL from a down interface. Not knowing is fine; it only
      # decides a comment in the generated file.
      carrier = False
    ports.append(Port(entry.name, mac, carrier))
  return ports
def default_model(ports):
  """The model a box gets when nobody told it what it is.

  One zone holding every port, each asking for an address. It filters
  and it does not route, which is the only shape that is safe without
  knowing which side of the box faces the world.
  """
  return {
    "zones": {"mgmt": {"ipv6": "off"}},
    "interfaces": {
      p.name: {"mac": p.mac, "address": "dhcp", "zone": "mgmt"}
      for p in ports
    },
    "services": {},
  }
def render_default_system(ports, when):
  """Render the default system.yaml, with the reasoning in it."""
  lines = [
    "# f appliance system configuration — written by firstboot on",
    f"# {when.isoformat(timespec='seconds')}.",
    "#",
    "# There was no /boot/f-provision.yaml, so this box was given the",
    "# only shape that is safe without knowing which port faces the",
    "# world: every port in one zone, each asking for an address,",
    "# nothing forwarded between them.",
    "#",
    "# THIS BOX FILTERS AND DOES NOT ROUTE. To make it a gateway,",
    "# split these ports into zones, put the uplink in its own one,",
    "# and add `masquerade` / `redirect to <uplink>` to the inside",
    "# zone's block in /etc/f/rules.fw. See",
    "# /usr/local/share/f/system.yaml.example and docs/howto/.",
    "#",
    "# Each name below is pinned to the MAC it was found on, so it",
    "# keeps meaning the same port. Renaming one here means the box",
    "# renames the port at the next boot.",
    "#",
    "#   f-sysconf -c /etc/f/system.yaml check",
    "#   f-sysconf -c /etc/f/system.yaml apply",
    "",
    "zones:",
    "  mgmt:",
    "    ipv6: off",
    "",
    "interfaces:",
  ]
  for port in ports:
    carrier = "link up" if port.carrier else "no link at first boot"
    lines += [
      f"  {port.name}:",
      f"    # {carrier}",
      f"    mac: \"{port.mac}\"",
      "    address: dhcp",
      "    zone: mgmt",
    ]
  lines += [
    "",
    "# No service is bound to any zone. A zone with no dhcp entry",
    "# hands out no addresses, and f-dnsmasq is not enabled — which",
    "# is deliberate: an appliance that starts a DHCP server on an",
    "# office network it was plugged into by mistake is the worst",
    "# first impression available.",
    "services: {}",
    "",
  ]
  return "\n".join(lines)
def render_supplied_system(model, source):
  """Render an operator-supplied model, keeping its provenance."""
  header = (
    "# f appliance system configuration — installed by firstboot\n"
    f"# from the `system:` block of {source}.\n"
    "#\n"
    "# Edit it here from now on; the provisioning file is read once.\n"
    "#\n"
    "#   f-sysconf -c /etc/f/system.yaml check\n"
    "#   f-sysconf -c /etc/f/system.yaml apply\n\n")
  return header + yaml.safe_dump(model, default_flow_style=False,
                                 sort_keys=False)
def _zone_interfaces(model):
  """Map zone name to the interfaces in it, in a stable order."""
  zones = {name: [] for name in (model.get("zones") or {})}
  for name, iface in (model.get("interfaces") or {}).items():
    zone = (iface or {}).get("zone")
    if zone is None:
      continue
    zones.setdefault(zone, []).append(name)
  return {z: sorted(i) for z, i in zones.items()}
def _zone_addresses(model, zone):
  """Static addresses the appliance itself holds in a zone."""
  out = []
  for iface in (model.get("interfaces") or {}).values():
    if (iface or {}).get("zone") != zone:
      continue
    address = (iface or {}).get("address")
    if address and address != "dhcp" and "/" in str(address):
      out.append(str(address).split("/", 1)[0])
  return out
def render_policy(model, uplink_zone=None,
                  management_ports=None, when=None):
  """Generate a starting policy from the zones in the model.

  The policy is `default drop` in every zone. What each zone admits
  beyond that is: replies to flows it started, the appliance's own
  client traffic, and the management ports.

  The appliance's own outbound traffic is the awkward case and the
  comments in the output say so. XDP sees ingress only, so a DNS query
  this box sends is never entered into conntrack and its answer is not
  `established`. The generated rules therefore admit answers by source
  port, which is a narrow hole with a name — and it closes the day the
  egress hook lands and host-originated flows get tracked.

  A multi-zone gateway used to be unloadable, and this is where it was
  generated: with `uplink_zone` named and more than one other zone,
  every one of them gets `redirect to <uplink>` and so declares
  `fwl_devmap_<uplink>`. While devmaps were pinned by name the SECOND
  such object failed to load — the kernel forces BPF_F_RDONLY_PROG in
  `dev_map_alloc`, so libbpf's pin-reuse check compared the object's
  declared 0 against the pinned map's 128 and refused with "parameter
  mismatch" — and a box provisioned that way came up with `fd` in
  auto-restart. Devmaps are no longer pinned (FWL_V04_SPEC.md 6.3);
  `fd` fills each object's own copy. Three zones load, attach and
  forward, proved on the wire by
  `fwl/tests/system/three_zone_gateway_netns.py`.

  Args:
    model: The parsed system.yaml.
    uplink_zone: The zone facing the world. When named, every other
      zone masquerades out through it and the box becomes a gateway.
    management_ports: TCP ports reachable on the box itself.
    when: Timestamp for the header.

  Returns:
    The .fw source as a string.
  """
  ports = management_ports or DEFAULT_MANAGEMENT_PORTS
  zones = _zone_interfaces(model)
  stamp = (when or datetime.datetime.now()).isoformat(
    timespec="seconds")
  out = [
    "# f firewall policy — written by firstboot on " + stamp + ".",
    "#",
    "# `default drop` in every zone. The provisioner this replaces",
    "# started a box with an allow-everything default, which is a box",
    "# that passes every packet while every counter, every dashboard",
    "# and every status line says the firewall is up.",
    "#",
    "# Edit with `einheit-f`, then `commit`. The compiler checks it",
    "# before anything is loaded, so a policy that does not compile",
    "# never replaces the one that is running.",
    "",
  ]
  for zone, interfaces in zones.items():
    if not interfaces:
      continue
    out.append(f"zone {zone} = [{', '.join(interfaces)}]")
  out.append("")

  for zone, interfaces in zones.items():
    if not interfaces:
      out += [f"# The zone `{zone}` has no interfaces in",
              "# system.yaml and so gets no block here: a program",
              "# attached to nothing inspects nothing, and a count of",
              "# loaded programs would say otherwise.", ""]
      continue
    inside = uplink_zone is not None and zone != uplink_zone
    out += _zone_block(model, zone, ports, inside, uplink_zone)
  return "\n".join(out)
def _zone_block(model, zone, management_ports, inside, uplink_zone):
  """One @xdp block: what this zone admits and what it does after."""
  out = [f"@xdp({zone})", ""]
  out += [f"count {zone}_total", ""]

  if inside:
    out += [
      "# 1. Traffic addressed to THIS BOX is delivered to this box.",
      "#    These come first because the two verbs at the bottom of",
      "#    this block are unconditional: anything that reaches them",
      "#    leaves on the uplink, including a DHCP DISCOVER that was",
      "#    never going anywhere.",
      "#    DHCP by port, because a client with no lease cannot",
      "#    address us and broadcasts instead.",
      "allow if pkt.proto == udp and pkt.dst_port == 67",
    ]
    for address in _zone_addresses(model, zone):
      out.append(f"allow if pkt.dst_ip == {address}")
    for port in management_ports:
      out.append(
        f"allow if pkt.proto == tcp and pkt.dst_port == {port}")
    out += [
      "",
      "# 2. This zone's own noise stays inside this zone. None of it",
      "#    is routable and all of it would otherwise be masqueraded",
      "#    onto the uplink one frame at a time.",
      "drop if pkt.dst_ip in 224.0.0.0/4",
      "drop if pkt.dst_ip == 255.255.255.255",
      "drop if pkt.proto == udp and (pkt.dst_port == 137 "
      "or pkt.dst_port == 138)",
      "",
      "# 3. Only what is left goes out, wearing the uplink's address.",
      f"count {zone}_out",
      "masquerade",
      f"redirect to {uplink_zone}",
      "",
      "default drop",
      "",
    ]
    return out

  out += [
    "# Replies to flows this zone started. `related` is not optional:",
    "# an ICMP error carries no ports so it is never `established`,",
    "# and the frag-needed that path-MTU discovery runs on is one.",
    "# Without it every large transfer hangs with nothing logged.",
    "allow if conntrack(pkt).state in [established, related]",
    "",
    "# The appliance's own client traffic. XDP sees ingress only, so",
    "# a query THIS BOX sent was never entered into conntrack and its",
    "# answer is not `established`. Admitting the answers by source",
    "# port is a real hole and a narrow one; it closes when",
    "# host-originated flows are tracked on egress.",
    "allow if pkt.proto == udp and pkt.src_port == 67 "
    "and pkt.dst_port == 68",
    "allow if pkt.proto == udp and pkt.src_port == 53",
    "allow if pkt.proto == udp and pkt.src_port == 123",
    "",
    "# Reaching the box to configure it.",
  ]
  for port in management_ports:
    out.append(f"allow if pkt.proto == tcp and pkt.dst_port == {port}")
  out += [
    "",
    "# So that a box that is up can be seen to be up.",
    "allow if pkt.proto == icmp",
    "",
    "default drop",
    "",
  ]
  return out
def build_parser():
  """Construct the argument parser."""
  parser = argparse.ArgumentParser(
    prog="firstboot.py",
    description="Provision an f appliance on its first boot.")
  parser.add_argument("--root", default="/",
                      help="Filesystem root to provision into")
  parser.add_argument("--provision",
                      help="Provisioning file "
                           "(default <root>/boot/f-provision.yaml)")
  parser.add_argument("--force", action="store_true",
                      help="Run even if the box is marked "
                           "provisioned, and even over SSH")
  return parser
def main(argv=None):
  """Entry point. Returns a process exit code."""
  args = build_parser().parse_args(argv)
  boot = Firstboot(root=args.root, provision_file=args.provision,
                   force=args.force)
  if args.force and boot.marker.exists():
    boot.marker.unlink()
  return boot.run_all()
if __name__ == "__main__":
  sys.exit(main())
