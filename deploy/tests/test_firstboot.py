"""Behavioural tests for the once-per-device provisioner.

firstboot runs exactly once on a real board, which means the only way
it gets exercised more than once is here. Every test drives the real
`Firstboot` against a temporary root, a fake `/sys/class/net` and a
recording command runner, and asserts on the artifacts it produced —
the system.yaml, the policy source, the bundle symlink and the set of
units it asked systemd to start. A stub that printed the right things
and wrote nothing would fail all of them.
"""

import datetime
import json
import subprocess
import sys
from pathlib import Path
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent
                       / "firstboot"))
import firstboot  # noqa: E402
from firstboot import Firstboot, Outcome  # noqa: E402

WHEN = datetime.datetime(2026, 8, 15, 9, 30, 0)
class FakeRunner:
  """Records every command and answers from a scripted table.

  Anything not in the table succeeds silently, so a test only has to
  describe the commands it cares about.
  """

  def __init__(self, failures=None, outputs=None, unit_states=None):
    """Build a runner.

    Args:
      failures: {first-two-argv-words: (returncode, stderr)}.
      outputs: {first-two-argv-words: stdout}.
      unit_states: {unit: (ActiveState, SubState, NRestarts)}. Units
        not named here answer active/running/0, so a test only
        describes the service it is about.
    """
    self.calls = []
    self.failures = failures or {}
    self.outputs = outputs or {}
    self.unit_states = unit_states or {}

  def __call__(self, argv, **kwargs):
    """Run one command."""
    self.calls.append(list(argv))
    if argv[:2] == ["systemctl", "show"]:
      active, sub, restarts = self.unit_states.get(
        argv[2], ("active", "running", "0"))
      return subprocess.CompletedProcess(
        argv, 0,
        f"ActiveState={active}\nSubState={sub}\n"
        f"NRestarts={restarts}\nResult=success\n", "")
    key = " ".join(Path(argv[0]).name.split() + list(argv[1:3]))
    rc, err = self.failures.get(key, (0, ""))
    return subprocess.CompletedProcess(
      argv, rc, self.outputs.get(key, ""), err)

  def ran(self, *words):
    """True if any recorded call contains this word sequence."""
    joined = [" ".join(c) for c in self.calls]
    return any(all(w in line for w in words) for line in joined)

  def systemctl_enabled(self):
    """Every unit passed to `systemctl enable --now`."""
    return [c[-1] for c in self.calls
            if c[:3] == ["systemctl", "enable", "--now"]]
def make_box(tmp_path, ports=(("enp1s0", "52:54:00:aa:bb:01", True),
                              ("enp2s0", "52:54:00:aa:bb:02", False)),
             install_ok=True):
  """Build a fake appliance root ready to be provisioned.

  Args:
    tmp_path: pytest temporary directory.
    ports: (name, mac, carrier) triples to present as hardware.
    install_ok: Whether f-install reports a complete install.

  Returns:
    The root path.
  """
  root = tmp_path / "box"
  for path in ("etc/f", "usr/share/f/compiled", "var/lib/f",
               "usr/local/bin", "boot", "sys/class/net"):
    (root / path).mkdir(parents=True, exist_ok=True)
  (root / "usr/local/share/f").mkdir(parents=True, exist_ok=True)
  (root / "usr/local/share/f/fd.yaml").write_text(
    "interfaces: []\nsocket: ipc:///run/f/control.sock\n")

  items = [{"id": "fd", "requirement": "required", "state": "present",
            "dest": "/usr/local/bin/fd", "needed_by": "fd.service"}]
  if not install_ok:
    items.append({"id": "f-confd", "requirement": "required",
                  "state": "missing",
                  "dest": "/usr/local/bin/f-confd",
                  "needed_by": "f-confd.service"})
  verifier = root / "usr/local/bin/f-install"
  verifier.write_text("#!/bin/sh\n")
  verifier.chmod(0o755)
  make_box.report = json.dumps({"verdict": "complete", "items": items})

  for name, mac, carrier in ports:
    port = root / "sys/class/net" / name
    port.mkdir(parents=True)
    (port / "device").mkdir()
    (port / "type").write_text("1\n")
    (port / "address").write_text(mac + "\n")
    (port / "carrier").write_text("1\n" if carrier else "0\n")
  # Things a firewall cannot be pinned to.
  for virtual in ("lo", "veth0"):
    (root / "sys/class/net" / virtual).mkdir(parents=True)
    (root / "sys/class/net" / virtual / "type").write_text("1\n")
    (root / "sys/class/net" / virtual / "address").write_text(
      "00:00:00:00:00:00\n")
  return root
def provisioner(root, runner, provision=None, env=None, force=False):
  """A Firstboot wired to a fake box.

  `env` defaults to empty: a provisioning run happens at the console,
  and a test that inherited the developer's SSH_CONNECTION would fail
  or pass depending on how the suite was started.
  """
  boot = Firstboot(root=root,
                   provision_file=provision,
                   run=runner,
                   sysfs_net=root / "sys/class/net",
                   now=lambda: WHEN,
                   env={} if env is None else env,
                   force=force)
  return boot
def _bundle_writer(root, objects=("mgmt.bpf.o",)):
  """A runner that also writes what `fwl compile` would write."""
  runner = FakeRunner()
  real_call = runner.__call__

  def call(argv, **kwargs):
    result = real_call(argv, **kwargs)
    if len(argv) > 3 and argv[1] == "compile":
      bundle = Path(argv[argv.index("--bundle") + 1])
      bundle.mkdir(parents=True, exist_ok=True)
      (bundle / "manifest.json").write_text("{}")
      for obj in objects:
        (bundle / obj).write_text("ELF")
    return result

  runner.__call__ = call
  return runner
class _Runner:
  """Wrapper so a FakeRunner with a patched __call__ stays callable."""

  def __init__(self, inner):
    self.inner = inner

  def __call__(self, argv, **kwargs):
    return self.inner.__call__(argv, **kwargs)

  def __getattr__(self, name):
    return getattr(self.inner, name)
def full_run(tmp_path, provision_doc=None, ports=None,
             objects=("mgmt.bpf.o",)):
  """Provision a fake box end to end and return (root, boot, runner)."""
  kwargs = {"ports": ports} if ports else {}
  root = make_box(tmp_path, **kwargs)
  runner = _Runner(_bundle_writer(root, objects))
  provision = None
  if provision_doc is not None:
    provision = root / "boot/f-provision.yaml"
    provision.write_text(yaml.safe_dump(provision_doc))
  boot = provisioner(root, runner, provision)
  boot.f_install = root / "usr/local/bin/f-install"
  runner.inner.outputs["f-install verify --format"] = make_box.report
  code = boot.run_all()
  return root, boot, runner, code
# -- the install gate -------------------------------------------------
def test_a_missing_binary_stops_the_run_before_anything_is_written(
    tmp_path):
  """The gate that the rehearsal's box did not have.

  A board with no f-confd has no anti-lockout timer. Discovering that
  during the change that locks you out is too late, so it is
  discovered here and nothing is provisioned.
  """
  root = make_box(tmp_path, install_ok=False)
  runner = FakeRunner(outputs={
    "f-install verify --format": make_box.report})
  boot = provisioner(root, runner)
  boot.f_install = root / "usr/local/bin/f-install"
  assert boot.run_all() == 1
  assert boot.steps[0].outcome is Outcome.FAILED
  assert "f-confd" in boot.steps[0].detail
  assert "f-confd.service" in boot.steps[0].detail
  assert not (root / "etc/f/system.yaml").exists()
  assert not (root / "etc/f/rules.fw").exists()
  assert not (root / "etc/f/.provisioned").exists()
  assert not runner.systemctl_enabled()
def test_the_report_survives_a_stopped_run(tmp_path):
  """A run that stopped still says where, in a file."""
  root = make_box(tmp_path, install_ok=False)
  runner = FakeRunner(outputs={
    "f-install verify --format": make_box.report})
  boot = provisioner(root, runner)
  boot.f_install = root / "usr/local/bin/f-install"
  boot.run_all()
  report = json.loads(
    (root / "var/lib/f/firstboot.json").read_text())
  assert report["provisioned"] is False
  assert report["steps"][0]["outcome"] == "failed"
def test_a_missing_verifier_is_itself_a_failure(tmp_path):
  """A box that cannot check itself is not a box that is fine."""
  root = make_box(tmp_path)
  (root / "usr/local/bin/f-install").unlink()
  boot = provisioner(root, FakeRunner())
  boot.f_install = root / "usr/local/bin/f-install"
  assert boot.run_all() == 1
  assert boot.steps[0].outcome is Outcome.FAILED
# -- what a default box is --------------------------------------------
def test_the_default_box_pins_every_port_to_its_mac(tmp_path):
  """Durable names, from hardware identity, with no provisioning."""
  root, boot, runner, code = full_run(tmp_path)
  assert code == 0, [s for s in boot.steps]
  model = yaml.safe_load((root / "etc/f/system.yaml").read_text())
  assert set(model["interfaces"]) == {"enp1s0", "enp2s0"}
  assert model["interfaces"]["enp1s0"]["mac"] == "52:54:00:aa:bb:01"
  assert model["interfaces"]["enp2s0"]["mac"] == "52:54:00:aa:bb:02"
  assert all(i["zone"] == "mgmt"
             for i in model["interfaces"].values())
  assert "mgmt" in model["zones"]
def test_virtual_interfaces_are_not_ports(tmp_path):
  """`lo` and a veth are not things a zone can be pinned to."""
  root, _, _, _ = full_run(tmp_path)
  model = yaml.safe_load((root / "etc/f/system.yaml").read_text())
  assert "lo" not in model["interfaces"]
  assert "veth0" not in model["interfaces"]
def test_the_default_policy_drops_by_default(tmp_path):
  """The one thing the v0.1 provisioner got wrong."""
  root, _, _, _ = full_run(tmp_path)
  policy = (root / "etc/f/rules.fw").read_text()
  assert "default drop" in policy
  assert "default allow" not in policy
def test_the_default_policy_keeps_the_box_reachable(tmp_path):
  """Safe is not the same as unreachable.

  A default-drop policy that admits nothing is a box you provision
  once and then drive to the site to recover.
  """
  root, _, _, _ = full_run(tmp_path)
  policy = (root / "etc/f/rules.fw").read_text()
  for rule in (
      "allow if conntrack(pkt).state in [established, related]",
      "allow if pkt.proto == tcp and pkt.dst_port == 22",
      "allow if pkt.proto == tcp and pkt.dst_port == 443",
      "allow if pkt.proto == icmp"):
    assert rule in policy, rule
  # DHCP, DNS and NTP answers to the box's own client traffic. XDP
  # sees ingress only, so these are not `established`.
  assert "pkt.src_port == 67 and pkt.dst_port == 68" in policy
  assert "pkt.src_port == 53" in policy
  assert "pkt.src_port == 123" in policy
def test_the_default_box_does_not_route(tmp_path):
  """Nothing was said about which port faces the world."""
  root, _, _, _ = full_run(tmp_path)
  policy = (root / "etc/f/rules.fw").read_text()
  assert "\nmasquerade\n" not in policy
  assert "\nredirect to " not in policy
  system = (root / "etc/f/system.yaml").read_text()
  assert "FILTERS AND DOES NOT ROUTE" in system
def test_no_service_is_bound_without_being_asked(tmp_path):
  """An appliance that DHCPs an office network by accident.

  The worst first impression available, and the reason the default
  model binds nothing.
  """
  root, boot, runner, _ = full_run(tmp_path)
  model = yaml.safe_load((root / "etc/f/system.yaml").read_text())
  assert model["services"] == {}
  assert "f-dnsmasq.service" not in runner.systemctl_enabled()
  assert "f-chrony.service" not in runner.systemctl_enabled()
def test_the_datapath_and_the_config_daemon_always_start(tmp_path):
  """f-confd is not optional; it holds the anti-lockout timer."""
  _, _, runner, _ = full_run(tmp_path)
  enabled = runner.systemctl_enabled()
  assert "fd.service" in enabled
  assert "f-confd.service" in enabled
  assert "einheit-f-ui.service" in enabled
def test_the_bundle_is_compiled_and_current_points_at_it(tmp_path):
  """fd cold-boots into `current`; firstboot is what creates it."""
  root, _, runner, _ = full_run(tmp_path)
  current = root / "usr/share/f/compiled/current"
  assert current.is_symlink()
  assert (current.resolve() / "mgmt.bpf.o").exists()
  assert runner.ran("compile", "--bundle")
def test_a_bundle_with_no_objects_is_a_failed_compile(tmp_path):
  """What a compile without clang produces, named as such."""
  root, boot, runner, code = full_run(tmp_path, objects=())
  assert code == 1
  compile_step = next(s for s in boot.steps if s.name == "compile")
  assert compile_step.outcome is Outcome.FAILED
  assert "clang" in compile_step.hint
  assert not (root / "etc/f/.provisioned").exists()
  assert not runner.systemctl_enabled()
def test_a_policy_the_compiler_refuses_stops_the_run(tmp_path):
  """And says the box is reachable and not filtering."""
  root = make_box(tmp_path)
  runner = FakeRunner(failures={
    "fwl check /etc/f/rules.fw": (1, "E001: syntax error")})
  runner.outputs["f-install verify --format"] = make_box.report
  boot = provisioner(root, runner)
  boot.f_install = root / "usr/local/bin/f-install"
  boot.rules = root / "etc/f/rules.fw"
  runner.failures[f"fwl check {boot.rules}"] = (1, "E001: syntax")
  assert boot.run_all() == 1
  step = next(s for s in boot.steps if s.name == "policy")
  assert step.outcome is Outcome.FAILED
  assert "NOT filtering" in step.hint
  assert not runner.systemctl_enabled()
def test_the_marker_is_only_written_after_a_clean_run(tmp_path):
  """The marker means 'this box is what firstboot makes'."""
  root, _, _, code = full_run(tmp_path)
  assert code == 0
  assert (root / "etc/f/.provisioned").exists()
def test_a_provisioned_box_is_not_provisioned_twice(tmp_path):
  """Idempotence, because a second run would rewrite the policy."""
  root, boot, runner, _ = full_run(tmp_path)
  again = provisioner(root, FakeRunner())
  assert again.run_all() == 0
  assert not again.steps
# -- what a provisioned box is ----------------------------------------
GATEWAY = {
  "hostname": "fw-edge-01",
  "system": {
    "zones": {"wan": {"ipv6": "off"}, "lan": {"ipv6": "off"}},
    "interfaces": {
      "wan0": {"mac": "52:54:00:aa:bb:01", "address": "dhcp",
               "zone": "wan"},
      "lan0": {"mac": "52:54:00:aa:bb:02",
               "address": "10.10.0.1/24", "zone": "lan"},
    },
    "services": {
      "dhcp": [{"zone": "lan", "range": "10.10.0.100-10.10.0.200"}],
      "dns": [{"zone": "lan", "upstream": ["9.9.9.9"]}],
    },
  },
  "policy": {"uplink_zone": "wan"},
}
def test_a_provisioned_gateway_gets_the_model_it_was_given(tmp_path):
  """The `system:` block is the system configuration, verbatim."""
  root, _, _, code = full_run(tmp_path, GATEWAY)
  assert code == 0
  model = yaml.safe_load((root / "etc/f/system.yaml").read_text())
  assert model["zones"].keys() == {"wan", "lan"}
  assert model["interfaces"]["lan0"]["address"] == "10.10.0.1/24"
  assert model["services"]["dhcp"][0]["zone"] == "lan"
def test_a_provisioned_gateway_masquerades_out_of_the_uplink(tmp_path):
  """`uplink_zone` is what turns a filtering box into a gateway."""
  root, _, _, _ = full_run(tmp_path, GATEWAY)
  policy = (root / "etc/f/rules.fw").read_text()
  assert "zone wan = [wan0]" in policy
  assert "zone lan = [lan0]" in policy
  assert "\nmasquerade\n" in policy
  assert "\nredirect to wan\n" in policy
  # The uplink block does not masquerade back out of itself.
  wan_block = policy.split("@xdp(wan)")[1].split("@xdp(")[0]
  assert "\nmasquerade\n" not in wan_block
def test_the_inside_zone_delivers_to_the_box_before_it_forwards(
    tmp_path):
  """The storm-shield ordering, which is the whole policy.

  masquerade and redirect are unconditional, so a DHCP DISCOVER from
  inside would be broadcast onto the uplink unless it is admitted
  first. That happened, on a real network, to a policy called storm
  shield.
  """
  root, _, _, _ = full_run(tmp_path, GATEWAY)
  policy = (root / "etc/f/rules.fw").read_text()
  lan = policy.split("@xdp(lan)")[1]
  dhcp_in = lan.index("pkt.dst_port == 67")
  gateway_in = lan.index("allow if pkt.dst_ip == 10.10.0.1")
  masq = lan.index("\nmasquerade\n")
  assert dhcp_in < masq and gateway_in < masq
def test_the_inside_zone_keeps_its_broadcast_to_itself(tmp_path):
  """The other half of not being the storm."""
  root, _, _, _ = full_run(tmp_path, GATEWAY)
  lan = (root / "etc/f/rules.fw").read_text().split("@xdp(lan)")[1]
  assert "drop if pkt.dst_ip in 224.0.0.0/4" in lan
  assert "drop if pkt.dst_ip == 255.255.255.255" in lan
  assert lan.index("255.255.255.255") < lan.index("\nmasquerade\n")
def test_binding_dhcp_enables_dnsmasq(tmp_path):
  """The unit set follows the model, not a fixed list."""
  _, _, runner, _ = full_run(tmp_path, GATEWAY)
  assert "f-dnsmasq.service" in runner.systemctl_enabled()
  assert "f-chrony.service" not in runner.systemctl_enabled()
def test_binding_ntp_enables_chrony(tmp_path):
  """Same shape, for time."""
  doc = json.loads(json.dumps(GATEWAY))
  doc["system"]["services"]["ntp"] = [{"zone": "lan",
                                       "upstream": ["pool.ntp.org"]}]
  _, _, runner, _ = full_run(tmp_path, doc)
  assert "f-chrony.service" in runner.systemctl_enabled()
def test_a_v01_provisioning_file_is_refused_by_name(tmp_path):
  """Not ignored. Ignoring it provisions a box it does not describe."""
  root = make_box(tmp_path)
  provision = root / "boot/f-provision.yaml"
  provision.write_text(yaml.safe_dump({
    "hostname": "old", "management": {"address": "192.168.1.1/24"},
    "interfaces": ["lan0", "lan1"]}))
  runner = FakeRunner(outputs={
    "f-install verify --format": make_box.report})
  boot = provisioner(root, runner, provision)
  boot.f_install = root / "usr/local/bin/f-install"
  assert boot.run_all() == 1
  step = next(s for s in boot.steps if s.name == "read provisioning")
  assert step.outcome is Outcome.FAILED
  assert "`management`" in step.detail
  assert "`interfaces`" in step.detail
  assert "system.interfaces" in step.detail
  assert not (root / "etc/f/system.yaml").exists()
def test_a_supplied_policy_is_installed_verbatim(tmp_path):
  """An operator who brought their own policy gets theirs."""
  root = make_box(tmp_path)
  (root / "boot/rules.fw").write_text(
    "zone mgmt = [enp1s0]\n@xdp(mgmt)\ndefault drop\n")
  doc = {"policy": {"source": "rules.fw"}}
  provision = root / "boot/f-provision.yaml"
  provision.write_text(yaml.safe_dump(doc))
  runner = _Runner(_bundle_writer(root))
  runner.inner.outputs["f-install verify --format"] = make_box.report
  boot = provisioner(root, runner, provision)
  boot.f_install = root / "usr/local/bin/f-install"
  assert boot.run_all() == 0
  assert (root / "etc/f/rules.fw").read_text().startswith(
    "zone mgmt = [enp1s0]")
def test_a_supplied_policy_that_is_not_there_is_a_failure(tmp_path):
  """Named, rather than quietly replaced with the default."""
  root = make_box(tmp_path)
  provision = root / "boot/f-provision.yaml"
  provision.write_text(yaml.safe_dump(
    {"policy": {"source": "nope.fw"}}))
  runner = FakeRunner(outputs={
    "f-install verify --format": make_box.report})
  boot = provisioner(root, runner, provision)
  boot.f_install = root / "usr/local/bin/f-install"
  assert boot.run_all() == 1
  step = next(s for s in boot.steps if s.name == "policy")
  assert step.outcome is Outcome.FAILED
  assert "nope.fw" in step.detail
# -- degradation ------------------------------------------------------
def test_a_service_that_will_not_start_degrades_and_names_itself(
    tmp_path):
  """Two of three started is not 'started'."""
  root = make_box(tmp_path)
  runner = _Runner(_bundle_writer(root))
  runner.inner.outputs["f-install verify --format"] = make_box.report
  runner.inner.failures["systemctl enable --now"] = (
    1, "Job for einheit-f-ui.service failed")
  boot = provisioner(root, runner)
  boot.f_install = root / "usr/local/bin/f-install"
  assert boot.run_all() == 2
  step = next(s for s in boot.steps if s.name == "start services")
  assert step.outcome is Outcome.DEGRADED
  assert "fd.service" in step.detail
  # A degraded run still provisioned the box.
  assert (root / "etc/f/.provisioned").exists()
def test_apply_system_failing_stops_the_run(tmp_path):
  """Nothing downstream of the network configuration can be right."""
  root = make_box(tmp_path)
  runner = FakeRunner(outputs={
    "f-install verify --format": make_box.report})
  boot = provisioner(root, runner)
  boot.f_install = root / "usr/local/bin/f-install"

  real = runner.__call__

  def call(argv, **kwargs):
    result = real(argv, **kwargs)
    if argv[0] == "f-sysconf" and argv[-1] == "apply":
      return subprocess.CompletedProcess(
        argv, 1, "", "SC031: zone testnet wants ra and has no "
                     "address6")
    return result

  boot.run = call
  assert boot.run_all() == 1
  step = next(s for s in boot.steps if s.name == "apply system")
  assert step.outcome is Outcome.FAILED
  assert "SC031" in step.detail
  assert not (root / "etc/f/.provisioned").exists()
def test_a_box_with_no_ports_is_a_failure(tmp_path):
  """A firewall with nothing to filter is not a provisioned box."""
  root = make_box(tmp_path, ports=())
  runner = FakeRunner(outputs={
    "f-install verify --format": make_box.report})
  boot = provisioner(root, runner)
  boot.f_install = root / "usr/local/bin/f-install"
  assert boot.run_all() == 1
  step = next(s for s in boot.steps if s.name == "system.yaml")
  assert step.outcome is Outcome.FAILED
  assert "no ethernet ports" in step.detail
# -- the pure renderers -----------------------------------------------
def test_a_zone_with_no_interfaces_gets_no_block():
  """A program attached to nothing inspects nothing (BUGLOG #43)."""
  model = {"zones": {"wan": {}, "empty": {}},
           "interfaces": {"wan0": {"zone": "wan"}}}
  policy = firstboot.render_policy(model, when=WHEN)
  assert "@xdp(wan)" in policy
  assert "@xdp(empty)" not in policy
  assert "zone empty =" not in policy
  assert "has no interfaces" in policy
def test_management_ports_are_configurable():
  """An operator who moved SSH still gets in."""
  model = {"zones": {"mgmt": {}},
           "interfaces": {"p0": {"zone": "mgmt"}}}
  policy = firstboot.render_policy(model, management_ports=[2222],
                                   when=WHEN)
  assert "pkt.dst_port == 2222" in policy
  assert "pkt.dst_port == 22\n" not in policy
def test_read_ports_is_stable_in_order(tmp_path):
  """The same hardware must produce the same file every time."""
  root = make_box(tmp_path, ports=(
    ("enp3s0", "aa:bb:cc:dd:ee:03", False),
    ("enp1s0", "aa:bb:cc:dd:ee:01", True),
    ("enp2s0", "aa:bb:cc:dd:ee:02", False)))
  names = [p.name for p in
           firstboot.read_ports(root / "sys/class/net")]
  assert names == ["enp1s0", "enp2s0", "enp3s0"]
def test_carrier_is_recorded_as_a_comment(tmp_path):
  """Which port had a cable in it at first boot is worth knowing."""
  root, _, _, _ = full_run(tmp_path)
  text = (root / "etc/f/system.yaml").read_text()
  assert "# link up" in text
  assert "# no link at first boot" in text
# -- the generated policy against the real compiler --------------------

# The `fwl` on a workstation's PATH is stale and accepts a different
# language from the one in this tree. Importing the in-tree compiler is
# the only way this test checks what it thinks it is checking.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent
                       / "fwl"))
def _analyze(text):
  """Run the in-tree compiler's front end over a policy source."""
  from fwl import analyzer, parser
  return analyzer.analyze(parser.parse(text))
def test_the_default_policy_is_accepted_by_the_compiler(tmp_path):
  """firstboot must not write a policy the box then refuses.

  The failure this catches is the whole shape of the old provisioner:
  a file that looks like a policy, that nothing ever compiled.
  """
  root, _, _, _ = full_run(tmp_path)
  program = _analyze((root / "etc/f/rules.fw").read_text())
  assert [z.name for z in program.zones] == ["mgmt"]
  assert len(program.programs) == 1
def test_the_gateway_policy_is_accepted_by_the_compiler(tmp_path):
  """Two zones, NAT and a redirect, through the real front end."""
  root, _, _, _ = full_run(tmp_path, GATEWAY)
  program = _analyze((root / "etc/f/rules.fw").read_text())
  assert {z.name for z in program.zones} == {"wan", "lan"}
  assert len(program.programs) == 2
def test_the_generated_policy_attaches_to_every_port(tmp_path):
  """A zone in the model that no program covers is a blind port.

  BUGLOG #43 was a bundle that loaded, reported a zone program and
  inspected nothing. The generator's version of that mistake is a
  system.yaml with three ports and a policy naming two.
  """
  root, boot, _, _ = full_run(tmp_path, ports=(
    ("enp1s0", "aa:bb:cc:dd:ee:01", True),
    ("enp2s0", "aa:bb:cc:dd:ee:02", False),
    ("enp3s0", "aa:bb:cc:dd:ee:03", False)))
  program = _analyze((root / "etc/f/rules.fw").read_text())
  covered = set()
  for zone in program.zones:
    covered.update(zone.interfaces)
  model = yaml.safe_load((root / "etc/f/system.yaml").read_text())
  assert covered == set(model["interfaces"])
# -- what systemd says, not what systemctl returned --------------------

def test_a_flapping_unit_is_not_a_started_unit(tmp_path):
  """`enable --now` exits 0 for a service in auto-restart.

  einheit-f-ui.service named a group no box has, systemd failed at
  step GROUP before exec, and the unit sat in auto-restart. The
  command returned success, `is-active` said `activating`, and the
  provisioner declared four of four units started.
  """
  root = make_box(tmp_path)
  runner = _Runner(_bundle_writer(root))
  runner.inner.outputs["f-install verify --format"] = make_box.report
  runner.inner.unit_states["einheit-f-ui.service"] = (
    "activating", "auto-restart", "67")
  boot = provisioner(root, runner)
  boot.f_install = root / "usr/local/bin/f-install"
  assert boot.run_all() == 2
  step = next(s for s in boot.steps if s.name == "start services")
  assert step.outcome is Outcome.DEGRADED
  assert "einheit-f-ui.service" in step.detail
  assert "67 restart" in step.detail
def test_a_unit_that_crashed_and_recovered_is_still_reported(tmp_path):
  """Active after twelve restarts is a service that is crashing."""
  root = make_box(tmp_path)
  runner = _Runner(_bundle_writer(root))
  runner.inner.outputs["f-install verify --format"] = make_box.report
  runner.inner.unit_states["fd.service"] = ("active", "running", "12")
  boot = provisioner(root, runner)
  boot.f_install = root / "usr/local/bin/f-install"
  assert boot.run_all() == 2
  step = next(s for s in boot.steps if s.name == "start services")
  assert "fd.service" in step.detail and "12 restart" in step.detail
def test_units_that_really_are_running_are_not_flagged(tmp_path):
  """The check must be able to say yes, or it says nothing."""
  _, boot, _, code = full_run(tmp_path)
  assert code == 0
  step = next(s for s in boot.steps if s.name == "start services")
  assert step.outcome is Outcome.DONE
  assert "running" in step.detail
# -- the session it would cut ------------------------------------------

def test_provisioning_over_ssh_is_refused(tmp_path):
  """Measured on a real box: the run severed the session making it."""
  root = make_box(tmp_path)
  runner = FakeRunner(outputs={
    "f-install verify --format": make_box.report})
  boot = provisioner(root, runner,
                     env={"SSH_CONNECTION": "10.0.0.5 51000 10.0.0.9 22"})
  boot.f_install = root / "usr/local/bin/f-install"
  assert boot.run_all() == 1
  step = next(s for s in boot.steps if s.name == "session")
  assert step.outcome is Outcome.FAILED
  assert "SSH" in step.detail
  assert "apply system confirmed" in step.hint
  assert not (root / "etc/f/system.yaml").exists()
  assert not (root / "etc/f/.provisioned").exists()
def test_force_provisions_over_ssh_and_says_what_it_risks(tmp_path):
  """An operator who can reach the box another way is not blocked."""
  root = make_box(tmp_path)
  runner = _Runner(_bundle_writer(root))
  runner.inner.outputs["f-install verify --format"] = make_box.report
  boot = provisioner(root, runner, force=True,
                     env={"SSH_CONNECTION": "10.0.0.5 51000 10.0.0.9 22"})
  boot.f_install = root / "usr/local/bin/f-install"
  assert boot.run_all() == 2
  step = next(s for s in boot.steps if s.name == "session")
  assert step.outcome is Outcome.DEGRADED
  assert "nothing puts it back" in step.hint
  assert (root / "etc/f/.provisioned").exists()
def test_a_console_run_is_not_obstructed(tmp_path):
  """The real first boot has no session, and pays nothing for this."""
  _, boot, _, code = full_run(tmp_path)
  assert code == 0
  step = next(s for s in boot.steps if s.name == "session")
  assert step.outcome is Outcome.DONE
