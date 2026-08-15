"""The one thing f-firstboot.service must never say again.

A unit that is ordered *before* another unit cannot start that unit
and wait for it. systemd will not run the second job until the first
one is done, and the first one is blocked on the second. For a
`Type=oneshot` service the start timeout defaults to infinity, so
nothing breaks the cycle: the box reaches neither multi-user.target
nor the marker, and sits there.

That is not a hypothetical ordering puzzle. It is what the first f
appliance image that got as far as starting services actually did,
and it was invisible until then because every earlier run had stopped
at an earlier step. This file encodes the shape so it cannot come
back quietly.
"""

import re
import sys
from pathlib import Path

DEPLOY = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(DEPLOY / "firstboot"))
import firstboot  # noqa: E402
UNIT = DEPLOY / "systemd/f-firstboot.service"
def directives(unit_text, name):
  """Every value of one directive, split into unit names."""
  found = []
  for line in unit_text.splitlines():
    line = line.strip()
    if line.startswith("#") or "=" not in line:
      continue
    key, _, value = line.partition("=")
    if key.strip() == name:
      found += value.split()
  return found
def units_firstboot_starts():
  """Every unit the provisioner can pass to `systemctl enable --now`.

  Read off `plan_units` rather than copied, so a new service added to
  the plan is covered by this test the day it is added.
  """
  boot = firstboot.Firstboot(root="/nonexistent")
  names = set()
  # Truthy values, because `plan_units` asks whether a service is
  # bound and an empty mapping is not.
  bound = {"zone": "lan"}
  for services in ({}, {"dhcp": bound}, {"dns": bound},
                   {"ntp": bound},
                   {"dhcp": bound, "dns": bound, "ntp": bound}):
    boot.model = {"services": services}
    boot.plan_units()
    names.update(boot.units)
  return names
def test_the_provisioner_starts_more_than_the_datapath():
  """Guard the guard: a plan of one unit would make this vacuous."""
  assert len(units_firstboot_starts()) >= 5
def test_it_is_not_ordered_before_anything_it_starts():
  """The deadlock, stated as an invariant."""
  text = UNIT.read_text(encoding="utf-8")
  ordered_before = set(directives(text, "Before"))
  started = units_firstboot_starts()
  assert not (ordered_before & started), (
    "f-firstboot.service is ordered Before "
    f"{sorted(ordered_before & started)}, and firstboot.py starts "
    "those units synchronously from its own ExecStart. systemd will "
    "hold their start jobs until f-firstboot finishes and "
    "f-firstboot will not finish until they start; Type=oneshot has "
    "no start timeout, so the boot hangs.")
def test_the_condition_that_makes_it_run_once_is_still_there():
  """The other half: a re-run must be a decision, not an accident."""
  text = UNIT.read_text(encoding="utf-8")
  assert "ConditionPathExists=!/etc/f/.provisioned" in text
def test_it_still_waits_for_the_filesystem_and_the_network():
  """Removing an ordering is only safe if the real ones remain."""
  after = set(directives(UNIT.read_text(encoding="utf-8"), "After"))
  assert {"local-fs.target", "systemd-networkd.service"} <= after
def test_every_unit_it_starts_is_installed_by_the_manifest():
  """A unit the plan names and the image lacks is a failed enable."""
  manifest = (DEPLOY / "manifest.yaml").read_text(encoding="utf-8")
  installed = set(re.findall(r"dest:\s*/lib/systemd/system/(\S+)",
                             manifest))
  assert units_firstboot_starts() <= installed
