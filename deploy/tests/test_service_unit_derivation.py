"""The Python half and the C++ half must name the same units.

`firstboot.py` enables the units the model implies at provisioning
time; `apply system` enables them every time after that. There is one
derivation behind both — `f::sysconfig::PlanServiceUnits` — and
firstboot reaches it by running `f-sysconf render units` rather than
keeping a table of its own.

The firstboot tests still need that answer without a build tree, so
`conftest.wanted_service_units` is a stand-in. This file is what makes
a stand-in safe: it runs the real binary over models chosen to sit on
either side of every judgement the derivation makes, and requires the
two to agree exactly. If they ever do not, the stand-in is wrong and
the firstboot tests have been proving something about a box that does
not exist.

It does not skip when the binary is missing. A test whose whole
content is an agreement cannot make the claim without both halves, and
"skipped" in a green run is how a check stops being one.
"""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from conftest import render_units_stdout

REPO = Path(__file__).resolve().parents[2]

# Each case is (name, system.yaml). They are chosen for the boundaries,
# not for coverage: a service bound to a placed zone and to an unplaced
# one, each service alone and together, and a box that binds nothing.
CASES = {
  "nothing-bound": """
zones:
  lan:
interfaces:
  lan0:
    mac: "52:54:00:aa:bb:01"
    address: 10.10.0.1/24
    zone: lan
""",
  "dhcp-on-a-placed-zone": """
zones:
  lan:
interfaces:
  lan0:
    mac: "52:54:00:aa:bb:01"
    address: 10.10.0.1/24
    zone: lan
services:
  dhcp:
    - zone: lan
      range: 10.10.0.100-10.10.0.200
""",
  "dns-only": """
zones:
  lan:
interfaces:
  lan0:
    mac: "52:54:00:aa:bb:01"
    address: 10.10.0.1/24
    zone: lan
services:
  dns:
    - zone: lan
      upstream: [9.9.9.9]
""",
  "ntp-only": """
zones:
  lan:
interfaces:
  lan0:
    mac: "52:54:00:aa:bb:01"
    address: 10.10.0.1/24
    zone: lan
services:
  ntp:
    - zone: lan
      upstream: [pool.ntp.org]
""",
  "all-three": """
zones:
  lan:
interfaces:
  lan0:
    mac: "52:54:00:aa:bb:01"
    address: 10.10.0.1/24
    zone: lan
services:
  dhcp:
    - zone: lan
      range: 10.10.0.100-10.10.0.200
  dns:
    - zone: lan
      upstream: [9.9.9.9]
  ntp:
    - zone: lan
      upstream: [pool.ntp.org]
""",
}

def find_f_sysconf():
  """Where the built binary is, or a message saying it is not."""
  for candidate in (REPO / "build" / "f-sysconf",
                    REPO / "build" / "bin" / "f-sysconf"):
    if candidate.is_file() and os.access(candidate, os.X_OK):
      return candidate
  found = shutil.which("f-sysconf")
  return Path(found) if found else None

def render_units(binary, path):
  """Run `f-sysconf render units` over one configuration."""
  proc = subprocess.run(
    [str(binary), "-c", str(path), "render", "units"],
    capture_output=True, text=True, check=False)
  assert proc.returncode == 0, (
    f"f-sysconf render units failed on {path.name}: {proc.stderr}")
  return proc.stdout

@pytest.fixture(scope="module")
def binary():
  """The built f-sysconf, or a failure naming how to get one."""
  found = find_f_sysconf()
  assert found is not None, (
    "f-sysconf is not built. This test is an agreement between the "
    "C++ derivation and the Python stand-in the firstboot tests use, "
    "and it cannot be checked with only one half present. "
    "`cmake --build --preset default` builds it.")
  return found

@pytest.mark.parametrize("name", sorted(CASES))
def test_the_two_halves_name_the_same_units(binary, tmp_path, name):
  """The real derivation and the stand-in agree, line for line."""
  path = tmp_path / "system.yaml"
  path.write_text(CASES[name], encoding="utf-8")
  model = yaml.safe_load(CASES[name])
  assert render_units(binary, path) == render_units_stdout(model), (
    f"case {name}: deploy/tests/conftest.py disagrees with "
    f"f::sysconfig::PlanServiceUnits, so every firstboot test that "
    f"uses the stand-in has been proving something about a box that "
    f"does not exist")

def test_the_cases_exercise_both_answers(binary, tmp_path):
  """Guard the guard.

  If every case produced the same output the agreement above would be
  satisfied by two functions that always return the same constant.
  """
  seen = set()
  for name, text in CASES.items():
    path = tmp_path / f"{name}.yaml"
    path.write_text(text, encoding="utf-8")
    seen.add(render_units(binary, path))
  assert len(seen) >= 4, (
    f"only {len(seen)} distinct answers across {len(CASES)} cases")

# The one case where the two derivations could differ — a service
# bound to a zone with no port in it, which `PlanDnsmasq` refuses to
# call `needed` and the Python stand-in would have to reproduce — never
# reaches either of them: the model refuses it first. Pinned here so
# that stays true, because if SC021 ever softened, the stand-in and the
# binary would start disagreeing on a document a box could hold.
UNPLACED = """
zones:
  lan:
  dmz:
interfaces:
  lan0:
    mac: "52:54:00:aa:bb:01"
    address: 10.10.0.1/24
    zone: lan
services:
  dhcp:
    - zone: dmz
      range: 10.20.0.100-10.20.0.200
"""

def test_a_service_with_nowhere_to_answer_never_reaches_a_unit(
    binary, tmp_path):
  """It is refused as a model, before any unit is derived from it."""
  path = tmp_path / "system.yaml"
  path.write_text(UNPLACED, encoding="utf-8")
  proc = subprocess.run(
    [str(binary), "-c", str(path), "render", "units"],
    capture_output=True, text=True, check=False)
  assert proc.returncode != 0
  assert "SC021" in proc.stderr, proc.stderr
  assert "f-dnsmasq.service" not in proc.stdout

def test_the_output_is_a_format_and_not_a_sentence(binary, tmp_path):
  """firstboot parses this, so its shape is a contract."""
  path = tmp_path / "system.yaml"
  path.write_text(CASES["all-three"], encoding="utf-8")
  lines = render_units(binary, path).splitlines()
  assert lines, "no units named at all"
  for line in lines:
    state, _, unit = line.partition(" ")
    assert state in ("wanted", "unwanted"), line
    assert unit.endswith(".service"), line
  # And the unit set is what the manifest installs, so a service added
  # to the derivation without a unit file cannot pass unnoticed.
  manifest = yaml.safe_load(
    (REPO / "deploy" / "manifest.yaml").read_text(encoding="utf-8"))
  installed = json.dumps(manifest)
  for line in lines:
    unit = line.split(" ", 1)[1]
    assert unit in installed, (
      f"{unit} is derived from the model and is in no manifest entry")
