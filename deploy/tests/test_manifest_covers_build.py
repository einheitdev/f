"""The manifest must keep up with the build.

`f-confd` and `f-sysconf` were added to CMakeLists.txt, built on every
machine, and never deployed anywhere, because the thing that decided
what got deployed was a directory somebody copied files into. This
test is the mechanism that stops that happening again: a binary the
build produces is either in the deployable set or explicitly listed as
not deployed, and adding one without doing either fails here.
"""

import re
from pathlib import Path
import pytest
import f_install

REPO = Path(__file__).resolve().parent.parent.parent
CMAKELISTS = REPO / "CMakeLists.txt"
@pytest.fixture
def manifest():
  """The real manifest."""
  return f_install.load_manifest(REPO / "deploy" / "manifest.yaml")
@pytest.fixture
def cmake_text():
  """CMakeLists.txt as text."""
  return CMAKELISTS.read_text(encoding="utf-8")
def _executables(text):
  """Every target named by an add_executable() call."""
  return set(re.findall(r"add_executable\(\s*([A-Za-z0-9_.-]+)", text))
def _installed_targets(text):
  """Every target in an install(TARGETS ...) call."""
  found = set()
  for block in re.findall(r"install\(\s*TARGETS(.*?)\)", text,
                          re.DOTALL):
    for token in block.split():
      if token.upper() in ("RUNTIME", "LIBRARY", "ARCHIVE",
                           "DESTINATION", "PUBLIC_HEADER"):
        break
      found.add(token)
  return found
def test_every_built_binary_is_deployed_or_declared_not_to_be(
    manifest, cmake_text):
  """No binary may be silently absent from the deployable set."""
  built = _executables(cmake_text)
  deployed = {i.source for i in manifest.components
              if i.kind == "binary"}
  declared = set(manifest.not_deployed)
  unaccounted = built - deployed - declared
  assert not unaccounted, (
    f"CMakeLists.txt builds {sorted(unaccounted)} and the manifest "
    f"neither deploys them nor lists them under `not_deployed`. Add "
    f"them to deploy/manifest.yaml, with the sentence saying what "
    f"breaks without them.")
def test_the_manifest_deploys_nothing_the_build_does_not_make(
    manifest, cmake_text):
  """A binary entry pointing at nothing would fail at install time."""
  built = _executables(cmake_text)
  for item in manifest.components:
    if item.kind != "binary":
      continue
    assert item.source in built, (
      f"manifest deploys `{item.source}`, which CMakeLists.txt does "
      f"not build")
def test_cmake_install_and_the_manifest_agree(manifest, cmake_text):
  """`cmake --install` and `f-install stage` deploy the same binaries.

  They are two mechanisms for two situations — a developer installing
  a native build, and a cross build being staged into a rootfs — and
  the moment they disagree one of them is producing a box the other
  would call broken.
  """
  installed = _installed_targets(cmake_text)
  deployed = {i.source for i in manifest.components
              if i.kind == "binary"}
  assert installed == deployed, (
    f"install(TARGETS ...) has {sorted(installed - deployed)} that "
    f"the manifest does not, and the manifest has "
    f"{sorted(deployed - installed)} that it does not")
def test_every_shipped_unit_file_exists(manifest):
  """A unit entry whose source is gone would stage a box with no."""
  for item in manifest.components:
    if not item.dest.startswith("/lib/systemd/system/"):
      continue
    assert (REPO / item.source).exists(), (
      f"{item.id} names {item.source}, which is not in the tree")
def test_every_unit_in_the_tree_is_shipped(manifest):
  """A unit written and never deployed is a feature nobody has."""
  shipped = {Path(i.source).name for i in manifest.components
             if i.source}
  for unit in sorted((REPO / "deploy" / "systemd").glob("*.service")):
    assert unit.name in shipped, (
      f"deploy/systemd/{unit.name} exists and the manifest does not "
      f"install it")
def test_the_units_binaries_are_all_in_the_set(manifest):
  """Every ExecStart under the prefix names something we deploy.

  This is the check that would have caught the shipped state directly:
  f-confd.service starts /usr/local/bin/f-confd, and /usr/local/bin/
  f-confd was on no list at all.
  """
  destinations = {i.dest for i in manifest.components}
  for unit in sorted((REPO / "deploy" / "systemd").glob("*.service")):
    text = unit.read_text(encoding="utf-8")
    for exec_line in re.findall(r"^Exec\w+=([^\s\\]+)", text,
                                re.MULTILINE):
      if not exec_line.startswith("/usr/local/"):
        continue
      assert exec_line in destinations, (
        f"{unit.name} runs {exec_line}, which the deployable set "
        f"does not install")
def test_the_units_asserted_paths_are_accounted_for(manifest):
  """AssertPathExists= names a file something must have created.

  The dnsmasq and chrony units refuse to start without their generated
  config, which is the right behaviour and also means the directory
  holding it has to be in the set.
  """
  dirs = {i.dest for i in manifest.components if i.kind == "dir"}
  for unit in sorted((REPO / "deploy" / "systemd").glob("*.service")):
    text = unit.read_text(encoding="utf-8")
    for asserted in re.findall(r"^AssertPathExists=(\S+)", text,
                               re.MULTILINE):
      parent = str(Path(asserted).parent)
      if parent.startswith("/etc/chrony"):
        # chronyd's AppArmor profile confines it to /etc/chrony,
        # which the chrony package owns. See BUGLOG #30.
        continue
      assert parent in dirs, (
        f"{unit.name} asserts {asserted} and nothing in the set "
        f"creates {parent}")
# Accounts and groups a Debian base system has before f is installed.
# Anything a unit names that is not here has to be created by something
# in the deployable set, or the unit dies at step USER/GROUP with
# status 216 — before exec, so nothing it would have logged is logged.
STOCK_ACCOUNTS = {
  "root", "nobody", "nogroup", "www-data", "daemon", "systemd-network",
  "systemd-resolve", "messagebus", "dnsmasq", "_chrony",
}
def test_no_unit_names_an_account_nothing_creates(manifest):
  """The failure that read as `activating` for sixty-seven restarts.

  einheit-f-ui.service carried `SupplementaryGroups=f`. No box has ever
  had a group called `f`. systemd failed at step GROUP with 216 on
  every start, and because a unit in auto-restart reports `activating`
  rather than `failed`, the dashboard looked like it was coming up.
  """
  created = {i.dest.split(":", 1)[-1] for i in manifest.components
             if i.kind == "group"}
  for unit in sorted((REPO / "deploy" / "systemd").glob("*.service")):
    text = unit.read_text(encoding="utf-8")
    named = set()
    for key in ("User", "Group"):
      named.update(re.findall(rf"^{key}=(\S+)", text, re.MULTILINE))
    for line in re.findall(r"^SupplementaryGroups=(.*)$", text,
                           re.MULTILINE):
      named.update(line.split())
    unknown = named - STOCK_ACCOUNTS - created
    assert not unknown, (
      f"{unit.name} runs as, or joins, {sorted(unknown)}, which no "
      f"stock Debian system has and nothing in the deployable set "
      f"creates. systemd exits 216 before exec and the unit flaps.")
