"""Behavioural tests for the deployable set and its installer.

These are written against the real `deploy/manifest.yaml` and the real
repository, not a fixture, because the thing being protected is the
enumeration itself. A test that invents its own three-item manifest
would still pass on the day somebody adds a binary and forgets to
deploy it, which is the bug that produced this file.
"""

import os
import stat
import subprocess
from pathlib import Path
import pytest
import f_install
from f_install import Scope, State, Verdict

REPO = Path(__file__).resolve().parent.parent.parent
MANIFEST = REPO / "deploy" / "manifest.yaml"
@pytest.fixture
def manifest():
  """The real manifest, resolved at the default prefix."""
  return f_install.load_manifest(MANIFEST)
def _fake_build_dir(tmp_path, manifest, omit=()):
  """A build directory holding every binary the manifest names.

  Args:
    tmp_path: pytest temporary directory.
    manifest: The manifest whose binaries to fake.
    omit: Ids to leave out, to simulate a build that did not produce
      them.

  Returns:
    The path to the fake build directory.
  """
  build = tmp_path / "build"
  build.mkdir(parents=True)
  for item in manifest.components:
    if item.kind != "binary" or item.id in omit:
      continue
    target = build / item.source
    target.write_text(f"#!/bin/sh\necho {item.id}\n")
    target.chmod(0o755)
  return build
def _finding(report, item_id):
  """The single finding for one manifest id."""
  matches = [f for f in report.findings if f.item.id == item_id]
  assert len(matches) == 1, f"{item_id} appears {len(matches)} times"
  return matches[0]
def test_manifest_substitutes_the_prefix(manifest):
  """{prefix} is resolved, and an override moves everything at once."""
  assert _item(manifest, "fd").dest == "/usr/local/bin/fd"
  moved = f_install.load_manifest(MANIFEST, prefix="/opt/f")
  assert _item(moved, "fd").dest == "/opt/f/bin/fd"
  # Absolute destinations that were never prefixed do not move.
  assert _item(moved, "unit-fd").dest == "/lib/systemd/system/fd.service"
def _item(manifest, item_id):
  """One component by id."""
  return next(i for i in manifest.components if i.id == item_id)
def test_every_item_says_what_it_costs(manifest):
  """No entry may be a bare path.

  The whole point of the file is that a missing item is reported with
  the service it breaks; an entry with no `why` and no `needed_by`
  would print as a path and put the operator back where they started.
  """
  for item in manifest.all_items:
    assert item.why.strip(), f"{item.id} has no `why`"
    if item.kind != "absent":
      assert item.needed_by.strip(), f"{item.id} has no `needed_by`"
    if not item.required and item.kind != "absent":
      assert item.required_when.strip(), (
        f"{item.id} is optional and does not say when it is not")
def test_the_four_binaries_the_old_staging_dir_forgot(manifest):
  """The set contains what the hand-maintained directory did not.

  `build-aarch64/staging/` held fd, fctl and einheit-f-ui. A box built
  from it had no CLI, no configuration daemon and no way to turn
  system.yaml into anything.
  """
  ids = {i.id for i in manifest.components}
  for missing_before in ("einheit-f", "f-confd", "f-sysconf"):
    assert missing_before in ids
    assert _item(manifest, missing_before).required
def test_verify_names_the_missing_binary(tmp_path, manifest):
  """A box without f-confd is incomplete, and says which item."""
  build = _fake_build_dir(tmp_path, manifest)
  root = tmp_path / "root"
  f_install.stage(manifest, build, REPO, root, with_pip=False)
  (root / "usr/local/bin/f-confd").unlink()
  report = f_install.verify(manifest, root=root)
  assert report.verdict is Verdict.INCOMPLETE
  assert _finding(report, "f-confd").state is State.MISSING
  assert "f-confd" in {f.item.id for f in report.missing_required}
def test_missing_is_not_the_same_value_as_unreadable(tmp_path,
                                                     manifest):
  """"Not there" and "not allowed to look" are different answers.

  A verifier that collapses them reports a working box as broken when
  it is run by the wrong user, which teaches the operator to ignore
  it.
  """
  if os.geteuid() == 0:
    pytest.skip("root can read anything")
  build = _fake_build_dir(tmp_path, manifest)
  root = tmp_path / "root"
  f_install.stage(manifest, build, REPO, root, with_pip=False)
  closed = root / "usr/local/bin"
  mode = closed.stat().st_mode
  closed.chmod(0)
  try:
    report = f_install.verify(manifest, root=root)
  finally:
    closed.chmod(stat.S_IMODE(mode))
  assert _finding(report, "fd").state is State.UNREADABLE
  assert report.verdict is Verdict.INDETERMINATE
  assert "fd" in {f.item.id for f in report.not_checked}
def test_a_staged_root_does_not_claim_the_hosts_clang(tmp_path,
                                                      manifest):
  """A directory cannot answer whether clang is installed."""
  build = _fake_build_dir(tmp_path, manifest)
  root = tmp_path / "root"
  f_install.stage(manifest, build, REPO, root, with_pip=False)
  report = f_install.verify(manifest, root=root)
  assert report.scope is Scope.STAGED
  for host_item in ("ext-clang", "ext-python3", "mount-bpffs"):
    assert _finding(report, host_item).state is State.NOT_CHECKED
  unchecked = {f.item.id for f in report.not_checked}
  assert {"ext-clang", "mount-bpffs"} <= unchecked
def test_a_staged_root_defers_the_compiler_import(tmp_path, manifest):
  """fwl staged as a file is not fwl proven to import."""
  build = _fake_build_dir(tmp_path, manifest)
  root = tmp_path / "root"
  f_install.stage(manifest, build, REPO, root, with_pip=False)
  assert _finding(report_of(manifest, root), "fwl").state is (
    State.MISSING)
  fwl = root / "usr/local/bin/fwl"
  fwl.parent.mkdir(parents=True, exist_ok=True)
  fwl.write_text("#!/bin/sh\n")
  assert _finding(report_of(manifest, root), "fwl").state is (
    State.NOT_CHECKED)
def report_of(manifest, root):
  """Verify shorthand."""
  return f_install.verify(manifest, root=root)
def test_optional_missing_is_degraded_not_incomplete(tmp_path,
                                                     manifest):
  """f-api is not there, and the box still works."""
  build = _fake_build_dir(tmp_path, manifest)
  root = tmp_path / "root"
  f_install.stage(manifest, build, REPO, root, with_pip=False)
  _complete_a_staged_root(root)
  assert report_of(manifest, root).verdict is Verdict.COMPLETE
  (root / "usr/local/bin/f-api").unlink()
  report = report_of(manifest, root)
  assert report.verdict is Verdict.DEGRADED
  assert _finding(report, "f-api").state is State.MISSING
def _complete_a_staged_root(root):
  """Stand in for the pieces `stage --no-pip` leaves out."""
  fwl = root / "usr/local/bin/fwl"
  fwl.parent.mkdir(parents=True, exist_ok=True)
  fwl.write_text("#!/bin/sh\n")
def test_a_shadowing_networkd_unit_is_a_conflict(tmp_path, manifest):
  """The v0.1 example that quietly takes eth0 away from the model."""
  build = _fake_build_dir(tmp_path, manifest)
  root = tmp_path / "root"
  f_install.stage(manifest, build, REPO, root, with_pip=False)
  _complete_a_staged_root(root)
  stale = root / "etc/systemd/network/10-eth0.network"
  stale.parent.mkdir(parents=True, exist_ok=True)
  stale.write_text("[Match]\nName=eth0\n")
  report = report_of(manifest, root)
  assert _finding(report, "stale-networkd-eth0").state is (
    State.CONFLICT)
  assert report.verdict is Verdict.DEGRADED
def test_remove_stale_deletes_it_and_says_so(tmp_path, manifest):
  """--remove-stale is the only thing that deletes anything."""
  build = _fake_build_dir(tmp_path, manifest)
  root = tmp_path / "root"
  stale = root / "etc/systemd/network/20-lan.network"
  stale.parent.mkdir(parents=True, exist_ok=True)
  stale.write_text("[Match]\nName=lan*\n")

  actions = f_install.stage(manifest, build, REPO, root,
                            with_pip=False)
  assert stale.exists(), "stage must not delete without being asked"
  refused = next(a for a in actions
                 if a.item.id == "stale-networkd-lan")
  assert not refused.done and "--remove-stale" in refused.detail

  actions = f_install.stage(manifest, build, REPO, root,
                            with_pip=False, remove_stale=True)
  assert not stale.exists()
  removed = next(a for a in actions
                 if a.item.id == "stale-networkd-lan")
  assert removed.done and "removed" in removed.detail
def test_a_missing_required_source_writes_nothing(tmp_path, manifest):
  """Pre-flight names every missing source and installs none of them.

  Half an appliance is worse than none, because the half that is there
  starts and looks like a box.
  """
  build = _fake_build_dir(tmp_path, manifest,
                          omit=("f-confd", "f-sysconf"))
  root = tmp_path / "root"
  with pytest.raises(FileNotFoundError) as caught:
    f_install.stage(manifest, build, REPO, root, with_pip=False)
  message = str(caught.value)
  assert "f-confd" in message and "f-sysconf" in message
  assert not root.exists() or not any(root.rglob("*"))
def test_a_missing_optional_source_is_reported_and_skipped(
    tmp_path, manifest):
  """The box still gets built; the gap is named."""
  build = _fake_build_dir(tmp_path, manifest, omit=("f-api",))
  root = tmp_path / "root"
  actions = f_install.stage(manifest, build, REPO, root,
                            with_pip=False)
  skipped = next(a for a in actions if a.item.id == "f-api")
  assert not skipped.done and "optional" in skipped.detail
  assert (root / "usr/local/bin/fd").exists()
def test_stage_then_verify_is_complete(tmp_path, manifest):
  """The round trip: everything the manifest names ends up staged."""
  build = _fake_build_dir(tmp_path, manifest)
  root = tmp_path / "root"
  f_install.stage(manifest, build, REPO, root, with_pip=False)
  _complete_a_staged_root(root)
  report = report_of(manifest, root)
  bad = [f for f in report.findings if not f.ok]
  assert not bad, [(f.item.id, f.state) for f in bad]
  assert report.verdict is Verdict.COMPLETE
  assert report.scope is Scope.STAGED
def test_staged_trees_are_not_empty(tmp_path, manifest):
  """A `tree` that copied nothing is not a tree that is present."""
  build = _fake_build_dir(tmp_path, manifest)
  root = tmp_path / "root"
  f_install.stage(manifest, build, REPO, root, with_pip=False)
  assert (root / "usr/share/einheit-ui/templates/fw"
          "/dashboard.html.inja").exists()
  for entry in (root / "usr/share/einheit-ui/assets").iterdir():
    del entry
    break
  else:
    pytest.fail("assets staged empty")
def test_an_empty_tree_is_reported_as_empty(tmp_path, manifest):
  """Present-but-empty is its own answer, not 'present'."""
  build = _fake_build_dir(tmp_path, manifest)
  root = tmp_path / "root"
  f_install.stage(manifest, build, REPO, root, with_pip=False)
  _complete_a_staged_root(root)
  assets = root / "usr/share/einheit-ui/assets"
  for child in list(assets.iterdir()):
    if child.is_dir():
      subprocess.run(["rm", "-rf", str(child)], check=True)
    else:
      child.unlink()
  report = report_of(manifest, root)
  assert _finding(report, "ui-assets").state is State.EMPTY
  assert report.verdict is Verdict.INCOMPLETE
def test_a_failing_verify_command_reads_as_missing(manifest):
  """`fwl version` failing means the compiler is not usable."""
  calls = []

  def fake_run(argv, **kwargs):
    calls.append(argv)
    return subprocess.CompletedProcess(
      argv, 1, "", "ModuleNotFoundError: No module named 'fwl'")

  # Verify against "/" so the command is in scope; every path check
  # will fail on this host, which is fine — we are asserting on the
  # one item that has a command.
  report = f_install.verify(manifest, root="/", run=fake_run)
  finding = _finding(report, "fwl")
  if finding.state is State.MISSING and not calls:
    pytest.skip("no fwl binary on this host to get as far as the "
                "import check")
  assert calls == [["fwl", "version"]]
  assert finding.state is State.MISSING
  assert "ModuleNotFoundError" in finding.detail
def test_exit_codes_follow_the_verdict():
  """Every verdict has an exit code, and they are all different."""
  assert set(f_install.EXIT_CODES) == set(Verdict)
  assert len(set(f_install.EXIT_CODES.values())) == len(Verdict)
  assert f_install.EXIT_CODES[Verdict.COMPLETE] == 0
  assert f_install.EXIT_CODES[Verdict.INCOMPLETE] == 1
def test_main_verify_returns_the_verdicts_code(tmp_path, manifest,
                                               capsys):
  """The CLI's exit status is the machine-readable answer."""
  build = _fake_build_dir(tmp_path, manifest)
  root = tmp_path / "root"
  f_install.stage(manifest, build, REPO, root, with_pip=False)
  _complete_a_staged_root(root)
  assert f_install.main(
    ["--manifest", str(MANIFEST), "verify", "--root", str(root)]) == 0
  (root / "usr/local/bin/fd").unlink()
  assert f_install.main(
    ["--manifest", str(MANIFEST), "verify", "--root", str(root)]) == 1
  out = capsys.readouterr().out
  assert "fd" in out and "fd.service" in out
def test_json_report_carries_the_reasons(tmp_path, manifest):
  """`einheit-f show install` renders this; it needs more than paths."""
  build = _fake_build_dir(tmp_path, manifest, omit=("f-sysconf",))
  root = tmp_path / "root"
  try:
    f_install.stage(manifest, build, REPO, root, with_pip=False)
  except FileNotFoundError:
    pass
  build = _fake_build_dir(tmp_path / "b2", manifest)
  f_install.stage(manifest, build, REPO, root, with_pip=False)
  (root / "usr/local/bin/f-sysconf").unlink()
  blob = f_install.report_to_json(report_of(manifest, root))
  assert blob["verdict"] == "incomplete"
  entry = next(i for i in blob["items"] if i["id"] == "f-sysconf")
  assert entry["state"] == "missing"
  assert entry["needed_by"] == "apply system"
  assert "system.yaml" in entry["why"]
# -- present is not the same as runnable ------------------------------

def test_a_binary_whose_libraries_are_missing_is_not_present():
  """The defect: `fd` installed, executable, and dead at exec.

  It was linked against a libspdlog.so that lived in the build tree
  and was on no list. The unit reported exit 127 and the box reported
  a complete install.
  """
  def fake_ldd(argv, **kwargs):
    if argv[0] != "ldd":
      return subprocess.CompletedProcess(argv, 0, "", "")
    return subprocess.CompletedProcess(
      argv, 0,
      "\tlinux-vdso.so.1 (0x00007ffd)\n"
      "\tlibspdlog.so.1.16 => not found\n"
      "\tlibc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f)\n",
      "")

  names, checked = f_install.unresolved_libraries("/bin/x", fake_ldd)
  assert checked
  assert names == ["libspdlog.so.1.16"]
def test_a_static_binary_is_not_reported_as_unusable():
  """ldd's least helpful message is the most reassuring answer."""
  def fake_ldd(argv, **kwargs):
    return subprocess.CompletedProcess(
      argv, 1, "", "\tnot a dynamic executable\n")

  names, checked = f_install.unresolved_libraries("/bin/x", fake_ldd)
  assert checked and names == []
def test_ldd_being_unavailable_is_not_a_clean_bill():
  """"Could not look" is not "nothing missing"."""
  def no_ldd(argv, **kwargs):
    raise OSError("no ldd")

  names, checked = f_install.unresolved_libraries("/bin/x", no_ldd)
  assert names == [] and not checked
def test_the_shipped_binaries_are_self_contained():
  """No shipped binary may need a library from the build tree.

  This one runs against the actual build, not a fake: a FetchContent
  dependency built as a shared object has no packaged home on a target
  and nothing would install it.
  """
  repo = REPO
  build = repo / "build"
  if not (build / "fd").exists():
    pytest.skip("no native build here to inspect")
  manifest = f_install.load_manifest(MANIFEST)
  for item in manifest.components:
    if item.kind != "binary":
      continue
    binary = build / item.source
    if not binary.exists():
      continue
    proc = subprocess.run(["ldd", str(binary)],
                          capture_output=True, text=True)
    from_build_tree = [line.strip() for line in proc.stdout.splitlines()
                       if "_deps" in line or "/build/" in line]
    assert not from_build_tree, (
      f"{item.source} links against something in the build tree, "
      f"which no target will have:\n  " +
      "\n  ".join(from_build_tree))
# -- upgrading a box that is running --------------------------------

def test_a_running_binary_can_be_replaced(tmp_path, manifest):
  """An upgrade must not fail on the daemon it is upgrading.

  Writing through the destination gets ETXTBSY from the kernel for a
  binary that is executing, and the install that hit it stopped in the
  middle of the deployable set. Replacing the name instead works while
  the old inode is still running.
  """
  build = _fake_build_dir(tmp_path, manifest)
  root = tmp_path / "root"
  f_install.stage(manifest, build, REPO, root, with_pip=False)
  binary = root / "usr/local/bin/fd"
  binary.write_text("#!/bin/sh\nsleep 30\n")
  binary.chmod(0o755)
  running = subprocess.Popen([str(binary)])
  try:
    (build / "fd").write_text("#!/bin/sh\necho new\n")
    actions = f_install.stage(manifest, build, REPO, root,
                              with_pip=False)
    replaced = next(a for a in actions if a.item.id == "fd")
    assert replaced.done, replaced.detail
    assert "echo new" in binary.read_text()
  finally:
    running.terminate()
    running.wait()
def test_one_unwritable_item_does_not_stop_the_rest(tmp_path,
                                                    manifest):
  """A half-done install has to say which half, not raise."""
  if os.geteuid() == 0:
    pytest.skip("root can write anywhere")
  build = _fake_build_dir(tmp_path, manifest)
  root = tmp_path / "root"
  f_install.stage(manifest, build, REPO, root, with_pip=False)
  closed = root / "lib/systemd/system"
  mode = closed.stat().st_mode
  closed.chmod(0o500)
  try:
    actions = f_install.stage(manifest, build, REPO, root,
                              with_pip=False)
  finally:
    closed.chmod(stat.S_IMODE(mode))
  blocked = {a.item.id for a in actions if not a.done}
  assert "unit-fd" in blocked and "unit-f-confd" in blocked, blocked
  # Everything outside that directory still went in, and every one of
  # them is reported as done rather than swallowed by the first error.
  assert (root / "usr/local/bin/fd").exists()
  assert (root / "usr/local/share/f/firstboot.py").exists()
  assert "fd" not in blocked and "firstboot" not in blocked
