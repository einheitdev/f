#!/usr/bin/env python3
"""Install an f appliance from the manifest, and check that one is.

`deploy/manifest.yaml` is the enumeration of everything an appliance
needs. This tool is its only consumer: it stages the set into a root
(`stage`), puts it on the running box (`install`), prints it (`list`),
and asks a box what it has of it (`verify`).

The design constraint is that a half-done install has to say which
half. So:

  * A missing source is named at pre-flight, together with every other
    missing source, and if any of them is required nothing is written
    at all. You get the whole list once instead of one failure per run.
  * Verification distinguishes "not there" from "could not look", and
    the verdict carries the scope it was reached in. A staged root
    cannot answer whether clang is installed, and says so rather than
    counting it as fine.

Exit codes:
  0  complete       everything in scope is present
  1  incomplete     a required item is missing
  2  degraded       only optional items are missing, or a stale file
                    that must not be present is
  3  indeterminate  something in scope could not be checked
"""

import argparse
import dataclasses
import enum
import json
import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path
import yaml

# Where to look for the manifest, in order. The first is the repo,
# where this file sits next to it; the rest are where an installed box
# has it. `f-install` is installed as /usr/local/bin/f-install, so the
# repo-relative guess is wrong there and would make the tool report
# "no manifest" on precisely the box it exists to check.
MANIFEST_SEARCH = (
  Path(__file__).resolve().parent / "manifest.yaml",
  Path("/usr/local/share/f/manifest.yaml"),
  Path("/usr/share/f/manifest.yaml"),
)
def default_manifest():
  """The first manifest that exists, or the first path we looked at.

  Returning a path that does not exist rather than None is deliberate:
  the error message then names where it looked first.
  """
  for candidate in MANIFEST_SEARCH:
    if candidate.exists():
      return candidate
  return MANIFEST_SEARCH[0]
DEFAULT_MANIFEST = MANIFEST_SEARCH[0]
class State(enum.Enum):
  """What one manifest item turned out to be on a given root.

  MISSING and UNREADABLE are separate values on purpose. "The file is
  not there" and "I was not allowed to look" lead to different actions,
  and a check that collapses them reports a box as broken when it is
  only being asked by the wrong user.

  UNUSABLE is the third one, and it was learned the hard way: `fd` was
  installed, executable, the right size, and died at exec because
  `libspdlog.so.1.16` lived in the build tree and nothing had ever
  shipped it. A check that only asks whether a path exists calls that
  box complete.
  """
  PRESENT = "present"
  MISSING = "missing"
  UNUSABLE = "unusable"
  WRONG_KIND = "wrong-kind"
  EMPTY = "empty"
  UNREADABLE = "unreadable"
  CONFLICT = "conflict"
  NOT_CHECKED = "not-checked"
class Scope(enum.Enum):
  """Where a verification ran, which bounds what it can conclude.

  TARGET is a live box: every item is checkable. STAGED is a directory
  being assembled, where the host's own clang, dnsmasq and bpffs mount
  are none of our business. A verdict without its scope would let a
  staged root claim it is a working appliance.
  """
  TARGET = "target"
  STAGED = "staged"
class Verdict(enum.Enum):
  """The one-word answer, and the exit code that goes with it."""
  COMPLETE = "complete"
  DEGRADED = "degraded"
  INCOMPLETE = "incomplete"
  INDETERMINATE = "indeterminate"
EXIT_CODES = {
  Verdict.COMPLETE: 0,
  Verdict.INCOMPLETE: 1,
  Verdict.DEGRADED: 2,
  Verdict.INDETERMINATE: 3,
}
@dataclasses.dataclass
class Item:
  """One line of the manifest, with its paths already resolved."""
  id: str
  group: str
  kind: str
  dest: str
  source: str = ""
  mode: str = ""
  requirement: str = "required"
  required_when: str = ""
  needed_by: str = ""
  provided_by: str = ""
  why: str = ""
  verify_command: list = dataclasses.field(default_factory=list)
  installed_by: str = ""

  @property
  def required(self):
    """True when the box does not work without this item."""
    return self.requirement == "required"
@dataclasses.dataclass
class Finding:
  """What one item turned out to be, and why that matters."""
  item: Item
  state: State
  detail: str = ""

  @property
  def ok(self):
    """True when this finding needs no action."""
    return self.state in (State.PRESENT, State.NOT_CHECKED)
@dataclasses.dataclass
class Report:
  """Every finding, plus the verdict they add up to."""
  scope: Scope
  root: str
  findings: list

  @property
  def verdict(self):
    """The strongest conclusion the findings support.

    Ordered so that a definite failure outranks an uncertainty: if a
    required file is known to be missing, the box is incomplete
    whether or not something else was unreadable.
    """
    if any(f.item.required and f.state in (
             State.MISSING, State.WRONG_KIND, State.EMPTY,
             State.UNUSABLE)
           for f in self.findings):
      return Verdict.INCOMPLETE
    if any(f.state is State.UNREADABLE for f in self.findings):
      return Verdict.INDETERMINATE
    if any(not f.ok for f in self.findings):
      return Verdict.DEGRADED
    return Verdict.COMPLETE

  @property
  def missing_required(self):
    """Required items that are definitely not there."""
    return [f for f in self.findings
            if f.item.required and f.state in (
              State.MISSING, State.WRONG_KIND, State.EMPTY,
              State.UNUSABLE)]

  @property
  def not_checked(self):
    """Items no conclusion was reached about."""
    return [f for f in self.findings
            if f.state in (State.NOT_CHECKED, State.UNREADABLE)]
class Manifest:
  """The deployable set, with {prefix} already substituted."""

  def __init__(self, doc, prefix=None):
    """Build a manifest from a parsed YAML document.

    Args:
      doc: The mapping loaded from manifest.yaml.
      prefix: Override for the document's own `prefix`.
    """
    self.version = doc.get("version", 0)
    self.prefix = prefix or doc.get("prefix", "/usr/local")
    self.components = [self._item(e, e.get("kind", "file"))
                       for e in doc.get("components", [])]
    self.absent = [self._item(e, "absent")
                   for e in doc.get("absent", [])]
    self.not_deployed = list(doc.get("not_deployed", []))

  def _item(self, entry, kind):
    """Turn one YAML entry into an Item with paths resolved."""
    fields = {f.name for f in dataclasses.fields(Item)}
    kwargs = {k: v for k, v in entry.items() if k in fields}
    kwargs["kind"] = kind
    kwargs.setdefault("group", "absent" if kind == "absent" else "")
    kwargs["dest"] = str(entry.get("dest", "")).replace(
      "{prefix}", self.prefix)
    return Item(**kwargs)

  @property
  def all_items(self):
    """Components and must-not-be-present entries together."""
    return self.components + self.absent
def load_manifest(path=DEFAULT_MANIFEST, prefix=None):
  """Read and resolve a manifest file.

  Args:
    path: Path to manifest.yaml.
    prefix: Override for the install prefix.

  Returns:
    A Manifest.

  Raises:
    FileNotFoundError: If the manifest is not there. It is itself part
      of the deployable set, so its absence is a real answer.
  """
  with open(path, "r", encoding="utf-8") as handle:
    return Manifest(yaml.safe_load(handle), prefix=prefix)
def _under(root, dest):
  """Join an absolute manifest destination onto a root directory."""
  return Path(root) / Path(dest).relative_to("/")
def _host_provided(item):
  """True for items the host supplies rather than the package."""
  return item.kind in ("external", "mount")
def _check_path(path, kind):
  """Classify one destination path.

  Args:
    path: The resolved path to look at.
    kind: The manifest kind, which decides what "present" means.

  Returns:
    A (State, detail) pair.
  """
  try:
    if kind == "mount":
      if not path.is_dir():
        return State.MISSING, "not a directory"
      if not os.path.ismount(path):
        return State.MISSING, "exists but is not a mount point"
      return State.PRESENT, ""
    if kind in ("tree", "dir"):
      if not path.exists():
        return State.MISSING, ""
      if not path.is_dir():
        return State.WRONG_KIND, "expected a directory"
      if kind == "tree" and not any(path.iterdir()):
        return State.EMPTY, "directory exists but is empty"
      return State.PRESENT, ""
    if not path.exists():
      return State.MISSING, ""
    if path.is_dir():
      return State.WRONG_KIND, "expected a file, found a directory"
    return State.PRESENT, ""
  except PermissionError as exc:
    return State.UNREADABLE, str(exc)
  except OSError as exc:
    return State.UNREADABLE, str(exc)
def unresolved_libraries(path, run=subprocess.run):
  """Shared objects this binary needs and this box cannot supply.

  `ldd` is the only thing that answers the question an operator
  actually has, which is not "is the file there" but "will it run".
  A binary linked against a library that lived in somebody's build
  tree is installed, executable, the right size, and dies at exec.

  Returns:
    A (names, checked) pair. `checked` is False when ldd could not be
    run or could not read the file, so "no missing libraries" is never
    confused with "nobody looked".
  """
  try:
    proc = run(["ldd", str(path)], capture_output=True, text=True)
  except OSError:
    return [], False
  # ldd exits non-zero for a static binary ("not a dynamic
  # executable"), which is the best possible answer here.
  text = (proc.stdout or "") + (proc.stderr or "")
  if "not a dynamic executable" in text:
    return [], True
  if proc.returncode != 0 and not proc.stdout:
    return [], False
  missing = []
  for line in proc.stdout.splitlines():
    if "not found" not in line:
      continue
    missing.append(line.strip().split()[0])
  return missing, True
def verify(manifest, root="/", run=subprocess.run):
  """Check a root against the manifest.

  Args:
    manifest: A Manifest.
    root: "/" for a live box, or a staged directory.
    run: subprocess.run, injectable for tests.

  Returns:
    A Report.
  """
  scope = Scope.TARGET if str(root) == "/" else Scope.STAGED
  findings = []
  for item in manifest.components:
    if scope is Scope.STAGED and _host_provided(item):
      findings.append(Finding(
        item, State.NOT_CHECKED,
        "host-provided; only a live box can answer this"))
      continue
    state, detail = _check_path(_under(root, item.dest), item.kind)
    # A binary that is present and cannot load is not present in any
    # sense the operator cares about. Only on the target: ldd on a
    # staged root would answer for the build host, and for a cross
    # build it would answer for the wrong architecture entirely.
    if (state is State.PRESENT and item.kind == "binary"
        and scope is Scope.TARGET):
      unresolved, checked = unresolved_libraries(
        _under(root, item.dest), run)
      if unresolved:
        state = State.UNUSABLE
        detail = ("will not start: no " + ", ".join(unresolved) +
                  " on this box")
      elif not checked:
        state = State.NOT_CHECKED
        detail = "ldd could not say whether its libraries resolve"
    if state is State.PRESENT and item.verify_command:
      if scope is Scope.TARGET:
        state, detail = _run_verify(item, run)
      else:
        # The file is staged, but whether it actually imports is a
        # question about a Python installation, and a staged root has
        # none. Saying "present" here would let a root that cannot
        # compile a policy pass as a complete appliance.
        state = State.NOT_CHECKED
        detail = (f"staged; `{' '.join(item.verify_command)}` can "
                  f"only be answered on the box")
    findings.append(Finding(item, state, detail))
  for item in manifest.absent:
    path = _under(root, item.dest)
    try:
      present = path.exists() or path.is_symlink()
    except PermissionError as exc:
      findings.append(Finding(item, State.UNREADABLE, str(exc)))
      continue
    findings.append(Finding(
      item, State.CONFLICT if present else State.PRESENT,
      "must not be present" if present else ""))
  return Report(scope=scope, root=str(root), findings=findings)
def _run_verify(item, run):
  """Run an item's verify_command and classify the result."""
  try:
    proc = run(item.verify_command, capture_output=True, text=True)
  except OSError as exc:
    return State.UNREADABLE, f"{item.verify_command[0]}: {exc}"
  if proc.returncode == 0:
    return State.PRESENT, ""
  detail = (proc.stderr or proc.stdout or "").strip().splitlines()
  return State.MISSING, (
    f"{' '.join(item.verify_command)} failed: "
    f"{detail[-1] if detail else 'exit ' + str(proc.returncode)}")
def source_path(item, build_dir, repo_root):
  """Where an item's content comes from on the build host."""
  if not item.source:
    return None
  base = Path(build_dir) if item.kind == "binary" else Path(repo_root)
  return (base / item.source).resolve()
def preflight(manifest, build_dir, repo_root):
  """Find every item whose source is not where it should be.

  Returns:
    A (missing_required, missing_optional) pair of Item lists. The
    caller writes nothing when the first is non-empty: a box that is
    missing a binary should be a build that failed loudly, not an
    install that half-happened.
  """
  required, optional = [], []
  for item in manifest.components:
    src = source_path(item, build_dir, repo_root)
    if src is None or src.exists():
      continue
    (required if item.required else optional).append(item)
  return required, optional
@dataclasses.dataclass
class Action:
  """One thing `stage` did or refused to do."""
  item: Item
  done: bool
  detail: str = ""
def stage(manifest, build_dir, repo_root, root, run=subprocess.run,
          remove_stale=False, with_pip=True):
  """Put the deployable set into a root.

  Args:
    manifest: A Manifest.
    build_dir: The CMake build directory holding the binaries.
    repo_root: The f repository root.
    root: Where to write. "/" installs onto the running box.
    run: subprocess.run, injectable for tests.
    remove_stale: Delete the `absent` entries instead of reporting
      them. firstboot passes this; a hand install is told about them
      and decides.
    with_pip: Install the Python compiler package. Off in tests, and
      off when the caller has another way to get fwl onto the box.

  Returns:
    A list of Actions, in manifest order.

  Raises:
    FileNotFoundError: When a required source is missing. The message
      names all of them.
  """
  missing_req, missing_opt = preflight(manifest, build_dir, repo_root)
  if missing_req:
    names = "\n".join(
      f"  {i.id:20} expected at "
      f"{source_path(i, build_dir, repo_root)}\n"
      f"  {'':20} {i.why.strip()}"
      for i in missing_req)
    raise FileNotFoundError(
      f"{len(missing_req)} required item(s) have no source; nothing "
      f"was installed:\n{names}")
  skip = {i.id for i in missing_opt}
  actions = []
  for item in manifest.components:
    if item.id in skip:
      actions.append(Action(
        item, False,
        f"optional, and no source at "
        f"{source_path(item, build_dir, repo_root)}"))
      continue
    try:
      actions.append(_stage_one(
        item, build_dir, repo_root, root, run, with_pip))
    except OSError as exc:
      # Report it and carry on. An installer that stops at the first
      # awkward file leaves a box in a state nothing describes, and
      # the operator finds out which half worked by running services
      # until one fails.
      actions.append(Action(item, False, f"{exc}"))
  for item in manifest.absent:
    path = _under(root, item.dest)
    if not (path.exists() or path.is_symlink()):
      actions.append(Action(item, True, "absent, as it must be"))
      continue
    if not remove_stale:
      actions.append(Action(
        item, False,
        f"present and must not be: {path} — pass --remove-stale"))
      continue
    if path.is_dir() and not path.is_symlink():
      shutil.rmtree(path)
    else:
      path.unlink()
    actions.append(Action(item, True, f"removed {path}"))
  return actions
def _stage_one(item, build_dir, repo_root, root, run, with_pip):
  """Install a single manifest item into a root."""
  dest = _under(root, item.dest)
  if item.kind in ("external", "mount"):
    return Action(item, True, "host-provided, nothing to install")
  if item.kind == "dir":
    dest.mkdir(parents=True, exist_ok=True)
    if item.mode:
      dest.chmod(int(item.mode, 8))
    return Action(item, True, f"directory {dest}")
  if item.kind == "python-package":
    if not with_pip:
      return Action(item, False, "skipped: pip install not requested")
    return _pip_install(item, repo_root, root, run)
  src = source_path(item, build_dir, repo_root)
  dest.parent.mkdir(parents=True, exist_ok=True)
  if item.kind == "tree":
    shutil.copytree(src, dest, dirs_exist_ok=True)
    return Action(item, True, f"{src} -> {dest}")
  _replace_file(src, dest, item.mode)
  return Action(item, True, f"{src} -> {dest}")


def _replace_file(src, dest, mode=""):
  """Put `src` at `dest` by replacing the name, not the file.

  Writing through a destination that is a running binary fails with
  ETXTBSY, and an upgrade that hits it stops in the middle with some
  of the new binaries in place and some not. Renaming a fresh inode
  over the name works while the old one is still executing — the
  running process keeps the file it opened and the next start gets
  the new one. It is also the reason a power cut during an install
  cannot leave a half-written binary behind.
  """
  tmp = dest.with_name(f".{dest.name}.new")
  try:
    shutil.copy2(src, tmp)
    if mode:
      tmp.chmod(int(mode, 8))
    os.replace(tmp, dest)
  finally:
    if tmp.exists():
      tmp.unlink()
def _pip_install(item, repo_root, root, run):
  """Install the FWL compiler package into a root."""
  src = str(Path(repo_root) / item.source)
  argv = [sys.executable, "-m", "pip", "install", "--no-input", src]
  if str(root) == "/":
    argv.insert(4, "--break-system-packages")
  else:
    argv[4:4] = ["--prefix", str(Path(root) / "usr/local"),
                 "--no-warn-script-location"]
  try:
    proc = run(argv, capture_output=True, text=True)
  except OSError as exc:
    return Action(item, False, f"pip: {exc}")
  if proc.returncode != 0:
    tail = (proc.stderr or proc.stdout or "").strip().splitlines()
    return Action(item, False,
                  f"pip failed: {tail[-1] if tail else 'no output'}")
  return Action(item, True, f"pip installed {src}")
_STATE_LABEL = {
  State.PRESENT: "ok",
  State.MISSING: "MISSING",
  State.UNUSABLE: "WILL NOT RUN",
  State.WRONG_KIND: "WRONG KIND",
  State.EMPTY: "EMPTY",
  State.UNREADABLE: "UNREADABLE",
  State.CONFLICT: "MUST NOT BE HERE",
  State.NOT_CHECKED: "not checked",
}
def _wrapped(text, indent, out):
  """Print prose under a fixed indent, wrapped to a terminal width."""
  pad = " " * indent
  for line in textwrap.wrap(" ".join(text.split()), width=78,
                            initial_indent=pad, subsequent_indent=pad):
    print(line, file=out)
def render_report(report, out=None, verbose=False):
  """Print a verification report for a human.

  Every item that is not fine is printed with the unit it breaks and
  the sentence from the manifest saying what that costs. An operator
  should never have to look a name up.
  """
  out = out or sys.stdout
  where = ("this box" if report.scope is Scope.TARGET
           else f"staged root {report.root}")
  print(f"f install — {where}\n", file=out)
  groups = {}
  for finding in report.findings:
    groups.setdefault(finding.item.group or "other", []).append(finding)
  for group, findings in groups.items():
    interesting = [f for f in findings
                   if verbose or f.state is not State.PRESENT]
    if not interesting:
      continue
    print(f"{group.upper()}", file=out)
    for finding in interesting:
      item = finding.item
      print(f"  {_STATE_LABEL[finding.state]:<18} {item.id:<22} "
            f"{item.dest}", file=out)
      if finding.state is State.PRESENT:
        continue
      if finding.detail:
        _wrapped(finding.detail, 21, out)
      if item.needed_by and item.needed_by != "none":
        _wrapped(f"needed by: {item.needed_by}", 21, out)
      if item.provided_by:
        _wrapped(f"install: {item.provided_by}", 21, out)
      if item.required_when:
        _wrapped(f"required when: {item.required_when}", 21, out)
      if item.why:
        _wrapped(item.why, 21, out)
    print("", file=out)
  # Never a bare verdict over an empty screen. "Everything is here"
  # and "I printed nothing" look identical otherwise, and only one of
  # them is reassuring.
  if all(f.state is State.PRESENT for f in report.findings):
    print(f"all {len(report.findings)} items present.", file=out)
  missing = report.missing_required
  if missing:
    print(f"{len(missing)} required item(s) missing: "
          f"{', '.join(f.item.id for f in missing)}", file=out)
  unchecked = report.not_checked
  if unchecked:
    print(f"{len(unchecked)} item(s) not checked "
          f"({'staged root' if report.scope is Scope.STAGED else 'see above'}"
          f"): {', '.join(f.item.id for f in unchecked)}", file=out)
  print(f"\nverdict: {report.verdict.value} "
        f"(scope: {report.scope.value})", file=out)
def report_to_json(report):
  """Serialise a report for `einheit-f show install` and for scripts."""
  return {
    "scope": report.scope.value,
    "root": report.root,
    "verdict": report.verdict.value,
    "items": [
      {
        "id": f.item.id,
        "group": f.item.group,
        "kind": f.item.kind,
        "dest": f.item.dest,
        "requirement": f.item.requirement,
        "state": f.state.value,
        "detail": f.detail,
        "needed_by": f.item.needed_by,
        "provided_by": f.item.provided_by,
        "required_when": f.item.required_when,
        "why": " ".join(f.item.why.split()),
      }
      for f in report.findings
    ],
  }
def render_list(manifest, out=None):
  """Print the deployable set itself, grouped, with reasons."""
  out = out or sys.stdout
  groups = {}
  for item in manifest.components:
    groups.setdefault(item.group or "other", []).append(item)
  print(f"The deployable set — manifest version {manifest.version}, "
        f"prefix {manifest.prefix}\n", file=out)
  for group, items in groups.items():
    print(group.upper(), file=out)
    for item in items:
      mark = "required" if item.required else "optional"
      print(f"  {item.id:<22} {mark:<9} {item.dest}", file=out)
      if item.why:
        _wrapped(item.why, 25, out)
    print("", file=out)
  if manifest.absent:
    print("MUST NOT BE PRESENT", file=out)
    for item in manifest.absent:
      print(f"  {item.id:<22} {'':<9} {item.dest}", file=out)
      _wrapped(item.why, 25, out)
    print("", file=out)
  total = len(manifest.components)
  req = sum(1 for i in manifest.components if i.required)
  print(f"{total} items, {req} of them required.", file=out)
def _default_repo_root():
  """The f repository this script was run out of, if any."""
  return Path(__file__).resolve().parent.parent
def build_parser():
  """Construct the argument parser."""
  parser = argparse.ArgumentParser(
    prog="f-install",
    description="Install an f appliance, and check that one is.")
  parser.add_argument("--manifest", default=None,
                      help="Path to manifest.yaml")
  parser.add_argument("--prefix", default=None,
                      help="Override the manifest's install prefix")
  sub = parser.add_subparsers(dest="command", required=True)

  sub.add_parser("list", help="Print the deployable set")

  ver = sub.add_parser("verify", help="Check a box against the set")
  ver.add_argument("--root", default="/",
                   help="Root to check; '/' means this box")
  ver.add_argument("--format", default="text",
                   choices=["text", "json"])
  ver.add_argument("-v", "--verbose", action="store_true",
                   help="List items that are present too")

  for name, help_text in (("stage", "Assemble the set into a root"),
                          ("install", "Put the set on this box")):
    cmd = sub.add_parser(name, help=help_text)
    cmd.add_argument("--build-dir", required=True,
                     help="CMake build directory holding the binaries")
    cmd.add_argument("--repo-root", default=str(_default_repo_root()),
                     help="The f repository root")
    cmd.add_argument("--remove-stale", action="store_true",
                     help="Delete files that must not be present")
    cmd.add_argument("--no-pip", action="store_true",
                     help="Do not pip-install the FWL compiler")
    if name == "stage":
      cmd.add_argument("--root", required=True,
                       help="Directory to assemble into")
  return parser
def main(argv=None):
  """Entry point. Returns a process exit code."""
  args = build_parser().parse_args(argv)
  args.manifest = args.manifest or default_manifest()
  try:
    manifest = load_manifest(args.manifest, prefix=args.prefix)
  except FileNotFoundError:
    print(f"f-install: no manifest at {args.manifest}. It is part of "
          f"the deployable set itself; a box without it cannot say "
          f"what it is missing.", file=sys.stderr)
    return 3

  if args.command == "list":
    render_list(manifest)
    return 0

  if args.command == "verify":
    report = verify(manifest, root=args.root)
    if args.format == "json":
      json.dump(report_to_json(report), sys.stdout, indent=2)
      print("")
    else:
      render_report(report, verbose=args.verbose)
    return EXIT_CODES[report.verdict]

  root = args.root if args.command == "stage" else "/"
  try:
    actions = stage(manifest, args.build_dir, args.repo_root, root,
                    remove_stale=args.remove_stale,
                    with_pip=not args.no_pip)
  except FileNotFoundError as exc:
    print(f"f-install: {exc}", file=sys.stderr)
    return 1
  failed = [a for a in actions if not a.done]
  for action in actions:
    mark = "ok  " if action.done else "SKIP"
    print(f"{mark} {action.item.id:<22} {action.detail}")
  if failed:
    print(f"\n{len(failed)} item(s) were not installed: "
          f"{', '.join(a.item.id for a in failed)}", file=sys.stderr)
  report = verify(manifest, root=root)
  print("")
  render_report(report)
  return EXIT_CODES[report.verdict]
if __name__ == "__main__":
  sys.exit(main())
