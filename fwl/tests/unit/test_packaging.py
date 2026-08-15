"""The compiler has to work after it is installed, not only in place.

`pip install -e` leaves the source tree where it is, so every
non-Python file the package reads at runtime keeps working whether or
not the wheel would have contained it. The first machine that finds
out otherwise is an appliance, and there it means `fwl` raises
FileNotFoundError before it can print a usage message — so the box runs
the policy it booted with and can never be given another.

That is what happened to `grammar.lark`: `parser.py` reads it at import
time with `importlib.resources`, `pyproject.toml` declared no
package-data, and a real install produced an `fwl` on PATH that could
not parse anything.
"""
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

FWL_ROOT = Path(__file__).resolve().parents[2]
PACKAGE = FWL_ROOT / "fwl"


def _package_data_globs():
  """The globs pyproject.toml says belong in the wheel."""
  with open(FWL_ROOT / "pyproject.toml", "rb") as handle:
    doc = tomllib.load(handle)
  data = doc.get("tool", {}).get("setuptools", {}).get(
    "package-data", {})
  return data.get("fwl", [])


def _runtime_data_files():
  """Every non-Python file that ships inside the package directory."""
  out = []
  for path in sorted(PACKAGE.iterdir()):
    if not path.is_file():
      continue
    if path.suffix in (".py", ".pyc"):
      continue
    out.append(path.name)
  return out


def test_every_data_file_in_the_package_is_declared():
  """A data file nobody declared is a file the wheel will not have."""
  globs = _package_data_globs()
  for name in _runtime_data_files():
    assert any(Path(name).match(pattern) for pattern in globs), (
      f"fwl/{name} is read from the installed package and no "
      f"`[tool.setuptools.package-data]` glob in pyproject.toml "
      f"matches it; a wheel built today would not contain it")


def test_the_grammar_is_one_of_them():
  """Named explicitly, because it is the one that already bit us."""
  assert "grammar.lark" in _runtime_data_files()


@pytest.mark.skipif(shutil.which("pip") is None,
                    reason="no pip to build an installation with")
def test_an_installed_copy_can_parse(tmp_path):
  """Install the package somewhere else and use it from there.

  This is the check that a declaration test cannot make: it proves the
  packaging machinery actually put the grammar in, by importing the
  parser out of an installed tree with the source directory nowhere on
  the path.

  It builds from a copy outside the repository on purpose. With
  setuptools-scm in the build requirements, a build run inside a git
  checkout gets its file list from git and picks up `grammar.lark`
  whether or not anything declared it — so building here would have
  passed on the day a real appliance got a compiler that could not
  parse. What reaches a box is a copy: an rsync'd staging directory, an
  unpacked sdist, a chroot. That is what this builds.
  """
  source = tmp_path / "src"
  shutil.copytree(FWL_ROOT, source,
                  ignore=shutil.ignore_patterns(
                    "__pycache__", "*.egg-info", ".git", "build",
                    "dist"))
  target = tmp_path / "site"
  install = subprocess.run(
    [sys.executable, "-m", "pip", "install", "--no-deps", "--no-input",
     "--target", str(target), str(source)],
    capture_output=True, text=True)
  if install.returncode != 0:
    pytest.skip(f"pip could not build the package here: "
                f"{install.stderr.strip().splitlines()[-1:]}")

  assert (target / "fwl" / "grammar.lark").exists(), (
    "the installed package has no grammar.lark; `fwl` on a box built "
    "from this would raise FileNotFoundError on every subcommand")

  # Import it from the installed copy with the repository nowhere in
  # sys.path, which is the situation on an appliance.
  proof = subprocess.run(
    [sys.executable, "-c",
     "import sys; sys.path.insert(0, sys.argv[1]);"
     "import fwl.parser;"
     "p = fwl.parser.parse('@xdp(eth0)\\ndefault drop\\n');"
     "print(len(p.programs))",
     str(target)],
    capture_output=True, text=True, cwd=str(tmp_path))
  assert proof.returncode == 0, proof.stderr
  assert proof.stdout.strip() == "1", proof.stdout
