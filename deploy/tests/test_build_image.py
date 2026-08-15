"""Tests for the gate that stands between a rootfs and an archive.

`build_image.py` used to seal an image as soon as every file the
manifest names was in place. That is a weaker claim than it reads as:
the first image ever built passed it with six binaries that could not
exec, because `libzmq5` and `libyaml-cpp0.8` were not in the package
list and nothing had asked the rootfs whether its own binaries load.

The check has to run inside the chroot. On the build host `ldd`
answers for the build host, and against a cross-built binary it
answers for the wrong architecture entirely — which is why
`f_install.verify` deliberately skips it on a staged root, and why
this is a separate question asked a different way.
"""

import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent
                       / "image"))
import build_image  # noqa: E402
import f_install  # noqa: E402
MANIFEST = Path(__file__).resolve().parent.parent / "manifest.yaml"
class FakeChroot:
  """Answers `ldd` for a scripted set of unresolved libraries."""

  def __init__(self, unresolved=None):
    """Build a runner.

    Args:
      unresolved: {destination path: [soname, ...]}.
    """
    self.unresolved = unresolved or {}
    self.calls = []

  def __call__(self, argv, **kwargs):
    """Stand in for subprocess.run."""
    self.calls.append(argv)
    dest = argv[-1]
    missing = self.unresolved.get(dest, [])
    lines = [f"\t{lib} => not found" for lib in missing]
    lines.append("\tlibc.so.6 => /lib/libc.so.6 (0x0000)")
    return subprocess.CompletedProcess(
      argv, 0, stdout="\n".join(lines) + "\n", stderr="")
def test_a_rootfs_whose_binaries_load_passes(monkeypatch):
  """The healthy case, so the gate is not merely always red."""
  monkeypatch.setattr(build_image.subprocess, "run", FakeChroot())
  manifest = f_install.load_manifest(MANIFEST)
  assert build_image.check_binaries_load("/rootfs", manifest) == {}
def test_an_unloadable_binary_is_named_with_its_library(monkeypatch):
  """The answer has to say which binary and which library."""
  fake = FakeChroot({"/usr/local/bin/fd": ["libzmq.so.5",
                                           "libyaml-cpp.so.0.8"]})
  monkeypatch.setattr(build_image.subprocess, "run", fake)
  manifest = f_install.load_manifest(MANIFEST)
  found = build_image.check_binaries_load("/rootfs", manifest)
  assert found == {"/usr/local/bin/fd": ["libzmq.so.5",
                                         "libyaml-cpp.so.0.8"]}
def test_every_binary_in_the_manifest_is_asked(monkeypatch):
  """A gate that skipped one binary would have missed this defect.

  All six were unloadable in the image that motivated the check, and a
  loop that stopped at the first answer would still have reported one.
  """
  fake = FakeChroot()
  monkeypatch.setattr(build_image.subprocess, "run", fake)
  manifest = f_install.load_manifest(MANIFEST)
  build_image.check_binaries_load("/rootfs", manifest)
  asked = {call[-1] for call in fake.calls}
  expected = {i.dest for i in manifest.components
              if i.kind == "binary"}
  assert asked == expected
  assert all(call[:3] == ["sudo", "chroot", "/rootfs"]
             for call in fake.calls)
def test_the_libraries_the_binaries_need_are_in_the_package_list():
  """The list that puts the libraries there, checked against a build.

  Skipped when there is no cross build to read, because the question
  is about the binaries this repo produces and nothing else can answer
  it. When there is one, every soname it needs must be traceable to a
  package in PACKAGES or to the base system — this is the list that
  was wrong, and the only reason it was noticed is that a box refused
  to run.
  """
  import pytest
  build = Path(__file__).resolve().parent.parent.parent / "build-aarch64"
  if not (build / "fd").exists():
    pytest.skip("no aarch64 cross build here to inspect")
  # Sonames the base system always provides; everything else has to be
  # named in PACKAGES by the package that ships it.
  base = {"libc.so.6", "libm.so.6", "libgcc_s.so.1",
          "libstdc++.so.6", "ld-linux-aarch64.so.1"}
  provides = {
    "libbpf.so.1": "libbpf1",
    "libzmq.so.5": "libzmq5",
    "libyaml-cpp.so.0.8": "libyaml-cpp0.8",
  }
  manifest = f_install.load_manifest(MANIFEST)
  unaccounted = {}
  for item in manifest.components:
    if item.kind != "binary" or not (build / item.source).exists():
      continue
    proc = subprocess.run(
      ["aarch64-linux-gnu-objdump", "-p", str(build / item.source)],
      capture_output=True, text=True, check=False)
    if proc.returncode != 0:
      pytest.skip("no aarch64 objdump on this host")
    for line in proc.stdout.splitlines():
      parts = line.split()
      if len(parts) != 2 or parts[0] != "NEEDED":
        continue
      soname = parts[1]
      if soname in base:
        continue
      package = provides.get(soname)
      if package is None or package not in build_image.PACKAGES:
        unaccounted.setdefault(item.id, []).append(soname)
  assert not unaccounted, (
    "these binaries need libraries no package in PACKAGES provides, "
    f"so the image will not run them: {unaccounted}")
class FakeWget:
  """Stand in for `wget`, answering per invocation.

  The preflight's whole job is to tell three situations apart, and
  they differ only in which invocation of one command succeeds.
  """
  def __init__(self, plain_ok, inet4_ok):
    # `plain_ok` is the IPv6 answer: the preflight asks about IPv6
    # explicitly rather than about whatever wget picks by default.
    self.inet6_ok = plain_ok
    self.inet4_ok = inet4_ok
    self.calls = []
  def __call__(self, argv, check=False, **kwargs):
    self.calls.append(list(argv))
    ok = self.inet4_ok if "-4" in argv else self.inet6_ok
    return subprocess.CompletedProcess(argv, 0 if ok else 4)
def test_a_mirror_reachable_over_ipv6_needs_no_help(
    monkeypatch, tmp_path):
  fake = FakeWget(plain_ok=True, inet4_ok=True)
  monkeypatch.setattr(build_image.subprocess, "run", fake)
  env = build_image.mirror_preflight("http://example/debian", "trixie",
                                     tmp_path)
  assert env == {}
  # One probe, and no wgetrc left behind on a machine that did not
  # need one.
  assert len(fake.calls) == 1
  assert "-6" in fake.calls[0]
  assert not (tmp_path / "wgetrc-inet4").exists()
def test_an_ipv6_only_hang_is_turned_into_ipv4(monkeypatch, tmp_path):
  # The measured case: wget over IPv6 never returns, `wget -4`
  # returns in 0.3 s, and debootstrap would have hung for as long as
  # you were willing to let it.
  fake = FakeWget(plain_ok=False, inet4_ok=True)
  monkeypatch.setattr(build_image.subprocess, "run", fake)
  env = build_image.mirror_preflight("http://example/debian", "trixie",
                                     tmp_path)
  wgetrc = tmp_path / "wgetrc-inet4"
  assert env == {"WGETRC": str(wgetrc)}
  assert "inet4_only = on" in wgetrc.read_text()
def test_an_unreachable_mirror_stops_the_build_rather_than_hanging(
    monkeypatch, tmp_path):
  # The point of the whole function. A build that cannot fetch its
  # mirror must say so in seconds, naming the mirror and the flag that
  # changes it — not print `I: Retrieving InRelease` and go quiet.
  fake = FakeWget(plain_ok=False, inet4_ok=False)
  monkeypatch.setattr(build_image.subprocess, "run", fake)
  import pytest
  with pytest.raises(FileNotFoundError) as excinfo:
    build_image.mirror_preflight("http://example/debian", "trixie",
                                 tmp_path)
  message = str(excinfo.value)
  assert "http://example/debian" in message
  assert "--mirror" in message
  assert "hang" in message
