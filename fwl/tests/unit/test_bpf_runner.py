"""The clang/BPF harness's handling of its own temporary files.

`compile_c` writes a source and an object into a temporary directory.
Leaving those behind is not untidiness: one directory per compile, at
the rate a soak run compiles, filled a 2 GiB tmpfs with 84,000 of them
and ended the run with ENOSPC. The compiler harness must not be able
to fill the disk of the machine measuring it.
"""
import subprocess
import tempfile
from pathlib import Path

import pytest

from fwl import analyzer, bpf_runner, emitter, parser

_SRC = "@xdp(e0)\ndrop if pkt.proto == icmp\ndefault allow\n"


def _emit() -> str:
  return emitter.emit(analyzer.analyze(parser.parse(_SRC)))


def _temp_dirs() -> set[Path]:
  return set(Path(tempfile.gettempdir()).glob("fwl-bpf-*"))


def _leaked(before: set[Path]) -> set[Path]:
  """Scratch directories that appeared and were not cleaned up.

  Only NEW directories, which is what "leaves nothing behind" means.
  Comparing the two snapshots for equality also asserted that nothing
  ELSE in /tmp changed, and that is not this test's business: a stale
  fwl-bpf-* directory from an old run, swept by whatever tidies /tmp
  while the suite happens to be running, made these tests fail
  intermittently with nothing wrong in the code they cover.
  """
  return _temp_dirs() - before


def _requires_clang() -> None:
  try:
    bpf_runner.check_compiles(_emit())
  except bpf_runner.BpfUnavailable as exc:
    pytest.skip(str(exc))


def test_check_compiles_leaves_nothing_behind():
  _requires_clang()
  before = _temp_dirs()
  for _ in range(5):
    bpf_runner.check_compiles(_emit())
  assert not _leaked(before)


def test_compile_c_cleans_up_on_context_exit():
  _requires_clang()
  before = _temp_dirs()
  with bpf_runner.compile_c(_emit()) as result:
    # The object really is there while the caller is using it.
    assert result.obj_path.exists()
    assert _leaked(before)
  assert not result.obj_path.exists()
  assert not _leaked(before)


def test_failed_compile_leaves_nothing_behind():
  # A compile that fails raises instead of returning a result, so the
  # caller has nothing to clean up and the harness must do it itself.
  _requires_clang()
  before = _temp_dirs()
  with pytest.raises(subprocess.CalledProcessError):
    bpf_runner.compile_c("this is not C\n")
  assert not _leaked(before)


def test_caller_supplied_work_dir_is_not_removed(tmp_path):
  # `fwl compile --bundle` compiles into the bundle directory and
  # keeps the objects. Cleanup must never touch a directory the caller
  # owns.
  _requires_clang()
  with bpf_runner.compile_c(_emit(), work_dir=tmp_path) as result:
    assert result.owned_dir is None
  assert result.obj_path.exists()
  assert tmp_path.exists()


def test_run_full_leaves_nothing_behind():
  before = _temp_dirs()
  try:
    bpf_runner.run_full(_emit(), b"\x00" * 64)
  except bpf_runner.BpfUnavailable as exc:
    pytest.skip(str(exc))
  assert not _leaked(before)
