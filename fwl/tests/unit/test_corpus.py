"""Pytest wrapper for the .pkt corpus.

Each `.pkt` file under tests/corpus/ and tests/generated/ becomes one
parametrized pytest case. Running `pytest tests/unit/` exercises
the full corpus through all three oracles alongside the module-level
unit tests, so a single command covers both pyramid layers.

The runner already does this work; this file just exposes it to
pytest so per-case results show up in pytest's output and CI tooling
that expects pytest-style reporting.
"""
from __future__ import annotations
from pathlib import Path

import pytest

from fwl import pkt, runner


_TESTS_ROOT = Path(__file__).resolve().parent.parent
_CORPUS_DIRS = (_TESTS_ROOT / "corpus", _TESTS_ROOT / "generated")


def _all_pkt_files() -> list[Path]:
  """Walk both corpus directories, return every .pkt sorted."""
  paths: list[Path] = []
  for d in _CORPUS_DIRS:
    if d.exists():
      paths.extend(sorted(d.rglob("*.pkt")))
  return paths


def _case_id(path: Path) -> str:
  """Pretty pytest id: relpath from tests/, stripped of .pkt suffix."""
  return path.relative_to(_TESTS_ROOT).with_suffix("").as_posix()


_PKT_FILES = _all_pkt_files()


@pytest.mark.parametrize(
  "pkt_path", _PKT_FILES, ids=[_case_id(p) for p in _PKT_FILES]
)
def test_pkt_case(pkt_path: Path) -> None:
  """Run one .pkt case through all reachable oracles and assert agreement.

  Skips count toward pass — the BPF oracle in particular skips when
  CAP_BPF is unavailable. Real oracle disagreements (status `fail`
  or `error`) fail the test with the per-oracle diagnostic detail.
  """
  case = pkt.load(pkt_path)
  result = runner.run_case(case)
  failures = [
    o for o in result.oracles if o.status not in ("pass", "skip")
  ]
  if failures:
    detail = "\n".join(
      f"  {o.name}: {o.status} -- {o.detail}" for o in failures
    )
    pytest.fail(f"\n{detail}")
