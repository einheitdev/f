"""Every FWL policy in the documentation compiles.

The docs are a test of the language, and this is what makes that
literal. Writing the guide found three places where a page described
behaviour the compiler does not have — a port comparison without its
protocol guard, `pkt.zone` inside a shared helper, and `chain` without
its stage name — each of which would have been a reader pasting a
policy the box refuses.

Only ```fwl fences are compiled. Fragments that are deliberately not
whole programs go in a plain fence, so a block being checked is a
decision the page makes rather than an accident of formatting.
"""
import pathlib
import re

import pytest

from fwl import analyzer, parser

DOCS = pathlib.Path(__file__).resolve().parents[3] / "docs"


def _blocks():
  out = []
  for md in sorted(DOCS.rglob("*.md")):
    text = md.read_text()
    for i, block in enumerate(
        re.findall(r"```fwl\n(.*?)```", text, re.S)):
      out.append((md.relative_to(DOCS).as_posix(), i + 1, block))
  return out


BLOCKS = _blocks()


def test_the_docs_contain_policies_at_all():
  """A checker that silently found nothing would pass forever."""
  assert len(BLOCKS) >= 20, (
    "the FWL guide should carry runnable policies; found %d"
    % len(BLOCKS)
  )


@pytest.mark.parametrize(
  "path,index,source", BLOCKS,
  ids=["%s#%d" % (p, i) for p, i, _ in BLOCKS],
)
def test_documented_policy_compiles(path, index, source):
  analyzer.analyze(parser.parse(source))
