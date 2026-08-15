"""Make the deploy tooling importable from its own test directory."""

import sys
from pathlib import Path

DEPLOY = Path(__file__).resolve().parent.parent
if str(DEPLOY) not in sys.path:
  sys.path.insert(0, str(DEPLOY))
