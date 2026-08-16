"""Make the deploy tooling importable from its own test directory."""

import sys
from pathlib import Path

DEPLOY = Path(__file__).resolve().parent.parent
if str(DEPLOY) not in sys.path:
  sys.path.insert(0, str(DEPLOY))

def wanted_service_units(model):
  """What `f-sysconf render units` prints for `model`, in Python.

  Only a stand-in for the C++ derivation, used by the firstboot tests
  so they can run without a build tree. It is not a second source of
  truth: `test_service_unit_derivation.py` runs the real binary and
  fails if this disagrees with it, which is the only thing that makes
  a copy of a table safe to keep.

  Args:
    model: The parsed `system.yaml` as a dict.

  Returns:
    The unit names the model binds, in f-sysconf's order.
  """
  services = (model or {}).get("services") or {}
  units = []
  # dnsmasq wants a zone it can answer ON, not merely a binding: a
  # server bound to a zone with no port in it would bind loopback and
  # serve nobody, which `PlanDnsmasq` refuses to call `needed`.
  placed = set()
  for iface in ((model or {}).get("interfaces") or {}).values():
    zone = (iface or {}).get("zone")
    if zone:
      placed.add(zone)
  bound = (list(services.get("dhcp") or []) +
           list(services.get("dns") or []))
  if any((b or {}).get("zone") in placed for b in bound):
    units.append("f-dnsmasq.service")
  # chrony has a client half with no placement, so a binding is
  # enough.
  if services.get("ntp"):
    units.append("f-chrony.service")
  return units

def render_units_stdout(model):
  """The exact bytes `f-sysconf render units` writes for `model`."""
  wanted = wanted_service_units(model)
  lines = []
  for unit in ("f-dnsmasq.service", "f-chrony.service"):
    state = "wanted" if unit in wanted else "unwanted"
    lines.append(f"{state} {unit}")
  return "\n".join(lines) + "\n"
