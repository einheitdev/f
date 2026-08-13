"""Which pinned maps may outlive the compilation that made them.

`MapScope` answers whether two zones of one bundle may land on one
kernel map. `MapLifetime` answers a different question that the same
registry is the right place for: may the CONTENTS of a map, left pinned
in bpffs by a previous compilation, be carried into the next one?

A pin outlives its process — bpffs holds a reference — so on a cold boot
`fd` finds the previous incarnation's maps still there. Adopting the
wrong one reports a dead policy's numbers against live rules, or fails
the load outright with libbpf's -EINVAL. Discarding the wrong one drops
every established connection. So each map has to say which it is, and
these tests hold the answer and its route to the daemon down.
"""
import json
import pathlib
import re

import pytest

from fwl import emitter
from fwl.errors import FwlException

_TWO_ZONES = (
  "zone a = [e0]\n"
  "zone b = [e1]\n"
  "@xdp(a)\n"
  "count a_one\n"
  "allow if conntrack(pkt).state == established\n"
  "allow\n"
  "@xdp(b)\n"
  "count b_one\n"
  "allow if conntrack(pkt).state == established\n"
  "allow\n"
)


def test_every_registry_row_declares_a_lifetime():
  """No default, for the same reason MapScope has none.

  The daemon discards every pin it is not told to keep, so a row that
  skipped the question would have its map silently dropped — and under
  the prefix-blocklist this replaced, silently adopted. Requiring the
  field is what makes the decision unskippable.
  """
  for kind in emitter._MAP_KINDS:
    assert isinstance(kind.lifetime, emitter.MapLifetime), kind.base
    assert kind.lifetime_why.strip(), kind.base


def test_only_flow_keyed_state_persists():
  """Exactly conntrack and fwl_nat, and the reasoning is per map.

  Both are keyed by the flow 5-tuple, which means the same thing under
  any policy. Everything else is numbered, sized or populated by one
  compilation — including two maps that are SHARED and still cannot
  persist, which is why this is a second axis and not a synonym for
  scope.
  """
  assert emitter.persistent_map_names() == ("conntrack", "fwl_nat")


def test_a_shared_map_can_still_be_policy_scoped():
  """The case where the two axes visibly disagree.

  `fwl_rl_g<slot>` is bundle-wide BY DECLARATION (v0.4 § 6.7), so it is
  correctly SHARED — and slot g0 of the next policy is a different rule
  with a different budget, so its accumulated tokens must not be
  inherited. A sweep driven by MapScope alone would have kept it.
  """
  glob = emitter._map_kind("fwl_rl_g0")
  assert glob.scope is emitter.MapScope.SHARED
  assert glob.lifetime is emitter.MapLifetime.POLICY
  assert "fwl_rl_g0" not in emitter.persistent_map_names()


def test_daemon_derived_maps_are_not_inherited():
  """fwl_nat_cfg and the devmaps are rewritten at every load.

  Nothing is lost by dropping them, and keeping them is a hazard: the
  daemon skips a zone interface that is not up yet rather than writing
  it, so an adopted devmap entry survives un-overwritten and redirects
  packets out of an interface the new policy never named.
  """
  for name in ("fwl_nat_cfg", "fwl_devmap_wan"):
    assert emitter._map_kind(name).lifetime is emitter.MapLifetime.POLICY
    assert name not in emitter.persistent_map_names()


def test_log_ring_is_not_inherited():
  """An unconsumed event carries the previous compilation's rule_index.

  Read back against the next policy it names the wrong rule, which is
  the same numbering fault as a stale counter map — only in a ring
  buffer, where it looks like a live log line.
  """
  kind = emitter._map_kind("fwl_log_events")
  assert kind.scope is emitter.MapScope.SHARED
  assert kind.lifetime is emitter.MapLifetime.POLICY


def test_a_private_map_cannot_claim_to_persist(monkeypatch):
  """FLOW and PRIVATE is a contradiction, and it raises.

  A map that survives a policy change is keyed by something the policy
  does not define — which is exactly what makes it safe to share across
  zones. A per-zone map cannot qualify, and letting one through would
  put a zone-qualified name into the manifest for fd to preserve.
  """
  bad = emitter._MapKind(
    r"fwl_counters", emitter.MapScope.PRIVATE, "per zone",
    lifetime=emitter.MapLifetime.FLOW, lifetime_why="wishful",
    private_name=r"fwl_counters_{zone}",
  )
  monkeypatch.setattr(emitter, "_MAP_KINDS", (bad,))
  with pytest.raises(FwlException) as excinfo:
    emitter.persistent_map_names()
  assert "PRIVATE" in str(excinfo.value)


def test_a_persistent_name_may_not_be_a_pattern(monkeypatch):
  """The manifest carries names, not regexes.

  fd compares them against what is actually pinned in bpffs, so a row
  whose `base` is a pattern would arrive at the daemon as a literal
  that matches nothing and its map would be swept.
  """
  bad = emitter._MapKind(
    r"fwl_devmap_\w+", emitter.MapScope.SHARED, "per destination zone",
    lifetime=emitter.MapLifetime.FLOW, lifetime_why="wishful",
  )
  monkeypatch.setattr(emitter, "_MAP_KINDS", (bad,))
  with pytest.raises(FwlException) as excinfo:
    emitter.persistent_map_names()
  assert "pattern" in str(excinfo.value)


def test_bundle_manifest_carries_the_persistent_names(tmp_path, monkeypatch):
  """The route from the registry to the daemon.

  fd reads `persistent_maps` out of the bundle it is about to load
  rather than re-deriving the rule from name prefixes. That second copy
  of the decision, in another language, is how the same defect got in
  three times before `_MAP_KINDS` existed.
  """
  from fwl import analyzer, cli, parser
  program = analyzer.analyze(parser.parse(_TWO_ZONES))
  bundle = tmp_path / "bundle"
  cli._emit_bundle_dir(program, bundle)
  manifest = json.loads((bundle / "manifest.json").read_text())
  assert manifest["persistent_maps"] == ["conntrack", "fwl_nat"]


def test_shared_pinned_maps_is_read_off_the_bundle(tmp_path):
  """And the neighbouring field states what the bundle really pins.

  `shared_pinned_maps` used to be the literal `["conntrack"]` for every
  bundle: wrong for one that pins fwl_nat or a devmap as well, and
  wrong for one whose policy never reads conntrack at all. Next to a
  correct `persistent_maps` an incorrect neighbour is worse than none.
  """
  from fwl import analyzer, cli, parser
  # Two zones, one redirecting into the other: pins conntrack (both
  # read it) and fwl_devmap_b, and pins no NAT map.
  source = (
    "zone a = [e0]\n"
    "zone b = [e1]\n"
    "@xdp(a)\n"
    "allow if conntrack(pkt).state == established\n"
    "redirect to b\n"
    "@xdp(b)\n"
    "allow if conntrack(pkt).state == established\n"
    "allow\n"
  )
  program = analyzer.analyze(parser.parse(source))
  bundle = tmp_path / "bundle"
  cli._emit_bundle_dir(program, bundle)
  manifest = json.loads((bundle / "manifest.json").read_text())
  assert manifest["shared_pinned_maps"] == ["conntrack", "fwl_devmap_b"]


def test_the_daemon_fallback_list_has_not_drifted():
  """fd's compiled-in fallback must equal the registry's answer.

  It is used only for bundles compiled before manifests carried
  `persistent_maps`, but a fallback that disagrees with the registry is
  a second opinion about which state survives — so read the daemon's
  source and hold the two together. Editing _MAP_KINDS' lifetimes fails
  here until src/bpf_loader.cc is updated to match.
  """
  src = (
    pathlib.Path(__file__).parents[3] / "src" / "bpf_loader.cc"
  ).read_text(encoding="utf-8")
  body = re.search(
    r"auto DefaultPersistentMapNames\(\)[^{]*\{(.*?)\n\}",
    src, re.DOTALL,
  )
  assert body is not None, "DefaultPersistentMapNames not found in fd"
  names = tuple(re.findall(r'"(\w+)"', body.group(1)))
  assert names == emitter.persistent_map_names()
