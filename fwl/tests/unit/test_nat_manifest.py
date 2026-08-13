"""What a NAT bundle tells the daemon, and what it must carry to work.

Two facts the compiler is the only one who knows, and the daemon cannot
re-derive:

  - WHICH zone masquerades. Every zone object in a NAT bundle embeds
    `fwl_nat_cfg`, because the de-NAT pass on the return path needs it.
    So the map's presence says nothing, and the daemon seeding the
    address from presence alone seeds it from whichever object it read
    last — for a gateway, the LAN-side address on the WAN program. The
    per-program `masquerades` flag is what makes the choice, and a
    `masquerade` reached only through a helper (v0.4 § 6.5) counts.

  - That a source-NAT program needs `conntrack` even when its policy
    never mentions conntrack. `fwl_snat_egress` inserts the post-NAT
    5-tuple so the reply reads `established`; without the map declared
    the return path is not tracked and the gateway is one-way.

Both are silent when wrong: the program compiles, loads, attaches, and
translates nothing (or translates to the wrong address).
"""
import json

import pytest

from fwl import analyzer, cli, emitter, parser

# A gateway: lan masquerades and redirects out; wan redirects back. Both
# objects carry the NAT machinery; only lan is a masquerade source.
_GATEWAY = (
  "zone lan = [veth0]\n"
  "zone wan = [veth1]\n"
  "@xdp(lan)\n"
  "masquerade\n"
  "redirect to wan\n"
  "@xdp(wan)\n"
  "redirect to lan\n"
)

# The same gateway with the masquerade behind a helper def.
_GATEWAY_VIA_HELPER = (
  "zone lan = [veth0]\n"
  "zone wan = [veth1]\n"
  "def out(pkt):\n"
  "  masquerade\n"
  "@xdp(lan)\n"
  "def l(pkt):\n"
  "  out(pkt)\n"
  "  redirect to wan\n"
  "@xdp(wan)\n"
  "def w(pkt):\n"
  "  allow\n"
)


def _manifest(source: str, tmp_path) -> dict:
  program = analyzer.analyze(parser.parse(source))
  bundle = tmp_path / "bundle"
  cli._emit_bundle_dir(program, bundle)
  return json.loads((bundle / "manifest.json").read_text())


def _flags(manifest: dict) -> dict[str, bool]:
  return {p["zone"]: p["masquerades"] for p in manifest["programs"]}


def test_only_the_masquerading_zone_is_flagged(tmp_path):
  """The WAN program carries fwl_nat_cfg and is still not a source.

  It is in the object because return traffic de-NATs on whichever zone
  it arrives, not because this zone translates anything. A daemon that
  seeded from map presence would program the LAN address as the
  masquerade source and rewrite outbound packets to an address no
  upstream router will route back.
  """
  assert _flags(_manifest(_GATEWAY, tmp_path)) == {
    "lan": True, "wan": False,
  }


def test_a_masquerade_reached_through_a_helper_still_counts(tmp_path):
  """The action is in a `def`; the object emits it either way.

  Scanning only the zone body missed it, and missing it is not a
  compile error or a load error: `fwl_nat_cfg` slot 0 stays unset, the
  XDP masquerade action no-ops on an unset slot, and the gateway
  forwards untranslated private sources.
  """
  assert _flags(_manifest(_GATEWAY_VIA_HELPER, tmp_path)) == {
    "lan": True, "wan": False,
  }


def test_the_flag_is_scanned_over_the_same_set_the_object_emits():
  """`_program_masquerades` and the emitter must not disagree.

  The emitter accounts for a zone body plus its reachable helpers; the
  manifest flag is read from the same closure, so a policy cannot
  produce an object whose code masquerades and a manifest that says it
  does not.
  """
  program = analyzer.analyze(parser.parse(_GATEWAY_VIA_HELPER))
  lan = program.programs[0]
  # Without the helpers the closure is empty and the answer is wrong —
  # this is the bug the argument exists to prevent, pinned here so the
  # parameter cannot quietly go away again.
  assert emitter._program_masquerades(lan) is False
  assert emitter._program_masquerades(lan, program.helpers) is True


@pytest.mark.parametrize("source", [_GATEWAY, _GATEWAY_VIA_HELPER])
def test_a_nat_program_declares_conntrack_it_never_reads(source, tmp_path):
  """No `conntrack(pkt).state` anywhere, and the map is still there.

  `fwl_snat_egress` writes the post-NAT 5-tuple into it, so the reply's
  reverse tuple reads `established` and a stateful WAN program lets the
  return traffic back in. Emitting the NAT helpers without the map they
  write to is how the masquerade gateway ended up one-way
  (tests/system/return_path_probe.sh).
  """
  assert "conntrack(pkt)" not in source
  manifest = _manifest(source, tmp_path)
  assert "conntrack" in manifest["shared_pinned_maps"]
  assert "fwl_nat" in manifest["shared_pinned_maps"]
  assert "fwl_nat_cfg" in manifest["shared_pinned_maps"]


def test_conntrack_is_absent_when_nothing_needs_it(tmp_path):
  """The declaration follows a need; it is not unconditional.

  `shared_pinned_maps` naming a map no object pins is the defect the
  field was rewritten to fix, and widening the NAT rule into "always"
  would put it back.
  """
  source = (
    "zone a = [e0]\n"
    "zone b = [e1]\n"
    "@xdp(a)\n"
    "redirect to b\n"
    "@xdp(b)\n"
    "allow\n"
  )
  manifest = _manifest(source, tmp_path)
  assert "conntrack" not in manifest["shared_pinned_maps"]
  assert "fwl_nat" not in manifest["shared_pinned_maps"]
