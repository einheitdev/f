"""Per-zone rule metadata in the bundle manifest.

The claim under test is the one an operator makes at the office: "this
is what the box is enforcing". It is only true if the metadata is
complete for the surface it says it covers, in policy order, and if the
places it is NOT complete say so by name rather than by producing
something that looks like FWL.

`TestTheRendererIsTotal` is the load-bearing one: it walks the AST's own
`Condition` and `Operand` unions, so a node type added to the language
without a rendering fails the build instead of shipping a `repr()` into
a manifest.
"""
from __future__ import annotations

import hashlib
import json
import typing

import pytest

from fwl import analyzer, ast, cli, parser, rulemeta


def _analyze(text: str) -> ast.Program:
  return analyzer.analyze(parser.parse(text))


def _bundle(tmp_path, text: str, name: str = "policy.fw") -> dict:
  """Compile `text` to a bundle and return its manifest."""
  tmp_path.mkdir(parents=True, exist_ok=True)
  src = tmp_path / name
  src.write_text(text, encoding="utf-8")
  out = tmp_path / "bundle"
  cli._emit_bundle_dir(_analyze(text), out, None,
                       source=src, source_text=text)
  return json.loads((out / "manifest.json").read_text())


def _zone(manifest: dict, zone: str) -> dict:
  for p in manifest["programs"]:
    if p["zone"] == zone:
      return p
  raise AssertionError(f"no program for zone {zone}")


TWO_ZONES = """\
zone lan = [veth0]
zone wan = [veth1]

@xdp(wan)
drop if pkt.proto == tcp and pkt.dst_port == 22
allow if conntrack(pkt).state in [established, related]
default drop

@xdp(lan)
count lan_total
masquerade
redirect to wan
"""


class TestTheRulesAreThere:
  """A zone's rules, in order, with action and match."""

  def test_every_rule_appears_once_in_policy_order(self, tmp_path):
    m = _bundle(tmp_path, TWO_ZONES)
    wan = _zone(m, "wan")["rules"]
    assert wan["form"] == "rules"
    assert [r["action"] for r in wan["rules"]] == ["drop", "allow"]
    # The outermost parentheses `render_condition` adds for nesting
    # say nothing about a whole-rule guard, so they are dropped.
    assert wan["rules"][0]["match"] == (
      "pkt.proto == tcp and pkt.dst_port == 22")
    assert wan["rules"][1]["match"] == (
      "conntrack(pkt).state in [established, related]")

  def test_order_is_the_source_order_not_a_sort(self, tmp_path):
    # `allow` is terminal, so a rule list reordered by any key at all
    # describes a different firewall. Two rules whose alphabetical and
    # source orders disagree.
    m = _bundle(tmp_path, """\
zone edge = [veth0]

@xdp(edge)
allow if pkt.proto == tcp and pkt.dst_port == 80
drop if pkt.proto == tcp and pkt.dst_port == 443
default drop
""")
    rules = _zone(m, "edge")["rules"]["rules"]
    assert [r["action"] for r in rules] == ["allow", "drop"]
    assert [r["log_rule_index"] for r in rules] == [0, 1]

  def test_the_action_carries_its_target(self, tmp_path):
    m = _bundle(tmp_path, """\
zone lan = [veth0]
zone wan = [veth1]
zone dmz = [veth2]

@xdp(lan)
count lan_total
dnat to 10.0.0.5:8080 if pkt.proto == tcp and pkt.dst_port == 80
snat to 192.0.2.1 if pkt.proto == udp
masquerade
redirect to wan

@xdp(wan)
redirect to dmz

@xdp(dmz)
default drop
""")
    texts = [r["action"] for r in _zone(m, "lan")["rules"]["rules"]]
    assert texts == [
      "count lan_total",
      "dnat to 10.0.0.5:8080",
      "snat to 192.0.2.1",
      "masquerade",
      "redirect to wan",
    ]
    # A redirect whose zone is dropped from the display is a redirect
    # to the wrong place that nobody can see.
    assert _zone(m, "wan")["rules"]["rules"][0]["action"] == (
      "redirect to dmz")

  def test_nesting_parentheses_are_kept_where_they_mean_something(
      self, tmp_path):
    # Only a pair that encloses the WHOLE guard is redundant. Dropping
    # the first `(` of `(a or b) and c` would change what the rule
    # matches, and a match text that is not the rule is worse than a
    # noisy one.
    m = _bundle(tmp_path, """\
zone e = [v0]

@xdp(e)
drop if (pkt.dst_ip == 10.0.0.1 or pkt.dst_ip == 10.0.0.2) \
and pkt.proto == icmp
default drop
""")
    match = _zone(m, "e")["rules"]["rules"][0]["match"]
    assert match == ("(pkt.dst_ip == 10.0.0.1 or "
                     "pkt.dst_ip == 10.0.0.2) and pkt.proto == icmp")

  def test_the_rate_limit_modifier_survives(self, tmp_path):
    m = _bundle(tmp_path, """\
zone edge = [veth0]

@xdp(edge)
drop limited by rate_limit(2000, per=src_ip)
default drop
""")
    r = _zone(m, "edge")["rules"]["rules"][0]
    assert r["rate_limit"] == "rate_limit(2000, per=src_ip)"
    assert r["text"] == "drop limited by rate_limit(2000, per=src_ip)"

  def test_terminal_is_marked(self, tmp_path):
    m = _bundle(tmp_path, TWO_ZONES)
    lan = _zone(m, "lan")["rules"]["rules"]
    by_action = {r["action"]: r["terminal"] for r in lan}
    assert by_action["count lan_total"] is False
    assert by_action["masquerade"] is False
    assert by_action["redirect to wan"] is True

  def test_a_line_number_points_into_the_source(self, tmp_path):
    m = _bundle(tmp_path, TWO_ZONES)
    lines = TWO_ZONES.splitlines()
    for prog in m["programs"]:
      for r in prog["rules"]["rules"]:
        assert r["line"] >= 1
        assert r["action"].split()[0] in lines[r["line"] - 1]


class TestTheDefaultIsNamed:
  """The most consequential line of a policy is never a blank."""

  def test_an_explicit_default_is_reported_as_written(self, tmp_path):
    m = _bundle(tmp_path, TWO_ZONES)
    d = _zone(m, "wan")["rules"]["default"]
    assert d["action"] == "drop"
    assert d["explicit"] is True

  def test_an_absent_default_reports_the_fall_through(self, tmp_path):
    # A zone with no `default` line falls through to XDP_PASS. A
    # manifest that reported `null` there would let a box that passes
    # everything reaching the end of a block look like a box with no
    # opinion.
    m = _bundle(tmp_path, TWO_ZONES)
    d = _zone(m, "lan")["rules"]["default"]
    assert d["action"] == "allow"
    assert d["explicit"] is False


class TestTierTwoIsNotPretendedAway:
  """A zone with no rule list says so, and does not say "no rules"."""

  def test_a_function_zone_reports_the_function_form(self, tmp_path):
    m = _bundle(tmp_path, """\
zone edge = [veth0]

@xdp(edge)
def policy(pkt):
  if pkt.dst_port == 22:
    drop
  allow
""")
    r = _zone(m, "edge")["rules"]
    assert r["form"] == "function"
    assert r["rules"] == []
    assert "Tier 2" in r["detail"]
    assert "policy" in r["detail"]

  def test_it_differs_from_a_zone_with_an_empty_rule_list(self,
                                                          tmp_path):
    empty = _bundle(tmp_path / "a", """\
zone edge = [veth0]

@xdp(edge)
default drop
""")
    fn = _bundle(tmp_path / "b", """\
zone edge = [veth0]

@xdp(edge)
def policy(pkt):
  allow
""")
    a = _zone(empty, "edge")["rules"]
    b = _zone(fn, "edge")["rules"]
    assert a["rules"] == [] and b["rules"] == []
    # Same empty list, different findings. A consumer that reads only
    # the list cannot tell them apart; `form` is what it must read.
    assert a["form"] != b["form"]


class TestTheStageBoundariesAreDeclaredRatherThanHidden:
  def test_a_chain_reports_boundaries_and_the_missing_labels(self,
                                                             tmp_path):
    m = _bundle(tmp_path, """\
zone edge = [veth0]

@xdp(edge)
drop if pkt.proto == tcp and pkt.dst_port == 22
chain late
drop if pkt.proto == tcp and pkt.dst_port == 23
default drop
""")
    r = _zone(m, "edge")["rules"]
    assert r["stage_boundaries"] == [1]
    assert "chain" in r["detail"] and "not reported" in r["detail"]
    # The rules themselves are all there — a split policy is not a
    # partial policy.
    assert len(r["rules"]) == 2


class TestTheRendererIsTotal:
  """Every node the language has, this build can write.

  A `repr()` in a manifest is not a match expression; it is a string
  that looks like one to a reader and parses as nothing. The union
  walk is what makes a new AST node a build failure rather than a
  surprise on a box.
  """

  @staticmethod
  def _members(union) -> list:
    out = []
    for arg in typing.get_args(union):
      if isinstance(arg, typing.ForwardRef):
        out.append(getattr(ast, arg.__forward_arg__))
      elif isinstance(arg, str):
        out.append(getattr(ast, arg))
      else:
        out.append(arg)
    return out

  def test_every_condition_node_type_has_a_rendering(self):
    unhandled = []
    for node_type in self._members(ast.Condition):
      src = _SAMPLE_CONDITIONS.get(node_type.__name__)
      if src is None:
        unhandled.append(node_type.__name__)
        continue
      cond = _first_condition(src)
      assert isinstance(cond, node_type) or _contains(cond, node_type)
      text = rulemeta.render_condition(cond)
      assert text and "object at 0x" not in text
    assert not unhandled, (
      f"no sample policy for condition node(s) {unhandled} — add one "
      f"and a rendering, or the manifest will carry a repr()")

  def test_every_operand_node_type_has_a_rendering(self):
    unhandled = []
    for node_type in self._members(ast.Operand):
      src = _SAMPLE_OPERANDS.get(node_type.__name__)
      if src is None:
        unhandled.append(node_type.__name__)
        continue
      text = rulemeta.render_condition(_first_condition(src))
      assert text and "object at 0x" not in text
    assert not unhandled, (
      f"no sample policy for operand node(s) {unhandled} — add one "
      f"and a rendering, or the manifest will carry a repr()")

  def test_an_unknown_node_is_refused_rather_than_repred(self):
    class Martian:
      pass
    with pytest.raises(rulemeta.Unrenderable):
      rulemeta.render_condition(Martian())
    with pytest.raises(rulemeta.Unrenderable):
      rulemeta.render_operand(Martian())

  def test_an_unrenderable_rule_says_so_instead_of_lying(self):
    class Martian:
      pass
    rule = ast.Rule(action=ast.Action.DROP, condition=Martian(),
                    modifier=None,
                    span=_first_rule_span("drop\n"))
    entry = rulemeta.rule_entry(0, rule)
    assert entry["renderable"] is False
    assert entry["match"] == ""
    assert "Martian" in entry["omitted"][0]
    # The one-line form must not present an empty match as an
    # unguarded rule: `drop` and `drop if <something we cannot write>`
    # are opposite claims about a firewall.
    assert entry["text"] == "drop if <?>"
    assert entry["guarded"] is True


class TestTheSourceIdentity:
  """Enough to tell a live policy from an edited file."""

  def test_the_digest_is_over_the_compiled_text(self, tmp_path):
    m = _bundle(tmp_path, TWO_ZONES, name="office.fw")
    ps = m["policy_source"]
    assert ps["name"] == "office.fw"
    assert ps["sha256"] == hashlib.sha256(
      TWO_ZONES.encode("utf-8")).hexdigest()
    assert ps["bytes"] == len(TWO_ZONES.encode("utf-8"))
    assert ps["path"].endswith("office.fw")

  def test_editing_the_source_changes_the_digest(self, tmp_path):
    a = _bundle(tmp_path / "a", TWO_ZONES)
    b = _bundle(tmp_path / "b",
                TWO_ZONES.replace("dst_port == 22", "dst_port == 23"))
    assert (a["policy_source"]["sha256"]
            != b["policy_source"]["sha256"])

  def test_a_bundle_built_without_a_file_says_the_source_is_unknown(
      self, tmp_path):
    # Some callers compile from an AST. Naming a file that was never
    # read would make every drift check on such a bundle answer with a
    # comparison against nothing.
    out = tmp_path / "b"
    cli._emit_bundle_dir(_analyze(TWO_ZONES), out, None)
    m = json.loads((out / "manifest.json").read_text())
    assert m["policy_source"] is None


def _first_condition(src: str) -> ast.Condition:
  program = _analyze(src)
  for zp in program.programs:
    for rule in zp.rules:
      if rule.condition is not None:
        return rule.condition
  raise AssertionError("sample policy has no guarded rule")


def _first_rule_span(src: str):
  return _analyze("zone e = [v0]\n\n@xdp(e)\n" + src).programs[
    0].rules[0].span


def _contains(node, node_type) -> bool:
  """True when `node_type` appears anywhere in the condition tree."""
  if isinstance(node, node_type):
    return True
  for attr in ("inner",):
    child = getattr(node, attr, None)
    if child is not None and _contains(child, node_type):
      return True
  for child in getattr(node, "operands", []) or []:
    if _contains(child, node_type):
      return True
  return False


def _zone_src(cond: str) -> str:
  return f"zone e = [v0]\nzone other = [v1]\n\n@xdp(e)\ndrop if {cond}\n"


# The compiler does not infer protocol guards — without one the
# program would read whatever bytes sit at the port offset of an ICMP
# packet — so every port/flag sample carries its own.
_TCP = "pkt.proto == tcp and "

_SAMPLE_CONDITIONS = {
  "Comparison": _zone_src(_TCP + "pkt.dst_port == 22"),
  "BoolField": _zone_src(_TCP + "pkt.tcp.syn"),
  "NotOp": _zone_src(_TCP + "not pkt.tcp.syn"),
  "AndOp": _zone_src(_TCP + "pkt.dst_port == 22"),
  "OrOp": _zone_src(
    _TCP + "(pkt.dst_port == 22 or pkt.dst_port == 23)"),
  "ConntrackStateCompare": _zone_src("conntrack(pkt).state == invalid"),
  "ZoneCompare": _zone_src("pkt.zone == e"),
  "CountCompare": (
    "zone e = [v0]\n\n@xdp(e)\ncount seen\ndrop if count(seen) > 5\n"),
}

_SAMPLE_OPERANDS = {
  "ProtoLiteral": _zone_src("pkt.proto == tcp"),
  "IntLiteral": _zone_src(_TCP + "pkt.dst_port == 22"),
  "IPv4Literal": _zone_src("pkt.dst_ip == 10.0.0.1"),
  "CidrLiteral": _zone_src("pkt.dst_ip in 10.0.0.0/8"),
  "Ipv6Literal": _zone_src("pkt.dst_ip6 == 2001:db8::1"),
  "Ipv6CidrLiteral": _zone_src("pkt.dst_ip6 in 2001:db8::/32"),
  "ListLiteral": _zone_src(_TCP + "pkt.dst_port in [80, 443]"),
  "CidrListLiteral": _zone_src(
    "pkt.dst_ip in [10.0.0.0/8, 192.168.0.0/16]"),
  "Ipv6CidrListLiteral": _zone_src(
    "pkt.dst_ip6 in [2001:db8::/32, 2001:db9::/32]"),
  "RangeLiteral": _zone_src(_TCP + "pkt.dst_port in 1000..2000"),
  "GeoIp": _zone_src("pkt.src_ip in geoip(DE)"),
  # A table reference renders as the name the author wrote. Resolving
  # the alias here would print a name that is not in the policy, and
  # `show policy` has to read back as the file does.
  "TableRef": (
    'table blocked {\n  kind = cidr4\n  max = 10\n'
    '  source = "b.txt"\n}\n'
    + _zone_src("pkt.src_ip in blocked")
  ),
}


class TestTheRenderedFormIsTheSourceForm:
  """A match an operator recognises is one FWL would accept back."""

  @pytest.mark.parametrize("cond", [
    _TCP + "pkt.dst_port == 22",
    "pkt.dst_ip in 10.0.0.0/8",
    "pkt.dst_ip in [10.0.0.0/8, 192.168.0.0/16]",
    _TCP + "pkt.dst_port in [80, 443]",
    _TCP + "pkt.dst_port in 1000..2000",
    "pkt.dst_ip6 in 2001:db8::/32",
    "pkt.dst_ip6 == 2001:db8::1",
    "conntrack(pkt).state in [established, related]",
    _TCP + "not pkt.tcp.syn",
    "pkt.src_ip in geoip(DE, FR)",
  ])
  def test_the_rendering_recompiles(self, cond):
    text = rulemeta.render_condition(_first_condition(_zone_src(cond)))
    # Round-trip: the rendered form is fed back to the parser, and the
    # rule it produces must render identically. A form that reads well
    # and does not parse is a screenshot, not a policy.
    again = rulemeta.render_condition(
      _first_condition(_zone_src(text)))
    assert again == text
