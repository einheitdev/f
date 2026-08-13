"""The map-sharing invariants (v0.4 § 6.2).

A map that is private per zone but pinned under a bundle-global name
has been found three times. Two of the three were omissions: nobody
misunderstood the problem, they just added a map and did not think
about sharing, and the old emitter treated silence as "share it".

So the emitter now refuses to emit a map whose sharing nobody
declared, and refuses to emit a bundle in which one pinned name is
declared two different ways. These tests hold both refusals down, and
the first of them — `test_unclassified_map_fails_the_build` — is the
regression test for the omission mode itself.

Every simulated defect here is injected as the DEFECT, not as the
error: the tests make the emitter produce the bad artifact and assert
the compile stops, rather than asserting that a checker was called.
"""
import pytest

from fwl import analyzer, emitter, parser
from fwl.errors import FwlException

ZL = "zone a = [e0]\nzone b = [e1]\n"

# Two zones that differ in every count a map could be sized from:
# rules, counters, and geoip call sites. A map whose shape comes from
# one zone's analysis diverges here rather than agreeing by luck.
_ASYMMETRIC = (
  ZL
  + "@xdp(a)\n"
    "count a_one\ncount a_two\n"
    "log(sample=4) if pkt.proto == udp\n"
    "drop if pkt.proto == icmp\n"
    "allow\n"
    "@xdp(b)\n"
    "count b_only\n"
    "log(sample=8) if pkt.proto == tcp\n"
    "redirect to a\n"
)

# A new map declaration, exactly as an author would write one at a
# declaration site — and exactly as the two omissions reached the tree.
_NEW_MAP = (
  "struct {\n"
  "  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);\n"
  "  __type(key, __u32);\n"
  "  __type(value, __u64);\n"
  "  __uint(max_entries, 8);\n"
  "} fwl_synflood SEC(\".maps\");\n"
)

# The same map written by an author who copied a bundle-shared
# declaration, pinning attribute and all. This is the shape that
# aliased silently: one name, one kernel map, every zone's slot 0 the
# same cell.
_NEW_MAP_PINNED = _NEW_MAP.replace(
  "  __uint(max_entries, 8);\n",
  "  __uint(max_entries, 8);\n"
  "  __uint(pinning, LIBBPF_PIN_BY_NAME);\n",
)


def _analyze(text):
  return analyzer.analyze(parser.parse(text))


def _inject(monkeypatch, decl):
  """Make the emitter declare `decl` in every zone object it emits.

  Hooks the geoip block, which every zone source concatenates and
  which is empty for a policy without geoip() — so the injected text
  is the only change to the output.
  """
  monkeypatch.setattr(
    emitter, "_emit_geoip_maps_and_helpers",
    lambda program, names: decl,
  )


# --------------------------------------------------------------------
class TestOmission:
  """Layer 1: a map nobody classified must not reach the kernel."""

  @pytest.mark.parametrize("decl", [_NEW_MAP, _NEW_MAP_PINNED])
  def test_unclassified_map_fails_the_build(self, monkeypatch, decl):
    # THE regression test. Before this invariant existed, a new map
    # declaration compiled: pinned, it took a bundle-global name and
    # aliased across every zone in silence; unpinned, it quietly
    # became per-object state. Which one you got depended on nothing
    # but the declaration the author happened to copy. Now neither
    # compiles until somebody says which it is.
    _inject(monkeypatch, decl)
    with pytest.raises(FwlException) as excinfo:
      emitter.emit_bundle(_analyze(_ASYMMETRIC))
    assert "fwl_synflood" in str(excinfo.value)
    assert "sharing scope" in str(excinfo.value)

  def test_unclassified_map_fails_single_object_emission_too(
    self, monkeypatch
  ):
    # Nothing is pinned in a single object, so this map could not
    # alias yet — but the same source becomes a zone object the moment
    # a second @xdp block is added, and the classification is what
    # decides what happens then. Catch it at the earliest compile.
    _inject(monkeypatch, _NEW_MAP)
    with pytest.raises(FwlException, match="fwl_synflood"):
      emitter.emit(_analyze("@xdp(e0)\ndrop\n"))

  def test_error_says_what_to_do(self, monkeypatch):
    # An error that names the map but not the fix sends the next
    # author looking for the checker instead of the registry.
    _inject(monkeypatch, _NEW_MAP)
    with pytest.raises(FwlException) as excinfo:
      emitter.emit(_analyze("@xdp(e0)\ndrop\n"))
    message = str(excinfo.value)
    assert "_MAP_KINDS" in message
    assert "SHARED" in message and "PRIVATE" in message

  def test_asking_for_an_unregistered_name_fails(self):
    # The other half of the same rule: a declaration site that asks
    # MapNames for a name gets the error before any C exists.
    with pytest.raises(FwlException, match="fwl_synflood"):
      emitter.MapNames("a").qualified("fwl_synflood")

  def test_registry_has_no_dead_rows(self):
    # Every row in the registry describes a map the emitter can really
    # produce. A row nobody matches is a row that has stopped
    # describing the code, and the next reader will trust it anyway.
    # Single-object emission is used because it leaves the base names
    # in place, which is what the registry is keyed on.
    sources = [
      emitter.emit(_analyze(
        ZL
        + "@xdp(a)\n"
          "count a_one\n"
          "log(sample=4) if pkt.proto == udp\n"
          "drop if pkt.src_ip in geoip(RU)\n"
          "drop limited by rate_limit(3, per=src_ip)\n"
          "drop limited by rate_limit(7, per=src_ip, scope=global)\n"
          "allow if conntrack(pkt).state == established\n"
          "masquerade\n"
          "redirect to b\n"
          "@xdp(b)\n"
          "allow\n"
      )),
      # The pipeline maps exist only in a split object (v0.4 § 6.6).
      emitter.emit(_analyze(
        "@xdp(e0)\n"
        + "".join(
          f"drop if pkt.src_ip == 10.0.0.{i} and pkt.proto == tcp "
          f"and pkt.dst_port == {1000 + i}\n"
          for i in range(60)
        )
        + "default allow\n"
      ), split=True),
    ]
    matched: set[str] = set()
    for src in sources:
      for decl in emitter._scan_map_decls(src):
        kind = emitter._map_kind(decl.name)
        assert kind is not None, decl.name
        matched.add(kind.base)
    assert matched == {k.base for k in emitter._MAP_KINDS}


# --------------------------------------------------------------------
class TestMisclassification:
  """Layer 2: one pinned name must be one map, declared one way."""

  def test_shared_map_sized_per_zone_fails_the_compile(
    self, monkeypatch
  ):
    # The misjudgement half: a map correctly declared SHARED, but
    # sized from the emitting zone's own analysis. libbpf would reject
    # the second object with -EINVAL at load; the bundle is visibly
    # inconsistent at compile time, so it stops here.
    real = emitter._emit_rl_maps

    def per_zone_sized(program, names, pinned_shared=False):
      return real(program, names, pinned_shared).replace(
        f"max_entries, {emitter._RL_MAX_ENTRIES}",
        f"max_entries, {100 * len(program.rules)}",
      )

    monkeypatch.setattr(emitter, "_emit_rl_maps", per_zone_sized)
    src = (
      ZL
      + "@xdp(a)\n"
        "drop if pkt.proto == icmp\n"
        "drop limited by rate_limit(7, per=src_ip, scope=global)\n"
        "allow\n"
        "@xdp(b)\n"
        "drop limited by rate_limit(7, per=src_ip, scope=global)\n"
        "allow\n"
    )
    with pytest.raises(FwlException) as excinfo:
      emitter.emit_bundle(_analyze(src))
    message = str(excinfo.value)
    # The map, both zones, and the values they disagree on.
    assert "fwl_rl_g0" in message
    assert "'a'" in message and "'b'" in message
    assert "max_entries=300" in message and "max_entries=200" in message

  def test_agreeing_shapes_are_accepted(self):
    # The invariant must not reject the legitimate case it exists to
    # protect: two zones declaring one global bucket identically.
    files = emitter.emit_bundle(_analyze(
      ZL
      + "@xdp(a)\n"
        "drop if pkt.proto == icmp\n"
        "drop limited by rate_limit(7, per=src_ip, scope=global)\n"
        "allow\n"
        "@xdp(b)\n"
        "drop limited by rate_limit(7, per=src_ip, scope=global)\n"
        "allow\n"
    ))
    a = files["a.bpf.c"]
    b = files["b.bpf.c"]
    assert "} fwl_rl_g0 SEC" in a and "} fwl_rl_g0 SEC" in b


# --------------------------------------------------------------------
class TestScopeIsHonoured:
  """The rest of layer 1: a scope also constrains name and pinning."""

  def test_private_map_under_a_global_name_fails(self, monkeypatch):
    # This IS the historical defect (4ec4ec4), reintroduced: the
    # counter map declared with its bundle-global name in a bundle.
    # The two zones here have different counter counts, so the old
    # loud failure would be -EINVAL at load; equalize them and it
    # would be silent. Either way the compile now refuses.
    monkeypatch.setattr(
      emitter, "_COUNTER_MAP_DECL_TEMPLATE",
      emitter._COUNTER_MAP_DECL_TEMPLATE.replace("{name}", "fwl_counters"),
    )
    with pytest.raises(FwlException) as excinfo:
      emitter.emit_bundle(_analyze(_ASYMMETRIC))
    message = str(excinfo.value)
    assert "fwl_counters" in message
    assert "PRIVATE" in message

  def test_object_private_map_may_not_be_pinned(self, monkeypatch):
    # fwl_scratch and fwl_stages are this object's own transients.
    # Pinning them by name would cross-wire two split zones' pipelines
    # — the one failure in this family that would not just report
    # wrong numbers but run the wrong program.
    monkeypatch.setattr(
      emitter, "_SCRATCH_MAP_DECL_TEMPLATE",
      emitter._SCRATCH_MAP_DECL_TEMPLATE.replace(
        "  __uint(max_entries, 1);",
        "  __uint(max_entries, 1);\n"
        "  __uint(pinning, LIBBPF_PIN_BY_NAME);",
      ),
    )
    with pytest.raises(FwlException) as excinfo:
      emitter.emit(_analyze(
        "@xdp(e0)\n"
        + "".join(
          f"drop if pkt.src_ip == 10.0.0.{i} and pkt.proto == tcp "
          f"and pkt.dst_port == {1000 + i}\n"
          for i in range(60)
        )
        + "default allow\n"
      ), split=True)
    assert "fwl_scratch" in str(excinfo.value)
    assert "object-private" in str(excinfo.value)

  def test_shared_map_must_be_pinned_in_a_bundle(self, monkeypatch):
    # The mirror-image bug: state declared bundle-wide but emitted
    # without LIBBPF_PIN_BY_NAME, so each object quietly gets its own
    # copy and cross-zone conntrack stops working.
    monkeypatch.setattr(emitter, "_maybe_pin", lambda decl, pinned: decl)
    with pytest.raises(FwlException) as excinfo:
      emitter.emit_bundle(_analyze(
        ZL
        + "@xdp(a)\nallow if conntrack(pkt).state == established\ndrop\n"
          "@xdp(b)\nallow\n"
      ))
    message = str(excinfo.value)
    assert "conntrack" in message
    assert "SHARED" in message


# --------------------------------------------------------------------
class TestDeclaredScopes:
  """What the registry says about the maps that exist today."""

  def test_rate_limit_global_bucket_is_shared(self):
    # v0.4 § 6.7 added the first deliberately bundle-shared map since
    # the audit. It belongs on the shared side: the budget is
    # bundle-wide by declaration and the map is sized from a constant.
    kind = emitter._map_kind("fwl_rl_g0")
    assert kind is not None
    assert kind.scope is emitter.MapScope.SHARED
    assert kind.private_name is None

  def test_zone_scoped_rate_limit_bucket_is_private(self):
    kind = emitter._map_kind("fwl_rl_map_3")
    assert kind is not None
    assert kind.scope is emitter.MapScope.PRIVATE
    assert emitter.MapNames("a").rate_limit(
      _analyze(
        "@xdp(e0)\n"
        "drop limited by rate_limit(5, per=src_ip)\n"
        "default allow\n"
      ).programs[0].rules[0].modifier, 0
    ) == "fwl_rl_a_0"

  def test_counters_and_log_sample_are_private(self):
    for base in ("fwl_counters", "fwl_log_sample"):
      kind = emitter._map_kind(base)
      assert kind is not None
      assert kind.scope is emitter.MapScope.PRIVATE
      assert kind.private_name is not None

  def test_cross_zone_state_is_shared(self):
    for base in ("conntrack", "fwl_nat", "fwl_nat_cfg",
                 "fwl_log_events", "fwl_devmap_wan"):
      kind = emitter._map_kind(base)
      assert kind is not None
      assert kind.scope is emitter.MapScope.SHARED

  def test_every_kind_states_why(self):
    # The rationale is the part a reader checks a new map against.
    for kind in emitter._MAP_KINDS:
      assert kind.why.strip()

  def test_single_object_emission_keeps_base_names(self):
    # `fwl compile -o` and the BPF oracle load one object and pin
    # nothing, and the runner addresses rate-limit buckets by base
    # name. Zone qualification is a bundle concern only.
    names = emitter.MapNames(None)
    assert names.counters() == "fwl_counters"
    assert names.geoip(2) == "fwl_geoip_2"
