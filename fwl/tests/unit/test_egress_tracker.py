"""The bundle's TC egress conntrack tracker (v0.4 § 6.9).

XDP conntrack only ever sees INGRESS, so a flow the box itself
originates creates no entry, its reply reads NEW, and `default drop`
eats it. Measured on the rig (l12_01): 5 requests out, 5 replies at the
port by datapath counter, 0 survived, conntrack 0 -> 0.

The tracker closes that at the qdisc layer. What these cases hold it to
is not "does it compile" — the rig answers that — but the four
properties a reader cannot check by eye and a wire test would only
catch by luck.
"""
import json
import re
from fwl import analyzer, cli, emitter, parser


def _analyze(source: str):
  return analyzer.analyze(parser.parse(source))


# A realistic office WAN policy: stateful return path, nothing else.
STATEFUL = (
  "zone lan = [e0]\n"
  "zone wanz = [e1]\n"
  "@xdp(lan)\n"
  "masquerade if pkt.dst_ip == 8.8.8.8\n"
  "redirect to wanz if pkt.dst_ip == 8.8.8.8\n"
  "allow\n"
  "@xdp(wanz)\n"
  "allow if conntrack(pkt).state in [established, related]\n"
  "default drop\n"
)

# The same shape with no conntrack question anywhere.
STATELESS = (
  "zone lan = [e0]\n"
  "zone wanz = [e1]\n"
  "@xdp(lan)\n"
  "allow\n"
  "@xdp(wanz)\n"
  "drop if pkt.proto == udp\n"
  "default allow\n"
)


def _conntrack_decl(src: str) -> str:
  m = re.search(
    r'struct \{[^{}]*\} conntrack SEC\("\.maps"\);', src
  )
  assert m, "no conntrack declaration"
  return m.group(0)


class TestWhenItIsEmitted:
  def test_a_policy_that_reads_conntrack_gets_a_tracker(self):
    files = emitter.emit_bundle(_analyze(STATEFUL))
    assert emitter.EGRESS_TRACKER_SOURCE in files

  def test_a_policy_that_never_reads_conntrack_gets_none(self):
    """Not a saving — a correctness rule.

    A bundle with no conntrack map has nothing for a tracker to write
    into, and emitting one anyway would pin `conntrack` from an object
    no zone program reads: state accumulating in a map the datapath
    never consults, and a pin `fd` would then have to reconcile against
    a bundle that does not declare it.
    """
    files = emitter.emit_bundle(_analyze(STATELESS))
    assert emitter.EGRESS_TRACKER_SOURCE not in files
    assert not emitter.bundle_needs_egress_tracker(_analyze(STATELESS))

  def test_one_zone_reading_conntrack_is_enough(self):
    """The zone that reads it is not the zone the box egresses from.

    A DNS query leaves through the WAN zone and its reply is judged
    there, but a policy can just as well ask the question only on the
    LAN side. The tracker is a property of the bundle, so one asker
    anywhere is what decides.
    """
    source = (
      "zone lan = [e0]\n"
      "zone wanz = [e1]\n"
      "@xdp(lan)\n"
      "allow if conntrack(pkt).state == established\n"
      "allow\n"
      "@xdp(wanz)\n"
      "allow\n"
    )
    assert emitter.bundle_needs_egress_tracker(_analyze(source))


class TestReservedNames:
  def test_a_zone_named_after_the_tracker_fails_the_compile(self):
    """The tracker is one more file in the bundle's dict of sources.

    A zone called `fwl_egress` compiles to the same filename, so the
    tracker would silently replace it: the zone's object would be built
    from the tracker's source, carry no `fwl_prog`, and fail the load
    with a message about the wrong thing entirely. A reserved name is a
    compile error, like a zone_id collision and for the same reason.
    """
    import pytest
    from fwl.errors import FwlException
    source = (
      "zone fwl_egress = [e0]\n"
      "zone b = [e1]\n"
      "@xdp(fwl_egress)\n"
      "allow if conntrack(pkt).state == established\n"
      "allow\n"
      "@xdp(b)\n"
      "allow\n"
    )
    with pytest.raises(FwlException, match="fwl_egress"):
      emitter.emit_bundle(_analyze(source))


class TestItSharesTheOneConntrackMap:
  def test_the_declaration_is_byte_identical_to_a_zone_object(self):
    """The property libbpf enforces, checked before libbpf sees it.

    Both objects pin `conntrack` by name. libbpf compares type, key,
    value, max_entries and flags when it reuses a pin and refuses a
    mismatch with -EINVAL and no detail. A tracker whose declaration had
    drifted would either fail every load with "Invalid argument" or —
    if only the comment moved — write entries into a second kernel map
    that no XDP program reads, which looks exactly like the bug it is
    supposed to fix.
    """
    files = emitter.emit_bundle(_analyze(STATEFUL))
    tracker = _conntrack_decl(files[emitter.EGRESS_TRACKER_SOURCE])
    for name, src in files.items():
      if name.endswith(".bpf.c") and "conntrack SEC" in src:
        assert _conntrack_decl(src) == tracker, name

  def test_it_pins_conntrack_by_name(self):
    src = emitter.emit_egress_tracker()
    assert "LIBBPF_PIN_BY_NAME" in _conntrack_decl(src)

  def test_its_own_tally_is_bundle_global(self):
    """One tracker, one tally. There is no zone to attribute it to."""
    src = emitter.emit_egress_tracker()
    decls = {d.name: d for d in emitter._scan_map_decls(src)}
    assert decls["fwl_egress_stats"].pinned
    kind = emitter._map_kind("fwl_egress_stats")
    assert kind.scope is emitter.MapScope.SHARED
    # POLICY, not FLOW: a count of how entries got there is attributed
    # to the compilation that made them, unlike the entries themselves.
    assert kind.lifetime is emitter.MapLifetime.POLICY
    assert "fwl_egress_stats" not in emitter.persistent_map_names()


class TestWhatItRefusesToTrack:
  def test_it_gates_on_the_skb_socket(self):
    """The whole reason it does not change what the firewall forwards.

    A packet the LOCAL STACK sent carries the socket that sent it; one
    this box merely FORWARDED has none. Without the gate the tracker
    would create an entry for every forwarded flow and quietly admit
    its replies — a policy change made by a component whose job is to
    observe. There is no wire test that distinguishes "tracked
    correctly" from "tracked everything" on a box whose policy would
    have allowed the reply anyway, so the gate is asserted in the text
    as well as on the rig.
    """
    src = emitter.emit_egress_tracker()
    assert "skb->sk == NULL" in src
    gate = src.index("skb->sk == NULL")
    create = src.index("BPF_NOEXIST")
    assert gate < create, "the socket gate must precede any insert"

  def test_a_non_first_fragment_is_not_keyed_on_ports_zero(self):
    src = emitter.emit_egress_tracker()
    assert "0x1FFF" in src

  def test_ports_are_parsed_for_tcp_and_udp_and_nothing_else(self):
    """And everything else is keyed on ports 0, like the prelude.

    The XDP prelude parses ports for TCP and UDP and leaves them at 0
    for every other protocol, so a box-originated GRE or IPsec flow HAS
    a key on the ingress side. A tracker that refused to write one would
    leave the two disagreeing about a tuple they both compute — and the
    box's own IPsec return traffic dropped.
    """
    src = emitter.emit_egress_tracker()
    assert "proto == IPPROTO_TCP || proto == IPPROTO_UDP" in src
    assert "proto != IPPROTO_ICMP" not in src

  def test_a_vlan_tag_is_skipped_the_way_the_prelude_skips_it(self):
    """Otherwise every box-originated flow on a VLAN zone is untracked.

    The prelude advances L3 past an 802.1Q tag and keys conntrack on
    the INNER header. A tracker that rejected tagged frames would agree
    with it on an untagged segment and silently disagree on a tagged
    one — with the daemon logging an attach and the CLI rendering a
    healthy row.
    """
    src = emitter.emit_egress_tracker()
    assert "ETH_P_8021Q" in src
    assert "fwl_vlanhdr" in src
    vlan = src.index("ETH_P_8021Q")
    ip_test = src.index("h_proto != bpf_htons(ETH_P_IP)")
    assert vlan < ip_test, "the tag must be skipped before the L3 test"


class TestWhatItCostsTheTable:
  def test_both_directions_are_probed_before_anything_is_created(self):
    """One entry per originated flow, not two per served flow.

    A reply the box sends to a client that queried it is egress traffic
    too, and its forward key is the REVERSE of the entry the client's
    own query already created on ingress. A tracker that probed one
    direction would miss, insert, and double conntrack's fill rate — in
    the table that is already the binding constraint at two entries per
    NAT mapping (l11_02). The occupancy curve measured flat at 2 % of
    the cap under a steady workload (l11_06), and that is the result
    this ordering preserves.
    """
    src = emitter.emit_egress_tracker()
    fwd = src.index("bpf_map_lookup_elem(&conntrack, &fwd)")
    rev = src.index("bpf_map_lookup_elem(&conntrack, &rev)")
    create = src.index("BPF_NOEXIST")
    assert fwd < create and rev < create

  def test_an_existing_entry_is_refreshed_not_replaced(self):
    """The GC ages on last_seen_ns, so an entry whose traffic is mostly
    OUTBOUND has to be stamped from here or it is collected out from
    under a live flow."""
    src = emitter.emit_egress_tracker()
    assert "v->last_seen_ns = now;" in src

  def test_a_refused_insert_is_counted(self):
    """The one way this feature can stop working, and it looks like
    nothing: conntrack full, the query still goes out, the reply still
    arrives, and `default drop` eats it — the original symptom, restored
    by a mechanism working exactly as designed."""
    src = emitter.emit_egress_tracker()
    assert "FWL_EGRESS_STAT_REFUSED" in src
    refused = src.index("FWL_EGRESS_STAT_REFUSED")
    tracked = src.index("fwl_egress_bump(FWL_EGRESS_STAT_TRACKED)")
    assert refused < tracked, "the failure path must return early"


class TestTheManifest:
  def test_it_names_the_object_and_the_program(self, tmp_path):
    program = _analyze(STATEFUL)
    bundle = tmp_path / "bundle"
    cli._emit_bundle_dir(program, bundle)
    manifest = json.loads((bundle / "manifest.json").read_text())
    entry = manifest["egress_tracker"]
    assert entry["source"] == emitter.EGRESS_TRACKER_SOURCE
    assert entry["program"] == emitter.EGRESS_TRACKER_PROG
    # `object` is None only when clang was unavailable; fd refuses such
    # a bundle rather than run without the tracker.
    assert entry["object"] in (None, "fwl_egress.bpf.o")

  def test_a_stateless_bundle_says_so_with_null(self, tmp_path):
    """Null, not absent.

    Absent means "compiled by an fwl that did not know about the hook",
    and fd has to warn about that case — a box whose own DNS its own
    policy drops looks healthy from every other line. Null means "this
    policy needs none", which is silent by design. Collapsing the two
    would either spam every stateless bundle or hide every stale one.
    """
    program = _analyze(STATELESS)
    bundle = tmp_path / "bundle"
    cli._emit_bundle_dir(program, bundle)
    manifest = json.loads((bundle / "manifest.json").read_text())
    assert "egress_tracker" in manifest
    assert manifest["egress_tracker"] is None

  def test_the_tally_is_declared_shared_in_the_manifest(self, tmp_path):
    program = _analyze(STATEFUL)
    bundle = tmp_path / "bundle"
    cli._emit_bundle_dir(program, bundle)
    manifest = json.loads((bundle / "manifest.json").read_text())
    assert "fwl_egress_stats" in manifest["shared_pinned_maps"]
    assert "conntrack" in manifest["shared_pinned_maps"]
