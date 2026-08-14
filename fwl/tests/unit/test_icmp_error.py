"""Unit tests for ICMP-error handling: `related`, and RFC 5508 NAT.

The two halves are separable in code and useless separately on the
wire, so they are tested separately here and together in the corpus:

  * classification — an ICMP error carries no ports, so its own
    5-tuple matches nothing and it reads NEW. Its flow is named in the
    datagram it CARRIES, and reading that is what makes it `related`
    (FWL_V04_SPEC.md § 4.3).
  * translation — the same embedded datagram, reversed, is the reply
    mapping's own key, so the mapping that de-NATs a flow's replies
    de-NATs the errors about it too (RFC 5508 § 4.2).

Measured before either existed, on the rig (l11_05): a genuine
frag-needed was dropped 20/20 by a stateful policy, and admitted 20/20
under a blanket `allow if pkt.proto == icmp` while reaching the
masqueraded host 0/20.
"""
import pytest

from fwl import analyzer, ast, emitter, interpreter, parser, pkt
from fwl.interpreter import ConntrackTable, NatState


H = "@xdp(eth0)\n"


def _analyze(text):
  return analyzer.analyze(parser.parse(text))


def _emit(text):
  return emitter.emit(_analyze(text))


def _pkt(builder):
  return pkt.build_packet(pkt.parse_builder(builder)).fields


def _ip(addr):
  return interpreter._ipv4_to_int(addr)


# One masqueraded flow, in the terms every test below reuses: guest
# 10.0.0.7:40000 -> 8.8.8.8:443, translated to 203.0.113.5:40000.
GUEST, MASQ, PEER = "10.0.0.7", "203.0.113.5", "8.8.8.8"
ROUTER = "192.0.2.1"
SPORT, DPORT = 40000, 443
# The tuple conntrack holds for it: the POST-NAT one, which is exactly
# what the router copies into the error it sends back.
TRACKED = ("tcp", _ip(MASQ), _ip(PEER), SPORT, DPORT)


def _frag_needed(**over):
  """The router's RFC 1191 error about that flow."""
  fields = {
    "src_ip": ROUTER, "dst_ip": MASQ, "type": 3, "code": 4,
    "inner_src_ip": MASQ, "inner_dst_ip": PEER,
    "inner_src_port": SPORT, "inner_dst_port": DPORT,
  }
  fields.update(over)
  args = ", ".join(
    f'{k}="{v}"' if isinstance(v, str) else f"{k}={v}"
    for k, v in fields.items()
  )
  return _pkt(f"icmperr({args})")


class TestBuilder:
  """The `.pkt` builder for an ICMP error — the thing the corpus could
  not express, and therefore the thing that made this untestable."""

  def test_frame_layout_is_header_plus_embedded_datagram(self):
    p = pkt.build_packet(pkt.parse_builder(
      'icmperr(src_ip="192.0.2.1", dst_ip="203.0.113.5")'
    ))
    # 14 eth + 20 IP + 8 ICMP + 20 embedded IP + 8 embedded transport.
    assert len(p.raw) == 70
    assert p.raw[23] == 1  # outer protocol is ICMP
    assert p.raw[34] == 3 and p.raw[35] == 4  # frag-needed by default

  def test_next_hop_mtu_lands_in_the_unused_word(self):
    p = pkt.build_packet(pkt.parse_builder("icmperr(mtu=1400)"))
    assert int.from_bytes(p.raw[40:42], "big") == 1400

  def test_reads_as_an_ordinary_icmp_packet(self):
    # `pkt.proto == icmp` and `pkt.icmp.type == 3` must match it: an
    # error IS an ICMP packet, and that is what an operator writes.
    f = _frag_needed()
    assert f["proto"] == "icmp"
    assert f["icmp_type"] == 3 and f["icmp_code"] == 4
    # ...and it has no ports of its own. Reporting any would let a case
    # assert the first four bytes of an ICMP header as a port pair.
    assert "src_port" not in f and "dst_port" not in f

  def test_embedded_tuple_is_decoded_under_private_names(self):
    f = _frag_needed()
    assert f["_inner_proto"] == "tcp"
    assert f["_inner_src_ip"] == MASQ and f["_inner_dst_ip"] == PEER
    assert f["_inner_src_port"] == SPORT
    assert f["_inner_dst_port"] == DPORT

  def test_embedded_source_defaults_to_the_error_destination(self):
    # An error comes back FROM the peer a packet was sent TO, so the
    # datagram it carries was addressed from the error's destination.
    f = _pkt('icmperr(src_ip="192.0.2.1", dst_ip="198.51.100.9")')
    assert f["_inner_src_ip"] == "198.51.100.9"

  def test_checksums_are_real(self):
    from fwl.runner import _checksum_diag
    p = pkt.build_packet(pkt.parse_builder(
      'icmperr(src_ip="192.0.2.1", dst_ip="203.0.113.5", mtu=1400)'
    ))
    assert _checksum_diag(p.raw) is None

  def test_plain_icmp_builder_also_carries_a_real_checksum(self):
    # It emitted a zero placeholder until ICMP-error NAT existed. A NAT
    # required NOT to touch a checksum is indistinguishable from one
    # that corrupts it unless the frame arrives with a correct one.
    from fwl.runner import _checksum_diag
    p = pkt.build_packet(pkt.parse_builder('icmp(type=8)'))
    assert p.raw[36:38] != b"\x00\x00"
    assert _checksum_diag(p.raw) is None

  def test_embedded_length_is_the_original_datagram_s(self):
    # A router copies the header it could not forward, and that
    # header's total length is the whole reason the error exists.
    p = pkt.build_packet(pkt.parse_builder("icmperr(inner_len=1500)"))
    assert int.from_bytes(p.raw[44:46], "big") == 1500

  def test_unknown_inner_proto_is_rejected(self):
    with pytest.raises(ValueError):
      pkt.build_packet(pkt.parse_builder('icmperr(inner_proto="sctp")'))

  def test_unknown_field_is_rejected(self):
    with pytest.raises(ValueError):
      pkt.parse_builder("icmperr(syn=true)")


class TestTruncationMirror:
  """A frame cut inside the embedded datagram names no flow.

  The emitter's bounds check is one test over the whole of it, so a
  partial embedded header must leave the interpreter with nothing
  rather than with part of a tuple — otherwise the two oracles
  disagree about a frame neither of them is wrong about."""

  @pytest.mark.parametrize("cut", [42, 50, 61, 69])
  def test_short_of_the_full_embedded_datagram_reads_nothing(self, cut):
    p = pkt._build_from_spec("icmperr()", cut)
    for key in pkt._INNER_GATED_KEYS:
      assert key not in p.fields

  def test_the_exact_boundary_reads_everything(self):
    p = pkt._build_from_spec("icmperr()", 70)
    assert p.fields["_inner_src_port"] == 0
    assert "_inner_proto" in p.fields

  def test_ip_options_do_not_hide_the_embedded_datagram(self):
    # ihl > 5 shifts the ICMP header but everything is still readable;
    # ihl < 5 is a header that lies, and nothing behind it parses.
    assert "_inner_proto" in _pkt("icmperr(ihl=6)")
    assert "_inner_proto" not in _pkt("icmperr(ihl=4)")


class TestRelatedClassification:
  def test_an_error_for_a_tracked_flow_is_related(self):
    t = ConntrackTable([TRACKED])
    assert t.state_for(_frag_needed()) == ast.CtState.RELATED

  def test_an_error_for_a_flow_in_the_other_direction_is_related(self):
    # The error may be provoked at either end; the flow is the same.
    t = ConntrackTable([("tcp", _ip(PEER), _ip(MASQ), DPORT, SPORT)])
    assert t.state_for(_frag_needed()) == ast.CtState.RELATED

  def test_an_error_for_an_untracked_flow_is_new(self):
    assert ConntrackTable().state_for(_frag_needed()) == ast.CtState.NEW

  def test_one_port_off_is_not_related(self):
    t = ConntrackTable([TRACKED])
    other = _frag_needed(inner_src_port=SPORT + 1)
    assert t.state_for(other) == ast.CtState.NEW

  def test_a_query_carrying_the_same_bytes_is_not_related(self):
    # An echo request whose payload is a copy of the tracked flow's
    # header — which anyone can send, because that header crossed the
    # wire in the clear. Only the type byte separates it from the
    # error above, and it is what stands between `default drop` and
    # "admitted on request".
    t = ConntrackTable([TRACKED])
    forged = _frag_needed(type=8, code=0)
    assert t.state_for(forged) == ast.CtState.NEW

  @pytest.mark.parametrize("icmp_type", [3, 4, 5, 11, 12])
  def test_every_rfc_792_error_type_carries_a_flow(self, icmp_type):
    t = ConntrackTable([TRACKED])
    err = _frag_needed(type=icmp_type, code=0)
    assert t.state_for(err) == ast.CtState.RELATED

  @pytest.mark.parametrize("icmp_type", [0, 8, 13, 14, 17, 18])
  def test_no_query_type_ever_does(self, icmp_type):
    t = ConntrackTable([TRACKED])
    err = _frag_needed(type=icmp_type, code=0)
    assert t.state_for(err) == ast.CtState.NEW

  def test_an_error_does_not_open_a_flow(self):
    # RELATED is evidence ABOUT a connection, not a connection. An
    # error that created an entry would let anyone open a hole by
    # describing one.
    prog = _analyze(
      H + "allow if conntrack(pkt).state in [established, related]\n"
      "default drop\n"
    )
    t = ConntrackTable([TRACKED])
    before = set(t._fwd)
    interpreter.evaluate_full(prog, _frag_needed(), {}, conntrack=t)
    assert set(t._fwd) == before

  def test_established_alone_does_not_admit_it(self):
    # The operator consequence, and the reason this is a migration and
    # not a silent improvement: every policy written before `related`
    # existed keeps dropping path-MTU errors until its author adds it.
    prog = _analyze(
      H + "allow if conntrack(pkt).state == established\ndefault drop\n"
    )
    got = interpreter.evaluate_full(
      prog, _frag_needed(), {}, conntrack=ConntrackTable([TRACKED])
    )
    assert got.action == interpreter.XdpAction.DROP

  def test_the_related_idiom_admits_it(self):
    prog = _analyze(
      H + "allow if conntrack(pkt).state in [established, related]\n"
      "default drop\n"
    )
    got = interpreter.evaluate_full(
      prog, _frag_needed(), {}, conntrack=ConntrackTable([TRACKED])
    )
    assert got.action == interpreter.XdpAction.PASS


class TestInterpreterTranslation:
  """RFC 5508 § 4.2 on the interpreter oracle."""

  PROG = (H + "masquerade if pkt.src_ip in [10.0.0.0/8]\n"
          "allow if conntrack(pkt).state in [established, related]\n"
          "default drop\n")

  def _nat_with_the_flow_open(self):
    nat = NatState(masq_ip=_ip(MASQ))
    nat.install_egress_reply(
      _pkt(f'tcp(src_ip="{GUEST}", dst_ip="{PEER}", '
           f"src_port={SPORT}, dst_port={DPORT}, syn=true)"),
      _ip(MASQ),
    )
    return nat

  def test_both_headers_are_translated(self):
    got = interpreter.evaluate_full(
      _analyze(self.PROG), _frag_needed(), {},
      conntrack=ConntrackTable([TRACKED]),
      nat=self._nat_with_the_flow_open(),
    )
    op = got.output_packet
    # The outer header, or the error never reaches the guest...
    assert op["dst_ip"] == GUEST
    # ...and the embedded one, or it arrives describing a connection
    # the guest never opened and its own stack discards it.
    assert op["inner_src_ip"] == GUEST
    assert op["inner_src_port"] == SPORT
    # Everything about the far end is left alone.
    assert op["inner_dst_ip"] == PEER
    assert op["inner_dst_port"] == DPORT

  def test_an_error_for_an_unmapped_flow_is_not_translated(self):
    got = interpreter.evaluate_full(
      _analyze(self.PROG), _frag_needed(inner_src_port=SPORT + 1), {},
      conntrack=ConntrackTable([TRACKED]),
      nat=self._nat_with_the_flow_open(),
    )
    assert got.output_packet is None

  def test_the_embedded_tuple_beats_the_outer_one(self):
    # The error's own 5-tuple is (router, masq, 0, 0, icmp), which is
    # the key a ping to that router installs. Which header identifies
    # the flow is not a preference: for an error it is the inner one,
    # or the error goes to whoever last pinged the sender.
    nat = self._nat_with_the_flow_open()
    other_guest = "10.0.0.9"
    nat.install_egress_reply(
      _pkt(f'icmp(src_ip="{other_guest}", dst_ip="{ROUTER}", type=8)'),
      _ip(MASQ),
    )
    got = interpreter.evaluate_full(
      _analyze(self.PROG), _frag_needed(), {},
      conntrack=ConntrackTable([TRACKED]), nat=nat,
    )
    assert got.output_packet["dst_ip"] == GUEST
    assert got.output_packet["inner_src_ip"] == GUEST

  def test_ip_options_are_declined_as_everywhere_else(self):
    # `fwl_find_ipv4` bails on ihl != 5 for every NAT rewrite; the
    # classification walks a variable IHL and still finds the flow, so
    # the frame is admitted and left untranslated.
    got = interpreter.evaluate_full(
      _analyze(self.PROG), _frag_needed(ihl=6), {},
      conntrack=ConntrackTable([TRACKED]),
      nat=self._nat_with_the_flow_open(),
    )
    assert got.action == interpreter.XdpAction.PASS
    assert got.output_packet is None


class TestEmission:
  def test_the_classifier_is_emitted_with_the_conntrack_read(self):
    c = _emit(
      H + "allow if conntrack(pkt).state == established\ndefault drop\n"
    )
    assert "fwl_ct_icmp_related" in c

  def test_a_program_that_reads_no_state_does_not_get_it(self):
    c = _emit(H + "allow if pkt.proto == tcp\ndefault drop\n")
    assert "fwl_ct_icmp_related" not in c

  def test_a_nat_only_program_declares_the_map_but_not_the_classifier(
      self):
    # NAT needs the conntrack map (the post-NAT insert), and nothing
    # references the classifier unless a rule reads a state.
    c = _emit(H + "masquerade if pkt.src_ip in [10.0.0.0/8]\n"
              "default allow\n")
    assert "} conntrack SEC" in c
    assert "fwl_ct_icmp_related" not in c

  def test_the_error_translation_is_emitted_with_nat(self):
    c = _emit(H + "masquerade if pkt.src_ip in [10.0.0.0/8]\n"
              "default allow\n")
    assert "fwl_nat_denat_icmp_error" in c

  def test_it_is_consulted_before_the_outer_tuple(self):
    c = _emit(H + "masquerade if pkt.src_ip in [10.0.0.0/8]\n"
              "default allow\n")
    body = c[c.index("void fwl_nat_denat(struct xdp_md *ctx)"):]
    inner = body.index("fwl_nat_denat_icmp_error")
    outer = body.index("bpf_map_lookup_elem(&fwl_nat, &k)")
    assert inner < outer

  def test_related_encodes_to_2(self):
    c = _emit(
      H + "allow if conntrack(pkt).state == related\ndefault drop\n"
    )
    assert "(ct_state == 2)" in c

  def test_the_error_types_are_the_rfc_792_five(self):
    c = _emit(
      H + "allow if conntrack(pkt).state == related\ndefault drop\n"
    )
    assert ("((t) == 3 || (t) == 4 || (t) == 5 || (t) == 11 || "
            "(t) == 12)") in c

  def test_the_stat_slot_count_matches_the_daemon_s_enum(self):
    # `include/f/types.h` numbers `FwlNatStat` from this header, and a
    # slot added on one side only reads a neighbour's counter.
    c = _emit(H + "masquerade if pkt.src_ip in [10.0.0.0/8]\n"
              "default allow\n")
    assert "#define FWL_NAT_STAT_ICMPERR    5" in c
    assert "#define FWL_NAT_STAT_SLOTS      6" in c
    assert "__uint(max_entries, FWL_NAT_STAT_SLOTS)" in c


class TestChecksumArithmetic:
  """The three-layer rewrite, checked against an independent sum.

  `fwl_csum_apply` is incremental (RFC 1624); these compute the same
  answers by summing the changed header from scratch, which is the
  only comparison that can catch an incremental update that is
  self-consistently wrong."""

  def _apply(self, check, delta):
    total = ((~check) & 0xFFFF) + delta
    while total >> 16:
      total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF

  def _delta32(self, old, new):
    return (
      ((~(old >> 16)) & 0xFFFF) + ((~(old & 0xFFFF)) & 0xFFFF)
      + (new >> 16) + (new & 0xFFFF)
    )

  def test_an_address_change_leaves_the_ip_checksum_correct(self):
    header = bytearray(pkt.build_packet(pkt.parse_builder(
      'icmperr(inner_src_ip="203.0.113.5", inner_dst_ip="8.8.8.8")'
    )).raw[42:62])
    old_ck = int.from_bytes(header[10:12], "big")
    old_a = int.from_bytes(header[12:16], "big")
    new_a = _ip("10.0.0.7")
    new_ck = self._apply(old_ck, self._delta32(old_a, new_a))
    header[10:12] = new_ck.to_bytes(2, "big")
    header[12:16] = new_a.to_bytes(4, "big")
    assert pkt._ipv4_checksum(bytes(header[:10]) + b"\x00\x00"
                              + bytes(header[12:])) == new_ck

  def test_an_address_change_alone_does_not_move_the_icmp_checksum(self):
    # Not a shortcut — a fact about where the sums nest. The ICMP
    # checksum covers the embedded IP header, whose own checksum
    # absorbs an address change exactly, so the two deltas cancel.
    # It is why an address-only corpus case cannot hold the ICMP
    # checksum update to account, and why the arm needs a case in
    # which an embedded PORT moves.
    old_a, new_a = _ip("203.0.113.5"), _ip("10.0.0.7")
    d_addr = self._delta32(old_a, new_a)
    old_ck = 0x1234
    new_ck = self._apply(old_ck, d_addr)
    d_ck = ((~old_ck) & 0xFFFF) + new_ck
    folded = d_addr + d_ck
    while folded >> 16:
      folded = (folded & 0xFFFF) + (folded >> 16)
    assert folded == 0xFFFF  # the ones-complement zero
