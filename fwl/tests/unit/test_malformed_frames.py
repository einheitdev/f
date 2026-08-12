"""Frames the wire can deliver and the builder could not, until now.

Every capability here was added because `hone branch-coverage` found a
guard in the emitted program that 1127 corpus cases had never
falsified, and the reason was always the same: the builder language
could not construct the frame that falsifies it.

The properties pinned here are the MIRRORS — the places where the
interpreter has to reproduce a decision the emitted C makes. A mirror
that drifts does not fail loudly; it produces a divergence that reads
as a compiler bug, which is the most expensive kind of false positive
this harness can generate.
"""
import pytest

from fwl import analyzer, interpreter, parser, pkt


def _build(builder: str, truncate_to=None):
  """Decoded fields as the .pkt loader would hand them to an oracle."""
  packet = pkt.build_packet(pkt.parse_builder(builder))
  if truncate_to is None:
    return packet
  return pkt.Packet(
    raw=packet.raw[:truncate_to],
    fields=pkt._strip_truncated_fields(packet.fields, truncate_to),
  )


def _evaluate(source: str, packet):
  program = analyzer.analyze(parser.parse(source))
  return interpreter.evaluate_full(program, packet.fields, {})


class TestIhlBuilder:
  """`ihl=` on the v4 builders: options, and a lying header length."""

  def test_default_is_five(self):
    raw = _build('tcp(dst_port=80)').raw
    assert raw[14] == 0x45

  def test_options_are_inserted_and_l4_follows_them(self):
    raw = _build('tcp(dst_port=80, ihl=7)').raw
    assert raw[14] == 0x47
    # 8 bytes of options between the fixed header and TCP.
    assert raw[34:42] == b"\x01" * 8
    # TCP source port lands after the options, not at offset 34.
    assert int.from_bytes(raw[42:44], "big") == 12345

  def test_total_length_covers_the_options(self):
    raw = _build('tcp(dst_port=80, ihl=7)').raw
    assert int.from_bytes(raw[16:18], "big") == 20 + 8 + 20
    assert len(raw) == 14 + 20 + 8 + 20

  def test_header_checksum_covers_the_options(self):
    """RFC 791 checksums the whole header, options included.

    The runner's post-rewrite diagnostic reads exactly ihl*4 bytes, so
    a checksum computed over the fixed header alone would report every
    options frame as corrupt after any NAT rewrite.
    """
    from fwl import runner
    raw = _build('udp(dst_port=53, ihl=8)').raw
    assert runner._ones_sum(raw[14:14 + 32]) == 0xFFFF

  def test_ihl_below_five_strips_the_l4_fields(self):
    """The emitted parser gates L4 on `ip_hlen >= sizeof(struct iphdr)`.

    Below that the header-length guard is false, no L4 parse happens,
    and the decoded dict must lose the same fields or the interpreter
    reads a port the compiled program never looked at.
    """
    fields = _build('tcp(dst_port=80, ihl=4)').fields
    assert "dst_port" not in fields
    assert "syn" not in fields
    # v4_ok is still set: the IPv4 header itself is present.
    assert fields["src_ip"] == "1.1.1.1"
    assert fields["proto"] == "tcp"

  def test_ihl_above_five_keeps_the_l4_fields(self):
    fields = _build('tcp(dst_port=80, ihl=6)').fields
    assert fields["dst_port"] == 80

  def test_ihl_is_not_an_fwl_field(self):
    """It shapes the frame; it is not something a rule can read."""
    fields = _build('tcp(dst_port=80, ihl=6)').fields
    assert "ihl" not in fields
    assert fields["_ihl"] == 6

  @pytest.mark.parametrize("bad", [-1, 16, "5", True])
  def test_out_of_range_is_rejected(self, bad):
    with pytest.raises(ValueError):
      pkt.build_packet({"proto": "tcp", "ihl": bad})

  def test_v6_builders_do_not_accept_it(self):
    with pytest.raises(ValueError):
      pkt.parse_builder('tcp6(dst_port=80, ihl=6)')


class TestZeroChecksumUdp:
  """RFC 768 lets a sender decline the UDP checksum by sending zero."""

  def test_default_udp_carries_a_checksum(self):
    raw = _build('udp(dst_port=53)').raw
    assert raw[40:42] != b"\x00\x00"

  def test_flag_produces_a_zero_checksum(self):
    raw = _build('udp(dst_port=53, udp_csum_zero=true)').raw
    assert raw[40:42] == b"\x00\x00"

  def test_flag_is_not_an_fwl_field(self):
    fields = _build('udp(dst_port=53, udp_csum_zero=true)').fields
    assert "udp_csum_zero" not in fields

  def test_tcp_does_not_accept_it(self):
    with pytest.raises(ValueError):
      pkt.parse_builder('tcp(dst_port=80, udp_csum_zero=true)')


class TestNonIpEarlyOut:
  """`if (!v4_ok && !v6_ok) return XDP_PASS;` — before the default.

  Introduced in v0.2 so an explicit `default drop` would not silently
  drop ARP. The interpreter did not model it, so every `default drop`
  policy disagreed with the compiled program on any frame whose L3
  header did not parse. Measured root on deb-02 before the fix:
  interpreter DROP, BPF PASS on a 20-byte frame.
  """

  DROP_DEFAULT = (
    "@xdp(eth0)\nallow if pkt.proto == tcp\ndefault drop\n"
  )

  def test_truncated_ipv4_frame_passes_a_drop_default(self):
    result = _evaluate(
      self.DROP_DEFAULT, _build('tcp(dst_port=80)', truncate_to=20)
    )
    assert result.action is interpreter.XdpAction.PASS

  def test_truncated_ipv6_frame_passes_a_drop_default(self):
    src = "2001:db8::1"
    source = (
      f"@xdp(eth0)\nallow if pkt.src_ip6 in {src}/128\ndefault drop\n"
    )
    result = _evaluate(
      source, _build(f'tcp6(src_ip="{src}", dst_port=80)',
                     truncate_to=40)
    )
    assert result.action is interpreter.XdpAction.PASS

  def test_whole_frame_still_reaches_the_default(self):
    """The early-out must not swallow parseable frames."""
    result = _evaluate(
      self.DROP_DEFAULT, _build('udp(dst_port=53)')
    )
    assert result.action is interpreter.XdpAction.DROP

  def test_a_program_reading_no_field_has_no_early_out(self):
    """No prelude is emitted at all, so the default really applies."""
    result = _evaluate(
      "@xdp(eth0)\ndefault drop\n",
      _build('tcp(dst_port=80)', truncate_to=20),
    )
    assert result.action is interpreter.XdpAction.DROP

  def test_a_vlan_rule_still_sees_a_tagged_non_ip_frame(self):
    """`vlan_ok` joins the gate when the program reads vlan fields."""
    source = (
      "@xdp(eth0)\ndrop if pkt.vlan_id == 10\ndefault allow\n"
    )
    # Double-tagged: the inner tag hides L3, so only the outer VLAN
    # fields decode — v4_ok and v6_ok are both 0.
    packet = _build('tcp(vlan_id=10, inner_vlan_id=20, dst_port=80)')
    assert "proto" not in packet.fields
    result = _evaluate(source, packet)
    assert result.action is interpreter.XdpAction.DROP

  def test_ihl_below_five_is_not_an_early_out(self):
    """v4_ok IS set — only the L4 parse is skipped."""
    result = _evaluate(
      "@xdp(eth0)\nallow if pkt.proto == tcp\ndefault drop\n",
      _build('tcp(dst_port=80, ihl=4)'),
    )
    assert result.action is interpreter.XdpAction.PASS


class TestNatDeclinesMalformedFrames:
  """`fwl_find_ipv4` bails; the interpreter's NAT model must too."""

  SNAT = "@xdp(lan)\nsnat to 203.0.113.1 if pkt.proto == tcp\nallow\n"

  def test_ip_options_are_not_translated(self):
    """`ip->ihl != 5` — an options packet crosses untranslated."""
    result = _evaluate(self.SNAT, _build(
      'tcp(src_ip="10.0.0.5", dst_ip="8.8.8.8", dst_port=80, ihl=6)'
    ))
    assert result.output_packet is None

  def test_a_plain_frame_is_translated(self):
    result = _evaluate(self.SNAT, _build(
      'tcp(src_ip="10.0.0.5", dst_ip="8.8.8.8", dst_port=80)'
    ))
    assert result.output_packet["src_ip"] == "203.0.113.1"

  def _snat_run(self, target, src):
    source = (
      f"@xdp(lan)\nsnat to {target} if pkt.proto == tcp\nallow\n"
    )
    nat = interpreter.NatState()
    program = analyzer.analyze(parser.parse(source))
    packet = _build(
      f'tcp(src_ip="{src}", dst_ip="8.8.8.8", dst_port=80)'
    )
    result = interpreter.evaluate_full(
      program, packet.fields, {}, nat=nat
    )
    return result, nat

  def test_snat_to_the_same_address_installs_no_reply_mapping(self):
    """`old_saddr == new_saddr` returns BEFORE the map update.

    The frame is unchanged either way, so the rewrite is not the
    observable — the absence of return-path state is, and it only
    shows up on a later packet. That is why the interpreter had to
    learn this even though no single-packet case can see it.
    """
    result, nat = self._snat_run("10.0.0.5", "10.0.0.5")
    assert result.output_packet["src_ip"] == "10.0.0.5"
    assert not nat._reply

  def test_snat_to_a_different_address_does_install_one(self):
    """The control: same policy shape, a target that differs."""
    result, nat = self._snat_run("203.0.113.1", "10.0.0.5")
    assert result.output_packet["src_ip"] == "203.0.113.1"
    assert nat._reply


class TestRateLimitMapCapacity:
  """A full bucket map cannot take a new key: -E2BIG, and a counter."""

  SOURCE = (
    "@xdp(eth0)\ndrop if pkt.proto == tcp\n"
    "     limited by rate_limit(1, per=src_port)\ndefault allow\n"
  )

  def _run(self, seeded_keys, probe_port):
    program = analyzer.analyze(parser.parse(self.SOURCE))
    state = {0: {port: 0 for port in range(1, seeded_keys + 1)}}
    packet = pkt.build_packet(pkt.parse_builder(
      f'tcp(src_port={probe_port}, dst_port=80)'
    ))
    return interpreter.evaluate_full(program, packet.fields, state)

  def test_full_map_and_a_new_key_ticks_the_overflow_counter(self):
    result = self._run(interpreter.RATE_LIMIT_MAP_MAX_ENTRIES, 9000)
    assert result.counter_changes[
      interpreter.RATE_LIMIT_OVERFLOW_COUNTER] == 1

  def test_one_slot_free_does_not_overflow(self):
    result = self._run(
      interpreter.RATE_LIMIT_MAP_MAX_ENTRIES - 1, 9000
    )
    assert interpreter.RATE_LIMIT_OVERFLOW_COUNTER not in \
      result.counter_changes

  def test_a_resident_key_does_not_overflow(self):
    """An overwrite is not an insert, however full the map is."""
    result = self._run(interpreter.RATE_LIMIT_MAP_MAX_ENTRIES, 1)
    assert interpreter.RATE_LIMIT_OVERFLOW_COUNTER not in \
      result.counter_changes

  def test_the_gate_never_fires_for_an_overflowed_key(self):
    """The security property, stated as a test.

    The insert fails, so `cur` stays 0 for that key forever: rate
    limiting silently stops working for every key past capacity, and
    __rate_limit_overflow is the only thing that says so.
    """
    program = analyzer.analyze(parser.parse(self.SOURCE))
    state = {0: {port: 0 for port in
                 range(1, interpreter.RATE_LIMIT_MAP_MAX_ENTRIES + 1)}}
    packet = pkt.build_packet(
      pkt.parse_builder('tcp(src_port=9000, dst_port=80)')
    )
    for _ in range(5):
      result = interpreter.evaluate_full(program, packet.fields, state)
      assert result.action is interpreter.XdpAction.PASS

  def test_the_gate_does_fire_when_the_map_has_room(self):
    """The control: same policy, same packets, a map that is not full."""
    program = analyzer.analyze(parser.parse(self.SOURCE))
    state = {}
    packet = pkt.build_packet(
      pkt.parse_builder('tcp(src_port=9000, dst_port=80)')
    )
    actions = [
      interpreter.evaluate_full(program, packet.fields, state).action
      for _ in range(3)
    ]
    assert actions[0] is interpreter.XdpAction.PASS
    assert actions[1] is interpreter.XdpAction.DROP

  def test_capacity_matches_the_emitter(self):
    """A mirror of a literal in another module, pinned to it."""
    from fwl import emitter
    program = analyzer.analyze(parser.parse(self.SOURCE))
    assert (
      f"__uint(max_entries, {interpreter.RATE_LIMIT_MAP_MAX_ENTRIES});"
      in emitter._emit_rl_maps(program)
    )


class TestSequenceStepAssertionsAreRead:
  """A sequence step's `counter_changes` used to be a silent no-op.

  The schema accepted it (`pkt._SEQUENCE_STEP_KEYS` -> `_EXPECTED_KEYS`)
  and even validated the counter NAME against the policy, and neither
  sequence oracle read the value. This is the same defect
  `expected.output_packet` had, one field over: a case could claim to
  verify a rate-limited counter and verify only the action.
  """

  SOURCE = (
    "@xdp(eth0)\ncount hits if pkt.proto == tcp "
    "limited by rate_limit(1, per=src_ip)\ndefault allow\n"
  )

  def _case(self, deltas, tmp_path):
    steps = "".join(
      "  - name: \"packet\"\n"
      "    builder: tcp(src_ip=\"10.0.0.7\", dst_port=80, syn=true)\n"
      "    expected:\n      bpf_action: allow\n"
      "      counter_changes:\n"
      f"        hits: {d}\n"
      for d in deltas
    )
    path = tmp_path / "seq.pkt"
    path.write_text(
      'name: "seq"\nsource_fw: |\n'
      + "".join(f"  {ln}\n" for ln in self.SOURCE.splitlines())
      + "sequence:\n" + steps,
      encoding="utf-8",
    )
    return pkt.load(path)

  def test_correct_deltas_pass(self, tmp_path):
    from fwl import runner
    case = self._case([0, 1, 1], tmp_path)
    assert runner._seq_interpreter_oracle(case).status == "pass"

  def test_wrong_delta_fails(self, tmp_path):
    from fwl import runner
    case = self._case([0, 0, 0], tmp_path)
    result = runner._seq_interpreter_oracle(case)
    assert result.status == "fail"
    assert "counter_changes" in result.detail

  def test_deltas_are_per_step_not_cumulative(self, tmp_path):
    """Three packets over threshold 1 fire once EACH, not 1/2/3.

    `bpf_runner._read_counter_totals` reads the map's absolute value,
    so the sequence path has to subtract the previous reading. It did
    not, and no case noticed because no sequence step's counter
    assertion was ever read.
    """
    from fwl import runner
    case = self._case([0, 1, 2], tmp_path)
    assert runner._seq_interpreter_oracle(case).status == "fail"


class TestRateLimitOverflowIsAssertable:
  """The reserved counter is not spelled by any `count` rule."""

  def test_pkt_accepts_the_reserved_counter(self, tmp_path):
    path = tmp_path / "ovf.pkt"
    path.write_text(
      'name: "ovf"\nsource_fw: |\n'
      "  @xdp(eth0)\n  drop if pkt.proto == tcp\n"
      "       limited by rate_limit(1, per=src_port)\n"
      "  default allow\n"
      "test_packet:\n  builder: tcp(src_port=9000, dst_port=80)\n"
      "expected:\n  compiles: true\n  bpf_action: allow\n"
      "  counter_changes:\n    __rate_limit_overflow: 0\n",
      encoding="utf-8",
    )
    case = pkt.load(path)
    assert case.expected["counter_changes"] == {
      "__rate_limit_overflow": 0
    }

  def test_a_program_without_rate_limit_still_rejects_it(self, tmp_path):
    """Reserved does not mean unchecked: the slot only exists when the
    emitter allocates it, and asserting a counter the program has no
    slot for would compare against a constant zero forever."""
    path = tmp_path / "no_rl.pkt"
    path.write_text(
      'name: "no rl"\nsource_fw: |\n'
      "  @xdp(eth0)\n  drop if pkt.proto == tcp\n  default allow\n"
      "test_packet:\n  builder: tcp(dst_port=80)\n"
      "expected:\n  compiles: true\n  bpf_action: drop\n"
      "  counter_changes:\n    __rate_limit_overflow: 0\n",
      encoding="utf-8",
    )
    with pytest.raises(ValueError, match="not declared"):
      pkt.load(path)


class TestCompileTempDirsAreBounded:
  """One long run used to leave 84,000 directories behind.

  They filled a 2 GB /tmp and killed a corpus run mid-measurement,
  which is worse than a slow run: a measurement that dies halfway
  through reports a partial number that looks like a whole one.
  """

  def test_a_tracked_dir_is_reclaimed_once_the_bound_is_passed(
    self, tmp_path, monkeypatch
  ):
    from fwl import bpf_runner
    monkeypatch.setattr(bpf_runner, "_TEMP_WORK_DIR_KEEP", 3)
    monkeypatch.setattr(bpf_runner, "_temp_work_dirs", [])
    made = []
    for i in range(6):
      path = tmp_path / f"d{i}"
      path.mkdir()
      made.append(path)
      bpf_runner._track_temp_work_dir(path)
    assert [p.exists() for p in made] == [
      False, False, False, True, True, True
    ]

  def test_an_explicit_work_dir_is_never_tracked(self, tmp_path):
    """`fwl compile --bundle-dir` needs its objects to survive."""
    import pytest as _pytest
    from fwl import bpf_runner
    try:
      bpf_runner.compile_c("int main(void) { return 0; }\n",
                           work_dir=tmp_path / "bundle")
    except bpf_runner.BpfUnavailable:
      _pytest.skip("clang not installed")
    except Exception:
      pass  # a compile failure is fine; tracking is what is asserted
    assert (tmp_path / "bundle") not in bpf_runner._temp_work_dirs
