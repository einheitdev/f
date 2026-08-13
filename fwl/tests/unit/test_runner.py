"""Unit tests for runner helper functions."""
from fwl import interpreter, runner


class TestCheckCounterChanges:
  def test_matching_counters_pass(self):
    assert runner._check_counter_changes(
      {"a": 1, "b": 0}, {"a": 1}
    ) == ""

  def test_mismatched_counter(self):
    diff = runner._check_counter_changes({"a": 2}, {"a": 1})
    assert "counter 'a'" in diff

  def test_missing_treated_as_zero(self):
    assert runner._check_counter_changes({"a": 0}, {}) == ""

  def test_expected_nonzero_absent(self):
    diff = runner._check_counter_changes({"a": 1}, {})
    assert "counter 'a'" in diff


class TestParseCounterTable:
  def test_parses_table(self):
    c = ("// fwl_counter_table:\n"
         "//   0\tssh\n//   1\thttp\n")
    assert runner._parse_counter_table(c) == {
      "ssh": 0, "http": 1
    }

  def test_empty(self):
    assert runner._parse_counter_table("int main(){}") == {}


class TestSlotDeltasToNamed:
  def test_converts(self):
    assert runner._slot_deltas_to_named(
      {0: 3, 1: 7}, {"ssh": 0, "http": 1}
    ) == {"ssh": 3, "http": 7}


class TestCheckLogEvents:
  def _ev(self, **kw):
    defaults = dict(
      zone="lan", rule_index=0, proto="tcp", src_ip="1.1.1.1",
      dst_ip="2.2.2.2", src_port=12345, dst_port=80,
      syn=False, ack=False,
    )
    defaults.update(kw)
    return interpreter.LogEvent(**defaults)

  def test_matching_pass(self):
    assert runner._check_log_events(
      [{"rule_index": 0}], [self._ev()]
    ) == ""

  def test_zone_matches(self):
    assert runner._check_log_events(
      [{"zone": "lan", "rule_index": 0}], [self._ev()]
    ) == ""

  def test_zone_mismatch(self):
    # The defect this field exists for: same rule index, other zone.
    diff = runner._check_log_events(
      [{"zone": "wan", "rule_index": 0}], [self._ev(zone="lan")]
    )
    assert "zone" in diff

  def test_count_mismatch(self):
    diff = runner._check_log_events([{"rule_index": 0}], [])
    assert "count mismatch" in diff

  def test_field_mismatch(self):
    diff = runner._check_log_events(
      [{"dst_port": 443}], [self._ev(dst_port=80)]
    )
    assert "dst_port" in diff

  def test_empty_expected_passes(self):
    assert runner._check_log_events([], [self._ev()]) == ""


class TestSequenceOraclesHonourIngressZone:
  """A `sequence:` case must run against the zone it names.

  Both single-packet oracles resolved `ingress_zone` through
  `_zone_program` and neither sequence oracle did, so a multi-zone
  sequence silently ran against whichever @xdp block came first. Both
  oracles ignored it identically, so the differential comparison
  agreed perfectly while measuring a program the case never named —
  the failure mode this harness exists to prevent, one level up from
  the case that finds it.

  Asserted on the shared selector rather than by running BPF, so it
  holds unprivileged too.
  """

  SOURCE = (
    "zone lan = [lan0]\n"
    "zone wan = [wan0]\n"
    "\n"
    "@xdp(lan)\n"
    "drop if pkt.proto == udp\n"
    "default allow\n"
    "\n"
    "@xdp(wan)\n"
    "allow if pkt.proto == udp\n"
    "default drop\n"
  )

  def _program(self):
    from fwl import analyzer, parser
    return analyzer.analyze(parser.parse(self.SOURCE))

  def test_selector_picks_the_named_block(self):
    picked = runner._zone_program(self._program(), "wan")
    assert [zp.zone_name for zp in picked.programs] == ["wan"]

  def test_selector_defaults_to_the_whole_program(self):
    whole = runner._zone_program(self._program(), None)
    assert [zp.zone_name for zp in whole.programs] == ["lan", "wan"]

  def test_both_sequence_oracles_call_the_selector(self):
    """The regression guard: the call sites, not just the selector.

    A source-level check because the defect was an ABSENT call, and
    nothing about the oracles' output distinguished it — they agreed
    with each other on the wrong program.
    """
    import inspect
    for fn in (runner._seq_interpreter_oracle, runner._seq_bpf_oracle):
      src = inspect.getsource(fn)
      assert "_zone_program(program, case.ingress_zone)" in src, (
        f"{fn.__name__} does not resolve ingress_zone; a multi-zone "
        "sequence case will run against the wrong @xdp block"
      )

  def test_an_unknown_zone_is_named_not_ignored(self):
    import pytest
    with pytest.raises(ValueError, match="matches no @xdp block"):
      runner._zone_program(self._program(), "dmz")
