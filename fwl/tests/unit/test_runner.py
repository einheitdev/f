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
      rule_index=0, proto="tcp", src_ip="1.1.1.1",
      dst_ip="2.2.2.2", src_port=12345, dst_port=80,
      syn=False, ack=False,
    )
    defaults.update(kw)
    return interpreter.LogEvent(**defaults)

  def test_matching_pass(self):
    assert runner._check_log_events(
      [{"rule_index": 0}], [self._ev()]
    ) == ""

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
