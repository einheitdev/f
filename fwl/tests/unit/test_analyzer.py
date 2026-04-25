"""Unit tests for the semantic analyzer (protocol guards + validators)."""
import pytest

from fwl import analyzer, parser
from fwl.errors import FwlException


def analyze(text):
  return analyzer.analyze(parser.parse(text))


class TestProtocolGuards:
  def test_proto_field_no_guard_required(self):
    analyze("@xdp(eth0)\ndrop if pkt.proto == tcp\n")

  def test_ip_fields_no_guard_required(self):
    analyze("@xdp(eth0)\ndrop if pkt.src_ip in 10.0.0.0/8\n")

  def test_port_with_tcp_guard_passes(self):
    analyze(
      "@xdp(eth0)\ndrop if pkt.proto == tcp and pkt.dst_port == 22\n"
    )

  def test_port_with_udp_guard_passes(self):
    analyze(
      "@xdp(eth0)\ndrop if pkt.proto == udp and pkt.dst_port == 53\n"
    )

  def test_port_without_guard_fails(self):
    with pytest.raises(FwlException) as exc:
      analyze("@xdp(eth0)\ndrop if pkt.dst_port == 22\n")
    assert "pkt.dst_port" in str(exc.value)

  def test_tcp_flag_with_tcp_guard_passes(self):
    analyze("@xdp(eth0)\ndrop if pkt.proto == tcp and pkt.tcp.syn\n")

  def test_tcp_flag_with_udp_guard_fails(self):
    with pytest.raises(FwlException):
      analyze("@xdp(eth0)\ndrop if pkt.proto == udp and pkt.tcp.syn\n")

  def test_tcp_flag_no_guard_fails(self):
    with pytest.raises(FwlException):
      analyze("@xdp(eth0)\ndrop if pkt.tcp.syn\n")

  def test_or_branch_unions_guards(self):
    """(tcp or udp) and dst_port should be allowed."""
    analyze(
      "@xdp(eth0)\n"
      "drop if (pkt.proto == tcp or pkt.proto == udp) "
      "and pkt.dst_port == 53\n"
    )

  def test_or_branch_with_inadequate_guard_fails(self):
    """tcp.syn requires tcp specifically; (tcp or udp) doesn't suffice."""
    with pytest.raises(FwlException):
      analyze(
        "@xdp(eth0)\n"
        "drop if (pkt.proto == tcp or pkt.proto == udp) and pkt.tcp.syn\n"
      )

  def test_not_does_not_propagate_guard(self):
    """`not (proto == tcp)` does NOT establish a tcp guard."""
    with pytest.raises(FwlException):
      analyze(
        "@xdp(eth0)\n"
        "drop if not (pkt.proto == udp) and pkt.tcp.syn\n"
      )


class TestRateLimit:
  def test_threshold_positive_passes(self):
    analyze(
      "@xdp(eth0)\ndrop limited by rate_limit(1, per=src_ip)\n"
    )

  def test_threshold_zero_fails(self):
    with pytest.raises(FwlException) as exc:
      analyze(
        "@xdp(eth0)\ndrop limited by rate_limit(0, per=src_ip)\n"
      )
    assert "rate_limit threshold" in str(exc.value)


class TestCounterLimit:
  def test_under_limit_passes(self):
    analyze(
      "@xdp(eth0)\n"
      "count a if pkt.proto == tcp\n"
      "count b if pkt.proto == udp\n"
    )

  def test_repeated_name_counts_once(self):
    """Same counter name across rules counts as one slot."""
    analyze(
      "@xdp(eth0)\n"
      "count seen if pkt.proto == tcp\n"
      "count seen if pkt.proto == udp\n"
    )
