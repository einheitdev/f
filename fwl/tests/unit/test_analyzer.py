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


class TestComparisonTypes:
  """Spec error #3: type mismatch in comparison."""

  def test_ip_field_eq_int_rejected(self):
    with pytest.raises(FwlException) as exc:
      analyze("@xdp(eth0)\ndrop if pkt.src_ip == 80\n")
    assert "ipv4" in str(exc.value).lower()

  def test_port_field_eq_proto_rejected(self):
    with pytest.raises(FwlException):
      analyze(
        "@xdp(eth0)\n"
        "drop if pkt.proto == tcp and pkt.dst_port == tcp\n"
      )

  def test_ip_field_in_int_list_rejected(self):
    with pytest.raises(FwlException):
      analyze("@xdp(eth0)\ndrop if pkt.src_ip in [80, 443]\n")

  def test_port_in_cidr_rejected(self):
    with pytest.raises(FwlException):
      analyze(
        "@xdp(eth0)\n"
        "drop if pkt.proto == tcp and pkt.dst_port in 10.0.0.0/8\n"
      )

  def test_compatible_types_pass(self):
    analyze("@xdp(eth0)\ndrop if pkt.src_ip == 1.2.3.4\n")
    analyze(
      "@xdp(eth0)\ndrop if pkt.proto == tcp and pkt.dst_port == 80\n"
    )
    analyze("@xdp(eth0)\ndrop if pkt.src_ip in 10.0.0.0/8\n")


class TestPortLiteralRange:
  """Spec error #7: port literal outside 0..65535."""

  def test_port_70000_rejected(self):
    with pytest.raises(FwlException) as exc:
      analyze(
        "@xdp(eth0)\n"
        "drop if pkt.proto == tcp and pkt.dst_port == 70000\n"
      )
    assert "0..65535" in str(exc.value)

  def test_port_in_list_with_oversize_rejected(self):
    with pytest.raises(FwlException):
      analyze(
        "@xdp(eth0)\n"
        "drop if pkt.proto == tcp and pkt.dst_port in [80, 70000]\n"
      )

  def test_port_in_range_with_oversize_rejected(self):
    with pytest.raises(FwlException):
      analyze(
        "@xdp(eth0)\n"
        "drop if pkt.proto == tcp and pkt.dst_port in 1024..70000\n"
      )

  def test_port_boundaries_pass(self):
    analyze(
      "@xdp(eth0)\n"
      "drop if pkt.proto == tcp and pkt.dst_port == 0\n"
    )
    analyze(
      "@xdp(eth0)\n"
      "drop if pkt.proto == tcp and pkt.dst_port == 65535\n"
    )


class TestPortRangeOrder:
  """Spec error #8: range with lo > hi."""

  def test_lo_greater_than_hi_rejected(self):
    with pytest.raises(FwlException) as exc:
      analyze(
        "@xdp(eth0)\n"
        "drop if pkt.proto == tcp and pkt.dst_port in 1000..500\n"
      )
    assert "exceeds" in str(exc.value)

  def test_lo_equals_hi_passes(self):
    analyze(
      "@xdp(eth0)\n"
      "drop if pkt.proto == tcp and pkt.dst_port in 80..80\n"
    )


class TestRateLimitThresholdRange:
  """Finding 1: rate_limit threshold must fit in u32."""

  def test_threshold_above_u32_rejected(self):
    with pytest.raises(FwlException) as exc:
      analyze(
        "@xdp(eth0)\n"
        "drop limited by rate_limit(99999999999999999999999999999999, "
        "per=src_ip)\n"
      )
    assert "u32" in str(exc.value)

  def test_threshold_at_u32_max_passes(self):
    analyze(
      "@xdp(eth0)\n"
      "drop limited by rate_limit(4294967295, per=src_ip)\n"
    )

  def test_threshold_at_u32_max_plus_one_rejected(self):
    with pytest.raises(FwlException):
      analyze(
        "@xdp(eth0)\n"
        "drop limited by rate_limit(4294967296, per=src_ip)\n"
      )


class TestCidrPrefixRange:
  """Spec error #6: CIDR prefix length must be 0..32."""

  def test_prefix_33_rejected(self):
    with pytest.raises(FwlException) as exc:
      analyze("@xdp(eth0)\ndrop if pkt.src_ip in 10.0.0.0/33\n")
    assert "0..32" in str(exc.value)

  def test_prefix_zero_passes(self):
    analyze("@xdp(eth0)\ndrop if pkt.src_ip in 0.0.0.0/0\n")

  def test_prefix_32_passes(self):
    analyze("@xdp(eth0)\ndrop if pkt.src_ip in 1.2.3.4/32\n")


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
