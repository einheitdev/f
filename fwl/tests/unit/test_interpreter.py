"""Unit tests for the AST interpreter."""
from fwl import analyzer, interpreter, parser


def evaluate(source, packet, state=None):
  program = analyzer.analyze(parser.parse(source))
  return interpreter.evaluate(program, packet, state)


PASS = interpreter.XdpAction.PASS
DROP = interpreter.XdpAction.DROP


class TestImplicitDefault:
  def test_no_rules_no_default_returns_pass(self):
    # `default drop` would fire; no default = implicit allow.
    program = analyzer.analyze(parser.parse(
      "@xdp(eth0)\ndrop if pkt.proto == tcp\n"
    ))
    assert interpreter.evaluate(program, {"proto": "udp"}) == PASS

  def test_explicit_default_drop_overrides_implicit_allow(self):
    program = analyzer.analyze(parser.parse(
      "@xdp(eth0)\nallow if pkt.proto == tcp\ndefault drop\n"
    ))
    assert interpreter.evaluate(program, {"proto": "udp"}) == DROP


class TestProtoMatching:
  def test_tcp_match(self):
    src = "@xdp(eth0)\ndrop if pkt.proto == tcp\n"
    assert evaluate(src, {"proto": "tcp"}) == DROP
    assert evaluate(src, {"proto": "udp"}) == PASS


class TestComposition:
  def test_and_short_circuit(self):
    src = (
      "@xdp(eth0)\n"
      "drop if pkt.proto == tcp and pkt.dst_port == 22\n"
    )
    assert evaluate(src, {"proto": "tcp", "dst_port": 22}) == DROP
    assert evaluate(src, {"proto": "tcp", "dst_port": 80}) == PASS
    # No proto -> AND fails immediately, short-circuits.
    assert evaluate(src, {"proto": "udp", "dst_port": 22}) == PASS

  def test_or_either_branch(self):
    src = (
      "@xdp(eth0)\n"
      "drop if pkt.proto == tcp or pkt.proto == udp\n"
    )
    assert evaluate(src, {"proto": "tcp"}) == DROP
    assert evaluate(src, {"proto": "udp"}) == DROP
    assert evaluate(src, {"proto": "icmp"}) == PASS

  def test_not(self):
    src = "@xdp(eth0)\ndrop if pkt.proto != tcp\n"
    assert evaluate(src, {"proto": "udp"}) == DROP
    assert evaluate(src, {"proto": "tcp"}) == PASS


class TestCidrMatching:
  def test_cidr_8(self):
    src = (
      "@xdp(eth0)\ndrop if pkt.src_ip in 10.0.0.0/8\ndefault allow\n"
    )
    assert evaluate(src, {"src_ip": "10.5.6.7"}) == DROP
    assert evaluate(src, {"src_ip": "11.0.0.0"}) == PASS

  def test_cidr_32_single_host(self):
    src = (
      "@xdp(eth0)\ndrop if pkt.src_ip in 1.2.3.4/32\ndefault allow\n"
    )
    assert evaluate(src, {"src_ip": "1.2.3.4"}) == DROP
    assert evaluate(src, {"src_ip": "1.2.3.5"}) == PASS

  def test_cidr_zero_matches_all(self):
    src = (
      "@xdp(eth0)\ndrop if pkt.src_ip in 0.0.0.0/0\ndefault allow\n"
    )
    assert evaluate(src, {"src_ip": "192.168.1.1"}) == DROP


class TestPortRangeAndList:
  def test_port_range_inclusive(self):
    src = (
      "@xdp(eth0)\n"
      "drop if pkt.proto == tcp and pkt.dst_port in 5000..6000\n"
      "default allow\n"
    )
    pkt = lambda p: {"proto": "tcp", "dst_port": p}
    assert evaluate(src, pkt(5000)) == DROP
    assert evaluate(src, pkt(6000)) == DROP
    assert evaluate(src, pkt(4999)) == PASS
    assert evaluate(src, pkt(6001)) == PASS

  def test_port_list(self):
    src = (
      "@xdp(eth0)\n"
      "drop if pkt.proto == tcp and pkt.dst_port in [22, 80, 443]\n"
      "default allow\n"
    )
    pkt = lambda p: {"proto": "tcp", "dst_port": p}
    assert evaluate(src, pkt(22)) == DROP
    assert evaluate(src, pkt(80)) == DROP
    assert evaluate(src, pkt(81)) == PASS


class TestNonTerminalActions:
  def test_log_continues_to_next_rule(self):
    src = (
      "@xdp(eth0)\n"
      "log if pkt.proto == tcp\n"
      "drop if pkt.proto == tcp\n"
      "default allow\n"
    )
    assert evaluate(src, {"proto": "tcp"}) == DROP

  def test_count_continues_to_next_rule(self):
    src = (
      "@xdp(eth0)\n"
      "count seen if pkt.proto == tcp\n"
      "drop if pkt.proto == tcp\n"
      "default allow\n"
    )
    assert evaluate(src, {"proto": "tcp"}) == DROP


class TestRateLimit:
  def test_no_state_means_count_zero(self):
    src = (
      "@xdp(eth0)\n"
      "drop if pkt.proto == tcp limited by rate_limit(3, per=src_ip)\n"
      "default allow\n"
    )
    assert evaluate(src, {"proto": "tcp", "src_ip": "1.2.3.4"}) == DROP

  def test_at_threshold_blocks(self):
    src = (
      "@xdp(eth0)\n"
      "drop if pkt.proto == tcp limited by rate_limit(3, per=src_ip)\n"
      "default allow\n"
    )
    state = {0: {"1.2.3.4": 3}}
    assert evaluate(
      src, {"proto": "tcp", "src_ip": "1.2.3.4"}, state
    ) == PASS

  def test_under_threshold_fires(self):
    src = (
      "@xdp(eth0)\n"
      "drop if pkt.proto == tcp limited by rate_limit(3, per=src_ip)\n"
      "default allow\n"
    )
    state = {0: {"1.2.3.4": 2}}
    assert evaluate(
      src, {"proto": "tcp", "src_ip": "1.2.3.4"}, state
    ) == DROP

  def test_independent_buckets(self):
    src = (
      "@xdp(eth0)\n"
      "drop if pkt.proto == tcp limited by rate_limit(3, per=src_ip)\n"
      "default allow\n"
    )
    state = {0: {"1.2.3.4": 100}}
    # Different bucket key, fresh count.
    assert evaluate(
      src, {"proto": "tcp", "src_ip": "5.6.7.8"}, state
    ) == DROP
