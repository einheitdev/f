"""The shipped examples are policy we ship, so they are tested.

`fwl/examples/*.fw` is what an operator copies. `storm_shield.fw` in
particular is deployed on the rig by `tests/system/hw/l2_06`, and its
header claims a testnet gateway that hides behind the wan address.

Until this file existed the examples were only ever checked for
"compiles". That is exactly the assertion that missed A3: the lan zone
did `masquerade` then `redirect to wan` unconditionally, which compiles
perfectly and means that a packet addressed to the *appliance* — a DHCP
DISCOVER from a client that has no address yet, so it is addressed to
255.255.255.255 — was source-NATed to the gateway's own wan address and
broadcast onto the corporate network. It arrived on the far side as
`10.99.82.1.68 > 255.255.255.255.67`, and the box's own dnsmasq, bound
and contained correctly, never saw the packet.

So every test here runs a shipped example through the interpreter with
a packet that a real segment produces, and asserts the verdict.
"""
import pathlib

import pytest

from fwl import analyzer, ast, interpreter, parser, pkt
from fwl.interpreter import XdpAction

EXAMPLES = pathlib.Path(__file__).resolve().parents[2] / "examples"
# The address storm_shield gives the appliance on the testnet.
GATEWAY = "10.99.82.1"
BROADCAST = "10.99.82.255"


def _example(name):
  return (EXAMPLES / name).read_text()


def _zone_program(text, zone):
  """The single-zone program for `zone`, as the daemon loads it."""
  prog = analyzer.analyze(parser.parse(text))
  return next(
    ast.Program(programs=[zp], zones=prog.zones)
    for zp in prog.programs if zp.zone_name == zone
  )


def _run(text, zone, builder, ct_seed=None):
  ct = interpreter.ConntrackTable(ct_seed) if ct_seed else None
  return interpreter.evaluate_full(
    _zone_program(text, zone),
    pkt.build_packet(pkt.parse_builder(builder)).fields,
    conntrack=ct,
  )


@pytest.fixture(scope="module")
def storm():
  return _example("storm_shield.fw")


class TestEveryExampleCompiles:
  @pytest.mark.parametrize("name", sorted(
    p.name for p in EXAMPLES.glob("*.fw")
  ))
  def test_analyzes(self, name):
    analyzer.analyze(parser.parse(_example(name)))


class TestStormShieldLanSide:
  """The half that decides whether we are the storm."""

  def test_dhcp_discover_is_delivered_locally(self, storm):
    # A client with no lease: src 0.0.0.0, dst 255.255.255.255, 68->67.
    # This is the packet that was masqueraded onto the office uplink.
    r = _run(storm, "lan",
             'udp(src_ip="0.0.0.0", dst_ip="255.255.255.255", '
             'src_port=68, dst_port=67)')
    assert r.action == XdpAction.PASS, (
      "a DHCP DISCOVER addressed to this box must reach this box's "
      "own dnsmasq, not be masqueraded onto the uplink"
    )
    assert r.redirect_zone is None
    assert r.output_packet is None, "and it must not be rewritten"

  def test_dhcp_renew_to_the_gateway_is_delivered_locally(self, storm):
    r = _run(storm, "lan",
             f'udp(src_ip="10.99.82.40", dst_ip="{GATEWAY}", '
             'src_port=68, dst_port=67)')
    assert r.action == XdpAction.PASS

  def test_dns_to_the_gateway_is_delivered_locally(self, storm):
    r = _run(storm, "lan",
             f'udp(src_ip="10.99.82.40", dst_ip="{GATEWAY}", '
             'src_port=51000, dst_port=53)')
    assert r.action == XdpAction.PASS
    assert r.output_packet is None

  def test_ssh_to_the_gateway_is_delivered_locally(self, storm):
    r = _run(storm, "lan",
             f'tcp(src_ip="10.99.82.40", dst_ip="{GATEWAY}", '
             'src_port=51001, dst_port=22, syn=true)')
    assert r.action == XdpAction.PASS

  @pytest.mark.parametrize("dst,port", [
    ("239.255.255.250", 1900),   # SSDP
    ("224.0.0.251", 5353),       # mDNS
    ("255.255.255.255", 7437),   # a chatty appliance
    (BROADCAST, 17500),          # directed broadcast
  ])
  def test_testnet_noise_never_reaches_the_office(self, storm, dst,
                                                 port):
    r = _run(storm, "lan",
             f'udp(src_ip="10.99.82.40", dst_ip="{dst}", '
             f'dst_port={port})')
    assert r.action == XdpAction.DROP, (
      "a storm shield that masquerades the testnet's own broadcast "
      "onto the uplink is the storm"
    )
    assert r.redirect_zone is None

  def test_netbios_never_reaches_the_office(self, storm):
    r = _run(storm, "lan",
             'udp(src_ip="10.99.82.40", dst_ip="10.99.82.9", '
             'dst_port=137)')
    assert r.action == XdpAction.DROP

  def test_ordinary_egress_is_still_masqueraded_and_redirected(
      self, storm):
    r = _run(storm, "lan",
             'tcp(src_ip="10.99.82.40", dst_ip="93.184.216.34", '
             'src_port=51002, dst_port=443, syn=true)')
    assert r.action == XdpAction.REDIRECT
    assert r.redirect_zone == "wan"
    assert r.output_packet is not None, "egress is still NATed"

  def test_udp_egress_is_still_masqueraded(self, storm):
    r = _run(storm, "lan",
             'udp(src_ip="10.99.82.40", dst_ip="9.9.9.9", '
             'src_port=51003, dst_port=53)')
    assert r.action == XdpAction.REDIRECT
    assert r.redirect_zone == "wan"


class TestStormShieldWanSide:
  """The half that was already right, pinned so it stays right."""

  def test_the_firehose_still_dies(self, storm):
    for builder in (
      'udp(src_ip="10.1.40.1", dst_ip="239.255.255.250", '
      'dst_port=1900)',
      'udp(src_ip="10.1.40.1", dst_ip="255.255.255.255", '
      'dst_port=7437)',
      'udp(src_ip="10.1.40.2", dst_ip="10.1.40.9", dst_port=137)',
    ):
      assert _run(storm, "wan", builder).action == XdpAction.DROP

  def test_our_own_dhcp_offer_survives(self, storm):
    r = _run(storm, "wan",
             'udp(src_ip="10.1.40.3", dst_ip="255.255.255.255", '
             'src_port=67, dst_port=68)')
    assert r.action == XdpAction.PASS

  def test_unsolicited_inbound_is_dropped(self, storm):
    r = _run(storm, "wan",
             'tcp(src_ip="10.1.40.9", dst_ip="10.1.40.2", '
             'src_port=443, dst_port=52000, syn=true, ack=true)')
    assert r.action == XdpAction.DROP

  def test_related_is_admitted_not_only_established(self, storm):
    """`== established` cannot admit an ICMP error.

    An ICMP error carries no ports, so it is never `established`. With
    the old spelling, ping worked, DNS worked, and every large transfer
    hung — because the frag-needed that path-MTU discovery runs on was
    dropped with nothing logged. The idiom is the list.
    """
    src = _example("storm_shield.fw")
    assert "in [established, related]" in src
    assert "state == established" not in src
