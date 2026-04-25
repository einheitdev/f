"""Unit tests for the .pkt loader and packet builder mini-language."""
import pytest

from fwl import pkt


class TestIPv4Validation:
  """Finding 3: builder must reject non-string IPv4 args cleanly."""

  def test_int_for_src_ip_rejected_with_clear_error(self):
    fields = pkt.parse_builder("tcp(src_ip=16909060, dst_port=80)")
    with pytest.raises(ValueError, match="src_ip"):
      pkt.build_packet(fields)

  def test_invalid_dotted_quad_rejected(self):
    fields = pkt.parse_builder('tcp(src_ip="not.an.ip.address")')
    with pytest.raises(ValueError, match="src_ip"):
      pkt.build_packet(fields)

  def test_octet_out_of_range_rejected(self):
    fields = pkt.parse_builder('tcp(src_ip="1.2.3.999")')
    with pytest.raises(ValueError, match="src_ip"):
      pkt.build_packet(fields)

  def test_well_formed_dotted_quad_passes(self):
    fields = pkt.parse_builder('tcp(src_ip="10.20.30.40")')
    packet = pkt.build_packet(fields)
    # IP source addr at offset 14+12 = 26
    assert packet.raw[26:30] == bytes([10, 20, 30, 40])


class TestBuilderParser:
  def test_tcp_with_kwargs(self):
    fields = pkt.parse_builder(
      'tcp(src_ip="1.2.3.4", dst_port=22, syn=true)'
    )
    assert fields["proto"] == "tcp"
    assert fields["src_ip"] == "1.2.3.4"
    assert fields["dst_port"] == 22
    assert fields["syn"] is True

  def test_udp_minimal(self):
    fields = pkt.parse_builder("udp()")
    assert fields == {"proto": "udp"}

  def test_icmp_minimal(self):
    fields = pkt.parse_builder("icmp()")
    assert fields == {"proto": "icmp"}

  def test_hex_value(self):
    fields = pkt.parse_builder("tcp(dst_port=0xff)")
    assert fields["dst_port"] == 255

  def test_unknown_proto_rejected(self):
    with pytest.raises(ValueError):
      pkt.parse_builder("sctp()")

  def test_argument_without_equals_rejected(self):
    with pytest.raises(ValueError):
      pkt.parse_builder("tcp(80)")


class TestBuildPacket:
  def test_tcp_packet_has_ipv4_ether_type(self):
    packet = pkt.build_packet(pkt.parse_builder("tcp()"))
    # Ethernet EtherType at offset 12-13: 0x0800 (IPv4)
    assert packet.raw[12:14] == b"\x08\x00"

  def test_tcp_packet_has_proto_6_in_ip(self):
    packet = pkt.build_packet(pkt.parse_builder("tcp()"))
    # IP protocol byte at offset 14 + 9 = 23
    assert packet.raw[23] == 6  # IPPROTO_TCP

  def test_udp_packet_has_proto_17_in_ip(self):
    packet = pkt.build_packet(pkt.parse_builder("udp()"))
    assert packet.raw[23] == 17  # IPPROTO_UDP

  def test_icmp_packet_has_proto_1_in_ip(self):
    packet = pkt.build_packet(pkt.parse_builder("icmp()"))
    assert packet.raw[23] == 1  # IPPROTO_ICMP

  def test_decoded_fields_carry_through(self):
    packet = pkt.build_packet(pkt.parse_builder(
      'tcp(src_ip="9.9.9.9", dst_port=443, syn=true)'
    ))
    assert packet.fields["proto"] == "tcp"
    assert packet.fields["src_ip"] == "9.9.9.9"
    assert packet.fields["dst_port"] == 443
    assert packet.fields["syn"] is True

  def test_default_ports_are_filled_in_for_tcp(self):
    packet = pkt.build_packet(pkt.parse_builder("tcp()"))
    assert "src_port" in packet.fields
    assert "dst_port" in packet.fields
