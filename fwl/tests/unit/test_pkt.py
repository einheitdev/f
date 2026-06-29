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


class TestV04Builders:
  """v0.4 — all 8 TCP flags and ICMP/ICMPv6 type/code builders."""

  @pytest.mark.parametrize(
    "flag,bit",
    [("fin", 0x01), ("syn", 0x02), ("rst", 0x04), ("psh", 0x08),
     ("ack", 0x10), ("urg", 0x20), ("ece", 0x40), ("cwr", 0x80)],
  )
  def test_each_tcp_flag_sets_its_bit(self, flag, bit):
    packet = pkt.build_packet(pkt.parse_builder(f"tcp({flag}=true)"))
    # TCP flags byte: eth(14) + ip(20) + offset 13 = 47.
    assert packet.raw[47] == bit
    assert packet.fields[flag] is True

  def test_tcp_flags_default_false_in_decoded(self):
    packet = pkt.build_packet(pkt.parse_builder("tcp()"))
    for flag in ("syn", "ack", "fin", "rst", "psh", "urg", "ece", "cwr"):
      assert packet.fields[flag] is False

  def test_xmas_flags_combine(self):
    packet = pkt.build_packet(
      pkt.parse_builder("tcp(fin=true, psh=true, urg=true)")
    )
    assert packet.raw[47] == (0x01 | 0x08 | 0x20)

  def test_icmp_type_code_in_header_and_decoded(self):
    packet = pkt.build_packet(pkt.parse_builder("icmp(type=3, code=1)"))
    # ICMP header: eth(14) + ip(20) = 34 → type, 35 → code.
    assert packet.raw[34] == 3
    assert packet.raw[35] == 1
    assert packet.fields["icmp_type"] == 3
    assert packet.fields["icmp_code"] == 1

  def test_icmp_type_defaults_to_echo_request(self):
    packet = pkt.build_packet(pkt.parse_builder("icmp()"))
    assert packet.fields["icmp_type"] == 8
    assert packet.fields["icmp_code"] == 0

  def test_icmp6_type_code_in_header_and_decoded(self):
    packet = pkt.build_packet(
      pkt.parse_builder("icmp6(type=135, code=0)")
    )
    # ICMPv6 header: eth(14) + ipv6(40) = 54 → type, 55 → code.
    assert packet.raw[54] == 135
    assert packet.raw[55] == 0
    assert packet.fields["icmp6_type"] == 135
    assert packet.fields["icmp6_code"] == 0

  def test_icmp6_type_defaults_to_echo_request(self):
    packet = pkt.build_packet(pkt.parse_builder("icmp6()"))
    assert packet.fields["icmp6_type"] == 128

  def test_unknown_icmp_field_rejected(self):
    with pytest.raises(ValueError):
      pkt.parse_builder("icmp(syn=true)")
