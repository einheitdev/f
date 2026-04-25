"""`.pkt` test format loader and packet builder mini-language.

A `.pkt` file is a YAML document. The `test_packet.builder` field is a
small expression language — NOT eval'd Python — describing how to
build the test packet. Builder syntax:

    tcp(src_ip="1.2.3.4", dst_port=22, syn=true, ack=false)
    udp(dst_ip="8.8.8.8", dst_port=53)
    icmp(src_ip="1.1.1.1")

The builder produces raw Ethernet+IPv4+L4 bytes for BPF_PROG_RUN.
"""
