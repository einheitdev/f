"""Unit tests for the BPF C emitter.

These tests check structural properties of the generated C — what's
present, what's not — rather than full snapshots, because incidental
formatting changes shouldn't fail the suite. The corpus + clang
compile already verifies the C is well-formed; these tests pin
specific emission decisions.
"""
from fwl import analyzer, emitter, parser


def emit(text):
  return emitter.emit(analyzer.analyze(parser.parse(text)))


class TestPrelude:
  def test_no_pkt_reference_no_prelude(self):
    src = emit("@xdp(eth0)\nallow\n")
    # No proto/data/eth declarations when no pkt.* is touched.
    assert "proto = 0" not in src
    assert "ethhdr" not in src

  def test_proto_only_minimal_prelude(self):
    src = emit("@xdp(eth0)\ndrop if pkt.proto == tcp\n")
    assert "proto = 0" in src
    assert "ethhdr" in src
    assert "iphdr" in src
    # No L4 since no port/flag access.
    assert "tcphdr" not in src
    assert "udphdr" not in src

  def test_port_access_emits_l4_parsing(self):
    src = emit(
      "@xdp(eth0)\ndrop if pkt.proto == tcp and pkt.dst_port == 22\n"
    )
    assert "tcphdr" in src
    # IHL handling.
    assert "ip->ihl * 4" in src

  def test_flag_access_emits_tcp_only(self):
    src = emit(
      "@xdp(eth0)\ndrop if pkt.proto == tcp and pkt.tcp.syn\n"
    )
    assert "tcp_syn = tcp->syn" in src


class TestActions:
  def test_allow_returns_xdp_pass(self):
    src = emit("@xdp(eth0)\nallow\n")
    assert "XDP_PASS" in src

  def test_drop_returns_xdp_drop(self):
    src = emit("@xdp(eth0)\ndrop\n")
    assert "XDP_DROP" in src

  def test_default_drop_changes_final_return(self):
    src = emit("@xdp(eth0)\nallow if pkt.proto == tcp\ndefault drop\n")
    # The implicit final return becomes XDP_DROP
    assert src.rstrip().endswith(
      'char _license[] SEC("license") = "GPL";'
    )
    # Find the bare `return XDP_DROP;` outside of any rule body.
    assert "  return XDP_DROP;" in src


class TestRateLimit:
  def test_emits_per_cpu_hash_map(self):
    src = emit(
      "@xdp(eth0)\n"
      "drop limited by rate_limit(10, per=src_ip)\n"
    )
    assert "BPF_MAP_TYPE_PERCPU_HASH" in src
    assert "fwl_rl_map_0" in src
    assert "max_entries, 4096" in src

  def test_two_modifiers_two_maps(self):
    src = emit(
      "@xdp(eth0)\n"
      "drop if pkt.proto == tcp and pkt.dst_port == 22\n"
      "     limited by rate_limit(3, per=src_ip)\n"
      "drop if pkt.proto == tcp and pkt.dst_port == 23\n"
      "     limited by rate_limit(5, per=src_ip)\n"
    )
    assert "fwl_rl_map_0" in src
    assert "fwl_rl_map_1" in src

  def test_threshold_appears_in_gate(self):
    src = emit("@xdp(eth0)\ndrop limited by rate_limit(42, per=src_ip)\n")
    # Action fires when the (pre-increment) bucket count has reached
    # the threshold — matches the user-facing reading of "drop traffic
    # exceeding N per second".
    assert "cur >= 42" in src


class TestLogAndCount:
  def test_log_emits_ringbuf(self):
    src = emit("@xdp(eth0)\nlog if pkt.proto == tcp\n")
    assert "BPF_MAP_TYPE_RINGBUF" in src
    assert "fwl_log_events" in src
    assert "bpf_ringbuf_reserve" in src
    assert "bpf_ringbuf_submit" in src

  def test_count_emits_per_cpu_array(self):
    src = emit("@xdp(eth0)\ncount foo if pkt.proto == tcp\n")
    assert "BPF_MAP_TYPE_PERCPU_ARRAY" in src
    assert "__sync_fetch_and_add" in src

  def test_counter_table_appended(self):
    src = emit(
      "@xdp(eth0)\n"
      "count a if pkt.proto == tcp\n"
      "count b if pkt.proto == udp\n"
    )
    assert "fwl_counter_table:" in src
    assert "0\ta" in src
    assert "1\tb" in src

  def test_counter_slots_stable(self):
    src = emit(
      "@xdp(eth0)\n"
      "count a if pkt.proto == tcp\n"
      "count a if pkt.proto == udp\n"  # same name, same slot
      "count b if pkt.proto == icmp\n"
    )
    # Only two distinct slots
    assert "max_entries, 2" in src


class TestComposition:
  def test_and_uses_logical_and(self):
    src = emit(
      "@xdp(eth0)\ndrop if pkt.proto == tcp and pkt.proto == tcp\n"
    )
    assert "&&" in src

  def test_or_uses_logical_or(self):
    src = emit(
      "@xdp(eth0)\ndrop if pkt.proto == tcp or pkt.proto == udp\n"
    )
    assert "||" in src

  def test_not_uses_negation(self):
    src = emit(
      "@xdp(eth0)\ndrop if pkt.proto == tcp and not pkt.tcp.syn\n"
    )
    assert "!(tcp_syn)" in src
