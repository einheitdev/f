"""Unit tests for the BPF C emitter.

These tests check structural properties of the generated C — what's
present, what's not — rather than full snapshots, because incidental
formatting changes shouldn't fail the suite. The corpus + clang
compile already verifies the C is well-formed; these tests pin
specific emission decisions.
"""
import re

import pytest

from fwl import analyzer, emitter, parser


def emit(text):
  return emitter.emit(analyzer.analyze(parser.parse(text)))


class TestPrelude:
  def test_no_pkt_reference_gets_gate_but_no_parse(self):
    src = emit("@xdp(eth0)\nallow\n")
    # No full parse when no pkt.* is touched...
    assert "proto = 0" not in src
    assert "iphdr" not in src
    # ...but the non-IP early-out is always present: without it an
    # unconditional drop/redirect acts on L2 control frames (ARP,
    # STP BPDUs) — reflected BPDUs trip switch loop protection on
    # real fabric (found on the EX2300 by the hardware tests).
    assert "ethhdr" in src
    assert "ETH_P_IPV6" in src

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

  @pytest.mark.parametrize(
    "flag", ["fin", "rst", "psh", "urg", "ece", "cwr"]
  )
  def test_new_flags_emit_bitfield_read(self, flag):
    src = emit(
      f"@xdp(eth0)\ndrop if pkt.proto == tcp and pkt.tcp.{flag}\n"
    )
    assert f"tcp_{flag} = tcp->{flag}" in src
    assert f"(l4_ok && tcp_{flag})" in src

  def test_icmp_type_emits_icmp_branch(self):
    src = emit(
      "@xdp(eth0)\ndrop if pkt.proto == icmp and pkt.icmp.type == 8\n"
    )
    assert "proto == IPPROTO_ICMP" in src
    assert "icmp_type = icmp->type" in src
    assert "(icmp_ok && (icmp_type == 8))" in src
    # Must NOT pull in the un-BPF-compilable kernel ICMP header.
    assert "#include <linux/icmp.h>" not in src
    assert "struct fwl_icmphdr" in src

  def test_icmp6_code_emits_icmpv6_branch(self):
    src = emit(
      "@xdp(eth0)\ndrop if pkt.proto == icmp6 and pkt.icmp6.code != 0\n"
    )
    assert "proto == IPPROTO_ICMPV6" in src
    assert "icmp6_code = icmp6->code" in src
    assert "(icmp6_ok && (icmp6_code != 0))" in src


def _early_out(src):
  """Return the non-IP early-out line, or None.

  Matched by shape rather than exact text: the gate accumulates
  terms (vlan_ok, is_v6_frame) as the language grows, and these
  tests are about which frames escape it, not its spelling.
  """
  for line in src.splitlines():
    s = line.strip()
    if s.startswith("if (!v4_ok") and "return XDP_PASS;" in s:
      return s
  return None


class TestNonIpEarlyOut:
  """Pin the ARP/non-IP early-out per planning/SOAK_INCIDENTS.md
  Incident #3. The dogfood soak surfaced that programs with
  `default drop` or a Tier 2 trailing `drop` silently dropped
  ARP, killing the management plane within minutes. The emitter
  must inject an unconditional XDP_PASS for non-IP frames after
  the prelude, when the program references any IP-aware field."""
  def test_prelude_emits_non_ip_early_out(self):
    src = emit("@xdp(eth0)\ndrop if pkt.proto == tcp\n")
    assert _early_out(src) is not None

  def test_no_prelude_no_early_out(self):
    src = emit("@xdp(eth0)\nallow\n")
    # No fields referenced ⇒ no prelude ⇒ no early-out (the user
    # is explicitly choosing to apply the action to every frame).
    assert "v4_ok" not in src

  def test_ipv6_is_excluded_from_the_early_out(self):
    # FWL_V02_SPEC.md:937 — in a program with no IPv6 surface,
    # IPv6 frames "fall through every rule ... and reach the
    # default action". Letting them take the non-IP early-out
    # makes `default drop` forward all IPv6 traffic.
    src = emit(
      "@xdp(eth0)\n"
      "count v4 if pkt.src_ip in 10.0.0.0/8\n"
      "default drop\n"
    )
    gate = _early_out(src)
    assert gate is not None
    assert "!is_v6_frame" in gate
    assert "is_v6_frame = 1;" in src

  def test_v6_active_program_keeps_early_out(self):
    src = emit(
      "@xdp(eth0)\n"
      "allow if pkt.src_ip6 in 2001:db8::/32\n"
      "default drop\n"
    )
    assert _early_out(src) is not None

  def test_tier2_default_drop_does_not_drop_non_ip(self):
    src = emit(
      "@xdp(eth0)\n\n"
      "def firewall(pkt):\n"
      "  if pkt.proto == tcp:\n"
      "    allow\n"
      "  drop\n"
    )
    # Without the early-out, ARP would land on the trailing
    # `return XDP_DROP;` and kill the link.
    gate = _early_out(src)
    assert gate is not None
    # And the early-out must precede any user rule.
    early_pos = src.index(gate)
    drop_pos = src.index("return XDP_DROP")
    assert early_pos < drop_pos


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

  def test_counter_table_rows_match_the_readers_format(self):
    """The table is a wire format, not a comment.

    Two readers parse it: `hw::counter` in the hardware harness and
    `f::ParseCounterTable` in the daemon, which is what makes
    `show counters` able to say `lan_total` instead of `slot 0`. Both
    require the marker on its own line and each row as `//`, spaces,
    the slot, a TAB, the name. A stylistic tidy-up here — spaces for
    the tab, a colon, an aligned column — silently costs every counter
    on the box its name, and the box still comes up.
    """
    src = emit(
      "@xdp(eth0)\n"
      "count a if pkt.proto == tcp\n"
      "count b if pkt.proto == udp\n"
    )
    lines = src.splitlines()
    marker = lines.index("// fwl_counter_table:")
    rows = []
    for line in lines[marker + 1:]:
      m = re.fullmatch(r"//\s+(\d+)\t(\S+)", line)
      if m is None:
        break
      rows.append((int(m.group(1)), m.group(2)))
    assert rows == [(0, "a"), (1, "b")]

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
    # v0.2: bool-field reads are gated on l4_ok to keep non-TCP
    # frames out of the rule body.
    assert "!((l4_ok && tcp_syn))" in src


TIER2_RL = (
  "@xdp(eth0)\n"
  "\n"
  "def firewall(pkt):\n"
  "  if pkt.proto == tcp and pkt.src_ip in 0.0.0.0/0:\n"
  "    if rate_limit(7, per=src_ip):\n"
  "      drop\n"
  "  allow\n"
)


class TestTier2RateLimit:
  """A Tier 2 rate_limit() must be a limiter, not a constant.

  It emitted `(0)` up to 2026-08-17, and the interpreter modelled it
  the same way — both wrong in the same direction, so every
  differential test agreed with itself and passed. No corpus case
  combined `def` with `rate_limit` at all. A 96 h gateway soak on
  hardware found it, by flooding the Tier 1 and Tier 2 forms side by
  side. These tests exist so the constant cannot come back quietly.
  """

  def test_no_longer_emits_a_constant(self):
    assert "if ((0))" not in emit(TIER2_RL)

  def test_emits_a_bucket_map(self):
    src = emit(TIER2_RL)
    assert "fwl_rl_t2_0" in src
    assert "BPF_MAP_TYPE_PERCPU_HASH" in src

  def test_call_site_reaches_the_helper_with_the_per_field(self):
    assert "fwl_rl_t2_hit_0((__u32)src_ip)" in emit(TIER2_RL)

  def test_helper_and_map_are_distinct_c_identifiers(self):
    # They cannot share a name: one is a function, the other an object.
    src = emit(TIER2_RL)
    assert "} fwl_rl_t2_0 SEC(\".maps\");" in src
    assert "int fwl_rl_t2_hit_0(__u32 rl_key)" in src

  def test_threshold_matches_tier1_semantics(self):
    # The same `cur >= N` the Tier 1 gate uses. The two tiers
    # disagreeing about what "rate exceeded" means would be worse than
    # the gap this replaces — invisible rather than absent, since a
    # policy author cannot see which tier their rule compiled through.
    assert "cur >= 7" in emit(TIER2_RL)

  def test_two_calls_get_separate_buckets(self):
    src = emit(
      "@xdp(eth0)\n"
      "\n"
      "def firewall(pkt):\n"
      "  if pkt.proto == tcp and pkt.src_ip in 0.0.0.0/0:\n"
      "    if rate_limit(3, per=src_ip):\n"
      "      drop\n"
      "    if rate_limit(9, per=dst_ip):\n"
      "      drop\n"
      "  allow\n"
    )
    assert "fwl_rl_t2_0" in src and "fwl_rl_t2_1" in src
    assert "fwl_rl_t2_hit_1((__u32)dst_ip)" in src

  def test_helper_precedes_its_call_site(self):
    src = emit(TIER2_RL)
    assert (src.index("int fwl_rl_t2_hit_0")
            < src.index("fwl_rl_t2_hit_0((__u32)src_ip)"))

  def test_bucket_is_zone_private_in_a_bundle(self):
    # PRIVATE in the registry: two zones must never address one kernel
    # map by their own call indices. Tier 2 has no `scope=global`
    # spelling, so there is nothing that could widen it.
    kind = emitter._map_kind("fwl_rl_t2_0")
    assert kind is not None
    assert kind.scope is emitter.MapScope.PRIVATE
    assert kind.lifetime is emitter.MapLifetime.POLICY
    assert emitter.MapNames("wan").rate_limit_call(0) == "fwl_rl_t2_wan_0"
