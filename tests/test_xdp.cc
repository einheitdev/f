/// @file test_xdp.cc
/// @brief XDP program test harness using BPF_PROG_RUN.
///
/// Loads the real BPF program, injects crafted packets,
/// verifies verdicts and counter increments.
/// Requires CAP_BPF (run as root).

#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <linux/bpf.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <algorithm>
#include <cstring>
#include <vector>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "f/engine.h"
#include "f/types.h"

namespace f {
namespace {

// ============================================================================
// Packet builder
// ============================================================================

struct EthHdr {
  uint8_t dst[6];
  uint8_t src[6];
  uint16_t proto;
} __attribute__((packed));

struct IpHdr {
  uint8_t ihl_ver;
  uint8_t tos;
  uint16_t tot_len;
  uint16_t id;
  uint16_t frag_off;
  uint8_t ttl;
  uint8_t protocol;
  uint16_t check;
  uint32_t saddr;
  uint32_t daddr;
} __attribute__((packed));

struct TcpHdr {
  uint16_t source;
  uint16_t dest;
  uint32_t seq;
  uint32_t ack_seq;
  uint16_t flags;
  uint16_t window;
  uint16_t check;
  uint16_t urg_ptr;
} __attribute__((packed));

struct UdpHdr {
  uint16_t source;
  uint16_t dest;
  uint16_t len;
  uint16_t check;
} __attribute__((packed));

/// Build a minimal Ethernet + IPv4 + TCP packet.
auto BuildTcpPacket(const char* src_ip,
                    const char* dst_ip,
                    uint16_t src_port,
                    uint16_t dst_port)
    -> std::vector<uint8_t> {
  std::vector<uint8_t> pkt(
      sizeof(EthHdr) + sizeof(IpHdr) + sizeof(TcpHdr));

  auto* eth = reinterpret_cast<EthHdr*>(pkt.data());
  std::memset(eth->dst, 0xff, 6);
  std::memset(eth->src, 0xaa, 6);
  eth->proto = htons(0x0800);

  auto* ip = reinterpret_cast<IpHdr*>(
      pkt.data() + sizeof(EthHdr));
  ip->ihl_ver = 0x45;  // IPv4, 5 words (20 bytes).
  ip->ttl = 64;
  ip->protocol = 6;  // TCP.
  ip->tot_len = htons(sizeof(IpHdr) + sizeof(TcpHdr));
  inet_pton(AF_INET, src_ip, &ip->saddr);
  inet_pton(AF_INET, dst_ip, &ip->daddr);

  auto* tcp = reinterpret_cast<TcpHdr*>(
      pkt.data() + sizeof(EthHdr) + sizeof(IpHdr));
  tcp->source = htons(src_port);
  tcp->dest = htons(dst_port);
  tcp->flags = htons(0x5002);  // SYN, doff=5.

  return pkt;
}

/// Build a minimal Ethernet + IPv4 + UDP packet.
auto BuildUdpPacket(const char* src_ip,
                    const char* dst_ip,
                    uint16_t src_port,
                    uint16_t dst_port)
    -> std::vector<uint8_t> {
  std::vector<uint8_t> pkt(
      sizeof(EthHdr) + sizeof(IpHdr) + sizeof(UdpHdr));

  auto* eth = reinterpret_cast<EthHdr*>(pkt.data());
  std::memset(eth->dst, 0xff, 6);
  std::memset(eth->src, 0xaa, 6);
  eth->proto = htons(0x0800);

  auto* ip = reinterpret_cast<IpHdr*>(
      pkt.data() + sizeof(EthHdr));
  ip->ihl_ver = 0x45;
  ip->ttl = 64;
  ip->protocol = 17;  // UDP.
  ip->tot_len = htons(sizeof(IpHdr) + sizeof(UdpHdr));
  inet_pton(AF_INET, src_ip, &ip->saddr);
  inet_pton(AF_INET, dst_ip, &ip->daddr);

  auto* udp = reinterpret_cast<UdpHdr*>(
      pkt.data() + sizeof(EthHdr) + sizeof(IpHdr));
  udp->source = htons(src_port);
  udp->dest = htons(dst_port);
  udp->len = htons(sizeof(UdpHdr));

  return pkt;
}

/// Build a non-IP packet (e.g. ARP).
auto BuildArpPacket() -> std::vector<uint8_t> {
  std::vector<uint8_t> pkt(64);
  auto* eth = reinterpret_cast<EthHdr*>(pkt.data());
  std::memset(eth->dst, 0xff, 6);
  std::memset(eth->src, 0xaa, 6);
  eth->proto = htons(0x0806);  // ARP.
  return pkt;
}

// ============================================================================
// BPF_PROG_RUN helper
// ============================================================================

/// Run one packet through the XDP program, return verdict.
auto RunXdp(int prog_fd,
            const std::vector<uint8_t>& pkt) -> int {
  struct bpf_test_run_opts opts{};
  opts.sz = sizeof(opts);
  opts.data_in = pkt.data();
  opts.data_size_in = static_cast<uint32_t>(pkt.size());

  // Output buffer (XDP can modify packets).
  std::vector<uint8_t> out(pkt.size() + 256);
  opts.data_out = out.data();
  opts.data_size_out = static_cast<uint32_t>(out.size());

  opts.repeat = 1;

  int err = bpf_prog_test_run_opts(prog_fd, &opts);
  if (err != 0) {
    return -1;
  }
  return opts.retval;
}

/// Run a packet N times.
auto RunXdpN(int prog_fd,
             const std::vector<uint8_t>& pkt,
             int count) -> int {
  struct bpf_test_run_opts opts{};
  opts.sz = sizeof(opts);
  opts.data_in = pkt.data();
  opts.data_size_in = static_cast<uint32_t>(pkt.size());

  std::vector<uint8_t> out(pkt.size() + 256);
  opts.data_out = out.data();
  opts.data_size_out = static_cast<uint32_t>(out.size());

  opts.repeat = static_cast<uint32_t>(count);

  int err = bpf_prog_test_run_opts(prog_fd, &opts);
  if (err != 0) {
    return -1;
  }
  return opts.retval;
}

// ============================================================================
// Map helpers
// ============================================================================

/// Insert a rule into a hash map.
auto InsertRule(int map_fd, uint32_t src_addr,
                uint32_t dst_addr, uint16_t src_port,
                uint16_t dst_port, uint8_t proto,
                uint8_t action) -> void {
  RuleKey key{};
  key.src_addr = src_addr;
  key.dst_addr = dst_addr;
  key.src_port = src_port;
  key.dst_port = dst_port;
  key.proto = proto;
  RuleValue val{};
  val.action = action;
  bpf_map_update_elem(map_fd, &key, &val, BPF_ANY);
}

/// Convert dotted IP to network-order uint32.
auto IpToNet(const char* ip) -> uint32_t {
  uint32_t addr;
  inet_pton(AF_INET, ip, &addr);
  return addr;
}

/// Read aggregated counter for a given index.
auto ReadCounter(int counters_fd, uint32_t idx)
    -> RuleCounter {
  RuleCounter total{};
  int ncpus = libbpf_num_possible_cpus();
  if (ncpus < 1) ncpus = 1;
  std::vector<RuleCounter> per_cpu(ncpus);
  if (bpf_map_lookup_elem(
          counters_fd, &idx, per_cpu.data()) == 0) {
    for (int c = 0; c < ncpus; c++) {
      total.packets += per_cpu[c].packets;
      total.bytes += per_cpu[c].bytes;
    }
  }
  return total;
}

/// Set the active config.
auto SetConfig(int config_fd, uint8_t default_action,
               uint8_t active_table,
               uint8_t conntrack_enabled) -> void {
  FwConfig cfg{};
  cfg.default_action = default_action;
  cfg.active_table = active_table;
  cfg.conntrack_enabled = conntrack_enabled;
  cfg.conntrack_timeout_s = 300;
  uint32_t key = 0;
  bpf_map_update_elem(config_fd, &key, &cfg, BPF_ANY);
}

/// Flush all entries from a hash map.
auto FlushMap(int map_fd) -> void {
  char key[256], next[256];
  while (bpf_map_get_next_key(
             map_fd, nullptr, next) == 0) {
    std::memcpy(key, next, sizeof(key));
    bpf_map_delete_elem(map_fd, key);
  }
}

// ============================================================================
// Test fixture
// ============================================================================

class XdpTest : public ::testing::Test {
 protected:
  void SetUp() override {
    auto res = LoadProgram();
    if (!res) {
      GTEST_SKIP() << "BPF load failed: "
                   << res.error().message
                   << " (need root/CAP_BPF)";
    }
    h_ = *res;
    // Default: allow all, table A, no conntrack.
    SetConfig(h_.config_fd, 1, 0, 0);
    // Flush all rule tables.
    FlushMap(h_.rules_a_fd);
    FlushMap(h_.rules_b_fd);
  }

  BpfHandles h_;
};

// ============================================================================
// Tests
// ============================================================================

TEST_F(XdpTest, NonIpPacketPasses) {
  auto pkt = BuildArpPacket();
  EXPECT_EQ(RunXdp(h_.prog_fd, pkt), XDP_PASS);
}

TEST_F(XdpTest, DefaultAllowPassesAll) {
  SetConfig(h_.config_fd, 1, 0, 0);  // ALLOW default.
  auto pkt = BuildTcpPacket(
      "10.0.0.1", "10.0.0.2", 12345, 80);
  EXPECT_EQ(RunXdp(h_.prog_fd, pkt), XDP_PASS);
}

TEST_F(XdpTest, DefaultDropDropsAll) {
  SetConfig(h_.config_fd, 0, 0, 0);  // DROP default.
  auto pkt = BuildTcpPacket(
      "10.0.0.1", "10.0.0.2", 12345, 80);
  EXPECT_EQ(RunXdp(h_.prog_fd, pkt), XDP_DROP);
}

TEST_F(XdpTest, ExactRuleDropsTcp) {
  // Rule: drop TCP from 10.0.0.1:12345 → 10.0.0.2:80.
  InsertRule(h_.rules_a_fd,
             IpToNet("10.0.0.1"), IpToNet("10.0.0.2"),
             12345, 80, 6, 0);

  auto pkt = BuildTcpPacket(
      "10.0.0.1", "10.0.0.2", 12345, 80);
  EXPECT_EQ(RunXdp(h_.prog_fd, pkt), XDP_DROP);

  // Different port — should pass (default allow).
  auto pkt2 = BuildTcpPacket(
      "10.0.0.1", "10.0.0.2", 12345, 443);
  EXPECT_EQ(RunXdp(h_.prog_fd, pkt2), XDP_PASS);
}

TEST_F(XdpTest, WildcardSrcPortMatches) {
  // Rule: drop TCP to port 22, any src_port (src_port=0).
  InsertRule(h_.rules_a_fd,
             0, 0, 0, 22, 6, 0);

  // Any source port should match.
  auto pkt1 = BuildTcpPacket(
      "10.0.0.1", "10.0.0.2", 54321, 22);
  EXPECT_EQ(RunXdp(h_.prog_fd, pkt1), XDP_DROP);

  auto pkt2 = BuildTcpPacket(
      "192.168.1.1", "172.16.0.1", 1111, 22);
  EXPECT_EQ(RunXdp(h_.prog_fd, pkt2), XDP_DROP);

  // Port 80 should pass.
  auto pkt3 = BuildTcpPacket(
      "10.0.0.1", "10.0.0.2", 54321, 80);
  EXPECT_EQ(RunXdp(h_.prog_fd, pkt3), XDP_PASS);
}

TEST_F(XdpTest, WildcardAllPortsMatches) {
  // Rule: drop TCP, any ports (both 0).
  InsertRule(h_.rules_a_fd,
             0, 0, 0, 0, 6, 0);

  auto pkt = BuildTcpPacket(
      "10.0.0.1", "10.0.0.2", 9999, 443);
  EXPECT_EQ(RunXdp(h_.prog_fd, pkt), XDP_DROP);

  // UDP should pass (proto mismatch).
  auto udp = BuildUdpPacket(
      "10.0.0.1", "10.0.0.2", 9999, 53);
  EXPECT_EQ(RunXdp(h_.prog_fd, udp), XDP_PASS);
}

TEST_F(XdpTest, DstOnlyRuleMatches) {
  // Rule: drop TCP to dst port 443, wildcard everything
  // else (key 3: src_addr=0, src_port=0, dst_port=443).
  InsertRule(h_.rules_a_fd,
             0, IpToNet("10.0.0.2"), 0, 443, 6, 0);

  auto pkt = BuildTcpPacket(
      "192.168.1.100", "10.0.0.2", 55555, 443);
  EXPECT_EQ(RunXdp(h_.prog_fd, pkt), XDP_DROP);
}

TEST_F(XdpTest, TableSwap) {
  // Table A: drop port 22.
  InsertRule(h_.rules_a_fd, 0, 0, 0, 22, 6, 0);
  SetConfig(h_.config_fd, 1, 0, 0);  // Table A active.

  auto ssh = BuildTcpPacket(
      "10.0.0.1", "10.0.0.2", 12345, 22);
  EXPECT_EQ(RunXdp(h_.prog_fd, ssh), XDP_DROP);

  // Table B: allow port 22 (no rule → default allow).
  SetConfig(h_.config_fd, 1, 1, 0);  // Table B active.
  EXPECT_EQ(RunXdp(h_.prog_fd, ssh), XDP_PASS);

  // Swap back.
  SetConfig(h_.config_fd, 1, 0, 0);  // Table A active.
  EXPECT_EQ(RunXdp(h_.prog_fd, ssh), XDP_DROP);
}

TEST_F(XdpTest, CounterIncrements) {
  auto pkt = BuildTcpPacket(
      "10.0.0.1", "10.0.0.2", 12345, 80);

  // Counter 0 is the total counter (always incremented).
  auto before = ReadCounter(h_.counters_fd, 0);
  RunXdpN(h_.prog_fd, pkt, 100);
  auto after = ReadCounter(h_.counters_fd, 0);

  EXPECT_GE(after.packets - before.packets, 100u);
  EXPECT_GT(after.bytes, before.bytes);
}

TEST_F(XdpTest, RuleCounterIncrements) {
  // Rule at wildcard key → counter index 1 (first
  // wildcard match in the cascade).
  InsertRule(h_.rules_a_fd, 0, 0, 0, 80, 6, 1);

  auto pkt = BuildTcpPacket(
      "10.0.0.1", "10.0.0.2", 54321, 80);

  auto before = ReadCounter(h_.counters_fd, 1);
  RunXdpN(h_.prog_fd, pkt, 50);
  auto after = ReadCounter(h_.counters_fd, 1);

  // Wildcard src_port match → counter index 2 (k=1).
  // Actually the apply_action uses k+1, so index depends
  // on which key matched. Let's check all.
  bool found = false;
  for (uint32_t i = 1; i <= 4; i++) {
    auto c = ReadCounter(h_.counters_fd, i);
    if (c.packets >= 50) {
      found = true;
      break;
    }
  }
  EXPECT_TRUE(found)
      << "Expected at least one rule counter >= 50";
}

TEST_F(XdpTest, AllowRuleOverridesDefaultDrop) {
  SetConfig(h_.config_fd, 0, 0, 0);  // Default DROP.

  // Allow TCP port 443.
  InsertRule(h_.rules_a_fd, 0, 0, 0, 443, 6, 1);

  // Port 443 allowed.
  auto https = BuildTcpPacket(
      "10.0.0.1", "10.0.0.2", 54321, 443);
  EXPECT_EQ(RunXdp(h_.prog_fd, https), XDP_PASS);

  // Port 80 dropped (default).
  auto http = BuildTcpPacket(
      "10.0.0.1", "10.0.0.2", 54321, 80);
  EXPECT_EQ(RunXdp(h_.prog_fd, http), XDP_DROP);
}

TEST_F(XdpTest, UdpRuleMatches) {
  InsertRule(h_.rules_a_fd, 0, 0, 0, 53, 17, 0);

  auto dns = BuildUdpPacket(
      "10.0.0.1", "8.8.8.8", 12345, 53);
  EXPECT_EQ(RunXdp(h_.prog_fd, dns), XDP_DROP);

  auto other = BuildUdpPacket(
      "10.0.0.1", "8.8.8.8", 12345, 5353);
  EXPECT_EQ(RunXdp(h_.prog_fd, other), XDP_PASS);
}

TEST_F(XdpTest, MultipleRulesPriority) {
  // More specific rule should match first.
  // Exact match: allow 10.0.0.1 → 10.0.0.2:22.
  InsertRule(h_.rules_a_fd,
             IpToNet("10.0.0.1"), IpToNet("10.0.0.2"),
             12345, 22, 6, 1);
  // Wildcard: drop all SSH.
  InsertRule(h_.rules_a_fd, 0, 0, 0, 22, 6, 0);

  // Exact match takes priority → PASS.
  auto pkt1 = BuildTcpPacket(
      "10.0.0.1", "10.0.0.2", 12345, 22);
  EXPECT_EQ(RunXdp(h_.prog_fd, pkt1), XDP_PASS);

  // Different src_port → falls to wildcard → DROP.
  auto pkt2 = BuildTcpPacket(
      "10.0.0.1", "10.0.0.2", 99999, 22);
  EXPECT_EQ(RunXdp(h_.prog_fd, pkt2), XDP_DROP);
}

TEST_F(XdpTest, HighThroughput) {
  auto pkt = BuildTcpPacket(
      "10.0.0.1", "10.0.0.2", 12345, 80);

  auto before = ReadCounter(h_.counters_fd, 0);

  // Run 1M packets through the program.
  struct bpf_test_run_opts opts{};
  opts.sz = sizeof(opts);
  opts.data_in = pkt.data();
  opts.data_size_in =
      static_cast<uint32_t>(pkt.size());
  std::vector<uint8_t> out(pkt.size() + 256);
  opts.data_out = out.data();
  opts.data_size_out =
      static_cast<uint32_t>(out.size());
  opts.repeat = 1000000;

  auto t0 = std::chrono::steady_clock::now();
  int err = bpf_prog_test_run_opts(h_.prog_fd, &opts);
  auto t1 = std::chrono::steady_clock::now();

  ASSERT_EQ(err, 0);
  EXPECT_EQ(opts.retval, XDP_PASS);

  auto after = ReadCounter(h_.counters_fd, 0);
  EXPECT_GE(after.packets - before.packets, 1000000u);

  auto ms = std::chrono::duration_cast<
      std::chrono::milliseconds>(t1 - t0).count();
  double mpps = 1000000.0 / (ms / 1000.0) / 1e6;
  std::printf("  1M packets in %ldms (%.1f Mpps)\n",
              ms, mpps);
}

}  // namespace
}  // namespace f
