/// @file test_nat.cc
/// @brief Unit tests for NatMgr: the anchor relation and reclamation.
///
/// The pure half (Anchor, occupancy arithmetic, the disabled guards)
/// runs anywhere. The reclamation half creates real BPF hash maps of
/// the emitted shapes and drives RunGc against them, so what is tested
/// is the actual map walk and the actual delete — not a model of one.
/// Those cases skip without CAP_BPF rather than pass vacuously.

#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <unistd.h>

#include <cstring>

#include <bpf/bpf.h>

#include "f/nat_mgr.h"
#include "f/types.h"

namespace f {
namespace {

constexpr uint64_t kSec = 1'000'000'000ULL;

auto Ip(const char* s) -> uint32_t {
  struct in_addr a {};
  inet_pton(AF_INET, s, &a);
  return a.s_addr;
}

/// One masquerade mapping as `fwl_snat_egress` installs it: guest
/// `guest:gport` translated to `masq:tport` toward `peer:pport`.
auto MasqKey(const char* peer, uint16_t pport, const char* masq,
             uint16_t tport) -> FwlNatKey {
  FwlNatKey k{};
  k.src_addr = Ip(peer);
  k.dst_addr = Ip(masq);
  k.src_port = pport;
  k.dst_port = tport;
  k.proto = 6;
  return k;
}

// ============================================================
// The anchor relation
// ============================================================

/// The whole conntrack-tied design rests on one claim: the conntrack
/// entry the datapath inserts for a translated flow is the mapping's
/// own key with both endpoints swapped. If that is wrong, every
/// mapping looks unanchored and the sweep frees live flows — so it is
/// asserted against the tuples the emitter actually writes, spelled
/// out here rather than derived by the same swap the code performs.
TEST(NatAnchorTest, AnchorIsThePostNatForwardTuple) {
  // fwl_snat_egress: guest 10.0.0.7:4444 -> peer 93.184.216.34:443,
  // masqueraded behind 203.0.113.9. The mapping it installs is keyed
  // on the REPLY direction...
  FwlNatKey mapping = MasqKey("93.184.216.34", 443, "203.0.113.9", 4444);
  // ...and the conntrack entry it inserts alongside is the FORWARD
  // direction after translation.
  ConnKey anchor = NatMgr::Anchor(mapping);
  EXPECT_EQ(anchor.src_addr, Ip("203.0.113.9"));
  EXPECT_EQ(anchor.dst_addr, Ip("93.184.216.34"));
  EXPECT_EQ(anchor.src_port, 4444);
  EXPECT_EQ(anchor.dst_port, 443);
  EXPECT_EQ(anchor.proto, 6);
}

TEST(NatAnchorTest, AnchorOfAnchorIsTheMapping) {
  FwlNatKey mapping = MasqKey("8.8.8.8", 53, "198.51.100.1", 33333);
  ConnKey a = NatMgr::Anchor(mapping);
  // Swapping twice is the identity: the relation is symmetric, which
  // is what lets one lookup answer for either NAT direction.
  FwlNatKey back{};
  back.src_addr = a.dst_addr;
  back.dst_addr = a.src_addr;
  back.src_port = a.dst_port;
  back.dst_port = a.src_port;
  back.proto = a.proto;
  EXPECT_EQ(0, std::memcmp(&back, &mapping, sizeof(back)));
}

TEST(NatAnchorTest, AnchorPadIsZeroed) {
  // The anchor is a map KEY: a hash map compares the whole struct
  // including padding, so a stray byte makes every lookup miss and
  // every mapping look dead.
  FwlNatKey mapping = MasqKey("1.2.3.4", 80, "5.6.7.8", 9999);
  ConnKey a = NatMgr::Anchor(mapping);
  for (unsigned char b : a.pad) EXPECT_EQ(b, 0);
}

// ============================================================
// Guards and reporting (no kernel needed)
// ============================================================

TEST(NatMgrTest, DisabledReclaimsNothing) {
  NatMgr n;
  n.enabled = false;
  n.map_fd = 7;
  EXPECT_EQ(n.RunGc(100 * kSec), 0u);
}

TEST(NatMgrTest, NoMapReclaimsNothing) {
  NatMgr n;
  n.enabled = true;
  n.map_fd = -1;
  EXPECT_EQ(n.RunGc(100 * kSec), 0u);
  EXPECT_EQ(n.Entries(), 0u);
}

TEST(NatMgrTest, MaybeGcRespectsTheSweepInterval) {
  NatMgr n;
  n.enabled = true;
  n.map_fd = -1;
  n.last_gc_ns = 1000 * kSec;
  EXPECT_EQ(n.MaybeRunGc(1010 * kSec, 30), 0u);
  EXPECT_EQ(n.last_gc_ns, 1000 * kSec);
  EXPECT_EQ(n.MaybeRunGc(1040 * kSec, 30), 0u);
  EXPECT_EQ(n.last_gc_ns, 1040 * kSec);
}

TEST(NatMgrTest, GetStateReportsOccupancyAgainstTheRealCap) {
  NatMgr n;
  n.enabled = true;
  n.max_entries = 65536;
  n.high_water = 32768;
  auto j = n.GetState();
  EXPECT_TRUE(j["enabled"].get<bool>());
  EXPECT_EQ(j["max_entries"].get<uint32_t>(), 65536u);
  EXPECT_EQ(j["occupancy_pct"].get<uint32_t>(), 0u);
  // A table that filled and drained between two status calls still
  // shows: occupancy alone would report the trough and say nothing.
  EXPECT_EQ(j["high_water"].get<uint32_t>(), 32768u);
  // The datapath tally is part of status, not a separate command —
  // "refused" is the field that means packets were dropped.
  EXPECT_TRUE(j.contains("refused"));
  EXPECT_TRUE(j.contains("table_full"));
  EXPECT_TRUE(j.contains("port_reallocated"));
  // `icmp_error` is a subset of `denat`, and its absence is the one
  // NAT failure that produces no drop, no log and no other counter
  // movement — a masquerading network where path-MTU discovery is
  // silently dead. Reported, therefore, rather than inferred.
  EXPECT_TRUE(j.contains("denat"));
  EXPECT_TRUE(j.contains("icmp_error"));
}

TEST(NatMgrTest, StatSlotsCoverEveryNamedEvent) {
  // The slot numbering is the FWL emitter's, not the daemon's: slot i
  // means the same event under every compilation, and the two ends
  // agree only because both count from this enum. A slot added on one
  // side and not the other reads a neighbour's counter and reports a
  // plausible wrong number, which is worse than reporting none.
  EXPECT_EQ(static_cast<uint32_t>(kFwlNatStatSlots), 6u);
  EXPECT_EQ(static_cast<uint32_t>(kFwlNatStatIcmpErr),
            static_cast<uint32_t>(kFwlNatStatSlots) - 1);
}

TEST(NatMgrTest, OccupancyIsZeroWhenTheCapIsUnknown) {
  NatMgr n;
  n.max_entries = 0;
  EXPECT_EQ(n.GetState()["occupancy_pct"].get<uint32_t>(), 0u);
}

TEST(NatMgrTest, SetStateUpdatesGraceAndWarnThreshold) {
  NatMgr n;
  EXPECT_TRUE(n.SetState({{"grace_s", 90}, {"warn_pct", 50}}));
  EXPECT_EQ(n.grace_s, 90u);
  EXPECT_EQ(n.warn_pct, 50u);
}

// ============================================================
// Reclamation against real maps
// ============================================================

class NatGcMapTest : public ::testing::Test {
 protected:
  void SetUp() override {
    nat_fd = bpf_map_create(BPF_MAP_TYPE_HASH, "fwl_nat",
                            sizeof(FwlNatKey), sizeof(FwlNatValue),
                            1024, nullptr);
    ct_fd = bpf_map_create(BPF_MAP_TYPE_HASH, "conntrack",
                           sizeof(ConnKey), sizeof(ConnValue), 1024,
                           nullptr);
    if (nat_fd < 0 || ct_fd < 0) {
      GTEST_SKIP() << "bpf_map_create failed (needs CAP_BPF)";
    }
    mgr.map_fd = nat_fd;
    mgr.conntrack_fd = ct_fd;
    mgr.enabled = true;
    mgr.max_entries = 1024;
    mgr.grace_s = 30;
  }

  void TearDown() override {
    if (nat_fd >= 0) close(nat_fd);
    if (ct_fd >= 0) close(ct_fd);
  }

  /// Install a mapping, optionally with its conntrack anchor.
  void Install(const FwlNatKey& k, uint64_t last_seen_ns, bool anchored) {
    FwlNatValue v{};
    v.last_seen_ns = last_seen_ns;
    v.new_addr = Ip("10.0.0.7");
    v.new_port = 4444;
    v.nat_type = 2;  // FWL_NAT_DNAT
    ASSERT_EQ(bpf_map_update_elem(nat_fd, &k, &v, BPF_ANY), 0);
    if (anchored) {
      ConnKey a = NatMgr::Anchor(k);
      ConnValue cv{};
      cv.last_seen_ns = last_seen_ns;
      cv.packets = 1;
      cv.state = 1;
      ASSERT_EQ(bpf_map_update_elem(ct_fd, &a, &cv, BPF_ANY), 0);
    }
  }

  int nat_fd = -1;
  int ct_fd = -1;
  NatMgr mgr;
};

TEST_F(NatGcMapTest, AnchoredMappingSurvivesHoweverOldItIs) {
  // The flow is alive as long as conntrack says it is. Age alone is
  // not a reason to free — that would be a second lifetime policy
  // guessing at what conntrack already knows.
  FwlNatKey k = MasqKey("93.184.216.34", 443, "203.0.113.9", 4444);
  Install(k, 1 * kSec, /*anchored=*/true);
  EXPECT_EQ(mgr.Entries(), 1u);
  EXPECT_EQ(mgr.RunGc(100000 * kSec), 0u);
  EXPECT_EQ(mgr.Entries(), 1u);
}

TEST_F(NatGcMapTest, UnanchoredIdleMappingIsReclaimed) {
  // Conntrack's own GC dropped the entry, so the flow is over. The
  // mapping goes with it — this is the whole point.
  FwlNatKey k = MasqKey("93.184.216.34", 443, "203.0.113.9", 4444);
  Install(k, 1000 * kSec, /*anchored=*/false);
  EXPECT_EQ(mgr.Entries(), 1u);
  EXPECT_EQ(mgr.RunGc(1100 * kSec), 1u);
  EXPECT_EQ(mgr.Entries(), 0u);
  EXPECT_EQ(mgr.total_reclaimed, 1u);
}

TEST_F(NatGcMapTest, UnanchoredButBusyMappingIsNotReclaimed) {
  // The case that makes the anchor safe to trust. A conntrack table at
  // its own cap silently refuses the anchor insert, so an unanchored
  // mapping is not proof of a dead flow — traffic on the mapping is
  // proof of a live one, and it wins. Never break a live flow.
  FwlNatKey k = MasqKey("93.184.216.34", 443, "203.0.113.9", 4444);
  Install(k, 1000 * kSec, /*anchored=*/false);
  EXPECT_EQ(mgr.RunGc(1005 * kSec), 0u);
  EXPECT_EQ(mgr.Entries(), 1u);
  // ...and once it does go quiet past the grace window, it is freed.
  EXPECT_EQ(mgr.RunGc(1040 * kSec), 1u);
  EXPECT_EQ(mgr.Entries(), 0u);
}

TEST_F(NatGcMapTest, ReclaimsOnlyTheDeadOnesOutOfMany) {
  // Vacuity guard: a sweep that freed everything, or nothing, would
  // pass a one-entry test either way. Here the survivors and the
  // casualties are asserted by identity, not by count alone.
  FwlNatKey live1 = MasqKey("93.184.216.34", 443, "203.0.113.9", 4444);
  FwlNatKey live2 = MasqKey("8.8.8.8", 53, "203.0.113.9", 5555);
  FwlNatKey dead1 = MasqKey("1.1.1.1", 443, "203.0.113.9", 6666);
  FwlNatKey dead2 = MasqKey("9.9.9.9", 853, "203.0.113.9", 7777);
  Install(live1, 1000 * kSec, true);
  Install(live2, 10 * kSec, true);
  Install(dead1, 900 * kSec, false);
  Install(dead2, 10 * kSec, false);
  ASSERT_EQ(mgr.Entries(), 4u);

  EXPECT_EQ(mgr.RunGc(1000 * kSec), 2u);
  EXPECT_EQ(mgr.Entries(), 2u);

  FwlNatValue v{};
  EXPECT_EQ(bpf_map_lookup_elem(nat_fd, &live1, &v), 0);
  EXPECT_EQ(bpf_map_lookup_elem(nat_fd, &live2, &v), 0);
  EXPECT_NE(bpf_map_lookup_elem(nat_fd, &dead1, &v), 0);
  EXPECT_NE(bpf_map_lookup_elem(nat_fd, &dead2, &v), 0);
}

TEST_F(NatGcMapTest, OccupancyAndHighWaterTrackTheTable) {
  // The observable half. A table that fills and drains must still be
  // readable as having filled — the l11_02 failure was invisible
  // precisely because there was no number to watch.
  for (uint16_t i = 0; i < 100; i++) {
    Install(MasqKey("1.1.1.1", 443, "203.0.113.9",
                    static_cast<uint16_t>(40000 + i)),
            10 * kSec, false);
  }
  EXPECT_EQ(mgr.Entries(), 100u);
  EXPECT_EQ(mgr.GetState()["occupancy_pct"].get<uint32_t>(), 9u);

  EXPECT_EQ(mgr.RunGc(1000 * kSec), 100u);
  EXPECT_EQ(mgr.Entries(), 0u);
  EXPECT_EQ(mgr.GetState()["occupancy_pct"].get<uint32_t>(), 0u);
  EXPECT_EQ(mgr.GetState()["high_water"].get<uint32_t>(), 100u);
  EXPECT_EQ(mgr.total_reclaimed, 100u);
}

TEST_F(NatGcMapTest, WithoutAConntrackFdNothingIsFreedEarly) {
  // Defensive: if the manager is somehow wired without a conntrack
  // table, the grace window alone decides. It must still not free a
  // mapping that is carrying traffic.
  mgr.conntrack_fd = -1;
  FwlNatKey k = MasqKey("93.184.216.34", 443, "203.0.113.9", 4444);
  Install(k, 1000 * kSec, false);
  EXPECT_EQ(mgr.RunGc(1010 * kSec), 0u);
  EXPECT_EQ(mgr.RunGc(1100 * kSec), 1u);
}

}  // namespace
}  // namespace f
