/// @file test_conntrack.cc
/// @brief Unit tests for ConntrackMgr GC logic.

#include "f/conntrack_mgr.h"

#include <gtest/gtest.h>

namespace f {

TEST(ConntrackGcTest, DisabledReturnsZero) {
  ConntrackMgr mgr;
  mgr.enabled = false;
  mgr.map_fd = -1;
  EXPECT_EQ(mgr.RunGc(1'000'000'000ULL), 0);
}

TEST(ConntrackGcTest, NoMapReturnsZero) {
  ConntrackMgr mgr;
  mgr.enabled = true;
  mgr.map_fd = -1;
  EXPECT_EQ(mgr.RunGc(1'000'000'000ULL), 0);
}

TEST(ConntrackGcTest, ZeroTimeoutReturnsZero) {
  ConntrackMgr mgr;
  mgr.enabled = true;
  mgr.map_fd = 42;
  mgr.timeout_s = 0;
  EXPECT_EQ(mgr.RunGc(1'000'000'000ULL), 0);
}

TEST(ConntrackGcTest, MaybeGcRespectsInterval) {
  ConntrackMgr mgr;
  mgr.enabled = true;
  mgr.map_fd = -1;
  mgr.gc_interval_s = 30;
  uint64_t ns = 1'000'000'000ULL;
  mgr.MaybeRunGc(ns);
  EXPECT_EQ(mgr.last_gc_ns, ns);
  uint64_t ns2 = ns + 10'000'000'000ULL;
  mgr.MaybeRunGc(ns2);
  EXPECT_EQ(mgr.last_gc_ns, ns);
  uint64_t ns3 = ns + 31'000'000'000ULL;
  mgr.MaybeRunGc(ns3);
  EXPECT_EQ(mgr.last_gc_ns, ns3);
}

TEST(ConntrackGcTest, MaybeGcDisabledReturnsZero) {
  ConntrackMgr mgr;
  mgr.enabled = false;
  mgr.gc_interval_s = 30;
  EXPECT_EQ(mgr.MaybeRunGc(1'000'000'000ULL), 0);
}

TEST(ConntrackGcTest, GetStateIncludesGcFields) {
  ConntrackMgr mgr;
  mgr.enabled = true;
  mgr.timeout_s = 120;
  mgr.gc_interval_s = 15;
  mgr.total_evicted = 42;
  auto state = mgr.GetState();
  EXPECT_EQ(state["gc_interval_s"], 15);
  EXPECT_EQ(state["total_evicted"], 42);
}

TEST(ConntrackGcTest, SetStateUpdatesGcInterval) {
  ConntrackMgr mgr;
  nlohmann::json j = {{"gc_interval_s", 60}};
  EXPECT_TRUE(mgr.SetState(j));
  EXPECT_EQ(mgr.gc_interval_s, 60);
}

}  // namespace f
