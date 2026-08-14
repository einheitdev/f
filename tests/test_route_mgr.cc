/// @file test_route_mgr.cc
/// @brief The daemon's view of what a redirect did to each frame.
///
/// A `redirect to <zone>` either re-addressed the frame to a next hop
/// this box resolved, or handed it on carrying the destination MAC it
/// arrived with. Both put a frame on the cable; only one of them
/// reaches a socket on the far side. No capture can tell them apart —
/// a promiscuous AF_PACKET witness counts both, which is precisely how
/// 1822 unit cases and eleven hardware scenarios missed the difference
/// — so the counters here are the only place it is written down, and
/// they have to be readable when the map is absent as well as present.

#include <filesystem>
#include <fstream>
#include <random>
#include <string>

#include <gtest/gtest.h>

#include "f/route_mgr.h"

namespace f {
namespace {

class RouteMgrTest : public ::testing::Test {
 protected:
  void SetUp() override {
    std::random_device rd;
    root_ = std::filesystem::temp_directory_path() /
            ("f-route-" + std::to_string(rd()));
    std::filesystem::create_directories(root_ / "net" / "ipv4");
    mgr_.proc_dir = root_.string();
  }
  void TearDown() override {
    std::error_code ec;
    std::filesystem::remove_all(root_, ec);
  }

  void WriteForwarding(const char* value) {
    std::ofstream out(root_ / "net" / "ipv4" / "ip_forward",
                      std::ios::trunc);
    out << value << "\n";
  }

  std::filesystem::path root_;
  RouteMgr mgr_;
};

TEST_F(RouteMgrTest, WithoutAMapEveryCounterReadsZeroAndNothingThrows) {
  EXPECT_EQ(mgr_.stats_fd, -1);
  EXPECT_EQ(mgr_.Stat(kFwlRouteStatRouted), 0U);
  EXPECT_EQ(mgr_.Stat(kFwlRouteStatBridged), 0U);
  auto j = mgr_.GetState();
  EXPECT_FALSE(j["enabled"].get<bool>());
  EXPECT_EQ(j["routed"].get<uint64_t>(), 0U);
}

/// The section names both outcomes side by side on purpose. `routed`
/// alone cannot be read: zero routed is normal for a bridged zone hop
/// and catastrophic for a masquerading gateway, and only the pair says
/// which situation you are looking at.
TEST_F(RouteMgrTest, TheStateNamesRoutedAndBridgedTogether) {
  auto j = mgr_.GetState();
  EXPECT_TRUE(j.contains("routed"));
  EXPECT_TRUE(j.contains("bridged"));
  EXPECT_TRUE(j.contains("no_route"));
  EXPECT_TRUE(j.contains("no_neigh"));
  EXPECT_TRUE(j.contains("off_zone"));
  EXPECT_TRUE(j.contains("ttl_expired"));
  EXPECT_TRUE(j.contains("ip_forward"));
}

TEST_F(RouteMgrTest, ForwardingOnIsRead) {
  WriteForwarding("1");
  EXPECT_TRUE(mgr_.Forwarding());
  EXPECT_TRUE(mgr_.GetState()["ip_forward"].get<bool>());
}

/// The value is a property of the running kernel, not of the policy
/// that was loaded, so it has to be read fresh. A cached copy reports
/// the box as it was at load — which is the state an operator asking
/// "is this thing routing?" is least interested in, and which made the
/// hardware scenario disagree with itself when it turned forwarding
/// off as a control.
TEST_F(RouteMgrTest, ForwardingIsReReadRatherThanCachedAtLoad) {
  WriteForwarding("1");
  mgr_.CheckForwarding(true);
  ASSERT_TRUE(mgr_.GetState()["ip_forward"].get<bool>());
  WriteForwarding("0");
  EXPECT_FALSE(mgr_.GetState()["ip_forward"].get<bool>());
}

/// The condition the whole A2 finding is about: a policy that
/// redirects between zones, on a kernel that will not forward. The
/// datapath cannot resolve a next hop (bpf_fib_lookup answers
/// FWD_DISABLED) and degrades to forwarding frames with the MAC they
/// arrived carrying, which nothing on the wire reports.
TEST_F(RouteMgrTest, ForwardingOffIsSeenAndRecorded) {
  WriteForwarding("0");
  mgr_.CheckForwarding(true);
  EXPECT_FALSE(mgr_.Forwarding());
  EXPECT_FALSE(mgr_.GetState()["ip_forward"].get<bool>());
}

/// An unreadable knob is not the same as a knob set to 0, but for this
/// question it has to fail the same way: "I could not look" must not
/// be reported as "forwarding is on".
TEST_F(RouteMgrTest, AnUnreadableKnobIsNotTakenAsForwardingOn) {
  EXPECT_FALSE(mgr_.Forwarding());
  EXPECT_FALSE(mgr_.GetState()["ip_forward"].get<bool>());
}

/// A policy with no redirect at all does not need forwarding, and the
/// value is still read — the status line reports the box, not the
/// policy.
TEST_F(RouteMgrTest, APolicyThatCannotRedirectStillReportsTheKnob) {
  WriteForwarding("1");
  mgr_.CheckForwarding(false);
  EXPECT_TRUE(mgr_.GetState()["ip_forward"].get<bool>());
}

/// The watermarks exist so a drop is logged once rather than every
/// sweep. With no map behind them, Report() must be a no-op instead of
/// reporting an imaginary zero-to-zero transition every 30 seconds.
TEST_F(RouteMgrTest, ReportOnADisabledManagerSaysNothing) {
  mgr_.enabled = false;
  mgr_.Report();
  EXPECT_EQ(mgr_.reported_no_route, 0U);
  EXPECT_EQ(mgr_.reported_no_neigh, 0U);
}

}  // namespace
}  // namespace f
