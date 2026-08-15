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

constexpr uint64_t kOneSecondNs = 1000000000ULL;

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
  ASSERT_TRUE(mgr_.GetState()["ip_forward"].get<bool>());
  WriteForwarding("0");
  EXPECT_FALSE(mgr_.GetState()["ip_forward"].get<bool>());
}

/// An unreadable knob is not the same as a knob set to 0, but for this
/// question it has to fail the same way: "I could not look" must not
/// be reported as "forwarding is on".
TEST_F(RouteMgrTest, AnUnreadableKnobIsNotTakenAsForwardingOn) {
  EXPECT_FALSE(mgr_.Forwarding());
  EXPECT_FALSE(mgr_.GetState()["ip_forward"].get<bool>());
}

// ---------------------------------------------------------------
// Fail closed. The box forwards only while it filters.
//
// The measurement behind these: a provisioned box with its compiled
// bundle removed refused to start `fd`, attached nothing, said so —
// and forwarded anyway, because the sysctl drop-in had set the knob
// once at provisioning time and systemd reapplied it every boot. An
// unsolicited inbound connection the healthy box refused with zero
// frames on the inside wire completed with four.
// ---------------------------------------------------------------

/// The default is closed, before anything has been loaded or asked.
/// A manager that defaulted to wanting forwarding would open the box
/// for the whole window between construction and the attach failing.
TEST_F(RouteMgrTest, AFreshManagerWantsForwardingOffAndSaysWhy) {
  EXPECT_FALSE(mgr_.desired_forwarding);
  EXPECT_FALSE(mgr_.forwarding_reason.empty());
  auto j = mgr_.GetState();
  EXPECT_FALSE(j["forwarding_desired"].get<bool>());
  EXPECT_FALSE(j["forwarding_reason"].get<std::string>().empty());
}

TEST_F(RouteMgrTest, RaisingWritesTheKnobAndKeepsTheReason) {
  WriteForwarding("0");
  mgr_.SetForwarding(true, "cold boot: datapath armed on 3 "
                           "interface(s)");
  EXPECT_TRUE(mgr_.Forwarding());
  EXPECT_TRUE(mgr_.desired_forwarding);
  EXPECT_NE(mgr_.forwarding_reason.find("3 interface"),
            std::string::npos);
  EXPECT_TRUE(mgr_.GetState()["ip_forward"].get<bool>());
}

/// The reason survives even when the write changed nothing. An
/// operator reading `fctl status` on a box that is already in the
/// right state still needs to know which state that is and why.
TEST_F(RouteMgrTest, TheReasonIsKeptEvenWhenTheKnobDidNotMove) {
  WriteForwarding("0");
  mgr_.SetForwarding(false, "fd is stopping: XDP detached");
  EXPECT_FALSE(mgr_.Forwarding());
  EXPECT_NE(mgr_.GetState()["forwarding_reason"].get<std::string>()
                .find("XDP detached"),
            std::string::npos);
}

TEST_F(RouteMgrTest, LoweringClosesABoxThatWasForwarding) {
  WriteForwarding("1");
  ASSERT_TRUE(mgr_.Forwarding());
  mgr_.SetForwarding(false, "no interface is running an f program");
  EXPECT_FALSE(mgr_.Forwarding());
  EXPECT_FALSE(mgr_.GetState()["forwarding_desired"].get<bool>());
}

/// The finding itself, in one case: nothing is filtering and
/// something has opened the box. That must not stand, whoever did it.
TEST_F(RouteMgrTest, AnUnarmedBoxThatSomethingOpenedIsClosedAgain) {
  mgr_.SetForwarding(false, "datapath not armed");
  WriteForwarding("1");
  mgr_.MaybeReassertForwarding(kOneSecondNs);
  EXPECT_FALSE(mgr_.Forwarding());
  EXPECT_EQ(mgr_.forwarding_corrections, 1U);
  EXPECT_EQ(mgr_.GetState()["forwarding_corrections"].get<uint64_t>(),
            1U);
}

/// And the other direction is NOT symmetric, deliberately. An armed
/// box whose forwarding somebody turned off is left alone and
/// reported. Writing it back would make the daemon un-overridable by
/// the operator whose box it is, and would break the controls in the
/// hardware scenarios, several of which prove "these frames were on
/// the wire and no socket took one" by holding forwarding down under
/// a running fd.
TEST_F(RouteMgrTest, AnArmedBoxSomebodyClosedIsReportedNotFought) {
  WriteForwarding("0");
  mgr_.SetForwarding(true, "cold boot: datapath armed on 2 "
                           "interface(s)");
  ASSERT_TRUE(mgr_.Forwarding());
  WriteForwarding("0");
  mgr_.MaybeReassertForwarding(kOneSecondNs);
  EXPECT_FALSE(mgr_.Forwarding());
  EXPECT_EQ(mgr_.forwarding_corrections, 0U);
  EXPECT_TRUE(mgr_.forwarding_overridden);
  EXPECT_TRUE(mgr_.GetState()["forwarding_overridden"].get<bool>());
}

/// ...and the flag clears again, so a box that was closed by hand and
/// reopened by hand does not carry the alarm forever.
TEST_F(RouteMgrTest, TheOverrideFlagClearsWhenTheKnobComesBack) {
  WriteForwarding("0");
  mgr_.SetForwarding(true, "armed");
  WriteForwarding("0");
  mgr_.MaybeReassertForwarding(kOneSecondNs);
  ASSERT_TRUE(mgr_.forwarding_overridden);
  WriteForwarding("1");
  mgr_.MaybeReassertForwarding(kOneSecondNs + 10 * kOneSecondNs);
  EXPECT_FALSE(mgr_.forwarding_overridden);
}

/// The re-check is rate limited, so the sweep may call it every
/// iteration. Without the limit this is an open/read/close of a proc
/// file ten times a second forever.
TEST_F(RouteMgrTest, TheRecheckIsRateLimited) {
  mgr_.SetForwarding(false, "datapath not armed");
  mgr_.MaybeReassertForwarding(kOneSecondNs);
  WriteForwarding("1");
  // Well inside forwarding_recheck_s of the call above.
  mgr_.MaybeReassertForwarding(kOneSecondNs + 100000000ULL);
  EXPECT_TRUE(mgr_.Forwarding());
  EXPECT_EQ(mgr_.forwarding_corrections, 0U);
  // ...and past it, the correction happens.
  mgr_.MaybeReassertForwarding(kOneSecondNs +
                               6 * kOneSecondNs);
  EXPECT_FALSE(mgr_.Forwarding());
  EXPECT_EQ(mgr_.forwarding_corrections, 1U);
}

/// A knob that cannot be written is not a knob that was written. The
/// reason has to say so, because the status row built from it is the
/// only thing standing between an operator and a box they believe is
/// closed.
TEST_F(RouteMgrTest, AWriteThatFailsIsReportedRatherThanAssumed) {
  RouteMgr broken;
  broken.proc_dir = (root_ / "no" / "such").string();
  // create_directories will make the parent, so make the target a
  // directory instead: it exists and cannot be opened for writing.
  std::filesystem::create_directories(
      root_ / "no" / "such" / "net" / "ipv4" / "ip_forward");
  auto wrote = broken.WriteForwarding(false);
  EXPECT_FALSE(wrote.has_value());
  broken.SetForwarding(false, "fd is stopping");
  EXPECT_NE(broken.forwarding_reason.find("COULD NOT LOWER"),
            std::string::npos);
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
