/// @file test_neigh_mgr.cc
/// @brief When fd asks the kernel to resolve a next hop, and when it
///        refuses to.
///
/// The finding: a masquerading box cannot resolve a next hop from the
/// traffic it forwards. `bpf_fib_lookup` answers NO_NEIGH, the datapath
/// hands the frame to the stack so the stack will ARP, and the stack
/// throws it out as a martian first — its source is one of this box's
/// own addresses now. Measured under qemu on 2026-08-15: seven
/// forwarded frames dropped, `routed` 0, nothing on the far wire, and
/// afterwards NO neighbour entry of any state for that next hop.
///
/// So the datapath records the address and this component drains it.
/// Everything here is about the two decisions that make that safe:
/// WHICH addresses may be solicited, and HOW OFTEN. The mechanism —
/// rtnetlink NTF_USE, and whether an ARP really goes out — is not
/// testable without a kernel and is measured in
/// `fwl/tests/system/cold_neighbour_netns.py` instead, which is the
/// split `fail_closed_netns.py` uses for `/proc/sys`.

#include <gtest/gtest.h>

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "f/neigh_mgr.h"

namespace {

using f::NeighKernel;
using f::NeighMgr;
using f::NeighState;
using f::NeighWanted;
using f::NextHop;

constexpr uint64_t kSec = 1000000000ULL;

/// The datapath's queue, in memory.
class FakeWanted : public NeighWanted {
 public:
  std::map<NextHop, uint64_t> rows;
  std::vector<NextHop> forgotten;

  auto Entries()
      -> std::vector<std::pair<NextHop, uint64_t>> override {
    return {rows.begin(), rows.end()};
  }

  auto Forget(const NextHop& nh) -> void override {
    forgotten.push_back(nh);
    rows.erase(nh);
  }
};

/// The kernel's neighbour table, in memory. `asked` is the whole point:
/// this file is mostly about which addresses end up in it.
class FakeKernel : public NeighKernel {
 public:
  std::map<NextHop, NeighState> table;
  std::vector<NextHop> asked;
  bool refuse = false;
  /// Resolve a next hop the moment it is solicited, which is what a
  /// working segment does. Off by default so a test has to opt in.
  bool answers = false;

  auto State(const NextHop& nh) -> NeighState override {
    auto it = table.find(nh);
    return it == table.end() ? NeighState::kAbsent : it->second;
  }

  auto Solicit(const NextHop& nh)
      -> std::expected<void, std::string> override {
    asked.push_back(nh);
    if (refuse) return std::unexpected("operation not permitted");
    if (answers) table[nh] = NeighState::kUsable;
    return {};
  }
};

/// 10.10.2.2 out of ifindex 3 — the address and the port from the
/// measured failure, so the numbers in this file are the numbers in the
/// finding.
auto Hop(int ifindex = 3, uint8_t last = 2) -> NextHop {
  return NextHop{ifindex, static_cast<uint32_t>(10 | (10 << 8) |
                                                (2 << 16) |
                                                (last << 24))};
}

class NeighMgrTest : public ::testing::Test {
 protected:
  void SetUp() override {
    auto wanted = std::make_unique<FakeWanted>();
    auto kernel = std::make_unique<FakeKernel>();
    wanted_ = wanted.get();
    kernel_ = kernel.get();
    mgr_.wanted = std::move(wanted);
    mgr_.kernel = std::move(kernel);
    mgr_.enabled = true;
    // The two data-plane ports of the measured box. The management port
    // it is administered over is deliberately NOT here.
    mgr_.datapath_ifindexes = {2, 3};
  }

  NeighMgr mgr_;
  FakeWanted* wanted_ = nullptr;
  FakeKernel* kernel_ = nullptr;
};

TEST_F(NeighMgrTest, AnAbsentNextHopIsSolicited) {
  // The measured state, exactly: the datapath wanted a next hop and the
  // table holds no entry of ANY kind for it, because nothing ever
  // asked. This is the one line of behaviour the whole change exists
  // for.
  wanted_->rows[Hop()] = 1000;
  mgr_.Resolve(2 * kSec);
  ASSERT_EQ(kernel_->asked.size(), 1u);
  EXPECT_EQ(kernel_->asked[0], Hop());
  EXPECT_EQ(mgr_.solicited, 1u);
  // Still outstanding: asking is not answering, and a component that
  // counted the ask as the cure would report a black-holed box as
  // healthy.
  ASSERT_EQ(mgr_.outstanding.size(), 1u);
  EXPECT_EQ(mgr_.outstanding[0], Hop());
  EXPECT_TRUE(wanted_->forgotten.empty());
}

TEST_F(NeighMgrTest, AResolvedNextHopIsForgottenAndLeftAlone) {
  // The success path. Once the entry is usable the datapath's next FIB
  // lookup returns a dmac, so there is nothing left to do and nothing
  // left to report — and above all nothing left to ARP for.
  wanted_->rows[Hop()] = 1000;
  kernel_->table[Hop()] = NeighState::kUsable;
  mgr_.Resolve(2 * kSec);
  EXPECT_TRUE(kernel_->asked.empty());
  EXPECT_EQ(mgr_.resolved, 1u);
  EXPECT_TRUE(mgr_.outstanding.empty());
  ASSERT_EQ(wanted_->forgotten.size(), 1u);
  EXPECT_EQ(wanted_->forgotten[0], Hop());
}

TEST_F(NeighMgrTest, AnIncompleteNextHopIsStillSolicited) {
  // An entry exists and is not usable — INCOMPLETE, or FAILED after the
  // kernel gave up. `bpf_fib_lookup` will not take a dmac from it, so
  // as far as the datapath is concerned it is no better than no entry
  // at all and the ask has to be repeated.
  //
  // (Which NUD states count as usable is decided in the rtnetlink
  // implementation against the kernel's own NUD_VALID, and is measured
  // in cold_neighbour_netns.py rather than asserted against a fake that
  // would simply agree with it here.)
  wanted_->rows[Hop()] = 1000;
  kernel_->table[Hop()] = NeighState::kIncomplete;
  mgr_.Resolve(2 * kSec);
  EXPECT_EQ(kernel_->asked.size(), 1u);
  EXPECT_EQ(mgr_.resolved, 0u);
}

TEST_F(NeighMgrTest, AnInterfaceTheDatapathIsNotOnIsNeverSolicited) {
  // THE safety bound. This daemon may not put ARP on a wire because a
  // map had an unexpected row in it, and the wire it must never put ARP
  // on is the one the box is administered over — the rig's rule is that
  // the management port is never touched, and this is that rule made
  // structural rather than argued.
  //
  // Unreachable through the datapath, which records only a next hop out
  // of the interface the policy's own redirect named. That is exactly
  // why it is a hard gate here: the interesting property is that a
  // future path which forgets cannot reach the wire through this one.
  NextHop mgmt{9, Hop().addr_be};
  wanted_->rows[mgmt] = 1000;
  mgr_.Resolve(2 * kSec);
  EXPECT_TRUE(kernel_->asked.empty());
  EXPECT_EQ(mgr_.off_datapath, 1u);
  EXPECT_TRUE(mgr_.outstanding.empty());
  ASSERT_EQ(wanted_->forgotten.size(), 1u);
  EXPECT_EQ(wanted_->forgotten[0], mgmt);
}

TEST_F(NeighMgrTest, TheGateIsTheInterfaceAndNotTheAddress) {
  // The control for the test above: the same ADDRESS on an interface
  // the datapath is on is solicited. Without this, a gate that rejected
  // everything would pass the previous test and disable the feature.
  wanted_->rows[NextHop{9, Hop().addr_be}] = 1000;
  wanted_->rows[Hop(2)] = 1000;
  mgr_.Resolve(2 * kSec);
  ASSERT_EQ(kernel_->asked.size(), 1u);
  EXPECT_EQ(kernel_->asked[0].ifindex, 2);
}

TEST_F(NeighMgrTest, OneNextHopIsSolicitedOncePerInterval) {
  // The rate bound, from this side. The kernel throttles too — asking
  // it to resolve an entry that is already probing does nothing — but a
  // bound that lives only in the kernel's internals is not a bound this
  // daemon can state, and the daemon is the thing being trusted with a
  // customer's wire.
  wanted_->rows[Hop()] = 1000;
  mgr_.solicit_interval_s = 1;
  mgr_.Resolve(10 * kSec);
  mgr_.Resolve(10 * kSec + kSec / 2);
  EXPECT_EQ(kernel_->asked.size(), 1u);
  mgr_.Resolve(12 * kSec);
  EXPECT_EQ(kernel_->asked.size(), 2u);
}

TEST_F(NeighMgrTest, TheDrainItselfIsRateLimited) {
  // `MaybeResolve` is what the engine's sweep calls, on a loop that
  // turns over every 100 ms. The interval has to be short enough that a
  // TCP client's first retransmit finds the neighbour — that is the
  // difference between one lost SYN and a connection that times out —
  // and it still must not be every pass.
  wanted_->rows[Hop()] = 1000;
  mgr_.drain_interval_ms = 200;
  mgr_.MaybeResolve(5 * kSec);
  mgr_.MaybeResolve(5 * kSec + 50000000ULL);
  EXPECT_EQ(kernel_->asked.size(), 1u);
}

TEST_F(NeighMgrTest, NothingIsDrainedWhileDisabled) {
  // A bundle with no queue in it (compiled before the map existed) must
  // not be read through a stale fd, and a disabled manager must not
  // talk to the kernel at all.
  mgr_.enabled = false;
  wanted_->rows[Hop()] = 1000;
  mgr_.MaybeResolve(5 * kSec);
  EXPECT_TRUE(kernel_->asked.empty());
}

TEST_F(NeighMgrTest, ANextHopTheDatapathHasStoppedWantingIsForgotten) {
  // Otherwise this daemon solicits a gateway that was replaced for the
  // life of the process — traffic on somebody's wire for an address no
  // loaded policy routes to, which is precisely what the bounds exist
  // to prevent.
  mgr_.stale_after_s = 60;
  wanted_->rows[Hop()] = 1 * kSec;
  mgr_.Resolve(90 * kSec);
  EXPECT_TRUE(kernel_->asked.empty());
  EXPECT_EQ(mgr_.forgotten_stale, 1u);
  ASSERT_EQ(wanted_->forgotten.size(), 1u);
}

TEST_F(NeighMgrTest, AFreshlyWantedNextHopIsNotStale) {
  // The control for the one above. A staleness rule with the comparison
  // the wrong way round would forget every entry the moment it arrived
  // and this feature would do nothing, with all its counters at zero
  // and nothing to see.
  mgr_.stale_after_s = 60;
  wanted_->rows[Hop()] = 89 * kSec;
  mgr_.Resolve(90 * kSec);
  EXPECT_EQ(kernel_->asked.size(), 1u);
  EXPECT_EQ(mgr_.forgotten_stale, 0u);
}

TEST_F(NeighMgrTest, ARefusedSolicitationIsCountedAndStaysOutstanding) {
  // Netlink refusing is not the next hop answering. The failure has to
  // be visible, and the address has to stay on the screen.
  kernel_->refuse = true;
  wanted_->rows[Hop()] = 1000;
  mgr_.Resolve(2 * kSec);
  EXPECT_EQ(mgr_.failed, 1u);
  EXPECT_EQ(mgr_.solicited, 0u);
  ASSERT_EQ(mgr_.outstanding.size(), 1u);
}

TEST_F(NeighMgrTest, AWorkingSegmentCostsOneSolicitationAndGoesQuiet) {
  // End to end over the fakes, in the order the real thing runs: the
  // datapath records a hop nothing has ever ARPed for, fd asks once,
  // the segment answers, and the next drain has nothing to do. The
  // last assertion is the one that matters — a component that kept
  // asking after the answer arrived would be an ARP source on a
  // customer's network forever.
  kernel_->answers = true;
  wanted_->rows[Hop()] = 1000;
  mgr_.Resolve(2 * kSec);
  EXPECT_EQ(kernel_->asked.size(), 1u);
  mgr_.Resolve(20 * kSec);
  EXPECT_EQ(kernel_->asked.size(), 1u);
  EXPECT_EQ(mgr_.resolved, 1u);
  EXPECT_TRUE(mgr_.outstanding.empty());
  EXPECT_TRUE(wanted_->rows.empty());
}

TEST_F(NeighMgrTest, TheStateNamesTheAddressAndNotJustACount) {
  // `fctl status` renders this. "1 unresolved" sends an operator
  // looking; the address and the port tell them which cable.
  wanted_->rows[Hop()] = 1000;
  mgr_.Resolve(2 * kSec);
  auto st = mgr_.GetState();
  ASSERT_EQ(st["unresolved"].size(), 1u);
  EXPECT_EQ(st["unresolved"][0]["address"], "10.10.2.2");
  EXPECT_EQ(st["unresolved"][0]["ifindex"], 3);
  EXPECT_EQ(st["solicited"], 1u);
}

TEST_F(NeighMgrTest, ResolvedNextHopsLeaveNothingOnTheScreen) {
  // The vacuity control for the row: a box with nothing to resolve must
  // not render a permanent warning about its ARP table. Every test
  // above would pass against a component that reported every next hop
  // it had ever seen as outstanding.
  kernel_->answers = true;
  wanted_->rows[Hop()] = 1000;
  mgr_.Resolve(2 * kSec);
  mgr_.Resolve(4 * kSec);
  EXPECT_TRUE(mgr_.GetState()["unresolved"].empty());
}

}  // namespace
