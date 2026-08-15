/// @file test_tc_egress.cc
/// @brief The lifecycle around the egress conntrack tracker.
///
/// The hook itself is nine bounds checks and a map update, and the rig
/// is its oracle. The risk is the lifecycle: a SECOND attach point
/// going through cold boot, hot reload and pin reconciliation, which is
/// where several of this project's silent defects have come from. The
/// specific failure to close is a load that reports success having
/// attached to nothing — the exact defect the XDP path was given a rule
/// against, one layer over.
///
/// Everything here runs without root, bpffs or a NIC: it is the
/// manifest-to-decision derivation and the daemon's reporting, which is
/// where the decisions actually are.

#include <filesystem>
#include <fstream>
#include <random>
#include <string>

#include <gtest/gtest.h>

#include "f/egress_mgr.h"
#include "f/tc_egress.h"

namespace f {
namespace {

class TcEgressTest : public ::testing::Test {
 protected:
  void SetUp() override {
    std::random_device rd;
    dir_ = std::filesystem::temp_directory_path() /
           ("f-egress-" + std::to_string(rd()));
    std::filesystem::create_directories(dir_);
  }
  void TearDown() override {
    std::error_code ec;
    std::filesystem::remove_all(dir_, ec);
  }

  void WriteManifest(const std::string& body) {
    std::ofstream out(dir_ / "manifest.json");
    out << body;
  }

  std::filesystem::path dir_;
};

// --- what the manifest says ------------------------------------------

TEST_F(TcEgressTest, NoFieldMeansTheBundlePredatesTheTracker) {
  // The upgrade case, and the one that must not be silent. An `fd` with
  // this code running a bundle staged by an older `fwl` looks identical
  // to a correctly-tracking box from every counter and every status
  // line — while its own DNS replies are dropped by its own policy.
  WriteManifest(R"({"version":"0.4","programs":[]})");
  EXPECT_FALSE(BundleDeclaresEgressTracker(dir_.string()));
  EXPECT_EQ(BundleEgressObject(dir_.string()), "");
}

TEST_F(TcEgressTest, NullMeansThisPolicyNeedsNoTracker) {
  // Different from absent, deliberately: a policy that never reads
  // conntrack has nothing to track for, and warning about it every
  // load would train the operator to ignore the warning that matters.
  WriteManifest(
      R"({"version":"0.4","egress_tracker":null,"programs":[]})");
  EXPECT_FALSE(BundleDeclaresEgressTracker(dir_.string()));
}

TEST_F(TcEgressTest, DeclaredTrackerResolvesToAPathInTheBundle) {
  WriteManifest(R"({"version":"0.4","egress_tracker":{
      "source":"fwl_egress.bpf.c","object":"fwl_egress.bpf.o",
      "program":"fwl_egress_ct"}})");
  EXPECT_TRUE(BundleDeclaresEgressTracker(dir_.string()));
  EXPECT_EQ(BundleEgressObject(dir_.string()),
            (dir_ / "fwl_egress.bpf.o").string());
  EXPECT_EQ(BundleEgressProgram(dir_.string()), "fwl_egress_ct");
}

TEST_F(TcEgressTest, AMissingManifestDeclaresNothing) {
  EXPECT_FALSE(BundleDeclaresEgressTracker(dir_.string()));
  EXPECT_EQ(BundleEgressObject(dir_.string()), "");
}

TEST_F(TcEgressTest, AnUnparseableManifestDeclaresNothing) {
  WriteManifest("{not json");
  EXPECT_FALSE(BundleDeclaresEgressTracker(dir_.string()));
}

// --- the refusals ----------------------------------------------------

TEST_F(TcEgressTest, ATrackerWithNoCompiledObjectIsRefused) {
  // Same shape, same cause and same answer as a zone entry with
  // `"object": null` — a compile on a host without clang. Falling back
  // to "no tracker" here would be the whole defect: a firewall that
  // filters correctly and drops the replies to its own DNS.
  WriteManifest(R"({"version":"0.4","egress_tracker":{
      "source":"fwl_egress.bpf.c","object":null}})");
  EXPECT_TRUE(BundleDeclaresEgressTracker(dir_.string()));
  EXPECT_EQ(BundleEgressObject(dir_.string()), "");

  auto r = AttachEgressTracker(dir_.string(), "/sys/fs/bpf/f",
                               {EgressTarget{1, "lo"}});
  ASSERT_FALSE(r.has_value());
  EXPECT_EQ(r.error().code, BpfError::kLoadFailed);
  // The message has to name the consequence, not the file. An operator
  // reading "no compiled object" learns nothing about why their box
  // cannot resolve a name.
  EXPECT_NE(r.error().message.find("originates"), std::string::npos);
}

TEST_F(TcEgressTest, AttachingToZeroInterfacesIsAnError) {
  // The rule the XDP path gained after a load reported "1 zone
  // program(s)" — true of the program list, silent about attachment —
  // while every packet on the box flowed unfiltered. A second attach
  // point must never report success having attached to nothing, and
  // stating that as an outcome closes every route to it at once rather
  // than one cause at a time.
  WriteManifest(R"({"version":"0.4","egress_tracker":{
      "source":"fwl_egress.bpf.c","object":"fwl_egress.bpf.o"}})");
  auto r = AttachEgressTracker(dir_.string(), "/sys/fs/bpf/f", {});
  ASSERT_FALSE(r.has_value());
  EXPECT_EQ(r.error().code, BpfError::kAttachFailed);
}

TEST_F(TcEgressTest, ADeclaredTrackerWhoseObjectIsMissingIsRefused) {
  // The manifest names an object that is not in the bundle. Nothing
  // downstream can recover from that, and carrying on would produce
  // exactly the "attached to nothing, reported ok" state.
  WriteManifest(R"({"version":"0.4","egress_tracker":{
      "source":"fwl_egress.bpf.c","object":"absent.bpf.o"}})");
  auto r = AttachEgressTracker(dir_.string(), "/sys/fs/bpf/f",
                               {EgressTarget{1, "lo"}});
  ASSERT_FALSE(r.has_value());
  EXPECT_EQ(r.error().code, BpfError::kLoadFailed);
}

TEST_F(TcEgressTest, AnUnattachedTrackerReportsItself) {
  EgressTracker t;
  EXPECT_FALSE(t.Attached());
  t.ifindexes.push_back(3);
  EXPECT_TRUE(t.Attached());
}

// --- what the daemon reports -----------------------------------------

TEST(EgressMgrTest, OffIsThreeDifferentBoxesAndSaysWhich) {
  // "enabled": false covers a policy that asks no conntrack question
  // (nothing to track for, fine), a bundle compiled before the tracker
  // existed (unknown, and possibly dropping its own DNS), and a hook
  // removed behind the daemon's back. One flag would make them
  // indistinguishable from the CLI, which is the exact shape of the
  // defect this feature closes.
  EgressMgr idle;
  idle.tracker_declared = false;
  idle.bundle_predates_tracker = false;
  auto ji = idle.GetState();
  EXPECT_FALSE(ji["tracker_declared"]);
  EXPECT_FALSE(ji["bundle_predates_tracker"]);

  EgressMgr old_bundle;
  old_bundle.bundle_predates_tracker = true;
  auto jo = old_bundle.GetState();
  EXPECT_FALSE(jo["enabled"]);
  EXPECT_TRUE(jo["bundle_predates_tracker"]);
}

TEST(EgressMgrTest, ANatOnlyPolicyIsNotAConntrackReader) {
  // The distinction that cost a healthy box a red status row and an
  // ERROR per load. Every NAT bundle carries the `conntrack` map —
  // fwl_snat_egress inserts the post-NAT tuple — so deriving "this
  // policy reads conntrack state" from the map's presence said yes for
  // a masquerade-only policy that never asks. The manifest's
  // `egress_tracker` key is the compiler's own answer, and it is what
  // the daemon reads.
  EgressMgr nat_only;
  nat_only.tracker_declared = false;
  nat_only.bundle_predates_tracker = false;
  nat_only.enabled = false;
  auto j = nat_only.GetState();
  EXPECT_FALSE(j["tracker_declared"]);
  EXPECT_FALSE(j["bundle_predates_tracker"]);
}

TEST(EgressMgrTest, EveryCounterIsReadableWithNoMap) {
  // A section that throws or omits rows when the map is absent is a
  // section nobody can write a check against.
  EgressMgr mgr;
  auto j = mgr.GetState();
  for (const char* k : {"seen", "not_local", "untracked", "tracked",
                        "refreshed", "refused"}) {
    ASSERT_TRUE(j.contains(k)) << k;
    EXPECT_EQ(j[k].get<uint64_t>(), 0U) << k;
  }
  EXPECT_TRUE(j["interfaces"].is_array());
}

TEST(EgressMgrTest, ItNamesTheInterfacesItIsOn) {
  // Not the count of anything that loaded. "Attached to which ports" is
  // the only number that answers whether box-originated tracking is in
  // the path.
  EgressMgr mgr;
  mgr.enabled = true;
  mgr.interfaces = {"enp1s0f1", "enp1s0f2"};
  auto j = mgr.GetState();
  ASSERT_EQ(j["interfaces"].size(), 2U);
  EXPECT_EQ(j["interfaces"][0], "enp1s0f1");
}

TEST(EgressMgrTest, ReportIsSilentWhileDisabled) {
  EgressMgr mgr;
  mgr.enabled = false;
  mgr.Report();
  EXPECT_EQ(mgr.reported_refusals, 0U);
}

TEST(EgressMgrTest, TheStatsSlotsAreTheOnesTheEmitterNumbers) {
  // The tally is a per-CPU array addressed by these constants, and the
  // emitter's egress header numbers them independently. A silent
  // renumbering would attribute every refusal to "untracked" — a row
  // nobody reads — and the failure would go quiet again.
  EXPECT_EQ(kFwlEgressStatSeen, 0U);
  EXPECT_EQ(kFwlEgressStatNotLocal, 1U);
  EXPECT_EQ(kFwlEgressStatUntracked, 2U);
  EXPECT_EQ(kFwlEgressStatTracked, 3U);
  EXPECT_EQ(kFwlEgressStatRefreshed, 4U);
  EXPECT_EQ(kFwlEgressStatRefused, 5U);
  EXPECT_EQ(kFwlEgressStatSlots, 6U);
}

}  // namespace
}  // namespace f
