/// @file test_bundle_guard.cc
/// @brief The anti-lockout guard on the bundle load path.
///
/// The property under test is not "a bad bundle produces an error".
/// The loader already did that, and it was never the failure that
/// loses a box. The failure is the one measured on the rig on
/// 2026-08-23: a load that pins every core, schedules nothing in
/// userspace, and ends in a watchdog reset — with `fd.service` set to
/// `Restart=on-failure`, reading whatever `current` points at, ordered
/// ahead of sshd. No error is returned because nothing returns.
///
/// So every test here simulates the daemon dying WITHOUT saying
/// anything: `Begin` is called and `Commit` never is, which is exactly
/// what a wedged board leaves behind. What has to hold is that the
/// second such start is the last one, and that the box comes up on
/// something afterwards.

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <string>

#include "f/bundle_guard.h"
#include "f/engine.h"

namespace f {
namespace {

namespace fs = std::filesystem;

class BundleGuardTest : public ::testing::Test {
 protected:
  void SetUp() override {
    root_ = fs::temp_directory_path() /
            std::format("f-guard-{}-{}", ::getpid(),
                        ::testing::UnitTest::GetInstance()
                            ->current_test_info()->name());
    fs::remove_all(root_);
    fs::create_directories(root_);
    cfg_.bundle_dir = root_.string();
  }
  void TearDown() override {
    std::error_code ec;
    fs::remove_all(root_, ec);
  }

  /// A bundle directory that looks like something `fwl compile` wrote.
  auto Stage(const std::string& version) -> void {
    fs::create_directories(root_ / version);
    std::ofstream(root_ / version / "manifest.json") << "{}";
  }
  auto SetCurrent(const std::string& version) -> void {
    auto res = PointCurrentAt(root_.string(), version);
    ASSERT_TRUE(res.has_value()) << res.error();
  }
  /// One start that never reaches an attached datapath, i.e. the box
  /// went away between these two lines.
  auto StartAndVanish() -> GuardDecision {
    return BundleGuardBegin(cfg_);
  }

  fs::path root_;
  GuardConfig cfg_;
};

TEST_F(BundleGuardTest, FirstStartOfAFreshBundleJustProceeds) {
  Stage("v1");
  SetCurrent("v1");
  auto d = BundleGuardBegin(cfg_);
  EXPECT_EQ(d.verdict, GuardVerdict::kProceed);
  EXPECT_EQ(d.version, "v1");
  EXPECT_EQ(d.load_dir, (root_ / "v1").string());
  // Nothing to warn about on a first attempt.
  EXPECT_TRUE(d.reason.empty()) << d.reason;
}

TEST_F(BundleGuardTest, ASuccessfulStartLeavesNoAttemptBehind) {
  Stage("v1");
  SetCurrent("v1");
  BundleGuardBegin(cfg_);
  ASSERT_TRUE(BundleGuardCommit(cfg_, "v1").has_value());
  EXPECT_FALSE(ReadAttemptRecord(cfg_).present);
  EXPECT_EQ(LastKnownGood(root_.string()), "v1");
  // ...and the next start is a first start again, however many times
  // it happens. A counter that only ever climbs would quarantine a
  // healthy box after enough reboots.
  for (int i = 0; i < 5; ++i) {
    auto d = BundleGuardBegin(cfg_);
    ASSERT_EQ(d.verdict, GuardVerdict::kProceed);
    ASSERT_TRUE(BundleGuardCommit(cfg_, "v1").has_value());
  }
}

TEST_F(BundleGuardTest, TheAttemptIsRecordedBeforeTheLoadNotAfterIt) {
  // This is the whole mechanism. `Begin` returns kProceed and the
  // record already says an attempt is outstanding — because the caller
  // may never come back to tell us anything.
  Stage("v1");
  SetCurrent("v1");
  auto d = BundleGuardBegin(cfg_);
  ASSERT_EQ(d.verdict, GuardVerdict::kProceed);
  auto r = ReadAttemptRecord(cfg_);
  EXPECT_TRUE(r.present);
  EXPECT_EQ(r.version, "v1");
  EXPECT_EQ(r.attempts, 1);
  EXPECT_TRUE(fs::exists(root_ / ".load-attempt.json"));
}

TEST_F(BundleGuardTest, ABundleThatWedgesTheBoxIsQuarantinedOnTheThirdBoot) {
  Stage("good");
  SetCurrent("good");
  BundleGuardBegin(cfg_);
  ASSERT_TRUE(BundleGuardCommit(cfg_, "good").has_value());

  Stage("bad");
  SetCurrent("bad");
  // Boot 1 and boot 2: the daemon starts and the board goes away.
  ASSERT_EQ(StartAndVanish().verdict, GuardVerdict::kProceed);
  ASSERT_EQ(StartAndVanish().verdict, GuardVerdict::kProceed);
  // Boot 3 does not touch the bundle at all.
  auto d = BundleGuardBegin(cfg_);
  EXPECT_EQ(d.verdict, GuardVerdict::kFallback);
  EXPECT_EQ(d.quarantined, "bad");
  EXPECT_EQ(d.version, "good");
  EXPECT_EQ(d.load_dir, (root_ / "good").string());
  EXPECT_NE(d.reason.find("bad"), std::string::npos) << d.reason;
  EXPECT_NE(d.reason.find("good"), std::string::npos) << d.reason;
  // And `current` is moved off the trap, so losing the attempt record
  // does not re-arm it. (EngineInit does the move; the guard exposes
  // the primitive and this asserts it works.)
  ASSERT_TRUE(PointCurrentAt(root_.string(), d.version).has_value());
  EXPECT_EQ(CurrentVersion(root_.string()), "good");
}

TEST_F(BundleGuardTest, TheFallbackGetsItsOwnAttemptCountNotAFreeRide) {
  // A last-known-good can stop being good — a kernel upgrade it no
  // longer loads under, a pin it can no longer reuse. If the fallback
  // were not counted, the box would loop on the fallback instead of on
  // `current` and nothing would be better.
  Stage("good");
  SetCurrent("good");
  BundleGuardBegin(cfg_);
  ASSERT_TRUE(BundleGuardCommit(cfg_, "good").has_value());
  Stage("bad");
  SetCurrent("bad");
  StartAndVanish();
  StartAndVanish();
  auto d = BundleGuardBegin(cfg_);
  ASSERT_EQ(d.verdict, GuardVerdict::kFallback);
  auto r = ReadAttemptRecord(cfg_);
  EXPECT_EQ(r.version, "good");
  EXPECT_EQ(r.attempts, 1);
}

TEST_F(BundleGuardTest, AFallbackThatAlsoWedgesEndsInARefusalNotALoop) {
  Stage("good");
  SetCurrent("good");
  BundleGuardBegin(cfg_);
  ASSERT_TRUE(BundleGuardCommit(cfg_, "good").has_value());
  Stage("bad");
  SetCurrent("bad");
  StartAndVanish();
  StartAndVanish();
  auto fell_back = BundleGuardBegin(cfg_);
  ASSERT_EQ(fell_back.verdict, GuardVerdict::kFallback);
  ASSERT_TRUE(PointCurrentAt(root_.string(), fell_back.version)
                  .has_value());
  // The fallback wedges too: one more start and it has used its two.
  ASSERT_EQ(StartAndVanish().verdict, GuardVerdict::kProceed);
  auto d = BundleGuardBegin(cfg_);
  EXPECT_EQ(d.verdict, GuardVerdict::kRefuse);
  EXPECT_TRUE(d.load_dir.empty());
  EXPECT_NE(d.reason.find("no last-known-good"), std::string::npos)
      << d.reason;
}

TEST_F(BundleGuardTest, FailClosedRefusesRatherThanRunSomethingElse) {
  cfg_.policy = GuardPolicy::kFailClosed;
  Stage("good");
  SetCurrent("good");
  BundleGuardBegin(cfg_);
  ASSERT_TRUE(BundleGuardCommit(cfg_, "good").has_value());
  Stage("bad");
  SetCurrent("bad");
  StartAndVanish();
  StartAndVanish();
  auto d = BundleGuardBegin(cfg_);
  EXPECT_EQ(d.verdict, GuardVerdict::kRefuse);
  // The last-known-good is still there and still named; the policy is
  // what declined to use it, and the message says so.
  EXPECT_EQ(LastKnownGood(root_.string()), "good");
  EXPECT_NE(d.reason.find("fail-closed"), std::string::npos)
      << d.reason;
}

TEST_F(BundleGuardTest, WithNoLastKnownGoodTheAnswerIsRefuseNotRetry) {
  Stage("bad");
  SetCurrent("bad");
  StartAndVanish();
  StartAndVanish();
  auto d = BundleGuardBegin(cfg_);
  EXPECT_EQ(d.verdict, GuardVerdict::kRefuse);
  EXPECT_NE(d.reason.find("verify-bundle"), std::string::npos)
      << d.reason;
}

TEST_F(BundleGuardTest, StagingANewBundleClearsTheOldOnesHistory) {
  // The count is per version. An operator who fixes the policy and
  // recompiles gets a clean slate, without having to know that a
  // hidden file exists.
  Stage("bad");
  SetCurrent("bad");
  StartAndVanish();
  StartAndVanish();
  Stage("fixed");
  SetCurrent("fixed");
  auto d = BundleGuardBegin(cfg_);
  EXPECT_EQ(d.verdict, GuardVerdict::kProceed);
  EXPECT_EQ(d.version, "fixed");
  EXPECT_EQ(ReadAttemptRecord(cfg_).attempts, 1);
}

TEST_F(BundleGuardTest, MaxAttemptsOfOneQuarantinesAfterASingleWedge) {
  cfg_.max_attempts = 1;
  Stage("good");
  SetCurrent("good");
  BundleGuardBegin(cfg_);
  ASSERT_TRUE(BundleGuardCommit(cfg_, "good").has_value());
  Stage("bad");
  SetCurrent("bad");
  ASSERT_EQ(StartAndVanish().verdict, GuardVerdict::kProceed);
  EXPECT_EQ(BundleGuardBegin(cfg_).verdict, GuardVerdict::kFallback);
}

TEST_F(BundleGuardTest, ADanglingLastKnownGoodIsNotAFallback) {
  // Pruning used to be free to delete any bundle `current` did not
  // point at. If it takes the fallback with it, the guard must not
  // report a directory that is no longer there as a recovery path.
  Stage("good");
  SetCurrent("good");
  BundleGuardBegin(cfg_);
  ASSERT_TRUE(BundleGuardCommit(cfg_, "good").has_value());
  std::error_code ec;
  fs::remove_all(root_ / "good", ec);
  EXPECT_EQ(LastKnownGood(root_.string()), "");
  Stage("bad");
  SetCurrent("bad");
  StartAndVanish();
  StartAndVanish();
  EXPECT_EQ(BundleGuardBegin(cfg_).verdict, GuardVerdict::kRefuse);
}

TEST_F(BundleGuardTest, ALoaderThatManagedToExplainItselfIsQuoted) {
  Stage("bad");
  SetCurrent("bad");
  StartAndVanish();
  BundleGuardNoteFailure(cfg_, "bad", "LoadZoneBundle: attached to 0");
  auto d = BundleGuardBegin(cfg_);
  ASSERT_EQ(d.verdict, GuardVerdict::kProceed);
  EXPECT_NE(d.reason.find("attached to 0"), std::string::npos)
      << d.reason;
  auto refused = BundleGuardBegin(cfg_);
  ASSERT_EQ(refused.verdict, GuardVerdict::kRefuse);
  EXPECT_NE(refused.reason.find("attached to 0"), std::string::npos)
      << refused.reason;
}

TEST_F(BundleGuardTest, ASilentDeathSaysSoRatherThanInventingAReason) {
  // The interesting case, and the one that must not read like a
  // missing field: the daemon never got to explain itself.
  Stage("bad");
  SetCurrent("bad");
  StartAndVanish();
  StartAndVanish();
  auto d = BundleGuardBegin(cfg_);
  ASSERT_EQ(d.verdict, GuardVerdict::kRefuse);
  EXPECT_NE(d.reason.find("never lived long enough"),
            std::string::npos)
      << d.reason;
}

TEST_F(BundleGuardTest, NoteFailureDoesNotAddAnAttemptOfItsOwn) {
  // `Begin` owns the count. If `NoteFailure` also incremented it, a
  // clean refusal — the case the loader DOES report — would burn two
  // attempts and quarantine a bundle after one boot.
  Stage("bad");
  SetCurrent("bad");
  BundleGuardBegin(cfg_);
  BundleGuardNoteFailure(cfg_, "bad", "manifest names no programs");
  EXPECT_EQ(ReadAttemptRecord(cfg_).attempts, 1);
}

TEST_F(BundleGuardTest, ACorruptRecordIsTreatedAsUnproven) {
  Stage("bad");
  SetCurrent("bad");
  std::ofstream(root_ / ".load-attempt.json") << "{not json";
  auto r = ReadAttemptRecord(cfg_);
  EXPECT_TRUE(r.present);
  EXPECT_GE(r.attempts, cfg_.max_attempts);
  EXPECT_EQ(BundleGuardBegin(cfg_).verdict, GuardVerdict::kRefuse);
}

TEST_F(BundleGuardTest, NothingStagedIsLeftForTheLoaderToComplainAbout) {
  // The guard has nothing useful to say about an empty bundle root and
  // the loader has a much better sentence for it. Proceeding is right;
  // inventing a quarantine here would bury the real message.
  auto d = BundleGuardBegin(cfg_);
  EXPECT_EQ(d.verdict, GuardVerdict::kProceed);
  EXPECT_EQ(d.version, "");
}

// --- and the same thing through EngineInit --------------------------
//
// The unit tests above check the bookkeeping. These check that the
// daemon's own start path is wired to it: that a quarantined `current`
// is not opened, that the fallback is the directory actually loaded,
// and that the symlink is moved so losing the record does not re-arm
// the trap.

class GuardEngineTest : public BundleGuardTest {
 protected:
  /// An Engine whose forwarding knob is a file in the scratch tree.
  /// Not a convenience: EngineInit WRITES ip_forward, and this suite
  /// is run as root on the rig.
  auto MakeEngine(Engine* e) -> void {
    e->route.proc_dir = (root_ / "proc-sys").string();
    fs::create_directories(root_ / "proc-sys" / "net" / "ipv4");
    std::ofstream(root_ / "proc-sys" / "net" / "ipv4" / "ip_forward")
        << "1\n";
    e->guard.max_attempts = cfg_.max_attempts;
    e->guard.policy = cfg_.policy;
  }
  /// A bundle whose manifest is well-formed and whose object is not
  /// there, so the load fails after the guard has had its say.
  auto StageLoadable(const std::string& version) -> void {
    fs::create_directories(root_ / version);
    std::ofstream(root_ / version / "manifest.json")
        << R"({"version":"0.4",)"
           R"("zones":[{"name":"wan","interfaces":["lo"]}],)"
           R"("programs":[{"zone":"wan","source":"wan.bpf.c",)"
           R"("object":"wan.bpf.o"}]})";
  }
  static constexpr const char* kSock = "ipc:///tmp/f-guard-test.sock";
};

TEST_F(GuardEngineTest, EngineInitRecordsAnAttemptBeforeItLoads) {
  StageLoadable("v1");
  SetCurrent("v1");
  Engine e;
  MakeEngine(&e);
  auto res = EngineInit(e, kSock, "/sys/fs/bpf/f-guard-test",
                        root_.string());
  ASSERT_FALSE(res);
  auto r = ReadAttemptRecord(cfg_);
  EXPECT_TRUE(r.present);
  EXPECT_EQ(r.version, "v1");
  EXPECT_EQ(r.attempts, 1);
  // The loader got far enough to say why, so the record carries it.
  EXPECT_FALSE(r.last_error.empty());
}

TEST_F(GuardEngineTest, AQuarantinedCurrentIsReplacedByTheFallback) {
  StageLoadable("good");
  SetCurrent("good");
  // "good" is the last-known-good by fiat: this test is about the
  // fallback path, not about how the marker got written (that is
  // ASuccessfulStartLeavesNoAttemptBehind).
  ASSERT_TRUE(BundleGuardCommit(cfg_, "good").has_value());
  StageLoadable("bad");
  SetCurrent("bad");
  StartAndVanish();
  StartAndVanish();

  Engine e;
  MakeEngine(&e);
  auto res = EngineInit(e, kSock, "/sys/fs/bpf/f-guard-test",
                        root_.string());
  // The load still fails — there is no real object in this scratch
  // tree — but it failed trying the FALLBACK, and `current` was moved.
  ASSERT_FALSE(res);
  EXPECT_EQ(CurrentVersion(root_.string()), "good");
  EXPECT_TRUE(e.guard_status.degraded);
  EXPECT_EQ(e.guard_status.running, "good");
  EXPECT_NE(e.guard_status.reason.find("bad"), std::string::npos)
      << e.guard_status.reason;
}

TEST_F(GuardEngineTest, FailClosedRefusesBeforeOpeningTheBundle) {
  cfg_.policy = GuardPolicy::kFailClosed;
  StageLoadable("good");
  SetCurrent("good");
  ASSERT_TRUE(BundleGuardCommit(cfg_, "good").has_value());
  StageLoadable("bad");
  SetCurrent("bad");
  StartAndVanish();
  StartAndVanish();

  Engine e;
  MakeEngine(&e);
  auto res = EngineInit(e, kSock, "/sys/fs/bpf/f-guard-test",
                        root_.string());
  ASSERT_FALSE(res);
  EXPECT_NE(res.error().message.find("will not be tried again"),
            std::string::npos) << res.error().message;
  // `current` is left naming what the operator asked for: fail-closed
  // does not quietly rewrite the box's intent.
  EXPECT_EQ(CurrentVersion(root_.string()), "bad");
  // And the box is not forwarding, which is what makes the refusal a
  // refusal rather than an outage with extra steps.
  std::ifstream in(root_ / "proc-sys" / "net" / "ipv4" / "ip_forward");
  std::string v;
  std::getline(in, v);
  EXPECT_EQ(v, "0");
}

TEST_F(GuardEngineTest, TheStatusSectionSaysWhichBundleIsRunning) {
  StageLoadable("v1");
  SetCurrent("v1");
  Engine e;
  MakeEngine(&e);
  auto res = EngineInit(e, kSock, "/sys/fs/bpf/f-guard-test",
                        root_.string());
  ASSERT_FALSE(res);
  auto j = GetFullState(e);
  ASSERT_TRUE(j.contains("bundle"));
  EXPECT_EQ(j["bundle"]["current"], "v1");
  EXPECT_EQ(j["bundle"]["failure_policy"], "fallback");
  // The pending attempt is readable from the status surface, so an
  // operator can see a bundle is on its last try before the box takes
  // the decision for him.
  ASSERT_FALSE(j["bundle"]["pending_attempt"].is_null());
  EXPECT_EQ(j["bundle"]["pending_attempt"]["version"], "v1");
}

TEST_F(BundleGuardTest, PolicyNamesRoundTrip) {
  EXPECT_EQ(*ParseGuardPolicy("fallback"), GuardPolicy::kFallback);
  EXPECT_EQ(*ParseGuardPolicy("fail-closed"), GuardPolicy::kFailClosed);
  EXPECT_STREQ(GuardPolicyName(GuardPolicy::kFallback), "fallback");
  EXPECT_STREQ(GuardPolicyName(GuardPolicy::kFailClosed),
               "fail-closed");
  auto bad = ParseGuardPolicy("maybe");
  ASSERT_FALSE(bad.has_value());
  // The error has to name both choices: an operator reading it is
  // configuring anti-lockout behaviour and has one guess.
  EXPECT_NE(bad.error().find("fallback"), std::string::npos);
  EXPECT_NE(bad.error().find("fail-closed"), std::string::npos);
}

TEST_F(BundleGuardTest, ARecordThatCannotBeWrittenStillLetsTheBoxBoot) {
  // A read-only /usr/share is a degraded box. Refusing to start on it
  // would turn a degraded box into a dead one, so the guard logs and
  // proceeds. Asserting it here so nobody "fixes" it into a refusal.
  Stage("v1");
  SetCurrent("v1");
  fs::permissions(root_, fs::perms::owner_read | fs::perms::owner_exec);
  auto d = BundleGuardBegin(cfg_);
  fs::permissions(root_, fs::perms::owner_all);
  EXPECT_EQ(d.verdict, GuardVerdict::kProceed);
  EXPECT_EQ(d.version, "v1");
}

}  // namespace
}  // namespace f
