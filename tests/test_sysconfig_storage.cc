/// @file test_sysconfig_storage.cc
/// @brief Bundle retention, log quota, and losses that must be visible.
///
/// The property under test is not "we delete old bundles". It is that
/// nothing on this box grows without a bound, **and** that when
/// something is lost anyway the box says so. An appliance that fills
/// its own disk stops working; one that quietly stops recording
/// during a storm is worse, because it looks fine.

#include <unistd.h>

#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include <format>

#include <gtest/gtest.h>

#include "f/sysconfig/storage.h"

namespace f::sysconfig {
namespace {

class TempDir {
 public:
  TempDir() {
    auto base = std::filesystem::temp_directory_path();
    for (int i = 0; i < 1000; ++i) {
      auto c = base / ("f-storage-test-" +
                       std::to_string(::getpid()) + "-" +
                       std::to_string(i));
      if (!std::filesystem::exists(c)) {
        std::filesystem::create_directories(c);
        path_ = c;
        return;
      }
    }
  }
  ~TempDir() {
    std::error_code ec;
    std::filesystem::remove_all(path_, ec);
  }
  TempDir(const TempDir&) = delete;
  auto operator=(const TempDir&) -> TempDir& = delete;

  auto Path() const -> std::string { return path_.string(); }
  auto Sub(const std::string& n) const -> std::filesystem::path {
    return path_ / n;
  }

 private:
  std::filesystem::path path_;
};

/// One bundle directory with `bytes` of content in it.
auto MakeBundle(const TempDir& dir, const std::string& name,
                std::size_t bytes) -> void {
  auto d = dir.Sub(name);
  std::filesystem::create_directories(d);
  std::ofstream out(d / "manifest.json");
  out << std::string(bytes, 'x');
}

auto PointCurrentAt(const TempDir& dir, const std::string& name)
    -> void {
  std::error_code ec;
  std::filesystem::remove(dir.Sub("current"), ec);
  std::filesystem::create_directory_symlink(name, dir.Sub("current"),
                                            ec);
}

auto Exists(const TempDir& dir, const std::string& name) -> bool {
  std::error_code ec;
  return std::filesystem::exists(dir.Sub(name), ec);
}

// -- retention ---------------------------------------------------------

TEST(RetentionTest, KeepsTheNewestAndRemovesTheRest) {
  TempDir dir;
  for (int i = 1; i <= 20; ++i) {
    MakeBundle(dir, std::format("2026081400{:02d}", i), 100);
  }
  RetentionPolicy policy;
  policy.compiled_dir = dir.Path();
  policy.keep = 5;

  auto plan = PlanRetention(policy);
  EXPECT_TRUE(plan.readable);
  EXPECT_EQ(plan.bundles.size(), 20u);
  EXPECT_EQ(plan.to_remove.size(), 15u);
  // Newest first, so the survivors are the five highest versions.
  EXPECT_EQ(plan.bundles.front().name, "202608140020");
  EXPECT_EQ(plan.reclaimable_bytes, 15u * 100u);

  auto report = PruneBundles(policy);
  ASSERT_TRUE(report.has_value()) << (report ? "" : report.error());
  EXPECT_EQ(report->removed.size(), 15u);
  EXPECT_TRUE(report->failed.empty());
  EXPECT_TRUE(Exists(dir, "202608140020"));
  EXPECT_TRUE(Exists(dir, "202608140016"));
  EXPECT_FALSE(Exists(dir, "202608140015"));
  EXPECT_FALSE(Exists(dir, "202608140001"));
}

// The one bundle that must never be removed is the one being served.
// Deleting the running policy to reclaim disk space would be an
// outage caused by tidying up.
TEST(RetentionTest, TheRunningPolicyIsNeverPruned) {
  TempDir dir;
  for (int i = 1; i <= 10; ++i) {
    MakeBundle(dir, std::format("2026081400{:02d}", i), 50);
  }
  // `current` points at the OLDEST, which is what happens after a
  // cold boot adopts the last known-good bundle and then somebody
  // compiles ten times.
  PointCurrentAt(dir, "202608140001");

  RetentionPolicy policy;
  policy.compiled_dir = dir.Path();
  policy.keep = 3;

  auto plan = PlanRetention(policy);
  for (const auto& b : plan.to_remove) {
    EXPECT_NE(b.name, "202608140001");
  }
  ASSERT_TRUE(PruneBundles(policy).has_value());
  EXPECT_TRUE(Exists(dir, "202608140001"));
  EXPECT_TRUE(Exists(dir, "current"));
  EXPECT_TRUE(Exists(dir, "202608140010"));
  EXPECT_FALSE(Exists(dir, "202608140005"));
}

TEST(RetentionTest, FewerBundlesThanTheLimitRemovesNothing) {
  TempDir dir;
  MakeBundle(dir, "202608140001", 10);
  MakeBundle(dir, "202608140002", 10);
  RetentionPolicy policy;
  policy.compiled_dir = dir.Path();
  policy.keep = 10;

  auto plan = PlanRetention(policy);
  EXPECT_TRUE(plan.to_remove.empty());
  EXPECT_EQ(plan.reclaimable_bytes, 0u);
  auto report = PruneBundles(policy);
  ASSERT_TRUE(report.has_value());
  EXPECT_TRUE(report->removed.empty());
}

// An unreadable directory is not an empty one, and a prune that
// reported "removed 0, all tidy" would be the same lie the lease view
// exists to avoid.
TEST(RetentionTest, AnUnreadableDirIsNotAnEmptyOne) {
  RetentionPolicy policy;
  policy.compiled_dir = "/nonexistent/f/compiled";
  auto plan = PlanRetention(policy);
  EXPECT_FALSE(plan.readable);
  EXPECT_TRUE(plan.bundles.empty());
  EXPECT_NE(plan.unreadable_reason.find("does not exist"),
            std::string::npos);
  auto report = PruneBundles(policy);
  EXPECT_FALSE(report.has_value());
}

// The `current` symlink is skipped rather than counted: following it
// would count the bundle it points at twice and make the reclaimable
// figure wrong in the direction that matters.
TEST(RetentionTest, TheSymlinkIsNotCountedAsABundle) {
  TempDir dir;
  MakeBundle(dir, "202608140001", 100);
  MakeBundle(dir, "202608140002", 100);
  PointCurrentAt(dir, "202608140002");
  RetentionPolicy policy;
  policy.compiled_dir = dir.Path();
  policy.keep = 10;
  auto plan = PlanRetention(policy);
  EXPECT_EQ(plan.bundles.size(), 2u);
  EXPECT_EQ(plan.total_bytes, 200u);
}

// -- the log policy ----------------------------------------------------

TEST(LogPolicyTest, TheJournalIsCapped) {
  auto plan = PlanLogging(LogPolicy{});
  EXPECT_NE(plan.content.find("SystemMaxUse=200M"),
            std::string::npos);
  EXPECT_NE(plan.content.find("SystemKeepFree=100M"),
            std::string::npos);
  EXPECT_NE(plan.content.find("SystemMaxFileSize=20M"),
            std::string::npos);
}

// The distribution default discards a burst and records "Suppressed N
// messages". A burst is exactly what a broadcast storm looks like, so
// the default trades away the minute most worth having.
TEST(LogPolicyTest, TheRateLimiterIsOffByDecisionNotByAccident) {
  auto plan = PlanLogging(LogPolicy{});
  EXPECT_EQ(plan.policy.rate_limit_burst, 0);
  EXPECT_NE(plan.content.find("RateLimitBurst=0"),
            std::string::npos);
  // And the file says why, because the next person to read it will
  // otherwise assume it was a mistake and put the default back.
  EXPECT_NE(plan.content.find("broadcast storm"), std::string::npos);
}

// -- what was lost -----------------------------------------------------

TEST(StorageReportTest, ADroppedLogIsShoutedAbout) {
  StorageReport r;
  r.availability = StorageAvailability::kObserved;
  r.suppression_read = true;
  r.suppressed_messages = 7;
  auto banner = StorageWarningBanner(r);
  EXPECT_NE(banner.find("LOG EVENTS HAVE BEEN DROPPED"),
            std::string::npos)
      << banner;
  r.suppression_bursts = 2;
  banner = StorageWarningBanner(r);
  EXPECT_NE(banner.find("7 message(s)"), std::string::npos)
      << banner;
  EXPECT_NE(banner.find("RateLimitBurst=0"), std::string::npos)
      << banner;
}

// The distinction the whole file turns on: "nothing was dropped" and
// "we could not tell whether anything was dropped" are different, and
// only one of them is reassuring.
TEST(StorageReportTest, NotKnowingIsNotTheSameAsNothingLost) {
  StorageReport r;
  r.availability = StorageAvailability::kObserved;
  r.suppression_read = false;
  auto banner = StorageWarningBanner(r);
  EXPECT_NE(banner.find("could not be determined"),
            std::string::npos)
      << banner;

  r.suppression_read = true;
  r.suppressed_messages = 0;
  EXPECT_EQ(StorageWarningBanner(r), "");
}

TEST(StorageReportTest, ATightDiskIsWarnedAboutWithTheNumber) {
  StorageReport r;
  r.availability = StorageAvailability::kObserved;
  r.suppression_read = true;
  r.fs_total_bytes = 1000;
  r.fs_free_bytes = 50;
  EXPECT_TRUE(r.Tight());
  auto banner = StorageWarningBanner(r);
  EXPECT_NE(banner.find("95% FULL"), std::string::npos) << banner;

  r.fs_free_bytes = 500;
  EXPECT_FALSE(r.Tight());
  EXPECT_EQ(StorageWarningBanner(r), "");
}

TEST(StorageReportTest, TheBundleCountAndOverageAreReported) {
  TempDir dir;
  for (int i = 1; i <= 12; ++i) {
    MakeBundle(dir, std::format("2026081400{:02d}", i), 1000);
  }
  StorageSource src;
  src.retention.compiled_dir = dir.Path();
  src.retention.keep = 4;
  // No journal on a build machine, and the report must survive that
  // by saying so rather than by reporting zero.
  src.journal_usage_cmd = "";
  src.suppressed_cmd = "";

  auto r = QueryStorage(src);
  EXPECT_EQ(r.availability, StorageAvailability::kObserved);
  EXPECT_EQ(r.bundle_count, 12u);
  EXPECT_EQ(r.bundles_over_policy, 8u);
  EXPECT_EQ(r.bundle_bytes, 12u * 1000u);
  EXPECT_FALSE(r.journal_read);
  EXPECT_FALSE(r.suppression_read);
  EXPECT_NE(StorageWarningBanner(r).find("could not be determined"),
            std::string::npos);
}

TEST(StorageReportTest, AnUnreadableBundleDirSaysSo) {
  StorageSource src;
  src.retention.compiled_dir = "/nonexistent/f/compiled";
  src.journal_usage_cmd = "";
  src.suppressed_cmd = "";
  auto r = QueryStorage(src);
  EXPECT_EQ(r.availability, StorageAvailability::kUnreadable);
  EXPECT_NE(r.detail.find("does not exist"), std::string::npos);
  EXPECT_EQ(r.bundle_count, 0u);
  // And it shouts, because a zero here would otherwise read as a
  // tidy box with nothing on it.
  EXPECT_NE(StorageWarningBanner(r).find("COULD NOT BE READ"),
            std::string::npos);
}

// A grep that finds nothing exits 1. Reading that as a failed probe
// would report "could not determine" forever on a healthy box, and an
// always-on warning is one nobody reads.
TEST(StorageReportTest, NoSuppressionRecordsIsACleanRead) {
  TempDir dir;
  MakeBundle(dir, "202608140001", 10);
  StorageSource src;
  src.retention.compiled_dir = dir.Path();
  src.journal_usage_cmd = "";
  src.suppressed_cmd = "false";
  auto r = QueryStorage(src);
  EXPECT_TRUE(r.suppression_read);
  EXPECT_EQ(r.suppressed_messages, 0u);
  EXPECT_EQ(StorageWarningBanner(r), "");
}

TEST(StorageReportTest, SuppressionLinesAreCounted) {
  TempDir dir;
  MakeBundle(dir, "202608140001", 10);
  StorageSource src;
  src.retention.compiled_dir = dir.Path();
  src.journal_usage_cmd = "";
  src.suppressed_cmd =
      "printf 'Suppressed 41 messages\\nSuppressed 9 messages\\n'";
  auto r = QueryStorage(src);
  EXPECT_TRUE(r.suppression_read);
  EXPECT_EQ(r.suppression_bursts, 2u);
  // The count comes out of the message, so what is reported is what
  // was actually lost rather than how many times it happened.
  EXPECT_EQ(r.suppressed_messages, 50u);
}

TEST(StorageReportTest, JournalUsageIsParsedWithItsUnit) {
  TempDir dir;
  MakeBundle(dir, "202608140001", 10);
  StorageSource src;
  src.retention.compiled_dir = dir.Path();
  src.suppressed_cmd = "";
  src.journal_usage_cmd =
      "echo 'Archived and active journals take up 96.0M in the file "
      "system.'";
  auto r = QueryStorage(src);
  EXPECT_TRUE(r.journal_read);
  EXPECT_EQ(r.journal_bytes, 96ULL * 1024 * 1024);
}

}  // namespace
}  // namespace f::sysconfig
