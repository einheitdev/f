/// @file test_watcher.cc
/// @brief Unit tests for the file watcher.
///
/// Exercises WatcherCheckOnce directly so tests don't depend on
/// the polling interval; also runs the live thread briefly to
/// verify end-to-end signalling.

#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <thread>

#include "f/watcher.h"

namespace f {
namespace {

auto MakeTempSource() -> std::filesystem::path {
  auto p = std::filesystem::temp_directory_path()
         / "fwl_watcher_test.fw";
  std::ofstream(p) << "default drop\n";
  return p;
}

auto Touch(const std::filesystem::path& p,
           std::chrono::seconds offset) -> void {
  auto now = std::filesystem::file_time_type::clock::now();
  std::filesystem::last_write_time(p, now + offset);
}

TEST(WatcherTest, InitRejectsEmptyPaths) {
  Watcher w;
  auto r = WatcherInit(
      w, "", "/tmp/out", std::chrono::seconds(5));
  EXPECT_FALSE(r);
  EXPECT_EQ(r.error().code,
            WatcherError::kInvalidConfig);
}

TEST(WatcherTest, InitFailsIfSourceMissing) {
  Watcher w;
  auto r = WatcherInit(
      w, "/nonexistent/missing.fw",
      "/tmp/out", std::chrono::seconds(5));
  EXPECT_FALSE(r);
  EXPECT_EQ(r.error().code,
            WatcherError::kSourceNotFound);
}

TEST(WatcherTest, CheckOnceFiresOnMtimeChange) {
  auto src = MakeTempSource();
  Watcher w;
  ASSERT_TRUE(WatcherInit(
      w, src.string(), "/tmp/f_watcher_out",
      std::chrono::seconds(5)));
  // Baseline: no change.
  EXPECT_FALSE(WatcherCheckOnce(w));
  EXPECT_FALSE(w.reload_requested.load());

  // Bump mtime: should fire.
  Touch(src, std::chrono::seconds(10));
  EXPECT_TRUE(WatcherCheckOnce(w));
  EXPECT_TRUE(w.reload_requested.load());

  // Subsequent check with no further change: no fire.
  EXPECT_FALSE(WatcherCheckOnce(w));

  std::filesystem::remove(src);
}

TEST(WatcherTest, ConsumeReloadClearsFlag) {
  auto src = MakeTempSource();
  Watcher w;
  ASSERT_TRUE(WatcherInit(
      w, src.string(), "/tmp/f_watcher_out",
      std::chrono::seconds(5)));

  Touch(src, std::chrono::seconds(10));
  WatcherCheckOnce(w);

  EXPECT_TRUE(WatcherConsumeReload(w));
  // Second consume returns false — flag was cleared.
  EXPECT_FALSE(WatcherConsumeReload(w));
  EXPECT_FALSE(w.reload_requested.load());

  std::filesystem::remove(src);
}

TEST(WatcherTest, LiveThreadDetectsChange) {
  auto src = MakeTempSource();
  Watcher w;
  ASSERT_TRUE(WatcherInit(
      w, src.string(), "/tmp/f_watcher_out",
      std::chrono::seconds(1)));

  WatcherStart(w);
  // Poll is 100ms-sliced, interval 1s.
  std::this_thread::sleep_for(
      std::chrono::milliseconds(300));
  EXPECT_FALSE(w.reload_requested.load());

  Touch(src, std::chrono::seconds(10));

  // Wait up to 2s for the thread to observe the change.
  auto deadline = std::chrono::steady_clock::now()
                + std::chrono::seconds(2);
  while (std::chrono::steady_clock::now() < deadline) {
    if (w.reload_requested.load()) break;
    std::this_thread::sleep_for(
        std::chrono::milliseconds(50));
  }
  EXPECT_TRUE(w.reload_requested.load());

  WatcherStop(w);
  std::filesystem::remove(src);
}

}  // namespace
}  // namespace f
