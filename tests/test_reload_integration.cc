/// @file test_reload_integration.cc
/// @brief End-to-end reload pipeline test (no root required).
///
/// Exercises ReloadFromSource against a real `fwl` invocation,
/// validates the bundle artifacts and `current` symlink. Skips
/// if `fwl` is not on PATH.
///
/// The actual XDP attach + program swap is not exercised here
/// (needs CAP_BPF + a real interface). That path is validated
/// manually via /tmp/test_fwl_xdp during development; full
/// end-to-end verification with privileges is a future addition.

#include <gtest/gtest.h>

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <thread>

#include <nlohmann/json.hpp>

#include "f/engine.h"
#include "f/reload.h"
#include "f/watcher.h"

namespace f {
namespace {

namespace fs = std::filesystem;
using json = nlohmann::json;

/// Skip test if fwl isn't on PATH.
auto FwlAvailable() -> bool {
  // Quick probe via system().
  return std::system("command -v fwl > /dev/null 2>&1") == 0;
}

auto WriteFile(const fs::path& p, std::string_view body)
    -> void {
  fs::create_directories(p.parent_path());
  std::ofstream(p) << body;
}

class ReloadIntegrationTest : public ::testing::Test {
 protected:
  void SetUp() override {
    if (!FwlAvailable()) {
      GTEST_SKIP() << "fwl not on PATH";
    }
    workdir_ = fs::temp_directory_path() / "fwl_reload_int";
    fs::remove_all(workdir_);
    fs::create_directories(workdir_);
    source_ = workdir_ / "rules.fw";
    compiled_ = workdir_ / "compiled";
    fs::create_directories(compiled_);

    engine_ = std::make_unique<Engine>();
    engine_->watcher.source_path = source_.string();
    engine_->watcher.compiled_dir = compiled_.string();
    engine_->watcher.fwl_path = "fwl";
  }

  void TearDown() override {
    if (engine_) {
      WatcherStop(engine_->watcher);
      engine_.reset();
    }
    if (!workdir_.empty()) {
      fs::remove_all(workdir_);
    }
  }

  fs::path workdir_;
  fs::path source_;
  fs::path compiled_;
  std::unique_ptr<Engine> engine_;
};

// Helper: locate the most recent bundle dir (regardless of
// whether the apply step succeeded and promoted `current`).
static auto LatestBundle(const fs::path& compiled) -> fs::path {
  fs::path latest;
  fs::file_time_type latest_mt{};
  for (const auto& e : fs::directory_iterator(compiled)) {
    if (!e.is_directory()) continue;
    auto mt = fs::last_write_time(e);
    if (latest.empty() || mt > latest_mt) {
      latest = e.path();
      latest_mt = mt;
    }
  }
  return latest;
}

TEST_F(ReloadIntegrationTest, Tier1SourceProducesBundle) {
  // Under unified compilation, Tier 1 sources also produce a
  // BPF program (synthesized `policy` wrapper). Bundle exists
  // regardless of whether the kernel load step succeeds.
  WriteFile(source_, R"(
allow dst_port 80, 443 proto tcp
default drop
)");

  auto res = ReloadFromSource(*engine_);

  auto bundle = LatestBundle(compiled_);
  ASSERT_FALSE(bundle.empty());
  EXPECT_TRUE(fs::exists(bundle / "manifest.json"));
  EXPECT_TRUE(fs::exists(bundle / "rules.json"));
  EXPECT_TRUE(fs::exists(bundle / "maps.json"));
  EXPECT_TRUE(fs::exists(bundle / "main.bpf.o"));

  json m = json::parse(
      std::ifstream(bundle / "manifest.json"));
  EXPECT_TRUE(m["has_program"].get<bool>());
  EXPECT_EQ(m["program"]["entry"].get<std::string>(),
            "policy");

  if (res) {
    // Privileged run: full success path.
    EXPECT_TRUE(res->program_updated);
    EXPECT_TRUE(fs::is_symlink(compiled_ / "current"));
  } else {
    // No CAP_BPF: apply failed at the load step.
    EXPECT_EQ(res.error().code, ReloadError::kApplyFailed);
    EXPECT_FALSE(fs::exists(compiled_ / "current"));
  }
}

TEST_F(ReloadIntegrationTest,
       Tier2BundleArtifactsCreatedEvenIfLoadDenied) {
  // Tier 2 source — produces a real .bpf.o that requires CAP_BPF
  // to load. Without privileges the apply step fails, but the
  // bundle artifacts (proving the compiler ran end-to-end) must
  // exist and `current` must NOT have been promoted.
  WriteFile(source_, R"(
@xdp(eth0)
def block_port(pkt):
  if pkt.proto == tcp and pkt.dst_port == 8080:
    drop
  allow
)");

  auto res = ReloadFromSource(*engine_);

  auto latest = LatestBundle(compiled_);
  ASSERT_FALSE(latest.empty());
  EXPECT_TRUE(fs::exists(latest / "manifest.json"));
  EXPECT_TRUE(fs::exists(latest / "main.bpf.c"));
  EXPECT_TRUE(fs::exists(latest / "main.bpf.o"));

  json m = json::parse(
      std::ifstream(latest / "manifest.json"));
  EXPECT_TRUE(m["has_program"].get<bool>());
  EXPECT_EQ(m["program"]["entry"].get<std::string>(),
            "block_port");

  if (!res) {
    // No CAP_BPF: apply failed, current NOT updated.
    EXPECT_EQ(res.error().code, ReloadError::kApplyFailed);
    EXPECT_FALSE(fs::exists(compiled_ / "current"));
  } else {
    // Privileged run: full success.
    EXPECT_TRUE(res->program_updated);
    EXPECT_TRUE(fs::is_symlink(compiled_ / "current"));
  }
}

TEST_F(ReloadIntegrationTest,
       SecondReloadProducesNewBundle) {
  // Both reloads now produce BPF programs (Tier 1 synthesizes
  // a wrapper). Verify two distinct bundle dirs land on disk
  // regardless of whether the kernel load step succeeds.
  WriteFile(source_, "default drop\n");
  ReloadFromSource(*engine_);

  // Snapshot directory list, sleep so timestamps differ, then
  // trigger a second reload.
  std::vector<fs::path> before;
  for (const auto& e : fs::directory_iterator(compiled_)) {
    if (e.is_directory()) before.push_back(e.path());
  }
  ASSERT_FALSE(before.empty());

  std::this_thread::sleep_for(std::chrono::seconds(1));
  WriteFile(source_, "default allow\n");
  ReloadFromSource(*engine_);

  std::vector<fs::path> after;
  for (const auto& e : fs::directory_iterator(compiled_)) {
    if (e.is_directory()) after.push_back(e.path());
  }
  EXPECT_GT(after.size(), before.size());
}

TEST_F(ReloadIntegrationTest,
       CompileFailureLeavesNoCurrent) {
  // Source with a semantic error: tcp field outside TCP guard.
  WriteFile(source_, R"(
@xdp(eth0)
def bad(pkt):
  if pkt.tcp.syn:
    drop
  allow
)");

  auto res = ReloadFromSource(*engine_);
  EXPECT_FALSE(res);
  EXPECT_EQ(res.error().code, ReloadError::kCompileFailed);

  // No current symlink should have been created.
  EXPECT_FALSE(fs::exists(compiled_ / "current"));
}

TEST_F(ReloadIntegrationTest,
       CompileFailurePreservesPreviousState) {
  // A successful reload, then a failing reload — current must
  // not be clobbered by the failure. (Skips the post-success
  // assertion when running without CAP_BPF — the first reload
  // will fail at apply, leaving no current to preserve.)
  WriteFile(source_, "default drop\n");
  auto good = ReloadFromSource(*engine_);
  if (!good) {
    GTEST_SKIP() << "no CAP_BPF: cannot establish prior state";
  }
  auto initial_target =
      fs::read_symlink(compiled_ / "current").string();

  std::this_thread::sleep_for(std::chrono::seconds(1));
  WriteFile(source_, "@xdp(eth0)\ndef bad(pkt):\n"
                     "  if pkt.tcp.syn:\n    drop\n  allow\n");
  EXPECT_FALSE(ReloadFromSource(*engine_));

  // Symlink unchanged — last good version still active.
  EXPECT_EQ(fs::read_symlink(compiled_ / "current").string(),
            initial_target);
}

TEST_F(ReloadIntegrationTest,
       WatcherTriggersReloadEndToEnd) {
  // Tie the watcher thread to the reload pipeline. Touch the
  // source after the watcher starts; verify that we observe a
  // reload-requested signal and the bundle artifacts land.
  WriteFile(source_, "default drop\n");

  ASSERT_TRUE(WatcherInit(
      engine_->watcher, source_.string(), compiled_.string(),
      std::chrono::seconds(1)));
  WatcherStart(engine_->watcher);

  std::this_thread::sleep_for(
      std::chrono::milliseconds(200));
  EXPECT_FALSE(engine_->watcher.reload_requested.load());

  // Bump mtime; wait for the polling thread to notice.
  auto fut = std::filesystem::file_time_type::clock::now()
           + std::chrono::seconds(10);
  std::filesystem::last_write_time(source_, fut);

  auto deadline = std::chrono::steady_clock::now()
                + std::chrono::seconds(3);
  while (std::chrono::steady_clock::now() < deadline
         && !engine_->watcher.reload_requested.load()) {
    std::this_thread::sleep_for(
        std::chrono::milliseconds(50));
  }
  ASSERT_TRUE(engine_->watcher.reload_requested.load());

  // Consume + drive the reload. Apply may fail without
  // CAP_BPF, but the bundle artifacts must always exist.
  EXPECT_TRUE(WatcherConsumeReload(engine_->watcher));
  ReloadFromSource(*engine_);
  auto bundle = LatestBundle(compiled_);
  ASSERT_FALSE(bundle.empty());
  EXPECT_TRUE(fs::exists(bundle / "manifest.json"));
}

}  // namespace
}  // namespace f
