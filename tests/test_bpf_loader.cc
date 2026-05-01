/// @file test_bpf_loader.cc
/// @brief Cold-boot bundle auto-load tests for the BPF loader.
///
/// `LoadProgram(bundle_dir)` resolves which `.bpf.o` to open in
/// a fixed precedence order:
///   1. `<bundle_dir>/current/main.bpf.o` (operator-staged)
///   2. v0.1 fall-back list: `fw.bpf.o`, `build/fw.bpf.o`,
///      `../bpf/fw.bpf.o`, `/usr/lib/f/fw.bpf.o`.
///
/// These tests exercise the resolver only — the live BPF load
/// path needs CAP_BPF and is covered by test_xdp.cc.

#include <gtest/gtest.h>

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>

#include "f/bpf_loader.h"

namespace f {
namespace {

namespace fs = std::filesystem;

class BpfLoaderResolverTest : public ::testing::Test {
 protected:
  void SetUp() override {
    // Per-test scratch dir; cleared on TearDown.
    auto base = fs::temp_directory_path()
        / std::format("fwl-bpf-loader-{}", ::getpid());
    auto suffix = ::testing::UnitTest::GetInstance()
                      ->current_test_info()
                      ->name();
    scratch_ = base / suffix;
    fs::create_directories(scratch_);
  }

  void TearDown() override {
    std::error_code ec;
    fs::remove_all(scratch_, ec);
  }

  // Drop a placeholder file at `path`, creating intermediate dirs.
  void Touch(const fs::path& path) {
    fs::create_directories(path.parent_path());
    std::ofstream(path) << "placeholder";
  }

  fs::path scratch_;
};

TEST_F(BpfLoaderResolverTest, EmptyBundleDirFallsBackToFwBpfO) {
  // No bundle_dir, no fall-back files in cwd → empty result.
  // The resolver must not invent a path.
  auto picked = ResolveBpfObjPath("");
  // `fw.bpf.o` doesn't exist in the test cwd — expect empty.
  // (If a build artefact happens to exist, this asserts it was
  // selected; either way, the bundle path was never reached.)
  EXPECT_TRUE(
      picked.empty()
      || picked == "fw.bpf.o"
      || picked == "build/fw.bpf.o"
      || picked == "../bpf/fw.bpf.o"
      || picked == "/usr/lib/f/fw.bpf.o");
}

TEST_F(BpfLoaderResolverTest, BundleCurrentSymlinkTakesPrecedence) {
  // Stage a fake bundle at <scratch>/current/main.bpf.o.
  auto current = scratch_ / "current" / "main.bpf.o";
  Touch(current);

  auto picked = ResolveBpfObjPath(scratch_.string());
  EXPECT_EQ(picked, current.string());
}

TEST_F(BpfLoaderResolverTest, BundleMissingFallsBackToFwBpfO) {
  // bundle_dir given but `current/main.bpf.o` doesn't exist.
  // Resolver must skip cleanly (no crash) and consult fall-back
  // entries — none of which exist in the test scratch dir, so
  // the result is empty unless a build artefact happens to be in
  // cwd (in which case the resolver picked correctly).
  auto picked = ResolveBpfObjPath(scratch_.string());
  EXPECT_NE(picked, (scratch_ / "current" / "main.bpf.o").string())
      << "fall-back path must NOT be the bundle's missing entry";
}

TEST_F(BpfLoaderResolverTest, BundleSymlinkFollowed) {
  // Real-world layout: `current` is a symlink into a versioned
  // sub-directory the reload pipeline maintains. Resolver must
  // follow it.
  auto versioned =
      scratch_ / "v-12345" / "main.bpf.o";
  Touch(versioned);
  auto link = scratch_ / "current";
  std::error_code ec;
  fs::create_directory_symlink(scratch_ / "v-12345", link, ec);
  ASSERT_FALSE(ec) << ec.message();

  auto picked = ResolveBpfObjPath(scratch_.string());
  // The resolver yields the symlink path (libbpf will follow it
  // when opening). Either the symlink path or the canonical
  // versioned path is acceptable; we lock the symlink form here
  // so a future canonicalisation change is a deliberate choice.
  EXPECT_EQ(picked, (link / "main.bpf.o").string());
}

}  // namespace
}  // namespace f
