/// @file test_bpf_loader.cc
/// @brief Unit tests for non-privileged bpf_loader paths.
///
/// LoadProgramFromPath, ReplaceXdp, and friends require root to
/// fully exercise. These tests cover the error paths that don't:
/// missing files, garbage objects, etc.

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>

#include "f/bpf_loader.h"

namespace f {
namespace {

namespace fs = std::filesystem;

TEST(BpfLoaderTest, LoadFromMissingPath) {
  auto r = LoadProgramFromPath(
      "/nonexistent/never-was.bpf.o");
  EXPECT_FALSE(r);
  EXPECT_EQ(r.error().code, BpfError::kLoadFailed);
}

TEST(BpfLoaderTest, LoadFromGarbageFile) {
  auto p = fs::temp_directory_path() / "garbage.bpf.o";
  std::ofstream(p) << "not a valid ELF object";
  auto r = LoadProgramFromPath(p.string());
  EXPECT_FALSE(r);
  EXPECT_EQ(r.error().code, BpfError::kLoadFailed);
  fs::remove(p);
}

TEST(BpfLoaderTest, UnloadIsIdempotent) {
  // Unloading an empty handle should be safe; unloading twice
  // shouldn't crash.
  BpfHandles h;
  UnloadProgram(h);
  UnloadProgram(h);
  EXPECT_EQ(h.obj, nullptr);
  EXPECT_EQ(h.prog_fd, -1);
}

TEST(BpfLoaderTest, ReplaceFailsOnInvalidIfindex) {
  // ifindex 0 is invalid; expect attach failure.
  auto r = ReplaceXdp(0, -1, -1);
  EXPECT_FALSE(r);
  EXPECT_EQ(r.error().code, BpfError::kAttachFailed);
}

}  // namespace
}  // namespace f
