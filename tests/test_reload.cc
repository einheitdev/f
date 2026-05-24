/// @file test_reload.cc
/// @brief Unit tests for the reload pipeline.
///
/// Covers deterministic pieces: manifest/rules.json parsing,
/// subprocess envelope handling. Full end-to-end reload against
/// a live BPF engine is covered in the integration test.

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>

#include <nlohmann/json.hpp>

#include "f/engine.h"
#include "f/reload.h"

namespace f {
namespace {

namespace fs = std::filesystem;
using json = nlohmann::json;

auto WriteFile(const fs::path& p, std::string_view body) -> void {
  fs::create_directories(p.parent_path());
  std::ofstream(p) << body;
}

auto MakeBundleDir(const fs::path& base,
                   const json& manifest,
                   const json& rules) -> fs::path {
  auto dir = base / "bundle";
  WriteFile(dir / "manifest.json", manifest.dump());
  WriteFile(dir / "rules.json", rules.dump());
  return dir;
}

TEST(ReloadApplyBundle, MissingManifestFails) {
  auto tmp = fs::temp_directory_path()
           / "fwl_reload_test_no_manifest";
  fs::remove_all(tmp);
  fs::create_directories(tmp);

  Engine e;
  auto res = ApplyBundle(e, tmp.string());
  EXPECT_FALSE(res);
  EXPECT_EQ(res.error().code,
            ReloadError::kManifestInvalid);
  fs::remove_all(tmp);
}

TEST(ReloadApplyBundle, BadManifestJsonFails) {
  auto tmp = fs::temp_directory_path()
           / "fwl_reload_test_bad_manifest";
  fs::remove_all(tmp);
  fs::create_directories(tmp);
  WriteFile(tmp / "manifest.json", "not json");

  Engine e;
  auto res = ApplyBundle(e, tmp.string());
  EXPECT_FALSE(res);
  EXPECT_EQ(res.error().code,
            ReloadError::kManifestInvalid);
  fs::remove_all(tmp);
}

TEST(ReloadApplyBundle, MissingVersionInManifest) {
  auto tmp = fs::temp_directory_path()
           / "fwl_reload_test_no_version";
  fs::remove_all(tmp);
  auto dir = MakeBundleDir(tmp,
      json{{"has_program", false}},
      json{{"rules", json::array()},
           {"default_action", 0}});
  Engine e;
  auto res = ApplyBundle(e, dir.string());
  EXPECT_FALSE(res);
  EXPECT_EQ(res.error().code,
            ReloadError::kManifestInvalid);
  fs::remove_all(tmp);
}

TEST(ReloadApplyBundle, MissingRulesJsonFails) {
  auto tmp = fs::temp_directory_path()
           / "fwl_reload_test_no_rules";
  fs::remove_all(tmp);
  fs::create_directories(tmp);
  WriteFile(tmp / "manifest.json",
            json{{"version", "v1"}}.dump());
  Engine e;
  auto res = ApplyBundle(e, tmp.string());
  EXPECT_FALSE(res);
  EXPECT_EQ(res.error().code,
            ReloadError::kRulesInvalid);
  fs::remove_all(tmp);
}

TEST(ReloadApplyBundle, ParsesRulesAndVersion) {
  // With no BPF loaded, ApplyConfig tolerates bad update_elem
  // calls and returns the count of successful inserts (0 here).
  // This lets us validate rules.json parsing + version flow
  // without needing a live kernel.
  auto tmp = fs::temp_directory_path()
           / "fwl_reload_test_parse_ok";
  fs::remove_all(tmp);
  auto dir = MakeBundleDir(tmp,
      json{{"version", "20260414T000000Z"}},
      json{{"default_action", 0},
           {"rules", json::array({
              json{{"type", "exact"},
                   {"key", json{{"dst_port", 8080},
                                {"proto", 6}}},
                   {"value", json{{"action", 0}}}},
              // CIDR entry — skipped by current apply path.
              json{{"type", "cidr"},
                   {"field", "src_net"},
                   {"addr", 0x0A000000u},
                   {"prefix", 8},
                   {"value", json{{"action", 0}}}},
           })}});

  Engine e;  // uninitialized; no real BPF
  auto res = ApplyBundle(e, dir.string());
  ASSERT_TRUE(res);
  EXPECT_EQ(res->version, "20260414T000000Z");
  // Update_elem failed silently; installed stays at 0.
  EXPECT_EQ(res->rules_installed, 0u);
  EXPECT_FALSE(res->program_updated);
  fs::remove_all(tmp);
}

TEST(ReloadRunCompiler, MissingBinarySurfacesSpawnError) {
  auto res = RunCompiler(
      "/nonexistent/fwl_xxx", "/tmp/source.fw", "/tmp/out");
  EXPECT_FALSE(res);
  // posix_spawnp may return either kSpawnFailed or
  // kCompileFailed depending on where failure surfaces.
  EXPECT_TRUE(res.error().code == ReloadError::kSpawnFailed
              || res.error().code
                 == ReloadError::kCompileFailed);
}

}  // namespace
}  // namespace f
