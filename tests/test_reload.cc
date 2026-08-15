/// @file test_reload.cc
/// @brief Unit tests for the reload pipeline.
///
/// Covers deterministic pieces: manifest parsing, the multi-zone
/// routing signal, and subprocess envelope handling. Full end-to-end
/// reload against a live BPF engine is covered in the integration
/// test.

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>

#include <nlohmann/json.hpp>

#include "f/bpf_loader.h"
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
                   const json& manifest) -> fs::path {
  auto dir = base / "bundle";
  WriteFile(dir / "manifest.json", manifest.dump());
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
  auto dir = MakeBundleDir(tmp, json{{"programs", json::array()}});
  Engine e;
  auto res = ApplyBundle(e, dir.string());
  EXPECT_FALSE(res);
  EXPECT_EQ(res.error().code,
            ReloadError::kManifestInvalid);
  fs::remove_all(tmp);
}

TEST(ReloadApplyBundle, AManifestWithNoProgramsIsRefused) {
  // `fwl compile --bundle` cannot write this: the grammar is
  // `program : zone_decl* function_def* xdp_block+`, so every bundle
  // names at least one @xdp program. A manifest without one came from
  // somewhere else, and what used to happen here was that ApplyBundle
  // fell through to the v0.1 rules.json/ApplyConfig tail and reported
  // success with `rules_installed: 0`. It refuses now, by name, and
  // says the running policy is untouched.
  auto tmp = fs::temp_directory_path()
           / "fwl_reload_test_no_programs";
  fs::remove_all(tmp);
  auto dir = MakeBundleDir(tmp, json{{"version", "20260414T000000Z"},
                                     {"programs", json::array()}});
  Engine e;
  auto res = ApplyBundle(e, dir.string());
  ASSERT_FALSE(res);
  EXPECT_EQ(res.error().code, ReloadError::kManifestInvalid);
  EXPECT_NE(res.error().message.find("no @xdp programs"),
            std::string::npos)
      << res.error().message;
  fs::remove_all(tmp);
}

// v0.4 § 6.2: the routing signal ApplyBundle and EngineInit use to
// decide whether a directory holds a loadable bundle at all.
TEST(ZoneBundleRouting, MultiZoneManifestDetected) {
  auto tmp = fs::temp_directory_path() / "fwl_multizone_detect";
  fs::remove_all(tmp);
  json manifest = {
      {"version", "0.4"},
      {"zones",
       {{{"name", "wan"}, {"interfaces", {"wan0"}}},
        {{"name", "lan"}, {"interfaces", {"lan0"}}}}},
      {"programs",
       {{{"zone", "wan"}, {"object", "wan.bpf.o"}, {"redirects_to", json::array()}},
        {{"zone", "lan"}, {"object", "lan.bpf.o"}, {"redirects_to", {"wan"}}}}},
  };
  WriteFile(tmp / "manifest.json", manifest.dump());
  EXPECT_TRUE(IsMultiZoneBundle(tmp.string()));
  fs::remove_all(tmp);
}

TEST(ZoneBundleRouting, AV01ManifestIsNotABundle) {
  auto tmp = fs::temp_directory_path() / "fwl_singleprog_detect";
  fs::remove_all(tmp);
  // A v0.1 manifest, as staged on boxes deployed before v0.4. It named
  // one `main.bpf.o` and no zones. It is not a bundle, and the answer
  // is now terminal rather than a route into a second loader: EngineInit
  // refuses to start on it and ApplyBundle leaves the running policy
  // alone.
  json manifest = {
      {"version", "20260414T000000Z"},
      {"has_program", true},
      {"program", {{"path", "main.bpf.o"}}},
  };
  WriteFile(tmp / "manifest.json", manifest.dump());
  EXPECT_FALSE(IsMultiZoneBundle(tmp.string()));
  fs::remove_all(tmp);
}

TEST(ZoneBundleRouting, MissingManifestIsNotMultiZone) {
  auto tmp = fs::temp_directory_path() / "fwl_nomanifest_detect";
  fs::remove_all(tmp);
  EXPECT_FALSE(IsMultiZoneBundle(tmp.string()));
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
