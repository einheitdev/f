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

#include <arpa/inet.h>

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

// --- geoip.json bundle parsing (v0.4 hardware-validation gap) -------

class GeoipParseTest : public BpfLoaderResolverTest {
 protected:
  void WriteGeoip(const std::string& body) {
    std::ofstream(scratch_ / "geoip.json") << body;
  }
};

TEST_F(GeoipParseTest, AbsentFileYieldsEmptyTries) {
  auto tries = ParseGeoipFile(scratch_.string());
  ASSERT_TRUE(tries.has_value());
  EXPECT_TRUE(tries->empty());
}

TEST_F(GeoipParseTest, ParsesV4AndV6Prefixes) {
  WriteGeoip(R"({"tries": [
    {"map": "fwl_geoip_0", "family": "ipv4",
     "prefixes": ["10.99.77.0/24", "192.0.2.0/25"]},
    {"map": "fwl_geoip_1", "family": "ipv6",
     "prefixes": ["2001:db8::/32"]}
  ]})");
  auto tries = ParseGeoipFile(scratch_.string());
  ASSERT_TRUE(tries.has_value());
  ASSERT_EQ(tries->size(), 2u);

  const auto& v4 = tries->at("fwl_geoip_0");
  ASSERT_EQ(v4.size(), 2u);
  EXPECT_EQ(v4[0].prefixlen, 24u);
  EXPECT_FALSE(v4[0].v6);
  // 10.99.77.0 in network order.
  EXPECT_EQ(v4[0].addr[0], 10);
  EXPECT_EQ(v4[0].addr[1], 99);
  EXPECT_EQ(v4[0].addr[2], 77);
  EXPECT_EQ(v4[0].addr[3], 0);
  EXPECT_EQ(v4[1].prefixlen, 25u);

  const auto& v6 = tries->at("fwl_geoip_1");
  ASSERT_EQ(v6.size(), 1u);
  EXPECT_TRUE(v6[0].v6);
  EXPECT_EQ(v6[0].prefixlen, 32u);
  EXPECT_EQ(v6[0].addr[0], 0x20);
  EXPECT_EQ(v6[0].addr[1], 0x01);
  EXPECT_EQ(v6[0].addr[2], 0x0d);
  EXPECT_EQ(v6[0].addr[3], 0xb8);
}

TEST_F(GeoipParseTest, MalformedJsonIsAnError) {
  WriteGeoip("{not json");
  auto tries = ParseGeoipFile(scratch_.string());
  EXPECT_FALSE(tries.has_value());
}

TEST_F(GeoipParseTest, PrefixWithoutLengthIsAnError) {
  WriteGeoip(R"({"tries": [{"map": "m", "family": "ipv4",
                "prefixes": ["10.0.0.0"]}]})");
  auto tries = ParseGeoipFile(scratch_.string());
  EXPECT_FALSE(tries.has_value());
}

TEST_F(GeoipParseTest, PrefixLengthOutOfRangeIsAnError) {
  WriteGeoip(R"({"tries": [{"map": "m", "family": "ipv4",
                "prefixes": ["10.0.0.0/33"]}]})");
  auto tries = ParseGeoipFile(scratch_.string());
  EXPECT_FALSE(tries.has_value());
}

TEST_F(GeoipParseTest, UnparseableAddressIsAnError) {
  WriteGeoip(R"({"tries": [{"map": "m", "family": "ipv4",
                "prefixes": ["not.an.ip/8"]}]})");
  auto tries = ParseGeoipFile(scratch_.string());
  EXPECT_FALSE(tries.has_value());
}

// --- masquerade address resolution ----------------------------------

TEST(FirstZoneIpv4Test, LoopbackResolves) {
  // 127.0.0.1 in network order — the one address every host has.
  uint32_t addr = FirstZoneIpv4({"lo"});
  EXPECT_EQ(addr, htonl(0x7F000001u));
}

TEST(FirstZoneIpv4Test, UnknownInterfaceYieldsZero) {
  EXPECT_EQ(FirstZoneIpv4({"no-such-if0"}), 0u);
}

TEST(FirstZoneIpv4Test, FallsThroughToLaterInterface) {
  EXPECT_EQ(FirstZoneIpv4({"no-such-if0", "lo"}),
            htonl(0x7F000001u));
}

// --- pinned-map conflict diagnostic ---------------------------------
//
// libbpf answers a pin-shape mismatch with -EINVAL and nothing else,
// so the daemon's job is to convert that into the one sentence an
// operator can act on: which map, which zones, which numbers.

TEST(DescribePinConflictTest, NamesTheMapZonesAndValues) {
  PinnedMapShape want;
  want.type = 6;
  want.key_size = 4;
  want.value_size = 8;
  want.max_entries = 3;
  PinnedMapShape have = want;
  have.max_entries = 1;

  std::string message = DescribePinConflict(
      "fwl_counters", "b", "zone 'a'", want, have);

  EXPECT_NE(message.find("fwl_counters"), std::string::npos);
  EXPECT_NE(message.find("zone 'b'"), std::string::npos);
  EXPECT_NE(message.find("zone 'a'"), std::string::npos);
  EXPECT_NE(message.find("max_entries 3 vs 1"), std::string::npos);
}

TEST(DescribePinConflictTest, ReportsEveryDifferingField) {
  PinnedMapShape want;
  want.type = 6;
  want.key_size = 4;
  want.value_size = 8;
  want.max_entries = 3;
  PinnedMapShape have;
  have.type = 2;
  have.key_size = 8;
  have.value_size = 16;
  have.max_entries = 3;

  std::string message = DescribePinConflict(
      "fwl_log_sample", "b", "zone 'a'", want, have);

  EXPECT_NE(message.find("type 6 vs 2"), std::string::npos);
  EXPECT_NE(message.find("key_size 4 vs 8"), std::string::npos);
  EXPECT_NE(message.find("value_size 8 vs 16"), std::string::npos);
  // Fields that agree must not be listed as differences.
  EXPECT_EQ(message.find("max_entries"), std::string::npos);
}

TEST(DescribePinConflictTest, IdenticalShapesExplainNothing) {
  // Not every failed load is a pin conflict. When the shapes agree
  // there is nothing to say, and the caller keeps libbpf's own error
  // rather than blaming an innocent map.
  PinnedMapShape shape;
  shape.type = 6;
  shape.key_size = 4;
  shape.value_size = 8;
  shape.max_entries = 3;
  EXPECT_TRUE(
      DescribePinConflict("conntrack", "b", "zone 'a'", shape, shape)
          .empty());
}

TEST(DescribePinConflictTest, SaysWhatToDoAboutIt) {
  // The operator reading this at 3am needs the fix, not just the
  // fault: a name that carries the zone, or a shape that does not
  // come from a per-zone count.
  PinnedMapShape want;
  want.max_entries = 3;
  PinnedMapShape have;
  have.max_entries = 1;
  std::string message = DescribePinConflict(
      "fwl_counters", "b", "zone 'a'", want, have);
  EXPECT_NE(message.find("per-zone"), std::string::npos);
  EXPECT_NE(message.find("ONE kernel map"), std::string::npos);
}

}  // namespace
}  // namespace f
