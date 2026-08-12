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

// --- Pin reconciliation ---------------------------------------------
//
// What a load may inherit from bpffs. The pins are left by a PREVIOUS
// compilation — on reload by the policy still attached, on cold boot by
// a process that is gone — and the two questions are separate: do the
// contents still mean anything (MapLifetime, carried in the manifest as
// `persistent_maps`), and does the definition still match (the check
// libbpf makes, made early enough to say something useful).
//
// DecidePinFate is the whole decision as a pure function so it can be
// tested without bpffs or root; ReconcilePinnedMaps is the loop that
// applies it, covered on hardware by l8_09/l8_10.

namespace {

/// A shape distinct enough that any field mismatch is visible.
auto SomeShape() -> PinnedMapShape {
  PinnedMapShape s;
  s.type = 1;
  s.key_size = 16;
  s.value_size = 24;
  s.max_entries = 65536;
  s.map_flags = 0;
  return s;
}

const std::vector<std::string> kPersistent = {"conntrack", "fwl_nat"};

}  // namespace

TEST(DecidePinFateTest, PolicyScopedPinsAlwaysGo) {
  // Numbered or sized by the compilation that pinned them. Their shape
  // agreeing with the new bundle's proves nothing — slot 0 of the next
  // policy is a different rule — so a matching declaration must not
  // rescue them on either path.
  auto shape = SomeShape();
  for (auto policy : {PinPolicy::kColdBoot, PinPolicy::kReload}) {
    for (const char* name : {"fwl_counters_a", "fwl_log_sample_a",
                             "fwl_rl_a_0", "fwl_rl_g0", "fwl_geoip_a_0",
                             "fwl_devmap_wan", "fwl_log_events",
                             "fwl_nat_cfg"}) {
      EXPECT_EQ(DecidePinFate(name, kPersistent, &shape, shape, policy),
                PinVerdict::kDiscard)
          << name;
    }
  }
}

TEST(DecidePinFateTest, FlowKeyedPinsAreAdoptedWhenTheyStillFit) {
  // conntrack and fwl_nat are keyed by the flow 5-tuple, which means
  // the same thing under any policy. This is the case that keeps
  // established connections alive across a reload AND across a
  // process restart.
  auto shape = SomeShape();
  for (auto policy : {PinPolicy::kColdBoot, PinPolicy::kReload}) {
    EXPECT_EQ(
        DecidePinFate("conntrack", kPersistent, &shape, shape, policy),
        PinVerdict::kAdopt);
    EXPECT_EQ(
        DecidePinFate("fwl_nat", kPersistent, &shape, shape, policy),
        PinVerdict::kAdopt);
  }
}

TEST(DecidePinFateTest, AdoptionStillRequiresTheDefinitionToMatch) {
  // The back door: a map allowed to persist is still only reusable if
  // the incoming bundle declares it exactly as it is pinned. Skipping
  // this check would reintroduce the -EINVAL load failure through the
  // one map that is permitted to survive.
  auto have = SomeShape();
  auto want = have;
  want.max_entries = 4096;
  EXPECT_NE(DecidePinFate("conntrack", kPersistent, &want, have,
                          PinPolicy::kColdBoot),
            PinVerdict::kAdopt);
  EXPECT_NE(DecidePinFate("conntrack", kPersistent, &want, have,
                          PinPolicy::kReload),
            PinVerdict::kAdopt);
}

TEST(DecidePinFateTest, ColdBootDiscardsWhatItCannotReuse) {
  // No running policy to fall back on: deferring to the loader means
  // fd exits, systemd restarts it, and it fails the same way forever
  // with nothing attached. Discarding costs a conntrack table; not
  // starting costs the whole firewall.
  auto have = SomeShape();
  auto want = have;
  want.value_size = 32;
  EXPECT_EQ(DecidePinFate("conntrack", kPersistent, &want, have,
                          PinPolicy::kColdBoot),
            PinVerdict::kDiscard);
}

TEST(DecidePinFateTest, ReloadDefersToTheLoaderInstead) {
  // On reload the old policy is attached and filtering. Destroying
  // live state to force the new bundle in would be the wrong trade:
  // let the load fail, keep what is running, and let
  // ExplainPinConflict name the map and the numbers.
  auto have = SomeShape();
  auto want = have;
  want.value_size = 32;
  EXPECT_EQ(DecidePinFate("conntrack", kPersistent, &want, have,
                          PinPolicy::kReload),
            PinVerdict::kDefer);
}

TEST(DecidePinFateTest, UndeclaredPersistentPinIsDroppedNotHoarded) {
  // conntrack pinned, but no zone of the incoming bundle uses
  // conntrack. Nothing reads it and nothing ages it out — GC only runs
  // while a loaded bundle carries the map — so keeping it means a
  // later policy that re-adds conntrack would adopt entries of
  // arbitrary age.
  auto have = SomeShape();
  EXPECT_EQ(DecidePinFate("conntrack", kPersistent, nullptr, have,
                          PinPolicy::kColdBoot),
            PinVerdict::kDiscard);
}

TEST(DecidePinFateTest, AnUnknownNameIsDiscarded) {
  // The sweep is an allowlist of what survives, not a blocklist of
  // what goes. A map added to the emitter and forgotten here is
  // discarded — at worst that costs state that could have been kept.
  // The previous prefix-blocklist adopted it instead, which is the
  // silent-wrong direction and how this class of defect kept
  // recurring.
  auto shape = SomeShape();
  EXPECT_EQ(DecidePinFate("fwl_something_new", kPersistent, &shape,
                          shape, PinPolicy::kColdBoot),
            PinVerdict::kDiscard);
}

TEST(DefaultPersistentMapNamesTest, IsExactlyTheFlowKeyedPair) {
  // Used for bundles compiled before manifests carried
  // `persistent_maps`. Must equal emitter.persistent_map_names();
  // fwl/tests/unit/test_map_lifetime.py reads this source file and
  // fails if the registry and this list drift apart.
  EXPECT_EQ(DefaultPersistentMapNames(),
            (std::vector<std::string>{"conntrack", "fwl_nat"}));
}

TEST_F(BpfLoaderResolverTest, ManifestPersistentMapsAreRead) {
  auto bundle = scratch_ / "bundle";
  fs::create_directories(bundle);
  std::ofstream(bundle / "manifest.json")
      << R"({"version":"0.4","persistent_maps":["conntrack"]})";
  EXPECT_EQ(ReadPersistentMapNames(bundle.string()),
            (std::vector<std::string>{"conntrack"}));
}

TEST_F(BpfLoaderResolverTest, OlderManifestFallsBackRatherThanSweeping) {
  // A bundle compiled before this field existed. Reading "no
  // persistent maps" out of its silence would drop the conntrack table
  // on the first reload after a package upgrade — the exact outage the
  // mechanism exists to prevent.
  auto bundle = scratch_ / "bundle";
  fs::create_directories(bundle);
  std::ofstream(bundle / "manifest.json")
      << R"({"version":"0.4","zones":[],"programs":[]})";
  EXPECT_EQ(ReadPersistentMapNames(bundle.string()),
            DefaultPersistentMapNames());
}

TEST_F(BpfLoaderResolverTest, UnreadableManifestFallsBackToo) {
  EXPECT_EQ(ReadPersistentMapNames((scratch_ / "absent").string()),
            DefaultPersistentMapNames());
}

TEST_F(BpfLoaderResolverTest, ReconcileOnAnAbsentPinRootIsQuiet) {
  // First boot, or bpffs freshly mounted. Nothing pinned, nothing to
  // reconcile, and no error either.
  auto report = ReconcilePinnedMaps((scratch_ / "bundle").string(),
                                    (scratch_ / "nopins").string(),
                                    PinPolicy::kColdBoot, 300);
  EXPECT_TRUE(report.discarded.empty());
  EXPECT_TRUE(report.adopted.empty());
  EXPECT_EQ(report.conntrack_swept, 0u);
}

}  // namespace
}  // namespace f
