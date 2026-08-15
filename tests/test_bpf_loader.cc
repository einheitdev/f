/// @file test_bpf_loader.cc
/// @brief Bundle manifest, pin reconciliation and attach-plan tests.
///
/// Four `ResolveBpfObjPath` tests were here, pinning the v0.1
/// cold-boot search list (`fw.bpf.o`, `build/fw.bpf.o`,
/// `../bpf/fw.bpf.o`, `/usr/lib/f/fw.bpf.o`) that `LoadProgram`
/// consulted when no bundle was staged. That list is gone; the shared
/// fixture below outlived it and the multi-zone tests still use it.

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
                             "fwl_nat_cfg_a"}) {
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

TEST(DecidePinFateTest, ADevmapPinLeftByAnOlderBundleIsSweptAway) {
  // The upgrade path for the devmap reclassification, and the only
  // thing on the daemon side that change touches.
  //
  // Until it, `fwl_devmap_<dest>` carried LIBBPF_PIN_BY_NAME, so a box
  // that ran any redirecting policy has one in bpffs. A devmap cannot
  // be reused from a pin at all — the kernel forces BPF_F_RDONLY_PROG
  // in dev_map_alloc and libbpf's reuse check compares that against
  // the object's declared map_flags of 0 — which is why the emitter
  // stopped pinning them, and why the second inside zone of a gateway
  // could not load. Bundles compiled since declare no such pin, so
  // `declared` is null here, and the pin has to GO rather than be left
  // to accumulate: it holds ifindexes of a policy that is no longer
  // running, and nothing will ever overwrite it.
  //
  // Both paths, because a devmap pin outlives a process restart just
  // as it outlives a reload.
  auto have = SomeShape();
  for (auto policy : {PinPolicy::kColdBoot, PinPolicy::kReload}) {
    EXPECT_EQ(DecidePinFate("fwl_devmap_wan", kPersistent, nullptr,
                            have, policy),
              PinVerdict::kDiscard);
  }
}

TEST(DecidePinFateTest, ALegacyNatCfgPinIsSweptAway) {
  // The upgrade path for the masquerade-source split.
  //
  // Until it, every zone object pinned one bundle-global `fwl_nat_cfg`,
  // so a box that ran any masquerading policy has one in bpffs. Bundles
  // compiled since pin `fwl_nat_cfg_<zone>` instead and declare that
  // name not at all, so `declared` is null here and the pin has to GO:
  // it holds the masquerade address of a policy that is no longer
  // running, and nothing will ever overwrite it.
  //
  // It costs nothing to discard, which is the whole reason the split is
  // safe. `fd` derives every slot from THIS bundle's redirect topology
  // and the live interface addresses at every load, so the value is
  // rewritten before the first packet either way.
  auto have = SomeShape();
  for (auto policy : {PinPolicy::kColdBoot, PinPolicy::kReload}) {
    EXPECT_EQ(DecidePinFate("fwl_nat_cfg", kPersistent, nullptr,
                            have, policy),
              PinVerdict::kDiscard);
    // And the new name is policy-scoped too: slot 0 is derived at load
    // time, so a matching declaration must not rescue it either.
    EXPECT_EQ(DecidePinFate("fwl_nat_cfg_lan", kPersistent, &have,
                            have, policy),
              PinVerdict::kDiscard);
  }
}

TEST(NatCfgMapNamesTest, ThePerZoneNameIsPreferredAndTheOldOneRemains) {
  // The masquerade source is `fwl_nat_cfg_<zone>` because the address
  // is a per-zone fact: it is the address of the zone THIS one
  // redirects to, and two masquerading zones need not name the same
  // uplink. Under the old bundle-global name it was one kernel map
  // with one slot 0, written once per masquerading zone, so the last
  // zone loaded decided what every masquerading program translated to.
  //
  // The old name stays in the list, second, and dropping it would be
  // the failure `ManifestStatesMasquerade` documents one field over: a
  // bundle staged by an older `fwl` has only the bundle-global map, and
  // an `fd` that could not find it would turn every masquerade in that
  // bundle into a silent no-op across an upgrade the operator did not
  // ask for.
  auto names = NatCfgMapNames("ina");
  ASSERT_EQ(names.size(), 2u);
  EXPECT_EQ(names[0], "fwl_nat_cfg_ina");
  EXPECT_EQ(names[1], "fwl_nat_cfg");
}

TEST(NatCfgMapNamesTest, TwoZonesAskForTwoDifferentMaps) {
  // The property the whole change rests on, stated where a rename
  // cannot quietly undo it.
  EXPECT_NE(NatCfgMapNames("ina")[0], NatCfgMapNames("inb")[0]);
  EXPECT_EQ(NatCfgMapNames("ina")[1], NatCfgMapNames("inb")[1]);
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

TEST_F(BpfLoaderResolverTest, ManifestNamesItsMasqueradeSources) {
  // Every object in a NAT bundle carries fwl_nat_cfg — the de-NAT pass
  // on the return path needs it — so the map's presence does not
  // identify a masquerade source. This flag does, and `false` here is
  // an answer, not a silence.
  auto bundle = scratch_ / "bundle";
  fs::create_directories(bundle);
  std::ofstream(bundle / "manifest.json")
      << R"({"version":"0.4","programs":[)"
         R"({"zone":"lan","masquerades":true},)"
         R"({"zone":"wan","masquerades":false}]})";
  EXPECT_TRUE(ManifestStatesMasquerade(bundle.string()));
}

TEST_F(BpfLoaderResolverTest, AManifestWithoutTheFlagAnswersNothing) {
  // Compiled before the field existed. Reading its silence as "no zone
  // masquerades" would seed no address at all, and the XDP masquerade
  // action no-ops on an unset slot: an `fd` upgrade would silently
  // stop translating a bundle it never recompiled. The loader falls
  // back to the old presence rule for these, which is what this
  // distinction is for.
  auto bundle = scratch_ / "bundle";
  fs::create_directories(bundle);
  std::ofstream(bundle / "manifest.json")
      << R"({"version":"0.4","programs":[{"zone":"lan"}]})";
  EXPECT_FALSE(ManifestStatesMasquerade(bundle.string()));
}

TEST_F(BpfLoaderResolverTest, AnAbsentManifestAnswersNothingEither) {
  EXPECT_FALSE(
      ManifestStatesMasquerade((scratch_ / "absent").string()));
}

// --- What the bundle asks to be attached, and where ------------------
//
// The manifest's "zones" array is not the answer on its own. A unit
// written in the simple form — `@xdp(eth0)`, no `zone` line, the form
// the docs teach and the first one anybody writes — declares no zones,
// so the array is `[]` while the program entry names `eth0`. Deriving
// interfaces from the array alone gave that bundle none, and the
// loader attached it to nothing and returned success: `fd` logged
// "1 zone program(s)", which was true of the program list and said
// nothing at all about attachment, while every packet on the box
// flowed unfiltered.

class BundlePlanTest : public BpfLoaderResolverTest {
 protected:
  auto Plan(const std::string& manifest) -> BundleAttachPlan {
    auto bundle = scratch_ / "bundle";
    fs::create_directories(bundle);
    std::ofstream(bundle / "manifest.json") << manifest;
    return PlanBundleAttach(bundle.string());
  }
};

TEST_F(BundlePlanTest, DeclaredZonesCarryTheirInterfaces) {
  auto plan = Plan(R"({"version":"0.4",
    "zones":[{"name":"lan","interfaces":["lan0","lan1"]},
             {"name":"wan","interfaces":["wan0"]}],
    "programs":[{"zone":"lan","object":"lan.bpf.o"},
                {"zone":"wan","object":"wan.bpf.o"}]})");
  EXPECT_EQ(plan.zone_interfaces["lan"],
            (std::vector<std::string>{"lan0", "lan1"}));
  EXPECT_EQ(plan.zone_interfaces["wan"],
            (std::vector<std::string>{"wan0"}));
  EXPECT_TRUE(plan.zones_without_interfaces.empty());
}

TEST_F(BundlePlanTest, TheSimpleFormNamesItsInterfaceInTheProgram) {
  // `@xdp(eth0)` with no zone declaration. FWL_V04_SPEC.md § 6.2:
  // "one implicit zone whose name is the @xdp argument"; the v0.1
  // spec spells the hook `@xdp(<interface>)`. So the zone name IS the
  // interface name, and a plan that comes back empty here is a
  // firewall that attaches to nothing.
  auto plan = Plan(R"({"version":"0.4","zones":[],
    "programs":[{"zone":"eth0","object":"eth0.bpf.o"}]})");
  EXPECT_EQ(plan.zone_interfaces["eth0"],
            (std::vector<std::string>{"eth0"}));
  EXPECT_TRUE(plan.zones_without_interfaces.empty());
}

TEST_F(BundlePlanTest, ARedirectOnlyZoneKeepsItsInterfaces) {
  // A declared zone with no @xdp block of its own is legal (v0.4
  // § 6.2) and is still a redirect destination — its interfaces are
  // what fills the destination devmap, so dropping it from the plan
  // would make every redirect into it drop the frame.
  auto plan = Plan(R"({"version":"0.4",
    "zones":[{"name":"lan","interfaces":["lan0"]},
             {"name":"dmz","interfaces":["dmz0"]}],
    "programs":[{"zone":"lan","object":"lan.bpf.o",
                 "redirects_to":["dmz"]}]})");
  EXPECT_EQ(plan.zone_interfaces["dmz"],
            (std::vector<std::string>{"dmz0"}));
}

TEST_F(BundlePlanTest, AProgramZoneWithNoInterfacesIsReported) {
  // A declared zone the manifest gives an empty interface list. `fwl`
  // cannot emit this (the analyzer rejects an empty zone), which is
  // the point: it means the manifest and the compiler disagree, and
  // the program can never be attached to anything. That is a
  // different fact from "the NIC has not appeared yet" and must not
  // be reported as one.
  auto plan = Plan(R"({"version":"0.4",
    "zones":[{"name":"lan","interfaces":[]}],
    "programs":[{"zone":"lan","object":"lan.bpf.o"}]})");
  EXPECT_EQ(plan.zones_without_interfaces,
            (std::vector<std::string>{"lan"}));
}

TEST_F(BundlePlanTest, AnUnreadableManifestPlansNothing) {
  EXPECT_TRUE(
      PlanBundleAttach((scratch_ / "absent").string())
          .zone_interfaces.empty());
}

// --- Refusing a load that would attach to nothing ---------------------

class ZeroAttachTest : public BpfLoaderResolverTest {
 protected:
  // A bundle whose manifest is `manifest` and whose named objects
  // exist as files. The objects are not valid ELF: these tests must
  // fail BEFORE libbpf is reached, so reaching it at all is the
  // failure they detect.
  auto Load(const std::string& manifest,
            const std::vector<std::string>& objects)
      -> std::expected<ZoneBundleHandles, Error<BpfError>> {
    auto bundle = scratch_ / "bundle";
    fs::create_directories(bundle);
    std::ofstream(bundle / "manifest.json") << manifest;
    for (const auto& o : objects) {
      Touch(bundle / o);
    }
    return LoadZoneBundle(bundle.string(),
                          (scratch_ / "pins").string());
  }
};

TEST_F(ZeroAttachTest, NoInterfaceOnThisHostIsAFailedLoad) {
  // Every interface the bundle names is absent. Nothing can be
  // attached, so not one packet would be inspected — and a load that
  // returns success here hands `fd` a firewall that is not in the
  // path while every indicator reads healthy. The rule is about the
  // outcome, not the reason: zero interfaces attached is a failed
  // load however it came about.
  auto r = Load(R"({"version":"0.4",
    "zones":[{"name":"lan","interfaces":["f-no-such-if0"]}],
    "programs":[{"zone":"lan","object":"lan.bpf.o"}]})",
                {"lan.bpf.o"});
  ASSERT_FALSE(r.has_value()) << "attached to nothing and said ok";
  EXPECT_EQ(r.error().code, BpfError::kAttachFailed);
  // Refused for the right reason, and early: had it got as far as
  // libbpf the message would be about opening a file that is not an
  // object. It must name the interface it wanted, too — an operator
  // reading this at 3am needs the typo, not a verdict.
  EXPECT_NE(r.error().message.find("f-no-such-if0"),
            std::string::npos)
      << r.error().message;
  EXPECT_NE(r.error().message.find("ZERO"), std::string::npos)
      << r.error().message;
}

TEST_F(ZeroAttachTest, TheSimpleFormIsRefusedForItsOwnInterface) {
  // The degenerate `@xdp(<iface>)` bundle, with an interface that
  // does not exist. Before the loader read the program's zone name as
  // an interface this could not even reach the refusal: the plan was
  // empty, the attach loop ran zero times, and the load succeeded.
  // Now it is the ordinary missing-interface case and says so.
  auto r = Load(R"({"version":"0.4","zones":[],
    "programs":[{"zone":"f-no-such-if1","object":"x.bpf.o"}]})",
                {"x.bpf.o"});
  ASSERT_FALSE(r.has_value()) << "attached to nothing and said ok";
  EXPECT_EQ(r.error().code, BpfError::kAttachFailed);
  EXPECT_NE(r.error().message.find("f-no-such-if1"),
            std::string::npos)
      << r.error().message;
}

TEST_F(ZeroAttachTest, AZoneProgramWithNoInterfaceAtAllIsRefused) {
  // Not a missing NIC — a manifest that names no interface for a
  // program at all. There is nothing to wait for, so it is refused
  // before any object is opened, with a message that says which zone.
  auto r = Load(R"({"version":"0.4",
    "zones":[{"name":"lan","interfaces":[]}],
    "programs":[{"zone":"lan","object":"lan.bpf.o"}]})",
                {"lan.bpf.o"});
  ASSERT_FALSE(r.has_value());
  EXPECT_EQ(r.error().code, BpfError::kLoadFailed);
  // The specific sentence, not merely "some error": the fake ELF in
  // this bundle would fail the load anyway, and a test satisfied by
  // that would pass without the check it exists to pin.
  EXPECT_NE(r.error().message.find("names no interface"),
            std::string::npos)
      << r.error().message;
  EXPECT_NE(r.error().message.find("lan"), std::string::npos)
      << r.error().message;
}

TEST_F(ZeroAttachTest, AnObjectlessBundleStillReportsItsOwnFault) {
  // The l8_01 case: no compiled object anywhere (clang unavailable at
  // compile time). The interface pre-flight must not steal this
  // message — nothing is attachable because nothing was compiled, and
  // that is what the operator has to fix.
  auto r = Load(R"({"version":"0.4",
    "zones":[{"name":"lan","interfaces":["lo"]}],
    "programs":[{"zone":"lan","object":null}]})",
                {});
  ASSERT_FALSE(r.has_value());
  EXPECT_EQ(r.error().code, BpfError::kLoadFailed);
  EXPECT_NE(r.error().message.find("no loadable zone programs"),
            std::string::npos)
      << r.error().message;
}

TEST_F(ZeroAttachTest, APresentInterfaceGetsPastThePreflight) {
  // The control that keeps the tests above from passing for the wrong
  // reason. `lo` exists on every host, so the pre-flight must let this
  // through and the load must fail later, on the object — proving the
  // refusals above are about attachment and not about the fake ELF
  // every one of these bundles carries.
  auto r = Load(R"({"version":"0.4",
    "zones":[{"name":"lan","interfaces":["lo"]}],
    "programs":[{"zone":"lan","object":"lan.bpf.o"}]})",
                {"lan.bpf.o"});
  ASSERT_FALSE(r.has_value());
  EXPECT_EQ(r.error().message.find("ZERO"), std::string::npos)
      << "pre-flight fired on a host that has `lo`: "
      << r.error().message;
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
