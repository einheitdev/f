/// @file test_sysconfig_networkd.cc
/// @brief Units that leave the model must leave the disk.
///
/// The sequence that produced this file is the most ordinary one
/// there is: `set address enp1s0f1 ...` once while exploring, then
/// write the real configuration. The first left `10-f-enp1s0f1.link`
/// behind; the second wrote `10-f-lan0.link`. Both pinned the same MAC
/// to different names, udev applied them in filename order, the stale
/// one sorted first and won, the port was never renamed — and every
/// generated file naming `lan0` then matched no device, silently.

#include <gtest/gtest.h>

#include <algorithm>
#include <filesystem>
#include <format>
#include <fstream>
#include <sstream>
#include <string>

#include "f/sysconfig/artifact.h"
#include "f/sysconfig/networkd.h"
#include "f/sysconfig/parse.h"

namespace f::sysconfig {
namespace {

namespace fs = std::filesystem;

constexpr const char* kTwoPorts = R"YAML(
zones:
  wan:
  testnet:
interfaces:
  wan0:
    mac: "52:54:00:aa:bb:01"
    address: dhcp
    zone: wan
  lan0:
    mac: "52:54:00:aa:bb:02"
    address: 10.10.0.1/24
    zone: testnet
)YAML";

auto MustParse(const std::string& yaml) -> SystemConfig {
  auto parsed = ParseSystemConfigString(yaml);
  EXPECT_TRUE(parsed.has_value());
  return parsed.value_or(SystemConfig{});
}

class UnitDir {
 public:
  UnitDir() {
    dir_ = fs::temp_directory_path() /
           std::format("f-networkd-{}-{}", ::getpid(), ++counter_);
    fs::create_directories(dir_);
  }
  ~UnitDir() {
    std::error_code ec;
    fs::remove_all(dir_, ec);
  }
  UnitDir(const UnitDir&) = delete;
  auto operator=(const UnitDir&) -> UnitDir& = delete;

  auto Path() const -> std::string { return dir_.string(); }

  auto Write(const std::string& name, const std::string& body)
      -> void {
    std::ofstream out(dir_ / name);
    out << body;
  }

  /// A file in the shape a previous apply would have left: digest
  /// header and all, so it is recognisably ours.
  auto WriteGenerated(const std::string& name,
                      const std::string& body) -> void {
    Write(name, WrapWithDigest(body));
  }

  auto Exists(const std::string& name) const -> bool {
    return fs::exists(dir_ / name);
  }

  auto Names() const -> std::vector<std::string> {
    std::vector<std::string> out;
    for (const auto& e : fs::directory_iterator(dir_)) {
      out.push_back(e.path().filename().string());
    }
    std::sort(out.begin(), out.end());
    return out;
  }

 private:
  fs::path dir_;
  static inline int counter_ = 0;
};

auto Options(const UnitDir& dir, bool force = false)
    -> NetworkdOptions {
  NetworkdOptions o;
  o.dir = dir.Path();
  o.refuse_on_drift = !force;
  return o;
}

/// The exact sequence from the rehearsal, reproduced end to end.
TEST(NetworkdSweepTest, StaleLinkFromAnEarlierNameIsRemoved) {
  UnitDir dir;
  // What one exploratory `set address enp1s0f1 ...` leaves behind.
  dir.WriteGenerated("10-f-enp1s0f1.link",
                     "[Match]\nMACAddress=52:54:00:aa:bb:02\n\n"
                     "[Link]\nName=enp1s0f1\nNamePolicy=\n");
  dir.WriteGenerated("10-f-enp1s0f1.network",
                     "[Match]\nName=enp1s0f1\n");

  auto report = ApplyNetworkd(MustParse(kTwoPorts), Options(dir));
  ASSERT_TRUE(report.has_value()) << report.error();

  EXPECT_TRUE(dir.Exists("10-f-lan0.link"));
  EXPECT_FALSE(dir.Exists("10-f-enp1s0f1.link"))
      << "a stale .link sorts before 10-f-lan0.link and wins the "
         "rename for the same MAC";
  EXPECT_FALSE(dir.Exists("10-f-enp1s0f1.network"));
  EXPECT_EQ(report->removed.size(), 2u);
  EXPECT_TRUE(report->conflicts.empty());
}

/// Idempotence: a second apply removes nothing, because there is
/// nothing left over. A sweep that kept finding work would be a sweep
/// that was deleting the wrong things.
TEST(NetworkdSweepTest, SecondApplyRemovesNothing) {
  UnitDir dir;
  auto cfg = MustParse(kTwoPorts);
  ASSERT_TRUE(ApplyNetworkd(cfg, Options(dir)).has_value());
  auto again = ApplyNetworkd(cfg, Options(dir));
  ASSERT_TRUE(again.has_value()) << again.error();
  EXPECT_TRUE(again->removed.empty());
  EXPECT_TRUE(again->changed.empty());
  EXPECT_EQ(dir.Names().size(), 4u);
}

/// An interface dropped from the model takes its units with it.
TEST(NetworkdSweepTest, InterfaceLeavingTheModelTakesItsUnits) {
  UnitDir dir;
  ASSERT_TRUE(
      ApplyNetworkd(MustParse(kTwoPorts), Options(dir)).has_value());
  auto smaller = MustParse(R"YAML(
zones:
  wan:
interfaces:
  wan0:
    mac: "52:54:00:aa:bb:01"
    address: dhcp
    zone: wan
)YAML");
  auto report = ApplyNetworkd(smaller, Options(dir));
  ASSERT_TRUE(report.has_value()) << report.error();
  EXPECT_FALSE(dir.Exists("10-f-lan0.link"));
  EXPECT_FALSE(dir.Exists("10-f-lan0.network"));
  EXPECT_EQ(report->removed.size(), 2u);
}

/// A file a person wrote is never deleted, however inconvenient its
/// name. It is reported instead, because it may still decide a port's
/// name and the operator is the only one who can say what it is for.
TEST(NetworkdSweepTest, AFileWeDidNotWriteIsReportedNotDeleted) {
  UnitDir dir;
  dir.Write("10-f-handmade.link",
            "[Match]\nMACAddress=52:54:00:99:99:99\n\n"
            "[Link]\nName=handmade\n");
  auto report = ApplyNetworkd(MustParse(kTwoPorts), Options(dir));
  ASSERT_TRUE(report.has_value()) << report.error();
  EXPECT_TRUE(dir.Exists("10-f-handmade.link"));
  ASSERT_EQ(report->conflicts.size(), 1u);
  EXPECT_NE(report->conflicts[0].find("10-f-handmade.link"),
            std::string::npos);
}

/// Somebody else's `.link` claiming one of our MACs under another name
/// still decides the rename, and we cannot delete it. So the apply is
/// refused: a policy aimed at the wrong port is a bypass, and a
/// warning at the bottom of a screen is not a defence.
TEST(NetworkdSweepTest, ForeignUnitClaimingOurMacRefusesTheApply) {
  UnitDir dir;
  dir.Write("05-vendor.link",
            "[Match]\nMACAddress=52:54:00:aa:bb:02\n\n"
            "[Link]\nName=eth7\n");
  auto report = ApplyNetworkd(MustParse(kTwoPorts), Options(dir));
  ASSERT_FALSE(report.has_value());
  EXPECT_NE(report.error().find("05-vendor.link"), std::string::npos)
      << report.error();
  EXPECT_NE(report.error().find("filename order"), std::string::npos)
      << report.error();

  // ...and force says so out loud rather than silently proceeding.
  auto forced =
      ApplyNetworkd(MustParse(kTwoPorts), Options(dir, true));
  ASSERT_TRUE(forced.has_value()) << forced.error();
  ASSERT_FALSE(forced->conflicts.empty());
}

/// A `.link` that names the same port the same way is not a conflict.
/// Refusing on it would make the sweep unusable on any real box.
TEST(NetworkdSweepTest, AgreeingUnitIsNotAConflict) {
  UnitDir dir;
  dir.Write("05-vendor.link",
            "[Match]\nMACAddress=52:54:00:AA:BB:02\n\n"
            "[Link]\nName=lan0\n");
  auto report = ApplyNetworkd(MustParse(kTwoPorts), Options(dir));
  ASSERT_TRUE(report.has_value()) << report.error();
  EXPECT_TRUE(report->conflicts.empty());
}

TEST(NetworkdSweepTest, ScanReadsWhoeverWroteTheUnit) {
  UnitDir dir;
  dir.WriteGenerated("10-f-lan0.link",
                     "[Match]\nMACAddress=52:54:00:AA:BB:02\n\n"
                     "[Link]\nName=lan0\n");
  dir.Write("99-other.link",
            "[Match]\nMACAddress=aa:bb:cc:dd:ee:ff\n\n"
            "[Link]\nName=other0\n");
  auto claims = ScanLinkUnits(dir.Path());
  ASSERT_EQ(claims.size(), 2u);
  EXPECT_EQ(claims[0].mac, "52:54:00:aa:bb:02");
  EXPECT_EQ(claims[0].name, "lan0");
  EXPECT_TRUE(claims[0].generated);
  EXPECT_EQ(claims[1].name, "other0");
  EXPECT_FALSE(claims[1].generated);
}

}  // namespace
}  // namespace f::sysconfig
