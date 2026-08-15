/// @file test_lease.cc
/// @brief The lease file, the journal and the join between them.
///
/// Three facts these tests exist to hold down:
///
///  1. An empty device list carries a reason with it. A stub returning
///     `{}` fails every case in the Availability suite, because each
///     one asserts *which* emptiness it got.
///  2. A device is only called new when we watched it arrive. The
///     first run on a box that has been up for a week must not paint
///     the whole segment as new arrivals.
///  3. Arrivals and departures are transitions, reported once. A
///     device that left an hour ago is not still leaving.

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "f/lease/journal.h"
#include "f/lease/lease.h"
#include "f/lease/view.h"
#include "f/sysconfig/model.h"
#include "f/sysconfig/parse.h"

namespace {

using f::lease::BuildReport;
using f::lease::CollectDevices;
using f::lease::Device;
using f::lease::DeviceRecord;
using f::lease::FirstSeenPrecision;
using f::lease::Journal;
using f::lease::JournalAvailability;
using f::lease::Lease;
using f::lease::LeaseAvailability;
using f::lease::LeaseError;
using f::lease::MatchDevices;
using f::lease::Observe;
using f::lease::ParseLeases;
using f::lease::ReadLeases;
using f::lease::ViewOptions;

/// A scratch directory that removes itself. Every filesystem-touching
/// test gets its own, so nothing here can read or write /var.
class TempDir {
 public:
  TempDir() {
    auto base = std::filesystem::temp_directory_path();
    path_ = base / std::format("f-lease-test-{}-{}", ::getpid(),
                               ++counter_);
    std::filesystem::create_directories(path_);
  }
  ~TempDir() {
    std::error_code ec;
    std::filesystem::remove_all(path_, ec);
  }
  TempDir(const TempDir&) = delete;
  auto operator=(const TempDir&) -> TempDir& = delete;

  auto operator/(const std::string& name) const -> std::string {
    return (path_ / name).string();
  }

 private:
  std::filesystem::path path_;
  static inline int counter_ = 0;
};

auto WriteFile(const std::string& path, const std::string& body)
    -> void {
  std::ofstream out(path, std::ios::trunc);
  out << body;
}

auto ReadWholeFile(const std::string& path) -> std::string {
  std::ifstream in(path);
  return std::string((std::istreambuf_iterator<char>(in)),
                     std::istreambuf_iterator<char>());
}

/// A config with one zone, one addressed interface and DHCP on it.
auto SampleConfig() -> f::sysconfig::SystemConfig {
  auto cfg = f::sysconfig::ParseSystemConfigString(R"(
zones:
  lan:
interfaces:
  lan0:
    mac: "52:54:00:11:22:33"
    address: 10.10.0.1/24
    zone: lan
services:
  dhcp:
    - zone: lan
      range: 10.10.0.100-10.10.0.200
      lease: 1h
)");
  EXPECT_TRUE(cfg.has_value());
  return cfg.value_or(f::sysconfig::SystemConfig{});
}

// -- parsing ---------------------------------------------------------

TEST(LeaseFile, ParsesTheFormatDnsmasqWrites) {
  auto r = ParseLeases(
      "1786000000 aa:bb:cc:dd:ee:01 10.10.0.101 board-a "
      "01:aa:bb:cc:dd:ee:01\n");
  ASSERT_EQ(r.leases.size(), 1U);
  EXPECT_EQ(r.leases[0].expiry, 1786000000);
  EXPECT_EQ(r.leases[0].mac, "aa:bb:cc:dd:ee:01");
  EXPECT_EQ(r.leases[0].address, "10.10.0.101");
  EXPECT_EQ(r.leases[0].hostname, "board-a");
  EXPECT_EQ(r.leases[0].client_id, "01:aa:bb:cc:dd:ee:01");
  EXPECT_TRUE(r.unparsable.empty());
}

TEST(LeaseFile, StarMeansTheClientSaidNothing) {
  auto r = ParseLeases(
      "1786000000 aa:bb:cc:dd:ee:01 10.10.0.101 * *\n");
  ASSERT_EQ(r.leases.size(), 1U);
  EXPECT_EQ(r.leases[0].hostname, "");
  EXPECT_EQ(r.leases[0].client_id, "");
}

TEST(LeaseFile, MacSpellingIsNormalised) {
  auto r = ParseLeases(
      "1786000000 AA:BB:CC:DD:EE:01 10.10.0.101 x *\n");
  ASSERT_EQ(r.leases.size(), 1U);
  EXPECT_EQ(r.leases[0].mac, "aa:bb:cc:dd:ee:01");
}

TEST(LeaseFile, KeepsGoingPastALineItCannotRead) {
  auto r = ParseLeases(
      "1786000000 aa:bb:cc:dd:ee:01 10.10.0.101 a *\n"
      "this is not a lease\n"
      "1786000001 aa:bb:cc:dd:ee:02 10.10.0.102 b *\n");
  EXPECT_EQ(r.leases.size(), 2U);
  ASSERT_EQ(r.unparsable.size(), 1U);
  EXPECT_EQ(r.unparsable[0], "this is not a lease");
}

TEST(LeaseFile, DuidLineIsNotALease) {
  auto r = ParseLeases(
      "duid 00:01:00:01:2d:xx\n"
      "1786000000 aa:bb:cc:dd:ee:01 10.10.0.101 a *\n");
  EXPECT_EQ(r.leases.size(), 1U);
  EXPECT_TRUE(r.unparsable.empty());
}

TEST(LeaseFile, Ipv6LeasesAreCountedNotCalledCorrupt) {
  auto r = ParseLeases(
      "1786000000 123456 2001:db8::5 host6 00:01:02\n"
      "1786000000 aa:bb:cc:dd:ee:01 10.10.0.101 a *\n");
  EXPECT_EQ(r.leases.size(), 1U);
  EXPECT_EQ(r.ipv6_skipped, 1U);
  EXPECT_TRUE(r.unparsable.empty());
}

TEST(LeaseFile, AbsentAndUnreadableAreDifferentAnswers) {
  TempDir dir;
  auto missing = ReadLeases(dir / "nope.leases");
  ASSERT_FALSE(missing.has_value());
  EXPECT_EQ(missing.error().code, LeaseError::kAbsent);

  auto path = dir / "locked.leases";
  WriteFile(path, "1786000000 aa:bb:cc:dd:ee:01 10.10.0.101 a *\n");
  std::filesystem::permissions(
      path, std::filesystem::perms::none,
      std::filesystem::perm_options::replace);
  auto locked = ReadLeases(path);
  // Running the suite as root defeats the permission bit; the case is
  // still worth asserting for every other environment.
  if (::geteuid() != 0) {
    ASSERT_FALSE(locked.has_value());
    EXPECT_EQ(locked.error().code, LeaseError::kUnreadable);
  }
  std::filesystem::permissions(
      path, std::filesystem::perms::owner_all,
      std::filesystem::perm_options::replace);
}

// -- the journal -----------------------------------------------------

TEST(Journal, FirstObservationDiscoversRatherThanWitnesses) {
  Journal j;
  std::vector<Lease> leases = {
      {.expiry = 4000, .mac = "aa:bb:cc:dd:ee:01",
       .address = "10.10.0.101", .hostname = "a", .client_id = ""},
  };
  auto r = Observe(j, leases, /*now=*/5000, /*lease_seconds=*/3600,
                   /*first_observation=*/true);
  EXPECT_TRUE(r.arrived.empty()) << "nothing was watched arriving";
  ASSERT_EQ(j.records.size(), 1U);
  EXPECT_EQ(j.records[0].precision, FirstSeenPrecision::kInferred);
  // expiry 4000 - lease 3600 = 400: the lease was issued then, so the
  // device has been there at least that long.
  EXPECT_EQ(j.records[0].first_seen, 400);
  EXPECT_EQ(j.records[0].last_arrival, 0);
}

TEST(Journal, ASecondSightingOfANewMacIsAnArrival) {
  Journal j;
  Observe(j, {}, 1000, 3600, /*first_observation=*/true);
  std::vector<Lease> leases = {
      {.expiry = 5000, .mac = "aa:bb:cc:dd:ee:02",
       .address = "10.10.0.102", .hostname = "b", .client_id = ""},
  };
  auto r = Observe(j, leases, 2000, 3600, false);
  ASSERT_EQ(r.arrived.size(), 1U);
  EXPECT_EQ(r.arrived[0], "aa:bb:cc:dd:ee:02");
  ASSERT_EQ(j.records.size(), 1U);
  EXPECT_EQ(j.records[0].precision, FirstSeenPrecision::kObserved);
  EXPECT_EQ(j.records[0].first_seen, 2000);
  EXPECT_EQ(j.records[0].last_arrival, 2000);
}

TEST(Journal, DepartureIsReportedOnceNotForever) {
  Journal j;
  std::vector<Lease> leases = {
      {.expiry = 5000, .mac = "aa:bb:cc:dd:ee:03",
       .address = "10.10.0.103", .hostname = "c", .client_id = ""},
  };
  Observe(j, leases, 1000, 3600, true);
  auto gone = Observe(j, {}, 2000, 3600, false);
  ASSERT_EQ(gone.departed.size(), 1U);
  auto still_gone = Observe(j, {}, 3000, 3600, false);
  EXPECT_TRUE(still_gone.departed.empty())
      << "a device that left an hour ago is not still leaving";
  EXPECT_TRUE(still_gone.Quiet());
}

TEST(Journal, ComingBackIsAnArrivalWithoutResettingFirstSeen) {
  Journal j;
  std::vector<Lease> leases = {
      {.expiry = 5000, .mac = "aa:bb:cc:dd:ee:04",
       .address = "10.10.0.104", .hostname = "d", .client_id = ""},
  };
  Observe(j, leases, 2000, 3600, true);
  Observe(j, {}, 3000, 3600, false);
  auto back = Observe(j, leases, 4000, 3600, false);
  ASSERT_EQ(back.arrived.size(), 1U);
  ASSERT_EQ(j.records.size(), 1U);
  EXPECT_EQ(j.records[0].last_arrival, 4000);
  EXPECT_EQ(j.records[0].first_seen, 1400)
      << "the first sighting does not move when a device returns";
}

TEST(Journal, ADeviceNeverFirstAppearsInTheFuture) {
  Journal j;
  // A lease issued at expiry-lease is in the future relative to `now`
  // — a clock step, or a lease file copied off another box. The bound
  // is capped at the present rather than printed as a negative age.
  std::vector<Lease> leases = {
      {.expiry = 99999, .mac = "aa:bb:cc:dd:ee:ff",
       .address = "10.10.0.199", .hostname = "skewed",
       .client_id = ""},
  };
  Observe(j, leases, 1000, 3600, true);
  ASSERT_EQ(j.records.size(), 1U);
  EXPECT_EQ(j.records[0].first_seen, 1000);
}

TEST(Journal, AChangeOfAddressIsCountedAndReported) {
  Journal j;
  std::vector<Lease> first = {
      {.expiry = 5000, .mac = "aa:bb:cc:dd:ee:05",
       .address = "10.10.0.105", .hostname = "e", .client_id = ""},
  };
  std::vector<Lease> second = {
      {.expiry = 9000, .mac = "aa:bb:cc:dd:ee:05",
       .address = "10.10.0.150", .hostname = "e", .client_id = ""},
  };
  Observe(j, first, 1000, 3600, true);
  auto r = Observe(j, second, 2000, 3600, false);
  ASSERT_EQ(r.readdressed.size(), 1U);
  EXPECT_EQ(j.records[0].address_changes, 1);
  EXPECT_EQ(j.records[0].address, "10.10.0.150");
}

TEST(Journal, SurvivesARoundTripThroughDisk) {
  TempDir dir;
  auto path = dir / "devices.json";
  Journal j;
  std::vector<Lease> leases = {
      {.expiry = 5000, .mac = "aa:bb:cc:dd:ee:06",
       .address = "10.10.0.106", .hostname = "f", .client_id = ""},
  };
  Observe(j, leases, 2000, 3600, true);
  ASSERT_TRUE(f::lease::SaveJournal(path, j).has_value());
  auto back = f::lease::LoadJournal(path);
  ASSERT_TRUE(back.has_value());
  ASSERT_EQ(back->records.size(), 1U);
  EXPECT_EQ(back->records[0].mac, "aa:bb:cc:dd:ee:06");
  EXPECT_TRUE(back->records[0].present);
  EXPECT_EQ(back->records[0].first_seen, 1400);
}

TEST(Journal, GarbageIsRefusedRatherThanReadAsEmpty) {
  TempDir dir;
  auto path = dir / "devices.json";
  WriteFile(path, "{ this is not json");
  auto back = f::lease::LoadJournal(path);
  ASSERT_FALSE(back.has_value());
  EXPECT_EQ(back.error().code, f::lease::JournalError::kCorrupt);
}

TEST(Journal, AFutureVersionIsRefusedNotHalfUnderstood) {
  TempDir dir;
  auto path = dir / "devices.json";
  WriteFile(path, R"({"version": 99, "devices": []})");
  auto back = f::lease::LoadJournal(path);
  ASSERT_FALSE(back.has_value());
  EXPECT_EQ(back.error().code, f::lease::JournalError::kCorrupt);
}

// -- availability: the point of the whole design ---------------------

TEST(Availability, NoDhcpConfiguredIsNotTheSameAsNoDevices) {
  TempDir dir;
  f::sysconfig::SystemConfig empty;
  ViewOptions opts;
  opts.lease_path = dir / "dnsmasq.leases";
  opts.journal_path = dir / "devices.json";
  auto r = CollectDevices(empty, opts, 1000);
  EXPECT_TRUE(r.devices.empty());
  EXPECT_EQ(r.leases, LeaseAvailability::kNoDhcpConfigured);
}

TEST(Availability, ConfiguredButNoLeaseFileIsItsOwnAnswer) {
  TempDir dir;
  ViewOptions opts;
  opts.lease_path = dir / "dnsmasq.leases";
  opts.journal_path = dir / "devices.json";
  auto r = CollectDevices(SampleConfig(), opts, 1000);
  EXPECT_TRUE(r.devices.empty());
  EXPECT_EQ(r.leases, LeaseAvailability::kNoLeaseFileYet);
}

TEST(Availability, AnEmptyLeaseFileMeansNobodyAsked) {
  TempDir dir;
  ViewOptions opts;
  opts.lease_path = dir / "dnsmasq.leases";
  opts.journal_path = dir / "devices.json";
  WriteFile(opts.lease_path, "");
  auto r = CollectDevices(SampleConfig(), opts, 1000);
  EXPECT_TRUE(r.devices.empty());
  EXPECT_EQ(r.leases, LeaseAvailability::kOk);
}

TEST(Availability, AnUnreadableLeaseFileNeverRendersAsNoDevices) {
  if (::geteuid() == 0) GTEST_SKIP() << "root defeats the mode bits";
  TempDir dir;
  ViewOptions opts;
  opts.lease_path = dir / "dnsmasq.leases";
  opts.journal_path = dir / "devices.json";
  WriteFile(opts.lease_path,
            "1786000000 aa:bb:cc:dd:ee:07 10.10.0.107 g *\n");
  std::filesystem::permissions(
      opts.lease_path, std::filesystem::perms::none,
      std::filesystem::perm_options::replace);
  auto r = CollectDevices(SampleConfig(), opts, 1000);
  EXPECT_EQ(r.leases, LeaseAvailability::kUnreadable);
  EXPECT_FALSE(r.detail.empty()) << "the reason must reach the user";
  std::filesystem::permissions(
      opts.lease_path, std::filesystem::perms::owner_all,
      std::filesystem::perm_options::replace);
}

TEST(Availability, AnUnwritableJournalSaysHistoryStops) {
  if (::geteuid() == 0) GTEST_SKIP() << "root defeats the mode bits";
  TempDir dir;
  auto sub = dir / "ro";
  std::filesystem::create_directories(sub);
  ViewOptions opts;
  opts.lease_path = dir / "dnsmasq.leases";
  opts.journal_path = sub + "/devices.json";
  WriteFile(opts.lease_path,
            "1786000000 aa:bb:cc:dd:ee:08 10.10.0.108 h *\n");
  std::filesystem::permissions(
      sub, std::filesystem::perms::owner_read |
               std::filesystem::perms::owner_exec,
      std::filesystem::perm_options::replace);
  auto r = CollectDevices(SampleConfig(), opts, 1000);
  EXPECT_EQ(r.journal, JournalAvailability::kUnwritable);
  EXPECT_EQ(r.devices.size(), 1U)
      << "the devices are still shown; only the history is lost";
  std::filesystem::permissions(
      sub, std::filesystem::perms::owner_all,
      std::filesystem::perm_options::replace);
}

TEST(Availability, AnUnreadableJournalIsNotOverwritten) {
  TempDir dir;
  ViewOptions opts;
  opts.lease_path = dir / "dnsmasq.leases";
  opts.journal_path = dir / "devices.json";
  WriteFile(opts.journal_path, "{ not json");
  WriteFile(opts.lease_path,
            "1786000000 aa:bb:cc:dd:ee:09 10.10.0.109 i *\n");
  auto r = CollectDevices(SampleConfig(), opts, 1000);
  EXPECT_EQ(r.journal, JournalAvailability::kUnreadable);
  std::ifstream in(opts.journal_path);
  std::string body((std::istreambuf_iterator<char>(in)),
                   std::istreambuf_iterator<char>());
  EXPECT_EQ(body, "{ not json")
      << "a journal that will not parse is left for the operator";
}

TEST(Availability, LookingAtAnEmptySegmentStillCountsAsLooking) {
  // The first `show leases` on a fresh box has no rows, and it still
  // has to write the journal — otherwise the first board plugged in
  // afterwards is a device we *found*, not one we watched arrive, and
  // it never gets marked new. This is the case the real-hardware run
  // caught.
  TempDir dir;
  ViewOptions opts;
  opts.lease_path = dir / "dnsmasq.leases";
  opts.journal_path = dir / "devices.json";

  auto empty = CollectDevices(SampleConfig(), opts, 1000);
  ASSERT_EQ(empty.leases, LeaseAvailability::kNoLeaseFileYet);
  ASSERT_TRUE(std::filesystem::exists(opts.journal_path))
      << "looking at nothing is still looking";

  WriteFile(opts.lease_path,
            "1786000000 aa:bb:cc:dd:ee:0e 10.10.0.114 p *\n");
  auto after = CollectDevices(SampleConfig(), opts, 2000);
  ASSERT_EQ(after.devices.size(), 1U);
  EXPECT_EQ(after.changes.arrived,
            std::vector<std::string>{"aa:bb:cc:dd:ee:0e"});
  EXPECT_TRUE(after.devices[0].IsNew(2000, f::lease::kNewWindowSeconds));
  EXPECT_EQ(after.devices[0].precision,
            FirstSeenPrecision::kObserved);
}

TEST(Availability, AMissingFileEndsThePresenceNotTheHistory) {
  TempDir dir;
  ViewOptions opts;
  opts.lease_path = dir / "dnsmasq.leases";
  opts.journal_path = dir / "devices.json";
  WriteFile(opts.lease_path,
            "1786000000 aa:bb:cc:dd:ee:0a 10.10.0.110 j *\n");
  auto first = CollectDevices(SampleConfig(), opts, 1000);
  ASSERT_EQ(first.devices.size(), 1U);

  std::filesystem::remove(opts.lease_path);
  auto second = CollectDevices(SampleConfig(), opts, 2000);
  EXPECT_EQ(second.leases, LeaseAvailability::kNoLeaseFileYet);
  ASSERT_EQ(second.devices.size(), 1U)
      << "what was here yesterday survives today's missing file";
  EXPECT_FALSE(second.devices[0].active);
  EXPECT_EQ(second.devices[0].address, "10.10.0.110")
      << "the last known address is still worth showing";
}

TEST(Availability, AnUnreadableFileIsNotADeviceThatLeft) {
  if (::geteuid() == 0) GTEST_SKIP() << "root defeats the mode bits";
  TempDir dir;
  ViewOptions opts;
  opts.lease_path = dir / "dnsmasq.leases";
  opts.journal_path = dir / "devices.json";
  WriteFile(opts.lease_path,
            "1786000000 aa:bb:cc:dd:ee:0f 10.10.0.115 q *\n");
  auto first = CollectDevices(SampleConfig(), opts, 1000);
  ASSERT_EQ(first.devices.size(), 1U);
  auto before = ReadWholeFile(opts.journal_path);

  std::filesystem::permissions(
      opts.lease_path, std::filesystem::perms::none,
      std::filesystem::perm_options::replace);
  auto second = CollectDevices(SampleConfig(), opts, 2000);
  EXPECT_EQ(second.leases, LeaseAvailability::kUnreadable);
  EXPECT_TRUE(second.changes.departed.empty())
      << "a file we could not read is not a device that left";
  EXPECT_EQ(ReadWholeFile(opts.journal_path), before)
      << "a permissions mistake must not rewrite the history";
  std::filesystem::permissions(
      opts.lease_path, std::filesystem::perms::owner_all,
      std::filesystem::perm_options::replace);
}

TEST(Availability, ADirectoryIsUnreadableNotEmpty) {
  // A path that opens fine and reads as nothing is the worst input
  // this reader can get: it renders as "no client holds a lease".
  TempDir dir;
  ViewOptions opts;
  opts.lease_path = dir / "not-a-file";
  opts.journal_path = dir / "devices.json";
  std::filesystem::create_directories(opts.lease_path);
  auto r = CollectDevices(SampleConfig(), opts, 1000);
  EXPECT_EQ(r.leases, LeaseAvailability::kUnreadable);
  EXPECT_FALSE(r.detail.empty());
}

// -- the join --------------------------------------------------------

TEST(View, ADeviceIsPlacedInTheZoneItsAddressBelongsTo) {
  Journal j;
  std::vector<Lease> leases = {
      {.expiry = 5000, .mac = "aa:bb:cc:dd:ee:0b",
       .address = "10.10.0.120", .hostname = "k", .client_id = ""},
  };
  Observe(j, leases, 1000, 3600, true);
  auto r = BuildReport(SampleConfig(), leases, j, 1000);
  ASSERT_EQ(r.devices.size(), 1U);
  EXPECT_EQ(r.devices[0].zone, "lan");
  EXPECT_TRUE(r.devices[0].active);
}

TEST(View, AnAddressOutsideEveryDeclaredSubnetHasNoZone) {
  Journal j;
  std::vector<Lease> leases = {
      {.expiry = 5000, .mac = "aa:bb:cc:dd:ee:0c",
       .address = "192.168.99.7", .hostname = "l", .client_id = ""},
  };
  Observe(j, leases, 1000, 3600, true);
  auto r = BuildReport(SampleConfig(), leases, j, 1000);
  ASSERT_EQ(r.devices.size(), 1U);
  EXPECT_EQ(r.devices[0].zone, "");
}

TEST(View, AReservationIsShownAgainstTheDeviceThatHasIt) {
  auto cfg = f::sysconfig::ParseSystemConfigString(R"(
zones:
  lan:
interfaces:
  lan0:
    mac: "52:54:00:11:22:33"
    address: 10.10.0.1/24
    zone: lan
services:
  dhcp:
    - zone: lan
      range: 10.10.0.100-10.10.0.200
      reservations:
        - mac: "AA:BB:CC:DD:EE:0D"
          address: 10.10.0.50
          hostname: pinned
)");
  ASSERT_TRUE(cfg.has_value());
  Journal j;
  std::vector<Lease> leases = {
      {.expiry = 5000, .mac = "aa:bb:cc:dd:ee:0d",
       .address = "10.10.0.150", .hostname = "m", .client_id = ""},
  };
  Observe(j, leases, 1000, 3600, true);
  auto r = BuildReport(*cfg, leases, j, 1000);
  ASSERT_EQ(r.devices.size(), 1U);
  EXPECT_TRUE(r.devices[0].reserved);
  EXPECT_EQ(r.devices[0].reserved_address, "10.10.0.50");
  EXPECT_EQ(r.devices[0].address, "10.10.0.150")
      << "the reservation has not taken effect yet, and both are shown";
}

TEST(View, NewestArrivalSortsFirst) {
  Journal j;
  std::vector<Lease> one = {
      {.expiry = 9000, .mac = "aa:bb:cc:dd:ee:11",
       .address = "10.10.0.111", .hostname = "old", .client_id = ""},
  };
  Observe(j, one, 1000, 3600, true);
  auto two = one;
  two.push_back({.expiry = 9000,
                 .mac = "aa:bb:cc:dd:ee:22",
                 .address = "10.10.0.122",
                 .hostname = "just-plugged-in",
                 .client_id = ""});
  Observe(j, two, 5000, 3600, false);
  auto r = BuildReport(SampleConfig(), two, j, 5000);
  ASSERT_EQ(r.devices.size(), 2U);
  EXPECT_EQ(r.devices[0].hostname, "just-plugged-in");
}

TEST(View, OnlyAWatchedArrivalCountsAsNew) {
  Journal j;
  std::vector<Lease> leases = {
      {.expiry = 5000, .mac = "aa:bb:cc:dd:ee:33",
       .address = "10.10.0.133", .hostname = "n", .client_id = ""},
  };
  Observe(j, leases, 1000, 3600, /*first_observation=*/true);
  auto r = BuildReport(SampleConfig(), leases, j, 1000);
  ASSERT_EQ(r.devices.size(), 1U);
  EXPECT_FALSE(r.devices[0].IsNew(1000, f::lease::kNewWindowSeconds))
      << "a device found on the first look was not watched arriving";
  EXPECT_EQ(r.devices[0].precision, FirstSeenPrecision::kInferred);
}

TEST(View, ADeviceWhoseLeaseExpiredKeepsItsLastKnownAddress) {
  Journal j;
  std::vector<Lease> leases = {
      {.expiry = 5000, .mac = "aa:bb:cc:dd:ee:44",
       .address = "10.10.0.144", .hostname = "o", .client_id = ""},
  };
  Observe(j, leases, 1000, 3600, true);
  Observe(j, {}, 2000, 3600, false);
  auto r = BuildReport(SampleConfig(), {}, j, 2000);
  ASSERT_EQ(r.devices.size(), 1U);
  EXPECT_FALSE(r.devices[0].active);
  EXPECT_EQ(r.devices[0].address, "10.10.0.144");
}

// -- lookup ----------------------------------------------------------

TEST(Match, FindsADeviceByMacInAnySpelling) {
  Journal j;
  std::vector<Lease> leases = {
      {.expiry = 5000, .mac = "aa:bb:cc:dd:ee:55",
       .address = "10.10.0.155", .hostname = "board",
       .client_id = ""},
  };
  Observe(j, leases, 1000, 3600, true);
  auto r = BuildReport(SampleConfig(), leases, j, 1000);
  EXPECT_EQ(MatchDevices(r, "AA:BB:CC:DD:EE:55").size(), 1U);
  EXPECT_EQ(MatchDevices(r, "10.10.0.155").size(), 1U);
  EXPECT_EQ(MatchDevices(r, "board").size(), 1U);
  EXPECT_EQ(MatchDevices(r, "BOARD").size(), 1U);
  EXPECT_EQ(MatchDevices(r, "boa").size(), 1U);
  EXPECT_TRUE(MatchDevices(r, "nothing-like-this").empty());
}

TEST(Match, AnAmbiguousNameReturnsEveryMatch) {
  Journal j;
  std::vector<Lease> leases = {
      {.expiry = 5000, .mac = "aa:bb:cc:dd:ee:66",
       .address = "10.10.0.166", .hostname = "board-1",
       .client_id = ""},
      {.expiry = 5000, .mac = "aa:bb:cc:dd:ee:77",
       .address = "10.10.0.177", .hostname = "board-2",
       .client_id = ""},
  };
  Observe(j, leases, 1000, 3600, true);
  auto r = BuildReport(SampleConfig(), leases, j, 1000);
  EXPECT_EQ(MatchDevices(r, "board").size(), 2U)
      << "the caller decides what to do about ambiguity, not us";
}

TEST(Age, ReadsTheSameEverywhere) {
  EXPECT_EQ(f::lease::FormatAge(0), "0s");
  EXPECT_EQ(f::lease::FormatAge(44), "44s");
  EXPECT_EQ(f::lease::FormatAge(60), "1m");
  EXPECT_EQ(f::lease::FormatAge(3600), "1h");
  EXPECT_EQ(f::lease::FormatAge(86400 * 6), "6d");
}

}  // namespace
