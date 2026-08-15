/// @file test_sysconfig_chrony.cc
/// @brief NTP placement, and a clock that reports its own honesty.
///
/// Two properties, and they are the same property twice.
///
/// The **server** cannot answer on the uplink, because the addresses
/// it binds are derived from zone membership and there is no key in
/// the model that names one. When no zone asks for a server, chrony
/// is told `port 0` and there is no socket at all.
///
/// The **clock** never reports a time without reporting how much of
/// it to believe. A board with no battery-backed RTC boots at the
/// epoch, and a log gathered at the office and stamped 1970 does not
/// merely look wrong — it destroys the ordering the analysis depends
/// on. So `TimeStatus::Trustworthy()` is the question every caller
/// actually has, and the three bad answers are distinct states rather
/// than one falsy value.

#include <unistd.h>

#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>

#include <gtest/gtest.h>

#include "f/sysconfig/chrony.h"
#include "f/sysconfig/model.h"
#include "f/sysconfig/parse.h"
#include "f/sysconfig/service_status.h"
#include "f/sysconfig/validate.h"

namespace f::sysconfig {
namespace {

constexpr const char* kOfficeShape = R"YAML(
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

services:
  ntp:
    - zone: testnet
      upstream: [pool.ntp.org, 192.0.2.10]
)YAML";

auto MustParse(const std::string& yaml) -> SystemConfig {
  auto cfg = ParseSystemConfigString(yaml);
  EXPECT_TRUE(cfg.has_value())
      << (cfg ? "" : cfg.error().diagnostics.front().Format());
  return cfg.value_or(SystemConfig{});
}

auto HasLine(const std::string& text, const std::string& line)
    -> bool {
  std::istringstream in(text);
  std::string got;
  while (std::getline(in, got)) {
    if (got == line) return true;
  }
  return false;
}

auto HasCode(const ValidationResult& r, const std::string& code)
    -> bool {
  for (const auto& d : r.diagnostics) {
    if (d.code == code) return true;
  }
  return false;
}

class TempDir {
 public:
  TempDir() {
    auto base = std::filesystem::temp_directory_path();
    for (int i = 0; i < 1000; ++i) {
      auto c = base / ("f-chrony-test-" + std::to_string(::getpid()) +
                       "-" + std::to_string(i));
      if (!std::filesystem::exists(c)) {
        std::filesystem::create_directories(c);
        path_ = c;
        return;
      }
    }
  }
  ~TempDir() {
    std::error_code ec;
    std::filesystem::remove_all(path_, ec);
  }
  TempDir(const TempDir&) = delete;
  auto operator=(const TempDir&) -> TempDir& = delete;

  auto File(const std::string& n) const -> std::string {
    return (path_ / n).string();
  }
  auto Write(const std::string& n, const std::string& body) const
      -> std::string {
    auto p = File(n);
    std::filesystem::create_directories(
        std::filesystem::path(p).parent_path());
    std::ofstream out(p);
    out << body;
    return p;
  }
  auto Mkdir(const std::string& n) const -> std::string {
    auto p = File(n);
    std::filesystem::create_directories(p);
    return p;
  }

 private:
  std::filesystem::path path_;
};

// -- placement ---------------------------------------------------------

TEST(ChronyTest, TheServerAnswersOnlyOnTheZoneItServes) {
  auto plan = PlanChrony(MustParse(kOfficeShape));
  EXPECT_TRUE(plan.serves);
  ASSERT_EQ(plan.bind_addresses.size(), 1u);
  EXPECT_EQ(plan.bind_addresses.front(), "10.10.0.1");
  EXPECT_TRUE(HasLine(plan.content, "bindaddress 10.10.0.1"));
  EXPECT_TRUE(HasLine(plan.content, "allow 10.10.0.0/24"));
  // The uplink's address never appears, because there is no key in
  // the model that could have put it there.
  EXPECT_EQ(plan.content.find("wan0"), std::string::npos)
      << plan.content;
}

// The containment, one directive wide. This is the NTP analogue of
// the rogue-DHCP gate: no zone asks for a server, so there is no
// listening socket to answer the office with.
TEST(ChronyTest, NoServerZoneMeansNoServerPort) {
  auto plan = PlanChrony(MustParse(R"YAML(
zones:
  wan:
interfaces:
  wan0:
    mac: "52:54:00:aa:bb:01"
    address: dhcp
    zone: wan
services:
  ntp:
    - zone: wan
      serve: false
      upstream: [pool.ntp.org]
)YAML"));
  EXPECT_FALSE(plan.serves);
  EXPECT_TRUE(HasLine(plan.content, "port 0"));
  EXPECT_FALSE(HasLine(plan.content, "port 123"));
  // The client half still works: this is the office deployment's own
  // shape, a box that learns the time and serves it to nobody.
  EXPECT_TRUE(HasLine(plan.content, "server pool.ntp.org iburst"));
}

// Same reasoning as SC022 for DHCP: a zone we take our own address
// from is a zone we are a guest on.
TEST(ChronyTest, ServingOnAZoneWeAreAClientOfIsRefused) {
  auto r = Validate(MustParse(R"YAML(
zones:
  wan:
interfaces:
  wan0:
    mac: "52:54:00:aa:bb:01"
    address: dhcp
    zone: wan
services:
  ntp:
    - zone: wan
      upstream: [pool.ntp.org]
)YAML"));
  EXPECT_TRUE(r.HasErrors());
  EXPECT_TRUE(HasCode(r, "SC042"));
}

TEST(ChronyTest, OfficeShapeValidates) {
  auto r = Validate(MustParse(kOfficeShape));
  EXPECT_FALSE(r.HasErrors())
      << (r.Errors().empty() ? "" : r.Errors().front().Format());
}

// A box with no upstream is a legitimate configuration whose
// consequence is entirely invisible, so it warns rather than passing
// silently — and it does not refuse, because refusing would be wrong.
TEST(ChronyTest, NothingSettingTheClockIsAWarningNotSilence) {
  auto r = Validate(MustParse(R"YAML(
zones:
  testnet:
interfaces:
  lan0:
    mac: "52:54:00:aa:bb:02"
    address: 10.10.0.1/24
    zone: testnet
services:
  ntp:
    - zone: testnet
)YAML"));
  EXPECT_FALSE(r.HasErrors());
  EXPECT_TRUE(HasCode(r, "SC044"));
  for (const auto& d : r.diagnostics) {
    if (d.code != "SC044") continue;
    EXPECT_EQ(d.severity, Severity::kWarning);
    EXPECT_NE(d.hint.find("1970"), std::string::npos) << d.hint;
  }
}

// A board that boots at the epoch cannot slew its way to the right
// time in any useful period, and the window between boot and first
// correction is exactly when timestamps are worthless.
TEST(ChronyTest, TheFirstCorrectionIsAStepNotASlew) {
  auto plan = PlanChrony(MustParse(kOfficeShape));
  EXPECT_TRUE(HasLine(plan.content, "makestep 1.0 3"));
  EXPECT_TRUE(HasLine(plan.content, "rtcsync"));
  // Inside chronyd's own AppArmor-permitted state directory.
  EXPECT_TRUE(
      HasLine(plan.content, "driftfile /var/lib/chrony/f.drift"));
  EXPECT_TRUE(HasLine(plan.content, "server pool.ntp.org iburst"));
}

TEST(ChronyTest, GenerationIsDeterministic) {
  auto cfg = MustParse(kOfficeShape);
  EXPECT_EQ(PlanChrony(cfg).content, PlanChrony(cfg).content);
}

TEST(ChronyTest, NoNtpAtAllMeansChronyIsNotNeeded) {
  auto plan = PlanChrony(MustParse(R"YAML(
zones:
  testnet:
interfaces:
  lan0:
    mac: "52:54:00:aa:bb:02"
    address: 10.10.0.1/24
    zone: testnet
)YAML"));
  EXPECT_FALSE(plan.needed);
}

// -- the clock ---------------------------------------------------------

TEST(TimeStatusTest, SynchronisedIsTheOnlyTrustworthyState) {
  TimeStatus s;
  s.trust = TimeTrust::kSynchronised;
  s.wall_seconds = 1755000000;
  EXPECT_TRUE(s.Trustworthy());

  for (auto bad : {TimeTrust::kNotYetSynchronised,
                   TimeTrust::kNoTimeSource, TimeTrust::kUnknown}) {
    s.trust = bad;
    EXPECT_FALSE(s.Trustworthy()) << TimeTrustName(bad);
  }
}

// The case the whole feature exists for: a kernel that believes it is
// disciplined, on a board whose clock never left 1970. Believing the
// flag alone would stamp a week of logs with the epoch and call them
// good.
TEST(TimeStatusTest, AnEpochWallClockIsNeverTrustworthy) {
  TimeStatus s;
  s.trust = TimeTrust::kSynchronised;
  s.wall_seconds = 42;
  s.implausible = true;
  EXPECT_FALSE(s.Trustworthy());
  EXPECT_NE(TimeWarningBanner(s).find("THE CLOCK IS AT THE EPOCH"),
            std::string::npos);
}

TEST(TimeStatusTest, TheEpochIsDetectedFromTheWallClock) {
  TempDir dir;
  TimeSource src;
  src.rtc_dir = dir.Mkdir("rtc");
  src.uptime_path = dir.Write("uptime", "12.34 40.00\n");
  src.chronyc_cmd = "";
  src.fake_wall_seconds = 30;
  src.fake_trust = 2;

  auto s = QueryTime(MustParse(kOfficeShape), src);
  EXPECT_TRUE(s.implausible);
  EXPECT_FALSE(s.Trustworthy());
  EXPECT_EQ(s.uptime_seconds, 12);
  EXPECT_EQ(s.rtc, RtcPresence::kAbsent);
}

TEST(TimeStatusTest, AnRtcIsFoundAndNamed) {
  TempDir dir;
  dir.Write("rtc/rtc0/name", "rk808-rtc\n");
  TimeSource src;
  src.rtc_dir = dir.File("rtc");
  src.uptime_path = dir.Write("uptime", "900.00 3600.00\n");
  src.chronyc_cmd = "";
  src.fake_wall_seconds = 1755000000;
  src.fake_trust = 1;

  auto s = QueryTime(MustParse(kOfficeShape), src);
  EXPECT_EQ(s.rtc, RtcPresence::kPresent);
  EXPECT_EQ(s.rtc_name, "rtc0 (rk808-rtc)");
  EXPECT_TRUE(s.Trustworthy());
  EXPECT_TRUE(TimeWarningBanner(s).empty());
}

// An absent RTC changes what "not yet synchronised" means: it is not
// a clock that is slightly out, it is a clock that started at zero.
TEST(TimeStatusTest, TheBannerNamesAMissingRtc) {
  TimeStatus s;
  s.trust = TimeTrust::kNotYetSynchronised;
  s.rtc = RtcPresence::kAbsent;
  s.wall_seconds = 5;
  s.implausible = true;
  auto banner = TimeWarningBanner(s);
  EXPECT_NE(banner.find("no RTC"), std::string::npos) << banner;
  EXPECT_NE(banner.find("epoch"), std::string::npos) << banner;
}

// No upstream anywhere is a different fault from an upstream that has
// not answered, and the operator's next move differs.
TEST(TimeStatusTest, NoUpstreamIsItsOwnState) {
  TempDir dir;
  TimeSource src;
  src.rtc_dir = dir.Mkdir("rtc");
  src.uptime_path = dir.Write("uptime", "60.0 60.0\n");
  src.chronyc_cmd = "";
  src.fake_wall_seconds = 1755000000;
  src.fake_trust = 2;

  auto cfg = MustParse(R"YAML(
zones:
  testnet:
interfaces:
  lan0:
    mac: "52:54:00:aa:bb:02"
    address: 10.10.0.1/24
    zone: testnet
services:
  ntp:
    - zone: testnet
)YAML");
  auto s = QueryTime(cfg, src);
  EXPECT_EQ(s.trust, TimeTrust::kNoTimeSource);
  EXPECT_NE(s.detail.find("nothing will ever set"),
            std::string::npos)
      << s.detail;
  EXPECT_NE(TimeWarningBanner(s).find("add an `ntp:` service"),
            std::string::npos);
}

// The banner is the load-bearing piece of the whole clock story, so
// it must be silent exactly when the clock can be believed. A warning
// that is always there is a warning nobody reads.
TEST(TimeStatusTest, ATrustworthyClockProducesNoBanner) {
  TimeStatus s;
  s.trust = TimeTrust::kSynchronised;
  s.wall_seconds = 1755000000;
  s.rtc = RtcPresence::kPresent;
  EXPECT_EQ(TimeWarningBanner(s), "");
}

TEST(TimeStatusTest, UnknownIsNotSynchronised) {
  TimeStatus s;
  s.trust = TimeTrust::kUnknown;
  s.wall_seconds = 1755000000;
  EXPECT_FALSE(s.Trustworthy());
  EXPECT_NE(TimeWarningBanner(s).find("not the same as correct"),
            std::string::npos);
}

// -- applying ----------------------------------------------------------

TEST(ChronyApplyTest, AHandEditIsRefusedNotOverwritten) {
  // chronyd may not be installed on a build machine; the drift check
  // runs before the tool check, so this exercises the half that does
  // not need it.
  TempDir dir;
  ChronyOptions opts;
  opts.conf_path = dir.File("chrony.conf");
  opts.chronyd_path = dir.File("no-such-chronyd");

  auto cfg = MustParse(kOfficeShape);
  {
    std::ofstream out(opts.conf_path);
    out << "# model-digest: 0000000000000000\nserver evil iburst\n";
  }
  auto refused = ApplyChrony(cfg, opts);
  ASSERT_FALSE(refused.has_value());
  EXPECT_EQ(refused.error().code, BackendError::kDrift);
  EXPECT_NE(refused.error().message.find("edited by hand"),
            std::string::npos);
}

TEST(ChronyApplyTest, AMissingDaemonIsNamed) {
  TempDir dir;
  ChronyOptions opts;
  opts.conf_path = dir.File("chrony.conf");
  opts.chronyd_path = dir.File("no-such-chronyd");
  auto r = ApplyChrony(MustParse(kOfficeShape), opts);
  ASSERT_FALSE(r.has_value());
  EXPECT_EQ(r.error().code, BackendError::kToolMissing);
}

// The time service is a service like any other, and "silently
// absent" is the wrong answer everywhere. A box whose clock is wrong
// because chronyd never started must say chronyd never started.
TEST(ChronyServiceTest, TheTimeServiceIsReportedLikeAnyOther) {
  ServiceProbe probe;
  probe.is_active_cmd = "echo inactive #";
  probe.restarts_cmd = "echo 0 #";
  probe.result_cmd = "echo success #";
  probe.load_state_cmd = "echo not-found #";
  probe.log_cmd = "echo '' #";

  auto out = QueryServices(MustParse(kOfficeShape), probe);
  const ServiceStatus* chrony = nullptr;
  for (const auto& s : out) {
    if (s.unit == "f-chrony.service") chrony = &s;
  }
  ASSERT_NE(chrony, nullptr);
  EXPECT_TRUE(chrony->expected);
  EXPECT_EQ(chrony->state, ServiceState::kNotInstalled);
  EXPECT_NE(chrony->detail.find("f-chrony.service"),
            std::string::npos)
      << chrony->detail;
  EXPECT_EQ(chrony->name, "ntp client+server (chrony)");
}

// No ntp in the model means chrony is not expected, and an unexpected
// absence must not read as a fault.
TEST(ChronyServiceTest, NoNtpMeansNotConfiguredNotFailed) {
  ServiceProbe probe;
  probe.is_active_cmd = "echo inactive #";
  probe.restarts_cmd = "echo 0 #";
  probe.result_cmd = "echo success #";
  probe.load_state_cmd = "echo not-found #";
  probe.log_cmd = "echo '' #";

  auto out = QueryServices(MustParse(R"YAML(
zones:
  testnet:
interfaces:
  lan0:
    mac: "52:54:00:aa:bb:02"
    address: 10.10.0.1/24
    zone: testnet
)YAML"), probe);
  for (const auto& s : out) {
    if (s.unit != "f-chrony.service") continue;
    EXPECT_FALSE(s.expected);
    EXPECT_EQ(s.state, ServiceState::kNotConfigured);
  }
}

}  // namespace
}  // namespace f::sysconfig
