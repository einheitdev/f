/// @file test_sysconfig_ipv6.cc
/// @brief The IPv6 stance: enforced, refused, and observable.
///
/// The property under test is not "we do not send router
/// advertisements". It is that an RA arriving from outside cannot
/// give a device in an `off` zone an address — and, separately, that
/// the refusal leaves a trace. A gate nobody can see held is
/// indistinguishable from a network that never spoke.
///
/// The behavioural half of this lives in
/// `tests/system/test_ipv6_ra_gate.py`, which injects a real RA at a
/// real client. These are the parts a fixture can settle: what the
/// artifacts say, what the model refuses, and that an empty
/// observation carries the reason it is empty.

#include <sys/stat.h>
#include <unistd.h>

#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "f/sysconfig/dnsmasq.h"
#include "f/sysconfig/ipv6.h"
#include "f/sysconfig/model.h"
#include "f/sysconfig/net.h"
#include "f/sysconfig/networkd.h"
#include "f/sysconfig/parse.h"
#include "f/sysconfig/validate.h"

namespace f::sysconfig {
namespace {

constexpr const char* kOfficeShape = R"YAML(
zones:
  wan:
  testnet:
    ipv6: off

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
  dhcp:
    - zone: testnet
      range: 10.10.0.100-10.10.0.200
  dns:
    - zone: testnet
      upstream: [9.9.9.9]
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
      auto c = base / ("f-ipv6-test-" + std::to_string(::getpid()) +
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

  auto Path() const -> std::string { return path_.string(); }
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

 private:
  std::filesystem::path path_;
};

// -- the parser knows all three words ---------------------------------

TEST(Ipv6StanceTest, ThreeStancesParseAndOnlyTwoValidate) {
  EXPECT_EQ(MustParse("zones:\n  a:\n").zones.front().ipv6,
            Ipv6Stance::kOff);
  EXPECT_EQ(MustParse("zones:\n  a:\n    ipv6: off\n")
                .zones.front()
                .ipv6,
            Ipv6Stance::kOff);
  EXPECT_EQ(
      MustParse("zones:\n  a:\n    ipv6: ra\n").zones.front().ipv6,
      Ipv6Stance::kRouterAdvertise);
  EXPECT_EQ(
      MustParse("zones:\n  a:\n    ipv6: full\n").zones.front().ipv6,
      Ipv6Stance::kFull);

  auto bad = ParseSystemConfigString(
      "zones:\n  a:\n    ipv6: sometimes\n");
  ASSERT_FALSE(bad.has_value());
  EXPECT_EQ(bad.error().diagnostics.front().code, "SC103");
  EXPECT_NE(bad.error().diagnostics.front().hint.find("full"),
            std::string::npos);
}

// `full` is not an unknown word — it is a known word this build
// cannot honour, and the difference is the whole message.
TEST(Ipv6StanceTest, FullIsRefusedByNameWithTheReason) {
  auto r = Validate(MustParse(R"YAML(
zones:
  testnet:
    ipv6: full
interfaces:
  lan0:
    mac: "52:54:00:aa:bb:02"
    address: 10.10.0.1/24
    zone: testnet
)YAML"));
  ASSERT_TRUE(r.HasErrors());
  ASSERT_TRUE(HasCode(r, "SC030"));
  std::string text;
  for (const auto& d : r.Errors()) text += d.Format();
  // The refusal has to carry the mechanism, or the operator's next
  // move is to file a feature request for a thing that is already
  // written and would silently hang his transfers.
  EXPECT_NE(text.find("related"), std::string::npos) << text;
  EXPECT_NE(text.find("Packet Too Big"), std::string::npos) << text;
  EXPECT_NE(text.find("never fragment"), std::string::npos) << text;
}

// BUGLOG #29, the model half: `ra` used to validate with no prefix
// anywhere, then generate a dnsmasq config that advertised nothing.
TEST(Ipv6StanceTest, RaWithoutAPrefixIsRefused) {
  auto r = Validate(MustParse(R"YAML(
zones:
  testnet:
    ipv6: ra
interfaces:
  lan0:
    mac: "52:54:00:aa:bb:02"
    address: 10.10.0.1/24
    zone: testnet
services:
  dhcp:
    - zone: testnet
      range: 10.10.0.100-10.10.0.200
)YAML"));
  EXPECT_TRUE(r.HasErrors());
  EXPECT_TRUE(HasCode(r, "SC031"));
}

TEST(Ipv6StanceTest, RaWithAPrefixValidates) {
  auto r = Validate(MustParse(R"YAML(
zones:
  testnet:
    ipv6: ra
interfaces:
  lan0:
    mac: "52:54:00:aa:bb:02"
    address: 10.10.0.1/24
    address6: fd00:10:10::1/64
    zone: testnet
services:
  dhcp:
    - zone: testnet
      range: 10.10.0.100-10.10.0.200
)YAML"));
  EXPECT_FALSE(r.HasErrors())
      << (r.Errors().empty() ? "" : r.Errors().front().Format());
}

TEST(Ipv6StanceTest, AV6AddressOnAnOffZoneIsAContradiction) {
  auto r = Validate(MustParse(R"YAML(
zones:
  testnet:
    ipv6: off
interfaces:
  lan0:
    mac: "52:54:00:aa:bb:02"
    address: 10.10.0.1/24
    address6: fd00:10:10::1/64
    zone: testnet
)YAML"));
  EXPECT_TRUE(HasCode(r, "SC032"));
}

TEST(Ipv6StanceTest, AMalformedV6AddressIsNamedAndLocated) {
  auto r = Validate(MustParse(R"YAML(
zones:
  testnet:
    ipv6: ra
interfaces:
  lan0:
    mac: "52:54:00:aa:bb:02"
    address: 10.10.0.1/24
    address6: fd00:10:10::1
    zone: testnet
services:
  dhcp:
    - zone: testnet
      range: 10.10.0.100-10.10.0.200
)YAML"));
  // A bare address with no length: refused, because this prefix is
  // handed to clients and a length nobody wrote is one somebody
  // guesses at.
  EXPECT_TRUE(HasCode(r, "SC032"));
}

// -- the v6 CIDR parser ------------------------------------------------

TEST(Prefix6Test, ParsesAndMasks) {
  auto p = ParseCidr6("fd00:10:10::1/64");
  ASSERT_TRUE(p.has_value());
  EXPECT_EQ(p->bits, 64);
  EXPECT_EQ(p->NetworkString(), "fd00:10:10::");

  auto q = ParseCidr6("2001:db8:abcd:1234::5/48");
  ASSERT_TRUE(q.has_value());
  EXPECT_EQ(q->NetworkString(), "2001:db8:abcd::");

  EXPECT_FALSE(ParseCidr6("fd00::1").has_value());
  EXPECT_FALSE(ParseCidr6("10.0.0.1/24").has_value());
  EXPECT_FALSE(ParseCidr6("fd00::1/129").has_value());
  EXPECT_FALSE(ParseCidr6("fd00::zz/64").has_value());
  EXPECT_FALSE(ParseCidr6("").has_value());
}

// -- the sysctl artifact ----------------------------------------------

TEST(Ipv6PlanTest, OffPortsRefuseRasAndStayCountable) {
  auto plan = PlanIpv6(MustParse(kOfficeShape));
  for (const auto& iface : {"wan0", "lan0"}) {
    EXPECT_TRUE(HasLine(plan.sysctl_content,
                        std::string("net.ipv6.conf.") + iface +
                            ".accept_ra = 0"))
        << plan.sysctl_content;
    EXPECT_TRUE(HasLine(plan.sysctl_content,
                        std::string("net.ipv6.conf.") + iface +
                            ".autoconf = 0"))
        << plan.sysctl_content;
  }
  // disable_ipv6 also refuses the RA, and was rejected on purpose: it
  // drops the frame before ICMPv6 accounting, so the box would be
  // safe and blind at once. If it is ever *set* here, the observer
  // below has quietly stopped being able to see anything. Matched on
  // settings lines only — the file explains the choice in a comment,
  // and that comment is the reason it is worth checking.
  std::istringstream lines(plan.sysctl_content);
  std::string line;
  while (std::getline(lines, line)) {
    if (!line.empty() && line.front() == '#') continue;
    EXPECT_EQ(line.find("disable_ipv6"), std::string::npos) << line;
  }
}

TEST(Ipv6PlanTest, NoZoneWantsV6SoTheBoxIsNotAV6Router) {
  auto plan = PlanIpv6(MustParse(kOfficeShape));
  EXPECT_FALSE(plan.forwarding);
  EXPECT_TRUE(
      HasLine(plan.sysctl_content, "net.ipv6.conf.all.forwarding = 0"));
  EXPECT_TRUE(HasLine(plan.sysctl_content,
                      "net.ipv6.conf.wan0.forwarding = 0"));
}

TEST(Ipv6PlanTest, AnUndeclaredPortStillDoesNotAutoconfigure) {
  // The dangerous port is the one nobody put in the config: it exists,
  // it is cabled, and the distribution default is "take an address
  // from whatever you hear".
  auto plan = PlanIpv6(MustParse(kOfficeShape));
  EXPECT_TRUE(HasLine(plan.sysctl_content,
                      "net.ipv6.conf.default.accept_ra = 0"));
  EXPECT_TRUE(HasLine(plan.sysctl_content,
                      "net.ipv6.conf.default.autoconf = 0"));
}

TEST(Ipv6PlanTest, RaZoneForwardsAndCarriesItsPrefix) {
  auto plan = PlanIpv6(MustParse(R"YAML(
zones:
  testnet:
    ipv6: ra
interfaces:
  lan0:
    mac: "52:54:00:aa:bb:02"
    address: 10.10.0.1/24
    address6: fd00:10:10::1/64
    zone: testnet
services:
  dhcp:
    - zone: testnet
      range: 10.10.0.100-10.10.0.200
)YAML"));
  EXPECT_TRUE(plan.forwarding);
  ASSERT_EQ(plan.interfaces.size(), 1u);
  EXPECT_TRUE(plan.interfaces.front().sends_ra);
  // Even here we do not take an address from a peer's advertisement:
  // a router that autoconfigures has been told what to do by whoever
  // shouted last.
  EXPECT_FALSE(plan.interfaces.front().accepts_ra);
  EXPECT_EQ(plan.interfaces.front().advertised_prefix,
            "fd00:10:10::");
  EXPECT_TRUE(HasLine(plan.sysctl_content,
                      "net.ipv6.conf.lan0.accept_ra = 0"));
}

TEST(Ipv6PlanTest, GenerationIsDeterministic) {
  auto cfg = MustParse(kOfficeShape);
  EXPECT_EQ(PlanIpv6(cfg).sysctl_content,
            PlanIpv6(cfg).sysctl_content);
}

// -- the networkd unit ------------------------------------------------

TEST(Ipv6NetworkdTest, EveryUnitRefusesRasWhateverTheV4Mode) {
  auto cfg = MustParse(kOfficeShape);
  NetworkdOptions opts;
  opts.dir = "/tmp/does-not-matter";
  int networks = 0;
  for (const auto& u : PlanNetworkd(cfg, opts)) {
    if (u.path.find(".network") == std::string::npos) continue;
    ++networks;
    EXPECT_TRUE(HasLine(u.content, "IPv6AcceptRA=no")) << u.content;
  }
  EXPECT_EQ(networks, 2);
}

// The uplink is a v4 DHCP client, which is exactly the port an office
// RA arrives on — so the v6 stance must not be inferred from the v4
// address mode.
TEST(Ipv6NetworkdTest, TheDhcpUplinkIsStillRaRefusing) {
  auto cfg = MustParse(kOfficeShape);
  NetworkdOptions opts;
  opts.dir = "/tmp/does-not-matter";
  for (const auto& u : PlanNetworkd(cfg, opts)) {
    if (u.path.find("wan0.network") == std::string::npos) continue;
    EXPECT_TRUE(HasLine(u.content, "DHCP=ipv4")) << u.content;
    EXPECT_TRUE(HasLine(u.content, "IPv6AcceptRA=no")) << u.content;
    EXPECT_TRUE(HasLine(u.content, "IPv6SendRA=no")) << u.content;
    EXPECT_EQ(u.content.find("DHCP=yes"), std::string::npos)
        << u.content;
  }
}

TEST(Ipv6NetworkdTest, TheRaZoneCarriesItsAddressAndForwards) {
  auto cfg = MustParse(R"YAML(
zones:
  testnet:
    ipv6: ra
interfaces:
  lan0:
    mac: "52:54:00:aa:bb:02"
    address: 10.10.0.1/24
    address6: fd00:10:10::1/64
    zone: testnet
services:
  dhcp:
    - zone: testnet
      range: 10.10.0.100-10.10.0.200
)YAML");
  NetworkdOptions opts;
  opts.dir = "/tmp/does-not-matter";
  for (const auto& u : PlanNetworkd(cfg, opts)) {
    if (u.path.find("lan0.network") == std::string::npos) continue;
    EXPECT_TRUE(HasLine(u.content, "Address=fd00:10:10::1/64"))
        << u.content;
    EXPECT_TRUE(HasLine(u.content, "IPForward=ipv6")) << u.content;
    // dnsmasq advertises, not networkd. Two RA sources on one segment
    // is a race whose winner decides the network.
    EXPECT_TRUE(HasLine(u.content, "IPv6SendRA=no")) << u.content;
  }
}

// -- the observer: which empty is it ----------------------------------

TEST(Ipv6ObserveTest, NoInterfacesIsNotZeroRas) {
  auto report = ObserveIpv6(MustParse("zones:\n  a:\n"), {});
  EXPECT_EQ(report.availability, Ipv6Availability::kNoInterfaces);
  EXPECT_TRUE(report.interfaces.empty());
  EXPECT_NE(Ipv6AvailabilityName(report.availability).find("no "),
            std::string::npos);
}

TEST(Ipv6ObserveTest, UnreadableCountersAreNotZeroRas) {
  Ipv6Source src;
  src.snmp6_dir = "/nonexistent/dev_snmp6";
  src.if_inet6_path = "/nonexistent/if_inet6";
  src.forwarding_path = "/nonexistent/forwarding";
  auto report = ObserveIpv6(MustParse(kOfficeShape), src);
  // The load-bearing distinction: the office may be shouting RAs at
  // us right now and we would report the same zero.
  EXPECT_EQ(report.availability,
            Ipv6Availability::kCountersUnreadable);
  ASSERT_EQ(report.interfaces.size(), 2u);
  for (const auto& i : report.interfaces) {
    EXPECT_FALSE(i.counters_read);
  }
  EXPECT_EQ(report.RefusedRas(), 0u);
}

TEST(Ipv6ObserveTest, ARefusedRaIsCounted) {
  TempDir dir;
  dir.Write("snmp6/wan0",
            "Ip6InReceives                     41\n"
            "Ip6InDiscards                     0\n"
            "Icmp6InRouterAdvertisements       17\n");
  dir.Write("snmp6/lan0",
            "Ip6InReceives                     0\n"
            "Icmp6InRouterAdvertisements       0\n");
  dir.Write("if_inet6", "");
  dir.Write("forwarding", "0\n");

  Ipv6Source src;
  src.snmp6_dir = dir.File("snmp6");
  src.if_inet6_path = dir.File("if_inet6");
  src.forwarding_path = dir.File("forwarding");

  auto report = ObserveIpv6(MustParse(kOfficeShape), src);
  EXPECT_EQ(report.availability, Ipv6Availability::kObserved);
  EXPECT_FALSE(report.forwarding);
  ASSERT_EQ(report.interfaces.size(), 2u);
  EXPECT_EQ(report.interfaces[0].intent.interface, "wan0");
  EXPECT_EQ(report.interfaces[0].ras_received, 17u);
  EXPECT_EQ(report.interfaces[0].v6_received, 41u);
  EXPECT_TRUE(report.interfaces[0].counters_read);
  // 17 advertisements arrived and nothing autoconfigured. That pair
  // is the gate holding, and the reason the stance uses accept_ra=0
  // rather than disable_ipv6=1.
  EXPECT_TRUE(report.interfaces[0].global_addresses.empty());
  EXPECT_EQ(report.RefusedRas(), 17u);
  EXPECT_TRUE(report.Violations().empty());
}

TEST(Ipv6ObserveTest, AnAddressOnAnOffPortIsAViolation) {
  TempDir dir;
  dir.Write("snmp6/wan0", "Icmp6InRouterAdvertisements 3\n");
  dir.Write("snmp6/lan0", "Icmp6InRouterAdvertisements 0\n");
  // Columns are: address, index, prefixlen, scope, flags, device.
  // Scope 00 is global; the link-local every port carries is 20 and
  // must not count, or every port would read as violated.
  dir.Write("if_inet6",
            "20010db8000000000000000000000001 03 40 00 80 wan0\n"
            "fe80000000000000988baefffe117e3a 03 40 20 80 wan0\n"
            "fe80000000000000988baefffe117e3b 04 40 20 80 lan0\n");
  dir.Write("forwarding", "0\n");

  Ipv6Source src;
  src.snmp6_dir = dir.File("snmp6");
  src.if_inet6_path = dir.File("if_inet6");
  src.forwarding_path = dir.File("forwarding");

  auto report = ObserveIpv6(MustParse(kOfficeShape), src);
  auto violations = report.Violations();
  ASSERT_EQ(violations.size(), 1u);
  EXPECT_NE(violations.front().find("wan0"), std::string::npos);
  EXPECT_NE(violations.front().find("2001:0db8"), std::string::npos)
      << violations.front();
  EXPECT_EQ(report.interfaces[1].global_addresses.size(), 0u);
}

// -- applying ----------------------------------------------------------

TEST(Ipv6ApplyTest, WritesTheArtifactAndReportsChange) {
  TempDir dir;
  Ipv6Options opts;
  opts.sysctl_path = dir.File("10-f-ipv6.conf");
  // No live push: this test is about the artifact.
  opts.proc_sys_root = "";

  auto cfg = MustParse(kOfficeShape);
  auto first = ApplyIpv6(cfg, opts);
  ASSERT_TRUE(first.has_value()) << (first ? "" : first.error());
  EXPECT_TRUE(first->changed);

  auto again = ApplyIpv6(cfg, opts);
  ASSERT_TRUE(again.has_value());
  EXPECT_FALSE(again->changed);
}

TEST(Ipv6ApplyTest, AHandEditIsRefusedNotOverwritten) {
  TempDir dir;
  Ipv6Options opts;
  opts.sysctl_path = dir.File("10-f-ipv6.conf");
  opts.proc_sys_root = "";
  auto cfg = MustParse(kOfficeShape);
  ASSERT_TRUE(ApplyIpv6(cfg, opts).has_value());

  {
    std::ofstream out(opts.sysctl_path, std::ios::app);
    out << "net.ipv6.conf.wan0.accept_ra = 1\n";
  }
  auto refused = ApplyIpv6(cfg, opts);
  ASSERT_FALSE(refused.has_value());
  EXPECT_NE(refused.error().find("edited by hand"),
            std::string::npos);

  opts.refuse_on_drift = false;
  EXPECT_TRUE(ApplyIpv6(cfg, opts).has_value());
}

// A stance that only half-applied has to say which half. The failure
// list is the only thing standing between "applied" and a port that
// is still taking orders from the office.
TEST(Ipv6ApplyTest, ASettingThatCouldNotBePushedIsNamed) {
  TempDir dir;
  Ipv6Options opts;
  opts.sysctl_path = dir.File("10-f-ipv6.conf");
  opts.proc_sys_root = dir.File("fakeproc");
  // A proc tree with exactly one writable knob in it.
  dir.Write("fakeproc/net/ipv6/conf/all/forwarding", "0\n");

  auto report = ApplyIpv6(MustParse(kOfficeShape), opts);
  ASSERT_TRUE(report.has_value()) << (report ? "" : report.error());
  EXPECT_EQ(report->applied_live.size(), 1u);
  EXPECT_EQ(report->applied_live.front(),
            "net.ipv6.conf.all.forwarding=0");
  EXPECT_FALSE(report->failed_live.empty());
  bool names_wan0 = false;
  for (const auto& f : report->failed_live) {
    if (f.find("net.ipv6.conf.wan0.accept_ra") != std::string::npos) {
      names_wan0 = true;
    }
  }
  EXPECT_TRUE(names_wan0);
}

}  // namespace
}  // namespace f::sysconfig
