/// @file test_sysconfig.cc
/// @brief System configuration model: parsing, validation, backends.
///
/// The tests that matter most are in ContainmentTest. They assert the
/// property the whole layering exists for: an interface can only end
/// up carrying a service if its *zone* carries that service. Nothing
/// in the config names an interface for a service, so the generated
/// daemon config cannot name one either.

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "f/sysconfig/artifact.h"
#include "f/sysconfig/dnsmasq.h"
#include "f/sysconfig/model.h"
#include "f/sysconfig/net.h"
#include "f/sysconfig/networkd.h"
#include "f/sysconfig/parse.h"
#include "f/sysconfig/service_status.h"
#include "f/sysconfig/validate.h"

namespace f::sysconfig {
namespace {

/// A config with the shape of the office deployment: a DHCP-client
/// uplink in its own zone, a statically addressed testnet, DHCP and
/// DNS bound to the testnet.
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
  dhcp:
    - zone: testnet
      range: 10.10.0.100-10.10.0.200
      lease: 12h
  dns:
    - zone: testnet
      upstream: [9.9.9.9]
)YAML";

auto MustParse(const char* yaml) -> SystemConfig {
  auto cfg = ParseSystemConfigString(yaml);
  EXPECT_TRUE(cfg.has_value());
  if (!cfg) {
    for (const auto& d : cfg.error().diagnostics) {
      ADD_FAILURE() << d.Format();
    }
    return {};
  }
  return *cfg;
}

/// Codes present in a validation result.
auto CodesOf(const ValidationResult& r) -> std::set<std::string> {
  std::set<std::string> out;
  for (const auto& d : r.diagnostics) out.insert(d.code);
  return out;
}

auto ParseCodes(const ParseFailure& f) -> std::set<std::string> {
  std::set<std::string> out;
  for (const auto& d : f.diagnostics) out.insert(d.code);
  return out;
}

/// Every value of `key=` in a dnsmasq config body.
auto ValuesFor(const std::string& conf, const std::string& key)
    -> std::set<std::string> {
  std::set<std::string> out;
  std::istringstream in(conf);
  std::string line;
  auto prefix = key + "=";
  while (std::getline(in, line)) {
    if (!line.empty() && line[0] == '#') continue;
    if (line.rfind(prefix, 0) == 0) out.insert(line.substr(prefix.size()));
  }
  return out;
}

auto HasLine(const std::string& conf, const std::string& want)
    -> bool {
  std::istringstream in(conf);
  std::string line;
  while (std::getline(in, line)) {
    if (line == want) return true;
  }
  return false;
}

class TempDir {
 public:
  TempDir() {
    auto base = std::filesystem::temp_directory_path();
    for (int i = 0; i < 1000; ++i) {
      auto candidate =
          base / ("f-sysconfig-test-" + std::to_string(::getpid()) +
                  "-" + std::to_string(i));
      if (!std::filesystem::exists(candidate)) {
        std::filesystem::create_directories(candidate);
        path_ = candidate;
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

 private:
  std::filesystem::path path_;
};

auto ReadFile(const std::string& p) -> std::string {
  std::ifstream in(p);
  std::ostringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

auto WriteFile(const std::string& p, const std::string& c) -> void {
  std::ofstream out(p);
  out << c;
}

// -- net helpers -----------------------------------------------------

TEST(NetTest, ParsesDottedQuad) {
  EXPECT_EQ(ParseIpv4("10.0.0.1"), 0x0A000001u);
  EXPECT_EQ(ParseIpv4("255.255.255.255"), 0xFFFFFFFFu);
  EXPECT_EQ(ParseIpv4("0.0.0.0"), 0u);
}

TEST(NetTest, RejectsShortAndOctalForms) {
  // inet_aton would accept all of these. A config file should not.
  EXPECT_FALSE(ParseIpv4("10.1").has_value());
  EXPECT_FALSE(ParseIpv4("010.0.0.1").has_value());
  EXPECT_FALSE(ParseIpv4("0x0a.0.0.1").has_value());
  EXPECT_FALSE(ParseIpv4("10.0.0.256").has_value());
  EXPECT_FALSE(ParseIpv4("10.0.0.1 ").has_value());
  EXPECT_FALSE(ParseIpv4("").has_value());
}

TEST(NetTest, PrefixArithmetic) {
  auto p = ParseCidr4("10.10.0.1/24");
  ASSERT_TRUE(p.has_value());
  EXPECT_EQ(FormatIpv4(p->Network()), "10.10.0.0");
  EXPECT_EQ(FormatIpv4(p->Broadcast()), "10.10.0.255");
  EXPECT_EQ(p->Netmask(), "255.255.255.0");
  EXPECT_TRUE(p->Contains(*ParseIpv4("10.10.0.200")));
  EXPECT_FALSE(p->Contains(*ParseIpv4("10.10.1.1")));
}

TEST(NetTest, OverlapIsSymmetricAndCatchesContainment) {
  auto a = *ParseCidr4("10.10.0.0/24");
  auto b = *ParseCidr4("10.10.0.128/25");
  auto c = *ParseCidr4("10.11.0.0/24");
  EXPECT_TRUE(PrefixesOverlap(a, b));
  EXPECT_TRUE(PrefixesOverlap(b, a));
  EXPECT_FALSE(PrefixesOverlap(a, c));
  EXPECT_FALSE(PrefixesOverlap(c, a));
}

TEST(NetTest, Durations) {
  EXPECT_EQ(ParseSeconds("600"), 600u);
  EXPECT_EQ(ParseSeconds("600s"), 600u);
  EXPECT_EQ(ParseSeconds("30m"), 1800u);
  EXPECT_EQ(ParseSeconds("12h"), 43200u);
  EXPECT_EQ(ParseSeconds("2d"), 172800u);
  EXPECT_FALSE(ParseSeconds("12 h").has_value());
  EXPECT_FALSE(ParseSeconds("forever").has_value());
  EXPECT_FALSE(ParseSeconds("").has_value());
}

// -- parsing ---------------------------------------------------------

TEST(ParseTest, OfficeShapeRoundTrips) {
  auto cfg = MustParse(kOfficeShape);
  ASSERT_EQ(cfg.zones.size(), 2u);
  ASSERT_EQ(cfg.interfaces.size(), 2u);
  ASSERT_EQ(cfg.dhcp.size(), 1u);
  ASSERT_EQ(cfg.dns.size(), 1u);

  const auto* wan = cfg.FindInterface("wan0");
  ASSERT_NE(wan, nullptr);
  EXPECT_EQ(wan->mode, AddressMode::kDhcpClient);
  EXPECT_EQ(wan->zone, "wan");
  EXPECT_EQ(wan->match.kind, MatchKind::kMac);
  EXPECT_EQ(wan->match.value, "52:54:00:aa:bb:01");

  const auto* lan = cfg.FindInterface("lan0");
  ASSERT_NE(lan, nullptr);
  EXPECT_EQ(lan->mode, AddressMode::kStatic);
  EXPECT_EQ(lan->address, "10.10.0.1/24");

  EXPECT_EQ(cfg.dhcp[0].bind.zone, "testnet");
  EXPECT_EQ(cfg.dhcp[0].lease_seconds, 43200u);
  EXPECT_EQ(cfg.dns[0].bind.zone, "testnet");
}

TEST(ParseTest, DiagnosticsCarryALocation) {
  auto bad = ParseSystemConfigString(R"YAML(
zones:
  testnet:
    ipv6: maybe
)YAML");
  ASSERT_FALSE(bad.has_value());
  ASSERT_EQ(bad.error().diagnostics.size(), 1u);
  const auto& d = bad.error().diagnostics[0];
  EXPECT_EQ(d.code, "SC103");
  EXPECT_GT(d.span.line, 0);
  EXPECT_NE(d.Format().find("4:"), std::string::npos) << d.Format();
}

/// The containment argument rests on there being nowhere to write an
/// interface name under a service. A parser that shrugged at an
/// unknown key would let an operator believe they had written
/// something binding, so an unknown key is refused, not ignored.
TEST(ParseTest, ServiceCannotNameAnInterface) {
  for (const char* key : {"interface", "interfaces", "listen",
                          "device", "bind"}) {
    auto yaml = std::string(R"YAML(
zones:
  testnet:
interfaces:
  lan0:
    mac: "52:54:00:aa:bb:02"
    address: 10.10.0.1/24
    zone: testnet
services:
  dhcp:
    - zone: testnet
      range: 10.10.0.100-10.10.0.200
      )YAML") + key + ": wan0\n";
    auto r = ParseSystemConfigString(yaml);
    ASSERT_FALSE(r.has_value())
        << "services.dhcp accepted a '" << key << "' key";
    EXPECT_TRUE(ParseCodes(r.error()).count("SC101") == 1)
        << "expected an unknown-key diagnostic for '" << key << "'";
  }
}

TEST(ParseTest, UnknownKeysAreRefusedEverywhere) {
  struct Case {
    const char* yaml;
    const char* what;
  };
  const Case cases[] = {
      {"firewall:\n  rules: x\n", "top level"},
      {"zones:\n  a:\n    colour: red\n", "zone"},
      {"interfaces:\n  a:\n    speed: 1000\n", "interface"},
      {"services:\n  vpn:\n    - zone: a\n", "services"},
      {"services:\n  ntp:\n    - zone: a\n      stratum: 3\n",
       "ntp entry"},
      {"services:\n  dns:\n    - zone: a\n      cache: 100\n",
       "dns entry"},
  };
  for (const auto& c : cases) {
    auto r = ParseSystemConfigString(c.yaml);
    ASSERT_FALSE(r.has_value()) << c.what;
    EXPECT_EQ(ParseCodes(r.error()).count("SC101"), 1u) << c.what;
  }
}

TEST(ParseTest, MalformedYamlIsLocated) {
  auto r = ParseSystemConfigString("zones:\n  a: [\n");
  ASSERT_FALSE(r.has_value());
  EXPECT_EQ(r.error().diagnostics[0].code, "SC100");
}

TEST(ParseTest, EmptyDocumentIsAnEmptyModel) {
  auto r = ParseSystemConfigString("");
  ASSERT_TRUE(r.has_value());
  EXPECT_TRUE(r->zones.empty());
  EXPECT_TRUE(r->interfaces.empty());
}

TEST(ParseTest, MacIsNormalisedSoSpellingsCompareEqual) {
  auto cfg = MustParse(R"YAML(
zones:
  a:
interfaces:
  p0:
    mac: "AA:BB:CC:DD:EE:FF"
    zone: a
)YAML");
  ASSERT_EQ(cfg.interfaces.size(), 1u);
  EXPECT_EQ(cfg.interfaces[0].match.value, "aa:bb:cc:dd:ee:ff");
}

// -- validation ------------------------------------------------------

TEST(ValidateTest, OfficeShapeIsClean) {
  auto r = Validate(MustParse(kOfficeShape));
  for (const auto& d : r.diagnostics) ADD_FAILURE() << d.Format();
  EXPECT_FALSE(r.HasErrors());
}

/// The rogue-DHCP case, caught in the model rather than on the wire:
/// if the uplink is dragged into the zone that serves DHCP, the
/// uplink's own `address: dhcp` gives it away.
TEST(ValidateTest, DhcpServerRefusedInAZoneThatIsADhcpClient) {
  auto r = Validate(MustParse(R"YAML(
zones:
  testnet:
interfaces:
  wan0:
    mac: "52:54:00:aa:bb:01"
    address: dhcp
    zone: testnet
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
  EXPECT_EQ(CodesOf(r).count("SC022"), 1u);
  bool named_the_interface = false;
  for (const auto& d : r.diagnostics) {
    if (d.code == "SC022" &&
        d.message.find("wan0") != std::string::npos) {
      named_the_interface = true;
    }
  }
  EXPECT_TRUE(named_the_interface)
      << "the diagnostic must name the offending interface";
}

TEST(ValidateTest, ServiceOnAnUndeclaredZoneIsRefused) {
  auto r = Validate(MustParse(R"YAML(
zones:
  testnet:
interfaces:
  lan0:
    mac: "52:54:00:aa:bb:02"
    address: 10.10.0.1/24
    zone: testnet
services:
  dhcp:
    - zone: testnat
      range: 10.10.0.100-10.10.0.200
)YAML"));
  EXPECT_EQ(CodesOf(r).count("SC020"), 1u);
}

TEST(ValidateTest, ZoneWithServicesButNoInterfacesIsRefused) {
  auto r = Validate(MustParse(R"YAML(
zones:
  testnet:
interfaces: {}
services:
  dns:
    - zone: testnet
)YAML"));
  EXPECT_EQ(CodesOf(r).count("SC021"), 1u);
}

TEST(ValidateTest, OverlappingSubnetsAcrossZonesAreRefused) {
  auto r = Validate(MustParse(R"YAML(
zones:
  a:
  b:
interfaces:
  p0:
    mac: "52:54:00:00:00:01"
    address: 10.10.0.1/24
    zone: a
  p1:
    mac: "52:54:00:00:00:02"
    address: 10.10.0.129/25
    zone: b
)YAML"));
  EXPECT_TRUE(r.HasErrors());
  EXPECT_EQ(CodesOf(r).count("SC012"), 1u);
}

TEST(ValidateTest, OverlapWithinOneZoneOnlyWarns) {
  auto r = Validate(MustParse(R"YAML(
zones:
  a:
interfaces:
  p0:
    mac: "52:54:00:00:00:01"
    address: 10.10.0.1/24
    zone: a
  p1:
    mac: "52:54:00:00:00:02"
    address: 10.10.0.2/24
    zone: a
)YAML"));
  EXPECT_FALSE(r.HasErrors());
  EXPECT_EQ(CodesOf(r).count("SC012"), 1u);
}

TEST(ValidateTest, InterfaceWithoutHardwareIdentityIsRefused) {
  auto r = Validate(MustParse(R"YAML(
zones:
  a:
interfaces:
  eth0:
    address: 10.10.0.1/24
    zone: a
)YAML"));
  EXPECT_TRUE(r.HasErrors());
  EXPECT_EQ(CodesOf(r).count("SC004"), 1u);
}

TEST(ValidateTest, TwoNamesForOnePortAreRefused) {
  auto r = Validate(MustParse(R"YAML(
zones:
  a:
interfaces:
  p0:
    mac: "52:54:00:00:00:01"
    zone: a
  p1:
    mac: "52:54:00:00:00:01"
    zone: a
)YAML"));
  EXPECT_EQ(CodesOf(r).count("SC003"), 1u);
}

TEST(ValidateTest, InterfaceInAnUndeclaredZoneIsRefused) {
  auto r = Validate(MustParse(R"YAML(
zones:
  a:
interfaces:
  p0:
    mac: "52:54:00:00:00:01"
    zone: nope
)YAML"));
  EXPECT_EQ(CodesOf(r).count("SC005"), 1u);
}

TEST(ValidateTest, DhcpRangeOutsideTheZoneSubnetIsRefused) {
  auto r = Validate(MustParse(R"YAML(
zones:
  testnet:
interfaces:
  lan0:
    mac: "52:54:00:aa:bb:02"
    address: 10.10.0.1/24
    zone: testnet
services:
  dhcp:
    - zone: testnet
      range: 10.99.0.100-10.99.0.200
)YAML"));
  EXPECT_EQ(CodesOf(r).count("SC026"), 1u);
}

TEST(ValidateTest, DhcpWithoutAStaticAddressIsRefused) {
  auto r = Validate(MustParse(R"YAML(
zones:
  testnet:
interfaces:
  lan0:
    mac: "52:54:00:aa:bb:02"
    zone: testnet
services:
  dhcp:
    - zone: testnet
      range: 10.10.0.100-10.10.0.200
)YAML"));
  EXPECT_EQ(CodesOf(r).count("SC024"), 1u);
}

TEST(ValidateTest, BackwardsRangeIsRefused) {
  auto r = Validate(MustParse(R"YAML(
zones:
  testnet:
interfaces:
  lan0:
    mac: "52:54:00:aa:bb:02"
    address: 10.10.0.1/24
    zone: testnet
services:
  dhcp:
    - zone: testnet
      range: 10.10.0.200-10.10.0.100
)YAML"));
  EXPECT_EQ(CodesOf(r).count("SC025"), 1u);
}

TEST(ValidateTest, ReservationOutsideTheSubnetIsRefused) {
  auto r = Validate(MustParse(R"YAML(
zones:
  testnet:
interfaces:
  lan0:
    mac: "52:54:00:aa:bb:02"
    address: 10.10.0.1/24
    zone: testnet
services:
  dhcp:
    - zone: testnet
      range: 10.10.0.100-10.10.0.200
      reservations:
        - mac: "aa:bb:cc:dd:ee:01"
          address: 10.99.0.5
)YAML"));
  EXPECT_EQ(CodesOf(r).count("SC027"), 1u);
}

TEST(ValidateTest, GatewayOffSubnetIsRefused) {
  auto r = Validate(MustParse(R"YAML(
zones:
  a:
interfaces:
  p0:
    mac: "52:54:00:00:00:01"
    address: 10.10.0.1/24
    gateway: 192.168.1.1
    zone: a
)YAML"));
  EXPECT_EQ(CodesOf(r).count("SC011"), 1u);
}

TEST(ValidateTest, RouterAdvertisementsNeedADhcpService) {
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
  dns:
    - zone: testnet
)YAML"));
  EXPECT_EQ(CodesOf(r).count("SC029"), 1u);
}

TEST(ValidateTest, DiagnosticsRenderNamedLocatedAndHinted) {
  auto r = Validate(MustParse(R"YAML(
zones:
  testnet:
interfaces:
  wan0:
    mac: "52:54:00:aa:bb:01"
    address: dhcp
    zone: testnet
  lan0:
    mac: "52:54:00:aa:bb:02"
    address: 10.10.0.1/24
    zone: testnet
services:
  dhcp:
    - zone: testnet
      range: 10.10.0.100-10.10.0.200
)YAML"));
  ASSERT_TRUE(r.HasErrors());
  auto text = r.Errors()[0].Format();
  EXPECT_NE(text.find("error[SC022]"), std::string::npos) << text;
  EXPECT_NE(text.find("hint:"), std::string::npos) << text;
}

// -- containment: the property the layering exists for ---------------

class ContainmentTest : public ::testing::Test {
 protected:
  /// Independently derive, from the raw model, which interfaces are in
  /// a zone that carries a DHCP server. Deliberately does not call
  /// SystemConfig's accessors — a test that agrees with the code by
  /// using the code proves only that the code agrees with itself.
  static auto ExpectedDhcpInterfaces(const SystemConfig& cfg)
      -> std::set<std::string> {
    std::set<std::string> zones;
    for (const auto& d : cfg.dhcp) zones.insert(d.bind.zone);
    std::set<std::string> out;
    for (const auto& i : cfg.interfaces) {
      if (zones.count(i.zone) != 0) out.insert(i.name);
    }
    return out;
  }

  static auto ExpectedServiceInterfaces(const SystemConfig& cfg)
      -> std::set<std::string> {
    std::set<std::string> zones;
    for (const auto& d : cfg.dhcp) zones.insert(d.bind.zone);
    for (const auto& d : cfg.dns) zones.insert(d.bind.zone);
    std::set<std::string> out;
    for (const auto& i : cfg.interfaces) {
      if (zones.count(i.zone) != 0) out.insert(i.name);
    }
    return out;
  }
};

TEST_F(ContainmentTest, UplinkNeverAppearsAsAServiceInterface) {
  auto cfg = MustParse(kOfficeShape);
  auto plan = PlanDnsmasq(cfg);

  auto listen = ValuesFor(plan.content, "interface");
  EXPECT_EQ(listen.count("wan0"), 0u)
      << "the uplink appeared in an interface= line";
  EXPECT_EQ(listen.count("lan0"), 1u);

  EXPECT_TRUE(HasLine(plan.content, "except-interface=wan0"));
  EXPECT_TRUE(HasLine(plan.content, "no-dhcp-interface=wan0"));
  EXPECT_FALSE(HasLine(plan.content, "no-dhcp-interface=lan0"));
}

/// The claim under test is not "wan0 is absent" but "an interface is
/// present exactly when its zone carries the service". Sweep a few
/// hundred shapes and check the equality both ways round — an
/// implementation that simply emitted nothing would pass the first
/// half and fail the second.
TEST_F(ContainmentTest, EmittedInterfacesEqualZoneDerivation) {
  std::mt19937 rng(20260812);
  const std::vector<std::string> zone_names = {"wan", "testnet",
                                               "lab", "dmz"};
  for (int iter = 0; iter < 400; ++iter) {
    SystemConfig cfg;
    for (const auto& z : zone_names) cfg.zones.push_back({z});

    const int n_ifaces = 1 + static_cast<int>(rng() % 6);
    for (int i = 0; i < n_ifaces; ++i) {
      Interface iface;
      iface.name = "p" + std::to_string(i);
      iface.match = {MatchKind::kMac,
                     "52:54:00:00:00:0" + std::to_string(i)};
      iface.zone = zone_names[rng() % zone_names.size()];
      iface.mode = AddressMode::kStatic;
      iface.address = "10." + std::to_string(20 + i) + ".0.1/24";
      cfg.interfaces.push_back(iface);
    }
    for (const auto& z : zone_names) {
      if (rng() % 3 == 0) {
        DhcpServer d;
        d.bind.zone = z;
        d.range_start = "10.20.0.100";
        d.range_end = "10.20.0.200";
        cfg.dhcp.push_back(d);
      }
      if (rng() % 3 == 0) {
        DnsForwarder d;
        d.bind.zone = z;
        cfg.dns.push_back(d);
      }
    }

    auto plan = PlanDnsmasq(cfg);
    auto listen = ValuesFor(plan.content, "interface");
    auto excluded = ValuesFor(plan.content, "except-interface");
    auto no_dhcp = ValuesFor(plan.content, "no-dhcp-interface");

    auto want_service = ExpectedServiceInterfaces(cfg);
    auto want_dhcp = ExpectedDhcpInterfaces(cfg);

    EXPECT_EQ(listen, want_service) << "iteration " << iter;

    std::set<std::string> all;
    for (const auto& i : cfg.interfaces) all.insert(i.name);

    // Every declared interface is accounted for exactly once: it is
    // either listened on or explicitly excluded, never merely omitted.
    std::set<std::string> covered;
    covered.insert(listen.begin(), listen.end());
    covered.insert(excluded.begin(), excluded.end());
    EXPECT_EQ(covered, all) << "iteration " << iter;
    for (const auto& n : listen) {
      EXPECT_EQ(excluded.count(n), 0u) << n << " both ways";
    }

    // DHCP is refused, by name, on every interface whose zone does
    // not serve DHCP.
    std::set<std::string> want_no_dhcp;
    std::set_difference(
        all.begin(), all.end(), want_dhcp.begin(), want_dhcp.end(),
        std::inserter(want_no_dhcp, want_no_dhcp.end()));
    EXPECT_EQ(no_dhcp, want_no_dhcp) << "iteration " << iter;
    EXPECT_EQ(plan.dhcp_interfaces.size(), want_dhcp.size());
  }
}

/// Moving the service between zones must move the interfaces with it,
/// with no edit anywhere near an interface name.
TEST_F(ContainmentTest, RebindingTheZoneMovesTheService) {
  auto to_testnet = MustParse(kOfficeShape);
  auto lan_plan = PlanDnsmasq(to_testnet);
  EXPECT_TRUE(HasLine(lan_plan.content, "interface=lan0"));
  EXPECT_TRUE(HasLine(lan_plan.content, "no-dhcp-interface=wan0"));

  // The single-token edit that would be the whole mistake.
  auto to_wan = to_testnet;
  to_wan.dhcp[0].bind.zone = "wan";
  auto wan_plan = PlanDnsmasq(to_wan);
  EXPECT_TRUE(HasLine(wan_plan.content, "no-dhcp-interface=lan0"));
  EXPECT_FALSE(HasLine(wan_plan.content, "no-dhcp-interface=wan0"));

  // ...and it does not survive validation, because the uplink is a
  // DHCP client. The config that would leak is not one you can apply.
  auto r = Validate(to_wan);
  EXPECT_TRUE(r.HasErrors());
  EXPECT_EQ(CodesOf(r).count("SC022"), 1u);
}

TEST_F(ContainmentTest, NoServicesMeansNoDaemon) {
  auto cfg = MustParse(R"YAML(
zones:
  wan:
interfaces:
  wan0:
    mac: "52:54:00:aa:bb:01"
    address: dhcp
    zone: wan
)YAML");
  auto plan = PlanDnsmasq(cfg);
  EXPECT_FALSE(plan.needed);
  EXPECT_TRUE(plan.allowed_interfaces.empty());
  EXPECT_TRUE(HasLine(plan.content, "except-interface=wan0"));
  EXPECT_TRUE(HasLine(plan.content, "no-dhcp-interface=wan0"));
  EXPECT_TRUE(HasLine(plan.content, "port=0"));
}

TEST_F(ContainmentTest, DnsOnlyZoneGetsNoDhcp) {
  auto cfg = MustParse(R"YAML(
zones:
  wan:
  lab:
interfaces:
  wan0:
    mac: "52:54:00:aa:bb:01"
    address: dhcp
    zone: wan
  lab0:
    mac: "52:54:00:aa:bb:03"
    address: 10.20.0.1/24
    zone: lab
services:
  dns:
    - zone: lab
)YAML");
  auto plan = PlanDnsmasq(cfg);
  EXPECT_TRUE(HasLine(plan.content, "interface=lab0"));
  EXPECT_TRUE(HasLine(plan.content, "no-dhcp-interface=lab0"));
  EXPECT_TRUE(HasLine(plan.content, "no-dhcp-interface=wan0"));
  EXPECT_TRUE(plan.dhcp_interfaces.empty());
}

// -- dnsmasq rendering ------------------------------------------------

TEST(DnsmasqTest, RangeCarriesTheZoneNetmaskAndLease) {
  auto plan = PlanDnsmasq(MustParse(kOfficeShape));
  EXPECT_TRUE(HasLine(
      plan.content,
      "dhcp-range=set:zone_testnet,10.10.0.100,10.10.0.200,"
      "255.255.255.0,43200"));
  EXPECT_TRUE(HasLine(
      plan.content,
      "dhcp-option=tag:zone_testnet,option:router,10.10.0.1"));
  EXPECT_TRUE(HasLine(
      plan.content,
      "dhcp-option=tag:zone_testnet,option:dns-server,10.10.0.1"));
  EXPECT_TRUE(HasLine(plan.content, "server=9.9.9.9"));
  EXPECT_TRUE(HasLine(plan.content, "no-resolv"));
}

TEST(DnsmasqTest, ReservationsRender) {
  auto plan = PlanDnsmasq(MustParse(R"YAML(
zones:
  testnet:
interfaces:
  lan0:
    mac: "52:54:00:aa:bb:02"
    address: 10.10.0.1/24
    zone: testnet
services:
  dhcp:
    - zone: testnet
      range: 10.10.0.100-10.10.0.200
      reservations:
        - mac: "AA:BB:CC:DD:EE:01"
          address: 10.10.0.50
          hostname: board1
)YAML"));
  EXPECT_TRUE(HasLine(
      plan.content, "dhcp-host=aa:bb:cc:dd:ee:01,10.10.0.50,board1"));
}

TEST(DnsmasqTest, RouterAdvertisementsAreOptIn) {
  auto off = PlanDnsmasq(MustParse(kOfficeShape));
  EXPECT_FALSE(HasLine(off.content, "enable-ra"));

  auto on = PlanDnsmasq(MustParse(R"YAML(
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
  EXPECT_TRUE(HasLine(on.content, "enable-ra"));
}

// BUGLOG #29. `enable-ra` on its own advertises nothing: dnsmasq only
// sends advertisements on an interface that also carries a v6
// dhcp-range. The stance therefore generated a config line, passed
// `dnsmasq --test`, started the daemon and delivered silence — a
// stance that reads as configured and is not.
TEST(DnsmasqTest, RouterAdvertisementsCarryAPrefixOrAreRefused) {
  auto with_prefix = PlanDnsmasq(MustParse(R"YAML(
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
  EXPECT_TRUE(HasLine(with_prefix.content, "enable-ra"));
  // The line that makes enable-ra do anything at all.
  EXPECT_NE(with_prefix.content.find(
                "dhcp-range=set:zone_testnet,::,constructor:lan0,"
                "ra-stateless"),
            std::string::npos)
      << with_prefix.content;

  // No prefix: refused in the artifact, and the reason is in it.
  auto no_prefix = PlanDnsmasq(MustParse(R"YAML(
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
  EXPECT_FALSE(HasLine(no_prefix.content, "enable-ra"));
  EXPECT_NE(no_prefix.content.find("no interface in it carries a v6 "
                                   "prefix"),
            std::string::npos)
      << no_prefix.content;
}

// The v4 containment says nothing about advertisements: a router
// advertisement is neither DHCPv4 nor DHCPv6, and it is the one that
// matters. Every declared port is named in exactly one of the two
// lists so the refusal is stated, not implied by an absent line.
TEST(DnsmasqTest, EveryPortIsNamedInTheV6Containment) {
  auto cfg = MustParse(kOfficeShape);
  auto plan = PlanDnsmasq(cfg);
  std::set<std::string> named;
  for (const auto& n : plan.ra_interfaces) named.insert(n);
  for (const auto& n : plan.ra_refused_interfaces) named.insert(n);
  EXPECT_EQ(named.size(), cfg.AllInterfaceNames().size());
  for (const auto& n : cfg.AllInterfaceNames()) {
    EXPECT_EQ(named.count(n), 1u) << n;
    EXPECT_TRUE(HasLine(plan.content, "no-dhcpv6-interface=" + n))
        << plan.content;
    EXPECT_TRUE(HasLine(plan.content, "ra-param=" + n + ",0,0"))
        << plan.content;
  }
  EXPECT_TRUE(plan.ra_interfaces.empty());
}

TEST(DnsmasqTest, GenerationIsDeterministic) {
  auto cfg = MustParse(kOfficeShape);
  EXPECT_EQ(PlanDnsmasq(cfg).content, PlanDnsmasq(cfg).content);
}

// -- derived artifacts ------------------------------------------------

TEST(ArtifactTest, InstallIsIdempotentAndReportsChange) {
  TempDir dir;
  auto p = dir.File("thing.conf");
  auto doc = WrapWithDigest("hello\n");

  auto first = InstallArtifact(p, doc);
  ASSERT_TRUE(first.has_value());
  EXPECT_TRUE(*first);

  auto second = InstallArtifact(p, doc);
  ASSERT_TRUE(second.has_value());
  EXPECT_FALSE(*second) << "rewriting identical content is not a change";
  EXPECT_EQ(ReadFile(p), doc);
}

TEST(ArtifactTest, DriftKindsAreDistinguished) {
  TempDir dir;
  auto p = dir.File("thing.conf");
  auto doc = WrapWithDigest("hello\n");

  EXPECT_EQ(CheckArtifactDrift(p, doc), DriftKind::kAbsent);

  ASSERT_TRUE(InstallArtifact(p, doc).has_value());
  EXPECT_EQ(CheckArtifactDrift(p, doc), DriftKind::kNone);

  // Model moved on; artifact is self-consistent but old.
  auto newer = WrapWithDigest("hello world\n");
  EXPECT_EQ(CheckArtifactDrift(p, newer), DriftKind::kStale);

  // Somebody edited the generated file.
  WriteFile(p, ReadFile(p) + "extra-line\n");
  EXPECT_EQ(CheckArtifactDrift(p, doc), DriftKind::kHandEdited);

  // A file with no digest header at all is an edit too.
  WriteFile(p, "hand written\n");
  EXPECT_EQ(CheckArtifactDrift(p, doc), DriftKind::kHandEdited);
}

TEST(DnsmasqTest, ApplyRefusesAnInvalidModelBeforeTouchingDisk) {
  TempDir dir;
  DnsmasqOptions opts;
  opts.conf_path = dir.File("dnsmasq.conf");
  auto cfg = MustParse(R"YAML(
zones:
  testnet:
interfaces:
  wan0:
    mac: "52:54:00:aa:bb:01"
    address: dhcp
    zone: testnet
  lan0:
    mac: "52:54:00:aa:bb:02"
    address: 10.10.0.1/24
    zone: testnet
services:
  dhcp:
    - zone: testnet
      range: 10.10.0.100-10.10.0.200
)YAML");
  auto r = ApplyDnsmasq(cfg, opts);
  ASSERT_FALSE(r.has_value());
  EXPECT_EQ(r.error().code, BackendError::kModelInvalid);
  EXPECT_NE(r.error().message.find("SC022"), std::string::npos);
  EXPECT_FALSE(std::filesystem::exists(opts.conf_path))
      << "a refused apply must not leave an artifact behind";
}

TEST(DnsmasqTest, ApplyRefusesAHandEditedArtifact) {
  TempDir dir;
  DnsmasqOptions opts;
  opts.conf_path = dir.File("dnsmasq.conf");
  // No dnsmasq needed: the drift check comes first by design, so the
  // operator is told about their edit rather than about a missing
  // tool.
  opts.dnsmasq_path = "/nonexistent/dnsmasq";
  auto cfg = MustParse(kOfficeShape);

  ASSERT_TRUE(
      InstallArtifact(opts.conf_path, PlanDnsmasq(cfg).content)
          .has_value());
  WriteFile(opts.conf_path,
            ReadFile(opts.conf_path) + "interface=wan0\n");

  auto r = ApplyDnsmasq(cfg, opts);
  ASSERT_FALSE(r.has_value());
  EXPECT_EQ(r.error().code, BackendError::kDrift);
  // The edit survives: drift is reported, not silently overwritten.
  EXPECT_NE(ReadFile(opts.conf_path).find("interface=wan0"),
            std::string::npos);
}

TEST(DnsmasqTest, ApplyReportsAMissingDaemon) {
  TempDir dir;
  DnsmasqOptions opts;
  opts.conf_path = dir.File("dnsmasq.conf");
  opts.dnsmasq_path = "/nonexistent/dnsmasq";
  auto r = ApplyDnsmasq(MustParse(kOfficeShape), opts);
  ASSERT_FALSE(r.has_value());
  EXPECT_EQ(r.error().code, BackendError::kToolMissing);
  EXPECT_FALSE(std::filesystem::exists(opts.conf_path));
}

TEST(DnsmasqTest, DriftHelperTracksTheModel) {
  TempDir dir;
  auto p = dir.File("dnsmasq.conf");
  auto cfg = MustParse(kOfficeShape);
  EXPECT_EQ(CheckDnsmasqDrift(cfg, p), DriftKind::kAbsent);
  ASSERT_TRUE(
      InstallArtifact(p, PlanDnsmasq(cfg).content).has_value());
  EXPECT_EQ(CheckDnsmasqDrift(cfg, p), DriftKind::kNone);
  cfg.dhcp[0].range_end = "10.10.0.150";
  EXPECT_EQ(CheckDnsmasqDrift(cfg, p), DriftKind::kStale);
}

// -- networkd ---------------------------------------------------------

TEST(NetworkdTest, LinkUnitPinsNameToHardware) {
  TempDir dir;
  NetworkdOptions opts;
  opts.dir = dir.Path();
  auto units = PlanNetworkd(MustParse(kOfficeShape), opts);

  const NetworkdUnit* link = nullptr;
  for (const auto& u : units) {
    if (u.path.ends_with("10-f-wan0.link")) link = &u;
  }
  ASSERT_NE(link, nullptr) << "no .link unit for wan0";
  EXPECT_NE(link->content.find("MACAddress=52:54:00:aa:bb:01"),
            std::string::npos);
  EXPECT_NE(link->content.find("Name=wan0"), std::string::npos);
  // Without an empty NamePolicy, systemd's own naming can win the
  // race with Name= and the pin silently does nothing.
  EXPECT_NE(link->content.find("NamePolicy="), std::string::npos);
}

TEST(NetworkdTest, AddressModesRender) {
  TempDir dir;
  NetworkdOptions opts;
  opts.dir = dir.Path();
  auto units = PlanNetworkd(MustParse(R"YAML(
zones:
  wan:
  testnet:
  quiet:
interfaces:
  wan0:
    mac: "52:54:00:aa:bb:01"
    address: dhcp
    zone: wan
  lan0:
    mac: "52:54:00:aa:bb:02"
    address: 10.10.0.1/24
    gateway: 10.10.0.254
    zone: testnet
  tap0:
    mac: "52:54:00:aa:bb:03"
    zone: quiet
)YAML"), opts);

  auto find = [&](const std::string& suffix) -> std::string {
    for (const auto& u : units) {
      if (u.path.ends_with(suffix)) return u.content;
    }
    return "";
  };

  auto wan = find("10-f-wan0.network");
  EXPECT_NE(wan.find("DHCP=ipv4"), std::string::npos);

  auto lan = find("10-f-lan0.network");
  EXPECT_NE(lan.find("Address=10.10.0.1/24"), std::string::npos);
  EXPECT_NE(lan.find("Gateway=10.10.0.254"), std::string::npos);
  EXPECT_EQ(lan.find("DHCP="), std::string::npos);

  auto tap = find("10-f-tap0.network");
  EXPECT_NE(tap.find("LinkLocalAddressing=no"), std::string::npos);
  EXPECT_EQ(tap.find("Address="), std::string::npos);
}

/// Office RAs reaching a testnet would let devices autoconfigure v6
/// and route around the v4 policy while appearing to work normally.
TEST(NetworkdTest, RouterAdvertisementsAreNotAccepted) {
  TempDir dir;
  NetworkdOptions opts;
  opts.dir = dir.Path();
  for (const auto& u : PlanNetworkd(MustParse(kOfficeShape), opts)) {
    if (!u.path.ends_with(".network")) continue;
    EXPECT_NE(u.content.find("IPv6AcceptRA=no"), std::string::npos)
        << u.path;
  }
}

TEST(NetworkdTest, ApplyThenDriftThenRefusal) {
  TempDir dir;
  NetworkdOptions opts;
  opts.dir = dir.Path();
  auto cfg = MustParse(kOfficeShape);

  auto first = ApplyNetworkd(cfg, opts);
  ASSERT_TRUE(first.has_value()) << first.error();
  EXPECT_EQ(first->changed.size(), first->units.size());

  auto second = ApplyNetworkd(cfg, opts);
  ASSERT_TRUE(second.has_value());
  EXPECT_TRUE(second->changed.empty());

  auto link = dir.File("10-f-wan0.link");
  WriteFile(link, ReadFile(link) + "Name=somethingelse\n");
  auto third = ApplyNetworkd(cfg, opts);
  ASSERT_FALSE(third.has_value());
  EXPECT_NE(third.error().find("10-f-wan0.link"), std::string::npos);
  EXPECT_NE(ReadFile(link).find("somethingelse"), std::string::npos)
      << "a refused apply must not have overwritten the edit";
}

// -- failure semantics -------------------------------------------------

/// The whole state table, because the interesting entries are the ones
/// where "not running" must not render as an empty row.
TEST(ServiceStatusTest, StateTable) {
  struct Case {
    const char* active;
    bool expected;
    int restarts;
    ServiceState want;
  };
  const Case cases[] = {
      {"active", true, 0, ServiceState::kRunning},
      {"reloading", true, 0, ServiceState::kRunning},
      {"activating", true, 0, ServiceState::kActivating},
      // The same systemd answer, but the unit has already been
      // restarted: it is failing, not starting. Rendering this as
      // progress is how a unit that never served a packet passes for
      // healthy.
      {"activating", true, 1, ServiceState::kRestarting},
      {"activating", true, 9, ServiceState::kRestarting},
      {"activating", false, 3, ServiceState::kUnexpected},
      {"failed", true, 0, ServiceState::kFailed},
      // The one that matters: configured, not running, never started.
      {"inactive", true, 0, ServiceState::kStopped},
      {"deactivating", true, 0, ServiceState::kStopped},
      // Nothing bound, nothing running: correct, and says so.
      {"inactive", false, 0, ServiceState::kNotConfigured},
      // Nothing bound, but something is answering anyway.
      {"active", false, 0, ServiceState::kUnexpected},
      // A failed unit is a fault whether or not we wanted it up.
      {"failed", false, 0, ServiceState::kFailed},
      // systemd did not answer. Unknown is not the same as fine.
      {"", true, 0, ServiceState::kUnknown},
      {"", false, 0, ServiceState::kUnknown},
      {"who-knows", true, 0, ServiceState::kUnknown},
  };
  for (const auto& c : cases) {
    EXPECT_EQ(ClassifyState(c.active, c.expected, c.restarts), c.want)
        << "active=" << c.active << " expected=" << c.expected
        << " restarts=" << c.restarts;
  }
  EXPECT_EQ(ClassifyState("active\n", true), ServiceState::kRunning);

  // systemd sets Result=exit-code on the first failed start, before
  // NRestarts has incremented. Observed on Debian 13 / systemd 257:
  // the unit sits at activating/restarts=0/result=exit-code for the
  // first two RestartSec windows, so NRestarts alone would render a
  // dead service as "starting" for ten seconds.
  EXPECT_EQ(ClassifyState("activating", true, 0, "exit-code"),
            ServiceState::kRestarting);
  EXPECT_EQ(ClassifyState("activating", true, 0, "signal"),
            ServiceState::kRestarting);
  EXPECT_EQ(ClassifyState("activating", true, 0, "success"),
            ServiceState::kActivating);
  EXPECT_EQ(ClassifyState("activating", true, 0, ""),
            ServiceState::kActivating);

  // Observed on the box: after the unit file is deleted, systemd
  // still answers `is-active` with the stale `failed` and even keeps
  // NRestarts=5. LoadState is the only honest signal, so it wins.
  EXPECT_EQ(ClassifyState("failed", true, 5, "exit-code",
                          "not-found"),
            ServiceState::kNotInstalled);
  EXPECT_EQ(ClassifyState("active", true, 0, "success", "not-found"),
            ServiceState::kNotInstalled);
  // Nothing bound and no unit: correct, and not a fault.
  EXPECT_EQ(ClassifyState("failed", false, 5, "exit-code",
                          "not-found"),
            ServiceState::kNotConfigured);
  EXPECT_EQ(ClassifyState("active", true, 0, "success", "loaded"),
            ServiceState::kRunning);
}

TEST(ServiceStatusTest, NoStateRendersAsBlank) {
  for (auto s : {ServiceState::kNotConfigured, ServiceState::kRunning,
                 ServiceState::kActivating, ServiceState::kRestarting,
                 ServiceState::kFailed, ServiceState::kNotInstalled,
                 ServiceState::kStopped, ServiceState::kUnexpected,
                 ServiceState::kUnknown}) {
    EXPECT_FALSE(ServiceStateName(s).empty());
  }
}

/// A stopped-but-configured service must carry a reason, not just a
/// state. The probe is injected so this needs no init system.
TEST(ServiceStatusTest, StoppedServiceCarriesAReason) {
  ServiceProbe probe;
  probe.is_active_cmd = "echo inactive #";
  probe.restarts_cmd = "echo 0 #";
  probe.result_cmd = "echo success #";
  probe.load_state_cmd = "echo loaded #";
  probe.log_cmd = "echo 'dnsmasq: bad address at line 4' #";
  auto out = QueryServices(MustParse(kOfficeShape), probe);
  ASSERT_GE(out.size(), 1u);
  EXPECT_TRUE(out[0].expected);
  EXPECT_EQ(out[0].state, ServiceState::kStopped);
  EXPECT_NE(out[0].detail.find("bad address"), std::string::npos);
  EXPECT_EQ(out[0].interfaces, std::vector<std::string>{"lan0"});
}

/// A flapping unit must say how many times it has flapped, or the
/// operator watches "starting" for half a minute before suspecting.
TEST(ServiceStatusTest, FlappingServiceSaysSo) {
  ServiceProbe probe;
  probe.is_active_cmd = "echo activating #";
  probe.restarts_cmd = "echo 4 #";
  probe.result_cmd = "echo exit-code #";
  probe.load_state_cmd = "echo loaded #";
  probe.log_cmd = "echo 'dnsmasq: bad option at line 31' #";
  auto out = QueryServices(MustParse(kOfficeShape), probe);
  ASSERT_GE(out.size(), 1u);
  EXPECT_EQ(out[0].state, ServiceState::kRestarting);
  EXPECT_NE(out[0].detail.find("restarted 4"), std::string::npos)
      << out[0].detail;
  EXPECT_NE(out[0].detail.find("bad option"), std::string::npos)
      << out[0].detail;

  // The first failed start: Result is already set, NRestarts is not,
  // and "restarted 0 times" would be a confusing thing to print.
  probe.restarts_cmd = "echo 0 #";
  auto first = QueryServices(MustParse(kOfficeShape), probe);
  ASSERT_GE(first.size(), 1u);
  EXPECT_EQ(first[0].state, ServiceState::kRestarting);
  EXPECT_EQ(first[0].detail.find("restarted 0"), std::string::npos)
      << first[0].detail;
  EXPECT_NE(first[0].detail.find("failed on start"),
            std::string::npos)
      << first[0].detail;
}

/// The model wants a service; the box has no unit for it. That must
/// not read as a crash, and must not read as nothing at all.
TEST(ServiceStatusTest, MissingUnitIsNamedNotBlamedOnACrash) {
  ServiceProbe probe;
  probe.is_active_cmd = "echo failed #";
  probe.restarts_cmd = "echo 5 #";
  probe.result_cmd = "echo exit-code #";
  probe.load_state_cmd = "echo not-found #";
  probe.log_cmd = "true #";
  auto out = QueryServices(MustParse(kOfficeShape), probe);
  ASSERT_GE(out.size(), 1u);
  EXPECT_EQ(out[0].state, ServiceState::kNotInstalled);
  EXPECT_NE(out[0].detail.find("not installed"), std::string::npos)
      << out[0].detail;
  EXPECT_NE(out[0].detail.find("testnet"), std::string::npos)
      << out[0].detail;
}

TEST(ServiceStatusTest, SilentSystemdIsNotHealth) {
  ServiceProbe probe;
  probe.is_active_cmd = "true #";
  probe.restarts_cmd = "true #";
  probe.result_cmd = "true #";
  probe.load_state_cmd = "echo loaded #";
  probe.log_cmd = "true #";
  auto out = QueryServices(MustParse(kOfficeShape), probe);
  ASSERT_GE(out.size(), 1u);
  EXPECT_EQ(out[0].state, ServiceState::kUnknown);
  EXPECT_FALSE(out[0].detail.empty())
      << "an unknown state must still say something";
}

TEST(ServiceStatusTest, NothingBoundMeansNothingExpected) {
  ServiceProbe probe;
  probe.is_active_cmd = "echo inactive #";
  probe.restarts_cmd = "echo 0 #";
  probe.result_cmd = "echo success #";
  probe.load_state_cmd = "echo loaded #";
  probe.log_cmd = "true #";
  auto out = QueryServices(MustParse(R"YAML(
zones:
  wan:
interfaces:
  wan0:
    mac: "52:54:00:aa:bb:01"
    address: dhcp
    zone: wan
)YAML"), probe);
  ASSERT_GE(out.size(), 1u);
  EXPECT_FALSE(out[0].expected);
  EXPECT_EQ(out[0].state, ServiceState::kNotConfigured);
}

/// Anything that writes `10-f-<iface>.network` by hand — the shape the
/// CLI's old `set address` used to emit, an operator with an editor —
/// has no digest header, so the model must see it as an edit rather
/// than quietly adopting or overwriting it. `set address` now edits the
/// system configuration instead (see test_fw_set_address.cc); this
/// keeps the guard on the file itself.
TEST(NetworkdTest, HandWrittenUnitsShowUpAsDrift) {
  TempDir dir;
  NetworkdOptions opts;
  opts.dir = dir.Path();
  auto cfg = MustParse(kOfficeShape);

  // Byte-for-byte what adapters/cli WriteNetworkd() emits.
  WriteFile(dir.File("10-f-lan0.network"),
            "[Match]\nName=lan0\n\n[Network]\nAddress=10.10.0.9/24\n");

  auto units = PlanNetworkd(cfg, opts);
  auto drift = CheckNetworkdDrift(units);
  bool saw = false;
  for (std::size_t i = 0; i < units.size(); ++i) {
    if (!units[i].path.ends_with("10-f-lan0.network")) continue;
    saw = true;
    EXPECT_EQ(drift[i], DriftKind::kHandEdited);
  }
  EXPECT_TRUE(saw);

  auto applied = ApplyNetworkd(cfg, opts);
  ASSERT_FALSE(applied.has_value())
      << "the model must not silently take the file over";
  EXPECT_NE(ReadFile(dir.File("10-f-lan0.network")).find("10.10.0.9"),
            std::string::npos);
}

TEST(NetworkdTest, NoLinkUnitWithoutHardwareIdentity) {
  TempDir dir;
  NetworkdOptions opts;
  opts.dir = dir.Path();
  SystemConfig cfg;
  cfg.zones.push_back({"a"});
  Interface i;
  i.name = "p0";
  i.zone = "a";
  cfg.interfaces.push_back(i);
  auto units = PlanNetworkd(cfg, opts);
  for (const auto& u : units) {
    EXPECT_FALSE(u.path.ends_with(".link"))
        << "an unpinnable interface must not get a pin";
  }
}

}  // namespace
}  // namespace f::sysconfig
