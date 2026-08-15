/// @file test_fw_config_verbs.cc
/// @brief Configuring the box through the CLI, end to end.
///
/// Before these verbs, `firstboot` was the only thing on an appliance
/// that ever *wrote* a zone or a policy, and everything an operator
/// did afterwards was an editor with no safety net. The rehearsal's
/// step 3 — configure interfaces and zones through the CLI — could
/// not be done at all.
///
/// So the assertions here are about the verbs existing *and reaching
/// the documents that matter*: `system.yaml` for zones and ports, the
/// `.fw` source for policy. They run against the real transport with
/// no `fd` and no `f-confd`, which is also the case that has to
/// degrade honestly — a change that was written but not loaded must
/// say which half happened.

#include <gtest/gtest.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>

#include <nlohmann/json.hpp>

#include "adapters/fw/adapter.h"
#include "adapters/fw/transport.h"
#include "einheit/cli/protocol/envelope.h"
#include "f/policy/edit.h"
#include "f/sysconfig/parse.h"

namespace {

using json = nlohmann::json;
namespace cli = einheit::cli;
namespace proto = cli::protocol;
namespace fw = einheit::adapters::fw;
namespace sc = f::sysconfig;

constexpr const char* kSystem = R"(# the bench box
zones:
  testnet:

interfaces:
  lo:
    mac: "00:00:00:00:00:00"
    address: 10.10.0.1/24
    zone: testnet
)";

constexpr const char* kPolicy = R"(zone testnet = [lo]

@xdp(testnet)

count testnet_total

allow if conntrack(pkt).state in [established, related]
allow if pkt.proto == tcp and pkt.dst_port == 22

default drop
)";

auto ReadText(const std::filesystem::path& p) -> std::string {
  std::ifstream in(p);
  std::ostringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

auto WriteText(const std::filesystem::path& p, const std::string& s)
    -> void {
  std::filesystem::create_directories(p.parent_path());
  std::ofstream out(p);
  out << s;
}

/// A stand-in for the compiler that accepts everything, so the tests
/// exercise the CLI's own pipeline on a machine with no `fwl`
/// installed. The refusal path gets a rejecting one of its own.
auto WriteFakeFwl(const std::filesystem::path& p, int exit_code,
                  const std::string& message) -> void {
  WriteText(p, std::format("#!/bin/sh\necho '{}'\nexit {}\n", message,
                           exit_code));
  std::filesystem::permissions(
      p, std::filesystem::perms::owner_all |
             std::filesystem::perms::group_exec |
             std::filesystem::perms::others_exec);
}

class ConfigVerbs : public ::testing::Test {
 protected:
  void SetUp() override {
    dir_ = std::filesystem::temp_directory_path() /
           std::format("f-cfgverbs-{}", ::getpid());
    std::filesystem::remove_all(dir_);
    std::filesystem::create_directories(dir_ / "net");
    std::filesystem::create_directories(dir_ / "gen");
    WriteText(SystemPath(), kSystem);
    WriteText(PolicyPath(), kPolicy);
    WriteFakeFwl(dir_ / "fwl-ok", 0, "ok");
    WriteFakeFwl(dir_ / "fwl-no", 1,
                 "error[E001]: 3:1: no such zone");

    cfg_.system_config = SystemPath().string();
    cfg_.fw_source = PolicyPath().string();
    cfg_.networkd_dir = (dir_ / "net").string();
    cfg_.dnsmasq_conf = (dir_ / "gen" / "dnsmasq.conf").string();
    cfg_.sysctl_dir = (dir_ / "gen").string();
    cfg_.sysctl_proc_dir = (dir_ / "gen" / "proc").string();
    cfg_.config_path = (dir_ / "cli.json").string();
    cfg_.fwl_path = (dir_ / "fwl-ok").string();
    // Nothing is listening on these; that is the point.
    cfg_.fd_socket = "ipc://" + (dir_ / "no-fd.sock").string();
    cfg_.confd_socket = "ipc://" + (dir_ / "no-confd.sock").string();
  }

  void TearDown() override {
    std::filesystem::remove_all(dir_);
  }

  auto SystemPath() const -> std::filesystem::path {
    return dir_ / "system.yaml";
  }
  auto PolicyPath() const -> std::filesystem::path {
    return dir_ / "rules.fw";
  }

  auto Send(const std::string& command,
            std::vector<std::string> args = {}) -> proto::Response {
    auto tx = fw::NewFLocalTransport(cfg_);
    EXPECT_TRUE(tx.has_value());
    proto::Request req;
    req.id = "t";
    req.command = command;
    req.args = std::move(args);
    auto resp = (*tx)->SendRequest(req, std::chrono::seconds(5));
    EXPECT_TRUE(resp.has_value());
    return *resp;
  }

  static auto Body(const proto::Response& r) -> json {
    if (r.data.empty()) return json::object();
    return json::parse(std::string(r.data.begin(), r.data.end()),
                       nullptr, false);
  }

  auto Model() const -> sc::SystemConfig {
    auto parsed = sc::ParseSystemConfigString(ReadText(SystemPath()));
    EXPECT_TRUE(parsed.has_value());
    return parsed ? *parsed : sc::SystemConfig{};
  }

  std::filesystem::path dir_;
  fw::FLocalConfig cfg_;
};

// -- zones ------------------------------------------------------------

TEST_F(ConfigVerbs, SetZoneWritesTheSystemConfiguration) {
  auto r = Send("zone_set", {"dmz"});
  ASSERT_EQ(r.status, proto::ResponseStatus::Ok)
      << (r.error ? r.error->message : "");
  const auto model = Model();
  EXPECT_NE(model.FindZone("dmz"), nullptr);
  // The document, not a second copy of it somewhere else.
  EXPECT_NE(ReadText(SystemPath()).find("dmz"), std::string::npos);
  // And the comment the operator wrote is still at the top.
  EXPECT_NE(ReadText(SystemPath()).find("# the bench box"),
            std::string::npos);
}

// A zone with no ports in it attaches no program. A green reply that
// did not say so would read as "the segment is now filtered".
TEST_F(ConfigVerbs, SetZoneSaysAnEmptyZoneIsEmpty) {
  auto r = Send("zone_set", {"dmz"});
  ASSERT_EQ(r.status, proto::ResponseStatus::Ok);
  auto j = Body(r);
  ASSERT_TRUE(j.contains("note"));
  EXPECT_NE(j["note"].get<std::string>().find("no interfaces"),
            std::string::npos);
}

TEST_F(ConfigVerbs, SetZoneCarriesAnIpv6Stance) {
  auto r = Send("zone_set", {"dmz", "off"});
  ASSERT_EQ(r.status, proto::ResponseStatus::Ok)
      << (r.error ? r.error->message : "");
  const auto model = Model();
  const auto* z = model.FindZone("dmz");
  ASSERT_NE(z, nullptr);
  EXPECT_EQ(z->ipv6, sc::Ipv6Stance::kOff);
  EXPECT_NE(ReadText(SystemPath()).find("ipv6: off"),
            std::string::npos);
}

// A stance the model refuses comes back as the *named* diagnostic,
// and the document on disk is untouched. `ra` needs a v6 prefix on an
// interface in the zone (SC031); an empty zone has none.
TEST_F(ConfigVerbs, ARefusedStanceReportsTheDiagnostic) {
  const auto before = ReadText(SystemPath());
  auto r = Send("zone_set", {"dmz", "ra"});
  auto j = Body(r);
  EXPECT_FALSE(j.value("applied", true));
  auto diags = j.value("diagnostics", json::array());
  ASSERT_FALSE(diags.empty());
  bool named = false;
  for (const auto& d : diags) {
    if (d.value("text", "").find("SC031") != std::string::npos) {
      named = true;
    }
  }
  EXPECT_TRUE(named) << diags.dump();
  EXPECT_EQ(ReadText(SystemPath()), before);
}

TEST_F(ConfigVerbs, SetInterfaceZoneMovesThePort) {
  ASSERT_EQ(Send("zone_set", {"dmz"}).status,
            proto::ResponseStatus::Ok);
  auto r = Send("iface_set_zone", {"lo", "dmz"});
  ASSERT_EQ(r.status, proto::ResponseStatus::Ok)
      << (r.error ? r.error->message : "");
  const auto model = Model();
  const auto* i = model.FindInterface("lo");
  ASSERT_NE(i, nullptr);
  EXPECT_EQ(i->zone, "dmz");
  EXPECT_EQ(i->address, "10.10.0.1/24");
}

TEST_F(ConfigVerbs, SetInterfaceZoneRefusesAnUndeclaredZone) {
  auto r = Send("iface_set_zone", {"lo", "nosuch"});
  ASSERT_EQ(r.status, proto::ResponseStatus::Error);
  ASSERT_TRUE(r.error.has_value());
  EXPECT_NE(r.error->message.find("not declared"),
            std::string::npos);
  // Nothing was written.
  const auto model = Model();
  EXPECT_EQ(model.FindInterface("lo")->zone, "testnet");
}

TEST_F(ConfigVerbs, NoZoneRefusesWhileAPortIsInIt) {
  auto r = Send("zone_delete", {"testnet"});
  ASSERT_EQ(r.status, proto::ResponseStatus::Error);
  ASSERT_TRUE(r.error.has_value());
  EXPECT_NE(r.error->message.find("lo"), std::string::npos);
  const auto model = Model();
  EXPECT_NE(model.FindZone("testnet"), nullptr);
}

TEST_F(ConfigVerbs, NoInterfaceZoneLeavesThePortDeclared) {
  auto r = Send("iface_del_zone", {"lo"});
  ASSERT_EQ(r.status, proto::ResponseStatus::Ok)
      << (r.error ? r.error->message : "");
  const auto model = Model();
  const auto* i = model.FindInterface("lo");
  ASSERT_NE(i, nullptr);
  EXPECT_TRUE(i->zone.empty());
  EXPECT_EQ(i->match.value, "00:00:00:00:00:00");
}

// f-confd is what reloads the derived artifacts. With it down the
// files are written and nothing is running them, and the reply has to
// carry that as its own field rather than as a green `applied`.
TEST_F(ConfigVerbs, WithoutConfdTheReplySaysNothingWasReloaded) {
  auto j = Body(Send("zone_set", {"dmz"}));
  EXPECT_EQ(j.value("via", ""), "direct");
  EXPECT_FALSE(j.value("activated", true));
  EXPECT_NE(j.value("activation_note", "").find("not running"),
            std::string::npos);
}

// -- services ----------------------------------------------------------

// The first hour used to need an editor for this block and only this
// block. Building the whole document from verbs is the claim; these
// are the two statements that were missing from it.
TEST_F(ConfigVerbs, TheWholeDocumentCanBeBuiltFromVerbs) {
  WriteText(SystemPath(), "");
  ASSERT_EQ(Send("zone_set", {"testnet"}).status,
            proto::ResponseStatus::Ok);
  ASSERT_EQ(Send("iface_set_zone", {"lo", "testnet"}).status,
            proto::ResponseStatus::Ok);
  ASSERT_EQ(Send("iface_set_address", {"lo", "10.10.0.1/24"}).status,
            proto::ResponseStatus::Ok);
  ASSERT_EQ(Send("dhcp_set",
                 {"testnet", "10.10.0.100-10.10.0.200", "12h"})
                .status,
            proto::ResponseStatus::Ok);
  ASSERT_EQ(Send("dns_set", {"testnet", "9.9.9.9"}).status,
            proto::ResponseStatus::Ok);
  ASSERT_EQ(
      Send("set_reservation",
           {"aa:bb:cc:dd:ee:01", "10.10.0.50", "bench1"})
          .status,
      proto::ResponseStatus::Ok);

  const auto model = Model();
  ASSERT_NE(model.FindZone("testnet"), nullptr);
  ASSERT_NE(model.FindInterface("lo"), nullptr);
  EXPECT_EQ(model.FindInterface("lo")->address, "10.10.0.1/24");
  EXPECT_TRUE(model.ZoneServesDhcp("testnet"));
  EXPECT_TRUE(model.ZoneServesDns("testnet"));
  ASSERT_EQ(model.dhcp.size(), 1u);
  ASSERT_EQ(model.dhcp[0].reservations.size(), 1u);
  EXPECT_EQ(model.dhcp[0].reservations[0].address, "10.10.0.50");
}

// dnsmasq is derived from the zones, so a change to them has to
// regenerate it. This path used to stop at networkd and sysctl: the
// reservation went into the model, the reply said `applied`, and the
// generated config still held the previous one.
TEST_F(ConfigVerbs, AServiceChangeRegeneratesTheDnsmasqConfig) {
  ASSERT_EQ(Send("dhcp_set",
                 {"testnet", "10.10.0.100-10.10.0.200", "12h"})
                .status,
            proto::ResponseStatus::Ok);
  const std::filesystem::path conf = cfg_.dnsmasq_conf;
  ASSERT_TRUE(std::filesystem::exists(conf));
  EXPECT_NE(ReadText(conf).find("10.10.0.100,10.10.0.200"),
            std::string::npos)
      << ReadText(conf);

  ASSERT_EQ(Send("set_reservation",
                 {"aa:bb:cc:dd:ee:02", "10.10.0.51"})
                .status,
            proto::ResponseStatus::Ok);
  EXPECT_NE(ReadText(conf).find("10.10.0.51"), std::string::npos)
      << "the reservation is in the model but not in the artifact "
         "the daemon reads";
}

TEST_F(ConfigVerbs, SetDhcpRefusesAZoneThatIsNotDeclared) {
  const auto before = ReadText(SystemPath());
  auto r = Send("dhcp_set", {"nope", "10.30.0.1-10.30.0.9"});
  ASSERT_EQ(r.status, proto::ResponseStatus::Error);
  EXPECT_EQ(ReadText(SystemPath()), before);
}

// -- policy -----------------------------------------------------------

TEST_F(ConfigVerbs, ShowPolicyNumbersTheStatements) {
  auto j = Body(Send("show_policy"));
  auto blocks = j.value("blocks", json::array());
  ASSERT_EQ(blocks.size(), 1u);
  EXPECT_EQ(blocks[0].value("zone", ""), "testnet");
  auto stmts = blocks[0].value("statements", json::array());
  ASSERT_EQ(stmts.size(), 4u);
  EXPECT_EQ(stmts[0].value("index", 0), 1);
  EXPECT_EQ(stmts[3].value("text", ""), "default drop");
  EXPECT_FALSE(stmts[3].value("guarded", true));
  // The source is not the running policy, and the reply says so.
  EXPECT_FALSE(j.value("caveat", "").empty());
}

TEST_F(ConfigVerbs, SetRuleWritesThePolicyFile) {
  auto r = Send("set_rule", {"testnet", "allow", "tcp", "443"});
  // fd is not running, so the change is saved and not loaded — an
  // error whose message names both halves.
  ASSERT_EQ(r.status, proto::ResponseStatus::Error);
  ASSERT_TRUE(r.error.has_value());
  EXPECT_NE(r.error->message.find("saved to"), std::string::npos);
  EXPECT_NE(r.error->message.find("UNCHANGED"), std::string::npos);

  auto view = f::policy::ReadPolicy(ReadText(PolicyPath()));
  bool found = false;
  for (const auto* s : view.InZone("testnet")) {
    if (s->text ==
        "allow if pkt.proto == tcp and pkt.dst_port == 443") {
      found = true;
      // Above `default drop`, or it could never match.
      EXPECT_LT(s->index, 5);
    }
  }
  EXPECT_TRUE(found);
}

// The compiler is the authority, and it gets the last word *before*
// the write. A policy that does not compile never reaches the file a
// cold start would load.
TEST_F(ConfigVerbs, ARuleThatWillNotCompileNeverReachesTheFile) {
  cfg_.fwl_path = (dir_ / "fwl-no").string();
  const auto before = ReadText(PolicyPath());
  auto r = Send("set_rule", {"testnet", "allow", "tcp", "443"});
  ASSERT_EQ(r.status, proto::ResponseStatus::Error);
  ASSERT_TRUE(r.error.has_value());
  EXPECT_NE(r.error->message.find("E001"), std::string::npos);
  EXPECT_EQ(ReadText(PolicyPath()), before);
}

TEST_F(ConfigVerbs, NoRuleRemovesTheStatementItWasGiven) {
  auto before = f::policy::ReadPolicy(ReadText(PolicyPath()))
                    .InZone("testnet")
                    .size();
  Send("no_rule", {"testnet", "3"});
  auto view = f::policy::ReadPolicy(ReadText(PolicyPath()));
  EXPECT_EQ(view.InZone("testnet").size(), before - 1);
  for (const auto* s : view.InZone("testnet")) {
    EXPECT_EQ(s->text.find("dst_port == 22"), std::string::npos);
  }
}

TEST_F(ConfigVerbs, SetRuleRefusesAZoneThePolicyDoesNotHave) {
  const auto before = ReadText(PolicyPath());
  auto r = Send("set_rule", {"dmz", "allow", "icmp"});
  ASSERT_EQ(r.status, proto::ResponseStatus::Error);
  EXPECT_EQ(ReadText(PolicyPath()), before);
}

// -- port forwards -----------------------------------------------------

// The inside zone is derived from the system configuration, never
// asked for: a `redirect` naming the wrong zone puts frames somewhere
// nothing inspects them, and the model already knows which segment an
// address belongs to.
class Forwards : public ConfigVerbs {
 protected:
  void SetUp() override {
    ConfigVerbs::SetUp();
    WriteText(SystemPath(), R"(zones:
  wan:
  testnet:

interfaces:
  lo:
    mac: "00:00:00:00:00:00"
    address: 10.10.0.1/24
    zone: testnet
  lo1:
    mac: "00:00:00:00:00:01"
    address: 192.0.2.5/24
    zone: wan
)");
    WriteText(PolicyPath(), R"(zone wan = [lo1]
zone testnet = [lo]

@xdp(wan)

allow if conntrack(pkt).state in [established, related]

default drop

@xdp(testnet)

allow if pkt.dst_ip == 10.10.0.1
masquerade
redirect to wan

default drop
)");
  }
};

TEST_F(Forwards, WritesBothHalvesAndDerivesTheInsideZone) {
  auto r = Send("set_forward",
                {"wan", "tcp", "80", "10.10.0.20:8080"});
  // fd is down, so this is the saved-not-loaded error. The file is
  // what the assertion is about.
  EXPECT_EQ(r.status, proto::ResponseStatus::Error);

  auto view = f::policy::ReadPolicy(ReadText(PolicyPath()));
  std::string dnat;
  std::string redirect;
  for (const auto* s : view.InZone("wan")) {
    if (s->verb == f::policy::Verb::kTranslate) dnat = s->text;
    if (s->verb == f::policy::Verb::kRedirect) redirect = s->text;
  }
  EXPECT_EQ(dnat,
            "dnat to 10.10.0.20:8080 if pkt.proto == tcp and "
            "pkt.dst_port == 80");
  EXPECT_EQ(redirect,
            "redirect to testnet if pkt.proto == tcp and "
            "pkt.dst_port == 80");
}

TEST_F(Forwards, RefusesATargetNoZoneHolds) {
  const auto before = ReadText(PolicyPath());
  auto r = Send("set_forward",
                {"wan", "tcp", "80", "203.0.113.9:8080"});
  ASSERT_EQ(r.status, proto::ResponseStatus::Error);
  ASSERT_TRUE(r.error.has_value());
  EXPECT_NE(r.error->message.find("not in the subnet"),
            std::string::npos);
  EXPECT_EQ(ReadText(PolicyPath()), before);
}

TEST_F(Forwards, NoForwardRemovesBothHalves) {
  Send("set_forward", {"wan", "tcp", "80", "10.10.0.20:8080"});
  Send("no_forward", {"wan", "tcp", "80"});
  auto view = f::policy::ReadPolicy(ReadText(PolicyPath()));
  for (const auto* s : view.InZone("wan")) {
    EXPECT_EQ(s->text.find("dst_port == 80"), std::string::npos)
        << s->text;
  }
}

// -- the surface that used to lie --------------------------------------

// `set <path> <value>` parsed its arguments, answered `status: set`,
// and wrote nothing anywhere. It is no longer a registered command,
// and the handler refuses by name so anything still sending the wire
// verb is told where the real ones are.
TEST_F(ConfigVerbs, SchemaPathSetIsRefusedRatherThanAcknowledged) {
  auto r = Send("set", {"daemon.log_level", "debug"});
  ASSERT_EQ(r.status, proto::ResponseStatus::Error);
  ASSERT_TRUE(r.error.has_value());
  EXPECT_NE(r.error->message.find("changed nothing"),
            std::string::npos);
}

TEST_F(ConfigVerbs, SchemaPathDeleteIsRefusedToo) {
  auto r = Send("delete", {"daemon.log_level"});
  EXPECT_EQ(r.status, proto::ResponseStatus::Error);
}

// An empty commit history and no commit history are different facts,
// and only one of them was ever being reported.
TEST_F(ConfigVerbs, ShowCommitsSaysWhenThereIsNoRecorder) {
  auto r = Send("show_commits");
  ASSERT_EQ(r.status, proto::ResponseStatus::Error);
  ASSERT_TRUE(r.error.has_value());
  EXPECT_NE(r.error->message.find("f-confd"), std::string::npos);
}

// A recorded revision you cannot return to is not a way back, and
// with no recorder there is no revision either. Both are said.
TEST_F(ConfigVerbs, RollbackSystemSaysWhenThereIsNothingToRollBackTo) {
  auto r = Send("rollback_system");
  ASSERT_EQ(r.status, proto::ResponseStatus::Error);
  ASSERT_TRUE(r.error.has_value());
  EXPECT_NE(r.error->message.find("f-confd"), std::string::npos);
}

// -- discoverability ---------------------------------------------------

TEST(FwSurface, EveryCommandCarriesHelp) {
  auto adapter = fw::NewFwAdapter();
  for (const auto& c : adapter->Commands()) {
    EXPECT_FALSE(c.help.empty()) << c.path << " has no help";
  }
}

// The verbs the rehearsal could not find, present by name.
TEST(FwSurface, TheConfigurationVerbsExist) {
  auto adapter = fw::NewFwAdapter();
  std::set<std::string> paths;
  for (const auto& c : adapter->Commands()) paths.insert(c.path);
  for (const auto* want :
       {"set zone", "no zone", "set interface zone",
        "no interface zone", "set dhcp", "no dhcp", "set dns",
        "no dns", "show policy", "set rule", "no rule",
        "set forward", "no forward", "rollback system",
        "show commits"}) {
    EXPECT_TRUE(paths.contains(want)) << want;
  }
}

// The framework's candidate family is not registered wholesale any
// more; these are the ones this product never implemented.
TEST(FwSurface, TheVerbsThatDidNothingAreGone) {
  auto adapter = fw::NewFwAdapter();
  std::set<std::string> paths;
  for (const auto& c : adapter->Commands()) paths.insert(c.path);
  for (const auto* gone :
       {"set", "delete", "save", "load factory", "commit confirmed",
        "confirm", "rollback previous", "rollback to",
        "show configs"}) {
    EXPECT_FALSE(paths.contains(gone)) << gone;
  }
}

}  // namespace
