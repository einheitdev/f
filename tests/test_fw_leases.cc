/// @file test_fw_leases.cc
/// @brief What the operator actually reads: the rendered lease view.
///
/// Every test here is about a *distinction* the output has to make. A
/// renderer that printed one fixed "no devices" line would pass a test
/// that only checked "the table is empty" — so each case asserts the
/// specific words that separate it from its neighbours:
///
///   nothing serves DHCP  /  nothing has asked  /  I could not read it
///
/// and, on the arrival side, watched-it-happen against found-it-there.

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <sstream>
#include <string>

#include "adapters/fw/adapter.h"
#include "einheit/cli/command_tree.h"
#include "einheit/cli/protocol/envelope.h"
#include "einheit/cli/render/table.h"
#include "einheit/cli/render/terminal_caps.h"

namespace {

using json = nlohmann::json;
namespace cli = einheit::cli;
namespace proto = cli::protocol;
namespace render = cli::render;

class LeaseRenderTest : public ::testing::Test {
 protected:
  void SetUp() override {
    adapter_ = einheit::adapters::fw::NewFwAdapter();
  }

  auto Spec(const std::string& path) -> const cli::CommandSpec* {
    for (const auto& c : adapter_->Commands()) {
      if (c.path == path) return &c;
    }
    return nullptr;
  }

  auto Render(const std::string& path, const json& data,
              std::uint16_t width = 100) -> std::string {
    const auto* spec = Spec(path);
    EXPECT_NE(spec, nullptr) << path;
    if (spec == nullptr) return {};
    auto s = data.dump();
    proto::Response resp{
        .id = "t",
        .status = proto::ResponseStatus::Ok,
        .data = {s.begin(), s.end()},
    };
    std::ostringstream out;
    render::TerminalCaps caps{};
    caps.colors = render::ColorDepth::None;
    caps.width = width;
    caps.height = 40;
    caps.unicode = false;
    render::Renderer r(out, caps);
    adapter_->RenderResponse(*spec, resp, r);
    return out.str();
  }

  /// Collapse runs of whitespace so a prose assertion is not defeated
  /// by the wrap point, which is a layout detail and not the message.
  static auto Flat(const std::string& s) -> std::string {
    std::string out;
    bool space = false;
    for (char c : s) {
      const bool ws = c == ' ' || c == '\n' || c == '\t';
      if (ws) {
        space = true;
        continue;
      }
      if (space && !out.empty()) out += ' ';
      space = false;
      out += c;
    }
    return out;
  }

  /// A device body with sensible defaults; override what matters.
  static auto Device(json over = json::object()) -> json {
    json d = {
        {"mac", "aa:bb:cc:dd:ee:01"},
        {"address", "10.10.0.101"},
        {"hostname", "board-a"},
        {"zone", "lan"},
        {"first_seen_age", 30},
        {"first_seen_exact", true},
        {"last_seen_age", 0},
        {"expires_in", 43200},
        {"active", true},
        {"new", false},
        {"reserved", false},
        {"reserved_address", ""},
        {"address_changes", 0},
    };
    d.update(over);
    return d;
  }

  static auto Report(json devices, json over = json::object())
      -> json {
    json j = {
        {"devices", std::move(devices)},
        {"active", 0},
        {"leases", "ok"},
        {"journal", "ok"},
        {"detail", ""},
        {"lease_path", "/var/lib/f/dnsmasq.leases"},
        {"journal_path", "/var/lib/f/devices.json"},
        {"unparsable", json::array()},
        {"ipv6_skipped", 0},
        {"hidden", 0},
        {"filter", "active"},
        {"now", 1000},
    };
    j.update(over);
    return j;
  }

  std::unique_ptr<cli::ProductAdapter> adapter_;
};

// -- the four ways of being empty ------------------------------------

TEST_F(LeaseRenderTest, NoDhcpConfiguredSaysSo) {
  auto out = Render("show leases",
                    Report(json::array(),
                           {{"leases", "no-dhcp-configured"}}));
  EXPECT_NE(out.find("no DHCP server is configured"),
            std::string::npos)
      << out;
  EXPECT_NE(Flat(out).find("services.dhcp"), std::string::npos)
      << "say what to do about it";
}

TEST_F(LeaseRenderTest, NoLeaseFileYetNamesThePathAndBothCauses) {
  auto out = Render("show leases",
                    Report(json::array(),
                           {{"leases", "no-lease-file-yet"}}));
  EXPECT_NE(out.find("no lease file yet"), std::string::npos) << out;
  EXPECT_NE(out.find("/var/lib/f/dnsmasq.leases"), std::string::npos);
  EXPECT_NE(Flat(out).find("show services"), std::string::npos)
      << "dnsmasq not running is one of the two causes";
}

TEST_F(LeaseRenderTest, UnreadableIsLoudAndCarriesTheReason) {
  auto out = Render(
      "show leases",
      Report(json::array(),
             {{"leases", "unreadable"},
              {"detail", "cannot read /var/lib/f/dnsmasq.leases: "
                         "Permission denied"}}));
  EXPECT_NE(out.find("unreadable"), std::string::npos) << out;
  EXPECT_NE(out.find("Permission denied"), std::string::npos)
      << "the errno text is the whole point";
  EXPECT_NE(Flat(out).find("not the same as having no devices"),
            std::string::npos);
}

TEST_F(LeaseRenderTest, GenuinelyEmptyIsDifferentFromAllOfThose) {
  auto out = Render("show leases", Report(json::array()));
  EXPECT_NE(out.find("no device holds a lease"), std::string::npos)
      << out;
  EXPECT_EQ(out.find("unreadable"), std::string::npos);
  EXPECT_EQ(out.find("no DHCP server is configured"),
            std::string::npos);
}

TEST_F(LeaseRenderTest, TheFourEmptiesAreFourDifferentTexts) {
  // The property a stub cannot fake: four inputs, four distinct
  // outputs. Any implementation that collapses them fails here.
  std::vector<std::string> texts;
  for (const char* state :
       {"ok", "no-dhcp-configured", "no-lease-file-yet",
        "unreadable"}) {
    texts.push_back(
        Render("show leases",
               Report(json::array(), {{"leases", state},
                                      {"detail", "some reason"}})));
  }
  for (std::size_t i = 0; i < texts.size(); ++i) {
    for (std::size_t k = i + 1; k < texts.size(); ++k) {
      EXPECT_NE(texts[i], texts[k])
          << "emptiness " << i << " reads the same as " << k;
    }
  }
}

TEST_F(LeaseRenderTest, NoNewArrivalsIsNotNoDevices) {
  auto out = Render("show leases",
                    Report(json::array(), {{"filter", "new"},
                                           {"active", 4},
                                           {"hidden", 4}}));
  EXPECT_NE(out.find("no new arrivals"), std::string::npos) << out;
  EXPECT_NE(Flat(out).find("8 device(s) are known"), std::string::npos)
      << "an operator must not read this as an empty network";
}

// -- history that is not being kept ----------------------------------

TEST_F(LeaseRenderTest, AnUnwritableJournalIsAnnouncedNotSwallowed) {
  auto out = Render(
      "show leases",
      Report(json::array({Device()}),
             {{"journal", "unwritable"},
              {"detail", "cannot write /var/lib/f/devices.json"}}));
  EXPECT_NE(Flat(out).find("NOT being recorded"), std::string::npos) << out;
  EXPECT_NE(out.find("cannot write"), std::string::npos);
}

TEST_F(LeaseRenderTest, TheFirstLookSaysItsTimesAreBounds) {
  auto out = Render(
      "show leases",
      Report(json::array({Device({{"first_seen_exact", false}})}),
             {{"journal", "first-observation"}}));
  EXPECT_NE(Flat(out).find("upper bounds"), std::string::npos) << out;
  EXPECT_NE(out.find(">=30s"), std::string::npos)
      << "an inferred age is rendered as a bound, not a measurement";
}

TEST_F(LeaseRenderTest, AnExactAgeCarriesNoBoundMarker) {
  auto out = Render("show leases",
                    Report(json::array({Device()})));
  EXPECT_NE(out.find("30s"), std::string::npos) << out;
  EXPECT_EQ(out.find(">="), std::string::npos)
      << "a watched arrival is a measurement and must not be hedged";
}

TEST_F(LeaseRenderTest, UnparsableLinesAreReportedVerbatim) {
  auto out = Render(
      "show leases",
      Report(json::array({Device()}),
             {{"unparsable", json::array({"garbage line here"})}}));
  EXPECT_NE(Flat(out).find("did not parse"), std::string::npos) << out;
  EXPECT_NE(out.find("garbage line here"), std::string::npos)
      << "show the line, not a count";
}

// -- the table itself ------------------------------------------------

TEST_F(LeaseRenderTest, NewArrivalsAreMarkedAndReservationsFlagged) {
  auto out = Render(
      "show leases",
      Report(json::array(
          {Device({{"new", true}, {"mac", "aa:bb:cc:dd:ee:aa"}}),
           Device({{"reserved", true},
                   {"reserved_address", "10.10.0.9"},
                   {"mac", "aa:bb:cc:dd:ee:bb"}})})));
  EXPECT_NE(out.find("NEW"), std::string::npos) << out;
  EXPECT_NE(out.find("aa:bb:cc:dd:ee:bb *"), std::string::npos);
  EXPECT_NE(out.find("has a static reservation"), std::string::npos);
}

TEST_F(LeaseRenderTest, AnAddressInNoDeclaredSubnetIsFlagged) {
  auto out = Render("show leases",
                    Report(json::array({Device({{"zone", ""}})})));
  EXPECT_NE(out.find("(no zone)"), std::string::npos) << out;
}

TEST_F(LeaseRenderTest, HiddenRowsSayWhyTheyAreHidden) {
  auto active = Render("show leases",
                       Report(json::array({Device()}),
                              {{"filter", "active"}, {"hidden", 2}}));
  EXPECT_NE(Flat(active).find("no current lease"), std::string::npos)
      << active;
  auto fresh = Render("show leases",
                      Report(json::array({Device({{"new", true}})}),
                             {{"filter", "new"}, {"hidden", 2}}));
  EXPECT_NE(Flat(fresh).find("other device(s) known"), std::string::npos)
      << fresh;
  EXPECT_EQ(Flat(fresh).find("no current lease"), std::string::npos)
      << "the reason rows are missing depends on the filter";
}

TEST_F(LeaseRenderTest, NarrowTerminalsAnnounceTheClipping) {
  auto out = Render("show leases",
                    Report(json::array({Device()})), /*width=*/40);
  EXPECT_NE(out.find("clipped"), std::string::npos)
      << "silent truncation of a MAC is worse than no table: " << out;
}

// -- one device ------------------------------------------------------

TEST_F(LeaseRenderTest, FdBeingDownIsNotADeviceTalkingToNobody) {
  json j = {
      {"mac", "aa:bb:cc:dd:ee:01"},
      {"address", "10.10.0.101"},
      {"hostname", "board-a"},
      {"zone", "lan"},
      {"active", true},
      {"expires_in", 100},
      {"first_seen_age", 5},
      {"first_seen_exact", true},
      {"last_seen_age", 0},
      {"flows_available", false},
      {"flows_detail", "fd is not running (no socket at ipc://x)"},
  };
  auto out = Render("show device", j);
  EXPECT_NE(out.find("fd could not be asked"), std::string::npos)
      << out;
  EXPECT_NE(out.find("no socket at ipc://x"), std::string::npos);
  EXPECT_NE(Flat(out).find("not the same as a device that is "
                            "talking to nobody"),
            std::string::npos);
}

TEST_F(LeaseRenderTest, NoFlowsWithFdUpSaysFdAnswered) {
  json j = {
      {"mac", "aa:bb:cc:dd:ee:01"}, {"address", "10.10.0.101"},
      {"active", true},             {"expires_in", 100},
      {"first_seen_age", 5},        {"first_seen_exact", true},
      {"last_seen_age", 0},         {"flows_available", true},
      {"flows", json::array()},     {"nat_available", true},
      {"nat", json::array()},
  };
  auto out = Render("show device", j);
  EXPECT_NE(Flat(out).find("fd answered"), std::string::npos) << out;
  EXPECT_EQ(out.find("could not be asked"), std::string::npos);
}

TEST_F(LeaseRenderTest, FlowsShowPeerStateAndIdle) {
  json j = {
      {"mac", "aa:bb:cc:dd:ee:01"},
      {"address", "10.10.0.101"},
      {"active", true},
      {"expires_in", 100},
      {"first_seen_age", 5},
      {"first_seen_exact", true},
      {"last_seen_age", 0},
      {"flows_available", true},
      {"packets", 120},
      {"flows", json::array({{{"proto", "tcp"},
                              {"direction", "out"},
                              {"peer", "8.8.8.8"},
                              {"peer_port", 443},
                              {"local_port", 51234},
                              {"state", "established"},
                              {"packets", 120},
                              {"idle", 4}}})},
      {"top_peers",
       json::array({{{"peer", "8.8.8.8"}, {"packets", 120}}})},
      {"nat_available", true},
      {"nat", json::array()},
  };
  auto out = Render("show device", j);
  EXPECT_NE(out.find("8.8.8.8:443"), std::string::npos) << out;
  EXPECT_NE(out.find("established"), std::string::npos);
  EXPECT_NE(out.find("4s"), std::string::npos) << "idle time";
  EXPECT_NE(out.find("TALKING TO"), std::string::npos);
}

TEST_F(LeaseRenderTest, AReservationNotYetInEffectSaysWhy) {
  json j = {
      {"mac", "aa:bb:cc:dd:ee:01"},
      {"address", "10.10.0.101"},
      {"active", true},
      {"expires_in", 100},
      {"first_seen_age", 5},
      {"first_seen_exact", true},
      {"last_seen_age", 0},
      {"reserved", true},
      {"reserved_address", "10.10.0.9"},
      {"flows_available", true},
      {"flows", json::array()},
      {"nat_available", true},
      {"nat", json::array()},
  };
  auto out = Render("show device", j);
  EXPECT_NE(Flat(out).find("not in effect yet"), std::string::npos) << out;
  EXPECT_NE(out.find("10.10.0.9"), std::string::npos);
}

// -- reservations ----------------------------------------------------

TEST_F(LeaseRenderTest, WrittenWithoutConfdIsNotCalledApplied) {
  auto out = Render("set reservation",
                    {{"action", "set reservation"},
                     {"mac", "aa:bb:cc:dd:ee:01"},
                     {"address", "10.10.0.9"},
                     {"zone", "lan"},
                     {"config", "/etc/f/system.yaml"},
                     {"applied", true},
                     {"via", "direct"},
                     {"note", "the client keeps its current address "
                              "until its lease is renewed"}});
  EXPECT_NE(out.find("written, not yet live"), std::string::npos)
      << out;
  EXPECT_NE(Flat(out).find("apply system"), std::string::npos);
}

TEST_F(LeaseRenderTest, ThroughConfdItIsLiveAndSaysSo) {
  auto out = Render("set reservation",
                    {{"action", "set reservation"},
                     {"mac", "aa:bb:cc:dd:ee:01"},
                     {"address", "10.10.0.9"},
                     {"zone", "lan"},
                     {"config", "/etc/f/system.yaml"},
                     {"applied", true},
                     {"via", "f-confd"}});
  EXPECT_NE(out.find("written and live"), std::string::npos) << out;
  EXPECT_EQ(Flat(out).find("apply system"), std::string::npos)
      << "do not tell the operator to do work already done";
}

TEST_F(LeaseRenderTest, ANatMatchedFlowSaysSo) {
  // Behind a masquerade the addresses in conntrack are the gateway's.
  // A row found through the NAT table has to admit it, or the local
  // port beside it looks like something conntrack said directly.
  json j = {
      {"mac", "aa:bb:cc:dd:ee:01"},
      {"address", "10.0.0.2"},
      {"active", true},
      {"expires_in", 100},
      {"first_seen_age", 5},
      {"first_seen_exact", true},
      {"last_seen_age", 0},
      {"flows_available", true},
      {"translated", true},
      {"packets", 4},
      {"flows", json::array({{{"proto", "tcp"},
                              {"direction", "out"},
                              {"peer", "1.1.1.1"},
                              {"peer_port", 443},
                              {"local_port", 40001},
                              {"translated", true},
                              {"state", "established"},
                              {"packets", 4},
                              {"idle", 1}}})},
      {"nat_available", true},
      {"nat", json::array()},
  };
  auto out = Render("show device", j);
  EXPECT_NE(out.find("VIA"), std::string::npos) << out;
  EXPECT_NE(out.find("nat"), std::string::npos) << out;
  EXPECT_NE(out.find("40001"), std::string::npos)
      << "the local port must be the device's, not the wire's";
}

TEST_F(LeaseRenderTest, NoFlowsBehindNatSaysTheAliasesWereTriedToo) {
  json j = {
      {"mac", "aa:bb:cc:dd:ee:01"}, {"address", "10.0.0.2"},
      {"active", true},             {"expires_in", 100},
      {"first_seen_age", 5},        {"first_seen_exact", true},
      {"last_seen_age", 0},         {"flows_available", true},
      {"translated", true},         {"flows", json::array()},
      {"nat_available", true},      {"nat", json::array()},
  };
  auto out = Render("show device", j);
  EXPECT_NE(Flat(out).find("translated endpoints"),
            std::string::npos)
      << out;
}

TEST_F(LeaseRenderTest, NatUnavailableIsItsOwnAnswerToo) {
  json j = {
      {"mac", "aa:bb:cc:dd:ee:01"}, {"address", "10.0.0.2"},
      {"active", true},             {"expires_in", 100},
      {"first_seen_age", 5},        {"first_seen_exact", true},
      {"last_seen_age", 0},         {"flows_available", false},
      {"flows_detail", "fd is not running"},
      {"nat_available", false},
      {"nat_detail", "fd is not running"},
  };
  auto out = Render("show device", j);
  EXPECT_NE(out.find("NAT"), std::string::npos) << out;
  EXPECT_NE(Flat(out).find("could not be asked"), std::string::npos)
      << out;
}

}  // namespace
