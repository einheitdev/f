/// @file test_fw_masq_sources.cc
/// @brief What the CLI says a masquerading box translates to.
///
/// `masquerade` translates the source to the address of the zone THIS
/// one redirects to, so a box whose two inside zones leave through two
/// different uplinks has two masquerade addresses. Until `fwl_nat_cfg`
/// became per zone it had one — one bundle-global map with one slot 0,
/// written once per masquerading zone by `fd`, so the last zone loaded
/// decided what every masquerading program translated to.
///
/// The report is half of why that stayed invisible: a screen with room
/// for one address cannot show two, so a box translating half its
/// traffic to the wrong uplink rendered exactly like a healthy one.
/// Each test here feeds a one-uplink and a two-uplink payload and
/// requires the screens to differ.

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

class MasqSourcesTest : public ::testing::Test {
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

  auto Render(const std::string& path, const json& data) -> std::string {
    const auto* spec = Spec(path);
    EXPECT_NE(spec, nullptr);
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
    caps.width = 200;
    caps.height = 60;
    caps.unicode = false;
    render::Renderer r(out, caps, render::OutputFormat::Table);
    adapter_->RenderResponse(*spec, resp, r);
    return out.str();
  }

  static auto Has(const std::string& hay, const std::string& needle)
      -> bool {
    return hay.find(needle) != std::string::npos;
  }

  /// The `nat` section of a status reply, with whatever masquerade
  /// fields the caller wants on top of a plausible table.
  static auto NatSection(const json& extra) -> json {
    json n = {
        {"enabled", true},        {"entries", 12},
        {"max_entries", 65536},   {"occupancy_pct", 0},
        {"high_water", 12},       {"grace_s", 30},
        {"total_reclaimed", 0},   {"installed", 12},
        {"port_reallocated", 0},  {"refused", 0},
        {"table_full", 0},        {"denat", 12},
        {"icmp_error", 0},
    };
    n.update(extra);
    return {{"nat", n}};
  }

  std::unique_ptr<cli::ProductAdapter> adapter_;
};

TEST_F(MasqSourcesTest, ShowNatNamesEveryZoneWhenTheyDiffer) {
  // The two-uplink box. Both addresses, each with the zone it belongs
  // to — anything less is a screen that cannot distinguish this box
  // from one whose zones have silently collapsed onto one address.
  auto out = Render("show nat", {
    {"translations", json::array()},
    {"masq_sources", json::array({
      json{{"zone", "ina"}, {"address", "10.99.210.2"}},
      json{{"zone", "inb"}, {"address", "10.99.211.2"}},
    })},
  });
  EXPECT_TRUE(Has(out, "10.99.210.2")) << out;
  EXPECT_TRUE(Has(out, "10.99.211.2")) << out;
  EXPECT_TRUE(Has(out, "ina")) << out;
  EXPECT_TRUE(Has(out, "inb")) << out;
}

TEST_F(MasqSourcesTest, ShowNatKeepsTheOneUplinkLineItAlwaysHad) {
  // The ordinary gateway, and every existing consumer's case: one
  // address, one line, unchanged. The zone is not named because there
  // is nothing to disambiguate.
  auto out = Render("show nat", {
    {"translations", json::array()},
    {"masq_source", "203.0.113.1"},
    {"masq_sources", json::array({
      json{{"zone", "lan"}, {"address", "203.0.113.1"}},
    })},
  });
  EXPECT_TRUE(Has(out, "masquerade source: 203.0.113.1")) << out;
}

TEST_F(MasqSourcesTest, TheSECONDZonesAddressIsOnTheScreen) {
  // The pair a renderer with room for one address collapses, and the
  // two payloads differ in NOTHING but zone inb's address — no
  // `masq_source` in either, so a renderer that reads only that field
  // prints identical (empty) screens for a box translating both zones
  // to one uplink and a box translating each to its own. That is the
  // defect exactly: the difference existed and no screen showed it.
  auto with = [this](const char* inb_addr) {
    return Render("show nat", {
      {"translations", json::array()},
      {"masq_sources", json::array({
        json{{"zone", "ina"}, {"address", "10.99.210.2"}},
        json{{"zone", "inb"}, {"address", inb_addr}},
      })},
    });
  };
  EXPECT_NE(with("10.99.210.2"), with("10.99.211.2"));
}

TEST_F(MasqSourcesTest, StatusShowsThemToo) {
  // `show status` is the live view an operator watches; the address
  // each zone translates to belongs there and not only behind a second
  // verb.
  auto out = Render("show status", NatSection({
    {"masq_sources", json::array({
      json{{"zone", "ina"}, {"address", "10.99.210.2"}},
      json{{"zone", "inb"}, {"address", "10.99.211.2"}},
    })},
  }));
  EXPECT_TRUE(Has(out, "nat_masquerade[ina]")) << out;
  EXPECT_TRUE(Has(out, "10.99.211.2")) << out;
}

TEST_F(MasqSourcesTest, ABundleWideAddressSaysSo) {
  // The upgrade case, and a third state rather than a second one. A
  // bundle compiled before the split holds ONE slot for the whole
  // bundle, so two zones reading differently is not possible however
  // the policy is written. The operator is told what is true and what
  // fixes it, rather than being shown one address as if it were a
  // per-zone answer.
  auto with = Render("show status", NatSection({
    {"masq_sources", json::array({
      json{{"zone", "ina"}, {"address", "10.99.210.2"}},
    })},
    {"masq_source_is_bundle_wide", true},
  }));
  auto without = Render("show status", NatSection({
    {"masq_sources", json::array({
      json{{"zone", "ina"}, {"address", "10.99.210.2"}},
    })},
  }));
  EXPECT_TRUE(Has(with, "recompile")) << with;
  EXPECT_FALSE(Has(without, "recompile")) << without;
  EXPECT_NE(with, without);
}

}  // namespace
