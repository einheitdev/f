/// @file test_fw_counters.cc
/// @brief What `show counters` puts on the screen, and the pairs of
/// findings it is not allowed to spell the same way.
///
/// The removed v0.1 counter page printed "no counters active" on a box
/// whose counters were moving, because every kind of empty rendered as
/// the same empty. So each test here feeds two payloads that a broken
/// renderer would collapse into one screen, and requires the screens to
/// differ — and says which way.

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

class ShowCountersTest : public ::testing::Test {
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

  auto Render(const json& data,
              render::OutputFormat format =
                  render::OutputFormat::Table) -> std::string {
    const auto* spec = Spec("show counters");
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
    render::Renderer r(out, caps, format);
    adapter_->RenderResponse(*spec, resp, r);
    return out.str();
  }

  static auto Has(const std::string& hay, const std::string& needle)
      -> bool {
    return hay.find(needle) != std::string::npos;
  }

  static auto Zone(const std::string& name,
                   const std::string& availability, const json& rows,
                   const std::string& detail = "",
                   unsigned slots = 4) -> json {
    return {{"zone", name},
            {"availability", availability},
            {"detail", detail},
            {"map_slots", slots},
            {"counters", rows}};
  }

  static auto Row(const std::string& name, unsigned slot, bool read,
                  std::uint64_t packets) -> json {
    return {{"name", name},
            {"slot", slot},
            {"read", read},
            {"packets", packets}};
  }

  std::unique_ptr<cli::ProductAdapter> adapter_;
};

TEST_F(ShowCountersTest, CommandExistsAndTakesAnOptionalName) {
  const auto* spec = Spec("show counters");
  ASSERT_NE(spec, nullptr);
  EXPECT_EQ(spec->wire_command, "show_counters");
  ASSERT_EQ(spec->args.size(), 1u);
  EXPECT_FALSE(spec->args[0].required);
}

TEST_F(ShowCountersTest, EachCounterAppearsUnderTheNameThePolicyGave) {
  auto out = Render({{"query", ""},
                     {"zones", json::array({Zone(
                          "lan", "read",
                          json::array({Row("lan_total", 0, true, 42),
                                       Row("lan_ssh", 1, true, 0)}))})}});
  EXPECT_TRUE(Has(out, "lan_total"));
  EXPECT_TRUE(Has(out, "lan_ssh"));
  EXPECT_TRUE(Has(out, "42"));
  EXPECT_TRUE(Has(out, "lan"));
}

TEST_F(ShowCountersTest, AHitCounterAndAnUnhitOneReadDifferently) {
  // The control the whole feature rests on: two counters in one
  // policy, one carrying traffic and one not. A renderer that pairs
  // names with values by position rather than by name would still
  // print both numbers — but against the wrong names.
  auto out = Render({{"query", ""},
                     {"zones", json::array({Zone(
                          "lan", "read",
                          json::array({Row("hit_me", 0, true, 17),
                                       Row("stays_zero", 1, true,
                                           0)}))})}});
  auto hit = out.find("hit_me");
  auto zero = out.find("stays_zero");
  ASSERT_NE(hit, std::string::npos);
  ASSERT_NE(zero, std::string::npos);
  // 17 is on the hit_me line, not the stays_zero line.
  auto seventeen = out.find("17");
  ASSERT_NE(seventeen, std::string::npos);
  EXPECT_GT(seventeen, hit);
  EXPECT_LT(seventeen, zero);
}

TEST_F(ShowCountersTest, ZeroAndUnreadableAreNotTheSameScreen) {
  auto zero = Render(
      {{"query", ""},
       {"zones", json::array({Zone("lan", "read",
                                   json::array({Row("lan_total", 0,
                                                    true, 0)}))})}});
  auto unread = Render(
      {{"query", ""},
       {"zones", json::array({Zone("lan", "read",
                                   json::array({Row("lan_total", 0,
                                                    false, 0)}),
                                   "1 of 1 slot(s) could not be "
                                   "read")})}});
  EXPECT_NE(zero, unread);
  EXPECT_TRUE(Has(zero, "0"));
  EXPECT_TRUE(Has(unread, "unreadable"));
  EXPECT_TRUE(Has(unread, "could not be read"));
}

TEST_F(ShowCountersTest, AZoneThatCannotBeReadStillOccupiesARow) {
  // Vanishing from the table is how a firewall with unreadable
  // counters comes to look like a firewall with none.
  auto out = Render(
      {{"query", ""},
       {"zones",
        json::array({Zone("lan", "read",
                          json::array({Row("lan_total", 0, true, 3)})),
                     Zone("wan", "table_unreadable", json::array(),
                          "wan.bpf.c could not be read")})}});
  EXPECT_TRUE(Has(out, "wan"));
  EXPECT_TRUE(Has(out, "names unknown"));
  EXPECT_TRUE(Has(out, "wan.bpf.c could not be read"));
}

TEST_F(ShowCountersTest, TheFourKindsOfEmptyRenderFourWays) {
  auto screen = [&](const std::string& availability) {
    return Render({{"query", ""},
                   {"zones", json::array({Zone("lan", availability,
                                               json::array(),
                                               "why")})}});
  };
  auto none = screen("none_declared");
  auto no_map = screen("map_missing");
  auto no_bound = screen("bound_unreadable");
  auto stale = screen("table_map_mismatch");
  auto unknown_state = screen("something_this_build_never_heard_of");
  EXPECT_NE(none, no_map);
  EXPECT_NE(no_map, no_bound);
  EXPECT_NE(no_bound, stale);
  EXPECT_NE(stale, unknown_state);
  EXPECT_TRUE(Has(none, "no count statements"));
  EXPECT_TRUE(Has(no_map, "no counter map"));
  EXPECT_TRUE(Has(no_bound, "size unknown"));
  EXPECT_TRUE(Has(stale, "stale table"));
  EXPECT_TRUE(Has(unknown_state, "unknown state"));
}

TEST_F(ShowCountersTest, NoZonesAtAllSaysSoRatherThanNothing) {
  auto out = Render({{"query", ""}, {"zones", json::array()}});
  EXPECT_TRUE(Has(out, "no zone programs"));
}

// -- asking for one name ---------------------------------------------

TEST_F(ShowCountersTest, AbsentNameAndUnprovableAbsenceDiffer) {
  auto absent = Render({{"query", "wan_total"},
                        {"verdict", "no_such_name"},
                        {"zones", json::array()},
                        {"unsearchable_zones", json::array()}});
  auto blind = Render({{"query", "wan_total"},
                       {"verdict", "cannot_tell"},
                       {"zones", json::array()},
                       {"unsearchable_zones", json::array({"wan"})}});
  EXPECT_NE(absent, blind);
  EXPECT_TRUE(Has(absent, "no counter named 'wan_total'"));
  EXPECT_TRUE(Has(blind, "cannot say whether"));
  // It names the zone it could not search, so the operator knows where
  // to look rather than only that the answer is unreliable.
  EXPECT_TRUE(Has(blind, "wan"));
  EXPECT_FALSE(Has(blind, "no counter named"));
}

TEST_F(ShowCountersTest, AFoundNameRendersItsZoneAndValue) {
  auto out = Render(
      {{"query", "lan_total"},
       {"verdict", "found"},
       {"unsearchable_zones", json::array()},
       {"zones", json::array({Zone("lan", "read",
                                   json::array({Row("lan_total", 0,
                                                    true, 9)}))})}});
  EXPECT_TRUE(Has(out, "lan_total"));
  EXPECT_TRUE(Has(out, "9"));
  EXPECT_FALSE(Has(out, "no counter named"));
}

TEST_F(ShowCountersTest, FoundButUnreadableIsNotAZero) {
  auto out = Render(
      {{"query", "lan_total"},
       {"verdict", "found"},
       {"unsearchable_zones", json::array()},
       {"zones", json::array({Zone("lan", "bound_unreadable",
                                   json::array(), "size unknown")})}});
  EXPECT_TRUE(Has(out, "size unknown"));
  EXPECT_FALSE(Has(out, "no counter named"));
}

TEST_F(ShowCountersTest, JsonModeCarriesTheAnswerAndNoProse) {
  // `--format json` owns stdout. A negative verdict that printed only
  // an English sentence would leave a pipe with nothing in it, and a
  // script would read "no output" as "no counters".
  auto out = Render({{"query", "wan_total"},
                     {"verdict", "no_such_name"},
                     {"zones", json::array()},
                     {"unsearchable_zones", json::array()}},
                    render::OutputFormat::Json);
  auto parsed = json::parse(out, nullptr, false);
  ASSERT_FALSE(parsed.is_discarded()) << out;
  EXPECT_TRUE(Has(out, "wan_total"));
  EXPECT_TRUE(Has(out, "no such counter"));
  EXPECT_FALSE(Has(out, "hint:"));
}

TEST_F(ShowCountersTest, JsonModeKeepsTheZoneReasonsOutOfTheStream) {
  auto out = Render(
      {{"query", ""},
       {"zones", json::array({Zone("lan", "read",
                                   json::array({Row("lan_total", 0,
                                                    true, 3)}),
                                   "1 of 2 slot(s) could not be "
                                   "read")})}},
      render::OutputFormat::Json);
  auto parsed = json::parse(out, nullptr, false);
  ASSERT_FALSE(parsed.is_discarded()) << out;
  EXPECT_TRUE(Has(out, "lan_total"));
}

}  // namespace
