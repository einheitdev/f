/// @file test_ui_pages.cc
/// @brief The counters and policy fragments, rendered.
///
/// `test_ui_views.cc` proves the view model keeps the four kinds of
/// empty apart. This proves the PAGE does — the two are different
/// claims, and the second is the one an operator sees. A template that
/// draws `none_declared`, `table_unreadable` and `table_map_mismatch`
/// as the same blank row would pass every test in the other file while
/// putting back exactly the screen this work exists to replace.
///
/// These render the real `.inja` files off disk with the real engine.

#include <set>
#include <string>

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include "adapters/fw/views.h"
#include "einheit/ui/render/template_engine.h"

namespace einheit::adapters::fw {
namespace {

using json = nlohmann::json;

auto Engine() -> ui::render::TemplateEngine {
  ui::render::TemplateEngineConfig cfg;
  cfg.search_paths = {FW_TEMPLATES_DIR};
  return ui::render::TemplateEngine(std::move(cfg));
}

auto RenderFragment(const std::string& name, const json& ctx)
    -> std::string {
  auto eng = Engine();
  auto r = eng.Render(name, ctx);
  EXPECT_TRUE(r.has_value())
      << "render failed: "
      << (r.has_value() ? std::string{} : r.error().message);
  return r.value_or(std::string{});
}

auto Ok(json body) -> FdAnswer {
  FdAnswer a;
  a.ok = true;
  a.body = std::move(body);
  return a;
}

auto Zone(const std::string& name, const std::string& availability,
          json counters = json::array()) -> json {
  return {{"zone", name},
          {"availability", availability},
          {"detail", ""},
          {"map_slots", 64},
          {"counters", std::move(counters)}};
}

auto Counter(const std::string& name, bool read, uint64_t packets)
    -> json {
  return {{"name", name},
          {"slot", 0},
          {"read", read},
          {"packets", packets}};
}

/// Render the counters fragment for one zone in one availability.
auto PageFor(const std::string& availability,
             json counters = json::array()) -> std::string {
  return RenderFragment(
      "fw/counters_table",
      CountersView(Ok(json{
          {"zones", json::array({Zone("edge", availability,
                                      std::move(counters))})}})));
}

TEST(CountersPage, TheFourKindsOfEmptyAreFourDifferentPages) {
  // The whole point of the availability type, carried to the last
  // place it can be lost. If any two of these render identically an
  // operator cannot tell a quiet firewall from a blind one.
  std::set<std::string> pages;
  for (const char* state :
       {"none_declared", "table_unreadable", "map_missing",
        "bound_unreadable", "table_map_mismatch"}) {
    auto html = PageFor(state);
    EXPECT_FALSE(html.empty());
    EXPECT_TRUE(pages.insert(html).second)
        << state << " renders identically to another state";
  }
  auto read = PageFor("read", json::array({Counter("hits", true, 3)}));
  EXPECT_TRUE(pages.insert(read).second);
}

TEST(CountersPage, EachStateWordSurvivesIntoTheHtml) {
  EXPECT_NE(PageFor("table_unreadable").find("names unknown"),
            std::string::npos);
  EXPECT_NE(PageFor("none_declared").find("no count statements"),
            std::string::npos);
  EXPECT_NE(PageFor("table_map_mismatch").find("stale table"),
            std::string::npos);
  EXPECT_NE(PageFor("map_missing").find("no counter map"),
            std::string::npos);
}

TEST(CountersPage, AZoneThatCouldNotBeReadIsStillOnThePage) {
  auto html = PageFor("table_unreadable");
  EXPECT_NE(html.find("edge"), std::string::npos);
}

TEST(CountersPage, AnUnreadableSlotIsAWordAndAZeroIsANumber) {
  auto html = RenderFragment(
      "fw/counters_table",
      CountersView(Ok(json{
          {"zones",
           json::array({Zone("edge", "read",
                             json::array({Counter("quiet", true, 0),
                                          Counter("broken", false,
                                                  0)}))})}})));
  EXPECT_NE(html.find("unreadable"), std::string::npos);
  EXPECT_NE(html.find("quiet"), std::string::npos);
  // The zero row and the unreadable row are both drawn, and only one
  // of them carries a number.
  EXPECT_NE(html.find(">0<"), std::string::npos);
}

TEST(CountersPage, FdBeingDownIsNotAnEmptyTable) {
  FdAnswer down;
  down.error = "fd is not answering";
  auto html = RenderFragment("fw/counters_table", CountersView(down));
  EXPECT_NE(html.find("fd is not answering"), std::string::npos);
  EXPECT_EQ(html.find("<table"), std::string::npos);
  // And it does not read like a box with no counters on it.
  EXPECT_EQ(html.find("no count statements"), std::string::npos);
}

TEST(CountersPage, CountsLandUnderTheirOwnNames) {
  auto html = RenderFragment(
      "fw/counters_table",
      CountersView(Ok(json{
          {"zones",
           json::array({Zone("edge", "read",
                             json::array({Counter("edge_probe", true,
                                                  7),
                                          Counter("edge_never", true,
                                                  0)}))})}})));
  auto probe = html.find("edge_probe");
  auto never = html.find("edge_never");
  ASSERT_NE(probe, std::string::npos);
  ASSERT_NE(never, std::string::npos);
  // 7 appears after edge_probe and before edge_never: the value sits
  // in its own name's row. A page that paired them by position would
  // put the 7 in the other row and look entirely plausible.
  auto seven = html.find(">7<", probe);
  ASSERT_NE(seven, std::string::npos);
  EXPECT_LT(seven, never);
}

TEST(CountersPage, FdsDetailIsPrintedRatherThanSwallowed) {
  json zone = Zone("edge", "table_map_mismatch");
  zone["detail"] = "edge.bpf.c names 'x' at slot 99";
  auto html = RenderFragment(
      "fw/counters_table",
      CountersView(Ok(json{{"zones", json::array({zone})}})));
  EXPECT_NE(html.find("slot 99"), std::string::npos);
}

TEST(PolicyPage, ADeadDaemonIsNotAPolicyWithNoZones) {
  FdAnswer down;
  down.error = "fd is not answering";
  auto html = RenderFragment(
      "fw/policy_table",
      PolicyView(down, Ok(json{{"zones", json::array()}})));
  EXPECT_NE(html.find("fd is not answering"), std::string::npos);
  EXPECT_EQ(html.find("<table"), std::string::npos);
}

TEST(PolicyPage, ZonesAndTheirCountedNamesReachTheHtml) {
  json topo = {{"zone", "edge"},
               {"interfaces", json::array({"eth0"})},
               {"attached", json::array({"eth0"})},
               {"attached_count", 1},
               {"xdp_mode", "native"},
               {"redirects_to", json::array({"lan"})},
               {"masquerades", true}};
  auto html = RenderFragment(
      "fw/policy_table",
      PolicyView(Ok(json::array({topo})),
                 Ok(json{{"zones",
                          json::array({Zone("edge", "read",
                                            json::array({Counter(
                                                "edge_probe", true,
                                                7)}))})}})));
  EXPECT_NE(html.find("edge_probe"), std::string::npos);
  EXPECT_NE(html.find("native"), std::string::npos);
  EXPECT_NE(html.find("lan"), std::string::npos);
}

TEST(PolicyPage, TheRuleGapIsStatedOnThePageItself) {
  // A page that shows zones and no rules, with nothing saying why,
  // reads as a policy that has no rules in it. The sentence is part of
  // the page, not part of a commit message.
  auto html = RenderFragment(
      "fw/policy",
      json{{"answered", true},
           {"unavailable", ""},
           {"zone_count", 0},
           {"zones", json::array()},
           {"empty_text", "nothing loaded"},
           {"features", json::array()}});
  EXPECT_NE(html.find("does not list the rules"), std::string::npos);
  EXPECT_NE(html.find("show policy"), std::string::npos);
}

TEST(DashboardPage, TheCountersRowIsAMeasurementAndSaysWhichKind) {
  auto row = [](const FdAnswer& a) {
    return RenderFragment(
        "fw/dashboard",
        json{{"daemon", {{"connected", true}}},
             {"iface_count", 1},
             {"attached_count", 1},
             {"datapath_armed", true},
             {"datapath_semantic", "good"},
             {"zone_count", 1},
             {"conntrack_count", 0},
             {"nat_count", 0},
             {"has_masq", false},
             {"masq_source", ""},
             {"counters", CountersSummary(a)}});
  };
  FdAnswer down;
  down.error = "fd is not answering";
  auto unreachable = row(down);
  auto measured = row(Ok(json{
      {"zones", json::array({Zone("edge", "read",
                                  json::array({Counter("hits", true,
                                                       1)}))})}}));
  EXPECT_NE(unreachable, measured);
  EXPECT_NE(unreachable.find("fd is not answering"),
            std::string::npos);
  EXPECT_NE(measured.find("1 named"), std::string::npos);
  // The badge it replaced was red on every box in every state. This
  // one is not red when the reading is fine.
  EXPECT_EQ(measured.find("badge-bad"), std::string::npos);
}

}  // namespace
}  // namespace einheit::adapters::fw
