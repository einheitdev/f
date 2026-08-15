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

/// fd's opcode-13 reply for one zone with one guarded drop rule.
auto RulesBody(const std::string& zone, const std::string& avail,
               json rules, json def = nullptr) -> json {
  return {{"zones", json::array({json{
               {"zone", zone},
               {"availability", avail},
               {"detail", ""},
               {"rules", std::move(rules)},
               {"default", std::move(def)},
               {"stage_boundaries", json::array()}}})},
          {"source",
           {{"known", true},
            {"name", "office.fw"},
            {"path", "/etc/f/office.fw"},
            {"sha256", std::string(64, 'a')},
            {"bytes", 42}}}};
}

auto Rule(const std::string& action, const std::string& match,
          bool guarded) -> json {
  return {{"log_rule_index", 0}, {"line", 5},   {"action", action},
          {"match", match},      {"text", ""},  {"rate_limit", ""},
          {"guarded", guarded},  {"terminal", true},
          {"renderable", true}};
}

TEST(PolicyPage, TheRulesAreOnThePageNow) {
  // The card this replaces said the rules could not be shown, and it
  // was true: the bundle carried no rule metadata. It does now, and a
  // page that still explained the gap would be documenting a hole
  // that has been filled.
  auto html = RenderFragment(
      "fw/policy",
      json{{"answered", true},
           {"unavailable", ""},
           {"zone_count", 0},
           {"zones", json::array()},
           {"empty_text", "nothing loaded"},
           {"features", json::array()},
           {"rules",
            PolicyRulesView(Ok(RulesBody(
                "edge", "listed",
                json::array({Rule("drop",
                                  "pkt.proto == tcp and "
                                  "pkt.dst_port == 22",
                                  true)}),
                json{{"action", "drop"}, {"line", 9},
                     {"stated", true}})))}});
  EXPECT_NE(html.find("pkt.dst_port == 22"), std::string::npos);
  EXPECT_NE(html.find("edge"), std::string::npos);
  EXPECT_NE(html.find("default drop"), std::string::npos);
  // The digest of the text this policy was compiled from, on the page,
  // so it can be checked against the file without leaving the screen.
  EXPECT_NE(html.find("office.fw"), std::string::npos);
}

TEST(PolicyPage, TheFiveRuleStatesRenderAsFiveDifferentPages) {
  // The whole reason fd distinguishes them. A page that drew a bundle
  // with no rule metadata the same way as a policy with no rules would
  // show a working firewall as an empty one on every box upgraded
  // across this change.
  auto page = [](const std::string& avail) {
    return RenderFragment(
        "fw/policy_rules",
        json{{"rules", PolicyRulesView(Ok(RulesBody(
                           "edge", avail, json::array())))}});
  };
  std::vector<std::string> pages = {
      page("listed"), page("none_declared"), page("function_form"),
      page("not_emitted"), page("something_new")};
  for (size_t i = 0; i < pages.size(); ++i) {
    for (size_t j = i + 1; j < pages.size(); ++j) {
      EXPECT_NE(pages[i], pages[j])
          << "two rule states render identically";
    }
  }
}

TEST(PolicyPage, AnUnaskableDaemonIsNotAPolicyWithNoRules) {
  FdAnswer down;
  down.ok = false;
  down.error = "fd is not running";
  auto html = RenderFragment(
      "fw/policy_rules", json{{"rules", PolicyRulesView(down)}});
  EXPECT_NE(html.find("fd is not running"), std::string::npos);
  // No table at all — an empty one is a claim that there is nothing
  // to show.
  EXPECT_EQ(html.find("<table"), std::string::npos);
}

TEST(PolicyPage, AnUnguardedRuleSaysSoRatherThanShowingABlank) {
  auto html = RenderFragment(
      "fw/policy_rules",
      json{{"rules",
            PolicyRulesView(Ok(RulesBody(
                "edge", "listed",
                json::array({Rule("drop", "", false)}))))}});
  // "matches everything" and "we have no match to show" must not be
  // the same empty cell.
  EXPECT_NE(html.find("every packet"), std::string::npos);
  EXPECT_NE(html.find("stops here"), std::string::npos);
}

TEST(PolicyPage, AnUnstatedDefaultNamesTheFallThrough) {
  auto html = RenderFragment(
      "fw/policy_rules",
      json{{"rules",
            PolicyRulesView(Ok(RulesBody(
                "edge", "listed", json::array({Rule("drop", "", true)}),
                json{{"action", "allow"}, {"line", 0},
                     {"stated", false}})))}});
  EXPECT_NE(html.find("falls through to ALLOW"), std::string::npos);
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
