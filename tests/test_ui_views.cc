/// @file test_ui_views.cc
/// @brief The web UI's judgement about fd's answers.
///
/// The defect these tests exist to prevent has shipped on this surface
/// once already, and it was invisible for months: `/counters` rendered
/// "no counters active" on every box ever deployed, including boxes
/// whose counters were moving, because the page drew its empty case
/// for a question it had never managed to ask. Nothing could catch it,
/// because the decision lived inside a Crow handler and there was
/// nothing to call.
///
/// So the rule under test throughout is: the FOUR kinds of empty stay
/// four, all the way into what the page renders. A test that cannot
/// tell "zero" from "could not ask" is the defect, not the check.

#include <string>

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include "adapters/fw/views.h"

namespace einheit::adapters::fw {
namespace {

using json = nlohmann::json;

auto Ok(json body) -> FdAnswer {
  FdAnswer a;
  a.ok = true;
  a.body = std::move(body);
  return a;
}

auto Failed(std::string why) -> FdAnswer {
  FdAnswer a;
  a.ok = false;
  a.error = std::move(why);
  return a;
}

/// One zone as fd puts it on the wire for opcode 12.
auto Zone(const std::string& name, const std::string& availability,
          json counters = json::array(),
          const std::string& detail = "") -> json {
  return {
      {"zone", name},
      {"availability", availability},
      {"detail", detail},
      {"map_slots", 64},
      {"counters", std::move(counters)},
  };
}

auto Counter(const std::string& name, uint32_t slot, bool read,
             uint64_t packets) -> json {
  return {{"name", name},
          {"slot", slot},
          {"read", read},
          {"packets", packets}};
}

// -- CountersView ----------------------------------------------------

TEST(CountersView, FdDownIsNotATableWithNoCountersInIt) {
  auto v = CountersView(Failed("fd is not answering"));
  EXPECT_FALSE(v["answered"].get<bool>());
  EXPECT_NE(v["unavailable"].get<std::string>().find(
                "fd is not answering"),
            std::string::npos);
  EXPECT_EQ(v["zones"].size(), 0u);
}

TEST(CountersView, APayloadWithNoZonesIsVersionSkewNotZeroCounters) {
  // An `fd` that predates opcode 12, or one whose reply shape drifted.
  // Rendering this as "no counters" is precisely the removed page's
  // failure: an answer that never arrived, drawn as a fact.
  auto v = CountersView(Ok(json{{"ok", true}}));
  EXPECT_FALSE(v["answered"].get<bool>());
  EXPECT_NE(v["unavailable"].get<std::string>().find("no zones"),
            std::string::npos);
}

TEST(CountersView, ZeroAndUnreadableAreDifferentOnThePage) {
  auto v = CountersView(Ok(json{
      {"zones", json::array({Zone("edge", "read",
                                  json::array({
                                      Counter("quiet_rule", 0, true, 0),
                                      Counter("broken", 1, false, 0),
                                  }))})}}));
  ASSERT_TRUE(v["answered"].get<bool>());
  const auto& rows = v["zones"][0]["rows"];
  ASSERT_EQ(rows.size(), 2u);
  EXPECT_EQ(rows[0]["value"].get<std::string>(), "0");
  EXPECT_EQ(rows[1]["value"].get<std::string>(), "unreadable");
  EXPECT_NE(rows[0]["value"].get<std::string>(),
            rows[1]["value"].get<std::string>());
  EXPECT_NE(rows[0]["value_semantic"].get<std::string>(),
            rows[1]["value_semantic"].get<std::string>());
}

TEST(CountersView, NamesTravelWithTheirOwnValues) {
  // The kGetRules defect in its UI form: pair by position and every
  // number is attributed to the wrong rule and looks entirely
  // plausible. The names are on the wire beside the values, and this
  // asserts the page keeps them together.
  auto v = CountersView(Ok(json{
      {"zones", json::array({Zone("edge", "read",
                                  json::array({
                                      Counter("edge_probe", 0, true, 7),
                                      Counter("edge_never", 1, true, 0),
                                  }))})}}));
  const auto& rows = v["zones"][0]["rows"];
  ASSERT_EQ(rows.size(), 2u);
  EXPECT_EQ(rows[0]["name"].get<std::string>(), "edge_probe");
  EXPECT_EQ(rows[0]["value"].get<std::string>(), "7");
  EXPECT_EQ(rows[1]["name"].get<std::string>(), "edge_never");
  EXPECT_EQ(rows[1]["value"].get<std::string>(), "0");
}

TEST(CountersView, EveryAvailabilityRendersAsItsOwnWord) {
  json zones = json::array({
      Zone("a", "read", json::array({Counter("c", 0, true, 1)})),
      Zone("b", "none_declared"),
      Zone("c", "table_unreadable"),
      Zone("d", "map_missing"),
      Zone("e", "bound_unreadable"),
      Zone("f", "table_map_mismatch"),
      Zone("g", "a_state_this_build_has_never_heard_of"),
  });
  auto v = CountersView(Ok(json{{"zones", zones}}));
  ASSERT_EQ(v["zones"].size(), 7u);
  std::vector<std::string> words;
  for (const auto& z : v["zones"]) {
    auto w = z["state_word"].get<std::string>();
    EXPECT_FALSE(w.empty());
    for (const auto& seen : words) {
      EXPECT_NE(w, seen)
          << "two availabilities render as the same word: " << w;
    }
    words.push_back(w);
  }
  // And the words are the CLI's words, character for character. An
  // operator who reads "names unknown" in the terminal must not find
  // the same zone described some other way on the screen.
  EXPECT_EQ(v["zones"][1]["state_word"].get<std::string>(),
            "no count statements");
  EXPECT_EQ(v["zones"][2]["state_word"].get<std::string>(),
            "names unknown");
  EXPECT_EQ(v["zones"][3]["state_word"].get<std::string>(),
            "no counter map");
  EXPECT_EQ(v["zones"][4]["state_word"].get<std::string>(),
            "size unknown");
  EXPECT_EQ(v["zones"][5]["state_word"].get<std::string>(),
            "stale table");
  EXPECT_EQ(v["zones"][6]["state_word"].get<std::string>(),
            "unknown state");
}

TEST(CountersView, NoneDeclaredAndUnreadableAreNotTheSameEmpty) {
  auto v = CountersView(Ok(json{
      {"zones", json::array({Zone("quiet", "none_declared"),
                             Zone("blind", "table_unreadable",
                                  json::array(),
                                  "removed the generated C")})}}));
  const auto& quiet = v["zones"][0];
  const auto& blind = v["zones"][1];
  EXPECT_NE(quiet["state_word"].get<std::string>(),
            blind["state_word"].get<std::string>());
  // One is a fact about the policy and one is a fault on the box, and
  // the page has to be able to show that difference at a glance.
  EXPECT_NE(quiet["state_semantic"].get<std::string>(),
            blind["state_semantic"].get<std::string>());
  EXPECT_EQ(blind["state_semantic"].get<std::string>(), "bad");
}

TEST(CountersView, AZoneThatCouldNotBeReadStillOccupiesARow) {
  auto v = CountersView(Ok(json{
      {"zones",
       json::array({Zone("edge", "read",
                         json::array({Counter("hits", 0, true, 3)})),
                    Zone("blind", "table_unreadable")})}}));
  ASSERT_EQ(v["zones"].size(), 2u);
  EXPECT_TRUE(v["zones"][0]["has_rows"].get<bool>());
  EXPECT_FALSE(v["zones"][1]["has_rows"].get<bool>());
  EXPECT_EQ(v["zones"][1]["zone"].get<std::string>(), "blind");
}

TEST(CountersView, ReadWithNothingInItSaysSoRatherThanDrawingABlank) {
  auto v = CountersView(
      Ok(json{{"zones", json::array({Zone("edge", "read")})}}));
  EXPECT_EQ(v["zones"][0]["state_word"].get<std::string>(),
            "read, but no counters returned");
  EXPECT_EQ(v["zones"][0]["state_semantic"].get<std::string>(), "bad");
}

TEST(CountersView, FdsOwnDetailReachesThePage) {
  auto v = CountersView(Ok(json{
      {"zones", json::array({Zone("edge", "table_map_mismatch",
                                  json::array(),
                                  "edge.bpf.c names 'x' at slot 99")})}}));
  ASSERT_EQ(v["notes"].size(), 1u);
  EXPECT_NE(v["notes"][0].get<std::string>().find("slot 99"),
            std::string::npos);
  EXPECT_NE(v["notes"][0].get<std::string>().find("edge"),
            std::string::npos);
}

TEST(CountersView, NoZoneProgramsIsItsOwnSentence) {
  auto v = CountersView(Ok(json{{"zones", json::array()}}));
  EXPECT_TRUE(v["answered"].get<bool>());
  EXPECT_EQ(v["zone_count"].get<size_t>(), 0u);
  EXPECT_FALSE(v["empty_text"].get<std::string>().empty());
}

// -- CountersSummary (the dashboard row) -----------------------------

TEST(CountersSummary, AnUnreachableDaemonIsNotZeroCounters) {
  auto s = CountersSummary(Failed("connection refused"));
  EXPECT_FALSE(s["known"].get<bool>());
  EXPECT_EQ(s["semantic"].get<std::string>(), "bad");
  EXPECT_NE(s["text"].get<std::string>().find("connection refused"),
            std::string::npos);
}

TEST(CountersSummary, ItCountsWhatWasRead) {
  auto s = CountersSummary(Ok(json{
      {"zones",
       json::array({Zone("edge", "read",
                         json::array({Counter("a", 0, true, 1),
                                      Counter("b", 1, true, 0)})),
                    Zone("quiet", "none_declared")})}}));
  EXPECT_TRUE(s["known"].get<bool>());
  EXPECT_NE(s["text"].get<std::string>().find("2 named"),
            std::string::npos);
  EXPECT_EQ(s["semantic"].get<std::string>(), "good");
}

TEST(CountersSummary, AnUnreadableZoneIsNamedAndNotAveragedAway) {
  // The failure this row must not have: a box whose only counted zone
  // went unreadable reading as a box that simply counts nothing.
  auto s = CountersSummary(Ok(json{
      {"zones", json::array({Zone("edge", "table_unreadable"),
                             Zone("quiet", "none_declared")})}}));
  EXPECT_EQ(s["semantic"].get<std::string>(), "bad");
  EXPECT_NE(s["text"].get<std::string>().find("edge"),
            std::string::npos);
  EXPECT_NE(s["text"].get<std::string>().find("unreadable"),
            std::string::npos);
}

TEST(CountersSummary, APolicyThatDeclaresNothingIsNotAFault) {
  auto s = CountersSummary(
      Ok(json{{"zones", json::array({Zone("quiet", "none_declared")})}}));
  EXPECT_EQ(s["semantic"].get<std::string>(), "info");
}

// -- PolicyView ------------------------------------------------------

auto ZoneTopology(const std::string& name) -> json {
  return {
      {"zone", name},
      {"interfaces", json::array({name + "0"})},
      {"attached", json::array({name + "0"})},
      {"attached_count", 1},
      {"xdp_mode", "native"},
      {"redirects_to", json::array()},
      {"masquerades", false},
  };
}

TEST(PolicyView, AnUnreachableDaemonIsNotAPolicyWithNoZones) {
  auto v = PolicyView(Failed("fd is not answering"),
                      Ok(json{{"zones", json::array()}}));
  EXPECT_FALSE(v["answered"].get<bool>());
  EXPECT_NE(v["unavailable"].get<std::string>().find(
                "fd is not answering"),
            std::string::npos);
  EXPECT_EQ(v["zones"].size(), 0u);
}

TEST(PolicyView, ZeroZonesLoadedIsSaidOutLoud) {
  auto v = PolicyView(Ok(json::array()),
                      Ok(json{{"zones", json::array()}}));
  EXPECT_TRUE(v["answered"].get<bool>());
  EXPECT_NE(v["empty_text"].get<std::string>().find("packet path"),
            std::string::npos);
}

TEST(PolicyView, EachZoneShowsTheCountersItsLoadedPolicyDeclares) {
  auto v = PolicyView(
      Ok(json::array({ZoneTopology("edge")})),
      Ok(json{{"zones",
               json::array({Zone("edge", "read",
                                 json::array({
                                     Counter("edge_probe", 0, true, 7),
                                     Counter("edge_never", 1, true, 0),
                                 }))})}}));
  ASSERT_EQ(v["zones"].size(), 1u);
  EXPECT_EQ(v["zones"][0]["counts_str"].get<std::string>(),
            "edge_probe, edge_never");
}

TEST(PolicyView, UnreadableCountsDoNotReadAsNoCounts) {
  auto declared_none = PolicyView(
      Ok(json::array({ZoneTopology("quiet")})),
      Ok(json{{"zones", json::array({Zone("quiet", "none_declared")})}}));
  auto unreadable = PolicyView(
      Ok(json::array({ZoneTopology("quiet")})),
      Ok(json{
          {"zones", json::array({Zone("quiet", "table_unreadable")})}}));
  EXPECT_NE(declared_none["zones"][0]["counts_str"].get<std::string>(),
            unreadable["zones"][0]["counts_str"].get<std::string>());
  EXPECT_EQ(unreadable["zones"][0]["counts_semantic"].get<std::string>(),
            "bad");
}

TEST(PolicyView, AZoneTheCounterAnswerDoesNotMentionIsAFinding) {
  // Two answers from one daemon disagreeing about which zones are
  // loaded is a fault, not a zone that counts nothing.
  auto v = PolicyView(Ok(json::array({ZoneTopology("edge")})),
                      Ok(json{{"zones", json::array()}}));
  EXPECT_EQ(v["zones"][0]["counts_str"].get<std::string>(),
            "not reported by fd");
  EXPECT_EQ(v["zones"][0]["counts_semantic"].get<std::string>(), "bad");
}

TEST(PolicyView, ACounterQueryThatFailedDoesNotBlankTheColumn) {
  auto v = PolicyView(Ok(json::array({ZoneTopology("edge")})),
                      Failed("fd is not answering"));
  EXPECT_TRUE(v["answered"].get<bool>());
  EXPECT_EQ(v["zones"][0]["counts_str"].get<std::string>(),
            "cannot read from fd");
  EXPECT_EQ(v["zones"][0]["counts_semantic"].get<std::string>(), "bad");
}

TEST(PolicyView, TopologyIsCarriedThroughFromTheDaemon) {
  auto topo = ZoneTopology("edge");
  topo["masquerades"] = true;
  topo["redirects_to"] = json::array({"lan"});
  topo["attached"] = json::array();
  topo["attached_count"] = 0;
  auto v = PolicyView(Ok(json::array({topo})),
                      Ok(json{{"zones", json::array()}}));
  EXPECT_EQ(v["zones"][0]["masq_str"].get<std::string>(), "yes");
  EXPECT_EQ(v["zones"][0]["redirects_str"].get<std::string>(), "lan");
  // A zone attached to nothing is the state this whole column exists
  // for; it must not read as a healthy zone.
  EXPECT_EQ(v["zones"][0]["attached_str"].get<std::string>(), "(none)");
  EXPECT_EQ(v["zones"][0]["attach_semantic"].get<std::string>(), "warn");
}

// -- PolicyFeatures --------------------------------------------------

TEST(PolicyFeatures, AnUnreachableDaemonAnswersNeitherQuestion) {
  auto f = PolicyFeatures(Failed("fd is not answering"));
  ASSERT_EQ(f.size(), 2u);
  for (const auto& row : f) {
    EXPECT_EQ(row["semantic"].get<std::string>(), "bad");
    EXPECT_NE(row["value"].get<std::string>().find("fd is not "
                                                   "answering"),
              std::string::npos);
  }
}

/// One `egress` section in the shape fd really sends it.
///
/// `attached` is a COUNT — `EgressMgr::AttachedNow()`, a live query of
/// the kernel — and `interfaces` is the name list. Reading `attached`
/// as a list is not a harmless mistake: it comes back empty, and this
/// page then tells the operator that the tracker his policy needs is
/// on no interface at all. It did exactly that on deb-03, on a box
/// whose `fctl status` said `"attached":2`.
auto Egress(bool declared, bool predates, size_t attached,
            json interfaces) -> FdAnswer {
  return Ok(json{
      {"conntrack",
       {{"enabled", true}, {"entries", 1}, {"timeout_s", 60}}},
      {"egress",
       {{"tracker_declared", declared},
        {"bundle_predates_tracker", predates},
        {"attached", attached},
        {"interfaces", std::move(interfaces)}}}});
}

TEST(PolicyFeatures, TheEgressStatesAreFiveDifferentSentences) {
  auto both = json::array({"eth0", "eth1"});
  auto tracked = PolicyFeatures(Egress(true, false, 2, both))[1];
  auto partly = PolicyFeatures(Egress(true, false, 1, both))[1];
  auto detached = PolicyFeatures(Egress(true, false, 0, both))[1];
  auto old_bundle = PolicyFeatures(
      Egress(false, true, 0, json::array()))[1];
  auto not_needed = PolicyFeatures(
      Egress(false, false, 0, json::array()))[1];
  std::vector<std::string> values{
      tracked["value"].get<std::string>(),
      partly["value"].get<std::string>(),
      detached["value"].get<std::string>(),
      old_bundle["value"].get<std::string>(),
      not_needed["value"].get<std::string>()};
  for (size_t i = 0; i < values.size(); i++) {
    for (size_t k = i + 1; k < values.size(); k++) {
      EXPECT_NE(values[i], values[k]);
    }
  }
  EXPECT_EQ(tracked["semantic"].get<std::string>(), "good");
  EXPECT_NE(tracked["value"].get<std::string>().find("eth0"),
            std::string::npos);
  // A policy that reads conntrack on a bundle with no egress hook is
  // the box whose own DNS replies read as NEW.
  EXPECT_EQ(old_bundle["semantic"].get<std::string>(), "bad");
  EXPECT_EQ(detached["semantic"].get<std::string>(), "bad");
  EXPECT_EQ(partly["semantic"].get<std::string>(), "bad");
  EXPECT_EQ(not_needed["semantic"].get<std::string>(), "info");
}

TEST(PolicyFeatures, AnAttachedTrackerIsNotReportedAsMissing) {
  // The regression, pinned in the daemon's own words: this is the
  // `egress` object `fctl status` printed on deb-03 while the tracker
  // was attached to both interfaces, and the page said "DECLARED AND
  // NOT ATTACHED".
  auto status = Ok(json::parse(R"({
    "conntrack": {"enabled": true, "entries": 0, "timeout_s": 300},
    "egress": {"attached": 2, "bundle_predates_tracker": false,
               "enabled": true, "interfaces": ["fwan0", "flan0"],
               "tracker_declared": true, "seen": 3, "tracked": 0}
  })"));
  auto row = PolicyFeatures(status)[1];
  EXPECT_EQ(row["semantic"].get<std::string>(), "good");
  EXPECT_EQ(row["value"].get<std::string>(),
            "tracked on fwan0, flan0");
}

TEST(PolicyFeatures, AnEgressSectionOfTheWrongShapeDoesNotThrow) {
  // A daemon a version away must not take the page down, and must not
  // be answered with a confident sentence either.
  auto status = Ok(json{
      {"conntrack", {{"enabled", false}}},
      {"egress", {{"tracker_declared", true},
                  {"attached", json::array({"eth0"})},
                  {"interfaces", "eth0"}}}});
  auto rows = PolicyFeatures(status);
  ASSERT_EQ(rows.size(), 2u);
  EXPECT_EQ(rows[1]["semantic"].get<std::string>(), "bad");
}

TEST(PolicyFeatures, ConntrackReportsWhatTheDaemonMeasured) {
  auto f = PolicyFeatures(Ok(json{
      {"conntrack",
       {{"enabled", true}, {"entries", 12}, {"timeout_s", 30}}},
      {"egress", {{"tracker_declared", false},
                  {"bundle_predates_tracker", false},
                  {"attached", json::array()}}}}));
  EXPECT_NE(f[0]["value"].get<std::string>().find("12"),
            std::string::npos);
  EXPECT_NE(f[0]["value"].get<std::string>().find("30"),
            std::string::npos);
}

// -- the shared helpers the pages lean on ----------------------------

TEST(UnavailableTextTest, AnErrorNeverReadsAsAnEmptyTable) {
  FdAnswer down = Failed("no such file or directory");
  auto text = UnavailableText(down, "no active translations");
  EXPECT_NE(text, "no active translations");
  EXPECT_NE(text.find("no such file"), std::string::npos);
  EXPECT_EQ(UnavailableText(Ok(json::array()), "no translations"),
            "no translations");
}

TEST(JoinArrTest, NonStringsAreSkippedRatherThanThrowing) {
  // A daemon whose reply shape drifted must not take the page down.
  EXPECT_EQ(JoinArr(json::array({"a", 7, "b"})), "a, b");
  EXPECT_EQ(JoinArr(json("not an array")), "");
}

}  // namespace
}  // namespace einheit::adapters::fw
