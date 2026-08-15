/// @file test_rules.cc
/// @brief The loaded policy's rules: capture, states, drift, wire.
///
/// Two things are on trial here. The first is that the five kinds of
/// "no rules to show" stay five all the way to the wire and back — a
/// bundle that predates the metadata, a Tier 2 zone, a zone whose
/// policy really is only a default, a form this build has no reading
/// for, and a real list. The second is that a drift verdict is
/// three-valued: a box that cannot read the source must say so rather
/// than report a match or an edit it did not observe.

#include <optional>
#include <string>
#include <vector>

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include "f/rules.h"
#include "f/sha256.h"

using json = nlohmann::json;
using f::CompareSource;
using f::LoadedRule;
using f::ParsePolicySource;
using f::ParseRuleTable;
using f::PolicySource;
using f::PolicySourceFromJson;
using f::RuleAvailability;
using f::RuleAvailabilityFromName;
using f::RuleAvailabilityName;
using f::RuleStateWord;
using f::Sha256Hex;
using f::SourceDrift;
using f::ZoneRules;
using f::ZoneRulesFromJson;
using f::ZoneRulesToJson;

namespace {

/// A manifest `programs[]` entry with a two-rule policy.
auto TwoRuleEntry() -> json {
  return json{
      {"zone", "wan"},
      {"object", "wan.bpf.o"},
      {"source", "wan.bpf.c"},
      {"rules",
       {{"form", "rules"},
        {"detail", ""},
        {"default", {{"action", "drop"}, {"line", 9},
                     {"explicit", true}}},
        {"rules",
         json::array(
             {json{{"log_rule_index", 0},
                   {"line", 5},
                   {"action", "drop"},
                   {"match", "pkt.proto == tcp and pkt.dst_port == 22"},
                   {"text", "drop if pkt.proto == tcp and "
                            "pkt.dst_port == 22"},
                   {"rate_limit", ""},
                   {"guarded", true},
                   {"terminal", true},
                   {"renderable", true}},
              json{{"log_rule_index", 1},
                   {"line", 6},
                   {"action", "redirect to lan"},
                   {"match", ""},
                   {"text", "redirect to lan"},
                   {"rate_limit", ""},
                   {"guarded", false},
                   {"terminal", true},
                   {"renderable", true}}})}}}};
}

}  // namespace

// --- Capture from a manifest entry ----------------------------------

TEST(RulesCapture, ARuleListArrivesInPolicyOrder) {
  auto z = ParseRuleTable(TwoRuleEntry(), "wan");
  EXPECT_EQ(z.zone, "wan");
  EXPECT_EQ(z.availability, RuleAvailability::kListed);
  ASSERT_EQ(z.rules.size(), 2u);
  EXPECT_EQ(z.rules[0].action, "drop");
  EXPECT_EQ(z.rules[1].action, "redirect to lan");
  EXPECT_TRUE(z.rules[0].guarded);
  EXPECT_FALSE(z.rules[1].guarded);
  EXPECT_TRUE(z.rules[1].terminal);
}

TEST(RulesCapture, TheDefaultActionComesWithIt) {
  auto z = ParseRuleTable(TwoRuleEntry(), "wan");
  EXPECT_TRUE(z.default_action.known);
  EXPECT_EQ(z.default_action.action, "drop");
  EXPECT_TRUE(z.default_action.stated);
}

TEST(RulesCapture, AnUnstatedDefaultIsStillReported) {
  // A zone with no `default` line ALLOWS whatever reaches the end of
  // the block. A capture that lost `stated` would present the two as
  // the same policy.
  auto e = TwoRuleEntry();
  e["rules"]["default"] = json{{"action", "allow"}, {"line", 0},
                               {"explicit", false}};
  auto z = ParseRuleTable(e, "wan");
  EXPECT_TRUE(z.default_action.known);
  EXPECT_EQ(z.default_action.action, "allow");
  EXPECT_FALSE(z.default_action.stated);
}

TEST(RulesCapture, ABundleWithNoRuleMetadataCannotBeAsked) {
  // The state that matters most across an upgrade. A bundle compiled
  // by an older `fwl` has no `rules` key at all, and reporting that as
  // an empty rule list would show a working firewall as a firewall
  // with nothing in it.
  json old = {{"zone", "wan"}, {"object", "wan.bpf.o"}};
  auto z = ParseRuleTable(old, "wan");
  EXPECT_EQ(z.availability, RuleAvailability::kNotEmitted);
  EXPECT_TRUE(z.rules.empty());
  EXPECT_NE(z.detail.find("recompile"), std::string::npos);
}

TEST(RulesCapture, ANotEmittedBundleIsNotTheSameAsAnEmptyPolicy) {
  json old = {{"zone", "wan"}};
  json empty = {{"zone", "wan"},
                {"rules", {{"form", "rules"},
                           {"rules", json::array()},
                           {"default", {{"action", "drop"},
                                        {"line", 3},
                                        {"explicit", true}}}}}};
  auto a = ParseRuleTable(old, "wan");
  auto b = ParseRuleTable(empty, "wan");
  ASSERT_TRUE(a.rules.empty());
  ASSERT_TRUE(b.rules.empty());
  // Same empty list, opposite findings.
  EXPECT_NE(a.availability, b.availability);
  EXPECT_EQ(b.availability, RuleAvailability::kNoneDeclared);
  EXPECT_NE(RuleStateWord(a.availability),
            RuleStateWord(b.availability));
}

TEST(RulesCapture, ATierTwoZoneSaysItHasNoRuleList) {
  json fn = {{"zone", "wan"},
             {"rules", {{"form", "function"},
                        {"detail", "Tier 2 function `policy`"},
                        {"rules", json::array()},
                        {"default", nullptr}}}};
  auto z = ParseRuleTable(fn, "wan");
  EXPECT_EQ(z.availability, RuleAvailability::kFunctionForm);
  EXPECT_FALSE(z.default_action.known);
  EXPECT_NE(z.detail.find("Tier 2"), std::string::npos);
}

TEST(RulesCapture, AFormThisBuildCannotReadIsNotRenderedAnyway) {
  // Version skew in the other direction: a newer compiler describing a
  // zone's policy in a shape this build has no reading for. Showing
  // the array under it would be showing a list whose meaning is not
  // established.
  json future = {{"zone", "wan"},
                 {"rules", {{"form", "decision_tree"},
                            {"rules", json::array({json{
                                {"action", "allow"}}})}}}};
  auto z = ParseRuleTable(future, "wan");
  EXPECT_EQ(z.availability, RuleAvailability::kUnknown);
  EXPECT_TRUE(z.rules.empty());
  EXPECT_NE(z.detail.find("decision_tree"), std::string::npos);
}

TEST(RulesCapture, StageBoundariesSurviveAndTheLabelsAreNotInvented) {
  auto e = TwoRuleEntry();
  e["rules"]["stage_boundaries"] = json::array({1});
  e["rules"]["detail"] = "the `chain` labels are not reported";
  auto z = ParseRuleTable(e, "wan");
  ASSERT_EQ(z.stage_boundaries.size(), 1u);
  EXPECT_EQ(z.stage_boundaries[0], 1);
  EXPECT_EQ(z.rules.size(), 2u);
}

TEST(RulesCapture, AnUnrenderableMatchIsNeverPresentedAsNoMatch) {
  auto e = TwoRuleEntry();
  e["rules"]["rules"][0]["renderable"] = false;
  e["rules"]["rules"][0]["match"] = "";
  e["rules"]["rules"][0]["omitted"] =
      json::array({"no source form for a Martian node"});
  auto z = ParseRuleTable(e, "wan");
  EXPECT_FALSE(z.rules[0].renderable);
  // `guarded` is what stops an empty match reading as an unguarded
  // rule — the difference between "drop everything" and "drop
  // something we could not write down".
  EXPECT_TRUE(z.rules[0].guarded);
  ASSERT_EQ(z.rules[0].omitted.size(), 1u);
}

TEST(UnguardedWord, TerminalAndFallThroughAreDifferentSentences) {
  // One definition, three surfaces. An unguarded `drop` stops every
  // packet that reaches it; an unguarded `count` runs on every packet
  // and falls through. Spelling them the same way puts a warning
  // beside the one statement in the block that is harmless.
  EXPECT_NE(f::UnguardedMatchWord(true), f::UnguardedMatchWord(false));
  EXPECT_NE(f::UnguardedMatchWord(true).find("stops here"),
            std::string_view::npos);
  EXPECT_NE(f::UnguardedMatchWord(false).find("falls through"),
            std::string_view::npos);
  // And neither is empty, because an empty cell is how a guard nobody
  // could render would look.
  EXPECT_FALSE(f::UnguardedMatchWord(true).empty());
  EXPECT_FALSE(f::UnguardedMatchWord(false).empty());
}

// --- Availability vocabulary ----------------------------------------

TEST(RuleAvailabilityNames, EveryStateRoundTrips) {
  for (auto a : {RuleAvailability::kListed,
                 RuleAvailability::kNoneDeclared,
                 RuleAvailability::kFunctionForm,
                 RuleAvailability::kNotEmitted,
                 RuleAvailability::kUnknown}) {
    EXPECT_EQ(RuleAvailabilityFromName(RuleAvailabilityName(a)), a);
  }
}

TEST(RuleAvailabilityNames, AnUnknownTokenIsUnknownNotAGuess) {
  EXPECT_EQ(RuleAvailabilityFromName("something_new"),
            RuleAvailability::kUnknown);
  EXPECT_EQ(RuleAvailabilityFromName(""),
            RuleAvailability::kUnknown);
}

TEST(RuleAvailabilityNames, EveryStateHasItsOwnOperatorWord) {
  std::vector<std::string_view> words;
  for (auto a : {RuleAvailability::kListed,
                 RuleAvailability::kNoneDeclared,
                 RuleAvailability::kFunctionForm,
                 RuleAvailability::kNotEmitted,
                 RuleAvailability::kUnknown}) {
    words.push_back(RuleStateWord(a));
  }
  for (size_t i = 0; i < words.size(); ++i) {
    for (size_t j = i + 1; j < words.size(); ++j) {
      EXPECT_NE(words[i], words[j])
          << "two states spell the same on screen";
    }
  }
}

// --- The policy source and the drift verdict ------------------------

TEST(PolicySourceParse, AManifestWithNoSourceIsNotKnown) {
  EXPECT_FALSE(ParsePolicySource(json::object()).known);
  EXPECT_FALSE(ParsePolicySource(json{{"policy_source", nullptr}})
                   .known);
}

TEST(PolicySourceParse, ASourceWithNoDigestIsNotKnownEither) {
  // A recorded name with no digest cannot answer the question the
  // record exists for; treating it as known would make every
  // comparison against it a match against nothing.
  auto s = ParsePolicySource(
      json{{"policy_source", {{"name", "office.fw"}}}});
  EXPECT_FALSE(s.known);
}

TEST(PolicySourceParse, ADigestIsCarried) {
  auto s = ParsePolicySource(json{
      {"policy_source",
       {{"path", "/etc/f/office.fw"},
        {"name", "office.fw"},
        {"sha256", Sha256Hex("policy")},
        {"bytes", 6}}}});
  EXPECT_TRUE(s.known);
  EXPECT_EQ(s.name, "office.fw");
  EXPECT_EQ(s.sha256, Sha256Hex("policy"));
}

TEST(Drift, TheSameBytesAreAMatch) {
  PolicySource loaded;
  loaded.known = true;
  loaded.sha256 = Sha256Hex("zone lan = [v0]\n");
  auto c = CompareSource(loaded, Sha256Hex("zone lan = [v0]\n"),
                         "/etc/f/office.fw");
  EXPECT_EQ(c.verdict, SourceDrift::kMatch);
  EXPECT_NE(c.text.find("/etc/f/office.fw"), std::string::npos);
}

TEST(Drift, AnEditedFileIsDrift) {
  PolicySource loaded;
  loaded.known = true;
  loaded.sha256 = Sha256Hex("drop if pkt.dst_port == 22\n");
  auto c = CompareSource(loaded,
                         Sha256Hex("drop if pkt.dst_port == 23\n"),
                         "/etc/f/office.fw");
  EXPECT_EQ(c.verdict, SourceDrift::kDiffers);
  // The sentence has to say which policy the box is running, because
  // the rules on the screen beside it are the loaded ones.
  EXPECT_NE(c.text.find("OLDER"), std::string::npos);
}

TEST(Drift, AnUnreadableFileIsNeitherMatchNorDrift) {
  PolicySource loaded;
  loaded.known = true;
  loaded.sha256 = Sha256Hex("x");
  auto c = CompareSource(loaded, std::nullopt, "/etc/f/office.fw");
  EXPECT_EQ(c.verdict, SourceDrift::kCannotTell);
  EXPECT_NE(c.text.find("/etc/f/office.fw"), std::string::npos);
}

TEST(Drift, ABundleThatRecordsNoSourceCannotBeCompared) {
  PolicySource loaded;  // known == false
  auto c = CompareSource(loaded, Sha256Hex("anything"),
                         "/etc/f/office.fw");
  EXPECT_EQ(c.verdict, SourceDrift::kCannotTell);
  EXPECT_NE(c.text.find("recompile"), std::string::npos);
}

TEST(Drift, EveryVerdictHasItsOwnSentence) {
  PolicySource known;
  known.known = true;
  known.sha256 = Sha256Hex("a");
  PolicySource unknown;
  std::vector<std::string> texts = {
      CompareSource(known, Sha256Hex("a"), "/p").text,
      CompareSource(known, Sha256Hex("b"), "/p").text,
      CompareSource(known, std::nullopt, "/p").text,
      CompareSource(unknown, Sha256Hex("a"), "/p").text,
  };
  for (size_t i = 0; i < texts.size(); ++i) {
    for (size_t j = i + 1; j < texts.size(); ++j) {
      EXPECT_NE(texts[i], texts[j]);
    }
  }
}

// --- The wire shape -------------------------------------------------

TEST(RulesWire, ARuleListRoundTrips) {
  std::vector<ZoneRules> zones = {ParseRuleTable(TwoRuleEntry(),
                                                 "wan")};
  PolicySource src;
  src.known = true;
  src.path = "/etc/f/office.fw";
  src.name = "office.fw";
  src.sha256 = Sha256Hex("policy text");
  src.bytes = 11;

  auto wire = ZoneRulesToJson(zones, src);
  auto back = ZoneRulesFromJson(wire);
  ASSERT_EQ(back.size(), 1u);
  EXPECT_EQ(back[0].zone, "wan");
  EXPECT_EQ(back[0].availability, RuleAvailability::kListed);
  ASSERT_EQ(back[0].rules.size(), 2u);
  EXPECT_EQ(back[0].rules[0].text,
            "drop if pkt.proto == tcp and pkt.dst_port == 22");
  EXPECT_EQ(back[0].rules[1].action, "redirect to lan");
  EXPECT_TRUE(back[0].default_action.known);
  EXPECT_EQ(back[0].default_action.action, "drop");
  EXPECT_TRUE(back[0].default_action.stated);

  auto s = PolicySourceFromJson(wire);
  EXPECT_TRUE(s.known);
  EXPECT_EQ(s.sha256, src.sha256);
  EXPECT_EQ(s.name, "office.fw");
}

TEST(RulesWire, EveryAvailabilityStateSurvivesTheWire) {
  std::vector<ZoneRules> zones;
  for (auto a : {RuleAvailability::kListed,
                 RuleAvailability::kNoneDeclared,
                 RuleAvailability::kFunctionForm,
                 RuleAvailability::kNotEmitted,
                 RuleAvailability::kUnknown}) {
    ZoneRules z;
    z.zone = std::string(RuleAvailabilityName(a));
    z.availability = a;
    zones.push_back(z);
  }
  auto back = ZoneRulesFromJson(ZoneRulesToJson(zones, {}));
  ASSERT_EQ(back.size(), zones.size());
  for (size_t i = 0; i < zones.size(); ++i) {
    EXPECT_EQ(back[i].availability, zones[i].availability)
        << "state " << zones[i].zone << " did not survive the wire";
  }
}

TEST(RulesWire, APayloadWithNoAvailabilityIsUnknownNotListed) {
  // A daemon that answered with a rule array and no reason for it has
  // not established that the array is complete.
  json wire = {{"zones",
                json::array({json{{"zone", "wan"},
                                  {"rules", json::array()}}})}};
  auto back = ZoneRulesFromJson(wire);
  ASSERT_EQ(back.size(), 1u);
  EXPECT_EQ(back[0].availability, RuleAvailability::kUnknown);
}

TEST(RulesWire, AWrongShapedPayloadYieldsNoZonesRatherThanEmptyOnes) {
  EXPECT_TRUE(ZoneRulesFromJson(json::array()).empty());
  EXPECT_TRUE(ZoneRulesFromJson(json{{"error", "unknown command"}})
                  .empty());
  EXPECT_FALSE(PolicySourceFromJson(
                   json{{"error", "unknown command"}}).known);
}

TEST(RulesWire, AnUnknownSourceIsSaidToBeUnknownOnTheWire) {
  auto wire = ZoneRulesToJson({}, {});
  ASSERT_TRUE(wire.contains("source"));
  EXPECT_FALSE(wire["source"].value("known", true));
  // No digest is offered at all, so nothing downstream can compare
  // against an empty string and call it a match.
  EXPECT_FALSE(wire["source"].contains("sha256"));
}

// --- SHA-256 --------------------------------------------------------

TEST(Sha256, PublishedVectors) {
  EXPECT_EQ(Sha256Hex(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b"
            "7852b855");
  EXPECT_EQ(Sha256Hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61"
            "f20015ad");
  EXPECT_EQ(Sha256Hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlm"
                      "nomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd4"
            "19db06c1");
}

TEST(Sha256, BlockBoundaries) {
  // The tail path has two shapes — one padding block or two — and the
  // boundary is where an off-by-one lives. 55/56/63/64/65 bytes cover
  // both sides of it.
  EXPECT_EQ(Sha256Hex(std::string(55, 'a')),
            "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e91"
            "0f734318");
  EXPECT_EQ(Sha256Hex(std::string(56, 'a')),
            "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef797068"
            "6ec6738a");
  EXPECT_EQ(Sha256Hex(std::string(63, 'a')),
            "7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da45"
            "7ddc2f34");
  EXPECT_EQ(Sha256Hex(std::string(64, 'a')),
            "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df"
            "154668eb");
  EXPECT_EQ(Sha256Hex(std::string(65, 'a')),
            "635361c48bb9eab14198e76ea8ab7f1a41685d6ad62aa9146d301d4f"
            "17eb0ae0");
}

TEST(Sha256, AByteChangeChangesTheDigest) {
  EXPECT_NE(Sha256Hex("drop if pkt.dst_port == 22\n"),
            Sha256Hex("drop if pkt.dst_port == 23\n"));
  // Whitespace counts. An operator who reflowed the file has still
  // edited a policy that was never compiled.
  EXPECT_NE(Sha256Hex("allow\n"), Sha256Hex("allow \n"));
}
