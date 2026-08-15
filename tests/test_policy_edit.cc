/// @file test_policy_edit.cc
/// @brief Composing a policy without an editor.
///
/// The property that matters here is placement, not syntax. FWL's
/// `allow` is terminal and `masquerade` / `redirect` are
/// unconditional, so a rule appended to the end of a zone block is a
/// rule that can never match — and it would look exactly like a rule
/// that works, in the file and in every listing. A verb that appends
/// is worse than no verb at all, so the tests below are mostly about
/// where a statement lands and what the caller is told about it.
///
/// The fixture is the shape firstboot writes, because that is the
/// policy every box actually starts from.

#include <gtest/gtest.h>

#include <string>

#include "f/policy/edit.h"

namespace {

using f::policy::AddForward;
using f::policy::AddRule;
using f::policy::ForwardSpec;
using f::policy::ReadPolicy;
using f::policy::RemoveForward;
using f::policy::RemoveRule;
using f::policy::RuleSpec;
using f::policy::Verb;

constexpr const char* kPolicy = R"(# written by firstboot

zone wan = [wan0]
zone lan = [lan0]

@xdp(wan)

count wan_total

# Replies to flows this zone started.
allow if conntrack(pkt).state in [established, related]

# Reaching the box to configure it.
allow if pkt.proto == tcp and pkt.dst_port == 22

default drop

@xdp(lan)

count lan_total

# 1. Traffic addressed to THIS BOX is delivered to this box.
allow if pkt.proto == udp and pkt.dst_port == 67
allow if pkt.dst_ip == 10.10.0.1

# 3. Only what is left goes out.
count lan_out
masquerade
redirect to wan

default drop
)";

/// The statement at 1-based `index` in `zone`, or "<absent>".
auto At(const std::string& doc, const std::string& zone, int index)
    -> std::string {
  auto view = ReadPolicy(doc);
  for (const auto* s : view.InZone(zone)) {
    if (s->index == index) return s->text;
  }
  return "<absent>";
}

auto CountIn(const std::string& doc, const std::string& zone)
    -> std::size_t {
  return ReadPolicy(doc).InZone(zone).size();
}

// -- reading ---------------------------------------------------------

TEST(PolicyRead, FindsTheZoneBlocks) {
  auto view = ReadPolicy(kPolicy);
  ASSERT_EQ(view.zones.size(), 2u);
  EXPECT_EQ(view.zones[0], "wan");
  EXPECT_EQ(view.zones[1], "lan");
  EXPECT_EQ(view.declared.size(), 2u);
}

TEST(PolicyRead, NumbersStatementsPerBlock) {
  auto view = ReadPolicy(kPolicy);
  auto wan = view.InZone("wan");
  ASSERT_EQ(wan.size(), 4u);
  EXPECT_EQ(wan[0]->text, "count wan_total");
  EXPECT_EQ(wan[0]->index, 1);
  EXPECT_EQ(wan[3]->text, "default drop");
  EXPECT_EQ(wan[3]->index, 4);
  // Numbering restarts in the next block: `no rule lan 1` must not
  // mean the ninth statement of the file.
  auto lan = view.InZone("lan");
  ASSERT_FALSE(lan.empty());
  EXPECT_EQ(lan[0]->index, 1);
}

TEST(PolicyRead, TellsGuardedFromUnguarded) {
  auto view = ReadPolicy(kPolicy);
  auto lan = view.InZone("lan");
  for (const auto* s : lan) {
    if (s->text == "masquerade") {
      EXPECT_FALSE(s->guarded);
      EXPECT_EQ(s->verb, Verb::kTranslate);
    }
    if (s->text.starts_with("allow if pkt.proto == udp")) {
      EXPECT_TRUE(s->guarded);
      EXPECT_EQ(s->verb, Verb::kFilter);
    }
  }
}

// A statement spread over three lines is one statement, or every
// index after it is wrong and `no rule 7` deletes something else.
TEST(PolicyRead, FoldsContinuationLines) {
  const std::string doc =
      "@xdp(lan)\n"
      "drop if pkt.proto == udp\n"
      "       and (pkt.dst_port == 137\n"
      "       or pkt.dst_port == 138)\n"
      "default drop\n";
  auto view = ReadPolicy(doc);
  auto lan = view.InZone("lan");
  ASSERT_EQ(lan.size(), 2u);
  EXPECT_EQ(lan[0]->lines, 3);
  EXPECT_EQ(lan[0]->text,
            "drop if pkt.proto == udp and (pkt.dst_port == 137 "
            "or pkt.dst_port == 138)");
  EXPECT_EQ(lan[1]->text, "default drop");
}

// -- adding a rule ---------------------------------------------------

// The whole reason this module exists rather than a string append.
TEST(PolicyAdd, LandsBeforeTheFirstUnconditionalAction) {
  RuleSpec spec;
  spec.proto = "tcp";
  spec.port = 8080;
  auto out = AddRule(kPolicy, "lan", "allow", spec);
  ASSERT_TRUE(out.has_value()) << out.error();
  EXPECT_EQ(out->placement.before, "count lan_out")
      << "expected the placement to be reported against the "
         "statement it was put in front of";

  // And in the document: the new rule is above `masquerade`.
  auto view = ReadPolicy(out->document);
  int added = 0;
  int masq = 0;
  for (const auto* s : view.InZone("lan")) {
    if (s->text == "allow if pkt.proto == tcp and pkt.dst_port == 8080") {
      added = s->index;
    }
    if (s->text == "masquerade") masq = s->index;
  }
  ASSERT_GT(added, 0);
  ASSERT_GT(masq, 0);
  EXPECT_LT(added, masq)
      << "a rule after `masquerade` can never match";
}

// The reply has to be able to say "it went in front of this, and this
// is unconditional", because that is the sentence that tells an
// operator why it did not go where they expected.
TEST(PolicyAdd, ReportsWhenItLandedInFrontOfAnUnconditionalAction) {
  RuleSpec spec;
  spec.proto = "tcp";
  spec.port = 443;
  auto out = AddRule(kPolicy, "wan", "allow", spec);
  ASSERT_TRUE(out.has_value()) << out.error();
  EXPECT_EQ(out->placement.before, "default drop");
  EXPECT_TRUE(out->placement.before_is_unconditional);
}

TEST(PolicyAdd, LandsAtTheEndOfABlockWithNoUnconditionalAction) {
  const std::string doc =
      "@xdp(wan)\n"
      "allow if pkt.proto == icmp\n";
  RuleSpec spec;
  spec.proto = "tcp";
  spec.port = 443;
  auto out = AddRule(doc, "wan", "allow", spec);
  ASSERT_TRUE(out.has_value()) << out.error();
  EXPECT_TRUE(out->placement.before.empty());
  EXPECT_EQ(At(out->document, "wan", 2),
            "allow if pkt.proto == tcp and pkt.dst_port == 443");
}

TEST(PolicyAdd, GoesAboveTheCommentThatIntroducesTheBlockBelow) {
  RuleSpec spec;
  spec.proto = "tcp";
  spec.port = 8080;
  auto out = AddRule(kPolicy, "lan", "allow", spec);
  ASSERT_TRUE(out.has_value()) << out.error();
  auto added = out->document.find("dst_port == 8080");
  auto comment = out->document.find("# 3. Only what is left");
  ASSERT_NE(added, std::string::npos);
  ASSERT_NE(comment, std::string::npos);
  EXPECT_LT(added, comment)
      << "an insertion between a comment and the statement it "
         "explains leaves the file lying about itself";
}

TEST(PolicyAdd, RendersEveryTermOfASpec) {
  RuleSpec spec;
  spec.proto = "tcp";
  spec.from = "10.1.0.0/16";
  spec.to = "10.10.0.20";
  spec.port = 443;
  EXPECT_EQ(spec.Condition(),
            "pkt.proto == tcp and pkt.src_ip in 10.1.0.0/16 and "
            "pkt.dst_ip == 10.10.0.20 and pkt.dst_port == 443");
}

// A port with no protocol guard makes the program read whatever bytes
// sit at the port offset of a packet that has no ports. The compiler
// does not infer the guard, so neither does this.
TEST(PolicyAdd, RefusesAPortWithNoProtocol) {
  RuleSpec spec;
  spec.port = 443;
  auto out = AddRule(kPolicy, "lan", "allow", spec);
  ASSERT_FALSE(out.has_value());
  EXPECT_NE(out.error().find("protocol"), std::string::npos);
}

TEST(PolicyAdd, RefusesARuleWithNoCondition) {
  auto out = AddRule(kPolicy, "lan", "allow", RuleSpec{});
  ASSERT_FALSE(out.has_value());
  EXPECT_NE(out.error().find("default"), std::string::npos);
}

TEST(PolicyAdd, RefusesAnUnknownZoneAndNamesTheOnesThereAre) {
  RuleSpec spec;
  spec.proto = "icmp";
  auto out = AddRule(kPolicy, "dmz", "allow", spec);
  ASSERT_FALSE(out.has_value());
  EXPECT_NE(out.error().find("wan"), std::string::npos);
  EXPECT_NE(out.error().find("lan"), std::string::npos);
}

TEST(PolicyAdd, RefusesADuplicate) {
  RuleSpec spec;
  spec.proto = "tcp";
  spec.port = 22;
  auto out = AddRule(kPolicy, "wan", "allow", spec);
  ASSERT_FALSE(out.has_value());
  EXPECT_NE(out.error().find("already"), std::string::npos);
}

TEST(PolicyAdd, RefusesAnUnknownAction) {
  RuleSpec spec;
  spec.proto = "icmp";
  auto out = AddRule(kPolicy, "wan", "permit", spec);
  EXPECT_FALSE(out.has_value());
}

// -- removing --------------------------------------------------------

TEST(PolicyRemove, RemovesTheStatementItWasAskedFor) {
  auto before = CountIn(kPolicy, "wan");
  auto out = RemoveRule(kPolicy, "wan", 3);
  ASSERT_TRUE(out.has_value()) << out.error();
  ASSERT_EQ(out->removed.size(), 1u);
  EXPECT_EQ(out->removed[0],
            "allow if pkt.proto == tcp and pkt.dst_port == 22");
  EXPECT_EQ(CountIn(out->document, "wan"), before - 1);
  // The block that was not named is untouched.
  EXPECT_EQ(CountIn(out->document, "lan"), CountIn(kPolicy, "lan"));
}

TEST(PolicyRemove, RemovesEveryLineOfAMultiLineStatement) {
  const std::string doc =
      "@xdp(lan)\n"
      "drop if pkt.proto == udp\n"
      "       and pkt.dst_port == 137\n"
      "default drop\n";
  auto out = RemoveRule(doc, "lan", 1);
  ASSERT_TRUE(out.has_value()) << out.error();
  EXPECT_EQ(out->document.find("dst_port == 137"), std::string::npos)
      << "a continuation line left behind is a syntax error the "
         "operator did not write";
  EXPECT_EQ(CountIn(out->document, "lan"), 1u);
}

TEST(PolicyRemove, RefusesAnIndexTheBlockDoesNotHave) {
  auto out = RemoveRule(kPolicy, "wan", 99);
  ASSERT_FALSE(out.has_value());
  EXPECT_NE(out.error().find("4"), std::string::npos);
}

// An operator's prose is not ours to delete. An orphaned comment is a
// smaller problem than a missing explanation.
TEST(PolicyRemove, LeavesTheCommentAbove) {
  auto out = RemoveRule(kPolicy, "wan", 3);
  ASSERT_TRUE(out.has_value()) << out.error();
  EXPECT_NE(out->document.find("# Reaching the box to configure it."),
            std::string::npos);
}

// -- port forwards ---------------------------------------------------

TEST(PolicyForward, WritesBothHalvesWithTheSameGuard) {
  ForwardSpec spec;
  spec.proto = "tcp";
  spec.port = 80;
  spec.target_ip = "10.10.0.20";
  spec.target_port = 8080;
  spec.inside_zone = "lan";
  auto out = AddForward(kPolicy, "wan", spec);
  ASSERT_TRUE(out.has_value()) << out.error();

  auto view = ReadPolicy(out->document);
  const f::policy::Statement* dnat = nullptr;
  const f::policy::Statement* redir = nullptr;
  for (const auto* s : view.InZone("wan")) {
    if (s->verb == Verb::kTranslate) dnat = s;
    if (s->verb == Verb::kRedirect) redir = s;
  }
  ASSERT_NE(dnat, nullptr);
  ASSERT_NE(redir, nullptr);
  EXPECT_EQ(dnat->text,
            "dnat to 10.10.0.20:8080 if pkt.proto == tcp and "
            "pkt.dst_port == 80");
  EXPECT_EQ(redir->text,
            "redirect to lan if pkt.proto == tcp and "
            "pkt.dst_port == 80");
  // A redirect whose guard is wider than its dnat's is the documented
  // way to send untranslated frames into the inside zone.
  auto dg = dnat->text.substr(dnat->text.find(" if "));
  auto rg = redir->text.substr(redir->text.find(" if "));
  EXPECT_EQ(dg, rg);
  EXPECT_EQ(dnat->index + 1, redir->index);
}

TEST(PolicyForward, CarriesASourceRestrictionIntoBothHalves) {
  ForwardSpec spec;
  spec.proto = "tcp";
  spec.port = 80;
  spec.target_ip = "10.10.0.20";
  spec.target_port = 8080;
  spec.inside_zone = "lan";
  spec.from = "10.1.0.0/16";
  auto out = AddForward(kPolicy, "wan", spec);
  ASSERT_TRUE(out.has_value()) << out.error();
  auto view = ReadPolicy(out->document);
  int with_guard = 0;
  for (const auto* s : view.InZone("wan")) {
    if (s->text.find("pkt.src_ip in 10.1.0.0/16") !=
        std::string::npos) {
      ++with_guard;
    }
  }
  EXPECT_EQ(with_guard, 2);
}

TEST(PolicyForward, LandsAboveTheStatefulRule) {
  ForwardSpec spec;
  spec.proto = "tcp";
  spec.port = 80;
  spec.target_ip = "10.10.0.20";
  spec.target_port = 8080;
  spec.inside_zone = "lan";
  auto out = AddForward(kPolicy, "wan", spec);
  ASSERT_TRUE(out.has_value()) << out.error();
  auto view = ReadPolicy(out->document);
  int dnat = 0;
  int conntrack = 0;
  for (const auto* s : view.InZone("wan")) {
    if (s->verb == Verb::kTranslate) dnat = s->index;
    if (s->text.find("conntrack") != std::string::npos) {
      conntrack = s->index;
    }
  }
  ASSERT_GT(dnat, 0);
  ASSERT_GT(conntrack, 0);
  EXPECT_LT(dnat, conntrack);
}

TEST(PolicyForward, SaysItIsAHole) {
  ForwardSpec spec;
  spec.proto = "tcp";
  spec.port = 80;
  spec.target_ip = "10.10.0.20";
  spec.target_port = 8080;
  spec.inside_zone = "lan";
  auto out = AddForward(kPolicy, "wan", spec);
  ASSERT_TRUE(out.has_value()) << out.error();
  ASSERT_FALSE(out->warnings.empty());
  EXPECT_NE(out->warnings[0].find("hole"), std::string::npos);
}

TEST(PolicyForward, RefusesAnInsideZoneWithNoBlock) {
  ForwardSpec spec;
  spec.proto = "tcp";
  spec.port = 80;
  spec.target_ip = "10.20.0.20";
  spec.target_port = 8080;
  spec.inside_zone = "dmz";
  auto out = AddForward(kPolicy, "wan", spec);
  EXPECT_FALSE(out.has_value());
}

TEST(PolicyForward, RefusesForwardingIntoTheZoneItArrivesOn) {
  ForwardSpec spec;
  spec.proto = "tcp";
  spec.port = 80;
  spec.target_ip = "10.10.0.20";
  spec.target_port = 8080;
  spec.inside_zone = "wan";
  auto out = AddForward(kPolicy, "wan", spec);
  EXPECT_FALSE(out.has_value());
}

TEST(PolicyForward, RefusesADuplicate) {
  ForwardSpec spec;
  spec.proto = "tcp";
  spec.port = 80;
  spec.target_ip = "10.10.0.20";
  spec.target_port = 8080;
  spec.inside_zone = "lan";
  auto first = AddForward(kPolicy, "wan", spec);
  ASSERT_TRUE(first.has_value()) << first.error();
  auto second = AddForward(first->document, "wan", spec);
  EXPECT_FALSE(second.has_value());
}

TEST(PolicyForward, RemovesBothHalves) {
  ForwardSpec spec;
  spec.proto = "tcp";
  spec.port = 80;
  spec.target_ip = "10.10.0.20";
  spec.target_port = 8080;
  spec.inside_zone = "lan";
  auto added = AddForward(kPolicy, "wan", spec);
  ASSERT_TRUE(added.has_value()) << added.error();
  auto out = RemoveForward(added->document, "wan", "tcp", 80);
  ASSERT_TRUE(out.has_value()) << out.error();
  EXPECT_EQ(out->removed.size(), 2u);
  EXPECT_TRUE(out->warnings.empty());
  EXPECT_EQ(CountIn(out->document, "wan"), CountIn(kPolicy, "wan"));
}

// Half a forward is the dangerous state, so removing it says which
// half was already missing rather than reporting a clean removal.
TEST(PolicyForward, NamesTheMissingHalf) {
  const std::string doc =
      "@xdp(wan)\n"
      "redirect to lan if pkt.proto == tcp and pkt.dst_port == 80\n"
      "default drop\n"
      "\n"
      "@xdp(lan)\n"
      "default drop\n";
  auto out = RemoveForward(doc, "wan", "tcp", 80);
  ASSERT_TRUE(out.has_value()) << out.error();
  ASSERT_EQ(out->removed.size(), 1u);
  ASSERT_FALSE(out->warnings.empty());
  EXPECT_NE(out->warnings[0].find("dnat"), std::string::npos);
}

TEST(PolicyForward, RefusesToRemoveOneThatIsNotThere) {
  auto out = RemoveForward(kPolicy, "wan", "tcp", 80);
  EXPECT_FALSE(out.has_value());
}

// `no rule` on one half of a pair is legal, and the survivor is named
// rather than left for the operator to discover on the wire.
TEST(PolicyForward, RemovingOneHalfByIndexNamesTheOther) {
  ForwardSpec spec;
  spec.proto = "tcp";
  spec.port = 80;
  spec.target_ip = "10.10.0.20";
  spec.target_port = 8080;
  spec.inside_zone = "lan";
  auto added = AddForward(kPolicy, "wan", spec);
  ASSERT_TRUE(added.has_value()) << added.error();
  auto view = ReadPolicy(added->document);
  int dnat_index = 0;
  for (const auto* s : view.InZone("wan")) {
    if (s->verb == Verb::kTranslate) dnat_index = s->index;
  }
  ASSERT_GT(dnat_index, 0);
  auto out = RemoveRule(added->document, "wan", dnat_index);
  ASSERT_TRUE(out.has_value()) << out.error();
  ASSERT_FALSE(out->warnings.empty());
  EXPECT_NE(out->warnings[0].find("redirect to lan"),
            std::string::npos);
}

}  // namespace
