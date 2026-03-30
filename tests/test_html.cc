/// @file test_html.cc
/// @brief HTML fragment rendering tests.

#include <gtest/gtest.h>

#include <string>
#include <utility>
#include <vector>

#include "f/daemon.h"
#include "f/html.h"

namespace f {

TEST(HtmlTest, TagBasic) {
  Html h;
  h.Tag("div", "class=\"foo\"", "hello");
  auto result = h.Build();
  EXPECT_EQ(result, R"(<div class="foo">hello</div>)");
}

TEST(HtmlTest, TagNoAttrs) {
  Html h;
  h.Tag("p", "", "text");
  auto result = h.Build();
  EXPECT_EQ(result, "<p>text</p>");
}

TEST(HtmlTest, RawAppend) {
  Html h;
  h.Raw("<br>");
  h.Raw("<hr>");
  auto result = h.Build();
  EXPECT_EQ(result, "<br><hr>");
}

TEST(HtmlTest, RenderRulesTableEmpty) {
  std::vector<std::pair<RuleKey, RuleValue>> rules;
  auto result = RenderRulesTable(rules);
  EXPECT_NE(result.find("No rules"), std::string::npos);
}

TEST(HtmlTest, RenderRulesTableWithRules) {
  RuleKey key{};
  key.dst_port = 443;
  key.proto = 6;
  RuleValue val{};
  val.action = 1;

  std::vector<std::pair<RuleKey, RuleValue>> rules;
  rules.emplace_back(key, val);

  auto result = RenderRulesTable(rules);
  EXPECT_NE(result.find("443"), std::string::npos);
  EXPECT_NE(result.find("TCP"), std::string::npos);
  EXPECT_NE(result.find("ALLOW"), std::string::npos);
}

TEST(HtmlTest, RenderCountersTable) {
  std::vector<RuleCounter> counters = {
      {100, 5000}, {200, 10000}};
  auto result = RenderCountersTable(counters);
  EXPECT_NE(result.find("100"), std::string::npos);
  EXPECT_NE(result.find("5000"), std::string::npos);
  EXPECT_NE(result.find("200"), std::string::npos);
}

TEST(HtmlTest, RenderStatusCard) {
  StatusResponse s{};
  s.pid = 999;
  s.uptime_s = 42;
  s.active_table = 0;
  s.rule_count = 5;
  s.iface_count = 1;

  auto result = RenderStatusCard(s);
  EXPECT_NE(result.find("999"), std::string::npos);
  EXPECT_NE(result.find("42s"), std::string::npos);
  EXPECT_NE(result.find("5"), std::string::npos);
}

TEST(HtmlTest, RenderLogEntries) {
  std::vector<LogEntry> entries = {
      {"2024-01-01T00:00:00", "info", "hello"},
      {"2024-01-01T00:00:01", "error", "oops"},
  };
  auto result = RenderLogEntries(entries);
  EXPECT_NE(result.find("hello"), std::string::npos);
  EXPECT_NE(result.find("oops"), std::string::npos);
  EXPECT_NE(result.find("log-error"),
            std::string::npos);
}

TEST(HtmlTest, RenderInterfaceList) {
  IfAttach ifaces[2];
  ifaces[0].ifindex = 2;
  std::strncpy(ifaces[0].name, "eth0",
               sizeof(ifaces[0].name));
  ifaces[1].ifindex = 3;
  std::strncpy(ifaces[1].name, "eth1",
               sizeof(ifaces[1].name));

  auto result = RenderInterfaceList(
      std::span<const IfAttach>(ifaces, 2));
  EXPECT_NE(result.find("eth0"), std::string::npos);
  EXPECT_NE(result.find("eth1"), std::string::npos);
  EXPECT_NE(result.find("ifindex=2"), std::string::npos);
}

}  // namespace f
