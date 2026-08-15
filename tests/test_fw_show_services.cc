/// @file test_fw_show_services.cc
/// @brief The five places the CLI reported green while broken.
///
/// Each test here is about a *distinction the screen has to make*. The
/// defect they were written for is one defect wearing four hats: a
/// column whose value is re-derived from the model that generated the
/// config cannot be evidence about whether the config worked, because
/// it can only ever agree with itself.
///
/// So every case below feeds one payload that describes a working box
/// and one that describes a broken one, and asserts that the rendered
/// text differs — and says which. A renderer that printed a fixed
/// string, or that echoed intent, passes neither.

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

class GreenWhileBrokenTest : public ::testing::Test {
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
              std::uint16_t width = 160) -> std::string {
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
    caps.height = 60;
    caps.unicode = false;
    render::Renderer r(out, caps);
    adapter_->RenderResponse(*spec, resp, r);
    return out.str();
  }

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

  static auto Has(const std::string& hay, const std::string& needle)
      -> bool {
    return Flat(hay).find(needle) != std::string::npos;
  }

  /// A dnsmasq that systemd calls active. `answers_on` is the only
  /// thing that differs between the two payloads.
  static auto Service(const json& answers_on, bool mismatch,
                      const json& listening, bool loopback_only)
      -> json {
    return {
        {"name", "dhcp+dns (dnsmasq)"},
        {"unit", "f-dnsmasq.service"},
        {"state", "running"},
        {"expected", true},
        {"healthy", !mismatch},
        {"zones", json::array({"testnet"})},
        {"bound_to", json::array({"lan0"})},
        {"observed", "observed"},
        {"answers_on", answers_on},
        {"answers_known", true},
        {"listening", listening},
        {"wildcard", true},
        {"loopback_only", loopback_only},
        {"mismatch", mismatch},
        {"mismatch_detail",
         mismatch ? "the model binds it to lan0 and the kernel shows "
                    "it listening on 127.0.0.1:53/udp"
                  : ""},
        {"detail", ""},
    };
  }

  std::unique_ptr<cli::ProductAdapter> adapter_;
};

// -- B6 ----------------------------------------------------------------

/// The defect, stated as a test: the same model, two boxes, and output
/// that used to be byte-identical.
TEST_F(GreenWhileBrokenTest, BoundAndUnboundDoNotRenderTheSame) {
  auto bound = Render(
      "show services",
      {{"services",
        json::array({Service(json::array({"lan0"}), false,
                             json::array({"10.10.0.1:53/tcp",
                                          "0.0.0.0:67/udp"}),
                             false)})},
       {"drift", "none"}});
  auto blind = Render(
      "show services",
      {{"services",
        json::array({Service(json::array(), true,
                             json::array({"127.0.0.1:53/tcp",
                                          "0.0.0.0:67/udp"}),
                             true)})},
       {"drift", "none"}});

  EXPECT_NE(Flat(bound), Flat(blind))
      << "this view printed identical bytes whether dnsmasq was "
         "bound to lan0 or to nothing at all";
  EXPECT_TRUE(Has(bound, "lan0"));
  EXPECT_TRUE(Has(blind, "LOOPBACK ONLY")) << blind;
  EXPECT_TRUE(Has(blind, "127.0.0.1")) << blind;
}

/// Intent is still shown — it is useful — but never in the column that
/// claims to report reality.
TEST_F(GreenWhileBrokenTest, IntentAndObservationAreSeparateColumns) {
  auto out = Render("show services",
                    {{"services",
                      json::array({Service(json::array(), true,
                                           json::array(), true)})},
                     {"drift", "none"}});
  EXPECT_TRUE(Has(out, "BOUND TO")) << out;
  EXPECT_TRUE(Has(out, "ANSWERS ON")) << out;
}

/// An observation nobody could make renders as a question mark with a
/// reason, never as "nowhere". The §0 convention, applied to a column
/// that is not a table.
TEST_F(GreenWhileBrokenTest, UnobservableIsNotNowhere) {
  auto s = Service(json::array(), false, json::array(), false);
  s["answers_known"] = false;
  s["observed"] = "socket table unreadable";
  s["wildcard"] = false;
  auto out = Render("show services",
                    {{"services", json::array({s})},
                     {"drift", "none"}});
  EXPECT_TRUE(Has(out, "?")) << out;
  EXPECT_TRUE(Has(out, "socket table unreadable")) << out;
  EXPECT_FALSE(Has(out, "LOOPBACK ONLY"));
}

/// dnsmasq's DHCP socket is always a wildcard. Saying so stops an
/// operator reading `0.0.0.0:67` as a containment failure, which it is
/// not — DHCP containment is per received packet.
TEST_F(GreenWhileBrokenTest, WildcardSocketIsExplainedNotHidden) {
  auto out = Render(
      "show services",
      {{"services",
        json::array({Service(json::array({"lan0"}), false,
                             json::array({"0.0.0.0:67/udp"}),
                             false)})},
       {"drift", "none"}});
  EXPECT_TRUE(Has(out, "per received packet")) << out;
}

// -- A5 ----------------------------------------------------------------

/// Rebind protection has to be visible whichever way it is set,
/// because its symptom — an internal name resolving to an empty answer
/// with no error — points nowhere near it.
TEST_F(GreenWhileBrokenTest, RebindProtectionIsStatedEitherWay) {
  auto on = Render("show services",
                   {{"services", json::array()},
                    {"drift", "none"},
                    {"rebind_protection", true},
                    {"rebind_exempt", json::array()}});
  EXPECT_TRUE(Has(on, "rebind protection is ON")) << on;
  EXPECT_TRUE(Has(on, "empty answer")) << on;
  EXPECT_TRUE(Has(on, "rebind_ok")) << on;

  auto off = Render("show services",
                    {{"services", json::array()},
                     {"drift", "none"},
                     {"rebind_protection", false},
                     {"rebind_exempt", json::array()}});
  EXPECT_TRUE(Has(off, "rebind protection is off")) << off;
  EXPECT_NE(Flat(on), Flat(off));
}

// -- B9 ----------------------------------------------------------------

/// The port is present, powered and correctly identified. Matching by
/// name said `no`; matching by the identity in the column next to it
/// says what is actually true.
TEST_F(GreenWhileBrokenTest, PendingRenameIsNotPresentNo) {
  json payload = {
      {"config", "/etc/f/system.yaml"},
      {"ok", true},
      {"zones", json::array()},
      {"interfaces",
       json::array({{
           {"name", "lan0"},
           {"match_kind", "mac"},
           {"match", "52:54:00:aa:bb:02"},
           {"mode", "static"},
           {"address", "10.10.0.1/24"},
           {"zone", "testnet"},
           {"presence", "pending rename"},
           {"present", false},
           {"current_name", "enp1s0f1"},
           {"presence_detail",
            "the port pinned to 52:54:00:aa:bb:02 is still called "
            "enp1s0f1"},
       }})},
      {"ports_read", true},
      {"pending",
       json::array({{{"interface", "lan0"},
                     {"current_name", "enp1s0f1"},
                     {"identity", "52:54:00:aa:bb:02"},
                     {"detail",
                      "the port pinned to 52:54:00:aa:bb:02 is still "
                      "called enp1s0f1"}}})},
      {"listen", json::array()},
      {"excluded", json::array()},
      {"dhcp_on", json::array()},
      {"confirm", {{"pending", false}}},
  };
  auto out = Render("show system", payload);
  EXPECT_TRUE(Has(out, "pending rename (now enp1s0f1)")) << out;
  EXPECT_TRUE(Has(out, "still called enp1s0f1")) << out;

  // The same row once the rename has happened.
  payload["interfaces"][0]["presence"] = "yes";
  payload["interfaces"][0]["present"] = true;
  payload["interfaces"][0]["current_name"] = "";
  payload["pending"] = json::array();
  auto renamed = Render("show system", payload);
  EXPECT_FALSE(Has(renamed, "pending rename"));
  EXPECT_NE(Flat(out), Flat(renamed));
}

/// A port table we could not read is unknown, not absent.
TEST_F(GreenWhileBrokenTest, UnreadablePortTableIsNotPresentNo) {
  auto out = Render(
      "show system",
      {{"config", "/etc/f/system.yaml"},
       {"ok", true},
       {"zones", json::array()},
       {"interfaces", json::array({{
                          {"name", "lan0"},
                          {"match", "52:54:00:aa:bb:02"},
                          {"mode", "static"},
                          {"address", "10.10.0.1/24"},
                          {"zone", "testnet"},
                          {"presence", "?"},
                          {"present", false},
                      }})},
       {"ports_read", false},
       {"ports_detail", "/sys/class/net is not readable"},
       {"pending", json::array()},
       {"listen", json::array()},
       {"excluded", json::array()},
       {"dhcp_on", json::array()},
       {"confirm", {{"pending", false}}}});
  EXPECT_TRUE(Has(out, "unknown rather than no")) << out;
}

// -- B7 / B8 -----------------------------------------------------------

/// "applied via f-confd, revision 1" over a config naming ports that
/// will not exist until reboot is true about the files and false about
/// the box.
TEST_F(GreenWhileBrokenTest, ApplyStatesAPendingRenameAndItsRecovery) {
  auto out = Render(
      "apply system",
      {{"config", "/etc/f/system.yaml"},
       {"ok", true},
       {"applied", true},
       {"via", "f-confd"},
       {"commit_id", "1"},
       {"written", json::array({"/etc/systemd/network/"
                                "10-f-lan0.link"})},
       {"removed", json::array()},
       {"leftover", json::array()},
       {"pending",
        json::array({{{"interface", "lan0"},
                      {"current_name", "enp1s0f1"}}})},
       {"pending_note",
        "PENDING RENAME: lan0 (currently enp1s0f1). Until the rename "
        "happens those names match no device.\n"
        "  udevadm control --reload\n"
        "  ip link set enp1s0f1 down\n"
        "  udevadm trigger --action=add /sys/class/net/enp1s0f1"}});
  EXPECT_TRUE(Has(out, "PENDING RENAME")) << out;
  EXPECT_TRUE(Has(out, "udevadm trigger --action=add")) << out;
}

/// A removal is as load-bearing as a write: the file that was deleted
/// is the one that would otherwise have won the rename.
TEST_F(GreenWhileBrokenTest, ApplyNamesWhatItRemoved) {
  auto out = Render(
      "apply system",
      {{"config", "/etc/f/system.yaml"},
       {"ok", true},
       {"applied", true},
       {"via", "direct"},
       {"written", json::array({"/etc/systemd/network/"
                                "10-f-lan0.link"})},
       {"removed", json::array({"/etc/systemd/network/"
                                "10-f-enp1s0f1.link"})},
       {"leftover", json::array({"/etc/systemd/network/"
                                 "05-vendor.link"})},
       {"pending", json::array()},
       {"pending_note", ""}});
  EXPECT_TRUE(Has(out, "removed /etc/systemd/network/"
                       "10-f-enp1s0f1.link"))
      << out;
  EXPECT_TRUE(Has(out, "no longer in the configuration")) << out;
  EXPECT_TRUE(Has(out, "LEFT IN PLACE")) << out;
  EXPECT_TRUE(Has(out, "not ours to delete")) << out;
}

/// And when nothing was pending, nothing is shouted. A banner that
/// fires every time is a banner the operator stops reading.
TEST_F(GreenWhileBrokenTest, AQuietApplyStaysQuiet) {
  auto out = Render("apply system",
                    {{"config", "/etc/f/system.yaml"},
                     {"ok", true},
                     {"applied", true},
                     {"via", "f-confd"},
                     {"commit_id", "2"},
                     {"written", json::array()},
                     {"removed", json::array()},
                     {"leftover", json::array()},
                     {"pending", json::array()},
                     {"pending_note", ""}});
  EXPECT_FALSE(Has(out, "PENDING RENAME"));
  EXPECT_FALSE(Has(out, "LEFT IN PLACE"));
}

}  // namespace
