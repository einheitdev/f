/// @file test_fw_no_neighbour.cc
/// @brief What `show status` says about a box that resolved no next hop.
///
/// The shape this project spends its time on: everything reads healthy
/// and nothing crosses. A reboot empties the kernel's neighbour table,
/// and a masquerading box cannot refill it from forwarded traffic — the
/// frame XDP hands to the stack carries one of the box's own addresses
/// as its source, so `fib_validate_source` rejects it as a martian
/// before anything would ask for a neighbour, and no ARP is ever sent.
/// Every frame after it meets the same empty table.
///
/// Measured under qemu on 2026-08-15, on a box whose `forwarding` row
/// said on and whose two zones were both attached: `no_neigh` 0 -> 7
/// across one client's entire retry window, `routed` 0, zero frames on
/// the far side's wire — and the identical flow crossed the moment the
/// box's own stack pinged the far side.
///
/// So the screen has to carry the diagnosis. The `forwards` row is
/// HIDDEN in this state, because it renders only once routed or bridged
/// is non-zero; the no-neighbour row is the only thing left, and until
/// now it was a WARN reading `7 (next hop not in the ARP table)`, which
/// says nothing about traffic being lost and nothing about the cure.

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <memory>
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

class NoNeighbourTest : public ::testing::Test {
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
    // The severity is half of what this screen says, and on a plain
    // terminal it is carried by the `[OK]` / `[WARN]` / `[FAIL]`
    // marker rather than by a colour a test cannot see.
    caps.force_plain = true;
    render::Renderer r(out, caps, render::OutputFormat::Table);
    adapter_->RenderResponse(*spec, resp, r);
    return out.str();
  }

  static auto Has(const std::string& hay, const std::string& needle)
      -> bool {
    return hay.find(needle) != std::string::npos;
  }

  /// A status reply from an armed, forwarding, two-zone box, with
  /// whatever routing tally the caller wants on it. Everything outside
  /// the `route` section is deliberately healthy: that is the whole
  /// point of the case.
  static auto Status(const json& route) -> json {
    json rt = {
        {"enabled", true},
        {"ip_forward", true},
        {"forwarding_desired", true},
        {"forwarding_overridden", false},
        {"forwarding_corrections", 0},
        {"forwarding_reason",
         "cold boot: datapath armed on 2 interface(s)"},
        {"routed", 0},     {"bridged", 0},     {"no_route", 0},
        {"no_neigh", 0},   {"ttl_expired", 0}, {"off_zone", 0},
    };
    rt.update(route);
    return {{"pid", 344}, {"uptime_s", 30}, {"route", rt}};
  }

  std::unique_ptr<cli::ProductAdapter> adapter_;
};

TEST_F(NoNeighbourTest, ABoxThatHasRoutedNothingIsToldWhatToDo) {
  // The post-reboot box. Nothing has been forwarded, so the `forwards`
  // row is not on the screen at all, and this row is the only place
  // the operator can learn that traffic is being dropped rather than
  // that a few packets were slow.
  auto out = Render("show status", Status({{"no_neigh", 7}}));
  EXPECT_TRUE(Has(out, "route_no_neighbour")) << out;
  EXPECT_TRUE(Has(out, "DROPPED")) << out;
  EXPECT_TRUE(Has(out, "nothing is crossing")) << out;
  // The cure, on the screen that shows the fault. Without it the
  // operator has a number and no next move.
  EXPECT_TRUE(Has(out, "Ping the next hop FROM this box")) << out;
  // The control: the row must be the alarming one, not a warning. A
  // [WARN] beside a healthy `forwarding` row is what this box looked
  // like while it carried nothing.
  EXPECT_TRUE(Has(out, "[FAIL]")) << out;
}

TEST_F(NoNeighbourTest, ABoxThatIsForwardingKeepsTheMilderLine) {
  // The other reading of the same counter, and the reason this is not
  // simply escalated everywhere: on a box that IS routing, a handful
  // of unresolved next hops is a fact worth a line and not a fault.
  // The two payloads differ in `routed` alone.
  auto working = Render("show status",
                        Status({{"no_neigh", 7}, {"routed", 4000}}));
  auto stalled = Render("show status", Status({{"no_neigh", 7}}));
  EXPECT_TRUE(Has(working, "route_no_neighbour")) << working;
  EXPECT_FALSE(Has(working, "nothing is crossing")) << working;
  EXPECT_TRUE(Has(working, "lost")) << working;
  EXPECT_NE(working, stalled);
}

TEST_F(NoNeighbourTest, TheRowIsAbsentWhenTheCounterIsZero) {
  // The vacuity control. Both tests above would pass against a
  // renderer that printed this line unconditionally, and a screen that
  // always warns about the ARP table is a screen nobody reads.
  auto out = Render("show status", Status({{"routed", 4000}}));
  EXPECT_FALSE(Has(out, "route_no_neighbour")) << out;
}

}  // namespace
