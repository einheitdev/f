/// @file test_fw_adapter.cc
/// @brief Tests for the f firewall CLI adapter.

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <sstream>
#include <string>
#include <vector>

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

class FwAdapterTest : public ::testing::Test {
 protected:
  void SetUp() override {
    adapter_ = einheit::adapters::fw::NewFwAdapter();
  }

  auto FindCommand(const std::string& path) -> const cli::CommandSpec* {
    for (const auto& c : adapter_->Commands()) {
      if (c.path == path) return &c;
    }
    return nullptr;
  }

  auto MakeResponse(const json& data) -> proto::Response {
    auto s = data.dump();
    return {
        .id = "test",
        .status = proto::ResponseStatus::Ok,
        .data = {s.begin(), s.end()},
    };
  }

  auto RenderToString(const cli::CommandSpec& cmd,
                      const proto::Response& resp)
      -> std::string {
    std::ostringstream out;
    render::TerminalCaps caps{};
    caps.colors = render::ColorDepth::None;
    caps.width = 80;
    caps.unicode = false;
    render::Renderer r(out, caps);
    adapter_->RenderResponse(cmd, resp, r);
    return out.str();
  }

  std::unique_ptr<cli::ProductAdapter> adapter_;
};

TEST_F(FwAdapterTest, Metadata) {
  auto m = adapter_->Metadata();
  EXPECT_EQ(m.id, "f");
  EXPECT_EQ(m.prompt, "f");
  EXPECT_FALSE(m.display_name.empty());
  EXPECT_FALSE(m.banner.empty());
}

TEST_F(FwAdapterTest, SchemaLoads) {
  const auto& schema = adapter_->GetSchema();
  EXPECT_EQ(schema.product, "f");
}

TEST_F(FwAdapterTest, CommandsRegistered) {
  auto cmds = adapter_->Commands();
  EXPECT_GE(cmds.size(), 5u);

  std::vector<std::string> expected = {
      "show status",
      "show interfaces",
      "show zones",
      "show nat",
      "show conntrack",
      "reload firewall",
  };
  for (const auto& path : expected) {
    bool found = false;
    for (const auto& c : cmds) {
      if (c.path == path) {
        found = true;
        break;
      }
    }
    EXPECT_TRUE(found) << "missing command: " << path;
  }
}

TEST_F(FwAdapterTest, TheV01VerbsAreGoneRatherThanEmpty) {
  // `show firewall`, `show firewall rules`, `show counters` and
  // `clear counters` addressed the single-program datapath. On a v0.4
  // box the first answered a fixed fabrication (`default_action drop`,
  // `active_table 0`, `conntrack disabled`, `rule_count 0`, from an
  // `FwConfig` only the removed ApplyConfig ever wrote) and the other
  // three were refused by fd. A verb that cannot answer is worse than
  // no verb: the operator reaches for it first and is told something.
  //
  // `show counters` is off this list now — see below. The other three
  // still have no datapath to ask.
  auto cmds = adapter_->Commands();
  for (const auto& gone : {"show firewall", "show firewall rules",
                           "clear counters"}) {
    for (const auto& c : cmds) {
      EXPECT_NE(c.path, gone)
          << gone << " is registered again; it has no datapath to ask";
    }
  }
}

TEST_F(FwAdapterTest, ShowCountersIsBackAgainstTheOtherMap) {
  // The verb returned because the map it reads changed, not because
  // the old one was forgiven. The v0.1 version asked opcode 2 for a
  // `counters` map keyed by match tier, which no v0.4 bundle pins;
  // this one asks opcode 12 for each zone's own `fwl_counters_<zone>`
  // — the map a policy's `count <name>` statements actually write —
  // and presents the values under the names the policy gave them.
  const cli::CommandSpec* spec = nullptr;
  for (const auto& c : adapter_->Commands()) {
    if (c.path == "show counters") spec = &c;
  }
  ASSERT_NE(spec, nullptr)
      << "`count` is a language feature; something must read it back";
  EXPECT_EQ(spec->wire_command, "show_counters");
}

TEST_F(FwAdapterTest, CommandTreeIntegration) {
  cli::CommandTree tree;
  for (auto spec : adapter_->Commands()) {
    auto r = cli::Register(tree, std::move(spec));
    EXPECT_TRUE(r.has_value()) << r.error().message;
  }
  EXPECT_GE(tree.by_path.size(), 5u);
}

TEST_F(FwAdapterTest, WireCommandsNonEmpty) {
  for (const auto& c : adapter_->Commands()) {
    EXPECT_FALSE(c.wire_command.empty())
        << "command " << c.path << " has no wire_command";
  }
}

TEST_F(FwAdapterTest, RenderShowStatusNoData) {
  auto cmds = adapter_->Commands();
  cli::CommandSpec cmd;
  for (const auto& c : cmds) {
    if (c.wire_command == "show_status") {
      cmd = c;
      break;
    }
  }
  json data = {
      {"daemon", "not connected"},
      {"pin_path", "/sys/fs/bpf/f"},
  };
  auto resp = MakeResponse(data);
  auto output = RenderToString(cmd, resp);
  EXPECT_NE(output.find("daemon"), std::string::npos);
  EXPECT_NE(output.find("not connected"),
            std::string::npos);
}

TEST_F(FwAdapterTest, RenderShowInterfacesEmpty) {
  auto cmds = adapter_->Commands();
  cli::CommandSpec cmd;
  for (const auto& c : cmds) {
    if (c.wire_command == "show_interfaces") {
      cmd = c;
      break;
    }
  }
  auto resp = MakeResponse(json::array());
  auto output = RenderToString(cmd, resp);
  EXPECT_NE(output.find("no interfaces found"),
            std::string::npos);
}

TEST_F(FwAdapterTest, RenderShowInterfacesWithData) {
  auto cmds = adapter_->Commands();
  cli::CommandSpec cmd;
  for (const auto& c : cmds) {
    if (c.wire_command == "show_interfaces") {
      cmd = c;
      break;
    }
  }
  json data = json::array({
      {{"name", "eth0"},
       {"state", "up"},
       {"mac", "aa:bb:cc:dd:ee:ff"},
       {"mtu", "1500"},
       {"speed", "1G"},
       {"addresses", {"192.168.1.1"}},
       {"rx_bytes", "1234567"},
       {"tx_bytes", "7654321"},
       {"rx_packets", "1000"},
       {"tx_packets", "2000"}},
  });
  auto resp = MakeResponse(data);
  auto output = RenderToString(cmd, resp);
  EXPECT_NE(output.find("eth0"), std::string::npos);
  EXPECT_NE(output.find("192.168.1.1"),
            std::string::npos);
}

TEST_F(FwAdapterTest, RenderErrorResponse) {
  auto cmds = adapter_->Commands();
  cli::CommandSpec cmd;
  for (const auto& c : cmds) {
    if (c.wire_command == "show_zones") {
      cmd = c;
      break;
    }
  }
  proto::Response resp;
  resp.id = "test";
  resp.status = proto::ResponseStatus::Error;
  resp.error = proto::ResponseError{
      "no_maps",
      "BPF maps not available",
      "Start fd first",
  };
  auto output = RenderToString(cmd, resp);
  EXPECT_NE(output.find("no_maps"), std::string::npos);
  EXPECT_NE(output.find("BPF maps not available"),
            std::string::npos);
}

}  // namespace
