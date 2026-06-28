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
      "show firewall",
      "show firewall rules",
      "show counters",
      "reload firewall",
      "clear counters",
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
      {"maps_available", false},
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

TEST_F(FwAdapterTest, RenderShowFirewall) {
  auto cmds = adapter_->Commands();
  cli::CommandSpec cmd;
  for (const auto& c : cmds) {
    if (c.wire_command == "show_firewall") {
      cmd = c;
      break;
    }
  }
  json data = {
      {"default_action", "allow"},
      {"active_table", 0},
      {"conntrack", false},
      {"rule_count", 5},
  };
  auto resp = MakeResponse(data);
  auto output = RenderToString(cmd, resp);
  EXPECT_NE(output.find("allow"), std::string::npos);
  EXPECT_NE(output.find("5"), std::string::npos);
}

TEST_F(FwAdapterTest, RenderShowFirewallRulesEmpty) {
  auto cmds = adapter_->Commands();
  cli::CommandSpec cmd;
  for (const auto& c : cmds) {
    if (c.wire_command == "show_firewall_rules") {
      cmd = c;
      break;
    }
  }
  auto resp = MakeResponse(json::array());
  auto output = RenderToString(cmd, resp);
  EXPECT_NE(output.find("no rules loaded"),
            std::string::npos);
}

TEST_F(FwAdapterTest, RenderShowFirewallRulesWithData) {
  auto cmds = adapter_->Commands();
  cli::CommandSpec cmd;
  for (const auto& c : cmds) {
    if (c.wire_command == "show_firewall_rules") {
      cmd = c;
      break;
    }
  }
  json data = json::array({
      {{"idx", 0},
       {"src", "10.0.0.1"},
       {"dst", "10.0.0.2"},
       {"proto", "tcp"},
       {"src_port", 0},
       {"dst_port", 22},
       {"action", "drop"},
       {"packets", 42},
       {"bytes", 1234}},
  });
  auto resp = MakeResponse(data);
  auto output = RenderToString(cmd, resp);
  EXPECT_NE(output.find("10.0.0.1"), std::string::npos);
  EXPECT_NE(output.find("drop"), std::string::npos);
  EXPECT_NE(output.find("42"), std::string::npos);
}

TEST_F(FwAdapterTest, RenderErrorResponse) {
  auto cmds = adapter_->Commands();
  cli::CommandSpec cmd;
  for (const auto& c : cmds) {
    if (c.wire_command == "show_firewall") {
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

TEST_F(FwAdapterTest, RenderClearCounters) {
  auto cmds = adapter_->Commands();
  cli::CommandSpec cmd;
  for (const auto& c : cmds) {
    if (c.wire_command == "clear_counters") {
      cmd = c;
      break;
    }
  }
  json data = {{"cleared", 256}};
  auto resp = MakeResponse(data);
  auto output = RenderToString(cmd, resp);
  EXPECT_NE(output.find("cleared"), std::string::npos);
  EXPECT_NE(output.find("256"), std::string::npos);
}

TEST_F(FwAdapterTest, RenderConfigureFirewallValid) {
  auto cmds = adapter_->Commands();
  cli::CommandSpec cmd;
  for (const auto& c : cmds) {
    if (c.wire_command == "configure_firewall") {
      cmd = c;
      break;
    }
  }
  json data = {
      {"status", "valid"},
      {"source", "/etc/f/rules.fw"},
      {"reload", "triggered"},
  };
  auto resp = MakeResponse(data);
  auto output = RenderToString(cmd, resp);
  EXPECT_NE(output.find("valid"), std::string::npos);
  EXPECT_NE(output.find("triggered"), std::string::npos);
}

TEST_F(FwAdapterTest, RenderConfigureFirewallUnchanged) {
  auto cmds = adapter_->Commands();
  cli::CommandSpec cmd;
  for (const auto& c : cmds) {
    if (c.wire_command == "configure_firewall") {
      cmd = c;
      break;
    }
  }
  json data = {
      {"status", "unchanged"},
      {"message", "No changes made"},
  };
  auto resp = MakeResponse(data);
  auto output = RenderToString(cmd, resp);
  EXPECT_NE(output.find("unchanged"), std::string::npos);
}

TEST_F(FwAdapterTest, RenderSetEditor) {
  auto cmds = adapter_->Commands();
  cli::CommandSpec cmd;
  for (const auto& c : cmds) {
    if (c.wire_command == "set_editor") {
      cmd = c;
      break;
    }
  }
  json data = {
      {"editor", "nano"},
      {"config", "/home/test/.config/einheit-f/config.yaml"},
  };
  auto resp = MakeResponse(data);
  auto output = RenderToString(cmd, resp);
  EXPECT_NE(output.find("nano"), std::string::npos);
}

TEST_F(FwAdapterTest, RenderShowLogEmpty) {
  auto cmds = adapter_->Commands();
  cli::CommandSpec cmd;
  for (const auto& c : cmds) {
    if (c.wire_command == "show_log") {
      cmd = c;
      break;
    }
  }
  json data = {
      {"source", "none"},
      {"entries", json::array()},
      {"message", "No log source available"},
  };
  auto resp = MakeResponse(data);
  auto output = RenderToString(cmd, resp);
  EXPECT_NE(output.find("No log source"),
            std::string::npos);
}

TEST_F(FwAdapterTest, RenderShowLogWithEntries) {
  auto cmds = adapter_->Commands();
  cli::CommandSpec cmd;
  for (const auto& c : cmds) {
    if (c.wire_command == "show_log") {
      cmd = c;
      break;
    }
  }
  json data = {
      {"source", "journald"},
      {"entries", {"2026-06-28 fd[1234]: Engine running",
                   "2026-06-28 fd[1234]: Attached eth0"}},
  };
  auto resp = MakeResponse(data);
  auto output = RenderToString(cmd, resp);
  EXPECT_NE(output.find("Engine running"),
            std::string::npos);
  EXPECT_NE(output.find("Attached eth0"),
            std::string::npos);
}

TEST_F(FwAdapterTest, NewCommandsRegistered) {
  auto cmds = adapter_->Commands();
  std::vector<std::string> expected = {
      "show log",
      "configure firewall",
      "set editor",
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

TEST_F(FwAdapterTest, ConfigureFirewallRequiresRole) {
  auto cmds = adapter_->Commands();
  for (const auto& c : cmds) {
    if (c.path == "configure firewall") {
      EXPECT_EQ(c.role, cli::RoleGate::OperatorOrAdmin);
      break;
    }
  }
}

TEST_F(FwAdapterTest, EventTopicsEmpty) {
  auto cmds = adapter_->Commands();
  for (const auto& c : cmds) {
    auto topics = adapter_->EventTopicsFor(c);
    EXPECT_TRUE(topics.empty());
  }
}

}  // namespace
