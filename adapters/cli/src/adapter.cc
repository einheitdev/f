/// @file adapter.cc
/// @brief f firewall CLI adapter — commands and rendering.

#include "adapters/fw/adapter.h"

#include <filesystem>
#include <format>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "einheit/cli/command_tree.h"
#include "einheit/cli/protocol/envelope.h"
#include "einheit/cli/render/table.h"
#include "einheit/cli/schema.h"

namespace einheit::adapters::fw {

namespace {

using json = nlohmann::json;
using cli::CommandSpec;
using cli::ProductMetadata;
using cli::RoleGate;
using cli::protocol::Event;
using cli::protocol::Response;
using cli::protocol::ResponseStatus;
using cli::render::Align;
using cli::render::Cell;
using cli::render::Priority;
using cli::render::Renderer;
using cli::render::RenderError;
using cli::render::RenderFormatted;
using cli::render::Semantic;
using cli::render::Table;
using cli::schema::Schema;

constexpr const char* kSchemaYaml = R"YAML(
version: 1
product: f
config:
  firewall:
    type: object
    fields:
      source:
        type: string
        help: "Path to the FWL source file"
        default: "/etc/f/rules.fw"
        example: "/etc/f/rules.fw"
      compiled_dir:
        type: string
        help: "Directory for compiled bundles"
        default: "/usr/share/f/compiled"
      default_action:
        type: enum
        values: [allow, drop]
        default: "allow"
        help: "Default action when no rule matches"
      conntrack:
        type: boolean
        default: "false"
        help: "Enable connection tracking"
  daemon:
    type: object
    fields:
      socket:
        type: string
        help: "ZMQ IPC control socket path"
        default: "ipc:///tmp/fd-control.sock"
      pin_path:
        type: string
        help: "BPF map pin directory"
        default: "/sys/fs/bpf/f"
      log_level:
        type: enum
        values: [trace, debug, info, warn, error]
        default: "info"
  editor:
    type: string
    help: "Preferred editor for configure firewall"
    default: "vim"

types: {}
)YAML";

auto LoadBakedSchema() -> std::shared_ptr<Schema> {
  const auto path =
      std::filesystem::temp_directory_path() /
      "einheit_fw_schema.yaml";
  {
    std::ofstream f(path);
    f << kSchemaYaml;
  }
  auto s = cli::schema::LoadSchema(path.string());
  if (!s) return std::make_shared<Schema>();
  return *s;
}

auto Show(std::string path, std::string wire,
          std::string help,
          RoleGate role = RoleGate::AnyAuthenticated)
    -> CommandSpec {
  CommandSpec c;
  c.path = "show " + std::move(path);
  c.wire_command = std::move(wire);
  c.help = std::move(help);
  c.role = role;
  return c;
}

auto ParseData(const Response& resp) -> json {
  if (resp.data.empty()) return json();
  try {
    return json::parse(resp.data.begin(), resp.data.end());
  } catch (...) {
    return json();
  }
}

auto FormatBytes(uint64_t bytes) -> std::string {
  if (bytes >= 1'000'000'000) {
    return std::format("{:.1f}G",
        static_cast<double>(bytes) / 1'000'000'000.0);
  }
  if (bytes >= 1'000'000) {
    return std::format("{:.1f}M",
        static_cast<double>(bytes) / 1'000'000.0);
  }
  if (bytes >= 1'000) {
    return std::format("{:.1f}K",
        static_cast<double>(bytes) / 1'000.0);
  }
  return std::to_string(bytes);
}

auto SemanticForState(const std::string& state)
    -> Semantic {
  if (state == "up") return Semantic::Good;
  if (state == "down") return Semantic::Bad;
  return Semantic::Dim;
}

auto SemanticForAction(const std::string& action)
    -> Semantic {
  if (action == "allow") return Semantic::Good;
  if (action == "drop") return Semantic::Bad;
  return Semantic::Warn;
}

// -- Renderers -------------------------------------------------------

auto RenderShowStatus(const Response& resp,
                      Renderer& renderer) -> void {
  auto j = ParseData(resp);
  Table t;
  AddColumn(t, "FIELD", Align::Left, Priority::High);
  AddColumn(t, "VALUE", Align::Left, Priority::High);

  auto row = [&](const std::string& field,
                 const std::string& val,
                 Semantic sem = Semantic::Default) {
    AddRow(t, {Cell{field, Semantic::Info},
               Cell{val, sem}});
  };

  if (j.contains("pid")) {
    row("pid", std::to_string(j["pid"].get<int>()));
  }
  if (j.contains("uptime_s")) {
    auto s = j["uptime_s"].get<uint64_t>();
    auto h = s / 3600;
    auto m = (s % 3600) / 60;
    row("uptime", std::format("{}h {}m {}s",
                              h, m, s % 60));
  }
  if (j.contains("daemon")) {
    auto v = j["daemon"].get<std::string>();
    auto sem = v == "not connected" ? Semantic::Bad
               : v == "not responding" ? Semantic::Warn
               : Semantic::Good;
    row("daemon", v, sem);
  }
  row("maps", j.value("maps_available", false)
                  ? "available"
                  : "unavailable",
      j.value("maps_available", false) ? Semantic::Good
                                       : Semantic::Bad);
  if (j.contains("pin_path")) {
    row("pin_path", j["pin_path"].get<std::string>());
  }
  if (j.contains("rules")) {
    auto& r = j["rules"];
    row("active_table",
        std::to_string(r.value("active_table", 0)));
    row("rule_count",
        std::to_string(r.value("rule_count", 0)));
  }
  if (j.contains("interfaces")) {
    auto& ifaces = j["interfaces"];
    row("interfaces",
        std::to_string(ifaces.value("count", 0)));
  }
  if (j.contains("slow_path")) {
    auto& sp = j["slow_path"];
    row("events",
        std::to_string(sp.value("events", 0)));
  }
  RenderFormatted(t, renderer);
}

auto RenderShowInterfaces(const Response& resp,
                          Renderer& renderer) -> void {
  auto j = ParseData(resp);
  if (!j.is_array() || j.empty()) {
    Table t;
    AddColumn(t, "INTERFACES");
    AddRow(t, {Cell{"no interfaces found", Semantic::Dim}});
    RenderFormatted(t, renderer);
    return;
  }
  Table t;
  AddColumn(t, "NAME", Align::Left, Priority::High);
  AddColumn(t, "STATE", Align::Left, Priority::High);
  AddColumn(t, "MAC", Align::Left, Priority::Medium);
  AddColumn(t, "MTU", Align::Right, Priority::Low);
  AddColumn(t, "SPEED", Align::Right, Priority::Low);
  AddColumn(t, "ADDRESSES", Align::Left, Priority::High);
  AddColumn(t, "RX", Align::Right, Priority::Medium);
  AddColumn(t, "TX", Align::Right, Priority::Medium);

  for (const auto& iface : j) {
    auto name = iface.value("name", "");
    auto state = iface.value("state", "unknown");
    auto addrs = iface.value("addresses", json::array());
    std::string addr_str;
    for (const auto& a : addrs) {
      if (!addr_str.empty()) addr_str += ", ";
      addr_str += a.get<std::string>();
    }
    if (addr_str.empty()) addr_str = "-";
    auto rx = iface.value("rx_bytes", "0");
    auto tx = iface.value("tx_bytes", "0");
    AddRow(t, {
        Cell{name, Semantic::Emphasis},
        Cell{state, SemanticForState(state)},
        Cell{iface.value("mac", ""), Semantic::Dim},
        Cell{iface.value("mtu", ""), Semantic::Default},
        Cell{iface.value("speed", ""), Semantic::Default},
        Cell{addr_str, Semantic::Default},
        Cell{FormatBytes(std::stoull(
            rx.empty() ? "0" : rx))},
        Cell{FormatBytes(std::stoull(
            tx.empty() ? "0" : tx))},
    });
  }
  RenderFormatted(t, renderer);
}

auto RenderShowFirewall(const Response& resp,
                        Renderer& renderer) -> void {
  auto j = ParseData(resp);
  Table t;
  AddColumn(t, "FIELD", Align::Left, Priority::High);
  AddColumn(t, "VALUE", Align::Left, Priority::High);

  auto row = [&](const std::string& field,
                 const std::string& val,
                 Semantic sem = Semantic::Default) {
    AddRow(t, {Cell{field, Semantic::Info},
               Cell{val, sem}});
  };

  row("default_action",
      j.value("default_action", "unknown"),
      SemanticForAction(
          j.value("default_action", "")));
  row("active_table",
      std::to_string(j.value("active_table", 0)));
  row("conntrack",
      j.value("conntrack", false) ? "enabled"
                                  : "disabled");
  row("rule_count",
      std::to_string(j.value("rule_count", 0)));
  RenderFormatted(t, renderer);
}

auto RenderShowFirewallRules(const Response& resp,
                             Renderer& renderer) -> void {
  auto j = ParseData(resp);
  if (!j.is_array() || j.empty()) {
    Table t;
    AddColumn(t, "RULES");
    AddRow(t, {Cell{"no rules loaded", Semantic::Dim}});
    RenderFormatted(t, renderer);
    return;
  }
  Table t;
  AddColumn(t, "#", Align::Right, Priority::High);
  AddColumn(t, "SRC", Align::Left, Priority::High);
  AddColumn(t, "DST", Align::Left, Priority::High);
  AddColumn(t, "PROTO", Align::Left, Priority::Medium);
  AddColumn(t, "SPORT", Align::Right, Priority::Low);
  AddColumn(t, "DPORT", Align::Right, Priority::Low);
  AddColumn(t, "ACTION", Align::Left, Priority::High);
  AddColumn(t, "PACKETS", Align::Right, Priority::High);
  AddColumn(t, "BYTES", Align::Right, Priority::Medium);

  for (const auto& r : j) {
    auto action = r.value("action", "");
    auto sp = r.value("src_port", 0);
    auto dp = r.value("dst_port", 0);
    AddRow(t, {
        Cell{std::to_string(r.value("idx", 0)),
             Semantic::Dim},
        Cell{r.value("src", "0.0.0.0")},
        Cell{r.value("dst", "0.0.0.0")},
        Cell{r.value("proto", "any"), Semantic::Info},
        Cell{sp == 0 ? "*" : std::to_string(sp)},
        Cell{dp == 0 ? "*" : std::to_string(dp)},
        Cell{action, SemanticForAction(action)},
        Cell{std::to_string(r.value("packets", 0))},
        Cell{FormatBytes(r.value("bytes", 0ULL))},
    });
  }
  RenderFormatted(t, renderer);
}

auto RenderShowCounters(const Response& resp,
                        Renderer& renderer) -> void {
  auto j = ParseData(resp);
  if (!j.is_array() || j.empty()) {
    Table t;
    AddColumn(t, "COUNTERS");
    AddRow(t, {Cell{"no counters active", Semantic::Dim}});
    RenderFormatted(t, renderer);
    return;
  }
  Table t;
  AddColumn(t, "ID", Align::Right, Priority::High);
  AddColumn(t, "PACKETS", Align::Right, Priority::High);
  AddColumn(t, "BYTES", Align::Right, Priority::High);

  for (const auto& c : j) {
    AddRow(t, {
        Cell{std::to_string(c.value("id", 0)),
             Semantic::Info},
        Cell{std::to_string(c.value("packets", 0))},
        Cell{FormatBytes(c.value("bytes", 0ULL))},
    });
  }
  RenderFormatted(t, renderer);
}

auto RenderSimpleOk(const Response& resp,
                    Renderer& renderer) -> void {
  auto j = ParseData(resp);
  Table t;
  AddColumn(t, "RESULT");
  std::string msg = "ok";
  if (j.contains("cleared")) {
    msg = std::format("cleared {} counter slots",
                      j["cleared"].get<int>());
  }
  AddRow(t, {Cell{msg, Semantic::Good}});
  RenderFormatted(t, renderer);
}

auto RenderConfigureFirewall(const Response& resp,
                             Renderer& renderer) -> void {
  auto j = ParseData(resp);
  Table t;
  AddColumn(t, "FIELD", Align::Left, Priority::High);
  AddColumn(t, "VALUE", Align::Left, Priority::High);

  auto status = j.value("status", "");
  Semantic sem = status == "valid"     ? Semantic::Good
                 : status == "unchanged" ? Semantic::Dim
                                       : Semantic::Warn;
  AddRow(t, {Cell{"status", Semantic::Info},
             Cell{status, sem}});
  if (j.contains("source")) {
    AddRow(t, {Cell{"source", Semantic::Info},
               Cell{j["source"].get<std::string>()}});
  }
  if (j.contains("reload")) {
    AddRow(t, {Cell{"reload", Semantic::Info},
               Cell{j["reload"].get<std::string>(),
                    Semantic::Good}});
  }
  if (j.contains("message")) {
    AddRow(t, {Cell{"message", Semantic::Info},
               Cell{j["message"].get<std::string>()}});
  }
  RenderFormatted(t, renderer);
}

auto RenderSetEditor(const Response& resp,
                     Renderer& renderer) -> void {
  auto j = ParseData(resp);
  Table t;
  AddColumn(t, "FIELD", Align::Left, Priority::High);
  AddColumn(t, "VALUE", Align::Left, Priority::High);
  AddRow(t, {Cell{"editor", Semantic::Info},
             Cell{j.value("editor", ""),
                  Semantic::Good}});
  if (j.contains("config")) {
    AddRow(t, {Cell{"config", Semantic::Info},
               Cell{j["config"].get<std::string>(),
                    Semantic::Dim}});
  }
  RenderFormatted(t, renderer);
}

auto RenderShowLog(const Response& resp,
                   Renderer& renderer) -> void {
  auto j = ParseData(resp);
  if (j.contains("message")) {
    Table t;
    AddColumn(t, "LOG");
    AddRow(t, {Cell{j["message"].get<std::string>(),
                    Semantic::Dim}});
    RenderFormatted(t, renderer);
    return;
  }
  auto entries = j.value("entries", json::array());
  if (entries.empty()) {
    Table t;
    AddColumn(t, "LOG");
    AddRow(t, {Cell{"no log entries", Semantic::Dim}});
    RenderFormatted(t, renderer);
    return;
  }
  auto& out = renderer.Out();
  for (const auto& entry : entries) {
    out << entry.get<std::string>() << "\n";
  }
}

// -- Adapter class ---------------------------------------------------

class FwAdapter final : public cli::ProductAdapter {
 public:
  FwAdapter() : schema_(LoadBakedSchema()) {}

  auto Metadata() const -> ProductMetadata override {
    return {
        .id = "f",
        .display_name = "f firewall",
        .version = "0.1.0",
        .banner = "f firewall appliance",
        .prompt = "f",
    };
  }

  auto GetSchema() const -> const Schema& override {
    return *schema_;
  }

  auto ControlSocketPath() const -> std::string override {
    return "ipc:///tmp/fd-control.sock";
  }

  auto EventSocketPath() const -> std::string override {
    return "ipc:///tmp/fd-events.sock";
  }

  auto Commands() const
      -> std::vector<CommandSpec> override {
    return {
        Show("status", "show_status",
             "Daemon status, uptime, attach state"),
        Show("interfaces", "show_interfaces",
             "Network interfaces, addresses, counters"),
        Show("firewall", "show_firewall",
             "Firewall program overview"),
        Show("firewall rules", "show_firewall_rules",
             "Per-rule detail with hit counts"),
        Show("counters", "show_counters",
             "Named counters from the BPF program"),
        MakeShowLog(),
        MakeConfigureFirewall(),
        MakeSetEditor(),
        MakeReload(),
        MakeClearCounters(),
    };
  }

  auto RenderResponse(const CommandSpec& cmd,
                      const Response& response,
                      Renderer& renderer) const
      -> void override {
    if (response.error) {
      auto& e = *response.error;
      RenderError(e.code, e.message, e.hint, renderer);
      return;
    }
    auto& wc = cmd.wire_command;
    if (wc == "show_status") {
      RenderShowStatus(response, renderer);
    } else if (wc == "show_interfaces") {
      RenderShowInterfaces(response, renderer);
    } else if (wc == "show_firewall") {
      RenderShowFirewall(response, renderer);
    } else if (wc == "show_firewall_rules") {
      RenderShowFirewallRules(response, renderer);
    } else if (wc == "show_counters") {
      RenderShowCounters(response, renderer);
    } else if (wc == "show_log") {
      RenderShowLog(response, renderer);
    } else if (wc == "configure_firewall") {
      RenderConfigureFirewall(response, renderer);
    } else if (wc == "set_editor") {
      RenderSetEditor(response, renderer);
    } else if (wc == "reload_firewall" ||
               wc == "clear_counters") {
      RenderSimpleOk(response, renderer);
    }
  }

  auto EventTopicsFor(const CommandSpec& /*cmd*/) const
      -> std::vector<std::string> override {
    return {};
  }

  auto RenderEvent(const std::string& /*topic*/,
                   const Event& /*event*/,
                   Renderer& /*renderer*/) const
      -> void override {}

 private:
  std::shared_ptr<Schema> schema_;

  static auto MakeShowLog() -> CommandSpec {
    CommandSpec c;
    c.path = "show log";
    c.wire_command = "show_log";
    c.help = "Recent daemon log entries";
    c.args = {{
        .name = "lines",
        .help = "Number of lines to show (default 20)",
        .required = false,
    }};
    return c;
  }

  static auto MakeConfigureFirewall() -> CommandSpec {
    CommandSpec c;
    c.path = "configure firewall";
    c.wire_command = "configure_firewall";
    c.help = "Edit firewall rules in your preferred "
             "editor, validate, and reload";
    c.role = RoleGate::OperatorOrAdmin;
    return c;
  }

  static auto MakeSetEditor() -> CommandSpec {
    CommandSpec c;
    c.path = "set editor";
    c.wire_command = "set_editor";
    c.help = "Set preferred editor (vim, nano, emacs)";
    c.role = RoleGate::AnyAuthenticated;
    c.args = {{
        .name = "name",
        .help = "Editor command name",
        .required = false,
    }};
    return c;
  }

  static auto MakeReload() -> CommandSpec {
    CommandSpec c;
    c.path = "reload firewall";
    c.wire_command = "reload_firewall";
    c.help = "Force recompile and hot-reload";
    c.role = RoleGate::OperatorOrAdmin;
    return c;
  }

  static auto MakeClearCounters() -> CommandSpec {
    CommandSpec c;
    c.path = "clear counters";
    c.wire_command = "clear_counters";
    c.help = "Reset all per-rule counters to zero";
    c.role = RoleGate::OperatorOrAdmin;
    return c;
  }
};

}  // namespace

auto NewFwAdapter()
    -> std::unique_ptr<cli::ProductAdapter> {
  return std::make_unique<FwAdapter>();
}

}  // namespace einheit::adapters::fw
