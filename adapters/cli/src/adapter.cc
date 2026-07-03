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
        default: "ipc:///run/f/control.sock"
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

  auto jstr = [](const json& v) -> std::string {
    if (v.is_string()) return v.get<std::string>();
    if (v.is_number()) return std::to_string(v.get<int64_t>());
    if (v.is_boolean()) return v.get<bool>() ? "true" : "false";
    return v.dump();
  };

  if (j.contains("pid")) {
    row("pid", jstr(j["pid"]));
  }
  if (j.contains("uptime_s")) {
    auto s = j["uptime_s"].get<uint64_t>();
    auto h = s / 3600;
    auto m = (s % 3600) / 60;
    row("uptime", std::format("{}h {}m {}s",
                              h, m, s % 60));
  }
  if (j.contains("daemon")) {
    if (j["daemon"].is_string()) {
      auto v = j["daemon"].get<std::string>();
      auto sem = v == "not connected" ? Semantic::Bad
                 : v == "not responding" ? Semantic::Warn
                 : Semantic::Good;
      row("daemon", v, sem);
    } else {
      row("daemon", "connected", Semantic::Good);
    }
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
    if (r.contains("active_table")) {
      row("active_table", jstr(r["active_table"]));
    }
    if (r.contains("count")) {
      row("rule_count", jstr(r["count"]));
    } else if (r.contains("rule_count")) {
      row("rule_count", jstr(r["rule_count"]));
    }
  }
  if (j.contains("interfaces")) {
    auto& ifaces = j["interfaces"];
    if (ifaces.contains("count")) {
      row("interfaces", jstr(ifaces["count"]));
    }
  }
  if (j.contains("slow_path")) {
    auto& sp = j["slow_path"];
    if (sp.contains("events")) {
      row("events", jstr(sp["events"]));
    }
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

auto JoinStrings(const json& arr) -> std::string {
  std::string out;
  if (!arr.is_array()) return out;
  for (const auto& s : arr) {
    if (!out.empty()) out += ", ";
    out += s.get<std::string>();
  }
  return out;
}

auto RenderShowZones(const Response& resp,
                     Renderer& renderer) -> void {
  auto j = ParseData(resp);
  if (!j.is_array() || j.empty()) {
    Table t;
    AddColumn(t, "ZONES");
    AddRow(t, {Cell{"no zones (single-program mode "
                    "or fd not running)",
                    Semantic::Dim}});
    RenderFormatted(t, renderer);
    return;
  }
  Table t;
  AddColumn(t, "ZONE", Align::Left, Priority::High);
  AddColumn(t, "INTERFACES", Align::Left, Priority::High);
  AddColumn(t, "ATTACHED", Align::Left, Priority::Medium);
  AddColumn(t, "MODE", Align::Left, Priority::Medium);
  AddColumn(t, "REDIRECTS TO", Align::Left, Priority::Medium);
  AddColumn(t, "MASQ", Align::Left, Priority::Medium);
  for (const auto& z : j) {
    auto ifaces = JoinStrings(z.value("interfaces",
                                      json::array()));
    auto attached = JoinStrings(z.value("attached",
                                        json::array()));
    auto redir = JoinStrings(z.value("redirects_to",
                                     json::array()));
    bool masq = z.value("masquerades", false);
    // A declared interface with no attach is down / absent.
    auto att_count = z.value("attached_count", 0);
    auto sem = att_count > 0 ? Semantic::Good : Semantic::Warn;
    // Generic (SKB) XDP is the software slow path — flag it so the
    // operator knows they are not at line rate.
    auto mode = z.value("xdp_mode", "");
    auto mode_sem = mode == "native" ? Semantic::Good
                    : mode == "generic" ? Semantic::Warn
                    : Semantic::Dim;
    AddRow(t, {
        Cell{z.value("zone", ""), Semantic::Emphasis},
        Cell{ifaces.empty() ? "-" : ifaces},
        Cell{attached.empty() ? "(none)" : attached, sem},
        Cell{mode.empty() ? "-" : mode, mode_sem},
        Cell{redir.empty() ? "-" : redir, Semantic::Info},
        Cell{masq ? "yes" : "no",
             masq ? Semantic::Good : Semantic::Dim},
    });
  }
  RenderFormatted(t, renderer);
}

auto RenderShowNat(const Response& resp,
                   Renderer& renderer) -> void {
  auto j = ParseData(resp);
  auto translations = j.value("translations", json::array());
  if (j.contains("masq_source")) {
    auto& out = renderer.Out();
    out << "masquerade source: "
        << j["masq_source"].get<std::string>() << "\n";
  }
  if (translations.empty()) {
    Table t;
    AddColumn(t, "NAT");
    AddRow(t, {Cell{"no active translations",
                    Semantic::Dim}});
    RenderFormatted(t, renderer);
    return;
  }
  Table t;
  AddColumn(t, "PROTO", Align::Left, Priority::Medium);
  AddColumn(t, "TYPE", Align::Left, Priority::High);
  AddColumn(t, "ORIG SRC", Align::Left, Priority::High);
  AddColumn(t, "ORIG DST", Align::Left, Priority::High);
  AddColumn(t, "TRANSLATED", Align::Left, Priority::High);
  for (const auto& tr : translations) {
    auto sport = tr.value("orig_src_port", 0);
    auto dport = tr.value("orig_dst_port", 0);
    auto nport = tr.value("new_port", 0);
    auto osrc = std::format("{}:{}",
        tr.value("orig_src", "0.0.0.0"), sport);
    auto odst = std::format("{}:{}",
        tr.value("orig_dst", "0.0.0.0"), dport);
    auto trans = std::format("{}:{}",
        tr.value("new_addr", "0.0.0.0"), nport);
    AddRow(t, {
        Cell{tr.value("proto", "any"), Semantic::Info},
        Cell{tr.value("type", ""), Semantic::Warn},
        Cell{osrc},
        Cell{odst},
        Cell{trans, Semantic::Good},
    });
  }
  RenderFormatted(t, renderer);
}

auto RenderShowConntrack(const Response& resp,
                         Renderer& renderer) -> void {
  auto j = ParseData(resp);
  if (!j.is_array() || j.empty()) {
    Table t;
    AddColumn(t, "CONNTRACK");
    AddRow(t, {Cell{"no tracked connections",
                    Semantic::Dim}});
    RenderFormatted(t, renderer);
    return;
  }
  Table t;
  AddColumn(t, "PROTO", Align::Left, Priority::Medium);
  AddColumn(t, "SOURCE", Align::Left, Priority::High);
  AddColumn(t, "DESTINATION", Align::Left, Priority::High);
  AddColumn(t, "STATE", Align::Left, Priority::High);
  AddColumn(t, "PACKETS", Align::Right, Priority::Medium);
  for (const auto& c : j) {
    auto state = c.value("state", "");
    auto sem = state == "established" ? Semantic::Good
               : state == "invalid" ? Semantic::Bad
               : Semantic::Warn;
    auto src = std::format("{}:{}",
        c.value("src", "0.0.0.0"), c.value("src_port", 0));
    auto dst = std::format("{}:{}",
        c.value("dst", "0.0.0.0"), c.value("dst_port", 0));
    AddRow(t, {
        Cell{c.value("proto", "any"), Semantic::Info},
        Cell{src},
        Cell{dst},
        Cell{state, sem},
        Cell{std::to_string(c.value("packets", 0))},
    });
  }
  RenderFormatted(t, renderer);
}

auto RenderSimpleOk(const Response& resp,
                    Renderer& renderer) -> void {
  auto j = ParseData(resp);
  // show_config renders file contents directly.
  if (j.contains("files")) {
    auto& out = renderer.Out();
    for (const auto& f : j["files"]) {
      out << "## " << f.value("path", "") << "\n";
      out << f.value("content", "") << "\n";
    }
    return;
  }
  // show_diff renders the diff directly.
  if (j.contains("diff")) {
    renderer.Out() << j["diff"].get<std::string>()
                   << "\n";
    return;
  }
  // show_commits renders the commit list.
  if (j.contains("commits")) {
    auto& commits = j["commits"];
    if (commits.empty()) {
      renderer.Out() << "no commits yet\n";
    }
    return;
  }
  Table t;
  AddColumn(t, "RESULT");
  std::string msg = "ok";
  if (j.contains("status")) {
    msg = j["status"].get<std::string>();
  }
  if (j.contains("cleared")) {
    msg = std::format("cleared {} counter slots",
                      j["cleared"].get<int>());
  }
  if (j.contains("reload")) {
    msg += " (" + j["reload"].get<std::string>() + ")";
  }
  if (j.contains("files_restored")) {
    msg += std::format(" ({} files restored)",
                       j["files_restored"].get<int>());
  }
  AddRow(t, {Cell{msg, Semantic::Good}});
  RenderFormatted(t, renderer);
}

auto RenderShowFiles(const Response& resp,
                     Renderer& renderer) -> void {
  auto j = ParseData(resp);
  auto files = j.value("files", json::array());
  if (files.empty()) {
    Table t;
    AddColumn(t, "FILES");
    AddRow(t, {Cell{"no .fw files found", Semantic::Dim}});
    RenderFormatted(t, renderer);
    return;
  }
  Table t;
  AddColumn(t, "FILE", Align::Left, Priority::High);
  AddColumn(t, "SIZE", Align::Right, Priority::Medium);
  AddColumn(t, "LINES", Align::Right, Priority::Medium);
  for (const auto& f : files) {
    AddRow(t, {
        Cell{f.value("name", ""), Semantic::Emphasis},
        Cell{f.value("size", "")},
        Cell{std::to_string(f.value("lines", 0))},
    });
  }
  RenderFormatted(t, renderer);
}

auto RenderEdit(const Response& resp,
                Renderer& renderer) -> void {
  auto j = ParseData(resp);
  Table t;
  AddColumn(t, "FIELD", Align::Left, Priority::High);
  AddColumn(t, "VALUE", Align::Left, Priority::High);

  if (j.contains("file")) {
    AddRow(t, {Cell{"file", Semantic::Info},
               Cell{j["file"].get<std::string>()}});
  }
  bool changed = j.value("changed", false);
  AddRow(t, {Cell{"changed", Semantic::Info},
             Cell{changed ? "yes" : "no",
                  changed ? Semantic::Good
                          : Semantic::Dim}});
  RenderFormatted(t, renderer);
}

auto RenderIfaceConfig(const Response& resp,
                       Renderer& renderer) -> void {
  auto j = ParseData(resp);
  Table t;
  AddColumn(t, "FIELD", Align::Left, Priority::High);
  AddColumn(t, "VALUE", Align::Left, Priority::High);
  auto row = [&](const std::string& f, const std::string& v,
                 Semantic sem = Semantic::Default) {
    AddRow(t, {Cell{f, Semantic::Info}, Cell{v, sem}});
  };
  if (j.contains("interface")) {
    row("interface", j["interface"].get<std::string>(),
        Semantic::Emphasis);
  }
  if (j.contains("action")) {
    row("action", j["action"].get<std::string>());
  }
  if (j.contains("value")) {
    row("value", j["value"].get<std::string>());
  }
  bool applied = j.value("applied", false);
  row("applied", applied ? "yes" : "no",
      applied ? Semantic::Good : Semantic::Warn);
  bool persisted = j.value("persisted", false);
  row("persisted", persisted ? j.value("config", "yes")
                             : "no",
      persisted ? Semantic::Good : Semantic::Dim);
  if (j.contains("warning")) {
    row("warning", j["warning"].get<std::string>(),
        Semantic::Warn);
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
    return "ipc:///run/f/control.sock";
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
        Show("zones", "show_zones",
             "Zones, interfaces, redirect topology (v0.4)"),
        Show("nat", "show_nat",
             "Active NAT translations and masquerade source"),
        Show("conntrack", "show_conntrack",
             "Connection-tracking table entries"),
        MakeShowLog(),
        MakeShowFiles(),
        MakeEdit(),
        MakeNewFile(),
        MakeRenameFile(),
        MakeDeleteFile(),
        MakeSetEditor(),
        MakeSetAddress(),
        MakeSetMtu(),
        MakeSetLink(),
        MakeNoAddress(),
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
    } else if (wc == "show_zones") {
      RenderShowZones(response, renderer);
    } else if (wc == "show_nat") {
      RenderShowNat(response, renderer);
    } else if (wc == "show_conntrack") {
      RenderShowConntrack(response, renderer);
    } else if (wc == "show_log") {
      RenderShowLog(response, renderer);
    } else if (wc == "show_files") {
      RenderShowFiles(response, renderer);
    } else if (wc == "edit" || wc == "new_file" ||
               wc == "rename_file" || wc == "delete_file") {
      RenderEdit(response, renderer);
    } else if (wc == "set_editor") {
      RenderSetEditor(response, renderer);
    } else if (wc == "iface_set_address" ||
               wc == "iface_set_mtu" ||
               wc == "iface_set_state" ||
               wc == "iface_del_address") {
      RenderIfaceConfig(response, renderer);
    } else if (wc == "configure" || wc == "commit" ||
               wc == "rollback" || wc == "set" ||
               wc == "delete" || wc == "show_config" ||
               wc == "show_diff" || wc == "show_commits" ||
               wc == "reload_firewall" ||
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

  static auto MakeShowFiles() -> CommandSpec {
    CommandSpec c;
    c.path = "show files";
    c.wire_command = "show_files";
    c.help = "List firewall rule files";
    return c;
  }

  static auto MakeNewFile() -> CommandSpec {
    CommandSpec c;
    c.path = "new file";
    c.wire_command = "new_file";
    c.help = "Create a new .fw rules file";
    c.role = RoleGate::AdminOnly;
    c.requires_session = true;
    c.args = {{
        .name = "name",
        .help = "Filename (e.g. dmz.fw)",
        .required = true,
    }};
    return c;
  }

  static auto MakeRenameFile() -> CommandSpec {
    CommandSpec c;
    c.path = "rename file";
    c.wire_command = "rename_file";
    c.help = "Rename a .fw rules file";
    c.role = RoleGate::AdminOnly;
    c.requires_session = true;
    c.args = {
        {.name = "from",
         .help = "Current filename",
         .required = true},
        {.name = "to",
         .help = "New filename",
         .required = true},
    };
    return c;
  }

  static auto MakeDeleteFile() -> CommandSpec {
    CommandSpec c;
    c.path = "delete file";
    c.wire_command = "delete_file";
    c.help = "Delete a .fw rules file";
    c.role = RoleGate::AdminOnly;
    c.requires_session = true;
    c.args = {{
        .name = "name",
        .help = "Filename to delete",
        .required = true,
    }};
    return c;
  }

  static auto MakeEdit() -> CommandSpec {
    CommandSpec c;
    c.path = "edit";
    c.wire_command = "edit";
    c.help = "Open a firewall rules file in the "
             "editor (default: main source file)";
    c.role = RoleGate::AdminOnly;
    c.requires_session = true;
    c.args = {{
        .name = "file",
        .help = "Filename to edit (relative to "
                "/etc/f/ or absolute path)",
        .required = false,
    }};
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

  static auto MakeSetAddress() -> CommandSpec {
    CommandSpec c;
    c.path = "set address";
    c.wire_command = "iface_set_address";
    c.help = "Assign an IPv4/IPv6 address to an interface "
             "(persists to networkd, applies immediately)";
    c.role = RoleGate::OperatorOrAdmin;
    c.args = {
        {.name = "interface",
         .help = "Interface name (e.g. eth0)",
         .required = true},
        {.name = "address",
         .help = "Address with prefix (e.g. 10.0.0.1/24)",
         .required = true},
    };
    return c;
  }

  static auto MakeSetMtu() -> CommandSpec {
    CommandSpec c;
    c.path = "set mtu";
    c.wire_command = "iface_set_mtu";
    c.help = "Set an interface MTU";
    c.role = RoleGate::OperatorOrAdmin;
    c.args = {
        {.name = "interface", .help = "Interface name",
         .required = true},
        {.name = "mtu", .help = "MTU in bytes (e.g. 1500)",
         .required = true},
    };
    return c;
  }

  static auto MakeSetLink() -> CommandSpec {
    CommandSpec c;
    c.path = "set link";
    c.wire_command = "iface_set_state";
    c.help = "Set an interface admin state up or down";
    c.role = RoleGate::OperatorOrAdmin;
    c.args = {
        {.name = "interface", .help = "Interface name",
         .required = true},
        {.name = "state", .help = "up or down",
         .required = true},
    };
    return c;
  }

  static auto MakeNoAddress() -> CommandSpec {
    CommandSpec c;
    c.path = "no address";
    c.wire_command = "iface_del_address";
    c.help = "Remove an address from an interface";
    c.role = RoleGate::OperatorOrAdmin;
    c.args = {
        {.name = "interface", .help = "Interface name",
         .required = true},
        {.name = "address",
         .help = "Address with prefix to remove",
         .required = true},
    };
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
