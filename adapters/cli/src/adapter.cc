/// @file adapter.cc
/// @brief f firewall CLI adapter — commands and rendering.

#include "adapters/fw/adapter.h"

#include <array>
#include <ctime>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <format>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "einheit/cli/command_tree.h"
#include "einheit/cli/protocol/envelope.h"
#include "einheit/cli/render/sparkline.h"
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
  system:
    type: object
    fields:
      config:
        type: string
        help: "System configuration: interfaces, zones, services"
        default: "/etc/f/system.yaml"
        example: "/etc/f/system.yaml"
      generated_dir:
        type: string
        help: "Where derived daemon configs are installed"
        default: "/etc/f/generated"
      networkd_dir:
        type: string
        help: "Where derived systemd-networkd units are installed"
        default: "/etc/systemd/network"
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

/// Render a `diagnostics` array if the reply carries one, and say
/// whether it did. Defined below; used by the device renderers here.
auto RenderDiagnostics(const json& j, Renderer& renderer) -> bool;

// -- device visibility -----------------------------------------------
//
// The rule these renderers exist to keep: an empty table always says
// which kind of empty it is. "Nothing is leased", "nothing serves
// DHCP" and "I was not allowed to read the lease file" are three
// different things to do next, and the daemon sends the reason
// alongside the (possibly empty) list precisely so this code cannot
// collapse them into one blank frame.

/// Compact age, matching `f::lease::FormatAge` on the daemon side.
auto Age(std::int64_t seconds) -> std::string {
  if (seconds < 0) return "-";
  if (seconds < 60) return std::format("{}s", seconds);
  if (seconds < 3600) return std::format("{}m", seconds / 60);
  if (seconds < 86400) return std::format("{}h", seconds / 3600);
  return std::format("{}d", seconds / 86400);
}

/// A wall clock, rendered so that a wrong one is obvious.
///
/// The epoch is spelled out rather than shown as a date, because
/// "1970-01-01 00:00:12" reads as a date and this is not one — it is
/// a board that has never been told what year it is.
auto FormatWallClock(std::int64_t seconds) -> std::string {
  if (seconds < 1577836800) {
    return std::format("{} — THE EPOCH, not a real time", seconds);
  }
  std::time_t t = static_cast<std::time_t>(seconds);
  std::tm tm{};
  if (::gmtime_r(&t, &tm) == nullptr) return std::to_string(seconds);
  std::array<char, 32> buf{};
  std::strftime(buf.data(), buf.size(), "%Y-%m-%d %H:%M:%S UTC",
                &tm);
  return std::string(buf.data());
}

/// A duration in the same compact spelling as an age.
auto FormatDuration(std::int64_t seconds) -> std::string {
  return Age(seconds);
}

/// Where prose goes.
///
/// Under `--format json` the output stream belongs to whatever is
/// parsing it, and a helpful English sentence in the middle of it is
/// not helpful — it is a syntax error. But dropping the sentence
/// would put back exactly the ambiguity these renderers exist to
/// remove, so it goes to stderr instead: the pipe stays clean and the
/// operator watching the terminal still gets told.
auto Prose(Renderer& renderer) -> std::ostream& {
  return renderer.Format() == cli::render::OutputFormat::Table
             ? renderer.Out()
             : std::cerr;
}

/// Break `text` into lines no wider than the terminal. A reason the
/// operator cannot read because a table cell clipped it is the same
/// as no reason at all, so explanations are printed as prose and
/// wrapped rather than squeezed into a column.
auto Wrap(const std::string& text, std::size_t width)
    -> std::vector<std::string> {
  if (width < 20) width = 20;
  std::vector<std::string> lines;
  std::string line;
  std::size_t i = 0;
  while (i <= text.size()) {
    auto space = text.find(' ', i);
    auto word = text.substr(i, space == std::string::npos
                                   ? std::string::npos
                                   : space - i);
    if (!line.empty() && line.size() + 1 + word.size() > width) {
      lines.push_back(line);
      line.clear();
    }
    if (!line.empty()) line += ' ';
    line += word;
    if (space == std::string::npos) break;
    i = space + 1;
  }
  if (!line.empty()) lines.push_back(line);
  return lines;
}

/// Why there is no device table: a headline short enough for a cell,
/// and the sentence that goes under it.
struct NoDevices {
  std::string headline;
  std::string detail;
  Semantic semantic = Semantic::Dim;
};

auto WhyNoDevices(const json& j) -> NoDevices {
  const auto avail = j.value("leases", "ok");
  const auto path = j.value("lease_path", "");
  if (avail == "no-dhcp-configured") {
    return {"no DHCP server is configured",
            "Nothing on this box hands out addresses, so there are "
            "no leases to show. Bind a DHCP server to a zone under "
            "services.dhcp in the system configuration.",
            Semantic::Warn};
  }
  if (avail == "no-lease-file-yet") {
    return {"no lease file yet",
            std::format(
                "DHCP is configured and {} does not exist. Either "
                "dnsmasq is not running (`show services`) or no "
                "client has asked it for an address yet.",
                path),
            Semantic::Warn};
  }
  if (avail == "unreadable") {
    return {"lease file unreadable",
            std::format("{}. This is not the same as having no "
                        "devices — the lease database is there and "
                        "could not be read.",
                        j.value("detail", "unknown reason")),
            Semantic::Bad};
  }
  const auto filter = j.value("filter", "all");
  const auto hidden = j.value("hidden", 0);
  if (filter == "new") {
    return {"no new arrivals",
            std::format("Nothing has appeared in the last 15 "
                        "minutes. {} device(s) are known; "
                        "`show leases` lists them.",
                        j.value("active", 0) + hidden),
            Semantic::Dim};
  }
  if (filter == "active" && hidden > 0) {
    return {"nothing holds a lease",
            std::format("{} device(s) have been seen before and "
                        "have no current lease; `show leases all` "
                        "includes them.",
                        hidden),
            Semantic::Dim};
  }
  return {"no device holds a lease",
          std::format("{} was read and is empty: dnsmasq is running "
                      "and no client has taken an address.",
                      path),
          Semantic::Dim};
}

/// A one-line table saying what is missing, with the sentence that
/// explains it wrapped underneath instead of clipped inside a cell.
auto RenderNote(const std::string& header,
                const std::string& headline,
                const std::string& detail, Semantic semantic,
                Renderer& renderer) -> void {
  Table t;
  AddColumn(t, header);
  AddRow(t, {Cell{headline, semantic}});
  RenderFormatted(t, renderer);
  if (detail.empty()) return;
  for (const auto& l : Wrap(detail, renderer.Caps().width)) {
    Prose(renderer) << l << "\n";
  }
}

auto RenderNoDevices(const json& j, Renderer& renderer) -> void {
  auto why = WhyNoDevices(j);
  RenderNote("LEASES", why.headline, why.detail, why.semantic,
             renderer);
}

/// Anything the operator should know about the view itself: history
/// that is not being kept, lines that did not parse. Printed above the
/// table so it is read before the data.
/// @param j The reply body.
/// @param renderer Destination.
/// @param has_rows Whether a device table follows; the
///   first-observation note is about the rows, so it is pointless
///   without any.
auto RenderLeaseCaveats(const json& j, Renderer& renderer,
                        bool has_rows) -> void {
  auto& out = Prose(renderer);
  const auto journal = j.value("journal", "ok");
  if (journal == "first-observation") {
    if (has_rows) {
      out << "first look at this box: arrival times below are upper "
             "bounds (>=), and nothing is marked new yet\n";
    }
  } else if (journal == "unwritable") {
    out << std::format(
        "device history is NOT being recorded ({}) — arrivals will "
        "not be detected\n",
        j.value("detail", ""));
  } else if (journal == "unreadable") {
    out << std::format(
        "{} could not be read ({}) — it has been left alone; move it "
        "aside to start a fresh history\n",
        j.value("journal_path", ""), j.value("detail", ""));
  }
  const auto bad = j.value("unparsable", json::array());
  if (bad.is_array() && !bad.empty()) {
    out << std::format("{} line(s) in {} did not parse, first: {}\n",
                       bad.size(), j.value("lease_path", ""),
                       bad[0].get<std::string>());
  }
  auto v6 = j.value("ipv6_skipped", 0);
  if (v6 > 0) {
    out << std::format("{} DHCPv6 lease(s) ignored — this appliance "
                       "serves IPv4 DHCP only\n",
                       v6);
  }
}

auto RenderLeaseTable(const json& j, Renderer& renderer) -> void {
  auto devices = j.value("devices", json::array());
  const auto now_new = [](const json& d) {
    return d.value("new", false);
  };

  Table t;
  // Header and cell carry the same word: a blank header would become
  // an empty key under --format json, and "NEW" is what the eye is
  // scanning for anyway.
  AddColumn(t, "NEW", Align::Left, Priority::High);
  // MAC and ADDRESS are the identity: on a narrow terminal everything
  // else goes before they do, because half a MAC still looks like a
  // MAC.
  AddColumn(t, "MAC", Align::Left, Priority::High);
  AddColumn(t, "ADDRESS", Align::Left, Priority::High);
  AddColumn(t, "HOSTNAME", Align::Left, Priority::Medium);
  AddColumn(t, "ZONE", Align::Left, Priority::Medium);
  AddColumn(t, "FIRST SEEN", Align::Right, Priority::High);
  AddColumn(t, "LAST SEEN", Align::Right, Priority::Medium);
  AddColumn(t, "EXPIRES", Align::Right, Priority::Low);
  for (const auto& d : devices) {
    const bool is_new = now_new(d);
    const bool active = d.value("active", false);
    // An inferred first sighting is rendered with a `>=` so it can
    // never be read as a measurement of when the device turned up.
    auto first = d.value("first_seen_exact", false)
                     ? Age(d.value("first_seen_age", 0))
                     : ">=" + Age(d.value("first_seen_age", 0));
    std::string expires = "-";
    if (active) {
      auto secs = d.value("expires_in", 0);
      expires = secs > 0 ? Age(secs) : "expired";
    }
    std::string host = d.value("hostname", "");
    if (host.empty()) host = "(none)";
    std::string zone = d.value("zone", "");
    auto zone_sem = Semantic::Default;
    if (zone.empty()) {
      // A leased address that falls in no declared subnet means the
      // model and the running dnsmasq disagree. Worth a colour.
      zone = "(no zone)";
      zone_sem = Semantic::Warn;
    }
    std::string mac = d.value("mac", "");
    if (d.value("reserved", false)) mac += " *";
    AddRow(t, {
        Cell{is_new ? "NEW" : "",
             is_new ? Semantic::Good : Semantic::Default},
        Cell{mac, active ? Semantic::Emphasis : Semantic::Dim},
        Cell{d.value("address", ""),
             active ? Semantic::Default : Semantic::Dim},
        Cell{host},
        Cell{zone, zone_sem},
        Cell{first, is_new ? Semantic::Good : Semantic::Default},
        Cell{Age(d.value("last_seen_age", 0)),
             active ? Semantic::Default : Semantic::Dim},
        Cell{expires},
    });
  }
  RenderFormatted(t, renderer);
  bool any_reserved = false;
  for (const auto& d : devices) {
    if (d.value("reserved", false)) any_reserved = true;
  }
  if (any_reserved) {
    Prose(renderer) << "* has a static reservation\n";
  }
  auto hidden = j.value("hidden", 0);
  if (hidden > 0) {
    // Which rows were left out depends on which filter did the
    // leaving. "not shown" without saying why is the ambiguity this
    // whole view exists to remove.
    Prose(renderer)
        << (j.value("filter", "all") == "new"
                ? std::format(
                      "{} other device(s) known — `show leases`\n",
                      hidden)
                : std::format(
                      "{} device(s) with no current lease not shown "
                      "— `show leases all`\n",
                      hidden));
  }
}

auto RenderShowLeases(const Response& resp, Renderer& renderer)
    -> void {
  auto j = ParseData(resp);
  if (RenderDiagnostics(j, renderer)) return;
  auto devices = j.value("devices", json::array());
  RenderLeaseCaveats(j, renderer, !devices.empty());
  if (devices.empty()) {
    RenderNoDevices(j, renderer);
    return;
  }
  RenderLeaseTable(j, renderer);
}

auto RenderShowDevice(const Response& resp, Renderer& renderer)
    -> void {
  auto j = ParseData(resp);
  auto& out = renderer.Out();

  Table id;
  AddColumn(id, "FIELD", Align::Left, Priority::High);
  AddColumn(id, "VALUE", Align::Left, Priority::High);
  auto row = [&](const std::string& k, const std::string& v,
                 Semantic s = Semantic::Default) {
    AddRow(id, {Cell{k, Semantic::Info}, Cell{v, s}});
  };
  const bool active = j.value("active", false);
  row("mac", j.value("mac", ""), Semantic::Emphasis);
  row("address", j.value("address", ""),
      active ? Semantic::Good : Semantic::Dim);
  auto host = j.value("hostname", "");
  row("hostname", host.empty() ? "(none)" : host);
  auto zone = j.value("zone", "");
  row("zone", zone.empty() ? "(no declared subnet covers it)" : zone,
      zone.empty() ? Semantic::Warn : Semantic::Default);
  row("lease", active ? std::format("holds a lease, {} left",
                                    Age(j.value("expires_in", 0)))
                      : "no current lease",
      active ? Semantic::Good : Semantic::Warn);
  row("first seen",
      (j.value("first_seen_exact", false) ? "" : ">=") +
          Age(j.value("first_seen_age", 0)) + " ago",
      j.value("new", false) ? Semantic::Good : Semantic::Default);
  row("last seen", Age(j.value("last_seen_age", 0)) + " ago");
  if (j.value("reserved", false)) {
    auto reserved = j.value("reserved_address", "");
    bool matches = reserved == j.value("address", "");
    row("reservation",
        matches ? reserved
                : std::format("{} (not in effect yet — the client "
                              "keeps {} until it renews)",
                              reserved, j.value("address", "")),
        matches ? Semantic::Good : Semantic::Warn);
  } else {
    row("reservation", "none — the address may change",
        Semantic::Dim);
  }
  auto moves = j.value("address_changes", 0);
  if (moves > 0) {
    row("address changes", std::to_string(moves),
        moves > 2 ? Semantic::Warn : Semantic::Default);
  }
  RenderFormatted(id, renderer);

  // -- what it is talking to
  out << "\n";
  const bool flows_ok = j.value("flows_available", false);
  if (!flows_ok) {
    RenderNote(
        "FLOWS", "unknown — fd could not be asked",
        std::format("{}. This is not the same as a device that is "
                    "talking to nobody: with fd down there is no "
                    "connection table to read.",
                    j.value("flows_detail", "fd is not running")),
        Semantic::Bad, renderer);
  }
  auto flows = j.value("flows", json::array());
  if (!flows_ok) flows = json::array();
  if (flows_ok && flows.empty()) {
    RenderNote("FLOWS",
               "fd is tracking no connections for this device",
               j.value("translated", false)
                   ? "fd answered. Its conntrack table has no entry "
                     "for this device's address, nor for any of the "
                     "translated endpoints NAT says belong to it."
                   : "fd answered; its conntrack table has no entry "
                     "whose source or destination is this address.",
               Semantic::Dim, renderer);
  } else if (flows_ok) {
    Table t;
    AddColumn(t, "DIR", Align::Left, Priority::Medium);
    AddColumn(t, "PROTO", Align::Left, Priority::Medium);
    AddColumn(t, "PEER", Align::Left, Priority::High);
    AddColumn(t, "LOCAL PORT", Align::Right, Priority::Low);
    AddColumn(t, "VIA", Align::Left, Priority::Medium);
    AddColumn(t, "STATE", Align::Left, Priority::High);
    AddColumn(t, "PACKETS", Align::Right, Priority::Medium);
    AddColumn(t, "IDLE", Align::Right, Priority::High);
    for (const auto& f : flows) {
      auto state = f.value("state", "");
      auto sem = state == "established" ? Semantic::Good
                 : state == "invalid"   ? Semantic::Bad
                                        : Semantic::Warn;
      auto idle = f.value("idle", -1);
      AddRow(t, {
          Cell{f.value("direction", ""), Semantic::Info},
          Cell{f.value("proto", "")},
          Cell{std::format("{}:{}", f.value("peer", ""),
                           f.value("peer_port", 0))},
          Cell{std::to_string(f.value("local_port", 0))},
          // Behind a masquerade the addresses conntrack carries are
          // the gateway's; this row was matched through the NAT
          // table, and saying so is the difference between a number
          // the operator trusts and one he has to work out.
          Cell{f.value("translated", false) ? "nat" : "direct",
               f.value("translated", false) ? Semantic::Warn
                                            : Semantic::Default},
          Cell{state, sem},
          Cell{std::to_string(f.value("packets", 0))},
          Cell{idle < 0 ? "-" : Age(idle),
               idle > 60 ? Semantic::Dim : Semantic::Default},
      });
    }
    RenderFormatted(t, renderer);

    auto peers = j.value("top_peers", json::array());
    if (!peers.empty()) {
      out << "\n";
      Table p;
      AddColumn(p, "TALKING TO", Align::Left, Priority::High);
      AddColumn(p, "PACKETS", Align::Right, Priority::High);
      AddColumn(p, "SHARE", Align::Left, Priority::Medium);
      auto total = j.value("packets", 0ULL);
      for (const auto& e : peers) {
        auto n = e.value("packets", 0ULL);
        double share = total > 0 ? static_cast<double>(n) /
                                       static_cast<double>(total)
                                 : 0.0;
        // A bar, not a sparkline: this is a share of one snapshot,
        // and a sparkline would imply a series over time that we do
        // not have.
        auto width = static_cast<int>(share * 20.0 + 0.5);
        AddRow(p, {
            Cell{e.value("peer", ""), Semantic::Emphasis},
            Cell{std::to_string(n)},
            Cell{std::string(static_cast<std::size_t>(width), '#') +
                     std::format(" {:.0f}%", share * 100.0),
                 Semantic::Info},
        });
      }
      RenderFormatted(p, renderer);
    }
  }

  if (!j.value("nat_available", true)) {
    out << "\n";
    RenderNote("NAT", "unknown — fd could not be asked",
               j.value("nat_detail", ""), Semantic::Bad, renderer);
    return;
  }
  auto nat = j.value("nat", json::array());
  if (!nat.empty()) {
    out << "\n";
    Table t;
    AddColumn(t, "NAT", Align::Left, Priority::High);
    AddColumn(t, "ORIGINAL", Align::Left, Priority::High);
    AddColumn(t, "TRANSLATED", Align::Left, Priority::High);
    for (const auto& n : nat) {
      AddRow(t, {
          Cell{n.value("type", ""), Semantic::Warn},
          Cell{std::format("{}:{} -> {}:{}",
                           n.value("orig_src", ""),
                           n.value("orig_src_port", 0),
                           n.value("orig_dst", ""),
                           n.value("orig_dst_port", 0))},
          Cell{std::format("{}:{}", n.value("new_addr", ""),
                           n.value("new_port", 0)),
               Semantic::Good},
      });
    }
    RenderFormatted(t, renderer);
  }
}

auto RenderReservation(const Response& resp, Renderer& renderer)
    -> void {
  auto j = ParseData(resp);
  if (RenderDiagnostics(j, renderer)) return;
  Table t;
  AddColumn(t, "FIELD", Align::Left, Priority::High);
  AddColumn(t, "VALUE", Align::Left, Priority::High);
  AddRow(t, {Cell{"action", Semantic::Info},
             Cell{j.value("action", "")}});
  AddRow(t, {Cell{"mac", Semantic::Info}, Cell{j.value("mac", "")}});
  if (j.contains("address")) {
    AddRow(t, {Cell{"address", Semantic::Info},
               Cell{j.value("address", ""), Semantic::Good}});
  }
  if (!j.value("zone", "").empty()) {
    AddRow(t, {Cell{"zone", Semantic::Info},
               Cell{j.value("zone", "")}});
  }
  AddRow(t, {Cell{"written to", Semantic::Info},
             Cell{j.value("config", "")}});
  // Writing the system configuration and making dnsmasq answer to it
  // are two different events. Through f-confd both happened; without
  // it only the first did, and calling that "applied" would be the
  // same class of overclaim as reporting a reload that never ran.
  const bool applied = j.value("applied", false);
  const bool live = j.value("via", "") == "f-confd";
  AddRow(t, {Cell{"state", Semantic::Info},
             Cell{!applied         ? "not written"
                  : live           ? "written and live (f-confd)"
                                   : "written, not yet live",
                  !applied ? Semantic::Bad
                  : live   ? Semantic::Good
                           : Semantic::Warn}});
  RenderFormatted(t, renderer);
  if (applied && !live) {
    for (const auto& l : Wrap(
             "f-confd is not running, so nothing regenerated "
             "dnsmasq's config: the reservation is recorded but the "
             "server does not know about it yet. Run `apply system` "
             "to make it live.",
             renderer.Caps().width)) {
      Prose(renderer) << l << "\n";
    }
  }
  if (!j.value("note", "").empty()) {
    for (const auto& l :
         Wrap(j.value("note", ""), renderer.Caps().width)) {
      Prose(renderer) << l << "\n";
    }
  }
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
  // "in the configuration" and "on the wire" are different claims, so
  // they get different rows.
  if (j.contains("via")) {
    row("applied via", j["via"].get<std::string>(),
        j["via"] == "f-confd" ? Semantic::Good : Semantic::Warn);
  }
  if (j.contains("commit_id") &&
      !j["commit_id"].get<std::string>().empty()) {
    row("revision", j["commit_id"].get<std::string>());
  }
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

/// Diagnostics render the way FWL renders a bad policy: named,
/// located, refused — and never collapsed into "invalid config".
auto RenderDiagnostics(const json& j, Renderer& renderer) -> bool {
  auto diags = j.value("diagnostics", json::array());
  if (diags.empty()) return false;
  auto& out = renderer.Out();
  for (const auto& d : diags) {
    out << d.value("text", "") << "\n";
  }
  return true;
}

auto RenderShowSystem(const Response& resp, Renderer& renderer)
    -> void {
  auto j = ParseData(resp);
  auto& out = renderer.Out();

  // First, because somebody reconnecting after a confirmed apply has a
  // deadline running whether or not they came here to look for one.
  auto confirm = j.value("confirm", json::object());
  if (confirm.value("pending", false)) {
    out << "CONFIRM PENDING — "
        << confirm.value("seconds_remaining", "?")
        << "s left on revision "
        << confirm.value("commit", "?")
        << ". Run `confirm system` to keep this configuration, or "
           "wait and the previous one is restored.\n\n";
  }

  Table zt;
  AddColumn(zt, "ZONE", Align::Left, Priority::High);
  AddColumn(zt, "INTERFACES", Align::Left, Priority::High);
  AddColumn(zt, "SERVICES", Align::Left, Priority::Medium);
  AddColumn(zt, "IPV6", Align::Left, Priority::Low);
  for (const auto& z : j.value("zones", json::array())) {
    auto ifaces = JoinStrings(z.value("interfaces", json::array()));
    bool has = z.value("services", false);
    AddRow(zt, {
        Cell{z.value("zone", ""), Semantic::Emphasis},
        Cell{ifaces.empty() ? "(none)" : ifaces,
             ifaces.empty() ? Semantic::Warn : Semantic::Default},
        Cell{z.value("dhcp", false) ? "dhcp+dns"
             : has                  ? "dns"
                                    : "-",
             has ? Semantic::Good : Semantic::Dim},
        Cell{z.value("ipv6", "off"), Semantic::Dim},
    });
  }
  RenderFormatted(zt, renderer);
  out << "\n";

  Table it;
  AddColumn(it, "INTERFACE", Align::Left, Priority::High);
  AddColumn(it, "PINNED TO", Align::Left, Priority::High);
  AddColumn(it, "ADDRESS", Align::Left, Priority::High);
  AddColumn(it, "ZONE", Align::Left, Priority::High);
  AddColumn(it, "PRESENT", Align::Left, Priority::Medium);
  for (const auto& i : j.value("interfaces", json::array())) {
    auto match = i.value("match", "");
    auto mode = i.value("mode", "none");
    auto addr = mode == "static" ? i.value("address", "") : mode;
    bool present = i.value("present", false);
    AddRow(it, {
        Cell{i.value("name", ""), Semantic::Emphasis},
        Cell{match.empty() ? "(unpinned)" : match,
             match.empty() ? Semantic::Bad : Semantic::Dim},
        Cell{addr, mode == "dhcp" ? Semantic::Warn
                                  : Semantic::Default},
        Cell{i.value("zone", "").empty() ? "(none)"
                                         : i.value("zone", "")},
        Cell{present ? "yes" : "no",
             present ? Semantic::Good : Semantic::Warn},
    });
  }
  RenderFormatted(it, renderer);
  out << "\n";

  // The derived placement is the answer to "where will a service
  // actually answer" — shown because it is computed, not configured.
  Table pt;
  AddColumn(pt, "DERIVED", Align::Left, Priority::High);
  AddColumn(pt, "INTERFACES", Align::Left, Priority::High);
  auto row = [&](const char* label, const char* key, Semantic sem) {
    auto v = JoinStrings(j.value(key, json::array()));
    AddRow(pt, {Cell{label, Semantic::Info},
                Cell{v.empty() ? "(none)" : v, sem}});
  };
  row("services listen on", "listen", Semantic::Good);
  row("dhcp answers on", "dhcp_on", Semantic::Good);
  row("excluded", "excluded", Semantic::Dim);
  RenderFormatted(pt, renderer);

  if (RenderDiagnostics(j, renderer)) {
    if (!j.value("ok", true)) {
      out << "\nrefused: fix the errors above, then "
             "`apply system`\n";
    }
  }
}

auto RenderShowServices(const Response& resp, Renderer& renderer)
    -> void {
  auto j = ParseData(resp);
  Table t;
  AddColumn(t, "SERVICE", Align::Left, Priority::High);
  AddColumn(t, "STATE", Align::Left, Priority::High);
  AddColumn(t, "ZONES", Align::Left, Priority::High);
  AddColumn(t, "ANSWERS ON", Align::Left, Priority::High);
  AddColumn(t, "UNIT", Align::Left, Priority::Low);
  for (const auto& s : j.value("services", json::array())) {
    auto state = s.value("state", "unknown");
    auto sem = s.value("healthy", false) ? Semantic::Good
               : state == "not configured" ? Semantic::Dim
                                           : Semantic::Bad;
    auto zones = JoinStrings(s.value("zones", json::array()));
    auto ifaces =
        JoinStrings(s.value("interfaces", json::array()));
    AddRow(t, {
        Cell{s.value("name", ""), Semantic::Emphasis},
        Cell{state, sem},
        Cell{zones.empty() ? "-" : zones},
        Cell{ifaces.empty() ? "(nowhere)" : ifaces,
             ifaces.empty() ? Semantic::Dim : Semantic::Default},
        Cell{s.value("unit", ""), Semantic::Dim},
    });
  }
  RenderFormatted(t, renderer);

  auto& out = renderer.Out();
  for (const auto& s : j.value("services", json::array())) {
    auto detail = s.value("detail", "");
    if (!detail.empty()) {
      out << "\n" << s.value("name", "") << ": " << detail << "\n";
    }
  }
  auto drift = j.value("drift", "none");
  if (drift == "hand-edited") {
    out << "\n" << j.value("artifact", "")
        << " was edited by hand. It is generated from the system "
           "config; fold the change back in, or `apply system "
           "force` to discard it.\n";
  } else if (drift == "stale") {
    out << "\n" << j.value("artifact", "")
        << " is older than the system config — run `apply "
           "system`.\n";
  }
}

/// The v6 stance as it stands on the box.
///
/// Two numbers per port, deliberately side by side: advertisements
/// that arrived, and addresses that were formed. Either alone is
/// ambiguous in exactly the direction that gets someone hurt — a
/// silent port is a gate holding *or* a network that never spoke, and
/// an address without a count is a bypass whose origin is unknown.
auto RenderShowIpv6(const Response& resp, Renderer& renderer)
    -> void {
  auto j = ParseData(resp);
  auto& out = renderer.Out();

  if (!j.value("observed", false)) {
    out << "no IPv6 observation: "
        << j.value("availability", "unknown") << "\n";
    return;
  }

  Table t;
  AddColumn(t, "INTERFACE", Align::Left, Priority::High);
  AddColumn(t, "ZONE", Align::Left, Priority::High);
  AddColumn(t, "STANCE", Align::Left, Priority::High);
  AddColumn(t, "RAS SEEN", Align::Right, Priority::High);
  AddColumn(t, "V6 FRAMES", Align::Right, Priority::Low);
  AddColumn(t, "ADDRESSES", Align::Left, Priority::High);
  for (const auto& i : j.value("interfaces", json::array())) {
    auto stance = i.value("stance", "off");
    auto addrs = JoinStrings(i.value("addresses", json::array()));
    bool bad = stance == "off" && !addrs.empty();
    if (!i.value("counters_read", false)) {
      // An unread counter is never rendered as a zero: the office
      // may be shouting advertisements at that port right now.
      AddRow(t, {
          Cell{i.value("interface", ""), Semantic::Emphasis},
          Cell{i.value("zone", "-")},
          Cell{stance, Semantic::Dim},
          Cell{"?", Semantic::Dim},
          Cell{"?", Semantic::Dim},
          Cell{"(device not present)", Semantic::Dim},
      });
      continue;
    }
    AddRow(t, {
        Cell{i.value("interface", ""), Semantic::Emphasis},
        Cell{i.value("zone", "-")},
        Cell{stance, stance == "off" ? Semantic::Default
                                     : Semantic::Warn},
        Cell{std::to_string(i.value("ras_received", 0ULL))},
        Cell{std::to_string(i.value("v6_received", 0ULL)),
             Semantic::Dim},
        Cell{addrs.empty() ? "(none)" : addrs,
             bad ? Semantic::Bad
                 : addrs.empty() ? Semantic::Dim
                                 : Semantic::Default},
    });
  }
  RenderFormatted(t, renderer);

  auto violations = j.value("violations", json::array());
  if (!violations.empty()) {
    out << "\n";
    for (const auto& v : violations) {
      out << "IPv6 STANCE VIOLATED: " << v.get<std::string>()
          << "\n";
    }
    out << "That port is carrying v6 the policy does not see. "
           "Re-run `apply system`, then find out what put it "
           "back.\n";
    return;
  }

  auto refused = j.value("refused_ras", 0ULL);
  out << "\n";
  if (refused > 0) {
    out << refused
        << " router advertisement(s) arrived on a zone whose "
           "stance is off, and were refused. Nothing "
           "autoconfigured.\n";
  } else {
    out << "no router advertisement has arrived on an off zone. "
           "That is a quiet network, not proof the gate works.\n";
  }
  out << "forwarding: " << (j.value("forwarding", false) ? "on"
                                                         : "off")
      << "\n";
}

/// The clock, and how much of it to believe.
auto RenderShowTime(const Response& resp, Renderer& renderer)
    -> void {
  auto j = ParseData(resp);
  auto& out = renderer.Out();

  auto banner = j.value("banner", "");
  if (!banner.empty()) out << banner << "\n";

  Table t;
  AddColumn(t, "FIELD", Align::Left, Priority::High);
  AddColumn(t, "VALUE", Align::Left, Priority::High);
  auto trust = j.value("trust", "unknown");
  bool ok = j.value("trustworthy", false);
  AddRow(t, {Cell{"trust", Semantic::Emphasis},
             Cell{trust, ok ? Semantic::Good : Semantic::Bad}});
  auto rtc = j.value("rtc", "unknown");
  auto rtc_name = j.value("rtc_name", "");
  AddRow(t, {Cell{"rtc"},
             Cell{rtc_name.empty() ? rtc : rtc + " — " + rtc_name,
                  rtc == "present" ? Semantic::Default
                                   : Semantic::Warn}});
  AddRow(t, {Cell{"wall clock"},
             Cell{FormatWallClock(j.value("wall_seconds", 0LL)),
                  j.value("implausible", false) ? Semantic::Bad
                                                : Semantic::Default}});
  // Always shown, and shown next to the wall clock on purpose:
  // uptime owes nothing to NTP, so it is the one ordering that still
  // works for anything stamped before the clock was set.
  AddRow(t, {Cell{"uptime"},
             Cell{FormatDuration(j.value("uptime_seconds", 0LL))}});
  auto ref = j.value("reference", "");
  if (!ref.empty()) AddRow(t, {Cell{"reference"}, Cell{ref}});
  RenderFormatted(t, renderer);

  auto detail = j.value("detail", "");
  if (!detail.empty()) out << "\n" << detail << "\n";
}

/// Disk, bundles, and what logging has already thrown away.
auto RenderShowStorage(const Response& resp, Renderer& renderer)
    -> void {
  auto j = ParseData(resp);
  auto& out = renderer.Out();

  auto banner = j.value("banner", "");
  if (!banner.empty()) out << banner << "\n";

  if (!j.value("observed", false)) {
    out << "no storage observation: "
        << j.value("availability", "unknown") << "\n";
    auto detail = j.value("detail", "");
    if (!detail.empty()) out << detail << "\n";
    return;
  }

  auto mib = [](std::uint64_t bytes) {
    return std::format("{} MiB", bytes / (1024 * 1024));
  };

  Table t;
  AddColumn(t, "WHAT", Align::Left, Priority::High);
  AddColumn(t, "VALUE", Align::Left, Priority::High);
  auto free_bytes = j.value("fs_free_bytes", 0ULL);
  auto total_bytes = j.value("fs_total_bytes", 0ULL);
  AddRow(t, {Cell{"free space", Semantic::Emphasis},
             Cell{std::format("{} of {}", mib(free_bytes),
                              mib(total_bytes)),
                  j.value("tight", false) ? Semantic::Bad
                                          : Semantic::Good}});
  auto over = j.value("bundles_over_policy", 0ULL);
  AddRow(t, {Cell{"compiled bundles"},
             Cell{std::format("{} using {} KiB",
                              j.value("bundle_count", 0ULL),
                              j.value("bundle_bytes", 0ULL) / 1024)}});
  AddRow(t, {Cell{"beyond the limit"},
             Cell{std::format("{} (keeping {})", over,
                              j.value("keep", 0ULL)),
                  over > 0 ? Semantic::Warn : Semantic::Dim}});
  // Never a bare zero: "no journal found" and "the journal is empty"
  // are different, and only one of them is reassuring.
  AddRow(t, {Cell{"journal"},
             j.value("journal_read", false)
                 ? Cell{mib(j.value("journal_bytes", 0ULL))}
                 : Cell{"(could not be read)", Semantic::Warn}});
  auto dropped = j.value("suppressed_messages", 0ULL);
  AddRow(t, {Cell{"dropped logs"},
             j.value("suppression_read", false)
                 ? Cell{std::format("{} suppression burst(s) in 24h",
                                    dropped),
                        dropped > 0 ? Semantic::Bad : Semantic::Good}
                 : Cell{"(could not be determined)",
                        Semantic::Warn}});
  RenderFormatted(t, renderer);

  if (over > 0) {
    out << "\n" << over
        << " bundle(s) are beyond the retention limit. fd prunes "
           "after each reload; `f-sysconf prune` does it now.\n";
  }
}

auto RenderCheckSystem(const Response& resp, Renderer& renderer)
    -> void {
  auto j = ParseData(resp);
  auto& out = renderer.Out();
  bool any = RenderDiagnostics(j, renderer);
  if (j.value("ok", false)) {
    if (any) out << "\n";
    out << "ok — " << j.value("config", "") << "\n";
  } else {
    out << "\nrefused — " << j.value("config", "") << "\n";
  }
}

auto RenderApplySystem(const Response& resp, Renderer& renderer)
    -> void {
  auto j = ParseData(resp);
  auto& out = renderer.Out();
  RenderDiagnostics(j, renderer);
  if (!j.value("applied", false)) {
    out << "\nrefused — nothing was changed\n";
    return;
  }
  auto via = j.value("via", "direct");
  if (via == "f-confd") {
    out << "applied via f-confd, revision "
        << j.value("commit_id", "?") << "\n";
  }
  for (const auto& p : j.value("written", json::array())) {
    out << "wrote " << p.get<std::string>() << "\n";
  }
  if (via == "direct" && j.value("written", json::array()).empty()) {
    out << "already up to date\n";
  }
  // The countdown is the only thing standing between the operator and
  // a box they cannot reach, so it goes first and it is loud.
  if (j.value("confirm_required", false)) {
    out << "\nCONFIRM WITHIN "
        << j.value("confirm_within_s", "?")
        << "s — run `confirm system`, or the previous "
           "configuration is restored automatically.\n";
  }
  auto note = j.value("note", "");
  if (!note.empty()) out << note << "\n";
  auto dhcp_on = JoinStrings(j.value("dhcp_on", json::array()));
  if (!dhcp_on.empty()) {
    out << "dhcp answers on: " << dhcp_on << "\n";
  }
}

auto RenderConfirmSystem(const Response& resp, Renderer& renderer)
    -> void {
  auto j = ParseData(resp);
  renderer.Out() << "confirmed — the change stays ("
                 << j.value("detail", "") << ")\n";
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
        MakeShowLeases(),
        MakeShowDevice(),
        MakeSetReservation(),
        MakeNoReservation(),
        Show("system", "show_system",
             "Interfaces, zones and where services will answer"),
        Show("services", "show_services",
             "DHCP/DNS health, and what they are bound to"),
        Show("storage", "show_storage",
             "Disk, compiled bundles, and whether log events are "
             "being dropped"),
        Show("time", "show_time",
             "The clock, whether it is synchronised, and whether "
             "this board can keep time across a power cut"),
        Show("ipv6", "show_ipv6",
             "Per-zone IPv6 stance: advertisements refused, and "
             "whether anything autoconfigured anyway"),
        MakeCheckSystem(),
        MakeApplySystem(),
        MakeApplySystemConfirmed(),
        MakeConfirmSystem(),
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
    } else if (wc == "show_leases") {
      RenderShowLeases(response, renderer);
    } else if (wc == "show_device") {
      RenderShowDevice(response, renderer);
    } else if (wc == "set_reservation" ||
               wc == "no_reservation") {
      RenderReservation(response, renderer);
    } else if (wc == "show_log") {
      RenderShowLog(response, renderer);
    } else if (wc == "show_system") {
      RenderShowSystem(response, renderer);
    } else if (wc == "show_services") {
      RenderShowServices(response, renderer);
    } else if (wc == "show_ipv6") {
      RenderShowIpv6(response, renderer);
    } else if (wc == "show_time") {
      RenderShowTime(response, renderer);
    } else if (wc == "show_storage") {
      RenderShowStorage(response, renderer);
    } else if (wc == "check_system") {
      RenderCheckSystem(response, renderer);
    } else if (wc == "apply_system" ||
               wc == "apply_system_confirmed") {
      RenderApplySystem(response, renderer);
    } else if (wc == "confirm_system") {
      RenderConfirmSystem(response, renderer);
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

  /// Which topics `watch <cmd>` should subscribe to.
  ///
  /// Only `show leases` has a live source behind it, and saying so
  /// here is what makes `watch show nat` fail with "adapter declared
  /// no topics" instead of sitting on a blank screen.
  auto EventTopicsFor(const CommandSpec& cmd) const
      -> std::vector<std::string> override {
    if (cmd.wire_command == "show_leases") return {"leases"};
    return {};
  }

  auto RenderEvent(const std::string& topic, const Event& event,
                   Renderer& renderer) const -> void override {
    if (topic != "leases") return;
    json j;
    try {
      j = json::parse(event.data.begin(), event.data.end());
    } catch (...) {
      return;
    }
    auto& out = renderer.Out();
    // What changed since the last frame, named. The table below is the
    // state; this line is the event, and it is the reason the operator
    // is watching at all.
    auto named = [&](const char* verb, const json& macs,
                     Semantic sem) {
      if (!macs.is_array() || macs.empty()) return;
      std::string list;
      for (const auto& m : macs) {
        if (!list.empty()) list += ", ";
        list += m.get<std::string>();
      }
      Table t;
      AddColumn(t, verb);
      AddRow(t, {Cell{list, sem}});
      RenderFormatted(t, renderer);
    };
    named("ARRIVED", j.value("arrived", json::array()),
          Semantic::Good);
    named("DEPARTED", j.value("departed", json::array()),
          Semantic::Warn);
    named("CHANGED ADDRESS", j.value("readdressed", json::array()),
          Semantic::Warn);

    // A genuine time series: one sample per poll, so the shape means
    // something. Kept short so it stays a hint rather than a chart.
    active_series_.push_back(
        static_cast<double>(j.value("active", 0)));
    if (active_series_.size() > 32) {
      active_series_.erase(active_series_.begin());
    }
    if (active_series_.size() > 1) {
      out << std::format(
          "{} device(s) leased  {}\n", j.value("active", 0),
          cli::render::Sparkline(active_series_, renderer.Caps()));
    }

    auto devices = j.value("devices", json::array());
    RenderLeaseCaveats(j, renderer, !devices.empty());
    if (devices.empty()) {
      RenderNoDevices(j, renderer);
      return;
    }
    RenderLeaseTable(j, renderer);
  }

 private:
  std::shared_ptr<Schema> schema_;
  /// Active-device count, one sample per watch event.
  mutable std::vector<double> active_series_;

  static auto MakeShowLeases() -> CommandSpec {
    CommandSpec c;
    c.path = "show leases";
    c.wire_command = "show_leases";
    c.help = "Devices that have taken a DHCP address: what they "
             "are, when they appeared, when they were last seen. "
             "`watch show leases` follows arrivals live.";
    c.args = {{
        .name = "filter",
        .help = "`new` for arrivals in the last 15 minutes, `all` "
                "to include devices with no current lease",
        .required = false,
    }};
    return c;
  }

  static auto MakeShowDevice() -> CommandSpec {
    CommandSpec c;
    c.path = "show device";
    c.wire_command = "show_device";
    c.help = "Everything known about one device: its lease, its "
             "zone, and the connections it currently has open";
    c.args = {{
        .name = "device",
        .help = "MAC address, IP address or hostname",
        .required = true,
    }};
    return c;
  }

  static auto MakeSetReservation() -> CommandSpec {
    CommandSpec c;
    c.path = "set reservation";
    c.wire_command = "set_reservation";
    c.help = "Pin a MAC to an address in the system configuration, "
             "so the board keeps it across reboots";
    c.role = RoleGate::OperatorOrAdmin;
    c.args = {
        {.name = "mac",
         .help = "Client hardware address",
         .required = true},
        {.name = "address",
         .help = "The address to reserve (must be in a DHCP zone's "
                 "subnet)",
         .required = true},
        {.name = "hostname",
         .help = "Optional name for the device",
         .required = false},
    };
    return c;
  }

  static auto MakeNoReservation() -> CommandSpec {
    CommandSpec c;
    c.path = "no reservation";
    c.wire_command = "no_reservation";
    c.help = "Remove a static reservation";
    c.role = RoleGate::OperatorOrAdmin;
    c.args = {{
        .name = "mac",
        .help = "Client hardware address",
        .required = true,
    }};
    return c;
  }

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

  static auto MakeCheckSystem() -> CommandSpec {
    CommandSpec c;
    c.path = "check system";
    c.wire_command = "check_system";
    c.help = "Validate the system configuration without "
             "applying it";
    c.role = RoleGate::AnyAuthenticated;
    return c;
  }

  static auto MakeApplySystem() -> CommandSpec {
    CommandSpec c;
    c.path = "apply system";
    c.wire_command = "apply_system";
    c.help = "Generate, validate and install the daemon configs "
             "from the system configuration";
    c.role = RoleGate::AdminOnly;
    // Deliberately NOT requires_session. The candidate this command
    // needs is f-confd's, which it opens itself; the CLI-side gate
    // added nothing but a `configure` to type first — and one-shot
    // invocations refuse session commands outright, which made
    // `einheit-f apply system confirmed 5` over SSH impossible. That
    // is the one context the command exists for.
    c.args = {{
        .name = "force",
        .help = "Pass 'force' to overwrite artifacts that were "
                "edited by hand",
        .required = false,
    }};
    return c;
  }

  static auto MakeApplySystemConfirmed() -> CommandSpec {
    CommandSpec c;
    c.path = "apply system confirmed";
    c.wire_command = "apply_system_confirmed";
    c.help = "Apply the system configuration and roll it back "
             "automatically unless `confirm system` is run within "
             "the window. Use this for any change that could cut "
             "your own access to the box.";
    c.role = RoleGate::AdminOnly;
    // See MakeApplySystem: no CLI-side session gate, so this works
    // from a single SSH command line.
    c.args = {
        {
            .name = "minutes",
            .help = "How long you have to confirm",
            .required = true,
        },
        {
            .name = "force",
            .help = "Pass 'force' to overwrite artifacts that "
                    "were edited by hand",
            .required = false,
        },
    };
    return c;
  }

  static auto MakeConfirmSystem() -> CommandSpec {
    CommandSpec c;
    c.path = "confirm system";
    c.wire_command = "confirm_system";
    c.help = "Keep the configuration applied by `apply system "
             "confirmed` — cancels the automatic rollback";
    c.role = RoleGate::AdminOnly;
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
    c.help = "Set an interface's address in the system "
             "configuration (accepts a CIDR or 'dhcp') and apply it";
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
