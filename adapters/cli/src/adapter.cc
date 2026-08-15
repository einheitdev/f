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

#include "f/counters.h"
#include "f/rules.h"

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
  // Three rows are gone from here and all three said the same thing on
  // every box: `maps [FAIL] unavailable` (nothing ever set
  // `maps_available` in this transport, so it read the default `false`
  // and painted a permanent red), `active_table A` and `rule_count 0`
  // (from `rules`, which fd derived from the v0.1 rule maps a bundle
  // does not have). A red row that is always red teaches the operator
  // to skip the column that exists to catch his eye. `show zones` is
  // where the loaded policy is, and `show policy` is where its rules
  // are.
  if (j.contains("pin_path")) {
    row("pin_path", j["pin_path"].get<std::string>());
  }
  if (j.contains("interfaces")) {
    auto& ifaces = j["interfaces"];
    if (ifaces.contains("count")) {
      row("interfaces", jstr(ifaces["count"]));
    }
  }
  if (j.contains("conntrack")) {
    auto& ct = j["conntrack"];
    if (ct.value("enabled", false) && ct.contains("entries")) {
      row("conntrack", std::format("{} flows (timeout {}s)",
                                   jstr(ct["entries"]),
                                   jstr(ct["timeout_s"])));
    }
  }
  // NAT was the one table with no collector behind it AND no line
  // here, which is why "new connections hang, old ones are fine" was
  // undiagnosable from the CLI. Occupancy is coloured, because the
  // number only means something against the cap, and any refusal is
  // Bad — a refusal is a dropped packet.
  if (j.contains("nat") && j["nat"].value("enabled", false)) {
    auto& n = j["nat"];
    auto pct = n.value("occupancy_pct", 0U);
    auto sem = pct >= 90   ? Semantic::Bad
               : pct >= 80 ? Semantic::Warn
                           : Semantic::Good;
    row("nat_mappings",
        std::format("{} / {} ({}%, peak {})", jstr(n["entries"]),
                    jstr(n["max_entries"]), pct,
                    jstr(n["high_water"])),
        sem);
    row("nat_reclaimed", jstr(n["total_reclaimed"]));
    auto refused = n.value("refused", uint64_t{0});
    if (refused > 0) {
      row("nat_refused",
          std::format("{} (packets DROPPED; {} were the table full)",
                      refused, jstr(n["table_full"])),
          Semantic::Bad);
    }
    auto realloc = n.value("port_reallocated", uint64_t{0});
    if (realloc > 0) {
      row("nat_port_moved", std::to_string(realloc), Semantic::Info);
    }
    // What each masquerading zone translates to, named by zone.
    //
    // One line per zone even when there is one zone, because the shape
    // is the point: two inside zones leaving through DIFFERENT uplinks
    // have two masquerade addresses, and until this map became per
    // zone they silently shared one — the last zone loaded decided for
    // all of them, and nothing on this screen could have said so.
    auto sources = n.value("masq_sources", json::array());
    for (const auto& s : sources) {
      row(std::format("nat_masquerade[{}]",
                      s.value("zone", std::string{})),
          s.value("address", std::string{}), Semantic::Info);
    }
    if (n.value("masq_source_is_bundle_wide", false)) {
      row("nat_masquerade",
          "ONE address for the whole bundle (compiled by an older "
          "fwl) — recompile if zones use different uplinks",
          Semantic::Warn);
    }
    // Shown whenever anything has been de-NAT'd at all, INCLUDING at
    // zero. Every other row here is hidden when idle because idle is
    // the good state; this one is the opposite. A masquerading box
    // carrying return traffic and translating no ICMP errors is the
    // path-MTU black hole, and its whole difficulty is that it looks
    // like nothing: large transfers hang, every counter climbs, and
    // no line anywhere says why.
    auto denat = n.value("denat", uint64_t{0});
    if (denat > 0) {
      auto icmp_err = n.value("icmp_error", uint64_t{0});
      row("nat_icmp_errors",
          std::format("{} of {} return translations", icmp_err, denat),
          icmp_err > 0 ? Semantic::Good : Semantic::Info);
    }
  }
  // A forward either went out addressed to a next hop this box
  // resolved, or it went out carrying the MAC it arrived with. Nothing
  // on the wire tells the two apart — a frame addressed to the wrong
  // MAC is on the cable, in the capture, and dropped by the far side's
  // NIC before any socket sees it — so this row is the operator's only
  // view of it. Shown from the first forward onward, including when
  // `routed` is zero, because zero-routed is the failure.
  if (j.contains("route") && j["route"].value("enabled", false)) {
    auto& rt = j["route"];
    auto routed = rt.value("routed", uint64_t{0});
    auto bridged = rt.value("bridged", uint64_t{0});
    if (routed > 0 || bridged > 0) {
      row("forwards",
          std::format("{} routed / {} L2-adjacent", routed, bridged),
          routed > 0 ? Semantic::Good : Semantic::Info);
    }
    auto no_route = rt.value("no_route", uint64_t{0});
    if (no_route > 0) {
      row("route_unreachable",
          std::format("{} (packets DROPPED)", no_route), Semantic::Bad);
    }
    auto no_neigh = rt.value("no_neigh", uint64_t{0});
    if (no_neigh > 0) {
      row("route_no_neighbour",
          std::format("{} (next hop not in the ARP table)", no_neigh),
          Semantic::Warn);
    }
    auto off_zone = rt.value("off_zone", uint64_t{0});
    if (off_zone > 0) {
      row("route_off_zone",
          std::format("{} (route leaves via another interface)",
                      off_zone),
          Semantic::Info);
    }
    auto ttl = rt.value("ttl_expired", uint64_t{0});
    if (ttl > 0) {
      row("route_ttl_expired", std::to_string(ttl), Semantic::Info);
    }
  }
  // Flows the BOX ITSELF starts. Rendered whenever the policy asks a
  // conntrack question at all — including when the answer is "no
  // tracker" — because that is the state in which the appliance's own
  // DNS, NTP and updates are dropped by its own policy, and every other
  // line on this box reads healthy while it is true.
  if (j.contains("egress") &&
      (j["egress"].value("tracker_declared", false) ||
       j["egress"].value("bundle_predates_tracker", false))) {
    auto& eg = j["egress"];
    if (eg.value("enabled", false)) {
      auto ifaces = eg.value("interfaces", json::array());
      std::string names;
      for (const auto& n : ifaces) {
        if (!names.empty()) names += ",";
        names += n.get<std::string>();
      }
      auto attached = eg.value("attached", uint32_t{0});
      if (attached < ifaces.size()) {
        // The daemon attached to more ports than the kernel now
        // carries: somebody removed a filter behind it. Reported as the
        // failure it is, because on those ports the box's own flows are
        // untracked again.
        row("own_flows_tracked",
            std::format("{} of {} ports lost the egress hook — the "
                        "box's own flows are untracked there",
                        ifaces.size() - attached, ifaces.size()),
            Semantic::Bad);
      } else {
        row("own_flows_tracked",
            std::format("{} flows on {}",
                        jstr(eg["tracked"]), names),
            Semantic::Good);
      }
      auto refused = eg.value("refused", uint64_t{0});
      if (refused > 0) {
        // The one way this can stop working, and it looks like nothing:
        // conntrack full, the query still goes out, the reply still
        // arrives, and `default drop` eats it.
        row("own_flows_untracked",
            std::format("{} (conntrack full; their replies WILL be "
                        "dropped)", refused),
            Semantic::Bad);
      }
    } else if (eg.value("bundle_predates_tracker", false)) {
      // The honest wording for the one thing an old manifest cannot
      // answer. It carries `conntrack` whether the policy reads the
      // state or merely masquerades, so claiming the box's DNS is
      // being dropped would be a false red on every healthy NAT gateway
      // — and a red row an operator learns to ignore is worse than no
      // row.
      row("own_flows_tracked",
          "unknown — this bundle predates egress tracking; if its "
          "policy reads conntrack(pkt).state its own DNS, NTP and "
          "update replies are being dropped (recompile to find out)",
          Semantic::Warn);
    } else {
      row("own_flows_tracked",
          "no — this bundle declares a tracker and none is attached",
          Semantic::Bad);
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
  // One line per masquerading zone. A box whose inside zones leave
  // through different uplinks has more than one masquerade source, and
  // a single line could only ever name one of them — which is the
  // failure this map was split to remove, so the report must not
  // reintroduce it. `masq_source` remains for the one-uplink case and
  // is what the older single line said.
  auto& out = renderer.Out();
  auto sources = j.value("masq_sources", json::array());
  if (sources.size() > 1) {
    for (const auto& s : sources) {
      out << "masquerade source: "
          << s.value("address", std::string{}) << " (zone "
          << s.value("zone", std::string{}) << ")\n";
    }
  } else if (j.contains("masq_source")) {
    out << "masquerade source: "
        << j["masq_source"].get<std::string>() << "\n";
  }
  if (j.value("masq_source_is_bundle_wide", false)) {
    out << "  note: this bundle predates the per-zone masquerade "
           "address and holds ONE for the whole bundle; recompile the "
           "policy if its zones leave through different uplinks\n";
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

/// Where prose goes: the terminal in table mode, stderr otherwise, so
/// a pipe stays parseable and the operator is still told. Defined
/// below, beside the renderers that established the rule.
auto Prose(Renderer& renderer) -> std::ostream&;

/// One word for a zone whose counters are not simply readable.
///
/// The vocabulary is fd's, mapped rather than passed through, so a
/// token this build has no word for reads as an unknown state instead
/// of being printed raw at the operator. The mapping itself lives in
/// `f/counters.h` because the web UI renders the same states and the
/// two surfaces must not drift into two vocabularies for one fact.
auto CounterStateWord(const std::string& availability) -> std::string {
  return std::string(::f::CounterStateWord(
      ::f::CounterAvailabilityFromName(availability)));
}

/// `show counters` — the loaded policy's named `count` statements.
///
/// The rule this renderer exists to keep is the one the removed v0.1
/// counter page broke: every empty answer says WHICH kind of empty it
/// is. A counter that read zero and a counter whose map could not be
/// read look nothing alike here, and a zone that could not be read at
/// all still occupies a row — vanishing from the table is how a
/// firewall with unreadable counters comes to look like a firewall
/// with none.
auto RenderShowCounters(const Response& resp,
                        Renderer& renderer) -> void {
  auto j = ParseData(resp);
  auto zones = j.value("zones", json::array());
  auto query = j.value("query", std::string{});

  if (!query.empty()) {
    auto verdict = j.value("verdict", std::string{});
    // The two negative verdicts still render a table, so `--format
    // json` carries the answer rather than an empty stream — and the
    // two answers are different rows, not one blank.
    if (verdict == "no_such_name" || verdict == "cannot_tell") {
      auto blind = JoinStrings(
          j.value("unsearchable_zones", json::array()));
      Table t;
      AddColumn(t, "COUNTER", Align::Left, Priority::High);
      AddColumn(t, "RESULT", Align::Left, Priority::High);
      AddRow(t, {
          Cell{query, Semantic::Emphasis},
          Cell{verdict == "no_such_name" ? "no such counter"
                                         : "cannot tell",
               Semantic::Bad},
      });
      RenderFormatted(t, renderer);
      auto& out = Prose(renderer);
      if (verdict == "no_such_name") {
        out << "no counter named '" << query
            << "' — the loaded policy declares none by that name\n"
            << "hint: `show counters` lists every counter it "
               "declares\n";
      } else {
        out << "cannot say whether a counter named '" << query
            << "' exists\n";
        out << "  '" << query << "' was not found in what could be "
            << "read, and the counter names of "
            << (blind.empty() ? std::string("some zones") : blind)
            << " could not be read at all — so this is not the same "
               "as 'there is no such counter'\n";
      }
      return;
    }
  }

  if (!zones.is_array() || zones.empty()) {
    Table t;
    AddColumn(t, "COUNTERS");
    AddRow(t, {Cell{"fd reports no zone programs loaded",
                    Semantic::Warn}});
    RenderFormatted(t, renderer);
    return;
  }

  Table t;
  AddColumn(t, "ZONE", Align::Left, Priority::High);
  AddColumn(t, "COUNTER", Align::Left, Priority::High);
  AddColumn(t, "PACKETS", Align::Right, Priority::High);
  std::vector<std::string> notes;
  for (const auto& z : zones) {
    auto zone = z.value("zone", "");
    auto availability = z.value("availability", "");
    auto detail = z.value("detail", "");
    auto rows = z.value("counters", json::array());
    if (availability != "read") {
      AddRow(t, {
          Cell{zone, Semantic::Emphasis},
          Cell{"(" + CounterStateWord(availability) + ")",
               availability == "none_declared" ? Semantic::Dim
                                               : Semantic::Bad},
          Cell{"-", Semantic::Dim},
      });
      if (!detail.empty()) {
        notes.push_back(std::format("{}: {}", zone, detail));
      }
      continue;
    }
    if (rows.empty()) {
      // kRead with nothing in it should not happen — a zone with no
      // counters is `none_declared` — so say that rather than draw a
      // blank.
      AddRow(t, {
          Cell{zone, Semantic::Emphasis},
          Cell{"(read, but no counters returned)", Semantic::Bad},
          Cell{"-", Semantic::Dim},
      });
      continue;
    }
    for (const auto& c : rows) {
      bool read = c.value("read", false);
      auto packets = c.value("packets", std::uint64_t{0});
      AddRow(t, {
          Cell{zone, Semantic::Emphasis},
          Cell{c.value("name", ""), Semantic::Info},
          // A slot that could not be read renders as a word, never as
          // a zero. "Nothing hit this rule" and "nobody could ask" are
          // the two answers an operator must never see spelled the
          // same way.
          read ? Cell{std::to_string(packets),
                      packets > 0 ? Semantic::Good : Semantic::Dim}
               : Cell{"unreadable", Semantic::Bad},
      });
    }
    if (!detail.empty()) {
      notes.push_back(std::format("{}: {}", zone, detail));
    }
  }
  RenderFormatted(t, renderer);
  for (const auto& n : notes) {
    Prose(renderer) << n << "\n";
  }
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
    // The generated config now *is* rewritten on this path — that
    // was the half `set reservation` used to leave out entirely. What
    // is still missing without f-confd is the restart that makes
    // dnsmasq read it, and that is what the sentence has to say.
    for (const auto& l : Wrap(
             "f-confd is not running: the reservation is in the "
             "model and in dnsmasq's generated config, but nothing "
             "restarted dnsmasq, so the running server has not read "
             "it. `systemctl restart f-dnsmasq`, or start f-confd "
             "and run `apply system`.",
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
  // A refused edit comes back Ok with `applied: false` and the
  // validation findings beside it. Rendering only the table turned a
  // named diagnostic — `SC031: zone 'dmz' asks for `ra` and no
  // interface in it carries a v6 prefix` — into a row reading
  // `applied: no`, which is the outcome without the reason.
  if (!j.value("applied", true) &&
      RenderDiagnostics(j, renderer)) {
    renderer.Out() << "nothing was changed\n";
    return;
  }
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
  if (j.contains("zone")) {
    row("zone", j["zone"].get<std::string>(), Semantic::Emphasis);
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
  if (j.contains("activated")) {
    bool live = j["activated"].get<bool>();
    row("reloaded", live ? "yes" : "no",
        live ? Semantic::Good : Semantic::Warn);
  }
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
  if (j.contains("activation_note")) {
    row("note", j["activation_note"].get<std::string>(),
        Semantic::Warn);
  }
  if (j.contains("note")) {
    row("note", j["note"].get<std::string>(), Semantic::Info);
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
    // PRESENT answers "is the port in the PINNED TO column here",
    // which is the only question the column can honestly ask. It used
    // to compare names, and so read `no` for a port that was present,
    // powered and correctly identified one column to the left — wrong
    // at exactly the moment it matters, before the rename.
    auto presence = i.value("presence", "?");
    auto current = i.value("current_name", "");
    auto shown = presence == "pending rename" && !current.empty()
                     ? std::format("pending rename (now {})", current)
                     : presence;
    auto sem = presence == "yes"          ? Semantic::Good
               : presence == "?"          ? Semantic::Dim
               : presence == "WRONG PORT" ? Semantic::Bad
                                          : Semantic::Warn;
    AddRow(it, {
        Cell{i.value("name", ""), Semantic::Emphasis},
        Cell{match.empty() ? "(unpinned)" : match,
             match.empty() ? Semantic::Bad : Semantic::Dim},
        Cell{addr, mode == "dhcp" ? Semantic::Warn
                                  : Semantic::Default},
        Cell{i.value("zone", "").empty() ? "(none)"
                                         : i.value("zone", "")},
        Cell{shown, sem},
    });
  }
  RenderFormatted(it, renderer);
  if (!j.value("ports_read", true)) {
    out << "the port table could not be read ("
        << j.value("ports_detail", "no reason given")
        << "), so PRESENT is unknown rather than no\n";
  }
  for (const auto& p : j.value("pending", json::array())) {
    out << "\n" << p.value("detail", "") << "\n";
  }
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

/// What a service is doing, as distinct from what it was told to do.
///
/// `BOUND TO` is intent, re-derived from the model. `ANSWERS ON` is
/// read out of the kernel's socket table. They are separate columns
/// because the whole failure this view exists to catch is the case
/// where they disagree — and while both were computed from the same
/// model, this table printed byte-identical output whether dnsmasq was
/// bound to lan0 or to nothing at all. A column that cannot disagree
/// with the config it reports on is not evidence.
auto RenderShowServices(const Response& resp, Renderer& renderer)
    -> void {
  auto j = ParseData(resp);
  Table t;
  AddColumn(t, "SERVICE", Align::Left, Priority::High);
  AddColumn(t, "STATE", Align::Left, Priority::High);
  AddColumn(t, "ZONES", Align::Left, Priority::High);
  AddColumn(t, "BOUND TO", Align::Left, Priority::Medium);
  AddColumn(t, "ANSWERS ON", Align::Left, Priority::High);
  AddColumn(t, "UNIT", Align::Left, Priority::Low);
  for (const auto& s : j.value("services", json::array())) {
    auto state = s.value("state", "unknown");
    bool mismatch = s.value("mismatch", false);
    auto sem = s.value("healthy", false) ? Semantic::Good
               : state == "not configured" ? Semantic::Dim
                                           : Semantic::Bad;
    auto zones = JoinStrings(s.value("zones", json::array()));
    auto want = JoinStrings(s.value("bound_to", json::array()));
    auto have = JoinStrings(s.value("answers_on", json::array()));
    std::string answers;
    Semantic answers_sem = Semantic::Default;
    if (!s.value("answers_known", false)) {
      // Never a blank and never a zero: an unanswerable question is
      // not the same answer as "nowhere".
      answers = "? (" + s.value("observed", "not observed") + ")";
      answers_sem = Semantic::Dim;
    } else if (!have.empty()) {
      answers = have;
      answers_sem = mismatch ? Semantic::Warn : Semantic::Good;
    } else if (s.value("loopback_only", false)) {
      answers = "LOOPBACK ONLY";
      answers_sem = Semantic::Bad;
    } else if (s.value("wildcard", false)) {
      answers = "every port (wildcard socket)";
      answers_sem = Semantic::Warn;
    } else {
      answers = "nothing";
      answers_sem = s.value("expected", false) ? Semantic::Bad
                                               : Semantic::Dim;
    }
    AddRow(t, {
        Cell{s.value("name", ""), Semantic::Emphasis},
        Cell{state, sem},
        Cell{zones.empty() ? "-" : zones},
        Cell{want.empty() ? "-" : want, Semantic::Dim},
        Cell{answers, answers_sem},
        Cell{s.value("unit", ""), Semantic::Dim},
    });
  }
  RenderFormatted(t, renderer);

  auto& out = renderer.Out();
  for (const auto& s : j.value("services", json::array())) {
    auto mismatch = s.value("mismatch_detail", "");
    if (!mismatch.empty()) {
      out << "\n" << s.value("name", "") << ": " << mismatch << "\n";
    }
    auto detail = s.value("detail", "");
    if (!detail.empty()) {
      out << "\n" << s.value("name", "") << ": " << detail << "\n";
    }
    auto listening = JoinStrings(s.value("listening", json::array()));
    if (!listening.empty() && s.value("wildcard", false)) {
      out << "\n" << s.value("name", "") << " sockets: " << listening
          << "\n  a wildcard socket (0.0.0.0/::) is on every port, so "
             "it is not evidence about any one of them. dnsmasq's "
             "DHCP socket is always one: DHCP containment is enforced "
             "per received packet, not by binding.\n";
    }
  }
  // The DNS setting whose failure mode is an internal name that
  // silently does not exist. It is stated here whichever way it is
  // set, because the symptom points nowhere near it.
  if (j.contains("rebind_protection")) {
    auto exempt = JoinStrings(j.value("rebind_exempt", json::array()));
    if (j.value("rebind_protection", false)) {
      out << "\nDNS rebind protection is ON"
          << (exempt.empty() ? ", exempting no domain"
                             : ", exempting " + exempt)
          << ". An upstream answer pointing into private address "
             "space is discarded and the client sees an empty answer "
             "with no error"
          << (exempt.empty()
                  ? " — every internal name in the building resolves "
                    "to nothing. List the internal domains under "
                    "`rebind_ok:`."
                  : ".")
          << "\n";
    } else {
      out << "\nDNS rebind protection is off: private-addressed "
             "answers are passed through, which is what an office's "
             "own names need.\n";
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

/// What this box has of the deployable set.
///
/// Rows for the items that are not fine, and nothing for the ones
/// that are — an operator running this wants the gap, not an
/// inventory. The verdict is printed as a word rather than inferred
/// from an empty table, because "everything is present" and "the
/// verifier could not look" produce the same empty table and mean
/// opposite things.
auto RenderShowInstall(const Response& resp, Renderer& renderer)
    -> void {
  auto j = ParseData(resp);
  auto& out = renderer.Out();
  auto verdict = j.value("verdict", "");
  auto items = j.value("items", json::array());

  Table t;
  AddColumn(t, "STATE", Align::Left, Priority::High);
  AddColumn(t, "ITEM", Align::Left, Priority::High);
  AddColumn(t, "WHERE", Align::Left, Priority::Medium);
  AddColumn(t, "NEEDED BY", Align::Left, Priority::Medium);
  int listed = 0;
  for (const auto& item : items) {
    auto state = item.value("state", "");
    if (state == "present") continue;
    ++listed;
    Semantic sem = Semantic::Warn;
    if (state == "missing" || state == "wrong-kind" ||
        state == "empty" || state == "conflict" ||
        state == "unusable") {
      sem = item.value("requirement", "") == "required"
                ? Semantic::Bad
                : Semantic::Warn;
    } else if (state == "not-checked") {
      sem = Semantic::Dim;
    }
    auto needed = item.value("needed_by", "");
    AddRow(t, {Cell{state, sem},
               Cell{item.value("id", ""), Semantic::Emphasis},
               Cell{item.value("dest", "")},
               Cell{needed.empty() ? "-" : needed, Semantic::Dim}});
  }
  if (listed > 0) RenderFormatted(t, renderer);

  // The sentence from the manifest, for the ones that actually stop
  // something working. An id and a path do not tell an operator what
  // it costs, and looking it up is a step nobody takes at 2 a.m.
  for (const auto& item : items) {
    auto state = item.value("state", "");
    if (state != "missing" && state != "wrong-kind" &&
        state != "empty" && state != "conflict" &&
        state != "unusable") {
      continue;
    }
    out << "\n" << item.value("id", "") << ": "
        << item.value("why", "") << "\n";
    auto detail = item.value("detail", "");
    if (!detail.empty()) out << "  " << detail << "\n";
    auto provided = item.value("provided_by", "");
    if (!provided.empty()) out << "  install: " << provided << "\n";
    auto when = item.value("required_when", "");
    if (!when.empty()) out << "  required when: " << when << "\n";
  }

  if (listed == 0) {
    out << "every item in the deployable set is present.\n";
  }
  out << "\nverdict: " << verdict << " (checked "
      << j.value("root", "/") << ", scope "
      << j.value("scope", "") << ")\n";
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
  // A removal is as load-bearing as a write here: two `.link` units
  // pinning one MAC to two names are decided by filename order, and
  // the leftover usually wins.
  for (const auto& p : j.value("removed", json::array())) {
    out << "removed " << p.get<std::string>()
        << " (its interface is no longer in the configuration)\n";
  }
  for (const auto& p : j.value("leftover", json::array())) {
    out << "LEFT IN PLACE " << p.get<std::string>()
        << " — we did not write it, so it is not ours to delete. "
           "It may still decide a port's name.\n";
  }
  if (via == "direct" && j.value("written", json::array()).empty() &&
      j.value("removed", json::array()).empty()) {
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
  // Last, and loudest: "applied" is a claim about files. If the ports
  // this configuration names do not exist yet, the box is not running
  // it, and saying so is the difference between an outage and a
  // firewall aimed at the wrong socket.
  auto pending_note = j.value("pending_note", "");
  if (!pending_note.empty()) {
    out << "\n" << pending_note << "\n";
  }
}

auto RenderConfirmSystem(const Response& resp, Renderer& renderer)
    -> void {
  auto j = ParseData(resp);
  renderer.Out() << "confirmed — the change stays ("
                 << j.value("detail", "") << ")\n";
}

/// The system-configuration revisions f-confd has recorded.
auto RenderShowCommits(const Response& resp, Renderer& renderer)
    -> void {
  auto j = ParseData(resp);
  auto commits = j.value("commits", json::array());
  if (commits.empty()) {
    renderer.Out() << "f-confd has recorded no revisions — nothing "
                      "has been applied through it on this box\n";
    return;
  }
  Table t;
  AddColumn(t, "ID", Align::Right, Priority::High);
  AddColumn(t, "BY", Align::Left, Priority::High);
  AddColumn(t, "AT", Align::Left, Priority::Medium);
  for (const auto& c : commits) {
    AddRow(t, {
        Cell{c.value("id", "")},
        Cell{c.value("by", "")},
        Cell{c.value("at", ""), Semantic::Dim},
    });
  }
  RenderFormatted(t, renderer);
  renderer.Out() << "these are " << j.value("scope", "revisions")
                 << " revisions; the policy has no revision history "
                    "— `configure` snapshots it and `rollback` puts "
                    "it back\n";
}

/// The policy source, block by block, numbered as `no rule` names it.
///
/// A table per zone for a person, because the numbering restarts per
/// block and one running sequence of row numbers beside restarting
/// indices is how `no rule lan 4` deletes the wrong statement.
///
/// One table with a ZONE column for a machine, because two JSON
/// arrays printed one after another are not a document, and the
/// position a row carries means nothing without the zone it counts
/// within.
/// What fd has LOADED, zone by zone, in policy order.
///
/// This table is the answer to "what is this box enforcing right now",
/// and every row in it came off the box: the compiler wrote each rule
/// into the bundle manifest, and the load that put the programs in the
/// packet path captured them beside the objects. Nothing here reads a
/// bundle directory.
///
/// There is no position column, deliberately. `no rule` numbers the
/// SOURCE statements, which include the `count` and `log` lines the
/// compiler folds away, so the two numberings are not the same — and a
/// second column of positions beside the first is how somebody deletes
/// a rule they were not looking at. Order is the meaning here; the
/// numbers live in the source table below.
auto RenderLoadedPolicy(const json& loaded, Renderer& renderer)
    -> void {
  auto& out = Prose(renderer);
  out << "LOADED — what fd has in the packet path\n";
  if (!loaded.value("answered", false)) {
    out << std::format(
        "  cannot read the loaded policy from fd: {}\n",
        loaded.value("error", "?"));
    return;
  }
  auto zones = loaded.value("zones", json::array());
  if (zones.empty()) {
    out << "  fd has no zone programs loaded — nothing of the policy "
           "is in the packet path\n";
    return;
  }
  for (const auto& z : zones) {
    const auto avail = ::f::RuleAvailabilityFromName(
        z.value("availability", std::string{}));
    out << std::format("zone {}\n", z.value("zone", "?"));
    auto rules = z.value("rules", json::array());
    if (avail != ::f::RuleAvailability::kListed || rules.empty()) {
      // A zone whose rules cannot be given still occupies its place,
      // with its own word for why. A zone that vanished here would be
      // how a box that cannot describe its policy comes to look like
      // a box with no policy.
      out << std::format("  ({})\n",
                         ::f::RuleStateWord(avail));
      auto detail = z.value("detail", std::string{});
      if (!detail.empty()) out << std::format("  {}\n", detail);
    } else {
      Table t;
      AddColumn(t, "ACTION", Align::Left, Priority::High);
      AddColumn(t, "MATCH", Align::Left, Priority::High);
      AddColumn(t, "LIMIT", Align::Left, Priority::Low);
      for (const auto& r : rules) {
        const bool terminal = r.value("terminal", false);
        const bool guarded = r.value("guarded", false);
        std::string match;
        if (!guarded) {
          match = ::f::UnguardedMatchWord(terminal);
        } else if (!r.value("renderable", true)) {
          // Never a blank, and never the empty string an unguarded
          // rule shows: "this rule matches everything" and "this
          // build cannot write down what this rule matches" are
          // opposite claims about a firewall.
          match = "(a guard this build cannot render)";
        } else {
          match = r.value("match", "");
        }
        AddRow(t, {
            Cell{r.value("action", ""),
                 terminal && !guarded ? Semantic::Warn
                                      : Semantic::Default},
            Cell{match, (!guarded && terminal) ? Semantic::Warn
                        : guarded              ? Semantic::Default
                                               : Semantic::Dim},
            Cell{r.value("rate_limit", ""), Semantic::Dim},
        });
      }
      RenderFormatted(t, renderer);
    }
    if (z.contains("default") && z["default"].is_object()) {
      const auto& d = z["default"];
      out << std::format(
          "  default {}{}\n", d.value("action", "?"),
          d.value("stated", false)
              ? ""
              : "  (no `default` line — the block falls through to "
                "ALLOW)");
    }
    out << "\n";
  }
}

auto RenderShowPolicy(const Response& resp, Renderer& renderer)
    -> void {
  auto j = ParseData(resp);
  auto blocks = j.value("blocks", json::array());
  // Machine-readable output owns stdout: under a machine format the
  // headings and the caveat go to stderr, so `| jq` gets a document
  // and the operator still gets told.
  auto& out = Prose(renderer);
  const bool machine_fmt =
      renderer.Format() != cli::render::OutputFormat::Table;
  if (!machine_fmt && j.contains("loaded")) {
    RenderLoadedPolicy(j["loaded"], renderer);
  }
  // No source on disk is not no policy: the machine document still
  // carries the loaded rows, and the reader still gets told the file
  // is missing. Only the human view can stop here.
  if (blocks.empty() && !machine_fmt) {
    if (j.contains("caveat")) {
      for (const auto& l :
           Wrap(j["caveat"].get<std::string>(),
                renderer.Caps().width)) {
        out << l << "\n";
      }
    } else {
      out << std::format(
          "no @xdp block in the policy at {}\n",
          j.value("source", "?"));
    }
    return;
  }
  if (!machine_fmt) {
    out << "SOURCE — the `.fw` files on disk; these are the positions "
           "`no rule` takes\n";
  }
  const bool machine = machine_fmt;

  /// An unguarded `allow` / `drop` / `masquerade` / `redirect` acts
  /// on everything that reaches it, so nothing below it can match.
  /// That is the single most expensive thing to misread in a policy,
  /// and it is what the MATCHES column is for.
  auto matches_of = [](const json& s) -> const char* {
    const bool guarded = s.value("guarded", false);
    const auto verb = s.value("verb", "other");
    const bool terminal =
        !guarded && (verb == "filter" || verb == "translate" ||
                     verb == "redirect" || verb == "default");
    // Three states, not two. A `count` with no guard also runs on
    // every packet, but it falls through — calling that the same
    // thing as an unguarded `drop` would put a warning beside the one
    // statement in the block that is harmless.
    if (terminal) return "every packet — stops here";
    return guarded ? "when it matches" : "every packet, falls through";
  };
  auto is_terminal = [](const json& s) {
    const auto verb = s.value("verb", "other");
    return !s.value("guarded", false) &&
           (verb == "filter" || verb == "translate" ||
            verb == "redirect" || verb == "default");
  };

  if (machine) {
    // ONE document, not two arrays printed one after another. Every
    // row says which of the two claims it belongs to: `loaded` is the
    // packet path as fd reports it, `source` is a statement in a file.
    //
    // A loaded row carries no POSITION, and that is the point. `no
    // rule` numbers the SOURCE statements — the compiler folds some of
    // them away and the default is not among them at all — so a
    // position taken from a loaded row would delete a statement
    // nobody was looking at. A blank cell is the only honest value.
    Table t;
    AddColumn(t, "KIND", Align::Left, Priority::High);
    AddColumn(t, "ZONE", Align::Left, Priority::High);
    AddColumn(t, "#", Align::Right, Priority::High);
    AddColumn(t, "STATEMENT", Align::Left, Priority::High);
    AddColumn(t, "MATCHES", Align::Left, Priority::High);
    AddColumn(t, "FILE", Align::Left, Priority::Low);
    auto row = [&](const std::string& kind, const std::string& zone,
                   const std::string& pos, const std::string& stmt,
                   const std::string& matches,
                   const std::string& file) {
      AddRow(t, {Cell{kind}, Cell{zone}, Cell{pos}, Cell{stmt},
                 Cell{matches}, Cell{file}});
    };
    if (j.contains("loaded")) {
      const auto& l = j["loaded"];
      if (!l.value("answered", false)) {
        row("loaded", "", "", "",
            "cannot read the loaded policy from fd: " +
                l.value("error", std::string("?")),
            "");
      }
      for (const auto& z : l.value("zones", json::array())) {
        const auto zone = z.value("zone", std::string{});
        const auto avail = ::f::RuleAvailabilityFromName(
            z.value("availability", std::string{}));
        auto rules = z.value("rules", json::array());
        if (avail != ::f::RuleAvailability::kListed || rules.empty()) {
          row("loaded", zone, "",
              std::format("({})", ::f::RuleStateWord(avail)),
              z.value("detail", std::string{}), "");
        }
        for (const auto& r : rules) {
          const bool guarded = r.value("guarded", false);
          row("loaded", zone, "", r.value("text", ""),
              guarded ? std::string("when it matches")
                      : std::string(::f::UnguardedMatchWord(
                            r.value("terminal", false))),
              "");
        }
        if (z.contains("default") && z["default"].is_object()) {
          const auto& d = z["default"];
          row("loaded", zone, "",
              std::format("default {}", d.value("action", "?")),
              d.value("stated", false)
                  ? "everything that reaches the end"
                  : "everything that reaches the end (no `default` "
                    "line — the block falls through)",
              "");
        }
      }
      // The verdict as a row, so a fleet check can read it without
      // parsing prose. A drift nobody can grep for is a drift nobody
      // finds.
      row("drift", "", "", l.value("drift", "cannot_tell"),
          l.value("drift_text", ""), l.value("compared_file", ""));
    }
    for (const auto& b : blocks) {
      for (const auto& s : b.value("statements", json::array())) {
        row("source", b.value("zone", ""),
            std::to_string(s.value("index", 0)), s.value("text", ""),
            matches_of(s), b.value("file", ""));
      }
    }
    RenderFormatted(t, renderer);
  } else {
    for (const auto& b : blocks) {
      out << std::format("zone {}  ({})\n",
                         b.value("zone", "?"), b.value("file", "?"));
      Table t;
      AddColumn(t, "#", Align::Right, Priority::High);
      AddColumn(t, "STATEMENT", Align::Left, Priority::High);
      // Medium: on a console too narrow for both, the statement text
      // wins. The warning this column carries is not lost with it —
      // an unconditional statement is rendered `Warn`, which the
      // plain-text renderer marks inline — and a rule the operator
      // cannot read is worse than one they cannot see annotated.
      AddColumn(t, "MATCHES", Align::Left, Priority::Medium);
      for (const auto& s : b.value("statements", json::array())) {
        const bool terminal = is_terminal(s);
        AddRow(t, {
            Cell{std::to_string(s.value("index", 0))},
            Cell{s.value("text", ""),
                 terminal ? Semantic::Warn : Semantic::Default},
            Cell{matches_of(s),
                 terminal ? Semantic::Warn : Semantic::Dim},
        });
      }
      RenderFormatted(t, renderer);
      out << "\n";
    }
  }
  if (j.contains("caveat")) {
    for (const auto& l :
         Wrap(j["caveat"].get<std::string>(),
              renderer.Caps().width)) {
      out << l << "\n";
    }
  }
  // The verdict that joins the two tables. A box whose source and
  // loaded policy have parted company is a box someone edited and
  // never applied, and until this line existed nothing anywhere said
  // so — the operator was told to compare two screens by eye.
  if (j.contains("loaded")) {
    const auto text = j["loaded"].value("drift_text", "");
    if (!text.empty()) {
      out << "\n";
      for (const auto& l : Wrap(text, renderer.Caps().width)) {
        out << l << "\n";
      }
    }
  }
}

/// The result of a policy edit: what was written, where, and whether
/// the running policy carries it.
auto RenderPolicyEdit(const Response& resp, Renderer& renderer)
    -> void {
  auto j = ParseData(resp);
  Table t;
  AddColumn(t, "FIELD", Align::Left, Priority::High);
  AddColumn(t, "VALUE", Align::Left, Priority::High);
  auto row = [&](const std::string& f, const std::string& v,
                 Semantic sem = Semantic::Default) {
    AddRow(t, {Cell{f, Semantic::Info}, Cell{v, sem}});
  };
  if (j.contains("zone")) {
    row("zone", j["zone"].get<std::string>(), Semantic::Emphasis);
  }
  if (j.contains("action")) row("action", j["action"]);
  if (j.contains("statement") &&
      !j["statement"].get<std::string>().empty()) {
    row("statement", j["statement"].get<std::string>(),
        Semantic::Emphasis);
  }
  for (const auto& r : j.value("removed", json::array())) {
    row("removed", r.get<std::string>(), Semantic::Warn);
  }
  if (j.value("position", 0) != 0) {
    row("position", std::format("{} in the block, line {}",
                                j.value("position", 0),
                                j.value("line", 0)));
  }
  // Order is the policy, so where it went is not a detail.
  if (j.contains("before")) {
    row("before", j["before"].get<std::string>(),
        j.value("before_is_unconditional", false) ? Semantic::Warn
                                                  : Semantic::Dim);
    if (j.value("before_is_unconditional", false)) {
      row("why there",
          "that statement is unconditional — anything after it can "
          "never match",
          Semantic::Dim);
    }
  }
  const bool saved = j.value("saved", false);
  row("saved to", saved ? j.value("file", "?") : "no",
      saved ? Semantic::Good : Semantic::Bad);
  const bool live = j.value("activated", false);
  row("running", live ? "yes — fd reloaded" : "no",
      live ? Semantic::Good : Semantic::Warn);
  if (j.contains("version") && !j["version"].is_null()) {
    // fd has answered with this field as both a number and a string
    // over the years, and a renderer that assumes one of them throws
    // where it should be printing.
    row("version", j["version"].is_string()
                       ? j["version"].get<std::string>()
                       : j["version"].dump());
  }
  for (const auto& w : j.value("warnings", json::array())) {
    row("warning", w.get<std::string>(), Semantic::Warn);
  }
  if (j.contains("note")) {
    row("note", j["note"].get<std::string>(), Semantic::Info);
  }
  RenderFormatted(t, renderer);
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
        Show("zones", "show_zones",
             "Zones, interfaces, redirect topology (v0.4)"),
        Show("nat", "show_nat",
             "Active NAT translations and masquerade source"),
        Show("conntrack", "show_conntrack",
             "Connection-tracking table entries"),
        MakeShowCounters(),
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
        Show("install", "show_install",
             "What this box has of the deployable set, and what it "
             "is missing"),
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
        MakeRollbackSystem(),
        MakeShowLog(),
        MakeConfigure(),
        MakeCommit(),
        MakeRollbackCandidate(),
        MakeShowDiff(),
        MakeShowPolicySource(),
        MakeShowCommits(),
        MakeShowFiles(),
        MakeShowPolicy(),
        MakeSetRule(),
        MakeNoRule(),
        MakeSetForward(),
        MakeNoForward(),
        MakeEdit(),
        MakeNewFile(),
        MakeRenameFile(),
        MakeDeleteFile(),
        MakeSetEditor(),
        MakeSetAddress(),
        MakeSetZone(),
        MakeNoZone(),
        MakeSetInterfaceZone(),
        MakeNoInterfaceZone(),
        MakeSetDhcp(),
        MakeNoDhcp(),
        MakeSetDns(),
        MakeNoDns(),
        MakeSetMtu(),
        MakeSetLink(),
        MakeNoAddress(),
        MakeReload(),
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
    } else if (wc == "show_zones") {
      RenderShowZones(response, renderer);
    } else if (wc == "show_nat") {
      RenderShowNat(response, renderer);
    } else if (wc == "show_conntrack") {
      RenderShowConntrack(response, renderer);
    } else if (wc == "show_counters") {
      RenderShowCounters(response, renderer);
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
    } else if (wc == "show_install") {
      RenderShowInstall(response, renderer);
    } else if (wc == "check_system") {
      RenderCheckSystem(response, renderer);
    } else if (wc == "apply_system" ||
               wc == "apply_system_confirmed") {
      RenderApplySystem(response, renderer);
    } else if (wc == "confirm_system") {
      RenderConfirmSystem(response, renderer);
    } else if (wc == "show_files") {
      RenderShowFiles(response, renderer);
    } else if (wc == "show_policy") {
      RenderShowPolicy(response, renderer);
    } else if (wc == "set_rule" || wc == "no_rule" ||
               wc == "set_forward" || wc == "no_forward") {
      RenderPolicyEdit(response, renderer);
    } else if (wc == "edit" || wc == "new_file" ||
               wc == "rename_file" || wc == "delete_file") {
      RenderEdit(response, renderer);
    } else if (wc == "set_editor") {
      RenderSetEditor(response, renderer);
    } else if (wc == "iface_set_address" ||
               wc == "iface_set_mtu" ||
               wc == "iface_set_state" ||
               wc == "iface_del_address" ||
               wc == "zone_set" || wc == "zone_delete" ||
               wc == "iface_set_zone" ||
               wc == "iface_del_zone" ||
               wc == "dhcp_set" || wc == "dhcp_delete" ||
               wc == "dns_set" || wc == "dns_delete" ||
               wc == "rollback_system") {
      RenderIfaceConfig(response, renderer);
    } else if (wc == "show_commits") {
      RenderShowCommits(response, renderer);
    } else if (wc == "configure" || wc == "commit" ||
               wc == "rollback" || wc == "show_config" ||
               wc == "show_diff" ||
               wc == "reload_firewall") {
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

  static auto MakeShowCounters() -> CommandSpec {
    CommandSpec c;
    c.path = "show counters";
    c.wire_command = "show_counters";
    c.help = "What the policy's own `count <name>` statements have "
             "counted, per zone — the map the datapath writes, read "
             "back under the names the policy gave the counters";
    c.args = {{
        .name = "counter",
        .help = "One counter's name; omit to list every counter the "
                "loaded policy declares",
        .required = false,
    }};
    return c;
  }

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

  static auto MakeRollbackSystem() -> CommandSpec {
    CommandSpec c;
    c.path = "rollback system";
    c.wire_command = "rollback_system";
    c.help = "Restore a system-configuration revision f-confd "
             "recorded — the previous one, or the id from `show "
             "commits`. This is the way back from a `set` verb, "
             "which applies on the spot. It does not touch the "
             "policy.";
    c.role = RoleGate::AdminOnly;
    c.args = {{
        .name = "revision",
        .help = "Revision id from `show commits`; omit for the "
                "previous one",
        .required = false,
    }};
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

  // -- the policy candidate ------------------------------------------
  //
  // There are two lifecycles on this box because there are two
  // documents, and the names now say which is which. These five verbs
  // govern `/etc/f/*.fw` — the firewall policy. The **system**
  // configuration (`/etc/f/system.yaml`: ports, zones, addresses,
  // DHCP, DNS) is `apply system` / `apply system confirmed` /
  // `confirm system`, and nothing here touches it.
  //
  // The framework registers sixteen more candidate verbs by default
  // (`set`, `delete`, `save`, `load …`, `rollback previous|rescue|to`,
  // `commit confirmed`, `confirm`, `show configs`, `show commit`).
  // This product implements none of them, so it no longer advertises
  // them — see `BuildTree` in cmd/einheit_f.cc.

  static auto MakeConfigure() -> CommandSpec {
    CommandSpec c;
    c.path = "configure";
    c.wire_command = "configure";
    c.help = "Open a policy candidate: snapshot the .fw files so "
             "`rollback` can put them back, and hold the edits until "
             "`commit`. This is the firewall policy — the system "
             "configuration is `apply system`.";
    c.role = RoleGate::AdminOnly;
    return c;
  }

  static auto MakeCommit() -> CommandSpec {
    CommandSpec c;
    c.path = "commit";
    c.wire_command = "commit";
    c.help = "Compile every .fw file and, if they all pass, make "
             "them live. A policy that does not compile is never "
             "loaded, and a commit fd did not apply says so rather "
             "than closing the session.";
    c.role = RoleGate::AdminOnly;
    c.requires_session = true;
    return c;
  }

  static auto MakeRollbackCandidate() -> CommandSpec {
    CommandSpec c;
    c.path = "rollback candidate";
    c.wire_command = "rollback";
    c.help = "Restore the .fw files to what they were when "
             "`configure` opened, and discard the session";
    c.role = RoleGate::AdminOnly;
    c.requires_session = true;
    return c;
  }

  static auto MakeShowDiff() -> CommandSpec {
    CommandSpec c;
    c.path = "show diff";
    c.wire_command = "show_diff";
    c.help = "What the open candidate changed in the policy files, "
             "against the snapshot `configure` took";
    return c;
  }

  static auto MakeShowPolicySource() -> CommandSpec {
    CommandSpec c;
    c.path = "show config";
    c.wire_command = "show_config";
    c.help = "The policy files as text. `show policy` is the same "
             "content numbered by statement, which is what `no rule` "
             "takes.";
    return c;
  }

  static auto MakeShowCommits() -> CommandSpec {
    CommandSpec c;
    c.path = "show commits";
    c.wire_command = "show_commits";
    c.help = "System-configuration revisions f-confd has recorded — "
             "who applied what, and when. Says so when f-confd is "
             "not running, rather than printing an empty history.";
    return c;
  }

  static auto MakeShowPolicy() -> CommandSpec {
    CommandSpec c;
    c.path = "show policy";
    c.wire_command = "show_policy";
    c.help = "What fd has LOADED, zone by zone in policy order, and "
             "the source on disk beside it — with a verdict on "
             "whether the file is still the policy in the packet "
             "path. The source positions are the numbers `no rule` "
             "takes.";
    c.args = {{
        .name = "zone",
        .help = "Show one zone's block only",
        .required = false,
    }};
    return c;
  }

  static auto MakeSetRule() -> CommandSpec {
    CommandSpec c;
    c.path = "set rule";
    c.wire_command = "set_rule";
    c.help = "Add an allow or drop rule to a zone's block. Placed at "
             "the end of the guarded rules, never after an "
             "unconditional statement where it could not match. The "
             "policy is compiled before it is written.";
    c.role = RoleGate::AdminOnly;
    c.args = {
        {.name = "zone", .help = "Zone whose block to edit",
         .required = true},
        {.name = "action", .help = "allow or drop",
         .required = true},
        {.name = "match",
         .help = "tcp|udp|icmp, a port number, `from <cidr>`, "
                 "`to <cidr>` — a port needs a protocol with it",
         .required = false},
    };
    // Match terms are variadic; the framework refuses surplus tokens
    // for a wire command that declares its arity, and this one does
    // not have a fixed one.
    c.variadic = true;
    return c;
  }

  static auto MakeNoRule() -> CommandSpec {
    CommandSpec c;
    c.path = "no rule";
    c.wire_command = "no_rule";
    c.help = "Remove a statement from a zone's block by the position "
             "`show policy` gives it";
    c.role = RoleGate::AdminOnly;
    c.args = {
        {.name = "zone", .help = "Zone whose block to edit",
         .required = true},
        {.name = "position", .help = "Position from `show policy`",
         .required = true},
    };
    return c;
  }

  static auto MakeSetForward() -> CommandSpec {
    CommandSpec c;
    c.path = "set forward";
    c.wire_command = "set_forward";
    c.help = "Forward a port to a machine inside. Writes the `dnat` "
             "and the `redirect` as one pair with one guard — a "
             "redirect wider than its dnat sends untranslated frames "
             "into the inside zone. The inside zone is derived from "
             "the system configuration, not asked for.";
    c.role = RoleGate::AdminOnly;
    c.args = {
        {.name = "zone", .help = "Zone the traffic arrives on",
         .required = true},
        {.name = "proto", .help = "tcp or udp", .required = true},
        {.name = "port", .help = "Port as it arrives",
         .required = true},
        {.name = "target", .help = "<ip>:<port> inside",
         .required = true},
        {.name = "from",
         .help = "`from <cidr>` to restrict the source",
         .required = false},
    };
    c.variadic = true;
    return c;
  }

  static auto MakeNoForward() -> CommandSpec {
    CommandSpec c;
    c.path = "no forward";
    c.wire_command = "no_forward";
    c.help = "Remove both halves of a port forward";
    c.role = RoleGate::AdminOnly;
    c.args = {
        {.name = "zone", .help = "Zone the traffic arrives on",
         .required = true},
        {.name = "proto", .help = "tcp or udp", .required = true},
        {.name = "port", .help = "Port as it arrives",
         .required = true},
    };
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

  static auto MakeSetZone() -> CommandSpec {
    CommandSpec c;
    c.path = "set zone";
    c.wire_command = "zone_set";
    c.help = "Declare a zone in the system configuration, or change "
             "its IPv6 stance. A zone is a name that interfaces join "
             "and services bind to; it may start out empty.";
    c.role = RoleGate::OperatorOrAdmin;
    c.args = {
        {.name = "name",
         .help = "Zone name (e.g. dmz)",
         .required = true},
        {.name = "ipv6",
         .help = "IPv6 stance: off or ra. Omit to leave it alone "
                 "(a new zone with no stance is off)",
         .required = false},
    };
    return c;
  }

  static auto MakeNoZone() -> CommandSpec {
    CommandSpec c;
    c.path = "no zone";
    c.wire_command = "zone_delete";
    c.help = "Remove a zone. Refused while an interface is still in "
             "it or a service is still bound to it.";
    c.role = RoleGate::OperatorOrAdmin;
    c.args = {{
        .name = "name",
        .help = "Zone name",
        .required = true,
    }};
    return c;
  }

  static auto MakeSetInterfaceZone() -> CommandSpec {
    CommandSpec c;
    c.path = "set interface zone";
    c.wire_command = "iface_set_zone";
    c.help = "Put an interface in a zone, declaring the interface "
             "(pinned to its MAC) if the configuration does not "
             "mention it yet. An interface is in exactly one zone.";
    c.role = RoleGate::OperatorOrAdmin;
    c.args = {
        {.name = "interface",
         .help = "Interface name (e.g. lan0)",
         .required = true},
        {.name = "zone",
         .help = "Zone name — must already be declared",
         .required = true},
    };
    return c;
  }

  static auto MakeNoInterfaceZone() -> CommandSpec {
    CommandSpec c;
    c.path = "no interface zone";
    c.wire_command = "iface_del_zone";
    c.help = "Take an interface out of its zone, leaving it declared "
             "and in no zone";
    c.role = RoleGate::OperatorOrAdmin;
    c.args = {{
        .name = "interface",
        .help = "Interface name",
        .required = true,
    }};
    return c;
  }

  static auto MakeSetDhcp() -> CommandSpec {
    CommandSpec c;
    c.path = "set dhcp";
    c.wire_command = "dhcp_set";
    c.help = "Serve DHCP on a zone. There is no interface argument "
             "and there cannot be one: the ports the server answers "
             "on are derived from zone membership every time the "
             "config is generated.";
    c.role = RoleGate::OperatorOrAdmin;
    c.args = {
        {.name = "zone", .help = "Zone to serve", .required = true},
        {.name = "range",
         .help = "<first>-<last>, e.g. 10.10.0.100-10.10.0.200",
         .required = true},
        {.name = "lease", .help = "Lease duration, e.g. 12h",
         .required = false},
    };
    return c;
  }

  static auto MakeNoDhcp() -> CommandSpec {
    CommandSpec c;
    c.path = "no dhcp";
    c.wire_command = "dhcp_delete";
    c.help = "Stop serving DHCP on a zone. Reservations on that zone "
             "go with it.";
    c.role = RoleGate::OperatorOrAdmin;
    c.args = {{.name = "zone", .help = "Zone", .required = true}};
    return c;
  }

  static auto MakeSetDns() -> CommandSpec {
    CommandSpec c;
    c.path = "set dns";
    c.wire_command = "dns_set";
    c.help = "Forward DNS for a zone. With no upstream named it "
             "inherits the system resolver, which on a DHCP uplink "
             "is whatever the upstream handed us.";
    c.role = RoleGate::OperatorOrAdmin;
    c.args = {
        {.name = "zone", .help = "Zone to serve", .required = true},
        {.name = "upstream",
         .help = "Resolvers to forward to, e.g. 9.9.9.9 1.1.1.1",
         .required = false},
    };
    c.variadic = true;
    return c;
  }

  static auto MakeNoDns() -> CommandSpec {
    CommandSpec c;
    c.path = "no dns";
    c.wire_command = "dns_delete";
    c.help = "Stop forwarding DNS for a zone";
    c.role = RoleGate::OperatorOrAdmin;
    c.args = {{.name = "zone", .help = "Zone", .required = true}};
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

};

}  // namespace

auto NewFwAdapter()
    -> std::unique_ptr<cli::ProductAdapter> {
  return std::make_unique<FwAdapter>();
}

}  // namespace einheit::adapters::fw
