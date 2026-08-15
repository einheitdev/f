/// @file ui_adapter.cc
/// @brief f firewall UI adapter. Reads BPF maps directly,
/// serves dashboard + rules + counters via HTMX, pushes
/// live counter updates over WebSocket.

#include "adapters/fw/ui_adapter.h"

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <format>
#include <fstream>
#include <map>
#include <string>
#include <thread>
#include <vector>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>
#include <zmq.hpp>

#include "einheit/ui/route.h"
#include "einheit/ui/stream.h"

#include "f/bpf_loader.h"
#include "f/engine.h"
#include "f/types.h"

namespace einheit::adapters::fw {
namespace {

using json = nlohmann::json;

auto ReadSysfs(const std::string& iface,
               const std::string& attr) -> std::string {
  auto path = std::format(
      "/sys/class/net/{}/{}", iface, attr);
  std::ifstream f(path);
  std::string val;
  if (f) std::getline(f, val);
  return val;
}

auto FormatSpeed(const std::string& raw)
    -> std::string {
  if (raw.empty() || raw == "-1") return "?";
  long mbps = std::strtol(raw.c_str(), nullptr, 10);
  if (mbps >= 1000) return std::format("{}G", mbps / 1000);
  return std::format("{}M", mbps);
}

auto GatherInterfaces() -> json {
  json out = json::array();
  struct ifaddrs* list = nullptr;
  if (getifaddrs(&list) != 0) return out;
  std::map<std::string, json> by_name;
  for (auto* ifa = list; ifa; ifa = ifa->ifa_next) {
    if (!ifa->ifa_name) continue;
    std::string name = ifa->ifa_name;
    if (name == "lo") continue;
    if (by_name.find(name) == by_name.end()) {
      by_name[name] = {
          {"name", name},
          {"state",
           (ifa->ifa_flags & IFF_UP) ? "up" : "down"},
          {"mac", ReadSysfs(name, "address")},
          {"mtu", ReadSysfs(name, "mtu")},
          {"speed",
           FormatSpeed(ReadSysfs(name, "speed"))},
          {"addresses", json::array()},
      };
    }
    if (ifa->ifa_addr) {
      char buf[64] = {};
      if (ifa->ifa_addr->sa_family == AF_INET) {
        auto* sin =
            reinterpret_cast<struct sockaddr_in*>(
                ifa->ifa_addr);
        inet_ntop(AF_INET, &sin->sin_addr, buf,
                  sizeof(buf));
        by_name[name]["addresses"].push_back(
            std::string(buf));
      } else if (ifa->ifa_addr->sa_family == AF_INET6) {
        auto* sin6 =
            reinterpret_cast<struct sockaddr_in6*>(
                ifa->ifa_addr);
        inet_ntop(AF_INET6, &sin6->sin6_addr, buf,
                  sizeof(buf));
        by_name[name]["addresses"].push_back(
            std::string(buf));
      }
    }
  }
  freeifaddrs(list);
  for (auto& [_, v] : by_name) out.push_back(v);
  return out;
}

auto ActionStr(uint8_t action) -> std::string {
  switch (static_cast<f::Action>(action)) {
    case f::Action::kDrop: return "drop";
    case f::Action::kAllow: return "allow";
    case f::Action::kRateLimit: return "rate-limit";
  }
  return "unknown";
}

auto ProtoStr(uint8_t proto) -> std::string {
  switch (static_cast<f::Proto>(proto)) {
    case f::Proto::kAny: return "any";
    case f::Proto::kIcmp: return "icmp";
    case f::Proto::kTcp: return "tcp";
    case f::Proto::kUdp: return "udp";
  }
  return std::to_string(proto);
}

auto ActionSemantic(const std::string& a)
    -> std::string {
  if (a == "allow") return "good";
  if (a == "drop") return "bad";
  return "warn";
}

auto StateSemantic(const std::string& s) -> std::string {
  if (s == "up") return "good";
  if (s == "down") return "bad";
  return "info";
}

auto ReadRules(const f::BpfHandles& maps) -> json {
  uint32_t cfg_key = 0;
  f::FwConfig fw_cfg{};
  bpf_map_lookup_elem(maps.config_fd, &cfg_key, &fw_cfg);
  int rules_fd = fw_cfg.active_table == 0
                     ? maps.rules_a_fd
                     : maps.rules_b_fd;
  int ncpus = libbpf_num_possible_cpus();
  if (ncpus < 1) ncpus = 1;

  json rules = json::array();
  f::RuleKey key{}, next{};
  uint32_t idx = 0;
  while (bpf_map_get_next_key(
             rules_fd, &key, &next) == 0) {
    f::RuleValue val{};
    bpf_map_lookup_elem(rules_fd, &next, &val);
    uint64_t pkts = 0, bytes = 0;
    std::vector<f::RuleCounter> per_cpu(ncpus);
    if (bpf_map_lookup_elem(
            maps.counters_fd, &idx,
            per_cpu.data()) == 0) {
      for (int c = 0; c < ncpus; c++) {
        pkts += per_cpu[c].packets;
        bytes += per_cpu[c].bytes;
      }
    }
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &next.src_addr, src, sizeof(src));
    inet_ntop(AF_INET, &next.dst_addr, dst, sizeof(dst));
    auto action = ActionStr(val.action);
    rules.push_back({
        {"idx", idx},
        {"src", std::string(src)},
        {"dst", std::string(dst)},
        {"src_port", next.src_port},
        {"dst_port", next.dst_port},
        {"proto", ProtoStr(next.proto)},
        {"action", action},
        {"action_semantic", ActionSemantic(action)},
        {"packets", pkts},
        {"bytes", bytes},
    });
    key = next;
    idx++;
  }
  return rules;
}

// What fd said, and whether it is an answer at all. A reply arriving
// is not the same thing as fd having the data: every command can come
// back with an `error` payload, and rendering that as an empty table
// tells the operator there are no zones / no NAT when the truth is
// that nobody could ask.
struct DaemonReply {
  bool ok = false;
  /// fd's own words for why not, or why we could not reach it.
  std::string error;
  json body;
};

// Send a single-byte control command to fd and classify the answer.
// The v0.4 zone/NAT/conntrack views read their data from the daemon's
// control surface (same commands the CLI uses) rather than the pinned
// maps.
auto AskDaemon(const std::string& fd_socket, f::Cmd cmd)
    -> DaemonReply {
  DaemonReply out;
  try {
    zmq::context_t ctx(1);
    zmq::socket_t sock(ctx, zmq::socket_type::req);
    sock.set(zmq::sockopt::linger, 0);
    sock.set(zmq::sockopt::rcvtimeo, 1000);
    sock.set(zmq::sockopt::sndtimeo, 1000);
    sock.connect(fd_socket);
    char b = static_cast<char>(static_cast<uint8_t>(cmd));
    zmq::message_t req(1);
    std::memcpy(req.data(), &b, 1);
    if (!sock.send(req, zmq::send_flags::none)) {
      out.error = "fd did not accept the request";
      return out;
    }
    zmq::message_t reply;
    if (!sock.recv(reply, zmq::recv_flags::none)) {
      out.error = "fd is not answering";
      return out;
    }
    out.body = json::parse(std::string(
        static_cast<char*>(reply.data()), reply.size()));
    if (out.body.is_object() && out.body.contains("error")) {
      out.error = out.body["error"].is_string()
                      ? out.body["error"].get<std::string>()
                      : out.body["error"].dump();
      return out;
    }
    out.ok = true;
  } catch (const std::exception& e) {
    out.error = e.what();
  }
  return out;
}

auto ReadDaemonStatus(const std::string& fd_socket) -> json {
  auto reply = AskDaemon(fd_socket, f::Cmd::kGetStatus);
  if (!reply.ok) {
    return {{"connected", false}, {"error", reply.error}};
  }
  json j = reply.body;
  j["connected"] = true;
  return j;
}

// Body only, for the paths that just want the data.
auto QueryDaemon(const std::string& fd_socket, f::Cmd cmd) -> json {
  auto reply = AskDaemon(fd_socket, cmd);
  return reply.ok ? reply.body : json();
}

// The message a view shows instead of a table: never a claim that the
// thing is empty when the truth is that we could not read it.
auto UnavailableText(const DaemonReply& reply,
                     const std::string& empty_text) -> std::string {
  if (reply.ok) return empty_text;
  return "cannot read this from fd: " + reply.error;
}

auto JoinArr(const json& arr) -> std::string {
  std::string out;
  if (!arr.is_array()) return out;
  for (const auto& s : arr) {
    if (!out.empty()) out += ", ";
    out += s.get<std::string>();
  }
  return out;
}

// Add the display fields the zones_table template renders (joined
// interface/redirect lists, yes/no + semantic badges).
auto DecorateZones(json zones) -> json {
  if (!zones.is_array()) return json::array();
  for (auto& z : zones) {
    z["ifaces_str"] = JoinArr(z.value("interfaces", json::array()));
    z["attached_str"] = JoinArr(z.value("attached", json::array()));
    if (z["attached_str"].get<std::string>().empty()) {
      z["attached_str"] = "(none)";
    }
    auto redir = JoinArr(z.value("redirects_to", json::array()));
    z["redirects_str"] = redir.empty() ? "-" : redir;
    bool masq = z.value("masquerades", false);
    z["masq_str"] = masq ? "yes" : "no";
    z["masq_semantic"] = masq ? "good" : "dim";
    z["attach_semantic"] =
        z.value("attached_count", 0) > 0 ? "good" : "warn";
    auto mode = z.value("xdp_mode", std::string("-"));
    if (mode.empty()) mode = "-";
    z["xdp_mode"] = mode;
    z["mode_semantic"] = mode == "native"    ? "good"
                         : mode == "generic" ? "warn"
                                             : "dim";
  }
  return zones;
}

// Tag each conntrack entry with a badge semantic for its state.
auto DecorateConntrack(json entries) -> json {
  if (!entries.is_array()) return json::array();
  for (auto& c : entries) {
    auto st = c.value("state", "");
    c["state_semantic"] = st == "established" ? "good"
                          : st == "invalid"   ? "bad"
                                              : "warn";
  }
  return entries;
}

class FwUiAdapter final : public ui::ProductUiAdapter {
 public:
  explicit FwUiAdapter(FwUiConfig cfg)
      : cfg_(std::move(cfg)) {}

  ~FwUiAdapter() override {
    sampler_stop_.store(true);
    if (sampler_.joinable()) sampler_.join();
  }

  auto Slug() const -> std::string override {
    return "f";
  }
  auto DisplayName() const -> std::string override {
    return "f firewall";
  }
  auto TemplatesDir() const -> std::string override {
    return EINHEIT_UI_ADAPTER_FW_TEMPLATES_DIR;
  }
  auto Nav() const -> std::vector<ui::NavEntry> override {
    return {
        {"/", "Dashboard", "dashboard", "monitor"},
        {"/interfaces", "Interfaces", "interfaces",
         "network"},
        {"/zones", "Zones", "zones", "layers"},
        {"/firewall", "Firewall", "firewall", "shield"},
        {"/nat", "NAT", "nat", "shuffle"},
        {"/conntrack", "Conntrack", "conntrack", "activity"},
        {"/counters", "Counters", "counters",
         "bar-chart-2"},
    };
  }

  auto Mount(ui::AdapterContext ctx) -> void override {
    auto* eng = ctx.templates;
    auto& app = *ctx.app;
    auto* events = ctx.events;
    auto nav = Nav();

    auto maps = f::OpenPinnedMaps(cfg_.pin_path);
    if (maps) {
      maps_ = *maps;
      maps_open_ = true;
    }

    StartSampler(events);

    events->Bind(ui::TopicBinding{
        .topic = "fw.rules",
        .fragment = "fw/rules_table",
        .swap_target = "rules-table",
        .swap_strategy = "outerHTML",
    });
    events->Bind(ui::TopicBinding{
        .topic = "fw.counters",
        .fragment = "fw/counters_table",
        .swap_target = "counters-table",
        .swap_strategy = "outerHTML",
    });
    // v0.4 live views: NAT translations, conntrack, zones.
    events->Bind(ui::TopicBinding{
        .topic = "fw.nat",
        .fragment = "fw/nat_table",
        .swap_target = "nat-table",
        .swap_strategy = "outerHTML",
    });
    events->Bind(ui::TopicBinding{
        .topic = "fw.conntrack",
        .fragment = "fw/conntrack_table",
        .swap_target = "conntrack-table",
        .swap_strategy = "outerHTML",
    });
    events->Bind(ui::TopicBinding{
        .topic = "fw.zones",
        .fragment = "fw/zones_table",
        .swap_target = "zones-table",
        .swap_strategy = "outerHTML",
    });

    // -- Dashboard --
    CROW_ROUTE(app, "/")
    ([eng, nav, this](const crow::request& req) {
      auto status = ReadDaemonStatus(cfg_.fd_socket);
      auto ifaces = GatherInterfaces();
      // v0.4 zone/NAT/conntrack summary, read from the daemon.
      auto zones = QueryDaemon(cfg_.fd_socket, f::Cmd::kGetZones);
      auto nat = QueryDaemon(cfg_.fd_socket, f::Cmd::kGetNat);
      auto ct = QueryDaemon(cfg_.fd_socket, f::Cmd::kGetConntrack);
      // How many interfaces are actually being filtered, summed from
      // the per-zone `attached_count` the daemon derives from the
      // kernel — NOT from how many NICs the box has, and not from how
      // many zone programs the manifest listed. Both of those read
      // healthy on a box whose bundle attached to nothing, which is
      // the state this card exists to make visible: a four-port
      // gateway with zero XDP attachments used to render
      // "interfaces: 4" under a heading that says "firewall".
      size_t attached = 0;
      if (zones.is_array()) {
        for (const auto& z : zones) {
          attached += z.value("attached_count", 0);
        }
      }
      json data = {
          {"daemon", status},
          {"maps_available", maps_open_},
          {"iface_count", ifaces.size()},
          {"attached_count", attached},
          {"datapath_armed", attached > 0},
          {"datapath_semantic", attached > 0 ? "good" : "bad"},
          {"has_firewall", false},
          {"zone_count", zones.is_array() ? zones.size() : 0},
          {"conntrack_count", ct.is_array() ? ct.size() : 0},
          {"nat_count", 0},
          {"has_masq", false},
          {"masq_source", ""},
      };
      if (nat.is_object()) {
        auto tr = nat.value("translations", json::array());
        data["nat_count"] = tr.size();
        if (nat.contains("masq_source")) {
          data["has_masq"] = true;
          data["masq_source"] =
              nat["masq_source"].get<std::string>();
        }
      }
      if (maps_open_) {
        uint32_t cfg_key = 0;
        f::FwConfig fw_cfg{};
        bpf_map_lookup_elem(
            maps_.config_fd, &cfg_key, &fw_cfg);
        auto action = fw_cfg.default_action == 0
                          ? "drop" : "allow";
        data["has_firewall"] = true;
        data["default_action"] = action;
        data["action_semantic"] =
            ActionSemantic(action);
        data["rule_count"] = 0;
        f::RuleKey key{}, next{};
        int rules_fd = fw_cfg.active_table == 0
                           ? maps_.rules_a_fd
                           : maps_.rules_b_fd;
        while (bpf_map_get_next_key(
                   rules_fd, &key, &next) == 0) {
          data["rule_count"] =
              data["rule_count"].get<int>() + 1;
          key = next;
        }
      }
      ui::RenderArgs args;
      args.fragment = "fw/dashboard";
      args.layout = "layout";
      args.data = data;
      args.meta = {
          {"title", "Dashboard"},
          {"brand", "f firewall"},
          {"active", "dashboard"},
          {"nav", ui::NavToJson(nav)},
      };
      auto r = ui::Render(*eng, req, args);
      if (!r) {
        return ui::RenderError(
            *eng, req, 500, "render", r.error().message);
      }
      return std::move(*r);
    });

    // -- Interfaces --
    CROW_ROUTE(app, "/interfaces")
    ([eng, nav, this](const crow::request& req) {
      auto ifaces = GatherInterfaces();
      for (auto& iface : ifaces) {
        iface["state_semantic"] =
            StateSemantic(iface.value("state", ""));
        auto addrs =
            iface.value("addresses", json::array());
        std::string addr_str;
        for (const auto& a : addrs) {
          if (!addr_str.empty()) addr_str += ", ";
          addr_str += a.get<std::string>();
        }
        iface["addr_str"] =
            addr_str.empty() ? "-" : addr_str;
      }
      ui::RenderArgs args;
      args.fragment = "fw/interfaces";
      args.layout = "layout";
      args.data = {{"interfaces", ifaces}};
      args.meta = {
          {"title", "Interfaces"},
          {"brand", "f firewall"},
          {"active", "interfaces"},
          {"nav", ui::NavToJson(nav)},
      };
      auto r = ui::Render(*eng, req, args);
      if (!r) {
        return ui::RenderError(
            *eng, req, 500, "render", r.error().message);
      }
      return std::move(*r);
    });

    // -- Firewall rules --
    CROW_ROUTE(app, "/firewall")
    ([eng, nav, this](const crow::request& req) {
      json data;
      if (maps_open_) {
        data["rules"] = ReadRules(maps_);
      } else {
        data["rules"] = json::array();
        data["error"] = "BPF maps not available";
      }
      ui::RenderArgs args;
      args.fragment = "fw/firewall";
      args.layout = "layout";
      args.data = data;
      args.meta = {
          {"title", "Firewall Rules"},
          {"brand", "f firewall"},
          {"active", "firewall"},
          {"nav", ui::NavToJson(nav)},
      };
      auto r = ui::Render(*eng, req, args);
      if (!r) {
        return ui::RenderError(
            *eng, req, 500, "render", r.error().message);
      }
      return std::move(*r);
    });

    // -- Zones (v0.4) --
    CROW_ROUTE(app, "/zones")
    ([eng, nav, this](const crow::request& req) {
      auto zones = AskDaemon(cfg_.fd_socket, f::Cmd::kGetZones);
      json data = {
          {"zones", DecorateZones(zones.body)},
          {"zones_empty", UnavailableText(
               zones, "no zones (single-program mode)")},
      };
      ui::RenderArgs args;
      args.fragment = "fw/zones";
      args.layout = "layout";
      args.data = data;
      args.meta = {
          {"title", "Zones"},
          {"brand", "f firewall"},
          {"active", "zones"},
          {"nav", ui::NavToJson(nav)},
      };
      auto r = ui::Render(*eng, req, args);
      if (!r) {
        return ui::RenderError(
            *eng, req, 500, "render", r.error().message);
      }
      return std::move(*r);
    });

    // -- NAT translations (v0.4) --
    CROW_ROUTE(app, "/nat")
    ([eng, nav, this](const crow::request& req) {
      auto nat = AskDaemon(cfg_.fd_socket, f::Cmd::kGetNat);
      json data;
      data["translations"] =
          nat.body.is_object()
              ? nat.body.value("translations", json::array())
              : json::array();
      data["has_masq"] =
          nat.body.is_object() && nat.body.contains("masq_source");
      data["masq_source"] =
          data["has_masq"].get<bool>()
              ? nat.body["masq_source"].get<std::string>()
              : std::string();
      data["translations_empty"] =
          UnavailableText(nat, "no active translations");
      ui::RenderArgs args;
      args.fragment = "fw/nat";
      args.layout = "layout";
      args.data = data;
      args.meta = {
          {"title", "NAT"},
          {"brand", "f firewall"},
          {"active", "nat"},
          {"nav", ui::NavToJson(nav)},
      };
      auto r = ui::Render(*eng, req, args);
      if (!r) {
        return ui::RenderError(
            *eng, req, 500, "render", r.error().message);
      }
      return std::move(*r);
    });

    // -- Conntrack (v0.4) --
    CROW_ROUTE(app, "/conntrack")
    ([eng, nav, this](const crow::request& req) {
      auto ct = AskDaemon(cfg_.fd_socket, f::Cmd::kGetConntrack);
      json data = {
          {"conntrack", DecorateConntrack(ct.body)},
          {"conntrack_empty",
           UnavailableText(ct, "no tracked connections")},
      };
      ui::RenderArgs args;
      args.fragment = "fw/conntrack";
      args.layout = "layout";
      args.data = data;
      args.meta = {
          {"title", "Conntrack"},
          {"brand", "f firewall"},
          {"active", "conntrack"},
          {"nav", ui::NavToJson(nav)},
      };
      auto r = ui::Render(*eng, req, args);
      if (!r) {
        return ui::RenderError(
            *eng, req, 500, "render", r.error().message);
      }
      return std::move(*r);
    });

    // -- Counters --
    CROW_ROUTE(app, "/counters")
    ([eng, nav, this](const crow::request& req) {
      json counters = json::array();
      if (maps_open_) {
        int ncpus = libbpf_num_possible_cpus();
        if (ncpus < 1) ncpus = 1;
        for (uint32_t i = 0; i < 256; i++) {
          std::vector<f::RuleCounter> per_cpu(ncpus);
          if (bpf_map_lookup_elem(
                  maps_.counters_fd, &i,
                  per_cpu.data()) != 0) {
            break;
          }
          uint64_t pkts = 0, bytes = 0;
          for (int c = 0; c < ncpus; c++) {
            pkts += per_cpu[c].packets;
            bytes += per_cpu[c].bytes;
          }
          if (pkts == 0 && bytes == 0) continue;
          counters.push_back({
              {"id", i},
              {"packets", pkts},
              {"bytes", bytes},
          });
        }
      }
      ui::RenderArgs args;
      args.fragment = "fw/counters";
      args.layout = "layout";
      args.data = {{"counters", counters}};
      args.meta = {
          {"title", "Counters"},
          {"brand", "f firewall"},
          {"active", "counters"},
          {"nav", ui::NavToJson(nav)},
      };
      auto r = ui::Render(*eng, req, args);
      if (!r) {
        return ui::RenderError(
            *eng, req, 500, "render", r.error().message);
      }
      return std::move(*r);
    });
  }

 private:
  FwUiConfig cfg_;
  f::BpfHandles maps_{};
  bool maps_open_ = false;
  std::atomic<bool> sampler_stop_{false};
  std::jthread sampler_;

  void StartSampler(ui::EventStream* events) {
    sampler_ = std::jthread(
        [this, events](std::stop_token) {
      while (!sampler_stop_.load()) {
        std::this_thread::sleep_for(
            std::chrono::milliseconds(
                cfg_.sample_interval_ms));
        if (sampler_stop_.load()) break;
        // v0.4 zone/NAT/conntrack come from the daemon, independent of
        // whether the pinned rule maps are open.
        // Publish even when the daemon refuses or disappears: a live
        // view that silently keeps showing the last good table is
        // showing something that is no longer true.
        auto zones = AskDaemon(cfg_.fd_socket, f::Cmd::kGetZones);
        events->Publish(
            "fw.zones",
            {{"zones", DecorateZones(zones.body)},
             {"zones_empty",
              UnavailableText(zones,
                              "no zones (single-program mode)")}});
        auto nat = AskDaemon(cfg_.fd_socket, f::Cmd::kGetNat);
        events->Publish(
            "fw.nat",
            {{"translations",
              nat.body.is_object()
                  ? nat.body.value("translations", json::array())
                  : json::array()},
             {"translations_empty",
              UnavailableText(nat, "no active translations")}});
        auto ct = AskDaemon(cfg_.fd_socket, f::Cmd::kGetConntrack);
        events->Publish(
            "fw.conntrack",
            {{"conntrack", DecorateConntrack(ct.body)},
             {"conntrack_empty",
              UnavailableText(ct, "no tracked connections")}});
        if (!maps_open_) continue;
        auto rules = ReadRules(maps_);
        events->Publish("fw.rules", {{"rules", rules}});
        int ncpus = libbpf_num_possible_cpus();
        if (ncpus < 1) ncpus = 1;
        json counters = json::array();
        for (uint32_t i = 0; i < 256; i++) {
          std::vector<f::RuleCounter> per_cpu(ncpus);
          if (bpf_map_lookup_elem(
                  maps_.counters_fd, &i,
                  per_cpu.data()) != 0) {
            break;
          }
          uint64_t pkts = 0, bytes = 0;
          for (int c = 0; c < ncpus; c++) {
            pkts += per_cpu[c].packets;
            bytes += per_cpu[c].bytes;
          }
          if (pkts == 0 && bytes == 0) continue;
          counters.push_back({
              {"id", i}, {"packets", pkts},
              {"bytes", bytes},
          });
        }
        events->Publish("fw.counters",
                        {{"counters", counters}});
      }
    });
  }
};

}  // namespace

auto NewFwUiAdapter(FwUiConfig cfg)
    -> std::unique_ptr<ui::ProductUiAdapter> {
  return std::make_unique<FwUiAdapter>(std::move(cfg));
}

}  // namespace einheit::adapters::fw
