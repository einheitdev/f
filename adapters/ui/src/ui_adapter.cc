/// @file ui_adapter.cc
/// @brief f firewall UI adapter. Serves dashboard, interfaces, zones,
/// policy, counters, NAT and conntrack via HTMX and pushes live
/// updates over WebSocket.
///
/// Everything on these pages comes from the daemon over the control
/// socket. It used to open the pinned BPF maps in-process as well, and
/// that half served the `/firewall` and `/counters` pages: it opened
/// `rules_a`, `rules_b`, `cidr_a`, `cidr_b`, `conntrack`, `counters`
/// and `config` — the v0.1 single-program map names, none of which a
/// v0.4 bundle pins. So on every deployed box `OpenPinnedMaps` failed
/// on its first name, `maps_open_` stayed false, `/firewall` rendered
/// "no rules loaded", `/counters` rendered "no counters active", and
/// the dashboard's maps badge was a red "unavailable" — measured on
/// deb-03 against master `dc0b0fc`, on a box whose real
/// `fwl_counters_testnet` was counting every frame on the wire. Those
/// pages are gone rather than fixed: there was nothing behind them to
/// fix, and an empty table is a claim.
///
/// `/counters` is back, and the difference is where its numbers come
/// from. fd holds the loaded objects AND the name->slot tables read in
/// the same call that opened the maps, and answers both halves over
/// opcode 12; this page is a second consumer of the answer
/// `einheit-f show counters` already reads. It opens nothing itself.
/// `/policy` is the same rule applied to the policy: it reports what
/// fd has LOADED, and states in place the one thing fd cannot answer.

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

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>
#include <zmq.hpp>

#include "einheit/ui/route.h"
#include "einheit/ui/stream.h"

#include "adapters/fw/views.h"
#include "f/protocol.h"
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

// What fd said, and whether it is an answer at all, plus every
// decision made about it, live in views.{h,cc} — reachable from a unit
// test, which the inside of a Crow handler is not. A reply arriving is
// not the same thing as fd having the data: every command can come
// back with an `error` payload, and rendering that as an empty table
// tells the operator there are no zones / no counters when the truth
// is that nobody could ask.
using DaemonReply = FdAnswer;

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
        {"/policy", "Policy", "policy", "shield"},
        {"/counters", "Counters", "counters", "list"},
        {"/zones", "Zones", "zones", "layers"},
        {"/nat", "NAT", "nat", "shuffle"},
        {"/conntrack", "Conntrack", "conntrack", "activity"},
    };
  }

  auto Mount(ui::AdapterContext ctx) -> void override {
    auto* eng = ctx.templates;
    auto& app = *ctx.app;
    auto* events = ctx.events;
    auto nav = Nav();

    StartSampler(events);

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
    // Counters move while the operator watches, and a policy changes
    // under him on a reload. Both fragments are republished from the
    // same sampler tick that feeds the rest, so a page left open shows
    // the box as it is now rather than as it was when it loaded.
    events->Bind(ui::TopicBinding{
        .topic = "fw.counters",
        .fragment = "fw/counters_table",
        .swap_target = "counters-table",
        .swap_strategy = "outerHTML",
    });
    events->Bind(ui::TopicBinding{
        .topic = "fw.policy",
        .fragment = "fw/policy_table",
        .swap_target = "policy-table",
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
      // A measurement, in the row where an unconditional red badge
      // used to sit. `maps [FAIL] unavailable` was painted by a field
      // nothing in this adapter ever set, on a box whose counters were
      // moving — a status indicator that has never once been a status.
      // This one either counts what the loaded policy declares or says
      // which zones it could not read and why.
      auto counters =
          AskDaemon(cfg_.fd_socket, f::Cmd::kGetFwlCounters);
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
          {"iface_count", ifaces.size()},
          {"attached_count", attached},
          {"datapath_armed", attached > 0},
          {"datapath_semantic", attached > 0 ? "good" : "bad"},
          {"zone_count", zones.is_array() ? zones.size() : 0},
          {"conntrack_count", ct.is_array() ? ct.size() : 0},
          {"nat_count", 0},
          {"has_masq", false},
          {"masq_source", ""},
          {"counters", CountersSummary(counters)},
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

    // -- Policy: what fd has loaded, per zone --
    //
    // Not the source on disk. `einheit-f show policy` reads the `.fw`
    // files and says in its own output that a file edited and never
    // reloaded reads exactly like one that is live; this page makes
    // the opposite claim — that what it shows is in the packet path —
    // so it is built only from what fd itself attached and loaded.
    CROW_ROUTE(app, "/policy")
    ([eng, nav, this](const crow::request& req) {
      auto zones = AskDaemon(cfg_.fd_socket, f::Cmd::kGetZones);
      auto counters =
          AskDaemon(cfg_.fd_socket, f::Cmd::kGetFwlCounters);
      auto status = AskDaemon(cfg_.fd_socket, f::Cmd::kGetStatus);
      json data = PolicyView(zones, counters);
      data["features"] = PolicyFeatures(status);
      ui::RenderArgs args;
      args.fragment = "fw/policy";
      args.layout = "layout";
      args.data = data;
      args.meta = {
          {"title", "Policy"},
          {"brand", "f firewall"},
          {"active", "policy"},
          {"nav", ui::NavToJson(nav)},
      };
      auto r = ui::Render(*eng, req, args);
      if (!r) {
        return ui::RenderError(
            *eng, req, 500, "render", r.error().message);
      }
      return std::move(*r);
    });

    // -- Counters: the policy's own `count` statements (opcode 12) --
    CROW_ROUTE(app, "/counters")
    ([eng, nav, this](const crow::request& req) {
      auto counters =
          AskDaemon(cfg_.fd_socket, f::Cmd::kGetFwlCounters);
      ui::RenderArgs args;
      args.fragment = "fw/counters";
      args.layout = "layout";
      args.data = CountersView(counters);
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
  }

 private:
  FwUiConfig cfg_;
  std::atomic<bool> sampler_stop_{false};
  std::jthread sampler_;

  /// Publish one live fragment, and say so when it does not go out.
  ///
  /// `Publish` fails on an unbound topic and on a fragment that will
  /// not render, and every call site here used to discard that. A live
  /// view whose updates stop arriving looks exactly like a box where
  /// nothing is changing — the page keeps showing the numbers it was
  /// loaded with, and nothing anywhere says they are old.
  static void Push(ui::EventStream* events, const char* topic,
                   const json& ctx) {
    auto r = events->Publish(topic, ctx);
    if (!r) {
      spdlog::warn("live update '{}' not sent: {}", topic,
                   r.error().message);
    }
  }

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
        Push(events, "fw.zones",
             {{"zones", DecorateZones(zones.body)},
              {"zones_empty",
               UnavailableText(zones,
                               "no zones (single-program mode)")}});
        auto nat = AskDaemon(cfg_.fd_socket, f::Cmd::kGetNat);
        Push(events, "fw.nat",
             {{"translations",
               nat.body.is_object()
                   ? nat.body.value("translations", json::array())
                   : json::array()},
              {"translations_empty",
               UnavailableText(nat, "no active translations")}});
        auto ct = AskDaemon(cfg_.fd_socket, f::Cmd::kGetConntrack);
        Push(events, "fw.conntrack",
             {{"conntrack", DecorateConntrack(ct.body)},
              {"conntrack_empty",
               UnavailableText(ct, "no tracked connections")}});
        // Counters and the loaded policy, from the same tick. Both
        // fragments are published whatever fd answered — a live table
        // that stops updating when the daemon goes away keeps showing
        // numbers that were true a minute ago, which is the one thing
        // a live view must never do.
        auto counters =
            AskDaemon(cfg_.fd_socket, f::Cmd::kGetFwlCounters);
        Push(events, "fw.counters", CountersView(counters));
        Push(events, "fw.policy", PolicyView(zones, counters));
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
