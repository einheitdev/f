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

auto ReadDaemonStatus(const std::string& fd_socket)
    -> json {
  json j = {{"connected", false}};
  try {
    zmq::context_t ctx(1);
    zmq::socket_t sock(ctx, zmq::socket_type::req);
    sock.set(zmq::sockopt::linger, 0);
    sock.set(zmq::sockopt::rcvtimeo, 1000);
    sock.set(zmq::sockopt::sndtimeo, 1000);
    sock.connect(fd_socket);
    std::string msg;
    msg += static_cast<char>(
        static_cast<uint8_t>(f::Cmd::kGetStatus));
    zmq::message_t req(msg.size());
    std::memcpy(req.data(), msg.data(), msg.size());
    if (sock.send(req, zmq::send_flags::none)) {
      zmq::message_t reply;
      if (sock.recv(reply, zmq::recv_flags::none)) {
        auto resp = std::string(
            static_cast<char*>(reply.data()),
            reply.size());
        try {
          j = json::parse(resp);
          j["connected"] = true;
        } catch (...) {}
      }
    }
  } catch (...) {}
  return j;
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
        {"/firewall", "Firewall", "firewall", "shield"},
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

    // -- Dashboard --
    CROW_ROUTE(app, "/")
    ([eng, nav, this](const crow::request& req) {
      auto status = ReadDaemonStatus(cfg_.fd_socket);
      auto ifaces = GatherInterfaces();
      json data = {
          {"daemon", status},
          {"maps_available", maps_open_},
          {"iface_count", ifaces.size()},
      };
      if (maps_open_) {
        uint32_t cfg_key = 0;
        f::FwConfig fw_cfg{};
        bpf_map_lookup_elem(
            maps_.config_fd, &cfg_key, &fw_cfg);
        data["default_action"] =
            fw_cfg.default_action == 0 ? "drop"
                                       : "allow";
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
