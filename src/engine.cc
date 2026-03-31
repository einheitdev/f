/// @file engine.cc
/// @brief BPF engine: load, attach, pin, ZMQ control loop.

#include "f/engine.h"

#include <net/if.h>
#include <sys/stat.h>
#include <unistd.h>

#include <chrono>
#include <cstring>
#include <filesystem>
#include <format>
#include <fstream>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

namespace f {

auto WritePidFile(const char* path) -> bool {
  std::ofstream f(path);
  if (!f) return false;
  f << getpid();
  return f.good();
}

auto ReadPidFile(const char* path) -> int {
  std::ifstream f(path);
  int pid = -1;
  f >> pid;
  return pid;
}

auto RemovePidFile(const char* path) -> void {
  std::filesystem::remove(path);
}

auto IsProcessRunning(int pid) -> bool {
  return pid > 0 && kill(pid, 0) == 0;
}

namespace {

using json = nlohmann::json;

auto CurrentTimeS() -> uint64_t {
  return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::seconds>(
          std::chrono::steady_clock::now().time_since_epoch())
          .count());
}

auto ResolveIfindex(std::string_view name) -> int {
  return static_cast<int>(
      if_nametoindex(std::string(name).c_str()));
}

auto FlushMap(int map_fd) -> void {
  char key[256];
  char next_key[256];
  while (bpf_map_get_next_key(
             map_fd, nullptr, next_key) == 0) {
    std::memcpy(key, next_key, sizeof(key));
    bpf_map_delete_elem(map_fd, key);
  }
}

auto HandleRequest(Engine& e, const std::string& req_str)
    -> std::string {
  if (req_str.empty()) {
    return R"({"error":"empty request"})";
  }
  auto cmd = static_cast<Cmd>(
      static_cast<uint8_t>(req_str[0]));
  switch (cmd) {
    case Cmd::kGetStatus: {
      return GetFullState(e).dump();
    }
    case Cmd::kStop: {
      spdlog::info("Received stop command.");
      e.state.store(EngineState::kStopping,
                    std::memory_order_release);
      return R"({"ok":true})";
    }
    case Cmd::kApplyConfig: {
      if (req_str.size() <= 1) {
        return R"({"error":"missing config payload"})";
      }
      try {
        auto j = json::parse(
            req_str.begin() + 1, req_str.end());
        ConfigMsg msg{};
        msg.default_action =
            j.value("default_action", 1);
        msg.conntrack_enabled =
            j.value("conntrack_enabled", 0);
        msg.conntrack_timeout_s =
            j.value("conntrack_timeout_s", 300);
        auto& rules_arr = j["rules"];
        msg.rule_count =
            static_cast<uint32_t>(rules_arr.size());

        std::vector<std::byte> rule_data;
        for (const auto& r : rules_arr) {
          RuleKey key{};
          key.src_addr = r.value("src_addr", 0u);
          key.dst_addr = r.value("dst_addr", 0u);
          key.src_port = r.value("src_port", 0);
          key.dst_port = r.value("dst_port", 0);
          key.proto = r.value("proto", 0);
          RuleValue val{};
          val.action = r.value("action", 0);
          val.rate_pps = r.value("rate_pps", 0u);
          auto* kp = reinterpret_cast<
              const std::byte*>(&key);
          rule_data.insert(
              rule_data.end(), kp, kp + sizeof(key));
          auto* vp = reinterpret_cast<
              const std::byte*>(&val);
          rule_data.insert(
              rule_data.end(), vp, vp + sizeof(val));
        }
        auto res = ApplyConfig(e, msg, rule_data);
        if (res) {
          return json({{"rules_installed", *res}}).dump();
        }
        return json({{"error",
            res.error().message}}).dump();
      } catch (const std::exception& ex) {
        return json({{"error", ex.what()}}).dump();
      }
    }
    default:
      return R"({"error":"unknown command"})";
  }
}

}  // namespace

auto EngineInit(Engine& e,
                std::string_view sock_addr,
                std::span<const std::string> ifaces,
                std::string_view pin_path)
    -> std::expected<void, Error<EngineError>> {
  e.socket_addr = std::string(sock_addr);
  e.pin_path = std::string(pin_path);
  e.start_time_s = CurrentTimeS();
  e.state.store(EngineState::kStarting);

  // Load BPF program.
  spdlog::info("Loading BPF program...");
  auto bpf_res = LoadProgram();
  if (!bpf_res) {
    return MakeError(EngineError::kBpfLoadFailed,
        bpf_res.error().message);
  }
  e.bpf = *bpf_res;
  spdlog::info("BPF program loaded.");

  // Pin maps.
  auto pin_res = PinMaps(e.bpf, e.pin_path);
  if (!pin_res) {
    spdlog::warn("Pin maps failed: {} — continuing.",
                 pin_res.error().message);
  } else {
    // Make pinned maps world-readable for f-api.
    for (const auto& entry :
         std::filesystem::directory_iterator(e.pin_path)) {
      chmod(entry.path().c_str(), 0644);
    }
    chmod(e.pin_path.c_str(), 0755);
    spdlog::info("Maps pinned to {}.", e.pin_path);
  }

  // Populate components with map fds.
  e.rules.rules_a_fd = e.bpf.rules_a_fd;
  e.rules.rules_b_fd = e.bpf.rules_b_fd;
  e.rules.config_fd = e.bpf.config_fd;
  e.rules.counters_fd = e.bpf.counters_fd;
  e.conntrack.map_fd = e.bpf.conntrack_fd;

  // Attach to interfaces.
  for (const auto& name : ifaces) {
    int idx = ResolveIfindex(name);
    if (idx == 0) {
      spdlog::warn("Interface {} not found.", name);
      continue;
    }
    auto att_res = AttachXdp(e.bpf, idx);
    if (!att_res) {
      spdlog::error("Attach {} failed: {}",
                    name, att_res.error().message);
      continue;
    }
    auto& entry = e.ifaces.interfaces[e.ifaces.count];
    entry.ifindex = idx;
    std::strncpy(entry.name, name.c_str(),
                 sizeof(entry.name) - 1);
    e.ifaces.count++;
    spdlog::info("XDP attached to {} (ifindex={}).",
                 name, idx);
  }

  // ZMQ control socket.
  try {
    e.zmq_ctx = std::make_unique<zmq::context_t>(1);
    e.ctrl_socket = std::make_unique<zmq::socket_t>(
        *e.zmq_ctx, zmq::socket_type::rep);
    e.ctrl_socket->set(zmq::sockopt::rcvtimeo, 100);
    e.ctrl_socket->set(zmq::sockopt::linger, 0);

    if (e.socket_addr.starts_with("ipc://")) {
      std::string path = e.socket_addr.substr(6);
      if (std::filesystem::exists(path)) {
        std::filesystem::remove(path);
      }
    }
    e.ctrl_socket->bind(e.socket_addr);

    if (e.socket_addr.starts_with("ipc://")) {
      chmod(e.socket_addr.substr(6).c_str(), 0777);
    }
  } catch (const zmq::error_t& ex) {
    return MakeError(EngineError::kSocketError,
        std::format("ZMQ bind failed: {}", ex.what()));
  }
  spdlog::info("Control socket: {}", e.socket_addr);

  return {};
}

auto EngineRun(Engine& e, std::stop_token stop)
    -> std::expected<void, Error<EngineError>> {
  e.state.store(EngineState::kRunning);
  spdlog::info("Engine running. {} interfaces.",
               e.ifaces.count);

  // Start slow path thread if ring buffer available.
  if (e.bpf.events_fd >= 0) {
    if (SlowPathInit(
            e.slow_path, e.bpf.events_fd, e.bpf)) {
      e.slow_path_thread = std::jthread(
          [&e](std::stop_token st) {
            SlowPathRun(e.slow_path, st);
          });
    }
  }

  while (!stop.stop_requested() &&
         e.state.load(std::memory_order_acquire) !=
             EngineState::kStopping) {
    try {
      zmq::pollitem_t items[] = {
          {static_cast<void*>(*e.ctrl_socket),
           0, ZMQ_POLLIN, 0}};
      zmq::poll(items, 1,
                std::chrono::milliseconds(100));

      if (items[0].revents & ZMQ_POLLIN) {
        zmq::message_t request;
        auto res = e.ctrl_socket->recv(
            request, zmq::recv_flags::none);
        if (res) {
          std::string req_str(
              static_cast<char*>(request.data()),
              request.size());
          auto response = HandleRequest(e, req_str);
          zmq::message_t reply(response.size());
          std::memcpy(reply.data(), response.data(),
                      response.size());
          e.ctrl_socket->send(
              reply, zmq::send_flags::none);
        }
      }
    } catch (const zmq::error_t& ex) {
      if (ex.num() != ETERM && ex.num() != EINTR) {
        spdlog::error("ZMQ error: {}", ex.what());
      }
    }
  }

  spdlog::info("Engine stopping.");
  e.state.store(EngineState::kStopping);
  return {};
}

auto EngineStop(Engine& e) -> void {
  // Stop slow path.
  if (e.slow_path_thread.joinable()) {
    e.slow_path_thread.request_stop();
    e.slow_path_thread.join();
  }
  SlowPathStop(e.slow_path);

  spdlog::info("Detaching XDP.");
  for (uint32_t i = 0; i < e.ifaces.count; i++) {
    DetachXdp(e.ifaces.interfaces[i].ifindex);
  }
  e.ctrl_socket.reset();
  e.zmq_ctx.reset();
  if (e.socket_addr.starts_with("ipc://")) {
    std::filesystem::remove(
        e.socket_addr.substr(6));
  }
  e.state.store(EngineState::kNotRunning);
  spdlog::info("Engine stopped.");
}

auto ApplyConfig(Engine& e, const ConfigMsg& msg,
                 std::span<const std::byte> rule_data)
    -> std::expected<uint32_t, Error<EngineError>> {
  uint8_t standby =
      e.rules.active_table == 0 ? 1 : 0;
  int rules_fd = standby == 0
                     ? e.bpf.rules_a_fd
                     : e.bpf.rules_b_fd;
  FlushMap(rules_fd);

  size_t entry_size = sizeof(RuleKey) + sizeof(RuleValue);
  uint32_t inserted = 0;
  for (uint32_t i = 0; i < msg.rule_count; i++) {
    size_t off = i * entry_size;
    if (off + entry_size > rule_data.size()) {
      break;
    }
    RuleKey key;
    RuleValue val;
    std::memcpy(&key, rule_data.data() + off,
                sizeof(key));
    std::memcpy(&val,
                rule_data.data() + off + sizeof(key),
                sizeof(val));
    int err = bpf_map_update_elem(
        rules_fd, &key, &val, BPF_ANY);
    if (err) {
      continue;
    }
    inserted++;
  }

  e.rules.active_table = standby;
  e.current_config.active_table = standby;
  e.current_config.default_action = msg.default_action;
  e.current_config.conntrack_enabled =
      msg.conntrack_enabled;
  e.current_config.conntrack_timeout_s =
      msg.conntrack_timeout_s;
  e.conntrack.enabled = msg.conntrack_enabled != 0;
  e.conntrack.timeout_s = msg.conntrack_timeout_s;

  uint32_t cfg_key = 0;
  bpf_map_update_elem(e.bpf.config_fd, &cfg_key,
                      &e.current_config, BPF_ANY);
  spdlog::info("Applied {} rules, table={}.",
               inserted, standby);
  return inserted;
}

auto GetCounters(const Engine& e, uint32_t rule_count)
    -> std::expected<std::vector<RuleCounter>,
                     Error<EngineError>> {
  std::vector<RuleCounter> out(rule_count);
  for (uint32_t i = 0; i < rule_count; i++) {
    int ncpus = libbpf_num_possible_cpus();
    if (ncpus < 1) ncpus = 1;
    std::vector<RuleCounter> per_cpu(ncpus);
    if (bpf_map_lookup_elem(
            e.bpf.counters_fd, &i,
            per_cpu.data()) == 0) {
      for (int c = 0; c < ncpus; c++) {
        out[i].packets += per_cpu[c].packets;
        out[i].bytes += per_cpu[c].bytes;
      }
    }
  }
  return out;
}

auto GetRules(const Engine& e)
    -> std::expected<
        std::vector<std::pair<RuleKey, RuleValue>>,
        Error<EngineError>> {
  int map_fd = e.rules.active_table == 0
                   ? e.bpf.rules_a_fd
                   : e.bpf.rules_b_fd;
  std::vector<std::pair<RuleKey, RuleValue>> rules;
  if (map_fd < 0) return rules;
  RuleKey key{}, next{};
  RuleValue val{};
  while (bpf_map_get_next_key(
             map_fd, &key, &next) == 0) {
    if (bpf_map_lookup_elem(
            map_fd, &next, &val) == 0) {
      rules.emplace_back(next, val);
    }
    key = next;
  }
  return rules;
}

auto GetStatus(const Engine& e) -> StatusResponse {
  StatusResponse s{};
  s.pid = static_cast<uint32_t>(getpid());
  s.uptime_s = CurrentTimeS() - e.start_time_s;
  s.active_table = e.rules.active_table;
  s.iface_count = e.ifaces.count;
  int map_fd = e.rules.active_table == 0
                   ? e.bpf.rules_a_fd
                   : e.bpf.rules_b_fd;
  if (map_fd >= 0) {
    uint32_t count = 0;
    RuleKey key{}, next{};
    while (bpf_map_get_next_key(
               map_fd, &key, &next) == 0) {
      count++;
      key = next;
    }
    s.rule_count = count;
  }
  return s;
}

auto GetFullState(const Engine& e) -> nlohmann::json {
  json j;

  // Engine metadata.
  j["pid"] = static_cast<uint32_t>(getpid());
  j["uptime_s"] = CurrentTimeS() - e.start_time_s;

  // Each component reports its own state.
  j["rules"] = e.rules.GetState();
  j["interfaces"] = e.ifaces.GetState();
  j["conntrack"] = e.conntrack.GetState();

  // Slow path stats.
  j["slow_path"] = {
      {"events", e.slow_path.events_received},
      {"allowed", e.slow_path.connections_allowed},
      {"denied", e.slow_path.connections_denied},
  };

  return j;
}

auto OpenPinnedMaps(std::string_view pin_path)
    -> std::expected<BpfHandles, Error<BpfError>> {
  std::string base(pin_path);
  BpfHandles h;

  struct MapOpen {
    int* fd;
    const char* name;
  };
  MapOpen maps[] = {
      {&h.rules_a_fd, "rules_a"},
      {&h.rules_b_fd, "rules_b"},
      {&h.cidr_a_fd, "cidr_a"},
      {&h.cidr_b_fd, "cidr_b"},
      {&h.conntrack_fd, "conntrack"},
      {&h.counters_fd, "counters"},
      {&h.config_fd, "config"},
  };

  for (auto& m : maps) {
    std::string path = base + "/" + m.name;
    *m.fd = bpf_obj_get(path.c_str());
    if (*m.fd < 0) {
      return MakeError(BpfError::kMapLookupFailed,
          std::format("bpf_obj_get {} failed: {}",
                      path, strerror(errno)));
    }
  }
  return h;
}

}  // namespace f
