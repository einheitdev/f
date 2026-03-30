/// @file daemon.cc
/// @brief Daemon state management and ZMQ control loop.

#include "f/daemon.h"

#include <net/if.h>
#include <sys/stat.h>
#include <unistd.h>

#include <chrono>
#include <cstring>
#include <filesystem>
#include <format>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <spdlog/spdlog.h>
#include <zmq.hpp>

#include "f/api.h"

namespace f {

namespace {

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

auto HandleRequest(Daemon& d, const std::string& req_str)
    -> std::string {
  if (req_str.empty()) {
    return R"({"error":"empty request"})";
  }
  auto cmd = static_cast<Cmd>(
      static_cast<uint8_t>(req_str[0]));
  switch (cmd) {
    case Cmd::kGetStatus: {
      auto res = GetStatus(d);
      if (!res) {
        return R"({"error":"status failed"})";
      }
      auto& s = *res;
      return std::format(
          R"({{"pid":{},"uptime_s":{},"active_table":{})"
          R"(,"rule_count":{},"iface_count":{}}})",
          s.pid, s.uptime_s, s.active_table,
          s.rule_count, s.iface_count);
    }
    case Cmd::kStop: {
      spdlog::info("Received stop command.");
      d.state.store(DaemonState::kStopping,
                    std::memory_order_release);
      return R"({"ok":true})";
    }
    default:
      return R"({"error":"unknown command"})";
  }
}

}  // namespace

auto DaemonInit(Daemon& d,
                std::string_view sock_addr,
                std::span<const std::string> ifaces,
                uint16_t api_port,
                std::string_view static_dir,
                bool no_bpf)
    -> std::expected<void, Error<DaemonError>> {
  d.socket_addr = std::string(sock_addr);
  d.api_port = api_port;
  d.static_dir = std::string(static_dir);
  d.start_time_s = CurrentTimeS();
  d.state.store(DaemonState::kStarting);

  // Create log sink.
  d.log_sink = std::make_shared<RingBufferSink_mt>(1000);
  spdlog::default_logger()->sinks().push_back(d.log_sink);

  if (!no_bpf) {
    spdlog::info("Loading BPF program...");
    auto bpf_res = LoadProgram();
    if (!bpf_res) {
      return MakeError(DaemonError::kBpfLoadFailed,
          bpf_res.error().message);
    }
    d.bpf = *bpf_res;
    spdlog::info("BPF program loaded.");

    for (const auto& name : ifaces) {
      int idx = ResolveIfindex(name);
      if (idx == 0) {
        spdlog::warn("Interface {} not found, skipping.",
                     name);
        continue;
      }
      auto att_res = AttachXdp(d.bpf, idx);
      if (!att_res) {
        spdlog::error("Failed to attach to {}: {}",
                      name, att_res.error().message);
        continue;
      }
      auto& entry = d.interfaces[d.iface_count];
      entry.ifindex = idx;
      std::strncpy(entry.name, name.c_str(),
                   sizeof(entry.name) - 1);
      d.iface_count++;
      spdlog::info("Attached XDP to {} (ifindex={}).",
                   name, idx);
    }
  } else {
    spdlog::warn("BPF disabled — running in dev mode.");
  }

  // Set up ZMQ control socket.
  try {
    d.zmq_ctx = std::make_unique<zmq::context_t>(1);
    d.ctrl_socket = std::make_unique<zmq::socket_t>(
        *d.zmq_ctx, zmq::socket_type::rep);
    d.ctrl_socket->set(zmq::sockopt::rcvtimeo, 100);
    d.ctrl_socket->set(zmq::sockopt::linger, 0);

    // Clean up stale IPC socket file.
    if (d.socket_addr.starts_with("ipc://")) {
      std::string path = d.socket_addr.substr(6);
      if (std::filesystem::exists(path)) {
        spdlog::debug("Removing stale socket: {}", path);
        std::filesystem::remove(path);
      }
    }

    d.ctrl_socket->bind(d.socket_addr);

    // Make IPC socket world-accessible so CLI tools
    // can connect without root.
    if (d.socket_addr.starts_with("ipc://")) {
      std::string path = d.socket_addr.substr(6);
      chmod(path.c_str(), 0777);
    }
  } catch (const zmq::error_t& e) {
    return MakeError(DaemonError::kSocketError,
        std::format("ZMQ bind {} failed: {}",
                    d.socket_addr, e.what()));
  }
  spdlog::info("Control socket: {}", d.socket_addr);

  return {};
}

auto DaemonRun(Daemon& d, std::stop_token stop)
    -> std::expected<void, Error<DaemonError>> {
  spdlog::info("Daemon running. API port={}, "
               "{} interfaces.",
               d.api_port, d.iface_count);

  // Start Crow API thread.
  auto api_data = std::make_shared<ApiData>(ApiData{
      .daemon = &d,
      .log_sink = d.log_sink,
      .api_port = d.api_port,
      .static_dir = d.static_dir,
  });
  d.api_thread = std::jthread(
      [api_data](std::stop_token st) {
        RunApi(st, api_data);
      });

  d.state.store(DaemonState::kRunning);

  // Main loop: poll ZMQ control socket.
  while (!stop.stop_requested() &&
         d.state.load(std::memory_order_acquire) !=
             DaemonState::kStopping) {
    try {
      zmq::pollitem_t items[] = {
          {static_cast<void*>(*d.ctrl_socket),
           0, ZMQ_POLLIN, 0}};
      zmq::poll(items, 1,
                std::chrono::milliseconds(100));

      if (items[0].revents & ZMQ_POLLIN) {
        zmq::message_t request;
        auto res = d.ctrl_socket->recv(
            request, zmq::recv_flags::none);
        if (res) {
          std::string req_str(
              static_cast<char*>(request.data()),
              request.size());
          auto response = HandleRequest(d, req_str);
          zmq::message_t reply(response.size());
          std::memcpy(reply.data(), response.data(),
                      response.size());
          d.ctrl_socket->send(
              reply, zmq::send_flags::none);
        }
      }
    } catch (const zmq::error_t& e) {
      if (e.num() != ETERM && e.num() != EINTR) {
        spdlog::error("ZMQ error: {}", e.what());
      }
    }
  }

  spdlog::info("Daemon stopping.");
  d.state.store(DaemonState::kStopping);
  d.api_thread.request_stop();
  return {};
}

auto DaemonStop(Daemon& d) -> void {
  spdlog::info("Detaching XDP from all interfaces.");
  for (uint32_t i = 0; i < d.iface_count; i++) {
    auto res = DetachXdp(d.interfaces[i].ifindex);
    if (!res) {
      spdlog::warn("Detach {} failed: {}",
                   d.interfaces[i].name,
                   res.error().message);
    }
  }
  d.ctrl_socket.reset();
  d.zmq_ctx.reset();
  // Clean up IPC socket file.
  if (d.socket_addr.starts_with("ipc://")) {
    std::filesystem::remove(d.socket_addr.substr(6));
  }
  d.state.store(DaemonState::kNotRunning);
  spdlog::info("Daemon stopped.");
}

auto ApplyConfig(Daemon& d, const ConfigMsg& msg,
                 std::span<const std::byte> rule_data)
    -> std::expected<uint32_t, Error<DaemonError>> {
  uint8_t standby =
      d.current_config.active_table == 0 ? 1 : 0;
  int rules_fd = standby == 0
                     ? d.bpf.rules_a_fd
                     : d.bpf.rules_b_fd;
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
      spdlog::warn("Rule insert {} failed: {}",
                   i, std::strerror(-err));
      continue;
    }
    inserted++;
  }

  d.current_config.active_table = standby;
  d.current_config.default_action = msg.default_action;
  d.current_config.conntrack_enabled =
      msg.conntrack_enabled;
  d.current_config.conntrack_timeout_s =
      msg.conntrack_timeout_s;

  uint32_t cfg_key = 0;
  bpf_map_update_elem(d.bpf.config_fd, &cfg_key,
                      &d.current_config, BPF_ANY);
  spdlog::info("Applied {} rules, active table={}.",
               inserted, standby);
  return inserted;
}

auto GetCounters(const Daemon& d, uint32_t rule_count)
    -> std::expected<std::vector<RuleCounter>,
                     Error<DaemonError>> {
  std::vector<RuleCounter> out(rule_count);
  for (uint32_t i = 0; i < rule_count; i++) {
    int ncpus = libbpf_num_possible_cpus();
    if (ncpus < 1) {
      ncpus = 1;
    }
    std::vector<RuleCounter> per_cpu(ncpus);
    int err = bpf_map_lookup_elem(
        d.bpf.counters_fd, &i, per_cpu.data());
    if (err) {
      continue;
    }
    for (int c = 0; c < ncpus; c++) {
      out[i].packets += per_cpu[c].packets;
      out[i].bytes += per_cpu[c].bytes;
    }
  }
  return out;
}

auto GetRules(const Daemon& d)
    -> std::expected<
        std::vector<std::pair<RuleKey, RuleValue>>,
        Error<DaemonError>> {
  int map_fd = d.current_config.active_table == 0
                   ? d.bpf.rules_a_fd
                   : d.bpf.rules_b_fd;
  std::vector<std::pair<RuleKey, RuleValue>> rules;
  if (map_fd < 0) {
    return rules;
  }
  RuleKey key{};
  RuleKey next_key{};
  RuleValue val{};
  while (bpf_map_get_next_key(
             map_fd, &key, &next_key) == 0) {
    if (bpf_map_lookup_elem(
            map_fd, &next_key, &val) == 0) {
      rules.emplace_back(next_key, val);
    }
    key = next_key;
  }
  return rules;
}

auto GetStatus(const Daemon& d)
    -> std::expected<StatusResponse,
                     Error<DaemonError>> {
  StatusResponse resp{};
  resp.pid = static_cast<uint32_t>(getpid());
  resp.uptime_s = CurrentTimeS() - d.start_time_s;
  resp.active_table = d.current_config.active_table;
  resp.iface_count = d.iface_count;

  int map_fd = d.current_config.active_table == 0
                   ? d.bpf.rules_a_fd
                   : d.bpf.rules_b_fd;
  if (map_fd >= 0) {
    uint32_t count = 0;
    RuleKey key{};
    RuleKey next_key{};
    while (bpf_map_get_next_key(
               map_fd, &key, &next_key) == 0) {
      count++;
      key = next_key;
    }
    resp.rule_count = count;
  }
  return resp;
}

}  // namespace f
