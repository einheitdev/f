/// @file engine.h
/// @brief BPF engine state and lifecycle. No HTTP, no Crow.

#ifndef INCLUDE_F_ENGINE_H_
#define INCLUDE_F_ENGINE_H_

#include <atomic>
#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <stop_token>
#include <string>
#include <thread>
#include <string_view>
#include <vector>

#include <zmq.hpp>

#include "f/bpf_loader.h"
#include "f/error.h"
#include "f/protocol.h"
#include "f/slow_path.h"
#include "f/types.h"

namespace f {

enum class EngineError : uint8_t {
  kBpfLoadFailed,
  kBpfAttachFailed,
  kMapUpdateFailed,
  kSocketError,
  kInvalidConfig,
  kAlreadyRunning,
};

enum class EngineState : uint8_t {
  kNotRunning,
  kStarting,
  kRunning,
  kStopping,
};

/// Attached interface record.
struct IfAttach {
  int ifindex;
  char name[16];
};

/// BPF engine state — no HTTP, no Crow.
struct Engine {
  std::atomic<EngineState> state{
      EngineState::kNotRunning};

  // ZMQ control socket.
  std::string socket_addr;
  std::unique_ptr<zmq::context_t> zmq_ctx;
  std::unique_ptr<zmq::socket_t> ctrl_socket;

  // BPF handles.
  BpfHandles bpf;

  // Pin path for BPF maps.
  std::string pin_path = "/sys/fs/bpf/f";

  // Attached interfaces.
  IfAttach interfaces[16];
  uint32_t iface_count = 0;

  // Current firewall config.
  FwConfig current_config{};

  // Slow path.
  SlowPath slow_path;
  std::jthread slow_path_thread;

  // Uptime tracking.
  uint64_t start_time_s = 0;
};

// PID file.
inline constexpr const char* kEnginePidPath =
    "/tmp/fd.pid";

auto WritePidFile(const char* path) -> bool;
auto ReadPidFile(const char* path) -> int;
auto RemovePidFile(const char* path) -> void;
auto IsProcessRunning(int pid) -> bool;

/// Initialize the engine: load BPF, attach XDP, pin maps,
/// bind ZMQ control socket.
auto EngineInit(Engine& e,
                std::string_view sock_addr,
                std::span<const std::string> ifaces,
                std::string_view pin_path)
    -> std::expected<void, Error<EngineError>>;

/// Run the engine ZMQ control loop (blocks until stop).
auto EngineRun(Engine& e, std::stop_token stop)
    -> std::expected<void, Error<EngineError>>;

/// Stop the engine: detach XDP, cleanup ZMQ.
auto EngineStop(Engine& e) -> void;

/// Replace the full rule set (A/B swap).
auto ApplyConfig(Engine& e, const ConfigMsg& msg,
                 std::span<const std::byte> rule_data)
    -> std::expected<uint32_t, Error<EngineError>>;

/// Read aggregated per-rule counters.
auto GetCounters(const Engine& e, uint32_t rule_count)
    -> std::expected<std::vector<RuleCounter>,
                     Error<EngineError>>;

/// Read current rule set from active table.
auto GetRules(const Engine& e)
    -> std::expected<
        std::vector<std::pair<RuleKey, RuleValue>>,
        Error<EngineError>>;

/// Read engine status.
auto GetStatus(const Engine& e)
    -> StatusResponse;

/// Open pinned BPF maps (for f-api read access).
auto OpenPinnedMaps(std::string_view pin_path)
    -> std::expected<BpfHandles, Error<BpfError>>;

}  // namespace f

#endif  // INCLUDE_F_ENGINE_H_
