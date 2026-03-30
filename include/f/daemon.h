/// @file daemon.h
/// @brief Daemon state and lifecycle functions.

#ifndef INCLUDE_F_DAEMON_H_
#define INCLUDE_F_DAEMON_H_

#include <atomic>
#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <zmq.hpp>

#include "f/bpf_loader.h"
#include "f/error.h"
#include "f/log_sink.h"
#include "f/protocol.h"
#include "f/types.h"

namespace f {

enum class DaemonError : uint8_t {
  kBpfLoadFailed,
  kBpfAttachFailed,
  kMapUpdateFailed,
  kSocketError,
  kInvalidConfig,
  kAlreadyAttached,
  kNotRunning,
};

enum class DaemonState : uint8_t {
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

/// Core daemon state.
struct Daemon {
  // Lifecycle.
  std::atomic<DaemonState> state{DaemonState::kNotRunning};

  // ZMQ control socket.
  std::string socket_addr;
  std::unique_ptr<zmq::context_t> zmq_ctx;
  std::unique_ptr<zmq::socket_t> ctrl_socket;

  // BPF handles.
  BpfHandles bpf;

  // Attached interfaces.
  IfAttach interfaces[16];
  uint32_t iface_count = 0;

  // Current firewall config.
  FwConfig current_config{};

  // Crow API.
  std::jthread api_thread;
  uint16_t api_port = 8080;
  std::string static_dir = "ui/";

  // Shared log ring buffer.
  std::shared_ptr<RingBufferSink_mt> log_sink;

  // Uptime tracking.
  uint64_t start_time_s = 0;
};

// PID file management.
inline constexpr const char* kPidFilePath =
    "/tmp/fd.pid";

auto WritePidFile(const char* path) -> bool;
auto ReadPidFile(const char* path) -> int;
auto RemovePidFile(const char* path) -> void;
auto IsProcessRunning(int pid) -> bool;

/// Initialize the daemon. Populates `d` in place.
auto DaemonInit(Daemon& d,
                std::string_view sock_addr,
                std::span<const std::string> ifaces,
                uint16_t api_port,
                std::string_view static_dir,
                bool no_bpf = false)
    -> std::expected<void, Error<DaemonError>>;

/// Run the daemon main loop (blocks until stop).
auto DaemonRun(Daemon& d, std::stop_token stop)
    -> std::expected<void, Error<DaemonError>>;

/// Stop the daemon: detach XDP, close sockets.
auto DaemonStop(Daemon& d) -> void;

/// Replace the full rule set (A/B swap).
auto ApplyConfig(Daemon& d, const ConfigMsg& msg,
                 std::span<const std::byte> rule_data)
    -> std::expected<uint32_t, Error<DaemonError>>;

/// Read aggregated per-rule counters.
auto GetCounters(const Daemon& d, uint32_t rule_count)
    -> std::expected<std::vector<RuleCounter>,
                     Error<DaemonError>>;

/// Read current rule set from active table.
auto GetRules(const Daemon& d)
    -> std::expected<
        std::vector<std::pair<RuleKey, RuleValue>>,
        Error<DaemonError>>;

/// Read daemon status.
auto GetStatus(const Daemon& d)
    -> std::expected<StatusResponse,
                     Error<DaemonError>>;

}  // namespace f

#endif  // INCLUDE_F_DAEMON_H_
