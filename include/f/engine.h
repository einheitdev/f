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
#include "f/conntrack_mgr.h"
#include "f/egress_mgr.h"
#include "f/error.h"
#include "f/iface_mgr.h"
#include "f/nat_mgr.h"
#include "f/route_mgr.h"
#include "f/protocol.h"
#include "f/rule_table.h"
#include "f/slow_path.h"
#include "f/types.h"
#include "f/watcher.h"

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

/// BPF engine state — no HTTP, no Crow.
struct Engine {
  std::atomic<EngineState> state{
      EngineState::kNotRunning};

  // ZMQ control socket.
  std::string socket_addr;
  std::unique_ptr<zmq::context_t> zmq_ctx;
  std::unique_ptr<zmq::socket_t> ctrl_socket;

  // BPF handles (single-program path).
  BpfHandles bpf;

  // v0.4 § 6.2: handles for a loaded multi-zone bundle. Empty on the
  // single-program path; populated when EngineInit cold-boots a
  // multi-zone bundle or ApplyBundle hot-loads one. Kept so a later
  // reload can detach the per-zone programs before re-attaching.
  ZoneBundleHandles zone_bundle;

  // Pin path for BPF maps.
  std::string pin_path = "/sys/fs/bpf/f";

  // Components — each owns its state.
  RuleTable rules;
  IfaceMgr ifaces;
  ConntrackMgr conntrack;
  NatMgr nat;
  RouteMgr route;
  EgressMgr egress;

  // Current firewall config.
  FwConfig current_config{};

  // Slow path.
  SlowPath slow_path;
  std::jthread slow_path_thread;

  // Source file-watcher / hot-reload state (ReloadFromSource reads
  // source_path, compiled_dir, fwl_path from here).
  Watcher watcher;

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
///
/// `bundle_dir` is the parent of the `current` symlink the
/// reload pipeline maintains. When a freshly-compiled bundle
/// is staged there, `fd` cold-boots into it directly; otherwise
/// it falls back to the built-in `fw.bpf.o` search paths.
auto EngineInit(Engine& e,
                std::string_view sock_addr,
                std::span<const std::string> ifaces,
                std::string_view pin_path,
                std::string_view bundle_dir = "")
    -> std::expected<void, Error<EngineError>>;

/// Run the engine ZMQ control loop (blocks until stop).
auto EngineRun(Engine& e, std::stop_token stop)
    -> std::expected<void, Error<EngineError>>;

/// Answer one control-socket request: `req` is the raw frame the
/// client sent (`[1B Cmd][payload]`), the result is the JSON body to
/// send back.
///
/// Exposed rather than kept private to the control loop because the
/// dispatch table is where several of this project's silent defects
/// have lived — a handler reading a file descriptor its own daemon
/// never opened and reporting the empty result as an answer. A test
/// cannot see that through a socket it has to stand a daemon up for,
/// so the loop calls this and so do the tests.
auto HandleControlRequest(Engine& e, const std::string& req)
    -> std::string;

/// How many slots the per-CPU `counters` array actually has, read
/// from the map itself; 0 when there is no map or it cannot be
/// interrogated.
///
/// The bound belongs to the map, not to the reader. `src/engine.cc`
/// carried a literal 256 while `bpf/fw.bpf.c` declared
/// `max_entries = 10000`, two numbers in two files with nothing tying
/// them together, and every slot from 256 up accrued packets that no
/// counters request could show and no clear could zero.
auto CountersMapSlots(int counters_fd) -> uint32_t;

/// Stop the engine: detach XDP, cleanup ZMQ.
auto EngineStop(Engine& e) -> void;

/// Replace the full rule set (A/B swap).
auto ApplyConfig(Engine& e, const ConfigMsg& msg,
                 std::span<const std::byte> rule_data)
    -> std::expected<uint32_t, Error<EngineError>>;

// GetCounters(e, rule_count) was here: it read `counters[0 ..
// rule_count)` and called the result "aggregated per-rule counters".
// bpf/fw.bpf.c keys that map by MATCH TIER, so those were never
// per-rule numbers and the signature said they were. It had no
// callers anywhere in the tree; it is removed rather than left as a
// correctly-named-looking trap for the next reader. `kGetCounters`
// reports the same slots under their own ids, which is what they are.

/// Read current rule set from active table.
auto GetRules(const Engine& e)
    -> std::expected<
        std::vector<std::pair<RuleKey, RuleValue>>,
        Error<EngineError>>;

/// Read engine status.
auto GetStatus(const Engine& e)
    -> StatusResponse;

/// Aggregate state from all components.
auto GetFullState(const Engine& e)
    -> nlohmann::json;

/// Point the NAT manager at the currently loaded bundle's maps.
///
/// Called from both places a bundle becomes live — cold boot and hot
/// reload — because they are the two places `e.zone_bundle` changes and
/// a manager left holding the previous bundle's fds reports plausible
/// numbers about a table nothing is using.
auto AttachNatMgr(Engine& e) -> void;

/// Point RouteMgr at the loaded bundle's routing tally.
auto AttachRouteMgr(Engine& e) -> void;

/// Point EgressMgr at the loaded bundle's egress tracker.
///
/// Called from the same two places for the same reason: a manager left
/// holding the previous bundle's `fwl_egress_stats` fd reports numbers
/// that look right about a hook that is no longer there.
auto AttachEgressMgr(Engine& e, std::string_view bundle_dir) -> void;

/// Open pinned BPF maps (for f-api read access).
auto OpenPinnedMaps(std::string_view pin_path)
    -> std::expected<BpfHandles, Error<BpfError>>;

}  // namespace f

#endif  // INCLUDE_F_ENGINE_H_
