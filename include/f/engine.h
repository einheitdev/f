/// @file engine.h
/// @brief BPF engine state and lifecycle. No HTTP, no Crow.

#ifndef INCLUDE_F_ENGINE_H_
#define INCLUDE_F_ENGINE_H_

#include <atomic>
#include <cstdint>
#include <expected>
#include <memory>
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
#include "f/neigh_mgr.h"
#include "f/route_mgr.h"
#include "f/protocol.h"
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

  // v0.4 § 6.2: handles for the loaded multi-zone bundle, populated
  // when EngineInit cold-boots one or ApplyBundle hot-loads one. Kept
  // so a later reload can detach the per-zone programs before
  // re-attaching. There is no other kind of loaded policy: the v0.1
  // single-program `BpfHandles` that used to sit beside this is gone
  // (see bpf_loader.h for what it did when it ran).
  ZoneBundleHandles zone_bundle;

  // Pin path for BPF maps.
  std::string pin_path = "/sys/fs/bpf/f";

  // Components — each owns its state.
  IfaceMgr ifaces;
  ConntrackMgr conntrack;
  NatMgr nat;
  RouteMgr route;
  // Beside RouteMgr and not inside it, because they answer opposite
  // questions about the same event: RouteMgr REPORTS that forwards were
  // lost, NeighMgr acts so that the next one is not. Folding the second
  // into the first is how the report would end up conditional on the
  // cure — and the whole reason this defect stayed invisible for a week
  // is that the box had no honest report of it.
  NeighMgr neigh;
  EgressMgr egress;

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

/// Initialize the engine: load the staged bundle, attach XDP per zone,
/// bind the ZMQ control socket.
///
/// `bundle_dir` is the parent of the `current` symlink the reload
/// pipeline maintains; `<bundle_dir>/current` must hold a compiled
/// bundle. There is no fallback. A missing, unreadable or non-bundle
/// `current` is an error and the daemon does not start — a box that
/// cannot load the operator's policy must not come up claiming to be a
/// firewall, and the fallback that used to be here came up ALLOWING
/// everything.
auto EngineInit(Engine& e,
                std::string_view sock_addr,
                std::string_view pin_path,
                std::string_view bundle_dir)
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

/// Stop the engine: detach XDP, cleanup ZMQ.
auto EngineStop(Engine& e) -> void;

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
///
/// Called from the same two places, and it was NOT — cold boot only.
/// After any hot reload (which is what every `commit` performs)
/// `e.route.stats_fd` still pointed into the object `CloseZoneBundle`
/// had just closed, so `fctl status` reported `0 routed / 0 bridged`
/// for the rest of the process's life and `RouteMgr::Report()` could
/// never fire. Routed-versus-bridged is the entire difference between
/// a working gateway and a silent one and it is invisible in a
/// capture, so this component going blind has no other symptom. Third
/// site of the same defect, after NAT and egress.
auto AttachRouteMgr(Engine& e) -> void;

/// Point NeighMgr at the loaded bundle's unresolved-next-hop queue, and
/// at the interfaces the datapath is on.
///
/// Called from the same two places as the three above, and AFTER
/// `e.ifaces` has been re-derived at each of them, because the
/// interface list is not decoration here — it is the gate that decides
/// which interfaces this daemon may put ARP on. A stale list would let
/// it solicit through a port the current policy has left, and the port
/// this box is administered over is exactly the one that must never be
/// reachable that way.
auto AttachNeighMgr(Engine& e) -> void;

/// Decide `net.ipv4.ip_forward` from what is actually in the packet
/// path, and write it. `when` names the moment for the journal and for
/// `fctl status` ("cold boot", "reload", "shutdown").
///
/// Fail-closed: this box forwards only while it filters. See
/// `RouteMgr`'s header for the invariant and for why the periodic
/// check is asymmetric.
auto SetForwardingFromDatapath(Engine& e, std::string_view when)
    -> void;

/// Point EgressMgr at the loaded bundle's egress tracker.
///
/// Called from the same two places for the same reason: a manager left
/// holding the previous bundle's `fwl_egress_stats` fd reports numbers
/// that look right about a hook that is no longer there.
auto AttachEgressMgr(Engine& e, std::string_view bundle_dir) -> void;

}  // namespace f

#endif  // INCLUDE_F_ENGINE_H_
