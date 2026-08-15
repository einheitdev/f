/// @file f_confd.cc
/// @brief `f-confd` — the appliance configuration daemon.
///
/// It exists for one reason the CLI cannot serve: a commit-confirmed
/// window has to be counted down by a process that survives the
/// session which armed it. An operator who changes an interface,
/// a zone or an address over SSH may sever their own access with that
/// very change; the revert timer is what brings the box back. A timer
/// running inside their CLI would die with the connection it was
/// meant to protect.
///
/// Everything about the config lifecycle — candidate, commit,
/// rollback, history, the confirm window and its durable recovery
/// across a restart — is the framework's confd::Runtime. This binary
/// supplies the product half: what "apply" means for the f appliance
/// (f::confd::SystemBackend) and a socket to reach it on.

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <mutex>
#include <string>
#include <thread>

#include <CLI/CLI.hpp>
#include <spdlog/spdlog.h>

#include "einheit/cli/audit.h"
#include "einheit/cli/confd/runtime.h"
#include "einheit/cli/confd/zmq_server.h"
#include "einheit/cli/signals.h"
#include "f/confd/system_backend.h"

namespace {

std::mutex g_mu;
std::condition_variable g_cv;
std::atomic<bool> g_stop{false};

auto RequestStop() -> void {
  g_stop.store(true);
  g_cv.notify_all();
}

}  // namespace

auto main(int argc, char** argv) -> int {
  CLI::App app{"f-confd — appliance configuration daemon"};

  f::confd::SystemBackendOptions opts;
  std::string state_dir = "/var/lib/f/confd";
  std::string control = "ipc:///run/f/confd.sock";
  std::string events = "ipc:///run/f/confd.pub";
  bool no_activate = false;

  app.add_option("-c,--config", opts.config_path,
                 "System configuration file");
  app.add_option("--state-dir", state_dir,
                 "Durable confd state (history, pending confirm)");
  app.add_option("--snapshot-dir", opts.snapshot_dir,
                 "Where applied configurations are kept");
  app.add_option("--control", control, "Control (REP) endpoint");
  app.add_option("--events", events, "Event (PUB) endpoint");
  app.add_option("--dnsmasq-conf", opts.dnsmasq_conf,
                 "Where the generated dnsmasq config is installed");
  app.add_option("--networkd-dir", opts.networkd_dir,
                 "Where generated networkd units are installed");
  app.add_option("--sysctl-dir", opts.sysctl_dir,
                 "Where the generated sysctl drop-in is installed");
  app.add_flag("--force", opts.force,
               "Overwrite artifacts that were edited by hand");
  app.add_flag("--no-activate", no_activate,
               "Write artifacts but do not reload any service");

  CLI11_PARSE(app, argc, argv);

  spdlog::set_pattern("[%H:%M:%S %z] [%^%L%$] %v");

  if (opts.snapshot_dir.empty()) {
    opts.snapshot_dir = state_dir + "/snapshots";
  }
  if (no_activate) opts.activate = f::confd::NullActivator();

  std::error_code ec;
  std::filesystem::create_directories(state_dir, ec);

  einheit::cli::signals::IgnoreSigpipe();
  einheit::cli::signals::ControlHandlers handlers;
  handlers.on_shutdown = [] { RequestStop(); };
  handlers.on_dump_status = [] {
    spdlog::info("f-confd: running");
  };
  einheit::cli::signals::ControlListener listener(
      std::move(handlers));

  f::confd::SystemBackend backend(opts);

  einheit::cli::confd::RuntimeOptions rt_opts;
  rt_opts.state_dir = state_dir;
  rt_opts.audit = [](const einheit::cli::audit::Record& rec) {
    spdlog::info("audit user={} cmd={} ok={} outcome={}", rec.user,
                 rec.wire_command, rec.ok, rec.outcome);
  };
  einheit::cli::confd::Runtime runtime(backend, rt_opts);

  einheit::cli::confd::ZmqServerConfig srv_cfg;
  srv_cfg.control_endpoint = control;
  srv_cfg.event_endpoint = events;
  einheit::cli::confd::ZmqServer server(runtime, srv_cfg);

  spdlog::info("f-confd listening on {} (config {}, state {})",
               server.ControlEndpoint(), opts.config_path,
               state_dir);
  auto pending = runtime.PendingConfirmState();
  if (pending.armed) {
    spdlog::warn(
        "f-confd: a commit-confirm window is still open — "
        "commit {} reverts to {} unless confirmed",
        pending.pending_commit, pending.rollback_to);
  }

  {
    std::unique_lock<std::mutex> lock(g_mu);
    g_cv.wait(lock, [] { return g_stop.load(); });
  }
  spdlog::info("f-confd stopping.");
  return 0;
}
