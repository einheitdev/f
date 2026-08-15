/// @file fd.cc
/// @brief BPF engine daemon. No HTTP.

#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <fstream>
#include <print>
#include <string>
#include <thread>
#include <vector>

#include <CLI/CLI.hpp>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>
#include <yaml-cpp/yaml.h>

#include "f/engine.h"
#include "f/route_mgr.h"

namespace {

std::atomic<bool> g_interrupted{false};

void SignalHandler(int) {
  g_interrupted.store(true, std::memory_order_release);
}

/// File-watcher settings from the `watch:` config block.
struct WatchConfig {
  bool enabled = false;
  std::string source;
  std::string compiled_dir;
  std::string fwl = "fwl";
  int interval_s = 5;
};

auto RunEngine(const std::string& sock_addr,
               const std::string& pin_path,
               const std::string& bundle_dir,
               const WatchConfig& watch) -> int {
  f::Engine engine;
  auto res = f::EngineInit(
      engine, sock_addr, pin_path, bundle_dir);
  if (!res) {
    spdlog::error("Init failed: {}",
                  res.error().message);
    return 1;
  }

  // Configure the reload pipeline (kReloadProg → ReloadFromSource).
  // This is unconditional, and separate from `watch.enabled`: the
  // control command is how the CLI's `commit` makes a policy live, and
  // it needs the source path and a place to put the bundle whether or
  // not anything is polling the file. Configured only by the watcher
  // thread, an operator with `watch.enabled: false` got "watcher not
  // configured" back from a commit that had nothing to do with the
  // watcher. The compiled-bundle root defaults to bundle_dir so an
  // on-demand reload updates the same `current` symlink the cold-boot
  // path reads.
  std::string compiled_dir =
      watch.compiled_dir.empty() ? bundle_dir : watch.compiled_dir;
  engine.watcher.source_path = watch.source;
  engine.watcher.compiled_dir = compiled_dir;
  if (!watch.fwl.empty()) engine.watcher.fwl_path = watch.fwl;

  // The polling thread on top of it: recompile and reload when the
  // source file's contents change.
  if (watch.enabled) {
    auto wres = f::WatcherInit(
        engine.watcher, watch.source, compiled_dir,
        std::chrono::seconds(watch.interval_s));
    if (!wres) {
      spdlog::warn("Watcher disabled: {}",
                   wres.error().message);
    } else {
      engine.watcher.fwl_path = watch.fwl;
      f::WatcherStart(engine.watcher);
      spdlog::info(
          "Watching {} every {}s (compile via {}).",
          watch.source, watch.interval_s, watch.fwl);
    }
  }

  struct sigaction sa{};
  sa.sa_handler = SignalHandler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  sigaction(SIGINT, &sa, nullptr);
  sigaction(SIGTERM, &sa, nullptr);

  std::stop_source ss;
  std::jthread stop_checker([&ss]() {
    while (!g_interrupted.load(
               std::memory_order_acquire)) {
      std::this_thread::sleep_for(
          std::chrono::milliseconds(100));
    }
    ss.request_stop();
  });

  auto run_res = f::EngineRun(engine, ss.get_token());
  f::EngineStop(engine);
  return run_res ? 0 : 1;
}

}  // namespace

auto LoadConfig(const std::string& path,
                std::string& socket_addr,
                std::string& pin_path,
                std::string& log_level,
                WatchConfig& watch) -> bool {
  try {
    auto cfg = YAML::LoadFile(path);
    // `interfaces:` was the v0.1 attach list, and it is refused rather
    // than ignored. Every interface `fd` attaches to now comes from the
    // bundle manifest's zones, so a box whose fd.yaml still names ports
    // is a box whose operator believes he chose them. Naming the key is
    // the only way he finds out he did not.
    if (cfg["interfaces"] && cfg["interfaces"].size() > 0) {
      spdlog::warn(
          "{}: `interfaces:` is no longer read. fd attaches to the "
          "interfaces the bundle's zones name; declare them in "
          "/etc/f/system.yaml and in the policy's `zone` lines. "
          "Remove the key to silence this.",
          path);
    }
    if (cfg["socket"]) {
      socket_addr = cfg["socket"].as<std::string>();
    }
    if (cfg["pin_path"]) {
      pin_path = cfg["pin_path"].as<std::string>();
    }
    if (cfg["log_level"]) {
      log_level = cfg["log_level"].as<std::string>();
    }
    if (cfg["watch"]) {
      auto w = cfg["watch"];
      watch.enabled = w["enabled"] && w["enabled"].as<bool>();
      if (w["source"]) {
        watch.source = w["source"].as<std::string>();
      }
      if (w["compiled_dir"]) {
        watch.compiled_dir = w["compiled_dir"].as<std::string>();
      }
      if (w["fwl"]) {
        watch.fwl = w["fwl"].as<std::string>();
      }
      if (w["interval"]) {
        // "5s" or a bare integer of seconds.
        auto text = w["interval"].as<std::string>();
        if (!text.empty() && text.back() == 's') {
          text.pop_back();
        }
        watch.interval_s = std::max(1, std::stoi(text));
      }
    }
    return true;
  } catch (const std::exception& e) {
    spdlog::warn("Config {}: {}", path, e.what());
    return false;
  }
}

int main(int argc, char** argv) {
  spdlog::set_level(spdlog::level::info);
  spdlog::set_pattern(
      "[%H:%M:%S %z] [%^%L%$] %v");

  CLI::App app{"fd — eBPF firewall engine"};
  app.require_subcommand(1);
  app.fallthrough();

  std::string config_file;
  std::string socket_addr =
      "ipc:///run/f/control.sock";
  std::string pin_path = "/sys/fs/bpf/f";
  std::string bundle_dir = "/usr/share/f/compiled";
  std::string log_level = "info";

  auto* opt_config = app.add_option("-c,--config", config_file,
                                    "YAML config file");
  auto* opt_socket = app.add_option("-s,--socket", socket_addr,
                                    "ZMQ IPC control address");
  auto* opt_pin = app.add_option("--pin-path", pin_path,
                                 "BPF map pin directory");
  app.add_option("--bundle-dir", bundle_dir,
                 "Compiled-bundle root; <dir>/current must hold a "
                 "compiled bundle or fd refuses to start");
  auto* opt_log = app.add_option("-l,--log-level", log_level,
                                 "Log level")
                      ->check(CLI::IsMember({"trace", "debug",
                                             "info", "warn",
                                             "error"}));
  (void)opt_config;

  app.add_subcommand("run", "Run in foreground");
  app.add_subcommand("start", "Daemonize and run");
  app.add_subcommand(
      "close-forwarding",
      "Set net.ipv4.ip_forward=0 and exit. Run by fd.service's "
      "ExecStopPost so that a SIGKILLed or crashed daemon still "
      "leaves the box non-routing.");

  CLI11_PARSE(app, argc, argv);

  // Load config file. CLI flags override config values: the config
  // is read into separate variables and applied only where the
  // corresponding flag was not given. (It used to overwrite CLI
  // values unconditionally — a standalone `fd -s ipc://... run`
  // silently bound the config file's socket instead; found by the
  // netns system tests running against a rig with /etc/f/fd.yaml.)
  WatchConfig watch;
  {
    std::string cfg_socket = socket_addr;
    std::string cfg_pin = pin_path;
    std::string cfg_log = log_level;
    bool loaded = false;
    if (!config_file.empty()) {
      loaded = LoadConfig(config_file, cfg_socket,
                          cfg_pin, cfg_log, watch);
    } else if (std::ifstream("/etc/f/fd.yaml").good()) {
      loaded = LoadConfig("/etc/f/fd.yaml", cfg_socket,
                          cfg_pin, cfg_log, watch);
    }
    if (loaded) {
      if (opt_socket->count() == 0) socket_addr = cfg_socket;
      if (opt_pin->count() == 0) pin_path = cfg_pin;
      if (opt_log->count() == 0) log_level = cfg_log;
    }
  }

  if (log_level == "trace")
    spdlog::set_level(spdlog::level::trace);
  else if (log_level == "debug")
    spdlog::set_level(spdlog::level::debug);
  else if (log_level == "warn")
    spdlog::set_level(spdlog::level::warn);
  else if (log_level == "error")
    spdlog::set_level(spdlog::level::err);

  auto* sub = app.get_subcommands().front();

  // Before the already-running check, on purpose. This runs as
  // fd.service's ExecStopPost, and the daemon it is cleaning up after
  // may have been SIGKILLed with its pid file still on disk. Refusing
  // to close the box because a stale pid file looks like a running
  // engine is the failure this subcommand exists to prevent.
  if (sub->get_name() == "close-forwarding") {
    f::RouteMgr route;
    auto wrote = route.WriteForwarding(false);
    if (!wrote) {
      spdlog::critical(
          "forwarding: could not lower net.ipv4.ip_forward ({}). This "
          "box may be FORWARDING WITHOUT FILTERING — no f program is "
          "guaranteed to be attached. Set it by hand: sysctl -w "
          "net.ipv4.ip_forward=0",
          wrote.error());
      return 1;
    }
    spdlog::info(
        "forwarding: net.ipv4.ip_forward = 0 (fd is not running, so "
        "nothing on this box is filtering).");
    return 0;
  }

  int existing = f::ReadPidFile(f::kEnginePidPath);
  if (f::IsProcessRunning(existing)) {
    spdlog::error("Engine already running (pid {}).",
                  existing);
    return 1;
  }

  if (sub->get_name() == "start") {
    if (daemon(1, 1) != 0) {
      spdlog::error("daemon() failed.");
      return 1;
    }
    f::WritePidFile(f::kEnginePidPath);
    chmod(f::kEnginePidPath, 0644);
    int rc = RunEngine(socket_addr, pin_path, bundle_dir, watch);
    f::RemovePidFile(f::kEnginePidPath);
    return rc;
  }

  // "run" — foreground.
  f::WritePidFile(f::kEnginePidPath);
  int rc = RunEngine(socket_addr, pin_path, bundle_dir, watch);
  f::RemovePidFile(f::kEnginePidPath);
  return rc;
}
