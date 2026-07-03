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

namespace {

std::atomic<bool> g_interrupted{false};

void SignalHandler(int) {
  g_interrupted.store(true, std::memory_order_release);
}

auto ParseInterfaces(const std::string& s)
    -> std::vector<std::string> {
  std::vector<std::string> out;
  size_t start = 0;
  while (start < s.size()) {
    size_t end = s.find(',', start);
    if (end == std::string::npos) end = s.size();
    auto t = s.substr(start, end - start);
    if (!t.empty()) out.push_back(t);
    start = end + 1;
  }
  return out;
}

auto RunEngine(const std::string& sock_addr,
               const std::vector<std::string>& ifaces,
               const std::string& pin_path,
               const std::string& bundle_dir,
               const std::string& source_path,
               const std::string& compiled_dir,
               const std::string& fwl_path) -> int {
  f::Engine engine;
  auto res = f::EngineInit(
      engine, sock_addr, ifaces, pin_path, bundle_dir);
  if (!res) {
    spdlog::error("Init failed: {}",
                  res.error().message);
    return 1;
  }

  // Configure the reload pipeline (kReloadProg → ReloadFromSource).
  // The compiled-bundle root defaults to bundle_dir so an on-demand
  // reload updates the same `current` symlink the cold-boot path reads.
  engine.watcher.source_path = source_path;
  engine.watcher.compiled_dir =
      compiled_dir.empty() ? bundle_dir : compiled_dir;
  if (!fwl_path.empty()) engine.watcher.fwl_path = fwl_path;

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
                std::string& interfaces,
                std::string& socket_addr,
                std::string& pin_path,
                std::string& log_level,
                std::string& source_path,
                std::string& compiled_dir,
                std::string& fwl_path) -> bool {
  try {
    auto cfg = YAML::LoadFile(path);
    if (auto w = cfg["watch"]; w && w.IsMap()) {
      if (w["source"]) source_path = w["source"].as<std::string>();
      if (w["compiled_dir"]) {
        compiled_dir = w["compiled_dir"].as<std::string>();
      }
      if (w["fwl"]) fwl_path = w["fwl"].as<std::string>();
    }
    if (cfg["interfaces"]) {
      std::string ifaces;
      for (const auto& n : cfg["interfaces"]) {
        if (!ifaces.empty()) ifaces += ',';
        ifaces += n.as<std::string>();
      }
      if (!ifaces.empty()) interfaces = ifaces;
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
  std::string interfaces;
  std::string socket_addr =
      "ipc:///run/f/control.sock";
  std::string pin_path = "/sys/fs/bpf/f";
  std::string bundle_dir = "/usr/share/f/compiled";
  std::string log_level = "info";
  std::string source_path;
  std::string compiled_dir;
  std::string fwl_path;

  app.add_option("-c,--config", config_file,
                 "YAML config file");
  auto* opt_iface = app.add_option(
      "-i,--interfaces", interfaces, "Comma-separated NIC list");
  auto* opt_socket = app.add_option(
      "-s,--socket", socket_addr, "ZMQ IPC control address");
  auto* opt_pin = app.add_option(
      "--pin-path", pin_path, "BPF map pin directory");
  app.add_option("--bundle-dir", bundle_dir,
                 "Compiled-bundle root; <dir>/current/main.bpf.o "
                 "is loaded at startup when present");
  auto* opt_log = app.add_option(
      "-l,--log-level", log_level, "Log level")
      ->check(CLI::IsMember(
          {"trace", "debug", "info", "warn", "error"}));

  app.add_subcommand("run", "Run in foreground");
  app.add_subcommand("start", "Daemonize and run");

  CLI11_PARSE(app, argc, argv);

  // Load the config file, then re-apply anything given on the command
  // line so a genuine CLI flag wins over the config (the flags are the
  // more specific, one-off intent). Snapshot the CLI values first.
  std::string cli_if = interfaces, cli_sk = socket_addr,
              cli_pin = pin_path, cli_lg = log_level;
  if (!config_file.empty()) {
    LoadConfig(config_file, interfaces, socket_addr, pin_path,
               log_level, source_path, compiled_dir, fwl_path);
  } else if (std::ifstream("/etc/f/fd.yaml").good()) {
    LoadConfig("/etc/f/fd.yaml", interfaces, socket_addr, pin_path,
               log_level, source_path, compiled_dir, fwl_path);
  }
  if (opt_iface->count() > 0) interfaces = cli_if;
  if (opt_socket->count() > 0) socket_addr = cli_sk;
  if (opt_pin->count() > 0) pin_path = cli_pin;
  if (opt_log->count() > 0) log_level = cli_lg;

  if (log_level == "trace")
    spdlog::set_level(spdlog::level::trace);
  else if (log_level == "debug")
    spdlog::set_level(spdlog::level::debug);
  else if (log_level == "warn")
    spdlog::set_level(spdlog::level::warn);
  else if (log_level == "error")
    spdlog::set_level(spdlog::level::err);

  int existing = f::ReadPidFile(f::kEnginePidPath);
  if (f::IsProcessRunning(existing)) {
    spdlog::error("Engine already running (pid {}).",
                  existing);
    return 1;
  }

  auto ifaces = ParseInterfaces(interfaces);
  auto* sub = app.get_subcommands().front();

  if (sub->get_name() == "start") {
    if (daemon(1, 1) != 0) {
      spdlog::error("daemon() failed.");
      return 1;
    }
    f::WritePidFile(f::kEnginePidPath);
    chmod(f::kEnginePidPath, 0644);
    int rc = RunEngine(socket_addr, ifaces, pin_path, bundle_dir,
                       source_path, compiled_dir, fwl_path);
    f::RemovePidFile(f::kEnginePidPath);
    return rc;
  }

  // "run" — foreground.
  f::WritePidFile(f::kEnginePidPath);
  int rc = RunEngine(socket_addr, ifaces, pin_path, bundle_dir,
                       source_path, compiled_dir, fwl_path);
  f::RemovePidFile(f::kEnginePidPath);
  return rc;
}
