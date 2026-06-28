/// @file f_api.cc
/// @brief Web dashboard daemon. Reads pinned BPF maps.
///        Independent of the fd engine process.

#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <print>
#include <string>
#include <thread>

#include <CLI/CLI.hpp>
#include <spdlog/spdlog.h>

#include "f/api.h"
#include "f/engine.h"
#include "f/log_sink.h"

namespace {

inline constexpr const char* kApiPidPath =
    "/tmp/f-api.pid";

std::atomic<bool> g_interrupted{false};

void SignalHandler(int) {
  g_interrupted.store(true, std::memory_order_release);
}

auto RunApiDaemon(uint16_t port,
                  const std::string& static_dir,
                  const std::string& pin_path,
                  const std::string& engine_addr)
    -> int {
  auto log_sink =
      std::make_shared<f::RingBufferSink_mt>(1000);
  spdlog::default_logger()->sinks().push_back(log_sink);

  // Open pinned BPF maps for counter/rule reads.
  // Requires CAP_BPF or root to open bpffs files.
  f::BpfHandles maps{};
  auto map_res = f::OpenPinnedMaps(pin_path);
  if (map_res) {
    maps = *map_res;
    spdlog::info("Opened pinned maps at {}.", pin_path);
  } else {
    spdlog::warn("Could not open pinned maps: {} "
                 "— running without BPF data.",
                 map_res.error().message);
  }

  auto api_data = std::make_shared<f::ApiData>(f::ApiData{
      .maps = maps,
      .log_sink = log_sink,
      .engine_addr = engine_addr,
      .api_port = port,
      .static_dir = static_dir,
  });

  spdlog::info("Starting web dashboard on port {}.",
               port);

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

  f::RunApi(ss.get_token(), api_data);
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  spdlog::set_level(spdlog::level::info);
  spdlog::set_pattern(
      "[%H:%M:%S %z] [%^%L%$] %v");

  CLI::App app{"f-api — firewall web dashboard"};
  app.require_subcommand(1);
  app.fallthrough();

  uint16_t port = 8080;
  std::string static_dir = "ui/";
  std::string pin_path = "/sys/fs/bpf/f";
  std::string engine_addr =
      "ipc:///run/f/control.sock";
  std::string log_level = "info";

  app.add_option("-p,--port", port, "HTTP port");
  app.add_option("--static-dir", static_dir,
                 "UI static files");
  app.add_option("--pin-path", pin_path,
                 "BPF pinned map path");
  app.add_option("--engine", engine_addr,
                 "Engine ZMQ address");
  app.add_option("-l,--log-level", log_level,
                 "Log level")
      ->check(CLI::IsMember(
          {"trace", "debug", "info", "warn", "error"}));

  app.add_subcommand("run", "Run in foreground");
  app.add_subcommand("start", "Daemonize and run");
  app.add_subcommand("stop", "Stop dashboard");

  CLI11_PARSE(app, argc, argv);

  if (log_level == "trace")
    spdlog::set_level(spdlog::level::trace);
  else if (log_level == "debug")
    spdlog::set_level(spdlog::level::debug);
  else if (log_level == "warn")
    spdlog::set_level(spdlog::level::warn);
  else if (log_level == "error")
    spdlog::set_level(spdlog::level::err);

  auto* sub = app.get_subcommands().front();
  auto name = sub->get_name();

  if (name == "stop") {
    int pid = f::ReadPidFile(kApiPidPath);
    if (pid > 0 && f::IsProcessRunning(pid)) {
      kill(pid, SIGTERM);
      for (int i = 0; i < 50; i++) {
        std::this_thread::sleep_for(
            std::chrono::milliseconds(100));
        if (!f::IsProcessRunning(pid)) {
          std::println("Dashboard stopped (pid {}).",
                       pid);
          return 0;
        }
      }
      std::println(stderr, "Did not exit (pid {}).",
                   pid);
      return 1;
    }
    std::println(stderr, "Dashboard not running.");
    return 1;
  }

  if (name == "start") {
    if (daemon(1, 1) != 0) {
      spdlog::error("daemon() failed.");
      return 1;
    }
    f::WritePidFile(kApiPidPath);
    chmod(kApiPidPath, 0644);
    int rc = RunApiDaemon(
        port, static_dir, pin_path, engine_addr);
    f::RemovePidFile(kApiPidPath);
    return rc;
  }

  // "run" — foreground.
  f::WritePidFile(kApiPidPath);
  int rc = RunApiDaemon(
      port, static_dir, pin_path, engine_addr);
  f::RemovePidFile(kApiPidPath);
  return rc;
}
