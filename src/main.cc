/// @file main.cc
/// @brief fd entry point — CLI parsing and daemon lifecycle.

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
#include <vector>

#include <CLI/CLI.hpp>
#include <spdlog/spdlog.h>
#include <zmq.hpp>

#include "f/daemon.h"
#include "f/protocol.h"

namespace f {

auto WritePidFile(const char* path) -> bool {
  std::ofstream f(path);
  if (!f) {
    return false;
  }
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

}  // namespace f

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
    if (end == std::string::npos) {
      end = s.size();
    }
    auto token = s.substr(start, end - start);
    if (!token.empty()) {
      out.push_back(token);
    }
    start = end + 1;
  }
  return out;
}

/// Send a command to the daemon via ZMQ REQ.
auto SendControlCmd(const std::string& addr,
                    f::Cmd cmd) -> int {
  zmq::context_t ctx(1);
  zmq::socket_t sock(ctx, zmq::socket_type::req);
  sock.set(zmq::sockopt::linger, 0);
  sock.set(zmq::sockopt::rcvtimeo, 2000);
  sock.set(zmq::sockopt::sndtimeo, 2000);

  try {
    sock.connect(addr);
  } catch (const zmq::error_t& e) {
    std::println(stderr, "connect {}: {}", addr, e.what());
    return 1;
  }

  uint8_t payload[] = {static_cast<uint8_t>(cmd)};
  zmq::message_t request(sizeof(payload));
  std::memcpy(request.data(), payload, sizeof(payload));
  auto sres = sock.send(request, zmq::send_flags::none);
  if (!sres) {
    std::println(stderr, "send failed — is fd running?");
    return 1;
  }

  zmq::message_t reply;
  auto rres = sock.recv(reply, zmq::recv_flags::none);
  if (!rres) {
    std::println(stderr, "recv timeout — is fd running?");
    return 1;
  }

  std::string resp(
      static_cast<char*>(reply.data()), reply.size());
  std::println("{}", resp);
  return 0;
}

/// Stop daemon and wait for it to exit.
auto StopDaemon(const std::string& addr) -> int {
  int rc = SendControlCmd(addr, f::Cmd::kStop);
  if (rc != 0) {
    return rc;
  }
  // Wait for process to exit (up to 5s).
  int pid = f::ReadPidFile(f::kPidFilePath);
  if (pid > 0) {
    for (int i = 0; i < 50; i++) {
      std::this_thread::sleep_for(
          std::chrono::milliseconds(100));
      if (!f::IsProcessRunning(pid)) {
        std::println("Daemon stopped (pid {}).", pid);
        return 0;
      }
    }
    std::println(stderr,
        "Daemon did not exit after 5s (pid {}).", pid);
    return 1;
  }
  return 0;
}

/// Common daemon init + run logic.
auto RunDaemon(const std::string& sock_addr,
               const std::vector<std::string>& ifaces,
               uint16_t port,
               const std::string& static_dir,
               bool no_bpf) -> int {
  f::Daemon daemon;
  auto res = f::DaemonInit(
      daemon, sock_addr, ifaces, port, static_dir,
      no_bpf);
  if (!res) {
    spdlog::error("Init failed: {}",
                  res.error().message);
    return 1;
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

  auto run_res = f::DaemonRun(daemon, ss.get_token());
  if (!run_res) {
    spdlog::error("Run failed: {}",
                  run_res.error().message);
  }

  f::DaemonStop(daemon);
  return run_res ? 0 : 1;
}

}  // namespace

int main(int argc, char** argv) {
  spdlog::set_level(spdlog::level::info);
  spdlog::set_pattern(
      "[%H:%M:%S %z] [%^%L%$] [thread %t] %v");

  CLI::App app{"fd — eBPF firewall daemon"};
  app.require_subcommand(1);
  app.fallthrough();

  uint16_t port = 8080;
  std::string interfaces;
  std::string socket_addr =
      "ipc:///tmp/fd-control.sock";
  std::string static_dir = "ui/";
  std::string log_level = "info";
  bool no_bpf = false;

  app.add_option("-p,--port", port, "API listen port");
  app.add_option("-i,--interfaces", interfaces,
                 "Comma-separated interface list");
  app.add_option("-s,--socket", socket_addr,
                 "ZMQ IPC control socket address");
  app.add_option("--static-dir", static_dir,
                 "UI static files directory");
  app.add_option("-l,--log-level", log_level, "Log level")
      ->check(CLI::IsMember(
          {"trace", "debug", "info", "warn", "error"}));
  app.add_flag("--no-bpf", no_bpf,
               "Skip BPF loading (UI/API dev mode)");

  app.add_subcommand("run", "Run in foreground");
  app.add_subcommand("start", "Daemonize and run");
  app.add_subcommand("stop", "Stop running daemon");
  app.add_subcommand("status", "Show daemon status");

  CLI11_PARSE(app, argc, argv);

  if (log_level == "trace") {
    spdlog::set_level(spdlog::level::trace);
  } else if (log_level == "debug") {
    spdlog::set_level(spdlog::level::debug);
  } else if (log_level == "warn") {
    spdlog::set_level(spdlog::level::warn);
  } else if (log_level == "error") {
    spdlog::set_level(spdlog::level::err);
  }

  auto* sub = app.get_subcommands().front();
  auto name = sub->get_name();

  if (name == "stop") {
    return StopDaemon(socket_addr);
  }
  if (name == "status") {
    return SendControlCmd(socket_addr, f::Cmd::kGetStatus);
  }

  // Check if already running.
  int existing = f::ReadPidFile(f::kPidFilePath);
  if (f::IsProcessRunning(existing)) {
    spdlog::error("Daemon already running (pid {}).",
                  existing);
    return 1;
  }

  auto ifaces = ParseInterfaces(interfaces);

  if (name == "start") {
    // Fork & daemonize. nochdir=1 keeps cwd, noclose=1
    // keeps stdio for logging.
    if (daemon(1, 1) != 0) {
      spdlog::error("daemon() failed: {}",
                    std::strerror(errno));
      return 1;
    }

    // We are now the daemon child process.
    if (!f::WritePidFile(f::kPidFilePath)) {
      spdlog::error("Failed to write PID file.");
      return 1;
    }
    chmod(f::kPidFilePath, 0644);

    int rc = RunDaemon(
        socket_addr, ifaces, port, static_dir, no_bpf);

    f::RemovePidFile(f::kPidFilePath);
    return rc;
  }

  // "run" — foreground, no fork.
  if (!f::WritePidFile(f::kPidFilePath)) {
    spdlog::warn("Could not write PID file.");
  }
  int rc = RunDaemon(
      socket_addr, ifaces, port, static_dir, no_bpf);
  f::RemovePidFile(f::kPidFilePath);
  return rc;
}
