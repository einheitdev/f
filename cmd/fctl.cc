/// @file fctl.cc
/// @brief CLI tool for controlling the fd engine via ZMQ.

#include <signal.h>
#include <unistd.h>

#include <chrono>
#include <cstring>
#include <print>
#include <string>
#include <thread>

#include <CLI/CLI.hpp>
#include <zmq.hpp>

#include "f/engine.h"
#include "f/protocol.h"

namespace {

auto SendCmd(const std::string& addr, f::Cmd cmd,
             const std::string& payload = "")
    -> std::string {
  zmq::context_t ctx(1);
  zmq::socket_t sock(ctx, zmq::socket_type::req);
  sock.set(zmq::sockopt::linger, 0);
  sock.set(zmq::sockopt::rcvtimeo, 3000);
  sock.set(zmq::sockopt::sndtimeo, 3000);

  try {
    sock.connect(addr);
  } catch (const zmq::error_t& e) {
    return std::format(
        "{{\"error\":\"connect: {}\"}}", e.what());
  }

  std::string msg;
  msg += static_cast<char>(static_cast<uint8_t>(cmd));
  msg += payload;

  zmq::message_t req(msg.size());
  std::memcpy(req.data(), msg.data(), msg.size());
  if (!sock.send(req, zmq::send_flags::none)) {
    return R"({"error":"send failed"})";
  }

  zmq::message_t reply;
  if (!sock.recv(reply, zmq::recv_flags::none)) {
    return R"({"error":"recv timeout — is fd running?"})";
  }

  return std::string(
      static_cast<char*>(reply.data()), reply.size());
}

}  // namespace

int main(int argc, char** argv) {
  CLI::App app{"fctl — firewall engine control"};
  app.require_subcommand(1);
  app.fallthrough();

  std::string socket_addr =
      "ipc:///run/f/control.sock";
  app.add_option("-s,--socket", socket_addr,
                 "ZMQ IPC address");

  app.add_subcommand("status", "Show engine status");
  app.add_subcommand("stop", "Stop engine");

  CLI11_PARSE(app, argc, argv);

  auto* sub = app.get_subcommands().front();
  auto name = sub->get_name();

  if (name == "status") {
    std::println("{}", SendCmd(
        socket_addr, f::Cmd::kGetStatus));
    return 0;
  }

  if (name == "stop") {
    auto resp = SendCmd(
        socket_addr, f::Cmd::kStop);
    std::println("{}", resp);
    // Wait for process to exit.
    int pid = f::ReadPidFile(f::kEnginePidPath);
    if (pid > 0) {
      for (int i = 0; i < 50; i++) {
        std::this_thread::sleep_for(
            std::chrono::milliseconds(100));
        if (!f::IsProcessRunning(pid)) {
          std::println("Engine stopped (pid {}).", pid);
          return 0;
        }
      }
      std::println(stderr,
          "Engine did not exit (pid {}).", pid);
      return 1;
    }
    return 0;
  }

  return 0;
}
