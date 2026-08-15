/// @file test_fw_apply_confirmed.cc
/// @brief `apply system confirmed` from the CLI's side of the wire.
///
/// The backend tests prove the revert works. These prove the operator
/// can actually reach it: that `apply system confirmed` routes through
/// f-confd, that `confirm system` cancels the window, that `show
/// system` shows the countdown to somebody who reconnects, and — the
/// case that matters most — that when f-confd is not running the CLI
/// refuses the confirmed apply instead of quietly performing an apply
/// with no way back.

#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <thread>

#include <nlohmann/json.hpp>

#include "adapters/fw/transport.h"
#include "einheit/cli/confd/runtime.h"
#include "einheit/cli/confd/zmq_server.h"
#include "einheit/cli/protocol/envelope.h"
#include "f/confd/system_backend.h"

namespace {

using std::chrono_literals::operator""s;
using std::chrono_literals::operator""ms;
using json = nlohmann::json;
namespace cli = einheit::cli;
namespace cc = cli::confd;
namespace proto = cli::protocol;
namespace fw = einheit::adapters::fw;

auto ConfigWithAddress(const std::string& addr) -> std::string {
  std::ostringstream o;
  o << "zones:\n"
    << "  lan:\n"
    << "interfaces:\n"
    << "  lan0:\n"
    << "    mac: \"52:54:00:aa:bb:02\"\n"
    << "    address: " << addr << "\n"
    << "    zone: lan\n";
  return o.str();
}

auto ReadFileText(const std::filesystem::path& p) -> std::string {
  std::ifstream in(p);
  std::ostringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

auto WriteFileText(const std::filesystem::path& p,
                   const std::string& text) -> void {
  std::filesystem::create_directories(p.parent_path());
  std::ofstream out(p);
  out << text;
}

class Box {
 public:
  Box() {
    root_ = std::filesystem::temp_directory_path() /
            ("f_apply_confirm_" + std::to_string(::getpid()) + "_" +
             std::to_string(++counter_));
    std::filesystem::remove_all(root_);
    std::filesystem::create_directories(root_);
    WriteFileText(config(), ConfigWithAddress("10.10.0.1/24"));
  }

  ~Box() {
    std::error_code ec;
    std::filesystem::remove_all(root_, ec);
  }

  auto config() const -> std::filesystem::path {
    return root_ / "system.yaml";
  }
  auto endpoint() const -> std::string {
    return "ipc://" + (root_ / "confd.sock").string();
  }
  auto events() const -> std::string {
    return "ipc://" + (root_ / "confd.pub").string();
  }

  auto TransportConfig() const -> fw::FLocalConfig {
    fw::FLocalConfig cfg;
    cfg.system_config = config().string();
    cfg.dnsmasq_conf = (root_ / "dnsmasq.conf").string();
    cfg.confd_socket = endpoint();
    cfg.fd_socket = "ipc://" + (root_ / "fd.sock").string();
    cfg.fw_source = (root_ / "rules").string();
    cfg.fwl_path = "/bin/true";
    cfg.networkd_dir = (root_ / "network").string();
    cfg.sysctl_dir = (root_ / "sysctl.d").string();
    cfg.sysctl_proc_dir = (root_ / "proc-sys").string();
    return cfg;
  }

  auto BackendOptions() const -> f::confd::SystemBackendOptions {
    f::confd::SystemBackendOptions o;
    o.config_path = config().string();
    o.snapshot_dir = (root_ / "snapshots").string();
    o.networkd_dir = (root_ / "network").string();
    o.sysctl_dir = (root_ / "sysctl.d").string();
    o.sysctl_proc_dir = (root_ / "proc-sys").string();
    o.dnsmasq_conf = (root_ / "dnsmasq.conf").string();
    o.activate = f::confd::NullActivator();
    return o;
  }

 private:
  std::filesystem::path root_;
  static inline int counter_ = 0;
};

/// f-confd, in process: the same Runtime and ZmqServer the daemon
/// builds, so the CLI is talking to the real thing over a real socket.
class Confd {
 public:
  explicit Confd(const Box& box)
      : backend_(box.BackendOptions()),
        runtime_(backend_),
        server_(runtime_, MakeCfg(box)) {}

  auto endpoint() const -> const std::string& {
    return server_.ControlEndpoint();
  }
  auto runtime() -> cc::Runtime& {
    return runtime_;
  }

 private:
  static auto MakeCfg(const Box& box) -> cc::ZmqServerConfig {
    cc::ZmqServerConfig cfg;
    cfg.control_endpoint = box.endpoint();
    cfg.event_endpoint = box.events();
    return cfg;
  }

  f::confd::SystemBackend backend_;
  cc::Runtime runtime_;
  cc::ZmqServer server_;
};

auto Req(const std::string& command,
         std::vector<std::string> args = {}) -> proto::Request {
  proto::Request r;
  r.id = "t";
  r.user = "operator";
  r.role = "admin";
  r.command = command;
  r.args = std::move(args);
  return r;
}

auto Body(const proto::Response& r) -> json {
  if (r.data.empty()) return json::object();
  try {
    return json::parse(std::string(r.data.begin(), r.data.end()));
  } catch (const std::exception&) {
    return json::object();
  }
}

template <class F>
auto WaitUntil(F pred, std::chrono::milliseconds timeout) -> bool {
  const auto deadline =
      std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline) {
    if (pred()) return true;
    std::this_thread::sleep_for(20ms);
  }
  return pred();
}

auto MakeTransport(const Box& box)
    -> std::unique_ptr<cli::transport::Transport> {
  auto tx = fw::NewFLocalTransport(box.TransportConfig());
  EXPECT_TRUE(tx.has_value());
  (*tx)->Connect();
  return std::move(*tx);
}

// With no f-confd there is no revert timer, so the confirmed apply is
// refused rather than performed with nothing to undo it.
TEST(ApplySystemConfirmed, RefusedWhenConfdIsNotRunning) {
  Box box;
  auto tx = MakeTransport(box);
  WriteFileText(box.config(), ConfigWithAddress("192.168.5.1/24"));

  auto resp = tx->SendRequest(
      Req("apply_system_confirmed", {"1"}), 10s);
  ASSERT_TRUE(resp.has_value());
  EXPECT_EQ(resp->status, proto::ResponseStatus::Error);
  ASSERT_TRUE(resp->error.has_value());
  EXPECT_EQ(resp->error->code, "no_confd");
  // Nothing was applied behind the refusal.
  EXPECT_FALSE(Body(*resp).value("applied", false));
}

TEST(ApplySystemConfirmed, AppliesAndArmsTheRevert) {
  Box box;
  Confd confd(box);
  auto tx = MakeTransport(box);

  WriteFileText(box.config(), ConfigWithAddress("192.168.5.1/24"));
  auto resp = tx->SendRequest(
      Req("apply_system_confirmed", {"0.02"}), 10s);
  ASSERT_TRUE(resp.has_value());
  ASSERT_EQ(resp->status, proto::ResponseStatus::Ok)
      << (resp->error ? resp->error->message : "");
  auto body = Body(*resp);
  EXPECT_TRUE(body.value("applied", false));
  EXPECT_EQ(body.value("via", ""), "f-confd");
  EXPECT_TRUE(body.value("confirm_required", false));
  EXPECT_TRUE(confd.runtime().PendingConfirmState().armed);

  // Unconfirmed, the box comes back on its own.
  EXPECT_TRUE(WaitUntil(
      [&] {
        return ReadFileText(box.config()).find("10.10.0.1/24") !=
               std::string::npos;
      },
      5s));
}

TEST(ApplySystemConfirmed, ConfirmSystemCancelsTheRevert) {
  Box box;
  Confd confd(box);
  auto tx = MakeTransport(box);

  WriteFileText(box.config(), ConfigWithAddress("192.168.5.1/24"));
  ASSERT_EQ(tx->SendRequest(Req("apply_system_confirmed", {"0.05"}),
                            10s)
                ->status,
            proto::ResponseStatus::Ok);

  auto confirmed = tx->SendRequest(Req("confirm_system"), 5s);
  ASSERT_TRUE(confirmed.has_value());
  ASSERT_EQ(confirmed->status, proto::ResponseStatus::Ok)
      << (confirmed->error ? confirmed->error->message : "");
  EXPECT_FALSE(confd.runtime().PendingConfirmState().armed);

  std::this_thread::sleep_for(4s);
  EXPECT_NE(ReadFileText(box.config()).find("192.168.5.1/24"),
            std::string::npos)
      << "a confirmed apply was reverted anyway";
}

// Somebody reconnects mid-window: `show system` has to tell them the
// clock is running, without them knowing to ask.
TEST(ApplySystemConfirmed, ShowSystemReportsTheOpenWindow) {
  Box box;
  Confd confd(box);
  auto tx = MakeTransport(box);

  WriteFileText(box.config(), ConfigWithAddress("192.168.5.1/24"));
  ASSERT_EQ(tx->SendRequest(Req("apply_system_confirmed", {"5"}),
                            10s)
                ->status,
            proto::ResponseStatus::Ok);

  auto fresh = MakeTransport(box);
  auto shown = fresh->SendRequest(Req("show_system"), 5s);
  ASSERT_TRUE(shown.has_value());
  auto confirm = Body(*shown).value("confirm", json::object());
  EXPECT_TRUE(confirm.value("pending", false))
      << Body(*shown).dump();
  EXPECT_EQ(confirm.value("confd", ""), "running");

  ASSERT_EQ(tx->SendRequest(Req("confirm_system"), 5s)->status,
            proto::ResponseStatus::Ok);
}

// A plain apply through a running f-confd is recorded as a revision
// and says so; it must not claim a confirm window it did not open.
TEST(ApplySystemConfirmed, PlainApplyGoesThroughConfdWithoutWindow) {
  Box box;
  Confd confd(box);
  auto tx = MakeTransport(box);

  WriteFileText(box.config(), ConfigWithAddress("192.168.6.1/24"));
  auto resp = tx->SendRequest(Req("apply_system"), 10s);
  ASSERT_TRUE(resp.has_value());
  ASSERT_EQ(resp->status, proto::ResponseStatus::Ok)
      << (resp->error ? resp->error->message : "");
  auto body = Body(*resp);
  EXPECT_EQ(body.value("via", ""), "f-confd");
  EXPECT_FALSE(body.value("confirm_required", false));
  EXPECT_FALSE(confd.runtime().PendingConfirmState().armed);
  EXPECT_FALSE(body.value("commit_id", "").empty());
}

// Without f-confd the direct path still works — and says plainly that
// nothing was reloaded and nothing will undo it.
TEST(ApplySystemConfirmed, DirectApplySaysItIsNotActivated) {
  Box box;
  auto tx = MakeTransport(box);
  auto resp = tx->SendRequest(Req("apply_system"), 10s);
  ASSERT_TRUE(resp.has_value());
  ASSERT_EQ(resp->status, proto::ResponseStatus::Ok)
      << (resp->error ? resp->error->message : "");
  auto body = Body(*resp);
  EXPECT_EQ(body.value("via", ""), "direct");
  EXPECT_FALSE(body.value("activated", true));
  EXPECT_NE(body.value("note", "").find("revert timer"),
            std::string::npos)
      << body.dump();
}

}  // namespace
