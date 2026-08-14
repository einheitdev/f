/// @file test_confd_system.cc
/// @brief `apply system` under commit-confirmed: the anti-lockout path.
///
/// Changing an interface address or a zone can sever the operator's
/// own access to the box. The protection against that is a revert
/// timer that runs somewhere the severed session cannot kill — which
/// is why the system configuration is applied through confd's Runtime
/// (daemon-side) rather than by the CLI process itself.
///
/// These tests hold the whole claim to account: the configuration
/// really is installed, the artifacts really are written, an
/// unconfirmed window really does put the previous configuration back
/// — including after the client that armed it has gone away — and a
/// confirm really does stand the timer down.

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "einheit/cli/confd/runtime.h"
#include "einheit/cli/confd/zmq_server.h"
#include "einheit/cli/protocol/envelope.h"
#include "einheit/cli/transport/zmq_local.h"
#include "f/confd/system_backend.h"
#include "f/sysconfig/artifact.h"

namespace {

using std::chrono_literals::operator""s;
using std::chrono_literals::operator""ms;
namespace cc = einheit::cli::confd;
namespace proto = einheit::cli::protocol;

// ~1.2s: long enough to be a real window, short enough for a test.
constexpr const char* kShortWindow = "0.02";

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

auto ReadFile(const std::filesystem::path& p) -> std::string {
  std::ifstream in(p);
  std::ostringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

auto WriteFile(const std::filesystem::path& p,
               const std::string& text) -> void {
  std::filesystem::create_directories(p.parent_path());
  std::ofstream out(p);
  out << text;
}

/// A scratch appliance: config file, snapshot store, networkd dir.
class Box {
 public:
  Box() {
    root_ = std::filesystem::temp_directory_path() /
            ("f_confd_sys_" + std::to_string(::getpid()) + "_" +
             std::to_string(++counter_));
    std::filesystem::remove_all(root_);
    std::filesystem::create_directories(root_);
    WriteFile(config(), ConfigWithAddress("10.10.0.1/24"));
  }

  ~Box() {
    std::error_code ec;
    std::filesystem::remove_all(root_, ec);
  }

  auto config() const -> std::filesystem::path {
    return root_ / "system.yaml";
  }
  auto networkd() const -> std::filesystem::path {
    return root_ / "network";
  }
  auto snapshots() const -> std::filesystem::path {
    return root_ / "snapshots";
  }
  auto state() const -> std::filesystem::path {
    return root_ / "state";
  }
  auto endpoint() const -> std::string {
    return "ipc://" + (root_ / "confd.sock").string();
  }
  auto events() const -> std::string {
    return "ipc://" + (root_ / "confd.pub").string();
  }
  auto lan0_network() const -> std::filesystem::path {
    return networkd() / "10-f-lan0.network";
  }

  auto Options() -> f::confd::SystemBackendOptions {
    f::confd::SystemBackendOptions o;
    o.config_path = config().string();
    o.snapshot_dir = snapshots().string();
    o.networkd_dir = networkd().string();
    o.sysctl_dir = (root_ / "sysctl.d").string();
    o.sysctl_proc_dir = (root_ / "proc-sys").string();
    o.dnsmasq_conf = (root_ / "dnsmasq.conf").string();
    return o;
  }

 private:
  std::filesystem::path root_;
  static inline int counter_ = 0;
};

/// Records what it was asked to activate; can be told to fail.
class RecordingActivator {
 public:
  auto Get() -> f::confd::Activator {
    return [this](const f::confd::Activation& act)
               -> std::expected<std::string, std::string> {
      calls_.fetch_add(1);
      {
        std::lock_guard<std::mutex> lock(mu_);
        last_units_ = act.networkd_changed;
        last_dnsmasq_ = act.dnsmasq_changed;
      }
      if (fail_.load()) {
        return std::unexpected("networkctl reload failed (test)");
      }
      return "reloaded (test activator)";
    };
  }

  auto Calls() const -> int {
    return calls_.load();
  }
  auto LastUnits() const -> std::vector<std::string> {
    std::lock_guard<std::mutex> lock(mu_);
    return last_units_;
  }
  auto FailNext(bool v) -> void {
    fail_.store(v);
  }

 private:
  std::atomic<int> calls_{0};
  std::atomic<bool> fail_{false};
  mutable std::mutex mu_;
  std::vector<std::string> last_units_;
  bool last_dnsmasq_ = false;
};

auto Req(const std::string& command,
         std::vector<std::string> args = {},
         std::optional<std::string> session = std::nullopt)
    -> proto::Request {
  proto::Request r;
  r.id = "t";
  r.user = "operator";
  r.role = "admin";
  r.command = command;
  r.args = std::move(args);
  r.session_id = std::move(session);
  return r;
}

auto DataString(const proto::Response& r) -> std::string {
  return std::string(r.data.begin(), r.data.end());
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

/// Stage `text` as the configuration to apply and commit it through
/// the runtime, with the given lifecycle command.
auto CommitConfig(cc::Runtime& rt, f::confd::SystemBackend& backend,
                  const std::string& text,
                  const std::string& command,
                  std::vector<std::string> args = {})
    -> proto::Response {
  auto digest = backend.Snapshot(text);
  EXPECT_TRUE(digest.has_value());
  const auto sid = DataString(rt.HandleRequest(Req("configure")));
  rt.HandleRequest(
      Req("set", {f::confd::kConfigKey, *digest}, sid));
  return rt.HandleRequest(Req(command, std::move(args), sid));
}

TEST(ConfdSystemBackend, BaselineIsTheConfigurationFoundOnTheBox) {
  Box box;
  RecordingActivator act;
  auto opts = box.Options();
  opts.activate = act.Get();
  f::confd::SystemBackend backend(opts);

  EXPECT_FALSE(backend.BaselineDigest().empty());
  EXPECT_EQ(backend.BaselineDigest(),
            f::sysconfig::BodyDigest(ReadFile(box.config())));
  // Running state names the configuration on disk.
  auto running = backend.ReadRunning();
  ASSERT_TRUE(running.count(f::confd::kConfigKey));
  EXPECT_EQ(running.at(f::confd::kConfigKey),
            backend.BaselineDigest());
}

TEST(ConfdSystemBackend, ApplyInstallsConfigAndDerivedUnits) {
  Box box;
  RecordingActivator act;
  auto opts = box.Options();
  opts.activate = act.Get();
  f::confd::SystemBackend backend(opts);
  cc::Runtime rt(backend);

  auto resp = CommitConfig(rt, backend,
                           ConfigWithAddress("10.20.0.1/24"),
                           "commit");
  ASSERT_EQ(resp.status, proto::ResponseStatus::Ok);

  EXPECT_NE(ReadFile(box.config()).find("10.20.0.1/24"),
            std::string::npos);
  ASSERT_TRUE(std::filesystem::exists(box.lan0_network()));
  EXPECT_NE(ReadFile(box.lan0_network()).find("10.20.0.1/24"),
            std::string::npos);
  EXPECT_EQ(act.Calls(), 1)
      << "artifacts written but nothing asked to adopt them";
  EXPECT_FALSE(act.LastUnits().empty());
}

// The point of the whole exercise: nobody confirms, and the box puts
// the previous configuration back by itself.
TEST(ConfdSystemBackend, UnconfirmedApplyRevertsTheWholeSystem) {
  Box box;
  RecordingActivator act;
  auto opts = box.Options();
  opts.activate = act.Get();
  f::confd::SystemBackend backend(opts);
  cc::Runtime rt(backend);

  // A first, confirmed commit establishes "the address that works".
  ASSERT_EQ(CommitConfig(rt, backend,
                         ConfigWithAddress("10.10.0.1/24"), "commit")
                .status,
            proto::ResponseStatus::Ok);
  ASSERT_NE(ReadFile(box.lan0_network()).find("10.10.0.1/24"),
            std::string::npos);

  // Now the change that could lock the operator out.
  auto resp = CommitConfig(rt, backend,
                           ConfigWithAddress("192.168.77.1/24"),
                           "commit_confirmed", {kShortWindow});
  ASSERT_EQ(resp.status, proto::ResponseStatus::Ok)
      << (resp.error ? resp.error->message : "");
  EXPECT_NE(ReadFile(box.config()).find("192.168.77.1/24"),
            std::string::npos);
  EXPECT_TRUE(rt.PendingConfirmState().armed);

  // Nobody confirms.
  const bool reverted = WaitUntil(
      [&] {
        return ReadFile(box.config()).find("10.10.0.1/24") !=
               std::string::npos;
      },
      5s);
  EXPECT_TRUE(reverted) << "the system config was not restored";
  // Not just the config file: the derived unit is back too, which is
  // what the operator's connectivity actually depends on.
  EXPECT_NE(ReadFile(box.lan0_network()).find("10.10.0.1/24"),
            std::string::npos);
  EXPECT_EQ(ReadFile(box.lan0_network()).find("192.168.77.1/24"),
            std::string::npos);
  EXPECT_FALSE(rt.PendingConfirmState().armed);
}

TEST(ConfdSystemBackend, ConfirmKeepsTheNewConfiguration) {
  Box box;
  RecordingActivator act;
  auto opts = box.Options();
  opts.activate = act.Get();
  f::confd::SystemBackend backend(opts);
  cc::Runtime rt(backend);

  ASSERT_EQ(CommitConfig(rt, backend,
                         ConfigWithAddress("10.10.0.1/24"), "commit")
                .status,
            proto::ResponseStatus::Ok);
  ASSERT_EQ(CommitConfig(rt, backend,
                         ConfigWithAddress("192.168.77.1/24"),
                         "commit_confirmed", {kShortWindow})
                .status,
            proto::ResponseStatus::Ok);

  auto confirmed = rt.HandleRequest(Req("confirm"));
  ASSERT_EQ(confirmed.status, proto::ResponseStatus::Ok);
  EXPECT_FALSE(rt.PendingConfirmState().armed);

  std::this_thread::sleep_for(2s);
  EXPECT_NE(ReadFile(box.config()).find("192.168.77.1/24"),
            std::string::npos)
      << "a confirmed commit must not be reverted";
}

// The first-ever confirmed apply has no previous commit to fall back
// to; it must fall back to what the box was running when confd
// started, not to an empty configuration.
TEST(ConfdSystemBackend, FirstCommitRevertsToTheBaseline) {
  Box box;
  RecordingActivator act;
  auto opts = box.Options();
  opts.activate = act.Get();
  f::confd::SystemBackend backend(opts);
  cc::Runtime rt(backend);

  ASSERT_EQ(CommitConfig(rt, backend,
                         ConfigWithAddress("192.168.77.1/24"),
                         "commit_confirmed", {kShortWindow})
                .status,
            proto::ResponseStatus::Ok);

  const bool reverted = WaitUntil(
      [&] {
        return ReadFile(box.config()).find("10.10.0.1/24") !=
               std::string::npos;
      },
      5s);
  EXPECT_TRUE(reverted)
      << "reverted to nothing instead of the baseline";
}

// An invalid configuration never reaches the box.
TEST(ConfdSystemBackend, InvalidConfigurationIsRefused) {
  Box box;
  RecordingActivator act;
  auto opts = box.Options();
  opts.activate = act.Get();
  f::confd::SystemBackend backend(opts);
  cc::Runtime rt(backend);

  // A service bound to a zone that does not exist (SC020).
  const std::string bad =
      "zones:\n"
      "  lan:\n"
      "interfaces:\n"
      "  lan0:\n"
      "    mac: \"52:54:00:aa:bb:02\"\n"
      "    address: 10.10.0.1/24\n"
      "    zone: lan\n"
      "services:\n"
      "  dhcp:\n"
      "    - zone: nosuchzone\n"
      "      range: 10.10.0.100-10.10.0.200\n";
  auto resp = CommitConfig(rt, backend, bad, "commit");
  EXPECT_EQ(resp.status, proto::ResponseStatus::Error);
  EXPECT_EQ(act.Calls(), 0);
  EXPECT_EQ(ReadFile(box.config()).find("nosuchzone"),
            std::string::npos);
}

// Written but not live is its own outcome, and it is not a success.
TEST(ConfdSystemBackend, ActivationFailureFailsTheCommit) {
  Box box;
  RecordingActivator act;
  act.FailNext(true);
  auto opts = box.Options();
  opts.activate = act.Get();
  f::confd::SystemBackend backend(opts);
  cc::Runtime rt(backend);

  auto resp = CommitConfig(rt, backend,
                           ConfigWithAddress("10.30.0.1/24"),
                           "commit");
  ASSERT_EQ(resp.status, proto::ResponseStatus::Error);
  ASSERT_TRUE(resp.error.has_value());
  EXPECT_NE(resp.error->message.find("NOT live"), std::string::npos)
      << resp.error->message;
}

// The whole reason the timer lives in a daemon: the client that armed
// it goes away — as an SSH session does when the change it just made
// severs it — and the revert still happens.
TEST(ConfdSystemBackend, RevertOutlivesTheClientThatArmedIt) {
  Box box;
  RecordingActivator act;
  auto opts = box.Options();
  opts.activate = act.Get();
  f::confd::SystemBackend backend(opts);
  cc::RuntimeOptions rt_opts;
  rt_opts.state_dir = box.state().string();
  cc::Runtime rt(backend, rt_opts);
  cc::ZmqServerConfig srv_cfg;
  srv_cfg.control_endpoint = box.endpoint();
  srv_cfg.event_endpoint = box.events();
  cc::ZmqServer server(rt, srv_cfg);

  auto digest =
      backend.Snapshot(ConfigWithAddress("192.168.99.1/24"));
  ASSERT_TRUE(digest.has_value());

  {
    einheit::cli::transport::ZmqLocalConfig tcfg;
    tcfg.control_endpoint = server.ControlEndpoint();
    tcfg.event_endpoint = server.EventEndpoint();
    auto tx =
        einheit::cli::transport::NewZmqLocalTransport(tcfg);
    ASSERT_TRUE(tx.has_value());
    ASSERT_TRUE((*tx)->Connect().has_value());

    auto configured =
        (*tx)->SendRequest(Req("configure"), 2s);
    ASSERT_TRUE(configured.has_value());
    const auto sid = DataString(*configured);
    auto set = (*tx)->SendRequest(
        Req("set", {f::confd::kConfigKey, *digest}, sid), 2s);
    ASSERT_TRUE(set.has_value());
    auto committed = (*tx)->SendRequest(
        Req("commit_confirmed", {kShortWindow}, sid), 5s);
    ASSERT_TRUE(committed.has_value());
    ASSERT_EQ(committed->status, proto::ResponseStatus::Ok)
        << (committed->error ? committed->error->message : "");
    EXPECT_NE(ReadFile(box.config()).find("192.168.99.1/24"),
              std::string::npos);
    (*tx)->Disconnect();
    // Client destroyed here — exactly what losing the session does.
  }

  const bool reverted = WaitUntil(
      [&] {
        return ReadFile(box.config()).find("10.10.0.1/24") !=
               std::string::npos;
      },
      5s);
  EXPECT_TRUE(reverted)
      << "the revert died with the session it was protecting";
}

}  // namespace
