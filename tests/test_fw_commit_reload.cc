/// @file test_fw_commit_reload.cc
/// @brief The commit path must never report a reload the daemon did
/// not perform.
///
/// `commit` writes the operator's policy and then asks fd to swap it
/// in. Those are two separate outcomes, and the CLI used to collapse
/// them: it treated *any* reply from fd as proof the reload happened,
/// so a daemon that answered `{"error":"unknown command"}` still
/// produced `{"status":"committed","reload":"triggered"}`. The single
/// action an operator takes to fix a broken box lied about having
/// worked.
///
/// These tests drive the real transport against a fake fd on a real
/// ZMQ socket, so a stub that hard-codes a happy answer cannot pass:
/// the fake decides what fd says, and the assertions are about what
/// the operator is told in each case.

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include <nlohmann/json.hpp>
#include <zmq.hpp>

#include "adapters/fw/transport.h"
#include "einheit/cli/protocol/envelope.h"

namespace {

using json = nlohmann::json;
namespace cli = einheit::cli;
namespace proto = cli::protocol;
namespace fw = einheit::adapters::fw;

constexpr std::uint8_t kReloadProg = 4;

/// A stand-in for fd's control socket: a real ZMQ REP endpoint that
/// answers with whatever the test decided this daemon knows how to do.
/// It records every command byte it received, so a test can assert the
/// CLI actually asked rather than assuming.
class FakeFd {
 public:
  explicit FakeFd(std::string endpoint)
      : endpoint_(std::move(endpoint)) {}

  ~FakeFd() {
    Stop();
  }

  /// Reply verbatim with `reply` when command byte `cmd` arrives.
  auto Answer(std::uint8_t cmd, std::string reply) -> void {
    replies_[cmd] = std::move(reply);
  }

  auto Start() -> void {
    thread_ = std::thread([this] { Serve(); });
    // Wait for the bind so a client cannot connect to nothing.
    while (!bound_.load() && !failed_.load()) {
      std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
  }

  auto Stop() -> void {
    stop_.store(true);
    if (thread_.joinable()) thread_.join();
  }

  auto Received() const -> std::vector<std::uint8_t> {
    std::lock_guard<std::mutex> lock(mu_);
    return received_;
  }

  auto SawCommand(std::uint8_t cmd) const -> bool {
    for (auto c : Received()) {
      if (c == cmd) return true;
    }
    return false;
  }

 private:
  auto Serve() -> void {
    try {
      zmq::context_t ctx(1);
      zmq::socket_t sock(ctx, zmq::socket_type::rep);
      sock.set(zmq::sockopt::linger, 0);
      sock.set(zmq::sockopt::rcvtimeo, 50);
      sock.bind(endpoint_);
      bound_.store(true);
      while (!stop_.load()) {
        zmq::message_t req;
        auto got = sock.recv(req, zmq::recv_flags::none);
        if (!got) continue;
        std::string body(static_cast<char*>(req.data()), req.size());
        std::uint8_t cmd =
            body.empty() ? 0 : static_cast<std::uint8_t>(body[0]);
        {
          std::lock_guard<std::mutex> lock(mu_);
          received_.push_back(cmd);
        }
        std::string reply = R"({"error":"unknown command"})";
        auto it = replies_.find(cmd);
        if (it != replies_.end()) reply = it->second;
        zmq::message_t out(reply.size());
        std::memcpy(out.data(), reply.data(), reply.size());
        (void)sock.send(out, zmq::send_flags::none);
      }
    } catch (const zmq::error_t&) {
      failed_.store(true);
    }
  }

  std::string endpoint_;
  std::unordered_map<std::uint8_t, std::string> replies_;
  std::thread thread_;
  std::atomic<bool> stop_{false};
  std::atomic<bool> bound_{false};
  std::atomic<bool> failed_{false};
  mutable std::mutex mu_;
  std::vector<std::uint8_t> received_;
};

/// A scratch directory holding one .fw source file.
class SourceTree {
 public:
  SourceTree() {
    dir_ = std::filesystem::temp_directory_path() /
           ("f_commit_reload_" + std::to_string(::getpid()) + "_" +
            std::to_string(++counter_));
    std::filesystem::create_directories(dir_);
    std::ofstream out(dir_ / "rules.fw");
    out << "zone lan = [eth0]\n";
  }

  ~SourceTree() {
    std::error_code ec;
    std::filesystem::remove_all(dir_, ec);
  }

  auto path() const -> std::string {
    return dir_.string();
  }

  auto socket() const -> std::string {
    return "ipc://" + (dir_ / "fd.sock").string();
  }

 private:
  std::filesystem::path dir_;
  static inline int counter_ = 0;
};

auto MakeRequest(const std::string& command) -> proto::Request {
  proto::Request r;
  r.id = "t";
  r.user = "operator";
  r.role = "admin";
  r.command = command;
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

auto Message(const proto::Response& r) -> std::string {
  return r.error ? r.error->message : std::string();
}

/// Text the operator would end up seeing for this response, whether it
/// came back as data or as an error. Assertions about honesty are
/// about this string, not about which field carried it.
auto OperatorText(const proto::Response& r) -> std::string {
  return Body(r).dump() + " " + Message(r) +
         (r.error ? " " + r.error->hint : std::string());
}

class CommitReloadTest : public ::testing::Test {
 protected:
  auto MakeTransport(const SourceTree& tree)
      -> std::unique_ptr<cli::transport::Transport> {
    fw::FLocalConfig cfg;
    cfg.fw_source = tree.path();
    cfg.fd_socket = tree.socket();
    // `fwl check` is exercised by its own tests; here every source is
    // valid so the reload half is what the assertions are about.
    cfg.fwl_path = "/bin/true";
    cfg.pin_path = tree.path() + "/pin";
    auto tx = fw::NewFLocalTransport(cfg);
    EXPECT_TRUE(tx.has_value());
    (*tx)->Connect();
    return std::move(*tx);
  }

  auto ConfigureThenCommit(cli::transport::Transport& tx)
      -> proto::Response {
    auto configured = tx.SendRequest(MakeRequest("configure"),
                                     std::chrono::seconds(5));
    EXPECT_TRUE(configured.has_value());
    auto committed = tx.SendRequest(MakeRequest("commit"),
                                    std::chrono::seconds(10));
    EXPECT_TRUE(committed.has_value());
    return *committed;
  }
};

// The bug, stated as a test: a daemon that does not implement the
// reload command answers with an error envelope, and the operator must
// not be told the policy is live.
TEST_F(CommitReloadTest, DaemonWithoutReloadIsNotReportedAsSuccess) {
  SourceTree tree;
  FakeFd fd(tree.socket());
  // No Answer() for kReloadProg — this daemon does not know the
  // command, exactly like a pre-v0.4 fd.
  fd.Start();

  auto tx = MakeTransport(tree);
  auto resp = ConfigureThenCommit(*tx);

  EXPECT_TRUE(fd.SawCommand(kReloadProg))
      << "commit must actually ask fd to reload";
  EXPECT_EQ(resp.status, proto::ResponseStatus::Error)
      << "a reload that did not happen is not a success";

  const auto text = OperatorText(resp);
  EXPECT_EQ(text.find("triggered"), std::string::npos)
      << "nothing was triggered: " << text;
  EXPECT_NE(text.find("unknown command"), std::string::npos)
      << "the daemon's own reason must reach the operator: " << text;
  EXPECT_FALSE(Body(resp).value("applied", false));
}

// The daemon performed the reload: report what it actually did, with
// the version and rule count it reported back.
TEST_F(CommitReloadTest, DaemonThatReloadsIsReportedAsApplied) {
  SourceTree tree;
  FakeFd fd(tree.socket());
  fd.Answer(kReloadProg,
            R"({"status":"reloaded","version":"20260807T101500Z",)"
            R"("rules_installed":7,"program_updated":true})");
  fd.Start();

  auto tx = MakeTransport(tree);
  auto resp = ConfigureThenCommit(*tx);

  ASSERT_EQ(resp.status, proto::ResponseStatus::Ok) << Message(resp);
  auto body = Body(resp);
  EXPECT_TRUE(body.value("applied", false));
  EXPECT_EQ(body.value("version", ""), "20260807T101500Z");
  EXPECT_EQ(body.value("rules_installed", 0), 7);
  // The operator is told which mechanism made it live.
  EXPECT_NE(body.dump().find("fd"), std::string::npos);
}

// The daemon accepted the command but the compile failed: the files
// are committed, the running policy is the old one, and saying so is
// the whole point.
TEST_F(CommitReloadTest, ReloadErrorFromDaemonSurfacesVerbatim) {
  SourceTree tree;
  FakeFd fd(tree.socket());
  fd.Answer(kReloadProg,
            R"({"error":"compile failed: undefined zone 'wan'"})");
  fd.Start();

  auto tx = MakeTransport(tree);
  auto resp = ConfigureThenCommit(*tx);

  EXPECT_EQ(resp.status, proto::ResponseStatus::Error);
  const auto text = OperatorText(resp);
  EXPECT_NE(text.find("undefined zone 'wan'"), std::string::npos)
      << text;
  EXPECT_EQ(text.find("triggered"), std::string::npos) << text;
}

// fd is not answering at all. There is no watcher in fd (nothing calls
// WatcherStart), and a cold start loads the last *compiled* bundle,
// not the source — so neither "watcher will apply" nor "applied on
// next start" is true, and neither may be said.
TEST_F(CommitReloadTest, UnreachableDaemonIsNotReportedAsApplied) {
  SourceTree tree;
  // No FakeFd: nothing is bound to the endpoint.
  auto tx = MakeTransport(tree);
  auto resp = ConfigureThenCommit(*tx);

  EXPECT_NE(resp.status, proto::ResponseStatus::Ok)
      << "an unapplied commit is not an unqualified success";
  const auto text = OperatorText(resp);
  EXPECT_EQ(text.find("watcher"), std::string::npos)
      << "fd runs no watcher: " << text;
  EXPECT_EQ(text.find("triggered"), std::string::npos) << text;
  EXPECT_FALSE(Body(resp).value("applied", false));
}

// A failed commit leaves the candidate session open so `rollback` can
// still restore the previous policy.
TEST_F(CommitReloadTest, FailedCommitLeavesSessionOpenForRollback) {
  SourceTree tree;
  FakeFd fd(tree.socket());
  fd.Answer(kReloadProg, R"({"error":"apply failed"})");
  fd.Start();

  auto tx = MakeTransport(tree);
  auto resp = ConfigureThenCommit(*tx);
  ASSERT_EQ(resp.status, proto::ResponseStatus::Error);

  auto rolled = tx->SendRequest(MakeRequest("rollback"),
                                std::chrono::seconds(5));
  ASSERT_TRUE(rolled.has_value());
  EXPECT_EQ(rolled->status, proto::ResponseStatus::Ok)
      << "rollback after a failed commit must still work: "
      << Message(*rolled);
}

// `reload firewall` is the other door onto the same daemon command; it
// must report the daemon's error too.
TEST_F(CommitReloadTest, ReloadCommandSurfacesDaemonError) {
  SourceTree tree;
  FakeFd fd(tree.socket());
  fd.Answer(kReloadProg, R"({"error":"watcher not configured"})");
  fd.Start();

  auto tx = MakeTransport(tree);
  auto resp = tx->SendRequest(MakeRequest("reload_firewall"),
                              std::chrono::seconds(5));
  ASSERT_TRUE(resp.has_value());
  EXPECT_EQ(resp->status, proto::ResponseStatus::Error);
  EXPECT_NE(Message(*resp).find("watcher not configured"),
            std::string::npos);
}

// --- Counts that must come from the work, not from the intent -------
//
// The same shape as the loader defect this file's own first test is
// about: a number reported from what was enumerated rather than from
// what was done reads healthy in exactly the case it exists to catch.

// Nothing to validate is not a validated commit. `ListFwFiles` returns
// {} for a source that holds no .fw file, and the validation loop then
// ran zero times — so a commit whose sources had gone missing got the
// same silent pass as a clean check, and nothing but fd's own compile
// stood between the operator and whatever was on disk.
TEST_F(CommitReloadTest, CommitWithNoSourcesIsRefusedNotSilentlyOk) {
  SourceTree tree;
  std::filesystem::remove(
      std::filesystem::path(tree.path()) / "rules.fw");
  FakeFd fd(tree.socket());
  fd.Answer(kReloadProg,
            R"({"status":"reloaded","version":"0.4"})");
  fd.Start();

  auto tx = MakeTransport(tree);
  auto resp = ConfigureThenCommit(*tx);

  EXPECT_EQ(resp.status, proto::ResponseStatus::Error)
      << "an empty source set validated nothing and said ok";
  EXPECT_NE(OperatorText(resp).find("nothing to validate"),
            std::string::npos)
      << OperatorText(resp);
  EXPECT_FALSE(fd.SawCommand(kReloadProg))
      << "a commit that validated nothing must not reach the daemon";
}

// `rollback` reported `files_restored` by counting snapshots, throwing
// away the bool `WriteFile` returns. A rollback that could not write —
// full disk, read-only mount, i.e. the circumstances under which
// somebody is rolling back — answered "ok (N files restored)" and left
// the bad policy in place.
TEST_F(CommitReloadTest, RollbackThatCannotWriteIsNotReportedAsOk) {
  if (::geteuid() == 0) {
    GTEST_SKIP() << "root ignores the file mode this test relies on";
  }
  SourceTree tree;
  FakeFd fd(tree.socket());
  fd.Answer(kReloadProg, R"({"error":"apply failed"})");
  fd.Start();

  auto tx = MakeTransport(tree);
  auto configured = tx->SendRequest(MakeRequest("configure"),
                                    std::chrono::seconds(5));
  ASSERT_TRUE(configured.has_value());
  // The snapshot is taken at `configure`; make the file itself
  // unwritable afterwards so the restore is the step that fails.
  auto file = std::filesystem::path(tree.path()) / "rules.fw";
  std::error_code ec;
  std::filesystem::permissions(file, std::filesystem::perms::owner_read,
                               std::filesystem::perm_options::replace,
                               ec);
  ASSERT_FALSE(ec) << ec.message();

  auto rolled = tx->SendRequest(MakeRequest("rollback"),
                                std::chrono::seconds(5));
  std::filesystem::permissions(file, std::filesystem::perms::owner_all,
                               std::filesystem::perm_options::replace,
                               ec);
  ASSERT_TRUE(rolled.has_value());
  EXPECT_EQ(rolled->status, proto::ResponseStatus::Error)
      << "restored nothing and reported success";
  EXPECT_NE(OperatorText(*rolled).find("FAILED to restore"),
            std::string::npos)
      << OperatorText(*rolled);
}

}  // namespace
