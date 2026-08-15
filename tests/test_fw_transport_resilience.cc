/// @file test_fw_transport_resilience.cc
/// @brief The CLI transport when fd is not there.
///
/// Three defects this file exists to keep fixed, all of the same
/// family — the CLI knew something and did not say it:
///
///  1. A ZMQ REQ socket enforces send/recv alternation. The first
///     command against a stopped fd timed out, and *every* command
///     after it in the same session died with "Operation cannot be
///     accomplished in current state" — a message about ZMQ's
///     internals, not about the daemon.
///  2. Connecting to a missing `ipc://` path succeeds, so "fd is not
///     running" was reported three seconds later as "recv timeout",
///     which reads as a slow daemon rather than an absent one.
///  3. `Subscribe` returned success for any topic and then delivered
///     nothing, so a `watch` on a topic with no source looked exactly
///     like a quiet network.

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <chrono>
#include <filesystem>
#include <string>

#include "adapters/fw/transport.h"
#include "einheit/cli/protocol/envelope.h"

namespace {

namespace proto = einheit::cli::protocol;

auto MakeTransport()
    -> std::unique_ptr<einheit::cli::transport::Transport> {
  einheit::adapters::fw::FLocalConfig cfg;
  // A path nothing is listening on, and nothing ever created.
  cfg.fd_socket = "ipc:///tmp/f-test-no-such-daemon.sock";
  cfg.system_config = "/tmp/f-test-no-such-config.yaml";
  auto tx = einheit::adapters::fw::NewFLocalTransport(cfg);
  EXPECT_TRUE(tx.has_value());
  if (!tx) return nullptr;
  (void)(*tx)->Connect();
  return std::move(*tx);
}

auto Ask(einheit::cli::transport::Transport& tx,
         const std::string& command) -> proto::Response {
  proto::Request req;
  req.id = "t";
  req.command = command;
  auto r = tx.SendRequest(req, std::chrono::seconds(5));
  EXPECT_TRUE(r.has_value()) << "the transport threw or failed hard";
  return r.value_or(proto::Response{});
}

TEST(TransportResilience, EveryQueryAfterAFailureStillAnswers) {
  std::filesystem::remove("/tmp/f-test-no-such-daemon.sock");
  auto tx = MakeTransport();
  ASSERT_NE(tx, nullptr);
  // Three fd-backed queries in a row. The second and third used to
  // throw out of ZMQ because the socket was left mid-transaction.
  for (const char* cmd :
       {"show_zones", "show_nat", "show_conntrack"}) {
    auto resp = Ask(*tx, cmd);
    ASSERT_EQ(resp.status, proto::ResponseStatus::Error) << cmd;
    ASSERT_TRUE(resp.error.has_value()) << cmd;
    EXPECT_EQ(resp.error->code, "no_daemon") << cmd;
    EXPECT_NE(resp.error->message.find("fd is not running"),
              std::string::npos)
        << cmd << ": " << resp.error->message;
    EXPECT_EQ(resp.error->message.find("current state"),
              std::string::npos)
        << "ZMQ's internal state is not an operator-facing reason";
  }
}

TEST(TransportResilience, AnAbsentSocketIsAnsweredImmediately) {
  std::filesystem::remove("/tmp/f-test-no-such-daemon.sock");
  auto tx = MakeTransport();
  ASSERT_NE(tx, nullptr);
  const auto start = std::chrono::steady_clock::now();
  auto resp = Ask(*tx, "show_zones");
  const auto elapsed = std::chrono::steady_clock::now() - start;
  EXPECT_EQ(resp.status, proto::ResponseStatus::Error);
  // The old path waited out the three-second receive timeout before
  // admitting it. Absence is knowable without waiting.
  EXPECT_LT(elapsed, std::chrono::milliseconds(500))
      << "the socket file is missing; that is not a timeout";
}

TEST(TransportResilience, ATopicWithNoSourceIsRefusedNotAccepted) {
  auto tx = MakeTransport();
  ASSERT_NE(tx, nullptr);
  auto r = tx->Subscribe("state.tunnels", [](const proto::Event&) {});
  ASSERT_FALSE(r.has_value())
      << "subscribing to a topic nothing publishes must fail, or a "
         "watch on it looks like a network with nothing happening";
  EXPECT_NE(r.error().message.find("leases"), std::string::npos)
      << "say which topic does exist: " << r.error().message;
}

TEST(TransportResilience, TheLeaseTopicIsAcceptedAndStopsCleanly) {
  auto tx = MakeTransport();
  ASSERT_NE(tx, nullptr);
  auto sub = tx->Subscribe("leases", [](const proto::Event&) {});
  ASSERT_TRUE(sub.has_value()) << sub.error().message;
  auto again = tx->Subscribe("leases", [](const proto::Event&) {});
  EXPECT_FALSE(again.has_value())
      << "a second subscription would race the first on the journal";
  auto un = tx->Unsubscribe("leases");
  EXPECT_TRUE(un.has_value());
}

TEST(TransportResilience, UnsubscribingFromSomethingElseIsAnError) {
  auto tx = MakeTransport();
  ASSERT_NE(tx, nullptr);
  auto r = tx->Unsubscribe("state.tunnels");
  EXPECT_FALSE(r.has_value());
}

}  // namespace
