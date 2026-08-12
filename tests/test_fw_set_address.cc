/// @file test_fw_set_address.cc
/// @brief `set address` writes the system configuration, not a rival
/// copy of the file the model generates.
///
/// The CLI used to write `10-f-<iface>.network` by hand. The model
/// generates that same file, so the two disagreed by construction:
/// the model reported the CLI's own write as a hand edit and refused
/// to apply, which is the correct behaviour for the wrong reason —
/// there should never have been a second writer.
///
/// The assertions here are about provenance: after `set address`, the
/// system configuration is what changed, the unit came from the model,
/// and `apply system` sees no drift.

#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>

#include <nlohmann/json.hpp>

#include "adapters/fw/transport.h"
#include "einheit/cli/confd/runtime.h"
#include "einheit/cli/confd/zmq_server.h"
#include "einheit/cli/protocol/envelope.h"
#include "f/confd/system_backend.h"
#include "f/sysconfig/networkd.h"
#include "f/sysconfig/parse.h"

namespace {

using std::chrono_literals::operator""s;
using json = nlohmann::json;
namespace cli = einheit::cli;
namespace cc = cli::confd;
namespace proto = cli::protocol;
namespace fw = einheit::adapters::fw;
namespace sc = f::sysconfig;

// `lo` is the one interface every host has, and the confd route never
// shells out to `ip`, so nothing here touches the host's networking.
constexpr const char* kIface = "lo";

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
            ("f_set_addr_" + std::to_string(::getpid()) + "_" +
             std::to_string(++counter_));
    std::filesystem::remove_all(root_);
    std::filesystem::create_directories(root_);
    std::ostringstream doc;
    doc << "zones:\n"
        << "  bench:\n"
        << "interfaces:\n"
        << "  # the operator wrote this and expects to see it again\n"
        << "  " << kIface << ":\n"
        << "    mac: \"52:54:00:aa:bb:07\"\n"
        << "    zone: bench\n";
    WriteFileText(config(), doc.str());
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
  auto unit() const -> std::filesystem::path {
    return networkd() / (std::string("10-f-") + kIface + ".network");
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
    cfg.networkd_dir = networkd().string();
    cfg.dnsmasq_conf = (root_ / "dnsmasq.conf").string();
    cfg.confd_socket = endpoint();
    cfg.fd_socket = "ipc://" + (root_ / "fd.sock").string();
    cfg.fw_source = (root_ / "rules").string();
    cfg.fwl_path = "/bin/true";
    return cfg;
  }

  auto BackendOptions() const -> f::confd::SystemBackendOptions {
    f::confd::SystemBackendOptions o;
    o.config_path = config().string();
    o.snapshot_dir = (root_ / "snapshots").string();
    o.networkd_dir = networkd().string();
    o.dnsmasq_conf = (root_ / "dnsmasq.conf").string();
    o.activate = f::confd::NullActivator();
    return o;
  }

 private:
  std::filesystem::path root_;
  static inline int counter_ = 0;
};

class Confd {
 public:
  explicit Confd(const Box& box)
      : backend_(box.BackendOptions()),
        runtime_(backend_),
        server_(runtime_, MakeCfg(box)) {}

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

auto MakeTransport(const Box& box)
    -> std::unique_ptr<cli::transport::Transport> {
  auto tx = fw::NewFLocalTransport(box.TransportConfig());
  EXPECT_TRUE(tx.has_value());
  (*tx)->Connect();
  return std::move(*tx);
}

TEST(SetAddress, ChangesTheSystemConfiguration) {
  Box box;
  Confd confd(box);
  auto tx = MakeTransport(box);

  auto resp = tx->SendRequest(
      Req("iface_set_address", {kIface, "10.99.0.1/24"}), 10s);
  ASSERT_TRUE(resp.has_value());
  ASSERT_EQ(resp->status, proto::ResponseStatus::Ok)
      << (resp->error ? resp->error->message : "");

  auto doc = ReadFileText(box.config());
  EXPECT_NE(doc.find("10.99.0.1/24"), std::string::npos) << doc;
  EXPECT_NE(doc.find("the operator wrote this"), std::string::npos)
      << "the edit ate the operator's comments";
  EXPECT_NE(doc.find("zone: bench"), std::string::npos);
  // The reply names the file that actually changed.
  EXPECT_EQ(Body(*resp).value("config", ""), box.config().string());
}

TEST(SetAddress, TheUnitIsTheModelsAndDoesNotDrift) {
  Box box;
  Confd confd(box);
  auto tx = MakeTransport(box);

  ASSERT_EQ(tx->SendRequest(
                   Req("iface_set_address", {kIface, "10.99.0.1/24"}),
                   10s)
                ->status,
            proto::ResponseStatus::Ok);

  auto unit = ReadFileText(box.unit());
  EXPECT_NE(unit.find("10.99.0.1/24"), std::string::npos) << unit;
  EXPECT_NE(unit.find("GENERATED FROM THE f SYSTEM CONFIGURATION"),
            std::string::npos)
      << "the unit was written by something other than the model";

  // The model must recognise its own work: no drift, so a later
  // `apply system` is not refused.
  auto parsed = sc::ParseSystemConfigString(ReadFileText(box.config()));
  ASSERT_TRUE(parsed.has_value());
  sc::NetworkdOptions opts;
  opts.dir = box.networkd().string();
  auto drift = sc::CheckNetworkdDrift(sc::PlanNetworkd(*parsed, opts));
  for (auto d : drift) {
    EXPECT_EQ(d, sc::DriftKind::kNone);
  }

  auto applied = tx->SendRequest(Req("apply_system"), 10s);
  ASSERT_TRUE(applied.has_value());
  EXPECT_EQ(applied->status, proto::ResponseStatus::Ok)
      << (applied->error ? applied->error->message : "");
}

TEST(SetAddress, AppliedThroughConfdSoItIsRecorded) {
  Box box;
  Confd confd(box);
  auto tx = MakeTransport(box);

  auto resp = tx->SendRequest(
      Req("iface_set_address", {kIface, "10.99.0.5/24"}), 10s);
  ASSERT_TRUE(resp.has_value());
  auto body = Body(*resp);
  EXPECT_EQ(body.value("via", ""), "f-confd");
  EXPECT_FALSE(body.value("commit_id", "").empty()) << body.dump();
}

TEST(SetAddress, RemovingItLeavesTheInterfaceDeclared) {
  Box box;
  Confd confd(box);
  auto tx = MakeTransport(box);

  ASSERT_EQ(tx->SendRequest(
                   Req("iface_set_address", {kIface, "10.99.0.1/24"}),
                   10s)
                ->status,
            proto::ResponseStatus::Ok);
  auto resp = tx->SendRequest(Req("iface_del_address", {kIface}), 10s);
  ASSERT_TRUE(resp.has_value());
  ASSERT_EQ(resp->status, proto::ResponseStatus::Ok)
      << (resp->error ? resp->error->message : "");

  auto doc = ReadFileText(box.config());
  EXPECT_EQ(doc.find("10.99.0.1/24"), std::string::npos) << doc;
  EXPECT_NE(doc.find(kIface), std::string::npos)
      << "the interface itself must stay declared";
}

TEST(SetAddress, UnknownInterfaceIsRefused) {
  Box box;
  Confd confd(box);
  auto tx = MakeTransport(box);
  auto resp = tx->SendRequest(
      Req("iface_set_address", {"nope99nope", "1.2.3.4/24"}), 10s);
  ASSERT_TRUE(resp.has_value());
  EXPECT_EQ(resp->status, proto::ResponseStatus::Error);
  EXPECT_EQ(ReadFileText(box.config()).find("1.2.3.4/24"),
            std::string::npos);
}

// An address the model rejects never reaches the box.
TEST(SetAddress, MalformedAddressIsRefused) {
  Box box;
  Confd confd(box);
  auto tx = MakeTransport(box);
  auto resp = tx->SendRequest(
      Req("iface_set_address", {kIface, "10.99.0.1/99"}), 10s);
  ASSERT_TRUE(resp.has_value());
  auto body = Body(*resp);
  const bool refused =
      resp->status == proto::ResponseStatus::Error ||
      !body.value("applied", false);
  EXPECT_TRUE(refused) << body.dump();
  EXPECT_EQ(ReadFileText(box.unit()).find("10.99.0.1/99"),
            std::string::npos);
}

}  // namespace
