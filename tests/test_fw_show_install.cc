/// @file test_fw_show_install.cc
/// @brief `show install` — what this box has of the deployable set.
///
/// The command exists because nothing enumerated that set: a box could
/// be missing `einheit-f`, `f-confd` and `f-sysconf` and say nothing
/// about it until a service failed to start days later. Two properties
/// are load-bearing and are what these tests pin:
///
///   * the answer comes from the installer, not from a second list
///     kept in the CLI — so the transport runs it and reports what it
///     said, including when running it fails;
///   * a missing item is *named*, with the unit it breaks and the
///     sentence saying what that costs. A row of ids and paths would
///     be a screen the operator has to look things up from.
///
/// The renderer tests feed one payload describing a complete box and
/// one describing a box missing f-confd, and assert the two differ in
/// the way an operator needs. A renderer printing a fixed string
/// passes neither.

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "adapters/fw/adapter.h"
#include "adapters/fw/transport.h"
#include "einheit/cli/command_tree.h"
#include "einheit/cli/protocol/envelope.h"
#include "einheit/cli/render/table.h"
#include "einheit/cli/render/terminal_caps.h"

namespace {

using json = nlohmann::json;
using std::chrono_literals::operator""s;
namespace cli = einheit::cli;
namespace fw = einheit::adapters::fw;
namespace proto = cli::protocol;
namespace render = cli::render;

/// A temporary box with a stand-in installer on it.
class Box {
 public:
  Box() {
    root_ = std::filesystem::temp_directory_path() /
            ("f_show_install_" + std::to_string(::getpid()) + "_" +
             std::to_string(++counter_));
    std::filesystem::remove_all(root_);
    std::filesystem::create_directories(root_);
  }

  ~Box() {
    std::error_code ec;
    std::filesystem::remove_all(root_, ec);
  }

  auto installer() const -> std::filesystem::path {
    return root_ / "f-install";
  }

  /// Write a fake installer that prints `body` and exits `code`.
  void InstallVerifier(const std::string& body, int code) {
    std::ofstream f(installer());
    f << "#!/bin/sh\ncat <<'EOF'\n" << body << "\nEOF\nexit "
      << code << "\n";
    f.close();
    std::filesystem::permissions(
        installer(), std::filesystem::perms::owner_all |
                         std::filesystem::perms::group_exec |
                         std::filesystem::perms::others_exec);
  }

  auto TransportConfig() const -> fw::FLocalConfig {
    fw::FLocalConfig cfg;
    cfg.install_tool = installer().string();
    cfg.system_config = (root_ / "system.yaml").string();
    cfg.fd_socket = "ipc://" + (root_ / "fd.sock").string();
    cfg.confd_socket = "ipc://" + (root_ / "confd.sock").string();
    cfg.fw_source = (root_ / "rules").string();
    cfg.fwl_path = "/bin/true";
    return cfg;
  }

 private:
  std::filesystem::path root_;
  static inline int counter_ = 0;
};

auto Req(const std::string& cmd) -> proto::Request {
  proto::Request r;
  r.id = "t";
  r.command = cmd;
  return r;
}

auto Body(const proto::Response& r) -> json {
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

auto CompleteReport() -> json {
  return json{
      {"scope", "target"},
      {"root", "/"},
      {"verdict", "complete"},
      {"items", json::array({
                    json{{"id", "fd"},
                         {"group", "binaries"},
                         {"kind", "binary"},
                         {"dest", "/usr/local/bin/fd"},
                         {"requirement", "required"},
                         {"state", "present"},
                         {"detail", ""},
                         {"needed_by", "fd.service"},
                         {"provided_by", ""},
                         {"required_when", ""},
                         {"why", "The datapath."}},
                })},
  };
}

auto MissingConfdReport() -> json {
  auto j = CompleteReport();
  j["verdict"] = "incomplete";
  j["items"].push_back(json{
      {"id", "f-confd"},
      {"group", "binaries"},
      {"kind", "binary"},
      {"dest", "/usr/local/bin/f-confd"},
      {"requirement", "required"},
      {"state", "missing"},
      {"detail", ""},
      {"needed_by", "f-confd.service"},
      {"provided_by", ""},
      {"required_when", ""},
      {"why", "Owns the commit-confirmed revert timer, which is the "
              "only thing standing between a wrong address and a box "
              "you cannot reach."}});
  return j;
}

// -- the transport ----------------------------------------------------

TEST(ShowInstall, ReportsWhatTheInstallerSaid) {
  Box box;
  box.InstallVerifier(MissingConfdReport().dump(), 1);
  auto tx = MakeTransport(box);

  auto resp = tx->SendRequest(Req("show_install"), 10s);
  ASSERT_TRUE(resp.has_value());
  ASSERT_EQ(resp->status, proto::ResponseStatus::Ok)
      << (resp->error ? resp->error->message : "");
  auto body = Body(*resp);
  EXPECT_EQ(body.value("verdict", ""), "incomplete");
  // The exit code travels with the report, so nothing downstream has
  // to re-derive a verdict from the rows.
  EXPECT_EQ(body.value("exit_code", 0), 1);
  bool found = false;
  for (const auto& item : body["items"]) {
    if (item.value("id", "") == "f-confd") found = true;
  }
  EXPECT_TRUE(found) << body.dump();
}

TEST(ShowInstall, AnInstallerThatIsNotThereIsItselfAFinding) {
  Box box;
  // Deliberately do not write one.
  auto tx = MakeTransport(box);

  auto resp = tx->SendRequest(Req("show_install"), 10s);
  ASSERT_TRUE(resp.has_value());
  EXPECT_EQ(resp->status, proto::ResponseStatus::Error);
  ASSERT_TRUE(resp->error.has_value());
  EXPECT_EQ(resp->error->code, "no_installer");
  // A box that cannot say what it is missing must not read as a box
  // that is missing nothing.
  EXPECT_NE(resp->error->message.find("cannot say"),
            std::string::npos)
      << resp->error->message;
}

TEST(ShowInstall, GarbageFromTheInstallerIsNotAnEmptyReport) {
  Box box;
  box.InstallVerifier("Traceback (most recent call last):", 3);
  auto tx = MakeTransport(box);

  auto resp = tx->SendRequest(Req("show_install"), 10s);
  ASSERT_TRUE(resp.has_value());
  EXPECT_EQ(resp->status, proto::ResponseStatus::Error);
  ASSERT_TRUE(resp->error.has_value());
  EXPECT_EQ(resp->error->code, "installer_failed");
  EXPECT_NE(resp->error->message.find("Traceback"),
            std::string::npos)
      << resp->error->message;
}

// -- the renderer -----------------------------------------------------

class RenderTest : public ::testing::Test {
 protected:
  void SetUp() override {
    adapter_ = einheit::adapters::fw::NewFwAdapter();
  }

  auto Spec(const std::string& path) -> const cli::CommandSpec* {
    for (const auto& c : adapter_->Commands()) {
      if (c.path == path) return &c;
    }
    return nullptr;
  }

  auto Render(const json& data) -> std::string {
    const auto* spec = Spec("show install");
    EXPECT_NE(spec, nullptr);
    if (spec == nullptr) return {};
    auto s = data.dump();
    proto::Response resp{
        .id = "t",
        .status = proto::ResponseStatus::Ok,
        .data = {s.begin(), s.end()},
    };
    std::ostringstream out;
    render::TerminalCaps caps{};
    caps.colors = render::ColorDepth::None;
    caps.width = 160;
    caps.height = 60;
    caps.unicode = false;
    render::Renderer r(out, caps);
    adapter_->RenderResponse(*spec, resp, r);
    return out.str();
  }

  static auto Has(const std::string& hay, const std::string& needle)
      -> bool {
    return hay.find(needle) != std::string::npos;
  }

  std::unique_ptr<cli::ProductAdapter> adapter_;
};

TEST_F(RenderTest, TheCommandExists) {
  EXPECT_NE(Spec("show install"), nullptr);
}

TEST_F(RenderTest, ACompleteBoxSaysSoRatherThanPrintingNothing) {
  auto text = Render(CompleteReport());
  EXPECT_TRUE(Has(text, "every item"))
      << "an empty screen means 'complete' and 'could not look' at "
         "once: " << text;
  EXPECT_TRUE(Has(text, "verdict: complete")) << text;
}

TEST_F(RenderTest, AMissingItemIsNamedWithWhatItBreaks) {
  auto text = Render(MissingConfdReport());
  EXPECT_TRUE(Has(text, "f-confd")) << text;
  EXPECT_TRUE(Has(text, "/usr/local/bin/f-confd")) << text;
  EXPECT_TRUE(Has(text, "f-confd.service")) << text;
  // And the cost, in the manifest's own words, on the screen.
  EXPECT_TRUE(Has(text, "commit-confirmed revert timer")) << text;
  EXPECT_TRUE(Has(text, "verdict: incomplete")) << text;
}

TEST_F(RenderTest, TheTwoBoxesDoNotRenderTheSame) {
  EXPECT_NE(Render(CompleteReport()), Render(MissingConfdReport()));
}

TEST_F(RenderTest, PresentItemsAreNotListed) {
  // The operator wants the gap, not an inventory.
  auto text = Render(MissingConfdReport());
  EXPECT_FALSE(Has(text, "/usr/local/bin/fd\n")) << text;
}

TEST_F(RenderTest, NotCheckedIsNotTheSameAsMissing) {
  auto j = CompleteReport();
  j["verdict"] = "indeterminate";
  j["items"].push_back(json{
      {"id", "ext-clang"},
      {"group", "external"},
      {"kind", "external"},
      {"dest", "/usr/bin/clang"},
      {"requirement", "required"},
      {"state", "unreadable"},
      {"detail", "Permission denied"},
      {"needed_by", "fwl compile"},
      {"provided_by", "clang"},
      {"required_when", ""},
      {"why", "fwl needs it to produce the .bpf.o fd loads."}});
  auto text = Render(j);
  EXPECT_TRUE(Has(text, "unreadable")) << text;
  EXPECT_TRUE(Has(text, "verdict: indeterminate")) << text;
  EXPECT_FALSE(Has(text, "verdict: incomplete")) << text;
}

TEST_F(RenderTest, AnOptionalGapCarriesTheConditionThatMakesItReal) {
  auto j = CompleteReport();
  j["verdict"] = "degraded";
  j["items"].push_back(json{
      {"id", "ext-dnsmasq"},
      {"group", "external"},
      {"kind", "external"},
      {"dest", "/usr/sbin/dnsmasq"},
      {"requirement", "optional"},
      {"state", "missing"},
      {"detail", ""},
      {"needed_by", "f-dnsmasq.service"},
      {"provided_by", "dnsmasq"},
      {"required_when", "a dhcp or dns service is bound to a zone"},
      {"why", "f generates its config and supervises it."}});
  auto text = Render(j);
  EXPECT_TRUE(Has(text, "required when: a dhcp or dns service"))
      << text;
  EXPECT_TRUE(Has(text, "install: dnsmasq")) << text;
}

TEST_F(RenderTest, ABinaryThatWillNotStartIsNotReportedAsPresent) {
  // `fd` installed, executable, and dead at exec because a shared
  // object lived in somebody's build tree.
  auto j = CompleteReport();
  j["verdict"] = "incomplete";
  j["items"].push_back(json{
      {"id", "fd"},
      {"group", "binaries"},
      {"kind", "binary"},
      {"dest", "/usr/local/bin/fd"},
      {"requirement", "required"},
      {"state", "unusable"},
      {"detail", "will not start: no libspdlog.so.1.16 on this box"},
      {"needed_by", "fd.service"},
      {"provided_by", ""},
      {"required_when", ""},
      {"why", "The datapath."}});
  auto text = Render(j);
  EXPECT_TRUE(Has(text, "libspdlog.so.1.16")) << text;
  EXPECT_TRUE(Has(text, "verdict: incomplete")) << text;
}

TEST_F(RenderTest, AFileThatMustNotBePresentIsCalledOut) {
  auto j = CompleteReport();
  j["verdict"] = "degraded";
  j["items"].push_back(json{
      {"id", "stale-networkd-eth0"},
      {"group", "absent"},
      {"kind", "absent"},
      {"dest", "/etc/systemd/network/10-eth0.network"},
      {"requirement", "required"},
      {"state", "conflict"},
      {"detail", "must not be present"},
      {"needed_by", ""},
      {"provided_by", ""},
      {"required_when", ""},
      {"why", "It sorts before the model's own unit and silently "
              "wins, configuring the uplink from a v0.1 example."}});
  auto text = Render(j);
  EXPECT_TRUE(Has(text, "conflict")) << text;
  EXPECT_TRUE(Has(text, "10-eth0.network")) << text;
  EXPECT_TRUE(Has(text, "silently")) << text;
}

}  // namespace
