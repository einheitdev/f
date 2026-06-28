/// @file einheit_f.cc
/// @brief f firewall appliance CLI. Reads BPF maps directly;
///        talks to fd over raw IPC for control commands.

#include <cstdlib>
#include <format>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include <CLI/CLI.hpp>

#include "adapters/fw/adapter.h"
#include "adapters/fw/transport.h"
#include "einheit/cli/auth.h"
#include "einheit/cli/command_tree.h"
#include "einheit/cli/globals.h"
#include "einheit/cli/render/table.h"
#include "einheit/cli/render/terminal_caps.h"
#include "einheit/cli/render/theme.h"
#include "einheit/cli/shell.h"

namespace {

auto BuildTree(einheit::cli::CommandTree& tree,
               einheit::cli::ProductAdapter& adapter)
    -> void {
  (void)einheit::cli::RegisterGlobals(tree);
  for (auto& spec : adapter.Commands()) {
    (void)einheit::cli::Register(
        tree, std::move(spec));
  }
}

}  // namespace

auto main(int argc, char** argv) -> int {
  CLI::App app{"einheit-f — f firewall appliance CLI"};
  app.option_defaults()->ignore_case();
  app.allow_extras();

  std::string color = "auto";
  bool ascii = false;
  int width = 0;
  std::string pin_path = "/sys/fs/bpf/f";
  std::string fd_socket = "ipc:///run/f/control.sock";
  std::string fw_source = "/etc/f/rules.fw";
  bool locked = false;

  app.add_option("--color", color, "always|never|auto");
  app.add_flag("--ascii", ascii, "Force ASCII borders");
  app.add_option("--width", width,
                 "Override detected width");
  app.add_option("--pin-path", pin_path,
                 "BPF map pin directory");
  app.add_option("--socket", fd_socket,
                 "fd control socket endpoint");
  app.add_option("--source", fw_source,
                 "FWL source file path");
  app.add_flag("--locked", locked,
               "Restricted mode — no shell escapes");

  try {
    app.parse(argc, argv);
  } catch (const CLI::ParseError& e) {
    return app.exit(e);
  }

  using namespace einheit;

  cli::render::CapOverrides ov;
  ov.color = (color == "always"  ? 1
              : color == "never" ? 0
                                 : -1);
  ov.force_ascii = ascii;
  ov.width = static_cast<std::uint16_t>(width);
  const auto caps = cli::render::ApplyOverrides(
      cli::render::DetectTerminal(), ov);

  auto adapter = adapters::fw::NewFwAdapter();

  adapters::fw::FLocalConfig tcfg;
  tcfg.pin_path = pin_path;
  tcfg.fd_socket = fd_socket;
  tcfg.fw_source = fw_source;
  auto tx_result = adapters::fw::NewFLocalTransport(tcfg);
  if (!tx_result) {
    std::cerr << std::format("transport: {}\n",
                             tx_result.error().message);
    return 1;
  }
  auto& tx = *tx_result;
  if (auto r = tx->Connect(); !r) {
    std::cerr << std::format("connect: {}\n",
                             r.error().message);
    return 1;
  }

  cli::shell::Shell s;
  s.tx = std::move(tx);
  s.caps = caps;
  s.locked = locked;
  s.theme = cli::render::PickTheme(caps, false);

  // On the appliance, every SSH session is admin.
  s.caller.user = "operator";
  s.caller.role = cli::RoleGate::AdminOnly;
  if (auto id = cli::auth::ResolveLocal(); id) {
    s.caller.user = id->user;
  }

  BuildTree(s.tree, *adapter);
  s.adapter = std::move(adapter);

  const auto leftovers = app.remaining();
  if (!leftovers.empty()) {
    auto r = cli::shell::RunOneshot(s, leftovers);
    if (!r) {
      std::cerr << std::format("error: {}\n",
                               r.error().message);
      return 1;
    }
    if (r->response &&
        r->response->status ==
            cli::protocol::ResponseStatus::Error) {
      return 1;
    }
    return 0;
  }

  auto rc = cli::shell::RunShell(s);
  if (!rc) {
    std::cerr << std::format("shell: {}\n",
                             rc.error().message);
    return 1;
  }
  return 0;
}
