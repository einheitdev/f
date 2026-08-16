/// @file einheit_f_ui.cc
/// @brief f firewall appliance web UI.
///
/// It does NOT read BPF maps — this comment said it did, and that was
/// the whole defect: the pages that opened pinned maps in process
/// opened names no v0.4 bundle pins and were blank on every box ever
/// deployed. Every page here asks `fd` over the control socket, which
/// is why this binary needs no capability of any kind.

#include <cstdlib>
#include <format>
#include <iostream>
#include <string>

#include <CLI/CLI.hpp>
#include <crow.h>
#include <spdlog/spdlog.h>

#include "adapters/fw/ui_adapter.h"
#include "einheit/ui/render/template_engine.h"
#include "einheit/ui/route.h"
#include "einheit/ui/server.h"
#include "einheit/ui/stream.h"
#include "einheit/ui/theme.h"

// The framework's TLS branch is `#ifdef CROW_ENABLE_SSL`
// (ui/src/server.cc:90). That define comes from the Crow target, and
// `f/cmake/deps.cmake` set it OFF — and won, because it is included
// long before the framework declares its own Crow with SSL ON and
// FetchContent's first declaration wins. So this binary could not
// serve TLS on any box, whatever it was passed, and nothing said so:
// the flags simply produced a confusing "both must be provided".
//
// Failing the BUILD is the guard, because every other symptom of this
// is silence.
// To fix: set CROW_ENABLE_SSL ON in cmake/deps.cmake.
#ifndef CROW_ENABLE_SSL
#error "einheit-f-ui cannot serve TLS without CROW_ENABLE_SSL"
#endif

auto main(int argc, char** argv) -> int {
  CLI::App app{
      "einheit-f-ui — f firewall web dashboard"};
  // Loopback, deliberately. This process serves the whole firewall
  // state — the loaded ruleset, the zone topology, the NAT table and
  // live conntrack — and it authenticates nobody: there is no auth in
  // this adapter and none in the framework HTTP path it links. It
  // cannot serve TLS either, because no --tls-cert/--tls-key option
  // exists here to set.
  //
  // The default used to be 0.0.0.0. Combined with a shipped unit that
  // passed --bind 0.0.0.0 --port 443 and a firstboot policy that
  // admitted 443 on the UPLINK zone, a stock box published all of the
  // above to the internet. The policy half is fixed in firstboot.py;
  // this is the half that still holds when `fd` is not running, which
  // is exactly when there is no XDP program filtering anything.
  //
  // Widening this is a deliberate act and should stay one until there
  // is something to authenticate against.
  std::string bind = "127.0.0.1";
  uint16_t port = 7542;
  // Empty means plaintext. The framework serves TLS when both are set
  // (`ui/src/server.cc:90`) and errors when only one is
  // (`ServerError::TlsConfigFailed`), so a half-configured box fails
  // loudly rather than quietly serving cleartext on 443.
  std::string tls_cert;
  std::string tls_key;
  std::string fd_socket = "ipc:///run/f/control.sock";
  int sample_ms = 1000;
  std::string templates_dir;
  std::string assets_dir;
  std::string theme_name = "psychotropic";

  app.add_option("--bind", bind, "Bind address");
  app.add_option("--port", port, "TCP port");
  app.add_option("--tls-cert", tls_cert,
                 "PEM certificate chain; enables HTTPS with --tls-key");
  app.add_option("--tls-key", tls_key,
                 "PEM private key; enables HTTPS with --tls-cert");
  app.add_option("--socket", fd_socket,
                 "fd control socket endpoint");
  app.add_option("--sample-ms", sample_ms,
                 "Live-view sampling interval (ms)");
  app.add_option("--templates", templates_dir,
                 "Override templates root");
  app.add_option("--assets", assets_dir,
                 "Override assets directory");
  app.add_option("--theme", theme_name,
                 "Color theme name");

  try {
    app.parse(argc, argv);
  } catch (const CLI::ParseError& e) {
    return app.exit(e);
  }

  einheit::adapters::fw::FwUiConfig ucfg;
  ucfg.fd_socket = fd_socket;
  ucfg.sample_interval_ms = sample_ms;
  auto adapter =
      einheit::adapters::fw::NewFwUiAdapter(
          std::move(ucfg));

  einheit::ui::render::TemplateEngineConfig tcfg;
  tcfg.search_paths.push_back(adapter->TemplatesDir());
  if (!templates_dir.empty()) {
    tcfg.search_paths.push_back(templates_dir);
  }
#ifdef EINHEIT_UI_TEMPLATES_DIR
  tcfg.search_paths.push_back(EINHEIT_UI_TEMPLATES_DIR);
#endif
  einheit::ui::render::TemplateEngine engine(
      std::move(tcfg));

  crow::SimpleApp crow_app;
  einheit::ui::ServerConfig scfg;
  scfg.bind_addr = bind;
  scfg.port = port;
  scfg.tls_cert_path = tls_cert;
  scfg.tls_key_path = tls_key;
  if (!assets_dir.empty()) {
    scfg.assets_dir = assets_dir;
  }
#ifdef EINHEIT_UI_ASSETS_DIR
  else {
    scfg.assets_dir = EINHEIT_UI_ASSETS_DIR;
  }
#endif
  if (auto r = einheit::ui::Configure(crow_app, scfg);
      !r) {
    std::cerr << std::format("server config: {}\n",
                             r.error().message);
    return 1;
  }

  einheit::ui::EventStream events(engine);
  events.Mount(crow_app);

  const auto theme =
      einheit::ui::NamedTheme(theme_name);
  CROW_ROUTE(crow_app, "/theme.css")
  ([&engine, theme](const crow::request&) {
    auto body = engine.Render("theme.css",
        einheit::ui::ToJson(theme));
    if (!body) {
      crow::response r{500, body.error().message};
      r.set_header("Content-Type",
                   "text/plain; charset=utf-8");
      return r;
    }
    crow::response r{200, *body};
    r.set_header("Content-Type",
                 "text/css; charset=utf-8");
    r.set_header("Cache-Control", "no-store");
    return r;
  });

  einheit::ui::SetLayoutPrimaryNav(
      einheit::ui::NavToJson(adapter->Nav()));
  einheit::ui::SetLayoutPrimaryBrand(
      adapter->DisplayName());

  einheit::ui::AdapterContext ctx{
      .app = &crow_app,
      .templates = &engine,
      .events = &events,
  };
  adapter->Mount(ctx);

  if (auto r = einheit::ui::Run(crow_app, scfg); !r) {
    std::cerr << std::format("server: {}\n",
                             r.error().message);
    return 1;
  }
  return 0;
}
