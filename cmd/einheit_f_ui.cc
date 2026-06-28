/// @file einheit_f_ui.cc
/// @brief f firewall appliance web UI. Reads BPF maps
///        directly, serves dashboard + rules + counters.

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

auto main(int argc, char** argv) -> int {
  CLI::App app{
      "einheit-f-ui — f firewall web dashboard"};
  std::string bind = "0.0.0.0";
  uint16_t port = 7542;
  std::string pin_path = "/sys/fs/bpf/f";
  std::string fd_socket = "ipc:///run/f/control.sock";
  int sample_ms = 1000;
  std::string templates_dir;
  std::string assets_dir;
  std::string theme_name = "psychotropic";

  app.add_option("--bind", bind, "Bind address");
  app.add_option("--port", port, "TCP port");
  app.add_option("--pin-path", pin_path,
                 "BPF map pin directory");
  app.add_option("--socket", fd_socket,
                 "fd control socket endpoint");
  app.add_option("--sample-ms", sample_ms,
                 "Counter sampling interval (ms)");
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
  ucfg.pin_path = pin_path;
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
