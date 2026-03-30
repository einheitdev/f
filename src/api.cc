/// @file api.cc
/// @brief Crow REST API endpoints and HTMX fragment serving.

#include "f/api.h"

#include <filesystem>
#include <fstream>
#include <sstream>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include "f/html.h"

namespace f {

namespace {

using json = nlohmann::json;

auto IsHtmx(const crow::request& req) -> bool {
  return req.get_header_value("HX-Request") == "true";
}

auto ServeFile(const std::string& path) -> crow::response {
  crow::response res;
  if (!std::filesystem::exists(path) ||
      !std::filesystem::is_regular_file(path)) {
    res.code = 404;
    res.write("Not found");
    return res;
  }

  std::ifstream file(path, std::ios::binary);
  if (!file) {
    res.code = 500;
    res.write("Failed to open file");
    return res;
  }

  std::ostringstream contents;
  contents << file.rdbuf();
  res.body = contents.str();

  auto ext =
      std::filesystem::path(path).extension().string();
  if (ext == ".html") {
    res.set_header("Content-Type", "text/html");
  } else if (ext == ".css") {
    res.set_header("Content-Type", "text/css");
  } else if (ext == ".js") {
    res.set_header(
        "Content-Type", "application/javascript");
  } else if (ext == ".json") {
    res.set_header("Content-Type", "application/json");
  } else {
    res.set_header(
        "Content-Type", "application/octet-stream");
  }
  return res;
}

auto RulesToJson(
    const std::vector<std::pair<RuleKey, RuleValue>>& rules)
    -> json {
  auto arr = json::array();
  for (const auto& [key, val] : rules) {
    arr.push_back({
        {"src_addr", key.src_addr},
        {"dst_addr", key.dst_addr},
        {"src_port", key.src_port},
        {"dst_port", key.dst_port},
        {"proto", key.proto},
        {"action", val.action},
        {"rate_pps", val.rate_pps},
    });
  }
  return arr;
}

auto CountersToJson(
    const std::vector<RuleCounter>& counters) -> json {
  auto arr = json::array();
  for (size_t i = 0; i < counters.size(); i++) {
    arr.push_back({
        {"rule_id", i},
        {"packets", counters[i].packets},
        {"bytes", counters[i].bytes},
    });
  }
  return arr;
}

auto StatusToJson(const StatusResponse& s) -> json {
  return {
      {"pid", s.pid},
      {"uptime_s", s.uptime_s},
      {"active_table", s.active_table},
      {"rule_count", s.rule_count},
      {"iface_count", s.iface_count},
  };
}

auto LogsToJson(const std::vector<LogEntry>& entries)
    -> json {
  auto arr = json::array();
  for (const auto& e : entries) {
    arr.push_back({
        {"timestamp", e.timestamp},
        {"level", e.level},
        {"message", e.message},
    });
  }
  return arr;
}

}  // namespace

auto SetupRoutes(crow::SimpleApp& app,
                 std::shared_ptr<ApiData> data) -> void {
  // ---- Static files ----
  CROW_ROUTE(app, "/")
  ([data]() {
    return ServeFile(data->static_dir + "/index.html");
  });

  CROW_ROUTE(app, "/test.html")
  ([data]() {
    return ServeFile(data->static_dir + "/test.html");
  });

  CROW_ROUTE(app, "/htmx.min.js")
  ([data]() {
    return ServeFile(data->static_dir + "/htmx.min.js");
  });

  CROW_ROUTE(app, "/plotly.min.js")
  ([data]() {
    return ServeFile(data->static_dir + "/plotly.min.js");
  });

  CROW_ROUTE(app, "/style.css")
  ([data]() {
    return ServeFile(data->static_dir + "/style.css");
  });

  // ---- Status ----
  CROW_ROUTE(app, "/api/v1/status")
  ([data](const crow::request& req) {
    auto res = GetStatus(*data->daemon);
    if (!res) {
      return crow::response(500, "Internal error");
    }
    if (IsHtmx(req)) {
      return crow::response(
          RenderStatusCard(*res));
    }
    crow::response resp;
    resp.set_header("Content-Type", "application/json");
    resp.write(StatusToJson(*res).dump());
    return resp;
  });

  // ---- Rules ----
  CROW_ROUTE(app, "/api/v1/rules")
      .methods(crow::HTTPMethod::GET)
  ([data](const crow::request& req) {
    auto rules = GetRules(*data->daemon);
    if (!rules) {
      return crow::response(500, "Internal error");
    }
    if (IsHtmx(req)) {
      return crow::response(
          RenderRulesTable(*rules));
    }
    crow::response resp;
    resp.set_header("Content-Type", "application/json");
    resp.write(RulesToJson(*rules).dump());
    return resp;
  });

  CROW_ROUTE(app, "/api/v1/rules")
      .methods(crow::HTTPMethod::PUT)
  ([data](const crow::request& req) {
    try {
      auto j = json::parse(req.body);
      ConfigMsg msg{};
      msg.cmd = Cmd::kApplyConfig;
      msg.default_action = j.value("default_action", 0);
      msg.conntrack_enabled =
          j.value("conntrack_enabled", 0);
      msg.conntrack_timeout_s =
          j.value("conntrack_timeout_s", 300);

      auto& rules_arr = j["rules"];
      msg.rule_count =
          static_cast<uint32_t>(rules_arr.size());

      std::vector<std::byte> rule_data;
      for (const auto& r : rules_arr) {
        RuleKey key{};
        key.src_addr = r.value("src_addr", 0u);
        key.dst_addr = r.value("dst_addr", 0u);
        key.src_port = r.value("src_port", 0);
        key.dst_port = r.value("dst_port", 0);
        key.proto = r.value("proto", 0);
        RuleValue val{};
        val.action = r.value("action", 0);
        val.rate_pps = r.value("rate_pps", 0u);

        auto* kp = reinterpret_cast<const std::byte*>(
            &key);
        rule_data.insert(
            rule_data.end(), kp, kp + sizeof(key));
        auto* vp = reinterpret_cast<const std::byte*>(
            &val);
        rule_data.insert(
            rule_data.end(), vp, vp + sizeof(val));
      }

      auto res = ApplyConfig(
          *data->daemon, msg, rule_data);
      if (!res) {
        return crow::response(500, res.error().message);
      }
      crow::response resp;
      resp.set_header(
          "Content-Type", "application/json");
      resp.write(
          json({{"rules_installed", *res}}).dump());
      return resp;
    } catch (const std::exception& e) {
      return crow::response(
          400, std::string("Bad request: ") + e.what());
    }
  });

  // ---- Counters ----
  CROW_ROUTE(app, "/api/v1/counters")
  ([data](const crow::request& req) {
    auto status = GetStatus(*data->daemon);
    // Always read at least 1 counter (index 0 = total).
    uint32_t count =
        status ? std::max(status->rule_count, 1u) : 1;
    auto counters = GetCounters(*data->daemon, count);
    if (!counters) {
      return crow::response(500, "Internal error");
    }
    if (IsHtmx(req)) {
      return crow::response(
          RenderCountersTable(*counters));
    }
    crow::response resp;
    resp.set_header("Content-Type", "application/json");
    resp.write(CountersToJson(*counters).dump());
    return resp;
  });

  // ---- Conntrack ----
  CROW_ROUTE(app, "/api/v1/conntrack")
  ([data](const crow::request& req) {
    // In no-bpf mode, conntrack map is empty.
    std::vector<std::pair<ConnKey, ConnValue>> conns;
    if (IsHtmx(req)) {
      return crow::response(
          RenderConntrackTable(conns));
    }
    crow::response resp;
    resp.set_header("Content-Type", "application/json");
    resp.write("[]");
    return resp;
  });

  // ---- Interfaces ----
  CROW_ROUTE(app, "/api/v1/interfaces")
  ([data](const crow::request& req) {
    auto* d = data->daemon;
    std::span<const IfAttach> ifaces(
        d->interfaces, d->iface_count);
    if (IsHtmx(req)) {
      return crow::response(
          RenderInterfaceList(ifaces));
    }
    auto arr = json::array();
    for (const auto& iface : ifaces) {
      arr.push_back({
          {"name", iface.name},
          {"ifindex", iface.ifindex},
      });
    }
    crow::response resp;
    resp.set_header("Content-Type", "application/json");
    resp.write(arr.dump());
    return resp;
  });

  // ---- Log ----
  CROW_ROUTE(app, "/api/v1/log")
  ([data](const crow::request& req) {
    if (!data->log_sink) {
      return crow::response(503, "No log sink");
    }
    auto entries = data->log_sink->GetLogs();
    if (IsHtmx(req)) {
      return crow::response(RenderLogEntries(entries));
    }
    crow::response resp;
    resp.set_header("Content-Type", "application/json");
    resp.write(LogsToJson(entries).dump());
    return resp;
  });
}

auto RunApi(std::stop_token stop,
            std::shared_ptr<ApiData> data) -> void {
  spdlog::info("Starting Crow on port {}.", data->api_port);

  crow::SimpleApp app;
  app.loglevel(crow::LogLevel::Warning);
  SetupRoutes(app, data);

  uint16_t port = data->api_port;

  // Spawn Crow on its own thread — port().concurrency().run()
  // all in one chain, matching OTC.Relay pattern.
  std::jthread crow_thread([port, &app](std::stop_token) {
    app.port(port).concurrency(3).run();
  });

  // Poll stop token.
  while (!stop.stop_requested()) {
    std::this_thread::sleep_for(
        std::chrono::milliseconds(100));
  }

  spdlog::info("Stopping Crow.");
  app.stop();
  crow_thread.join();
  spdlog::info("Crow stopped.");
}

}  // namespace f
