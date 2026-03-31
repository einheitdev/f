/// @file api.cc
/// @brief Crow REST API. Reads BPF maps directly for counters
///        and rules. Sends mutations to engine via ZMQ.

#include "f/api.h"

#include <filesystem>
#include <fstream>
#include <sstream>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>
#include <zmq.hpp>

#include "f/html.h"
#include "f/protocol.h"
#include "f/types.h"

namespace f {

namespace {

using json = nlohmann::json;

auto IsHtmx(const crow::request& req) -> bool {
  return req.get_header_value("HX-Request") == "true";
}

auto ServeFile(const std::string& path)
    -> crow::response {
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
  if (ext == ".html")
    res.set_header("Content-Type", "text/html");
  else if (ext == ".css")
    res.set_header("Content-Type", "text/css");
  else if (ext == ".js")
    res.set_header("Content-Type",
                   "application/javascript");
  else if (ext == ".json")
    res.set_header("Content-Type",
                   "application/json");
  else
    res.set_header("Content-Type",
                   "application/octet-stream");
  return res;
}

// Read counters from pinned per-CPU array map.
auto ReadCounters(int counters_fd, uint32_t count)
    -> std::vector<RuleCounter> {
  std::vector<RuleCounter> out(count);
  if (counters_fd < 0) return out;
  int ncpus = libbpf_num_possible_cpus();
  if (ncpus < 1) ncpus = 1;
  for (uint32_t i = 0; i < count; i++) {
    std::vector<RuleCounter> per_cpu(ncpus);
    if (bpf_map_lookup_elem(
            counters_fd, &i, per_cpu.data()) == 0) {
      for (int c = 0; c < ncpus; c++) {
        out[i].packets += per_cpu[c].packets;
        out[i].bytes += per_cpu[c].bytes;
      }
    }
  }
  return out;
}

// Read rules from pinned hash map.
auto ReadRules(int rules_fd)
    -> std::vector<std::pair<RuleKey, RuleValue>> {
  std::vector<std::pair<RuleKey, RuleValue>> rules;
  if (rules_fd < 0) return rules;
  RuleKey key{}, next{};
  RuleValue val{};
  while (bpf_map_get_next_key(
             rules_fd, &key, &next) == 0) {
    if (bpf_map_lookup_elem(
            rules_fd, &next, &val) == 0) {
      rules.emplace_back(next, val);
    }
    key = next;
  }
  return rules;
}

// Read config from pinned array map.
auto ReadConfig(int config_fd) -> FwConfig {
  FwConfig cfg{};
  uint32_t key = 0;
  bpf_map_lookup_elem(config_fd, &key, &cfg);
  return cfg;
}

// Read status by combining pinned map data.
auto ReadStatus(const ApiData& d) -> StatusResponse {
  StatusResponse s{};
  auto cfg = ReadConfig(d.maps.config_fd);
  s.active_table = cfg.active_table;
  int rules_fd = cfg.active_table == 0
                     ? d.maps.rules_a_fd
                     : d.maps.rules_b_fd;
  if (rules_fd >= 0) {
    uint32_t count = 0;
    RuleKey key{}, next{};
    while (bpf_map_get_next_key(
               rules_fd, &key, &next) == 0) {
      count++;
      key = next;
    }
    s.rule_count = count;
  }
  // PID and uptime come from the engine via ZMQ.
  // For now, show API's own PID.
  s.pid = static_cast<uint32_t>(getpid());
  return s;
}

auto CountersToJson(
    const std::vector<RuleCounter>& c) -> json {
  auto arr = json::array();
  for (size_t i = 0; i < c.size(); i++) {
    arr.push_back({{"rule_id", i},
                   {"packets", c[i].packets},
                   {"bytes", c[i].bytes}});
  }
  return arr;
}

auto RulesToJson(
    const std::vector<std::pair<RuleKey, RuleValue>>& r)
    -> json {
  auto arr = json::array();
  for (const auto& [k, v] : r) {
    arr.push_back({
        {"src_addr", k.src_addr},
        {"dst_addr", k.dst_addr},
        {"src_port", k.src_port},
        {"dst_port", k.dst_port},
        {"proto", k.proto},
        {"action", v.action},
        {"rate_pps", v.rate_pps},
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

auto LogsToJson(const std::vector<LogEntry>& e)
    -> json {
  auto arr = json::array();
  for (const auto& entry : e) {
    arr.push_back({{"timestamp", entry.timestamp},
                   {"level", entry.level},
                   {"message", entry.message}});
  }
  return arr;
}

}  // namespace

auto SetupRoutes(crow::SimpleApp& app,
                 std::shared_ptr<ApiData> data)
    -> void {
  // ---- Static files ----
  CROW_ROUTE(app, "/")
  ([data]() {
    return ServeFile(data->static_dir + "/index.html");
  });

  CROW_ROUTE(app, "/htmx.min.js")
  ([data]() {
    return ServeFile(data->static_dir + "/htmx.min.js");
  });

  CROW_ROUTE(app, "/plotly.min.js")
  ([data]() {
    return ServeFile(
        data->static_dir + "/plotly.min.js");
  });

  CROW_ROUTE(app, "/style.css")
  ([data]() {
    return ServeFile(data->static_dir + "/style.css");
  });

  CROW_ROUTE(app, "/test.html")
  ([data]() {
    return ServeFile(
        data->static_dir + "/test.html");
  });

  // ---- Status ----
  CROW_ROUTE(app, "/api/v1/status")
  ([data](const crow::request& req) {
    auto s = ReadStatus(*data);
    if (IsHtmx(req)) {
      return crow::response(RenderStatusCard(s));
    }
    crow::response resp;
    resp.set_header("Content-Type",
                    "application/json");
    resp.write(StatusToJson(s).dump());
    return resp;
  });

  // ---- Rules ----
  CROW_ROUTE(app, "/api/v1/rules")
      .methods(crow::HTTPMethod::GET)
  ([data](const crow::request& req) {
    auto cfg = ReadConfig(data->maps.config_fd);
    int fd = cfg.active_table == 0
                 ? data->maps.rules_a_fd
                 : data->maps.rules_b_fd;
    auto rules = ReadRules(fd);
    if (IsHtmx(req)) {
      return crow::response(RenderRulesTable(rules));
    }
    crow::response resp;
    resp.set_header("Content-Type",
                    "application/json");
    resp.write(RulesToJson(rules).dump());
    return resp;
  });

  CROW_ROUTE(app, "/api/v1/rules")
      .methods(crow::HTTPMethod::PUT)
  ([data](const crow::request& req) {
    // Forward to engine via ZMQ.
    try {
      zmq::context_t ctx(1);
      zmq::socket_t sock(ctx, zmq::socket_type::req);
      sock.set(zmq::sockopt::linger, 0);
      sock.set(zmq::sockopt::rcvtimeo, 3000);
      sock.connect(data->engine_addr);

      std::string msg;
      msg += static_cast<char>(
          static_cast<uint8_t>(Cmd::kApplyConfig));
      msg += req.body;

      zmq::message_t zmq_req(msg.size());
      std::memcpy(zmq_req.data(), msg.data(),
                  msg.size());
      sock.send(zmq_req, zmq::send_flags::none);

      zmq::message_t reply;
      if (sock.recv(reply, zmq::recv_flags::none)) {
        crow::response resp;
        resp.set_header("Content-Type",
                        "application/json");
        resp.write(std::string(
            static_cast<char*>(reply.data()),
            reply.size()));
        return resp;
      }
      return crow::response(504, "Engine timeout");
    } catch (const std::exception& e) {
      return crow::response(
          502, std::string("Engine error: ") +
                   e.what());
    }
  });

  // ---- Counters ----
  CROW_ROUTE(app, "/api/v1/counters")
  ([data](const crow::request& req) {
    // Always read at least 1 counter (total).
    uint32_t count = 1;
    auto cfg = ReadConfig(data->maps.config_fd);
    int rules_fd = cfg.active_table == 0
                       ? data->maps.rules_a_fd
                       : data->maps.rules_b_fd;
    if (rules_fd >= 0) {
      uint32_t rc = 0;
      RuleKey key{}, next{};
      while (bpf_map_get_next_key(
                 rules_fd, &key, &next) == 0) {
        rc++;
        key = next;
      }
      if (rc > 0) count = rc + 1;
    }
    auto counters = ReadCounters(
        data->maps.counters_fd, count);
    if (IsHtmx(req)) {
      return crow::response(
          RenderCountersTable(counters));
    }
    crow::response resp;
    resp.set_header("Content-Type",
                    "application/json");
    resp.write(CountersToJson(counters).dump());
    return resp;
  });

  // ---- Conntrack ----
  CROW_ROUTE(app, "/api/v1/conntrack")
  ([data](const crow::request& req) {
    std::vector<std::pair<ConnKey, ConnValue>> conns;
    if (data->maps.conntrack_fd >= 0) {
      ConnKey key{}, next{};
      ConnValue val{};
      while (bpf_map_get_next_key(
                 data->maps.conntrack_fd,
                 &key, &next) == 0) {
        if (bpf_map_lookup_elem(
                data->maps.conntrack_fd,
                &next, &val) == 0) {
          conns.emplace_back(next, val);
        }
        key = next;
      }
    }
    if (IsHtmx(req)) {
      return crow::response(
          RenderConntrackTable(conns));
    }
    crow::response resp;
    resp.set_header("Content-Type",
                    "application/json");
    resp.write("[]");
    return resp;
  });

  // ---- Interfaces ----
  CROW_ROUTE(app, "/api/v1/interfaces")
  ([data](const crow::request& req) {
    // Interface info comes from the engine.
    // For now return empty — engine has the attach
    // state, not the API.
    if (IsHtmx(req)) {
      return crow::response(
          R"(<div class="empty">)"
          R"(Query engine for interface info.</div>)");
    }
    crow::response resp;
    resp.set_header("Content-Type",
                    "application/json");
    resp.write("[]");
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
      return crow::response(
          RenderLogEntries(entries));
    }
    crow::response resp;
    resp.set_header("Content-Type",
                    "application/json");
    resp.write(LogsToJson(entries).dump());
    return resp;
  });
}

auto RunApi(std::stop_token stop,
            std::shared_ptr<ApiData> data) -> void {
  spdlog::info("Crow starting on port {}.",
               data->api_port);

  crow::SimpleApp app;
  app.loglevel(crow::LogLevel::Warning);
  SetupRoutes(app, data);

  uint16_t port = data->api_port;
  std::jthread crow_thread(
      [port, &app](std::stop_token) {
        app.port(port).concurrency(3).run();
      });

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
