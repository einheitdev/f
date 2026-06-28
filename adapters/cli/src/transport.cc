/// @file transport.cc
/// @brief Local transport: BPF map reads + raw ZMQ to fd.

#include "adapters/fw/transport.h"

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <format>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <nlohmann/json.hpp>
#include <zmq.hpp>

#include "f/bpf_loader.h"
#include "f/engine.h"
#include "f/types.h"

namespace einheit::adapters::fw {

namespace {

using json = nlohmann::json;
using json_t = nlohmann::json;
using Error_t = cli::Error<cli::transport::TransportError>;
namespace proto = cli::protocol;

auto MakeOk(const std::string& id, json data)
    -> proto::Response {
  auto s = data.dump();
  return {
      .id = id,
      .status = proto::ResponseStatus::Ok,
      .data = {s.begin(), s.end()},
  };
}

auto MakeErr(const std::string& id,
             const std::string& code,
             const std::string& msg,
             const std::string& hint = "")
    -> proto::Response {
  return {
      .id = id,
      .status = proto::ResponseStatus::Error,
      .error = proto::ResponseError{code, msg, hint},
  };
}

auto ReadSysfs(const std::string& iface,
               const std::string& attr)
    -> std::string {
  auto path = std::format(
      "/sys/class/net/{}/{}", iface, attr);
  std::ifstream f(path);
  std::string val;
  if (f) std::getline(f, val);
  return val;
}

auto FormatMac(const std::string& raw) -> std::string {
  return raw;
}

auto FormatSpeed(const std::string& raw) -> std::string {
  if (raw.empty() || raw == "-1") return "unknown";
  long mbps = std::strtol(raw.c_str(), nullptr, 10);
  if (mbps >= 1000) {
    return std::format("{}G", mbps / 1000);
  }
  return std::format("{}M", mbps);
}

auto GatherInterfaces() -> json {
  json ifaces = json::array();
  struct ifaddrs* ifa_list = nullptr;
  if (getifaddrs(&ifa_list) != 0) return ifaces;

  std::map<std::string, json> by_name;
  for (auto* ifa = ifa_list; ifa; ifa = ifa->ifa_next) {
    if (!ifa->ifa_name) continue;
    std::string name = ifa->ifa_name;
    if (name == "lo") continue;
    if (by_name.find(name) == by_name.end()) {
      by_name[name] = {
          {"name", name},
          {"state", (ifa->ifa_flags & IFF_UP) ? "up"
                                              : "down"},
          {"running", (ifa->ifa_flags & IFF_RUNNING) != 0},
          {"mac", FormatMac(
               ReadSysfs(name, "address"))},
          {"mtu", ReadSysfs(name, "mtu")},
          {"speed", FormatSpeed(
               ReadSysfs(name, "speed"))},
          {"addresses", json::array()},
          {"rx_bytes", ReadSysfs(
               name, "statistics/rx_bytes")},
          {"tx_bytes", ReadSysfs(
               name, "statistics/tx_bytes")},
          {"rx_packets", ReadSysfs(
               name, "statistics/rx_packets")},
          {"tx_packets", ReadSysfs(
               name, "statistics/tx_packets")},
      };
    }
    if (ifa->ifa_addr) {
      char buf[64] = {};
      if (ifa->ifa_addr->sa_family == AF_INET) {
        auto* sin = reinterpret_cast<struct sockaddr_in*>(
            ifa->ifa_addr);
        inet_ntop(AF_INET, &sin->sin_addr, buf,
                  sizeof(buf));
        by_name[name]["addresses"].push_back(
            std::string(buf));
      } else if (ifa->ifa_addr->sa_family == AF_INET6) {
        auto* sin6 =
            reinterpret_cast<struct sockaddr_in6*>(
                ifa->ifa_addr);
        inet_ntop(AF_INET6, &sin6->sin6_addr, buf,
                  sizeof(buf));
        by_name[name]["addresses"].push_back(
            std::string(buf));
      }
    }
  }
  freeifaddrs(ifa_list);
  for (auto& [_, v] : by_name) ifaces.push_back(v);
  return ifaces;
}

auto SendRawToFd(zmq::socket_t& sock, f::Cmd cmd,
                 const std::string& payload = "")
    -> std::expected<std::string, std::string> {
  std::string msg;
  msg += static_cast<char>(static_cast<uint8_t>(cmd));
  msg += payload;
  zmq::message_t req(msg.size());
  std::memcpy(req.data(), msg.data(), msg.size());
  if (!sock.send(req, zmq::send_flags::none)) {
    return std::unexpected("send failed");
  }
  zmq::message_t reply;
  if (!sock.recv(reply, zmq::recv_flags::none)) {
    return std::unexpected("recv timeout");
  }
  return std::string(
      static_cast<char*>(reply.data()), reply.size());
}

auto DefaultConfigPath() -> std::string {
  const char* home = std::getenv("HOME");
  if (!home) return "";
  return std::format("{}/.config/einheit-f/config.yaml",
                     home);
}

auto LoadCliConfig(const std::string& path) -> json {
  if (path.empty()) return json::object();
  std::ifstream f(path);
  if (!f) return json::object();
  try {
    return json::parse(f);
  } catch (...) {
    return json::object();
  }
}

auto SaveCliConfig(const std::string& path,
                   const json& cfg) -> bool {
  if (path.empty()) return false;
  auto dir = std::filesystem::path(path).parent_path();
  std::filesystem::create_directories(dir);
  std::ofstream f(path);
  if (!f) return false;
  f << cfg.dump(2) << "\n";
  return f.good();
}

auto ResolveEditor(const FLocalConfig& cfg) -> std::string {
  auto conf_path = cfg.config_path.empty()
                       ? DefaultConfigPath()
                       : cfg.config_path;
  auto cli_cfg = LoadCliConfig(conf_path);
  if (cli_cfg.contains("editor")) {
    return cli_cfg["editor"].get<std::string>();
  }
  const char* env = std::getenv("EDITOR");
  if (env && env[0]) return env;
  env = std::getenv("VISUAL");
  if (env && env[0]) return env;
  return cfg.editor;
}

auto RunSubprocess(const std::vector<std::string>& argv)
    -> std::pair<int, std::string> {
  int pipefd[2];
  if (pipe(pipefd) != 0) return {-1, "pipe failed"};

  pid_t pid = fork();
  if (pid < 0) {
    close(pipefd[0]);
    close(pipefd[1]);
    return {-1, "fork failed"};
  }
  if (pid == 0) {
    close(pipefd[0]);
    dup2(pipefd[1], STDOUT_FILENO);
    dup2(pipefd[1], STDERR_FILENO);
    close(pipefd[1]);
    std::vector<char*> args;
    for (auto& a : argv) {
      args.push_back(const_cast<char*>(a.c_str()));
    }
    args.push_back(nullptr);
    execvp(args[0], args.data());
    _exit(127);
  }
  close(pipefd[1]);
  std::string output;
  char buf[4096];
  ssize_t n;
  while ((n = read(pipefd[0], buf, sizeof(buf))) > 0) {
    output.append(buf, n);
  }
  close(pipefd[0]);
  int status = 0;
  waitpid(pid, &status, 0);
  int rc = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
  return {rc, output};
}

auto RunInteractive(const std::vector<std::string>& argv)
    -> int {
  pid_t pid = fork();
  if (pid < 0) return -1;
  if (pid == 0) {
    std::vector<char*> args;
    for (auto& a : argv) {
      args.push_back(const_cast<char*>(a.c_str()));
    }
    args.push_back(nullptr);
    execvp(args[0], args.data());
    _exit(127);
  }
  int status = 0;
  waitpid(pid, &status, 0);
  return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

auto FileMtime(const std::string& path) -> timespec {
  struct stat st {};
  if (stat(path.c_str(), &st) != 0) return {};
  return st.st_mtim;
}

class FLocalTransport final
    : public cli::transport::Transport {
 public:
  explicit FLocalTransport(FLocalConfig cfg)
      : cfg_(std::move(cfg)) {}

  auto Connect()
      -> std::expected<void, Error_t> override {
    auto maps = f::OpenPinnedMaps(cfg_.pin_path);
    if (maps) {
      maps_ = *maps;
      maps_open_ = true;
    }

    try {
      zmq_ctx_ = std::make_unique<zmq::context_t>(1);
      zmq_sock_ = std::make_unique<zmq::socket_t>(
          *zmq_ctx_, zmq::socket_type::req);
      zmq_sock_->set(zmq::sockopt::linger, 0);
      zmq_sock_->set(zmq::sockopt::rcvtimeo, 3000);
      zmq_sock_->set(zmq::sockopt::sndtimeo, 3000);
      zmq_sock_->connect(cfg_.fd_socket);
      fd_connected_ = true;
    } catch (const zmq::error_t& e) {
      // fd might not be running — show commands still
      // work via pinned maps.
    }
    return {};
  }

  auto Disconnect() -> void override {
    zmq_sock_.reset();
    zmq_ctx_.reset();
    fd_connected_ = false;
    // BPF map FDs are closed by the OS on process exit.
  }

  auto SendRequest(
      const proto::Request& req,
      std::chrono::milliseconds /*timeout*/)
      -> std::expected<proto::Response, Error_t> override {
    if (req.command == "show_status") {
      return HandleShowStatus(req);
    }
    if (req.command == "show_interfaces") {
      return HandleShowInterfaces(req);
    }
    if (req.command == "show_firewall") {
      return HandleShowFirewall(req);
    }
    if (req.command == "show_firewall_rules") {
      return HandleShowFirewallRules(req);
    }
    if (req.command == "show_counters") {
      return HandleShowCounters(req);
    }
    if (req.command == "reload_firewall") {
      return HandleReloadFirewall(req);
    }
    if (req.command == "clear_counters") {
      return HandleClearCounters(req);
    }
    if (req.command == "configure_firewall") {
      return HandleConfigureFirewall(req);
    }
    if (req.command == "set_editor") {
      return HandleSetEditor(req);
    }
    if (req.command == "show_log") {
      return HandleShowLog(req);
    }
    return MakeErr(req.id, "unknown_command",
                   "Unknown command: " + req.command);
  }

  auto Subscribe(const std::string& /*topic_prefix*/,
                 cli::transport::EventCallback /*cb*/)
      -> std::expected<void, Error_t> override {
    return {};
  }

  auto Unsubscribe(const std::string& /*topic_prefix*/)
      -> std::expected<void, Error_t> override {
    return {};
  }

 private:
  FLocalConfig cfg_;
  f::BpfHandles maps_{};
  bool maps_open_ = false;
  std::unique_ptr<zmq::context_t> zmq_ctx_;
  std::unique_ptr<zmq::socket_t> zmq_sock_;
  bool fd_connected_ = false;

  auto HandleShowStatus(const proto::Request& req)
      -> proto::Response {
    json j;
    if (fd_connected_) {
      auto resp = SendRawToFd(
          *zmq_sock_, f::Cmd::kGetStatus);
      if (resp) {
        try {
          j = json::parse(*resp);
        } catch (...) {
          j["daemon"] = "error parsing response";
        }
      } else {
        j["daemon"] = "not responding";
      }
    } else {
      j["daemon"] = "not connected";
    }
    j["maps_available"] = maps_open_;
    j["pin_path"] = cfg_.pin_path;
    return MakeOk(req.id, j);
  }

  auto HandleShowInterfaces(const proto::Request& req)
      -> proto::Response {
    return MakeOk(req.id, GatherInterfaces());
  }

  auto HandleShowFirewall(const proto::Request& req)
      -> proto::Response {
    if (!maps_open_) {
      return MakeErr(req.id, "no_maps",
          "BPF maps not available — is fd running?",
          "Start fd first: sudo fd -i <iface> run");
    }
    json j;
    // Read config map.
    uint32_t cfg_key = 0;
    f::FwConfig fw_cfg{};
    if (bpf_map_lookup_elem(
            maps_.config_fd, &cfg_key, &fw_cfg) == 0) {
      j["default_action"] =
          fw_cfg.default_action == 0 ? "drop" : "allow";
      j["active_table"] = fw_cfg.active_table;
      j["conntrack"] = fw_cfg.conntrack_enabled != 0;
    }
    // Count rules in active table.
    int rules_fd = fw_cfg.active_table == 0
                       ? maps_.rules_a_fd
                       : maps_.rules_b_fd;
    uint32_t count = 0;
    f::RuleKey key{}, next{};
    while (bpf_map_get_next_key(
               rules_fd, &key, &next) == 0) {
      count++;
      key = next;
    }
    j["rule_count"] = count;
    return MakeOk(req.id, j);
  }

  auto HandleShowFirewallRules(
      const proto::Request& req)
      -> proto::Response {
    if (!maps_open_) {
      return MakeErr(req.id, "no_maps",
          "BPF maps not available — is fd running?");
    }
    uint32_t cfg_key = 0;
    f::FwConfig fw_cfg{};
    bpf_map_lookup_elem(
        maps_.config_fd, &cfg_key, &fw_cfg);
    int rules_fd = fw_cfg.active_table == 0
                       ? maps_.rules_a_fd
                       : maps_.rules_b_fd;

    // Read counters.
    int ncpus = libbpf_num_possible_cpus();
    if (ncpus < 1) ncpus = 1;

    json rules = json::array();
    f::RuleKey key{}, next{};
    uint32_t idx = 0;
    while (bpf_map_get_next_key(
               rules_fd, &key, &next) == 0) {
      f::RuleValue val{};
      bpf_map_lookup_elem(rules_fd, &next, &val);
      // Aggregate per-CPU counters.
      uint64_t pkts = 0, bytes = 0;
      std::vector<f::RuleCounter> per_cpu(ncpus);
      if (bpf_map_lookup_elem(
              maps_.counters_fd, &idx,
              per_cpu.data()) == 0) {
        for (int c = 0; c < ncpus; c++) {
          pkts += per_cpu[c].packets;
          bytes += per_cpu[c].bytes;
        }
      }
      char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
      inet_ntop(AF_INET, &next.src_addr, src,
                sizeof(src));
      inet_ntop(AF_INET, &next.dst_addr, dst,
                sizeof(dst));
      std::string action_str;
      switch (static_cast<f::Action>(val.action)) {
        case f::Action::kDrop: action_str = "drop"; break;
        case f::Action::kAllow:
          action_str = "allow";
          break;
        case f::Action::kRateLimit:
          action_str = std::format(
              "rate-limit({})", val.rate_pps);
          break;
      }
      std::string proto_str;
      switch (static_cast<f::Proto>(next.proto)) {
        case f::Proto::kAny: proto_str = "any"; break;
        case f::Proto::kIcmp: proto_str = "icmp"; break;
        case f::Proto::kTcp: proto_str = "tcp"; break;
        case f::Proto::kUdp: proto_str = "udp"; break;
        default:
          proto_str = std::to_string(next.proto);
          break;
      }
      rules.push_back({
          {"idx", idx},
          {"src", std::string(src)},
          {"dst", std::string(dst)},
          {"src_port", next.src_port},
          {"dst_port", next.dst_port},
          {"proto", proto_str},
          {"action", action_str},
          {"packets", pkts},
          {"bytes", bytes},
      });
      key = next;
      idx++;
    }
    return MakeOk(req.id, rules);
  }

  auto HandleShowCounters(const proto::Request& req)
      -> proto::Response {
    if (!maps_open_) {
      return MakeErr(req.id, "no_maps",
          "BPF maps not available — is fd running?");
    }
    int ncpus = libbpf_num_possible_cpus();
    if (ncpus < 1) ncpus = 1;

    json counters = json::array();
    for (uint32_t i = 0; i < 256; i++) {
      std::vector<f::RuleCounter> per_cpu(ncpus);
      if (bpf_map_lookup_elem(
              maps_.counters_fd, &i,
              per_cpu.data()) != 0) {
        break;
      }
      uint64_t pkts = 0, bytes = 0;
      for (int c = 0; c < ncpus; c++) {
        pkts += per_cpu[c].packets;
        bytes += per_cpu[c].bytes;
      }
      if (pkts == 0 && bytes == 0) continue;
      counters.push_back({
          {"id", i},
          {"packets", pkts},
          {"bytes", bytes},
      });
    }
    return MakeOk(req.id, counters);
  }

  auto HandleReloadFirewall(const proto::Request& req)
      -> proto::Response {
    if (!fd_connected_) {
      return MakeErr(req.id, "no_daemon",
          "fd is not running",
          "Start fd first: sudo fd -i <iface> run");
    }
    auto resp = SendRawToFd(
        *zmq_sock_, f::Cmd::kReloadProg);
    if (!resp) {
      return MakeErr(req.id, "send_failed", resp.error());
    }
    json j;
    try {
      j = json::parse(*resp);
    } catch (...) {
      j["raw"] = *resp;
    }
    if (j.contains("error")) {
      return MakeErr(req.id, "reload_failed",
                     j["error"].get<std::string>());
    }
    return MakeOk(req.id, j);
  }

  auto HandleClearCounters(const proto::Request& req)
      -> proto::Response {
    if (!maps_open_) {
      return MakeErr(req.id, "no_maps",
          "BPF maps not available — is fd running?");
    }
    int ncpus = libbpf_num_possible_cpus();
    if (ncpus < 1) ncpus = 1;
    std::vector<f::RuleCounter> zeros(ncpus);
    uint32_t cleared = 0;
    for (uint32_t i = 0; i < 256; i++) {
      if (bpf_map_update_elem(
              maps_.counters_fd, &i, zeros.data(),
              BPF_ANY) != 0) {
        break;
      }
      cleared++;
    }
    return MakeOk(req.id, {{"cleared", cleared}});
  }

  auto HandleConfigureFirewall(const proto::Request& req)
      -> proto::Response {
    auto source = cfg_.fw_source;
    // Create the source file with a template if it
    // doesn't exist.
    if (!std::filesystem::exists(source)) {
      auto dir = std::filesystem::path(source)
                     .parent_path();
      std::filesystem::create_directories(dir);
      std::ofstream f(source);
      f << "# f firewall rules\n"
        << "# See: fwl --help\n\n"
        << "default allow\n";
    }

    auto editor = ResolveEditor(cfg_);
    auto before = FileMtime(source);

    int rc = RunInteractive({editor, source});
    if (rc != 0) {
      return MakeErr(req.id, "editor_failed",
          std::format("{} exited with code {}", editor,
                      rc));
    }

    auto after = FileMtime(source);
    bool changed = (before.tv_sec != after.tv_sec ||
                    before.tv_nsec != after.tv_nsec);
    if (!changed) {
      return MakeOk(req.id, {
          {"status", "unchanged"},
          {"message", "No changes made"},
      });
    }

    // Validate with fwl check.
    auto [check_rc, check_out] = RunSubprocess(
        {cfg_.fwl_path, "check", source});
    if (check_rc != 0) {
      return MakeErr(req.id, "validation_failed",
          check_out.empty()
              ? "fwl check failed"
              : check_out,
          "Fix the errors and run configure firewall "
          "again");
    }

    json result = {
        {"status", "valid"},
        {"source", source},
    };

    // If fd is running with watcher, it will pick up
    // the change. Optionally force immediate reload.
    if (fd_connected_) {
      auto resp = SendRawToFd(
          *zmq_sock_, f::Cmd::kReloadProg);
      if (resp) {
        result["reload"] = "triggered";
      } else {
        result["reload"] = "watcher will pick up change";
      }
    } else {
      result["reload"] = "fd not running — reload "
                         "when fd starts";
    }
    return MakeOk(req.id, result);
  }

  auto HandleSetEditor(const proto::Request& req)
      -> proto::Response {
    if (req.args.empty()) {
      auto editor = ResolveEditor(cfg_);
      return MakeOk(req.id, {{"editor", editor}});
    }
    auto name = req.args[0];
    auto conf_path = cfg_.config_path.empty()
                         ? DefaultConfigPath()
                         : cfg_.config_path;
    auto cli_cfg = LoadCliConfig(conf_path);
    cli_cfg["editor"] = name;
    if (!SaveCliConfig(conf_path, cli_cfg)) {
      return MakeErr(req.id, "save_failed",
          "Could not save config to " + conf_path);
    }
    return MakeOk(req.id, {
        {"editor", name},
        {"config", conf_path},
    });
  }

  auto HandleShowLog(const proto::Request& req)
      -> proto::Response {
    // Try journalctl first.
    std::string lines = "20";
    if (!req.args.empty()) lines = req.args[0];
    auto [rc, output] = RunSubprocess(
        {"journalctl", "-u", "fd.service", "-n", lines,
         "--no-pager", "-o", "short-iso"});
    if (rc == 0 && !output.empty() &&
        output.find("No journal files") ==
            std::string::npos) {
      json entries = json::array();
      std::istringstream ss(output);
      std::string line;
      while (std::getline(ss, line)) {
        if (!line.empty()) {
          entries.push_back(line);
        }
      }
      return MakeOk(req.id, {
          {"source", "journald"},
          {"entries", entries},
      });
    }
    // Fallback: check for a log file.
    std::string log_path = "/var/log/fd.log";
    if (std::filesystem::exists(log_path)) {
      std::ifstream f(log_path);
      json entries = json::array();
      std::string line;
      int n = std::stoi(lines);
      std::vector<std::string> all;
      while (std::getline(f, line)) all.push_back(line);
      int start = std::max(0,
          static_cast<int>(all.size()) - n);
      for (int i = start;
           i < static_cast<int>(all.size()); i++) {
        entries.push_back(all[i]);
      }
      return MakeOk(req.id, {
          {"source", "file"},
          {"path", log_path},
          {"entries", entries},
      });
    }
    return MakeOk(req.id, {
        {"source", "none"},
        {"entries", json::array()},
        {"message", "No log source available — fd is "
                    "not running as a systemd service "
                    "and no log file found"},
    });
  }
};

}  // namespace

auto NewFLocalTransport(const FLocalConfig& cfg)
    -> std::expected<
        std::unique_ptr<cli::transport::Transport>,
        cli::Error<cli::transport::TransportError>> {
  auto tx = std::make_unique<FLocalTransport>(cfg);
  return std::unique_ptr<cli::transport::Transport>(
      std::move(tx));
}

}  // namespace einheit::adapters::fw
