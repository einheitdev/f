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

#include <nlohmann/json.hpp>
#include <zmq.hpp>

#include "f/sysconfig/dnsmasq.h"
#include "f/sysconfig/model.h"
#include "f/sysconfig/networkd.h"
#include "f/sysconfig/parse.h"
#include "f/sysconfig/service_status.h"
#include "f/sysconfig/validate.h"

namespace fd_cmd {
enum : uint8_t {
  kGetCounters = 2,
  kGetStatus = 3,
  kReloadProg = 4,
  kStop = 5,
  kGetFirewall = 6,
  kGetRules = 7,
  kClearCounters = 8,
  kGetZones = 9,
  kGetNat = 10,
  kGetConntrack = 11,
};
}  // namespace fd_cmd

namespace einheit::adapters::fw {

namespace {

using json = nlohmann::json;
using json_t = nlohmann::json;
using Error_t = cli::Error<cli::transport::TransportError>;
namespace proto = cli::protocol;
namespace sc = ::f::sysconfig;

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

auto SendRawToFd(zmq::socket_t& sock, uint8_t cmd,
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

auto ReadFile(const std::string& path) -> std::string {
  std::ifstream f(path);
  if (!f) return "";
  return std::string(std::istreambuf_iterator<char>(f),
                     std::istreambuf_iterator<char>());
}

auto WriteFile(const std::string& path,
               const std::string& content) -> bool {
  auto dir = std::filesystem::path(path).parent_path();
  std::filesystem::create_directories(dir);
  std::ofstream f(path);
  if (!f) return false;
  f << content;
  return f.good();
}

auto ListFwFiles(const std::string& source_path)
    -> std::vector<std::string> {
  std::vector<std::string> files;
  // Single source file.
  if (std::filesystem::is_regular_file(source_path)) {
    files.push_back(source_path);
    return files;
  }
  // Directory of .fw files.
  if (std::filesystem::is_directory(source_path)) {
    for (const auto& e :
         std::filesystem::directory_iterator(
             source_path)) {
      if (e.path().extension() == ".fw") {
        files.push_back(e.path().string());
      }
    }
    std::sort(files.begin(), files.end());
  }
  return files;
}

auto SimpleDiff(const std::string& before,
                const std::string& after,
                const std::string& label) -> std::string {
  if (before == after) return "";
  std::string out;
  out += "--- " + label + " (running)\n";
  out += "+++ " + label + " (candidate)\n";
  std::istringstream ba(before), aa(after);
  std::string bl, al;
  bool have_b = true, have_a = true;
  while (have_b || have_a) {
    have_b = !!std::getline(ba, bl);
    have_a = !!std::getline(aa, al);
    if (!have_b && !have_a) break;
    std::string lb = have_b ? bl : "";
    std::string la = have_a ? al : "";
    if (lb != la) {
      if (!lb.empty()) out += "- " + lb + "\n";
      if (!la.empty()) out += "+ " + la + "\n";
    }
  }
  return out;
}

auto NewSessionId() -> std::string {
  static int counter = 0;
  auto now = std::chrono::system_clock::now();
  auto epoch = std::chrono::duration_cast<
      std::chrono::seconds>(now.time_since_epoch())
                   .count();
  return std::format("s-{}-{}", epoch, ++counter);
}

struct CandidateConfig {
  std::string session_id;
  std::map<std::string, std::string> snapshots;
  bool active = false;
};

class FLocalTransport final
    : public cli::transport::Transport {
 public:
  explicit FLocalTransport(FLocalConfig cfg)
      : cfg_(std::move(cfg)) {}

  auto Connect()
      -> std::expected<void, Error_t> override {
    try {
      zmq_ctx_ = std::make_unique<zmq::context_t>(1);
      zmq_sock_ = std::make_unique<zmq::socket_t>(
          *zmq_ctx_, zmq::socket_type::req);
      zmq_sock_->set(zmq::sockopt::linger, 0);
      zmq_sock_->set(zmq::sockopt::rcvtimeo, 3000);
      zmq_sock_->set(zmq::sockopt::sndtimeo, 3000);
      zmq_sock_->connect(cfg_.fd_socket);
      fd_connected_ = true;
    } catch (const zmq::error_t&) {
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
    if (req.command == "show_zones") {
      return FdQuery(req.id, fd_cmd::kGetZones);
    }
    if (req.command == "show_nat") {
      return FdQuery(req.id, fd_cmd::kGetNat);
    }
    if (req.command == "show_conntrack") {
      return FdQuery(req.id, fd_cmd::kGetConntrack);
    }
    if (req.command == "reload_firewall") {
      return HandleReloadFirewall(req);
    }
    if (req.command == "clear_counters") {
      return HandleClearCounters(req);
    }
    if (req.command == "configure") {
      return HandleConfigure(req);
    }
    if (req.command == "commit") {
      return HandleCommit(req);
    }
    if (req.command == "rollback") {
      return HandleRollback(req);
    }
    if (req.command == "set") {
      return HandleSet(req);
    }
    if (req.command == "delete") {
      return HandleDelete(req);
    }
    if (req.command == "show_config") {
      return HandleShowConfig(req);
    }
    if (req.command == "show_diff") {
      return HandleShowDiff(req);
    }
    if (req.command == "show_commits") {
      return HandleShowCommits(req);
    }
    if (req.command == "edit") {
      return HandleEdit(req);
    }
    if (req.command == "show_files") {
      return HandleShowFiles(req);
    }
    if (req.command == "new_file") {
      return HandleNewFile(req);
    }
    if (req.command == "rename_file") {
      return HandleRenameFile(req);
    }
    if (req.command == "delete_file") {
      return HandleDeleteFile(req);
    }
    if (req.command == "set_editor") {
      return HandleSetEditor(req);
    }
    if (req.command == "iface_set_address") {
      return HandleIfaceSetAddress(req);
    }
    if (req.command == "iface_del_address") {
      return HandleIfaceDelAddress(req);
    }
    if (req.command == "iface_set_mtu") {
      return HandleIfaceSetMtu(req);
    }
    if (req.command == "iface_set_state") {
      return HandleIfaceSetState(req);
    }
    if (req.command == "show_log") {
      return HandleShowLog(req);
    }
    if (req.command == "show_system") {
      return HandleShowSystem(req);
    }
    if (req.command == "show_services") {
      return HandleShowServices(req);
    }
    if (req.command == "check_system") {
      return HandleCheckSystem(req);
    }
    if (req.command == "apply_system") {
      return HandleApplySystem(req);
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
  std::unique_ptr<zmq::context_t> zmq_ctx_;
  std::unique_ptr<zmq::socket_t> zmq_sock_;
  bool fd_connected_ = false;
  CandidateConfig candidate_;

  auto RequireFd(const std::string& id)
      -> std::optional<proto::Response> {
    if (!fd_connected_) {
      return MakeErr(id, "no_daemon",
          "fd is not running",
          "Start fd: sudo systemctl start fd");
    }
    return std::nullopt;
  }

  auto FdQuery(const std::string& id, uint8_t cmd)
      -> proto::Response {
    if (auto err = RequireFd(id)) return *err;
    auto resp = SendRawToFd(*zmq_sock_, cmd);
    if (!resp) {
      return MakeErr(id, "fd_error", resp.error());
    }
    json j;
    try {
      j = json::parse(*resp);
    } catch (...) {
      j = {{"raw", *resp}};
    }
    if (j.contains("error")) {
      return MakeErr(id, "fd_error",
                     j["error"].get<std::string>());
    }
    return MakeOk(id, j);
  }

  auto HandleShowStatus(const proto::Request& req)
      -> proto::Response {
    auto resp = FdQuery(req.id, fd_cmd::kGetStatus);
    if (resp.status == proto::ResponseStatus::Error &&
        resp.error &&
        resp.error->code == "no_daemon") {
      return MakeOk(req.id, {
          {"daemon", "not connected"},
          {"pin_path", cfg_.pin_path},
      });
    }
    return resp;
  }

  auto HandleShowInterfaces(const proto::Request& req)
      -> proto::Response {
    return MakeOk(req.id, GatherInterfaces());
  }

  auto HandleShowFirewall(const proto::Request& req)
      -> proto::Response {
    return FdQuery(req.id, fd_cmd::kGetFirewall);
  }

  auto HandleShowFirewallRules(
      const proto::Request& req)
      -> proto::Response {
    return FdQuery(req.id, fd_cmd::kGetRules);
  }

  auto HandleShowCounters(const proto::Request& req)
      -> proto::Response {
    return FdQuery(req.id, fd_cmd::kGetCounters);
  }

  auto HandleReloadFirewall(const proto::Request& req)
      -> proto::Response {
    return FdQuery(req.id, fd_cmd::kReloadProg);
  }

  auto HandleClearCounters(const proto::Request& req)
      -> proto::Response {
    return FdQuery(req.id, fd_cmd::kClearCounters);
  }

  auto HandleConfigure(const proto::Request& req)
      -> proto::Response {
    if (candidate_.active) {
      return MakeErr(req.id, "already_configuring",
          "A configure session is already active",
          "commit or rollback first");
    }
    candidate_.session_id = NewSessionId();
    candidate_.active = true;
    candidate_.snapshots.clear();
    // Snapshot all managed files.
    for (const auto& path :
         ListFwFiles(cfg_.fw_source)) {
      candidate_.snapshots[path] = ReadFile(path);
    }
    // Session ID goes in data as raw bytes — the
    // framework extracts it with ExtractSessionIdFromData.
    auto sid = candidate_.session_id;
    return {
        .id = req.id,
        .status = proto::ResponseStatus::Ok,
        .data = {sid.begin(), sid.end()},
    };
  }

  auto HandleCommit(const proto::Request& req)
      -> proto::Response {
    if (!candidate_.active) {
      return MakeErr(req.id, "no_session",
          "No configure session active");
    }
    // Validate all .fw files with fwl check.
    for (const auto& path :
         ListFwFiles(cfg_.fw_source)) {
      auto [rc, out] = RunSubprocess(
          {cfg_.fwl_path, "check", path});
      if (rc != 0) {
        return MakeErr(req.id, "validation_failed",
            out.empty()
                ? std::format("fwl check failed: {}",
                              path)
                : out,
            "Fix errors, then commit again");
      }
    }
    // All valid — trigger reload if fd is running.
    json result = {{"status", "committed"}};
    if (fd_connected_) {
      auto resp = SendRawToFd(
          *zmq_sock_, fd_cmd::kReloadProg);
      result["reload"] = resp ? "triggered"
                              : "watcher will apply";
    } else {
      result["reload"] =
          "fd not running — applied on next start";
    }
    candidate_.active = false;
    candidate_.snapshots.clear();
    return MakeOk(req.id, result);
  }

  auto HandleRollback(const proto::Request& req)
      -> proto::Response {
    if (!candidate_.active) {
      return MakeErr(req.id, "no_session",
          "No configure session active");
    }
    int restored = 0;
    for (const auto& [path, content] :
         candidate_.snapshots) {
      WriteFile(path, content);
      restored++;
    }
    candidate_.active = false;
    candidate_.snapshots.clear();
    return MakeOk(req.id, {
        {"status", "rolled back"},
        {"files_restored", restored},
    });
  }

  auto HandleEdit(const proto::Request& req)
      -> proto::Response {
    if (!candidate_.active) {
      return MakeErr(req.id, "no_session",
          "Enter configure mode first");
    }
    std::string target;
    if (!req.args.empty()) {
      target = req.args[0];
      // Resolve relative to the source directory.
      if (!std::filesystem::path(target).is_absolute()) {
        auto dir = std::filesystem::path(cfg_.fw_source)
                       .parent_path();
        target = (dir / target).string();
      }
    } else {
      target = cfg_.fw_source;
    }
    // Create the file if it doesn't exist.
    if (!std::filesystem::exists(target)) {
      auto dir = std::filesystem::path(target)
                     .parent_path();
      std::filesystem::create_directories(dir);
      std::ofstream f(target);
      f << "# f firewall rules\n"
        << "# See: fwl --help\n\n"
        << "default allow\n";
      // Snapshot the new file too.
      candidate_.snapshots[target] = "";
    }
    // Snapshot if not already tracked.
    if (candidate_.snapshots.find(target) ==
        candidate_.snapshots.end()) {
      candidate_.snapshots[target] = ReadFile(target);
    }
    auto editor = ResolveEditor(cfg_);
    int rc = RunInteractive({editor, target});
    if (rc != 0) {
      return MakeErr(req.id, "editor_failed",
          std::format("{} exited with code {}",
                      editor, rc));
    }
    auto current = ReadFile(target);
    auto& snapshot = candidate_.snapshots[target];
    bool changed = (current != snapshot);
    return MakeOk(req.id, {
        {"file", target},
        {"changed", changed},
    });
  }

  auto ResolveFwPath(const std::string& name)
      -> std::string {
    if (std::filesystem::path(name).is_absolute()) {
      return name;
    }
    auto dir = std::filesystem::path(cfg_.fw_source)
                   .parent_path();
    return (dir / name).string();
  }

  auto FormatSize(uintmax_t bytes) -> std::string {
    if (bytes >= 1'000'000) {
      return std::format("{:.1f}M",
          static_cast<double>(bytes) / 1'000'000.0);
    }
    if (bytes >= 1'000) {
      return std::format("{:.1f}K",
          static_cast<double>(bytes) / 1'000.0);
    }
    return std::to_string(bytes);
  }

  auto HandleShowFiles(const proto::Request& req)
      -> proto::Response {
    json files = json::array();
    for (const auto& path :
         ListFwFiles(cfg_.fw_source)) {
      auto content = ReadFile(path);
      int lines = 0;
      for (char c : content) {
        if (c == '\n') lines++;
      }
      auto name =
          std::filesystem::path(path).filename()
              .string();
      uintmax_t sz = 0;
      try {
        sz = std::filesystem::file_size(path);
      } catch (...) {}
      files.push_back({
          {"name", name},
          {"path", path},
          {"size", FormatSize(sz)},
          {"lines", lines},
      });
    }
    return MakeOk(req.id, {{"files", files}});
  }

  auto HandleNewFile(const proto::Request& req)
      -> proto::Response {
    if (!candidate_.active) {
      return MakeErr(req.id, "no_session",
          "Enter configure mode first");
    }
    if (req.args.empty()) {
      return MakeErr(req.id, "missing_args",
          "Usage: new file <name.fw>");
    }
    auto name = req.args[0];
    if (name.find('/') != std::string::npos) {
      return MakeErr(req.id, "invalid_name",
          "Filename must not contain /");
    }
    if (!name.ends_with(".fw")) {
      name += ".fw";
    }
    auto path = ResolveFwPath(name);
    if (std::filesystem::exists(path)) {
      return MakeErr(req.id, "already_exists",
          std::format("{} already exists", name),
          "Use edit to modify it");
    }
    auto dir = std::filesystem::path(path)
                   .parent_path();
    std::filesystem::create_directories(dir);
    std::ofstream f(path);
    f << "# " << name << "\n\n"
      << "default allow\n";
    candidate_.snapshots[path] = "";
    return MakeOk(req.id, {
        {"file", name},
        {"path", path},
        {"changed", true},
    });
  }

  auto HandleRenameFile(const proto::Request& req)
      -> proto::Response {
    if (!candidate_.active) {
      return MakeErr(req.id, "no_session",
          "Enter configure mode first");
    }
    if (req.args.size() < 2) {
      return MakeErr(req.id, "missing_args",
          "Usage: rename file <from> <to>");
    }
    auto from = ResolveFwPath(req.args[0]);
    auto to_name = req.args[1];
    if (!to_name.ends_with(".fw")) {
      to_name += ".fw";
    }
    auto to = ResolveFwPath(to_name);
    if (!std::filesystem::exists(from)) {
      return MakeErr(req.id, "not_found",
          std::format("{} not found", req.args[0]));
    }
    if (std::filesystem::exists(to)) {
      return MakeErr(req.id, "already_exists",
          std::format("{} already exists", to_name));
    }
    // Snapshot the old file for rollback.
    if (candidate_.snapshots.find(from) ==
        candidate_.snapshots.end()) {
      candidate_.snapshots[from] = ReadFile(from);
    }
    std::filesystem::rename(from, to);
    candidate_.snapshots[to] = "";
    return MakeOk(req.id, {
        {"from", req.args[0]},
        {"to", to_name},
        {"changed", true},
    });
  }

  auto HandleDeleteFile(const proto::Request& req)
      -> proto::Response {
    if (!candidate_.active) {
      return MakeErr(req.id, "no_session",
          "Enter configure mode first");
    }
    if (req.args.empty()) {
      return MakeErr(req.id, "missing_args",
          "Usage: delete file <name>");
    }
    auto path = ResolveFwPath(req.args[0]);
    if (!std::filesystem::exists(path)) {
      return MakeErr(req.id, "not_found",
          std::format("{} not found", req.args[0]));
    }
    // Snapshot for rollback.
    if (candidate_.snapshots.find(path) ==
        candidate_.snapshots.end()) {
      candidate_.snapshots[path] = ReadFile(path);
    }
    std::filesystem::remove(path);
    return MakeOk(req.id, {
        {"file", req.args[0]},
        {"changed", true},
    });
  }

  auto HandleSet(const proto::Request& req)
      -> proto::Response {
    // Schema-based set — store in the candidate config
    // file (fd.yaml). Minimal: just acknowledge.
    if (req.args.size() < 2) {
      return MakeErr(req.id, "missing_args",
          "Usage: set <path> <value>");
    }
    return MakeOk(req.id, {
        {"path", req.args[0]},
        {"value", req.args[1]},
        {"status", "set"},
    });
  }

  auto HandleDelete(const proto::Request& req)
      -> proto::Response {
    if (req.args.empty()) {
      return MakeErr(req.id, "missing_args",
          "Usage: delete <path>");
    }
    return MakeOk(req.id, {
        {"path", req.args[0]},
        {"status", "deleted"},
    });
  }

  auto HandleShowConfig(const proto::Request& req)
      -> proto::Response {
    json files = json::array();
    for (const auto& path :
         ListFwFiles(cfg_.fw_source)) {
      files.push_back({
          {"path", path},
          {"content", ReadFile(path)},
      });
    }
    return MakeOk(req.id, {{"files", files}});
  }

  auto HandleShowDiff(const proto::Request& req)
      -> proto::Response {
    if (!candidate_.active) {
      return MakeOk(req.id, {{"diff", ""}});
    }
    std::string diff;
    for (const auto& [path, snapshot] :
         candidate_.snapshots) {
      auto current = ReadFile(path);
      diff += SimpleDiff(snapshot, current, path);
    }
    if (diff.empty()) diff = "no changes";
    return MakeOk(req.id, {{"diff", diff}});
  }

  auto HandleShowCommits(const proto::Request& req)
      -> proto::Response {
    return MakeOk(req.id, {
        {"commits", json::array()},
    });
  }

  auto IfaceExists(const std::string& name) -> bool {
    return std::filesystem::exists(
        std::format("/sys/class/net/{}", name));
  }

  // Path to the networkd unit this adapter manages for `iface`.
  auto NetworkdPath(const std::string& iface) -> std::string {
    return std::format(
        "/etc/systemd/network/10-f-{}.network", iface);
  }

  // Parsed view of the managed .network file. `extra` preserves any
  // [Network] keys the adapter does not itself manage (Gateway=, DNS=,
  // ...) so a hand-edited file is not clobbered on rewrite.
  struct IfaceNet {
    std::vector<std::string> addrs;
    std::string mtu;
    std::vector<std::string> extra;
  };

  // Read-modify basis: parse the managed .network file so add/remove
  // merges with what is already persisted, preserving unmanaged keys.
  auto ReadNetworkd(const std::string& iface) -> IfaceNet {
    IfaceNet n;
    std::ifstream f(NetworkdPath(iface));
    std::string line, section;
    while (std::getline(f, line)) {
      if (!line.empty() && line.front() == '[') {
        section = line;
        continue;
      }
      if (line.rfind("Address=", 0) == 0) {
        n.addrs.push_back(line.substr(8));
      } else if (line.rfind("MTUBytes=", 0) == 0) {
        n.mtu = line.substr(9);
      } else if (line.rfind("Name=", 0) == 0) {
        // regenerated from `iface`
      } else if (section == "[Network]" && !line.empty()) {
        n.extra.push_back(line);
      }
    }
    return n;
  }

  // Rewrite the managed .network file atomically (temp + rename) so a
  // crash mid-write cannot corrupt the unit. Returns false if the file
  // could not be written (e.g. missing privileges).
  auto WriteNetworkd(const std::string& iface, const IfaceNet& n)
      -> bool {
    std::string out;
    out += "[Match]\n";
    out += std::format("Name={}\n\n", iface);
    out += "[Network]\n";
    for (const auto& a : n.addrs) {
      out += std::format("Address={}\n", a);
    }
    for (const auto& e : n.extra) {
      out += e + "\n";
    }
    if (!n.mtu.empty()) {
      out += std::format("\n[Link]\nMTUBytes={}\n", n.mtu);
    }
    auto tmp = NetworkdPath(iface) + ".tmp";
    {
      std::ofstream f(tmp);
      if (!f) return false;
      f << out;
      if (!f.good()) return false;
    }
    std::error_code ec;
    std::filesystem::rename(tmp, NetworkdPath(iface), ec);
    if (ec) {
      std::filesystem::remove(tmp, ec);
      return false;
    }
    return true;
  }

  auto HandleIfaceSetAddress(const proto::Request& req)
      -> proto::Response {
    if (req.args.size() < 2) {
      return MakeErr(req.id, "missing_args",
          "Usage: set address <interface> <addr/prefix>");
    }
    const auto& iface = req.args[0];
    const auto& addr = req.args[1];
    if (!IfaceExists(iface)) {
      return MakeErr(req.id, "no_such_interface",
          std::format("interface {} not found", iface));
    }
    // Apply immediately; treat "exists" as success (idempotent).
    auto [rc, out] = RunSubprocess(
        {"ip", "addr", "add", addr, "dev", iface});
    bool applied = rc == 0 ||
                   out.find("File exists") != std::string::npos;
    // Persist: merge into the managed networkd file.
    auto net = ReadNetworkd(iface);
    if (std::find(net.addrs.begin(), net.addrs.end(), addr) ==
        net.addrs.end()) {
      net.addrs.push_back(addr);
    }
    bool persisted = WriteNetworkd(iface, net);
    json j = {
        {"interface", iface}, {"action", "set address"},
        {"value", addr}, {"applied", applied},
        {"persisted", persisted},
        {"config", NetworkdPath(iface)},
    };
    if (!applied && !out.empty()) j["warning"] = out;
    if (!persisted) {
      j["warning"] = "could not write networkd config "
                     "(need root?)";
    }
    return MakeOk(req.id, j);
  }

  auto HandleIfaceDelAddress(const proto::Request& req)
      -> proto::Response {
    if (req.args.size() < 2) {
      return MakeErr(req.id, "missing_args",
          "Usage: no address <interface> <addr/prefix>");
    }
    const auto& iface = req.args[0];
    const auto& addr = req.args[1];
    auto [rc, out] = RunSubprocess(
        {"ip", "addr", "del", addr, "dev", iface});
    bool applied = rc == 0 ||
                   out.find("Cannot assign") != std::string::npos;
    auto net = ReadNetworkd(iface);
    net.addrs.erase(
        std::remove(net.addrs.begin(), net.addrs.end(), addr),
        net.addrs.end());
    bool persisted = WriteNetworkd(iface, net);
    json j = {
        {"interface", iface}, {"action", "remove address"},
        {"value", addr}, {"applied", applied},
        {"persisted", persisted},
        {"config", NetworkdPath(iface)},
    };
    if (!applied && !out.empty()) j["warning"] = out;
    return MakeOk(req.id, j);
  }

  auto HandleIfaceSetMtu(const proto::Request& req)
      -> proto::Response {
    if (req.args.size() < 2) {
      return MakeErr(req.id, "missing_args",
          "Usage: set mtu <interface> <bytes>");
    }
    const auto& iface = req.args[0];
    const auto& mtu = req.args[1];
    if (!IfaceExists(iface)) {
      return MakeErr(req.id, "no_such_interface",
          std::format("interface {} not found", iface));
    }
    auto [rc, out] = RunSubprocess(
        {"ip", "link", "set", "dev", iface, "mtu", mtu});
    auto net = ReadNetworkd(iface);
    net.mtu = mtu;
    bool persisted = WriteNetworkd(iface, net);
    json j = {
        {"interface", iface}, {"action", "set mtu"},
        {"value", mtu}, {"applied", rc == 0},
        {"persisted", persisted},
        {"config", NetworkdPath(iface)},
    };
    if (rc != 0 && !out.empty()) j["warning"] = out;
    return MakeOk(req.id, j);
  }

  auto HandleIfaceSetState(const proto::Request& req)
      -> proto::Response {
    if (req.args.size() < 2) {
      return MakeErr(req.id, "missing_args",
          "Usage: set link <interface> <up|down>");
    }
    const auto& iface = req.args[0];
    const auto& state = req.args[1];
    if (state != "up" && state != "down") {
      return MakeErr(req.id, "invalid_state",
          "state must be 'up' or 'down'");
    }
    if (!IfaceExists(iface)) {
      return MakeErr(req.id, "no_such_interface",
          std::format("interface {} not found", iface));
    }
    auto [rc, out] = RunSubprocess(
        {"ip", "link", "set", "dev", iface, state});
    json j = {
        {"interface", iface}, {"action", "set link"},
        {"value", state}, {"applied", rc == 0},
        {"persisted", false},
        {"warning", "admin state is applied but not "
                    "persisted across reboot"},
    };
    if (rc != 0 && !out.empty()) j["warning"] = out;
    return MakeOk(req.id, j);
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

  // -- system configuration model ------------------------------------
  //
  // The appliance's network configuration:
  //     physical port -> interface -> zone -> services bind here
  // The CLI reads and applies the same model f-sysconf does; there is
  // one source of truth and one set of diagnostics.

  static auto DiagsToJson(
      const std::vector<sc::Diagnostic>& diags) -> json {
    json out = json::array();
    for (const auto& d : diags) {
      out.push_back({
          {"code", d.code},
          {"severity", d.severity == sc::Severity::kError
                           ? "error"
                           : "warning"},
          {"message", d.message},
          {"line", d.span.line},
          {"column", d.span.column},
          {"hint", d.hint},
          {"text", d.Format()},
      });
    }
    return out;
  }

  auto SystemConfigPath() const -> std::string {
    return cfg_.system_config;
  }

  /// Load the model. On failure, hands back the response the caller
  /// should return, so every entry point reports a bad config the
  /// same way.
  auto LoadSystem(const proto::Request& req,
                  sc::SystemConfig* out,
                  std::optional<proto::Response>* fail)
      -> bool {
    auto parsed = sc::ParseSystemConfigFile(SystemConfigPath());
    if (!parsed) {
      auto resp = MakeOk(req.id, {
          {"config", SystemConfigPath()},
          {"ok", false},
          {"diagnostics",
           DiagsToJson(parsed.error().diagnostics)},
      });
      *fail = resp;
      return false;
    }
    *out = *parsed;
    return true;
  }

  auto HandleShowSystem(const proto::Request& req)
      -> proto::Response {
    sc::SystemConfig cfg;
    std::optional<proto::Response> fail;
    if (!LoadSystem(req, &cfg, &fail)) return *fail;

    auto plan = sc::PlanDnsmasq(cfg);
    json zones = json::array();
    for (const auto& z : cfg.zones) {
      zones.push_back({
          {"zone", z.name},
          {"ipv6", sc::Ipv6StanceName(z.ipv6)},
          {"interfaces", cfg.InterfaceNamesInZone(z.name)},
          {"dhcp", cfg.ZoneServesDhcp(z.name)},
          {"services", cfg.ZoneHasService(z.name)},
      });
    }
    json ifaces = json::array();
    for (const auto& i : cfg.interfaces) {
      ifaces.push_back({
          {"name", i.name},
          {"match_kind",
           i.match.kind == sc::MatchKind::kMac ? "mac" : "path"},
          {"match", i.match.value},
          {"mode", sc::AddressModeName(i.mode)},
          {"address", i.address},
          {"gateway", i.gateway},
          {"zone", i.zone},
          {"present", i.name.empty()
                          ? false
                          : IfaceExists(i.name)},
      });
    }
    auto result = sc::Validate(cfg);
    return MakeOk(req.id, {
        {"config", SystemConfigPath()},
        {"ok", !result.HasErrors()},
        {"zones", zones},
        {"interfaces", ifaces},
        {"listen", plan.allowed_interfaces},
        {"excluded", plan.excluded_interfaces},
        {"dhcp_on", plan.dhcp_interfaces},
        {"diagnostics", DiagsToJson(result.diagnostics)},
    });
  }

  auto HandleShowServices(const proto::Request& req)
      -> proto::Response {
    sc::SystemConfig cfg;
    std::optional<proto::Response> fail;
    if (!LoadSystem(req, &cfg, &fail)) return *fail;

    json services = json::array();
    for (const auto& s : sc::QueryServices(cfg)) {
      services.push_back({
          {"name", s.name},
          {"unit", s.unit},
          {"state", sc::ServiceStateName(s.state)},
          {"expected", s.expected},
          {"healthy", s.state == sc::ServiceState::kRunning ||
                          s.state ==
                              sc::ServiceState::kNotConfigured ||
                          s.state ==
                              sc::ServiceState::kActivating},
          {"zones", s.zones},
          {"interfaces", s.interfaces},
          {"detail", s.detail},
      });
    }
    auto drift = sc::CheckDnsmasqDrift(cfg, cfg_.dnsmasq_conf);
    return MakeOk(req.id, {
        {"services", services},
        {"artifact", cfg_.dnsmasq_conf},
        {"drift", sc::DriftKindName(drift)},
    });
  }

  auto HandleCheckSystem(const proto::Request& req)
      -> proto::Response {
    sc::SystemConfig cfg;
    std::optional<proto::Response> fail;
    if (!LoadSystem(req, &cfg, &fail)) return *fail;
    auto result = sc::Validate(cfg);
    return MakeOk(req.id, {
        {"config", SystemConfigPath()},
        {"ok", !result.HasErrors()},
        {"diagnostics", DiagsToJson(result.diagnostics)},
    });
  }

  auto HandleApplySystem(const proto::Request& req)
      -> proto::Response {
    sc::SystemConfig cfg;
    std::optional<proto::Response> fail;
    if (!LoadSystem(req, &cfg, &fail)) return *fail;

    auto result = sc::Validate(cfg);
    if (result.HasErrors()) {
      return MakeOk(req.id, {
          {"config", SystemConfigPath()},
          {"ok", false},
          {"applied", false},
          {"diagnostics", DiagsToJson(result.diagnostics)},
      });
    }

    bool force = !req.args.empty() && req.args[0] == "force";
    sc::NetworkdOptions net_opts;
    net_opts.refuse_on_drift = !force;
    auto net = sc::ApplyNetworkd(cfg, net_opts);
    if (!net) {
      return MakeErr(req.id, "drift", net.error(),
                     "re-run with `apply system force` to discard "
                     "the edit");
    }

    json written = json::array();
    for (const auto& p : net->changed) written.push_back(p);

    auto plan = sc::PlanDnsmasq(cfg);
    if (!plan.needed) {
      return MakeOk(req.id, {
          {"config", SystemConfigPath()},
          {"ok", true},
          {"applied", true},
          {"written", written},
          {"dhcp_on", json::array()},
          {"note", "no service is bound to any zone; dnsmasq is "
                   "not needed"},
          {"diagnostics", DiagsToJson(result.diagnostics)},
      });
    }

    sc::DnsmasqOptions dm_opts;
    dm_opts.conf_path = cfg_.dnsmasq_conf;
    dm_opts.refuse_on_drift = !force;
    auto dm = sc::ApplyDnsmasq(cfg, dm_opts);
    if (!dm) {
      const char* code =
          dm.error().code == sc::BackendError::kDrift ? "drift"
          : dm.error().code == sc::BackendError::kToolMissing
              ? "tool_missing"
              : "rejected";
      return MakeErr(req.id, code, dm.error().message);
    }
    if (dm->changed) written.push_back(dm->conf_path);

    return MakeOk(req.id, {
        {"config", SystemConfigPath()},
        {"ok", true},
        {"applied", true},
        {"written", written},
        {"dhcp_on", dm->plan.dhcp_interfaces},
        {"diagnostics", DiagsToJson(result.diagnostics)},
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
