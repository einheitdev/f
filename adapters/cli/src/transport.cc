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

#include "einheit/cli/transport/zmq_local.h"
#include "f/confd/system_backend.h"
#include "f/sysconfig/artifact.h"
#include "f/sysconfig/dnsmasq.h"
#include "f/sysconfig/edit.h"
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
    if (confd_) {
      confd_->Disconnect();
      confd_.reset();
    }
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
    if (req.command == "apply_system_confirmed") {
      return HandleApplySystemConfirmed(req);
    }
    if (req.command == "confirm_system") {
      return HandleConfirmSystem(req);
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
  // Client onto f-confd, the process that owns the commit-confirmed
  // revert timer. Created on first use; a CLI on a box without it must
  // still be able to do everything else.
  std::unique_ptr<cli::transport::Transport> confd_;
  bool confd_probed_ = false;
  bool confd_up_ = false;

  /// Connect to f-confd and prove it answers. The connection alone
  /// proves nothing — a ZMQ connect to a dead ipc:// path succeeds.
  auto ConfdAvailable() -> bool {
    if (confd_probed_) return confd_up_;
    confd_probed_ = true;
    cli::transport::ZmqLocalConfig tcfg;
    tcfg.control_endpoint = cfg_.confd_socket;
    auto tx = cli::transport::NewZmqLocalTransport(tcfg);
    if (!tx) return false;
    if (!(*tx)->Connect()) return false;
    confd_ = std::move(*tx);
    proto::Request probe;
    probe.id = "probe";
    probe.command = "show_status";
    auto resp = confd_->SendRequest(
        probe, std::chrono::milliseconds(500));
    confd_up_ = resp.has_value() &&
                resp->status == proto::ResponseStatus::Ok;
    if (!confd_up_) {
      confd_->Disconnect();
      confd_.reset();
    }
    return confd_up_;
  }

  /// One request to f-confd, with the caller's identity carried over.
  auto ConfdRequest(const proto::Request& from,
                    const std::string& command,
                    std::vector<std::string> args = {},
                    std::optional<std::string> session = {},
                    std::chrono::milliseconds timeout =
                        std::chrono::seconds(10))
      -> std::expected<proto::Response, std::string> {
    if (!confd_) return std::unexpected("f-confd is not running");
    proto::Request req;
    req.id = from.id;
    req.user = from.user;
    req.role = from.role;
    req.command = command;
    req.args = std::move(args);
    req.session_id = std::move(session);
    auto resp = confd_->SendRequest(req, timeout);
    if (!resp) return std::unexpected(resp.error().message);
    return *resp;
  }

  auto RequireFd(const std::string& id)
      -> std::optional<proto::Response> {
    if (!fd_connected_) {
      return MakeErr(id, "no_daemon",
          "fd is not running",
          "Start fd: sudo systemctl start fd");
    }
    return std::nullopt;
  }

  /// What fd said. A reply arriving is not the same thing as fd having
  /// done the work: every command can answer with an `error` payload,
  /// so nothing may treat "we got bytes back" as success.
  struct FdReply {
    /// True only when fd answered without an `error` field.
    bool ok = false;
    /// fd's own words for why not — verbatim, so the operator sees the
    /// daemon's reason and not our paraphrase of it.
    std::string error;
    /// Parsed reply body on success.
    json body = json::object();
  };

  /// Send `cmd` (with optional payload) and classify the answer.
  /// The single place that decides whether fd succeeded.
  auto AskFd(uint8_t cmd, const std::string& payload = "")
      -> FdReply {
    FdReply out;
    if (!fd_connected_ || !zmq_sock_) {
      out.error = "fd is not running";
      return out;
    }
    auto resp = SendRawToFd(*zmq_sock_, cmd, payload);
    if (!resp) {
      out.error = std::format("fd did not answer: {}",
                              resp.error());
      return out;
    }
    json j;
    try {
      j = json::parse(*resp);
    } catch (...) {
      out.error = std::format(
          "fd sent a reply that is not JSON: {}", *resp);
      return out;
    }
    if (j.is_object() && j.contains("error")) {
      // The field is fd's, so do not assume it is a string.
      out.error = j["error"].is_string()
                      ? j["error"].get<std::string>()
                      : j["error"].dump();
      return out;
    }
    out.ok = true;
    out.body = std::move(j);
    return out;
  }

  auto FdQuery(const std::string& id, uint8_t cmd)
      -> proto::Response {
    if (auto err = RequireFd(id)) return *err;
    auto reply = AskFd(cmd);
    if (!reply.ok) {
      return MakeErr(id, "fd_error", reply.error);
    }
    return MakeOk(id, reply.body);
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
    // The sources are valid. They are not yet *live*: fd has to
    // recompile and swap them in, and that is a second outcome with
    // its own way of failing. There is exactly one mechanism that
    // applies a change — the kReloadProg command below. fd starts no
    // file watcher (nothing calls WatcherStart), and a cold start
    // loads the last compiled bundle rather than the source, so a
    // commit fd did not apply is not applied at all.
    auto reload = AskFd(fd_cmd::kReloadProg);
    if (!reload.ok) {
      // Leave the session open: the snapshots are the only way back to
      // the previous policy, and the operator needs `rollback` to
      // still work after a commit that did not take.
      return MakeErr(req.id, "not_applied",
          std::format(
              "saved to {}, but the running policy is UNCHANGED: {}",
              cfg_.fw_source, reload.error),
          "fix the cause and run `reload firewall`, or `rollback` to "
          "restore the previous configuration");
    }

    json result = {
        {"status", "committed"},
        {"applied", true},
        // Name the mechanism, not the intent: fd completed the swap
        // before it answered.
        {"mechanism", "fd hot-reload"},
        {"reload", "applied by fd"},
    };
    // fd's own account of what it installed.
    for (const char* field :
         {"version", "rules_installed", "program_updated"}) {
      if (reload.body.contains(field)) {
        result[field] = reload.body[field];
      }
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

  // -- addressing ------------------------------------------------------
  //
  // `set address` is a statement about the appliance's network, which
  // is what the system configuration is. It therefore edits *that* —
  // the one document — and lets the model generate the networkd unit,
  // rather than writing the same unit itself from a second place. Two
  // writers for one file is how an operator ends up with a running
  // address that no configuration explains.

  /// Put `document` in place as the system configuration and make it
  /// live, through f-confd when it is running. Returns the fields to
  /// merge into the reply.
  auto InstallSystemDocument(const proto::Request& req,
                             const std::string& document,
                             json* out)
      -> std::optional<proto::Response> {
    auto parsed = sc::ParseSystemConfigString(document);
    if (!parsed) {
      return MakeErr(req.id, "invalid_config",
          "the edited system configuration does not parse");
    }
    auto validation = sc::Validate(*parsed);
    if (validation.HasErrors()) {
      auto resp = MakeOk(req.id, {
          {"config", SystemConfigPath()},
          {"ok", false},
          {"applied", false},
          {"diagnostics", DiagsToJson(validation.diagnostics)},
      });
      return resp;
    }
    auto installed =
        sc::InstallArtifact(SystemConfigPath(), document);
    if (!installed) {
      return MakeErr(req.id, "write_failed", installed.error(),
                     "root is needed to change the system "
                     "configuration");
    }

    if (ConfdAvailable()) {
      auto sid = StageSystemConfig(req, false);
      if (!sid) return sid.error();
      auto committed = ConfdRequest(req, "commit", {}, *sid,
                                    std::chrono::seconds(30));
      if (!committed) {
        return MakeErr(req.id, "confd_error", committed.error());
      }
      if (committed->status != proto::ResponseStatus::Ok) {
        return MakeErr(req.id, "apply_failed",
            committed->error ? committed->error->message
                             : "f-confd refused the change");
      }
      auto body = ParseKv(std::string(committed->data.begin(),
                                      committed->data.end()));
      (*out)["via"] = "f-confd";
      (*out)["commit_id"] = body.value("commit_id", "");
      (*out)["live"] = true;
      return std::nullopt;
    }

    sc::NetworkdOptions net_opts;
    net_opts.dir = cfg_.networkd_dir;
    auto net = sc::ApplyNetworkd(*parsed, net_opts);
    if (!net) {
      return MakeErr(req.id, "drift", net.error(),
                     "fold the hand edit into the system "
                     "configuration, or `apply system force`");
    }
    (*out)["via"] = "direct";
    json written = json::array();
    for (const auto& p : net->changed) written.push_back(p);
    (*out)["written"] = written;
    return std::nullopt;
  }

  auto HandleIfaceSetAddress(const proto::Request& req)
      -> proto::Response {
    if (req.args.size() < 2) {
      return MakeErr(req.id, "missing_args",
          "Usage: set address <interface> <addr/prefix|dhcp>");
    }
    const auto& iface = req.args[0];
    const auto& addr = req.args[1];
    if (!IfaceExists(iface)) {
      return MakeErr(req.id, "no_such_interface",
          std::format("interface {} not found", iface));
    }
    sc::InterfaceSeed seed;
    seed.mac = ReadSysfs(iface, "address");
    auto edited = sc::SetInterfaceAddress(
        ReadFile(SystemConfigPath()), iface, addr, seed);
    if (!edited) {
      return MakeErr(req.id, "invalid_edit", edited.error());
    }

    json j = {
        {"interface", iface},
        {"action", "set address"},
        {"value", addr},
        {"config", SystemConfigPath()},
        {"live", false},
    };
    if (auto fail = InstallSystemDocument(req, *edited, &j)) {
      return *fail;
    }
    // Without f-confd nothing reloads networkd, so put the address on
    // the link directly — otherwise the operator is told about a
    // change the box is not carrying yet.
    if (j.value("via", "") == "direct" && addr != "dhcp" &&
        addr != "none") {
      auto [rc, out] = RunSubprocess(
          {"ip", "addr", "add", addr, "dev", iface});
      j["live"] = rc == 0 ||
                  out.find("File exists") != std::string::npos;
      if (!j["live"].get<bool>() && !out.empty()) {
        j["warning"] = out;
      }
    }
    j["applied"] = true;
    j["persisted"] = true;
    return MakeOk(req.id, j);
  }

  auto HandleIfaceDelAddress(const proto::Request& req)
      -> proto::Response {
    if (req.args.empty()) {
      return MakeErr(req.id, "missing_args",
          "Usage: no address <interface> [addr/prefix]");
    }
    const auto& iface = req.args[0];
    auto edited =
        sc::ClearInterfaceAddress(ReadFile(SystemConfigPath()),
                                  iface);
    if (!edited) {
      return MakeErr(req.id, "invalid_edit", edited.error());
    }

    json j = {
        {"interface", iface},
        {"action", "remove address"},
        {"value", req.args.size() > 1 ? req.args[1] : "all"},
        {"config", SystemConfigPath()},
        {"live", false},
    };
    if (auto fail = InstallSystemDocument(req, *edited, &j)) {
      return *fail;
    }
    if (j.value("via", "") == "direct" && req.args.size() > 1) {
      auto [rc, out] = RunSubprocess(
          {"ip", "addr", "del", req.args[1], "dev", iface});
      j["live"] = rc == 0 ||
                  out.find("Cannot assign") != std::string::npos;
      if (!j["live"].get<bool>() && !out.empty()) {
        j["warning"] = out;
      }
    }
    j["applied"] = true;
    j["persisted"] = true;
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
    // MTU is not (yet) part of the system configuration, and the
    // generated networkd unit belongs to the model — so this changes
    // the live link and says plainly that it will not survive a
    // reboot, rather than writing a rival copy of the model's file.
    json j = {
        {"interface", iface}, {"action", "set mtu"},
        {"value", mtu}, {"applied", rc == 0},
        {"persisted", false},
        {"warning", "applied to the live link only — the system "
                    "configuration has no MTU setting, so this does "
                    "not survive a reboot"},
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
        // An operator who reconnects after a confirmed apply must be
        // told the clock is running without having to know to ask.
        {"confirm", ConfirmState()},
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

  // -- applying the system configuration ------------------------------
  //
  // Two routes, and the operator is always told which one ran:
  //
  //  - through f-confd, which records the revision and — for a
  //    confirmed apply — counts down the revert in a process that
  //    survives the session. This is the one that protects against
  //    locking yourself out of the box you are reconfiguring.
  //  - directly, when f-confd is not running. Same artifacts, no
  //    revision history, no revert timer, and nothing is reloaded.

  /// Parse confd's `key=value ...` reply body.
  static auto ParseKv(const std::string& body) -> json {
    json out = json::object();
    std::istringstream ss(body);
    std::string tok;
    while (ss >> tok) {
      auto eq = tok.find('=');
      if (eq == std::string::npos) continue;
      out[tok.substr(0, eq)] = tok.substr(eq + 1);
    }
    return out;
  }

  /// Open a candidate on f-confd holding the system configuration
  /// currently on disk. Returns the session id.
  auto StageSystemConfig(const proto::Request& req, bool force)
      -> std::expected<std::string, proto::Response> {
    auto text = ReadFile(SystemConfigPath());
    if (text.empty()) {
      return std::unexpected(MakeErr(req.id, "no_config",
          std::format("{} is empty or unreadable",
                      SystemConfigPath())));
    }
    auto opened = ConfdRequest(req, "configure");
    if (!opened) {
      return std::unexpected(
          MakeErr(req.id, "confd_error", opened.error()));
    }
    if (opened->status != proto::ResponseStatus::Ok) {
      return std::unexpected(MakeErr(req.id, "confd_error",
          opened->error ? opened->error->message
                        : "f-confd refused to open a candidate"));
    }
    std::string sid(opened->data.begin(), opened->data.end());
    // f-confd resolves the digest against the same file; it refuses if
    // the two do not match, so a config edited between here and there
    // is never applied unseen.
    auto set = ConfdRequest(req, "set",
        {::f::confd::kConfigKey, sc::BodyDigest(text)}, sid);
    if (!set || set->status != proto::ResponseStatus::Ok) {
      return std::unexpected(MakeErr(req.id, "confd_error",
          set ? (set->error ? set->error->message : "set refused")
              : set.error()));
    }
    auto forced = ConfdRequest(req, "set",
        {::f::confd::kForceKey, force ? "true" : "false"}, sid);
    if (!forced || forced->status != proto::ResponseStatus::Ok) {
      return std::unexpected(MakeErr(req.id, "confd_error",
          forced ? "set force refused" : forced.error()));
    }
    return sid;
  }

  auto HandleApplySystemConfirmed(const proto::Request& req)
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
    if (req.args.empty()) {
      return MakeErr(req.id, "missing_args",
          "usage: apply system confirmed <minutes> [force]");
    }
    if (!ConfdAvailable()) {
      return MakeErr(req.id, "no_confd",
          "the revert timer lives in f-confd, which is not "
          "running — a confirmed apply would have nothing to "
          "undo it",
          "start it (systemctl start f-confd), or use `apply "
          "system` and accept that a change which severs your "
          "access will not be rolled back");
    }
    bool force = req.args.size() > 1 && req.args[1] == "force";
    auto sid = StageSystemConfig(req, force);
    if (!sid) return sid.error();

    auto committed = ConfdRequest(req, "commit_confirmed",
                                  {req.args[0]}, *sid,
                                  std::chrono::seconds(30));
    if (!committed) {
      return MakeErr(req.id, "confd_error", committed.error());
    }
    if (committed->status != proto::ResponseStatus::Ok) {
      return MakeErr(req.id, "apply_failed",
          committed->error ? committed->error->message
                           : "f-confd refused the apply",
          "the running configuration is unchanged");
    }
    auto body = ParseKv(
        std::string(committed->data.begin(),
                    committed->data.end()));
    body["config"] = SystemConfigPath();
    body["ok"] = true;
    body["applied"] = true;
    body["via"] = "f-confd";
    body["confirm_required"] = true;
    body["diagnostics"] = DiagsToJson(result.diagnostics);
    return MakeOk(req.id, body);
  }

  auto HandleConfirmSystem(const proto::Request& req)
      -> proto::Response {
    if (!ConfdAvailable()) {
      return MakeErr(req.id, "no_confd",
          "f-confd is not running, so no confirm window is open");
    }
    auto resp = ConfdRequest(req, "confirm");
    if (!resp) {
      return MakeErr(req.id, "confd_error", resp.error());
    }
    if (resp->status != proto::ResponseStatus::Ok) {
      return MakeErr(req.id, "not_pending",
          resp->error ? resp->error->message
                      : "no commit-confirm is pending");
    }
    return MakeOk(req.id, {
        {"status", "confirmed"},
        {"detail", std::string(resp->data.begin(),
                               resp->data.end())},
    });
  }

  /// The open confirm window, if f-confd reports one. Folded into
  /// `show system` so a reconnecting operator sees the countdown
  /// without knowing to ask.
  auto ConfirmState() -> json {
    json out = {{"pending", false}};
    if (!ConfdAvailable()) {
      out["confd"] = "not running";
      return out;
    }
    out["confd"] = "running";
    proto::Request probe;
    probe.id = "status";
    probe.command = "show_status";
    auto resp = ConfdRequest(probe, "show_status", {}, {},
                             std::chrono::seconds(2));
    if (!resp || resp->status != proto::ResponseStatus::Ok) {
      return out;
    }
    std::string body(resp->data.begin(), resp->data.end());
    std::istringstream ss(body);
    std::string line;
    while (std::getline(ss, line)) {
      auto eq = line.find('=');
      if (eq == std::string::npos) continue;
      auto key = line.substr(0, eq);
      auto val = line.substr(eq + 1);
      if (key == "confirm_pending") {
        out["pending"] = val == "yes";
      } else if (key == "confirm_seconds_remaining") {
        out["seconds_remaining"] = val;
      } else if (key == "confirm_commit") {
        out["commit"] = val;
      }
    }
    return out;
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

    // Prefer f-confd: one writer, a recorded revision, and a box that
    // can be rolled back to a named configuration afterwards.
    if (ConfdAvailable()) {
      auto sid = StageSystemConfig(req, force);
      if (!sid) return sid.error();
      auto committed = ConfdRequest(req, "commit", {}, *sid,
                                    std::chrono::seconds(30));
      if (!committed) {
        return MakeErr(req.id, "confd_error", committed.error());
      }
      if (committed->status != proto::ResponseStatus::Ok) {
        return MakeErr(req.id, "apply_failed",
            committed->error ? committed->error->message
                             : "f-confd refused the apply",
            "the running configuration is unchanged");
      }
      auto body = ParseKv(std::string(committed->data.begin(),
                                      committed->data.end()));
      body["config"] = SystemConfigPath();
      body["ok"] = true;
      body["applied"] = true;
      body["via"] = "f-confd";
      body["note"] =
          "applied without a confirm window — use `apply system "
          "confirmed <minutes>` when the change could cut your "
          "own access";
      body["diagnostics"] = DiagsToJson(result.diagnostics);
      return MakeOk(req.id, body);
    }

    sc::NetworkdOptions net_opts;
    net_opts.dir = cfg_.networkd_dir;
    net_opts.refuse_on_drift = !force;
    auto net = sc::ApplyNetworkd(cfg, net_opts);
    if (!net) {
      return MakeErr(req.id, "drift", net.error(),
                     "re-run with `apply system force` to discard "
                     "the edit");
    }

    json written = json::array();
    for (const auto& p : net->changed) written.push_back(p);

    // Said on every direct apply, because it is the difference
    // between "the files are right" and "the box is running them".
    const std::string kDirectNote =
        "f-confd is not running: no revision was recorded, no "
        "revert timer is armed, and nothing was reloaded — run "
        "`networkctl reload` to adopt the new units";

    auto plan = sc::PlanDnsmasq(cfg);
    if (!plan.needed) {
      return MakeOk(req.id, {
          {"config", SystemConfigPath()},
          {"ok", true},
          {"applied", true},
          {"via", "direct"},
          {"activated", false},
          {"written", written},
          {"dhcp_on", json::array()},
          {"note", "no service is bound to any zone; dnsmasq is "
                   "not needed. " + kDirectNote},
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
        {"via", "direct"},
        {"activated", false},
        {"written", written},
        {"dhcp_on", dm->plan.dhcp_interfaces},
        {"note", kDirectNote},
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
