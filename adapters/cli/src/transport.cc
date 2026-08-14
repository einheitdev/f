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
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <format>
#include <fstream>
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

#include <nlohmann/json.hpp>
#include <zmq.hpp>

#include "einheit/cli/transport/zmq_local.h"
#include "f/confd/system_backend.h"
#include "f/lease/journal.h"
#include "f/lease/lease.h"
#include "f/lease/view.h"
#include "f/sysconfig/artifact.h"
#include "f/sysconfig/chrony.h"
#include "f/sysconfig/dnsmasq.h"
#include "f/sysconfig/ipv6.h"
#include "f/sysconfig/edit.h"
#include "f/sysconfig/model.h"
#include "f/sysconfig/net.h"
#include "f/sysconfig/networkd.h"
#include "f/sysconfig/observe.h"
#include "f/sysconfig/parse.h"
#include "f/sysconfig/service_status.h"
#include "f/sysconfig/storage.h"
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
namespace lease = ::f::lease;

/// Unix seconds. The lease file and the journal are both stamped in
/// wall-clock time, because a lease expiry is a wall-clock fact.
auto NowSeconds() -> std::int64_t {
  return std::chrono::duration_cast<std::chrono::seconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

/// The daemon stamps conntrack with bpf_ktime_get_ns(), which is
/// CLOCK_MONOTONIC — so an idle time is computed against the same
/// clock, not against the wall.
auto MonotonicNs() -> std::uint64_t {
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          std::chrono::steady_clock::now().time_since_epoch())
          .count());
}

/// Render a device report as the wire body `show leases` renders.
///
/// Note what travels next to the list: `leases` and `journal` carry
/// *why* the list looks the way it does. The renderer is not allowed
/// to infer that from the list being empty, so it is sent whether or
/// not anything went wrong.
auto DeviceReportToJson(const lease::DeviceReport& r,
                        std::int64_t now) -> json {
  json devices = json::array();
  for (const auto& d : r.devices) {
    devices.push_back({
        {"mac", d.mac},
        {"address", d.address},
        {"hostname", d.hostname},
        {"zone", d.zone},
        {"first_seen", d.first_seen},
        {"first_seen_age", now - d.first_seen},
        {"first_seen_exact",
         d.precision == lease::FirstSeenPrecision::kObserved},
        {"last_seen", d.last_seen},
        {"last_seen_age", now - d.last_seen},
        {"last_arrival", d.last_arrival},
        {"expiry", d.expiry},
        {"expires_in", d.expiry > 0 ? d.expiry - now : 0},
        {"active", d.active},
        {"new", d.IsNew(now, lease::kNewWindowSeconds)},
        {"reserved", d.reserved},
        {"reserved_address", d.reserved_address},
        {"address_changes", d.address_changes},
    });
  }
  return {
      {"devices", devices},
      {"active", r.ActiveCount()},
      {"leases", lease::LeaseAvailabilityName(r.leases)},
      {"journal", lease::JournalAvailabilityName(r.journal)},
      {"detail", r.detail},
      {"lease_path", r.lease_path},
      {"journal_path", r.journal_path},
      {"unparsable", r.unparsable},
      {"ipv6_skipped", r.ipv6_skipped},
      {"arrived", r.changes.arrived},
      {"departed", r.changes.departed},
      {"readdressed", r.changes.readdressed},
      {"now", now},
  };
}

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

  /// A joinable poller thread at destruction would call terminate, so
  /// the watch is always stopped here as well as on Disconnect.
  ~FLocalTransport() override { StopWatch(); }

  auto Connect()
      -> std::expected<void, Error_t> override {
    // Connecting to a dead ipc:// path succeeds, so this proves
    // nothing about fd being up; every command finds that out for
    // itself and says so.
    (void)OpenFdSocket();
    return {};
  }

  auto Disconnect() -> void override {
    StopWatch();
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
    if (req.command == "show_leases") {
      return HandleShowLeases(req);
    }
    if (req.command == "show_device") {
      return HandleShowDevice(req);
    }
    if (req.command == "set_reservation") {
      return HandleSetReservation(req);
    }
    if (req.command == "no_reservation") {
      return HandleNoReservation(req);
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
    if (req.command == "show_ipv6") {
      return HandleShowIpv6(req);
    }
    if (req.command == "show_time") {
      return HandleShowTime(req);
    }
    if (req.command == "show_storage") {
      return HandleShowStorage(req);
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

  /// Subscribe to an event topic.
  ///
  /// This used to return success for anything and then deliver
  /// nothing, which made `watch` sit there looking like a quiet
  /// network. A topic with no source behind it is now refused by name.
  auto Subscribe(const std::string& topic_prefix,
                 cli::transport::EventCallback cb)
      -> std::expected<void, Error_t> override {
    if (topic_prefix != kLeaseTopic) {
      return std::unexpected(Error_t{
          cli::transport::TransportError::InvalidState,
          std::format(
              "nothing on this box publishes '{}'; the only live "
              "topic is '{}'",
              topic_prefix, kLeaseTopic)});
    }
    {
      std::lock_guard<std::mutex> lk(watch_mu_);
      if (watch_thread_.joinable()) {
        return std::unexpected(Error_t{
            cli::transport::TransportError::InvalidState,
            "already watching leases"});
      }
      watch_stop_ = false;
    }
    watch_thread_ = std::thread([this, cb = std::move(cb)] {
      PollLeases(cb);
    });
    return {};
  }

  auto Unsubscribe(const std::string& topic_prefix)
      -> std::expected<void, Error_t> override {
    if (topic_prefix != kLeaseTopic) {
      return std::unexpected(Error_t{
          cli::transport::TransportError::InvalidState,
          std::format("not subscribed to '{}'", topic_prefix)});
    }
    StopWatch();
    return {};
  }

 private:
  /// The one topic this transport can actually publish. Named here so
  /// the adapter and the transport agree on the spelling.
  static constexpr const char* kLeaseTopic = "leases";

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

  // The lease poller behind `watch show leases`.
  std::thread watch_thread_;
  std::mutex watch_mu_;
  std::condition_variable watch_cv_;
  bool watch_stop_ = false;

  auto StopWatch() -> void {
    {
      std::lock_guard<std::mutex> lk(watch_mu_);
      watch_stop_ = true;
    }
    watch_cv_.notify_all();
    if (watch_thread_.joinable()) watch_thread_.join();
  }

  /// Re-read the lease file until told to stop, publishing an event on
  /// the first pass and thereafter only when something changed.
  ///
  /// Repainting a still screen every two seconds would bury the one
  /// line the operator is waiting for, so a quiet segment stays quiet
  /// — but the first paint is immediate, because a watch that shows
  /// nothing until something happens is indistinguishable from a watch
  /// that is broken.
  auto PollLeases(const cli::transport::EventCallback& cb) -> void {
    bool first = true;
    for (;;) {
      auto now = NowSeconds();
      auto parsed = sc::ParseSystemConfigFile(SystemConfigPath());
      json body;
      if (!parsed) {
        // The watch keeps running: a system config being edited
        // underneath it is exactly when an operator is watching.
        body = {
            {"devices", json::array()},
            {"leases", "no-dhcp-configured"},
            {"journal", "unknown"},
            {"detail",
             std::format("{} does not parse", SystemConfigPath())},
            {"now", now},
        };
      } else {
        auto report =
            lease::CollectDevices(*parsed, ViewOptions(), now);
        const bool quiet = report.changes.Quiet();
        if (!first && quiet) {
          if (WaitOrStop()) return;
          continue;
        }
        body = DeviceReportToJson(report, now);
      }
      proto::Event ev;
      ev.topic = kLeaseTopic;
      ev.timestamp = Rfc3339(now);
      auto s = body.dump();
      ev.data.assign(s.begin(), s.end());
      cb(ev);
      first = false;
      if (WaitOrStop()) return;
    }
  }

  /// Sleep for the poll interval. Returns true when asked to stop, so
  /// Ctrl-C does not have to wait out the interval.
  auto WaitOrStop() -> bool {
    std::unique_lock<std::mutex> lk(watch_mu_);
    watch_cv_.wait_for(lk, cfg_.lease_poll,
                       [this] { return watch_stop_; });
    return watch_stop_;
  }

  static auto Rfc3339(std::int64_t epoch) -> std::string {
    auto t = static_cast<std::time_t>(epoch);
    std::tm tm{};
    ::gmtime_r(&t, &tm);
    char buf[32] = {};
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S.000Z", &tm);
    return buf;
  }

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

  /// Whether fd's control socket exists on disk.
  ///
  /// A ZMQ connect to a missing `ipc://` path succeeds and then times
  /// out three seconds later with "recv timeout", which reads as a
  /// slow daemon rather than an absent one. The socket file is a
  /// cheap, exact answer to "is fd there at all", so ask it first and
  /// keep the timeout for the case it is meant for: fd running and
  /// not answering.
  auto FdSocketPresent() const -> bool {
    constexpr std::string_view kIpc = "ipc://";
    if (!cfg_.fd_socket.starts_with(kIpc)) return true;
    auto path = cfg_.fd_socket.substr(kIpc.size());
    std::error_code ec;
    return std::filesystem::exists(path, ec);
  }

  auto RequireFd(const std::string& id)
      -> std::optional<proto::Response> {
    if (!FdSocketPresent()) {
      fd_connected_ = false;
      return MakeErr(id, "no_daemon",
          std::format("fd is not running (no socket at {})",
                      cfg_.fd_socket),
          "Start fd: sudo systemctl start fd");
    }
    // The socket is there; fd may have been restarted since our last
    // exchange failed, so rebuild the client side if we dropped it.
    if ((!fd_connected_ || !zmq_sock_) && !OpenFdSocket()) {
      return MakeErr(id, "no_daemon",
          "fd's control socket exists but could not be opened",
          "Check permissions on " + cfg_.fd_socket);
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
  /// Build the REQ socket onto fd's control endpoint.
  ///
  /// A ZMQ REQ socket enforces strict send/recv alternation: once a
  /// send has gone out and the reply has not come back, the next send
  /// throws. A connect to a dead `ipc://` path still succeeds, so the
  /// *first* command against a stopped fd times out — and every
  /// command after it in the same session used to die with
  /// "Operation cannot be accomplished in current state", which names
  /// nothing an operator can act on. So a failed exchange throws the
  /// socket away and makes a new one: one timeout, one honest message,
  /// and the session recovers by itself the moment fd comes back.
  auto OpenFdSocket() -> bool {
    try {
      if (!zmq_ctx_) zmq_ctx_ = std::make_unique<zmq::context_t>(1);
      zmq_sock_ = std::make_unique<zmq::socket_t>(
          *zmq_ctx_, zmq::socket_type::req);
      zmq_sock_->set(zmq::sockopt::linger, 0);
      zmq_sock_->set(zmq::sockopt::rcvtimeo, 3000);
      zmq_sock_->set(zmq::sockopt::sndtimeo, 3000);
      zmq_sock_->connect(cfg_.fd_socket);
      fd_connected_ = true;
      return true;
    } catch (const zmq::error_t&) {
      zmq_sock_.reset();
      fd_connected_ = false;
      return false;
    }
  }

  auto AskFd(uint8_t cmd, const std::string& payload = "")
      -> FdReply {
    FdReply out;
    if (!FdSocketPresent()) {
      fd_connected_ = false;
      out.error = std::format("fd is not running (no socket at {})",
                              cfg_.fd_socket);
      return out;
    }
    if ((!fd_connected_ || !zmq_sock_) && !OpenFdSocket()) {
      // A previous exchange failed and dropped the socket; fd may
      // have been restarted since, so this is a retry, not a state.
      out.error = "fd's control socket could not be opened";
      return out;
    }
    std::expected<std::string, std::string> resp;
    try {
      resp = SendRawToFd(*zmq_sock_, cmd, payload);
    } catch (const zmq::error_t& e) {
      resp = std::unexpected(e.what());
    }
    if (!resp) {
      // The socket is now mid-transaction and unusable; replace it so
      // the next command starts clean.
      zmq_sock_.reset();
      fd_connected_ = false;
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
    //
    // Nothing to validate is not a validated commit. `ListFwFiles`
    // returns {} for a source directory holding no .fw file and for a
    // path that is neither a file nor a directory, and the loop below
    // then ran zero times — so a commit whose sources had gone missing
    // reported the same "validated" it reports for a clean check, and
    // the only thing left standing between the operator and a broken
    // policy was fd's own compile.
    auto sources = ListFwFiles(cfg_.fw_source);
    if (sources.empty()) {
      return MakeErr(req.id, "no_sources",
          std::format("no .fw source found at {} — there is nothing "
                      "to validate and nothing to commit",
                      cfg_.fw_source),
          "check the configured source path exists and holds at "
          "least one .fw file");
    }
    for (const auto& path : sources) {
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
    // applies a change on demand — the kReloadProg command below —
    // and a cold start loads the last compiled bundle rather than the
    // source, so a commit fd did not apply is not applied at all.
    // (fd does configure a file watcher at cmd/fd.cc; it is off by
    // default and is not what `commit` relies on.)
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
    // Count the writes that succeeded, not the snapshots that were
    // attempted. `WriteFile` returns bool and this loop used to throw
    // it away, so a rollback that could not write a single file — a
    // full disk, a read-only mount, the exact circumstances under
    // which somebody is rolling back — answered "ok (N files
    // restored)" and left the bad policy on disk.
    int restored = 0;
    std::vector<std::string> failed;
    for (const auto& [path, content] :
         candidate_.snapshots) {
      if (WriteFile(path, content)) {
        restored++;
      } else {
        failed.push_back(path);
      }
    }
    candidate_.active = false;
    candidate_.snapshots.clear();
    if (!failed.empty()) {
      std::string names;
      for (const auto& p : failed) {
        names += (names.empty() ? "" : ", ") + p;
      }
      return MakeErr(req.id, "rollback_incomplete",
          std::format("restored {} file(s); FAILED to restore {}: {}. "
                      "The configuration on disk is neither the "
                      "candidate nor the previous state — fix the "
                      "write error and restore those files by hand "
                      "before committing.",
                      restored, failed.size(), names));
    }
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
    // PRESENT is answered from the hardware identity the row already
    // prints, never from the name. Matching by name reports "no" for
    // a port that is plugged in, powered and correctly identified —
    // and it does so at exactly the moment it matters, before a
    // pending `.link` rename has happened.
    auto ports = sc::ObservePorts();
    auto presence = sc::MatchInterfaces(cfg, ports);
    json ifaces = json::array();
    for (std::size_t idx = 0; idx < cfg.interfaces.size(); ++idx) {
      const auto& i = cfg.interfaces[idx];
      const auto& p = presence[idx];
      ifaces.push_back({
          {"name", i.name},
          {"match_kind",
           i.match.kind == sc::MatchKind::kMac ? "mac" : "path"},
          {"match", i.match.value},
          {"mode", sc::AddressModeName(i.mode)},
          {"address", i.address},
          {"gateway", i.gateway},
          {"zone", i.zone},
          {"presence", sc::PortPresenceName(p.presence)},
          {"present",
           p.presence == sc::PortPresence::kPresentNamed},
          {"current_name", p.current_name},
          {"presence_detail", p.detail},
      });
    }
    auto result = sc::Validate(cfg);
    json pending = json::array();
    for (const auto& p : presence) {
      if (!p.RenamePending() &&
          p.presence != sc::PortPresence::kNameTakenByOther) {
        continue;
      }
      pending.push_back({
          {"interface", p.interface},
          {"current_name", p.current_name},
          {"identity", p.identity},
          {"detail", p.detail},
      });
    }
    return MakeOk(req.id, {
        {"config", SystemConfigPath()},
        {"ok", !result.HasErrors()},
        {"zones", zones},
        {"interfaces", ifaces},
        {"ports_read",
         ports.availability == sc::PortAvailability::kObserved},
        {"ports_detail", ports.detail},
        {"pending", pending},
        {"listen", plan.allowed_interfaces},
        {"excluded", plan.excluded_interfaces},
        {"dhcp_on", plan.dhcp_interfaces},
        // An operator who reconnects after a confirmed apply must be
        // told the clock is running without having to know to ask.
        {"confirm", ConfirmState()},
        {"diagnostics", DiagsToJson(result.diagnostics)},
    });
  }

  /// The v6 stance, as it stands on this box right now.
  ///
  /// The question an operator has is not "what does the config say" —
  /// it is "is anything routing around me". So the answer carries the
  /// two numbers that settle it together: how many advertisements
  /// arrived, and how many addresses were formed. A zero on its own
  /// is ambiguous in exactly the direction that gets someone hurt.
  auto HandleShowIpv6(const proto::Request& req) -> proto::Response {
    sc::SystemConfig cfg;
    std::optional<proto::Response> fail;
    if (!LoadSystem(req, &cfg, &fail)) return *fail;

    auto report = sc::ObserveIpv6(cfg, sc::Ipv6Source{});
    json ports = json::array();
    for (const auto& i : report.interfaces) {
      ports.push_back({
          {"interface", i.intent.interface},
          {"zone", i.intent.zone},
          {"stance", sc::Ipv6StanceName(i.intent.stance)},
          {"counters_read", i.counters_read},
          {"ras_received", i.ras_received},
          {"v6_received", i.v6_received},
          {"v6_discarded", i.v6_discarded},
          {"addresses", i.global_addresses},
          {"sends_ra", i.intent.sends_ra},
          {"advertised_prefix", i.intent.advertised_prefix},
      });
    }
    return MakeOk(req.id, {
        {"availability",
         sc::Ipv6AvailabilityName(report.availability)},
        {"observed",
         report.availability == sc::Ipv6Availability::kObserved},
        {"forwarding", report.forwarding},
        {"refused_ras", report.RefusedRas()},
        {"violations", report.Violations()},
        {"interfaces", ports},
    });
  }

  /// The clock, and whether a timestamp taken now means anything.
  ///
  /// Every other view on this box is stamped in this clock — leases,
  /// the device journal, the log ring, conntrack ages. So the honest
  /// thing is not to print a time; it is to print the time together
  /// with how much of it to believe.
  auto HandleShowTime(const proto::Request& req) -> proto::Response {
    sc::SystemConfig cfg;
    std::optional<proto::Response> fail;
    if (!LoadSystem(req, &cfg, &fail)) return *fail;

    auto t = sc::QueryTime(cfg, sc::TimeSource{});
    return MakeOk(req.id, {
        {"trust", sc::TimeTrustName(t.trust)},
        {"trustworthy", t.Trustworthy()},
        {"rtc", sc::RtcPresenceName(t.rtc)},
        {"rtc_name", t.rtc_name},
        {"wall_seconds", t.wall_seconds},
        {"uptime_seconds", t.uptime_seconds},
        {"implausible", t.implausible},
        {"max_error_us", t.max_error_us},
        {"reference", t.reference},
        {"detail", t.detail},
        {"banner", sc::TimeWarningBanner(t)},
    });
  }

  /// Disk, bundles, and — the number this view exists for — how much
  /// logging has already been thrown away.
  auto HandleShowStorage(const proto::Request& req)
      -> proto::Response {
    sc::StorageSource src;
    src.retention.compiled_dir = cfg_.compiled_dir;
    auto r = sc::QueryStorage(src);
    return MakeOk(req.id, {
        {"availability",
         sc::StorageAvailabilityName(r.availability)},
        {"observed",
         r.availability == sc::StorageAvailability::kObserved},
        {"fs_total_bytes", r.fs_total_bytes},
        {"fs_free_bytes", r.fs_free_bytes},
        {"tight", r.Tight()},
        {"bundle_count", r.bundle_count},
        {"bundle_bytes", r.bundle_bytes},
        {"bundles_over_policy", r.bundles_over_policy},
        {"keep", src.retention.keep},
        {"compiled_dir", src.retention.compiled_dir},
        {"journal_bytes", r.journal_bytes},
        {"journal_read", r.journal_read},
        {"suppressed_messages", r.suppressed_messages},
        {"suppression_read", r.suppression_read},
        {"detail", r.detail},
        {"banner", sc::StorageWarningBanner(r)},
    });
  }

  auto HandleShowServices(const proto::Request& req)
      -> proto::Response {
    sc::SystemConfig cfg;
    std::optional<proto::Response> fail;
    if (!LoadSystem(req, &cfg, &fail)) return *fail;

    json services = json::array();
    for (const auto& s : sc::QueryServices(cfg)) {
      json listening = json::array();
      for (const auto& l : s.observed.listeners) {
        listening.push_back(l.Format());
      }
      bool observed =
          s.observed.availability ==
          sc::BindingAvailability::kObserved;
      services.push_back({
          {"name", s.name},
          {"unit", s.unit},
          {"state", sc::ServiceStateName(s.state)},
          {"expected", s.expected},
          {"healthy", (s.state == sc::ServiceState::kRunning ||
                       s.state == sc::ServiceState::kNotConfigured ||
                       s.state == sc::ServiceState::kActivating) &&
                          !s.Mismatched()},
          {"zones", s.zones},
          // Intent and observation are two keys, never one. A single
          // "interfaces" key is what let this view print identical
          // bytes for a working bind and for a daemon listening on
          // 127.0.0.1 and nothing else.
          {"bound_to", s.interfaces},
          {"observed",
           sc::BindingAvailabilityName(s.observed.availability)},
          {"answers_on", observed ? json(s.observed.interfaces)
                                  : json(json::array())},
          {"answers_known", observed},
          {"listening", listening},
          {"wildcard", s.observed.wildcard},
          {"loopback_only", s.observed.LoopbackOnly()},
          {"mismatch", s.Mismatched()},
          {"mismatch_detail", s.MismatchDetail()},
          {"detail", s.detail.empty() ? s.observed.detail : s.detail},
      });
    }
    auto plan = sc::PlanDnsmasq(cfg);
    auto drift = sc::CheckDnsmasqDrift(cfg, cfg_.dnsmasq_conf);
    return MakeOk(req.id, {
        {"services", services},
        {"artifact", cfg_.dnsmasq_conf},
        {"drift", sc::DriftKindName(drift)},
        // The one DNS setting whose failure mode is a name that
        // silently does not exist. Surfaced here because no other view
        // of a healthy-looking box would ever mention it.
        {"rebind_protection", plan.rebind_protection},
        {"rebind_exempt", plan.rebind_exempt},
    });
  }

  // -- device visibility ----------------------------------------------
  //
  // Plug something in; find out what it is and what it is talking to.
  //
  // The lease view is assembled from three sources that fail
  // independently — the system configuration, dnsmasq's lease file and
  // the device journal — plus fd for the flow half. Each one's
  // availability travels with the answer, because an empty table has
  // to be able to say which kind of empty it is.

  auto ViewOptions() const -> lease::ViewOptions {
    lease::ViewOptions o;
    o.lease_path = cfg_.lease_file;
    o.journal_path = cfg_.device_journal;
    return o;
  }

  /// The device report, or the response that explains why there is
  /// none. A system configuration that will not parse is not a lease
  /// view with no devices in it.
  auto CollectReport(const proto::Request& req,
                     lease::DeviceReport* out,
                     std::optional<proto::Response>* fail,
                     std::int64_t now) -> bool {
    sc::SystemConfig cfg;
    if (!LoadSystem(req, &cfg, fail)) return false;
    *out = lease::CollectDevices(cfg, ViewOptions(), now);
    return true;
  }

  auto HandleShowLeases(const proto::Request& req)
      -> proto::Response {
    const auto now = NowSeconds();
    lease::DeviceReport report;
    std::optional<proto::Response> fail;
    if (!CollectReport(req, &report, &fail, now)) return *fail;

    bool only_new = false;
    bool include_gone = false;
    for (const auto& a : req.args) {
      if (a == "new") only_new = true;
      if (a == "all") include_gone = true;
    }
    if (only_new || !include_gone) {
      std::vector<lease::Device> kept;
      for (const auto& d : report.devices) {
        if (only_new && !d.IsNew(now, lease::kNewWindowSeconds)) {
          continue;
        }
        if (!include_gone && !only_new && !d.active) continue;
        kept.push_back(d);
      }
      // How many rows were left out is part of the answer: "3 devices"
      // next to a table of one is a question the operator should not
      // have to ask.
      auto hidden = report.devices.size() - kept.size();
      auto j = DeviceReportToJson(report, now);
      report.devices = std::move(kept);
      auto shown = DeviceReportToJson(report, now);
      shown["hidden"] = hidden;
      shown["filter"] = only_new ? "new" : "active";
      shown["active"] = j["active"];
      return MakeOk(req.id, shown);
    }
    auto j = DeviceReportToJson(report, now);
    j["hidden"] = 0;
    j["filter"] = "all";
    return MakeOk(req.id, j);
  }

  auto HandleShowDevice(const proto::Request& req)
      -> proto::Response {
    if (req.args.empty()) {
      return MakeErr(req.id, "missing_args",
          "Usage: show device <mac|address|hostname>");
    }
    const auto& query = req.args[0];
    const auto now = NowSeconds();
    lease::DeviceReport report;
    std::optional<proto::Response> fail;
    if (!CollectReport(req, &report, &fail, now)) return *fail;

    auto hits = lease::MatchDevices(report, query);
    if (hits.empty()) {
      // Not knowing the device and not being able to read the leases
      // are different answers, and the hint says which one happened.
      std::string hint =
          report.leases == lease::LeaseAvailability::kOk
              ? "`show leases all` lists every device seen"
              : std::format("the lease view is unavailable: {}",
                            lease::LeaseAvailabilityName(
                                report.leases));
      return MakeErr(req.id, "no_such_device",
                     std::format("no device matches '{}'", query),
                     hint);
    }
    if (hits.size() > 1) {
      std::string names;
      for (const auto* d : hits) {
        if (!names.empty()) names += ", ";
        names += std::format("{} ({})", d->mac, d->address);
      }
      return MakeErr(req.id, "ambiguous_device",
          std::format("'{}' matches {} devices", query, hits.size()),
          names);
    }
    const auto& d = *hits[0];

    json j = {
        {"mac", d.mac},
        {"address", d.address},
        {"hostname", d.hostname},
        {"zone", d.zone},
        {"first_seen", d.first_seen},
        {"first_seen_age", now - d.first_seen},
        {"first_seen_exact",
         d.precision == lease::FirstSeenPrecision::kObserved},
        {"last_seen_age", now - d.last_seen},
        {"expires_in", d.expiry > 0 ? d.expiry - now : 0},
        {"active", d.active},
        {"new", d.IsNew(now, lease::kNewWindowSeconds)},
        {"reserved", d.reserved},
        {"reserved_address", d.reserved_address},
        {"address_changes", d.address_changes},
        {"leases", lease::LeaseAvailabilityName(report.leases)},
        {"journal", lease::JournalAvailabilityName(report.journal)},
    };

    // NAT first, because the flow half needs it.
    //
    // Conntrack is keyed on the addresses that are *on the wire*, and
    // behind a masquerade those are the gateway's, not the device's.
    // Filtering conntrack by the device's own address therefore finds
    // nothing on exactly the topology this appliance exists to run,
    // and reports "tracking no connections" about a device with two.
    // The NAT table is what makes the two views joinable: it maps
    // each translated endpoint back to the host that owns it.
    auto nat = AskFd(fd_cmd::kGetNat);
    // Endpoints seen on the wire that really belong to this device.
    struct WireAlias {
      std::string addr;
      int port = 0;
      int local_port = 0;
    };
    std::vector<WireAlias> aliases;
    if (nat.ok) {
      j["nat_available"] = true;
      json translations = json::array();
      for (const auto& t : nat.body.value("translations",
                                          json::array())) {
        // `type` is the *original* direction. For an outbound
        // masquerade the device is behind `new_addr`, and the wire
        // carries `orig_dst`; for an inbound port-forward it is the
        // other way round.
        const auto type = t.value("type", "");
        std::string device_side;
        WireAlias alias;
        if (type == "snat") {
          device_side = t.value("new_addr", "");
          alias.addr = t.value("orig_dst", "");
          alias.port = t.value("orig_dst_port", 0);
          alias.local_port = t.value("new_port", 0);
        } else {
          device_side = t.value("orig_src", "");
          alias.addr = t.value("new_addr", "");
          alias.port = t.value("new_port", 0);
          alias.local_port = t.value("orig_src_port", 0);
        }
        if (device_side != d.address) continue;
        translations.push_back(t);
        if (!alias.addr.empty()) aliases.push_back(alias);
      }
      j["nat"] = translations;
    } else {
      j["nat_available"] = false;
      j["nat_detail"] = nat.error;
    }
    j["translated"] = !aliases.empty();

    // The flow half. fd being down is reported as such; it is not the
    // same picture as a device that is talking to nobody.
    auto ct = AskFd(fd_cmd::kGetConntrack);
    if (!ct.ok) {
      j["flows_available"] = false;
      j["flows_detail"] = ct.error;
    } else {
      j["flows_available"] = true;
      json flows = json::array();
      const auto now_ns = MonotonicNs();
      std::uint64_t packets_total = 0;
      std::unordered_map<std::string, std::uint64_t> peers;
      for (const auto& c : ct.body) {
        auto src = c.value("src", "");
        auto dst = c.value("dst", "");
        auto sport = c.value("src_port", 0);
        auto dport = c.value("dst_port", 0);
        bool outbound = src == d.address;
        bool mine = outbound || dst == d.address;
        bool translated = false;
        int local_port = outbound ? sport : dport;
        if (!mine) {
          for (const auto& a : aliases) {
            if (src == a.addr && sport == a.port) {
              mine = true;
              outbound = true;
              translated = true;
              local_port = a.local_port;
              break;
            }
            if (dst == a.addr && dport == a.port) {
              mine = true;
              outbound = false;
              translated = true;
              local_port = a.local_port;
              break;
            }
          }
        }
        if (!mine) continue;
        auto seen = c.value("last_seen_ns", std::uint64_t{0});
        std::int64_t idle = -1;
        if (seen > 0 && now_ns > seen) {
          idle = static_cast<std::int64_t>((now_ns - seen) /
                                           1'000'000'000ULL);
        }
        auto pkts = c.value("packets", std::uint64_t{0});
        packets_total += pkts;
        auto peer = outbound ? dst : src;
        peers[peer] += pkts;
        flows.push_back({
            {"proto", c.value("proto", "any")},
            {"direction", outbound ? "out" : "in"},
            {"peer", peer},
            {"peer_port", outbound ? dport : sport},
            {"local_port", local_port},
            // True when this row was found through the NAT table
            // rather than by the device's own address — worth saying,
            // because the address conntrack shows is not the
            // device's.
            {"translated", translated},
            {"state", c.value("state", "")},
            {"packets", pkts},
            {"idle", idle},
        });
      }
      j["flows"] = flows;
      j["packets"] = packets_total;
      json top = json::array();
      std::vector<std::pair<std::string, std::uint64_t>> ranked(
          peers.begin(), peers.end());
      std::sort(ranked.begin(), ranked.end(),
                [](const auto& a, const auto& b) {
                  return a.second > b.second;
                });
      for (std::size_t i = 0; i < ranked.size() && i < 5; ++i) {
        top.push_back({{"peer", ranked[i].first},
                       {"packets", ranked[i].second}});
      }
      j["top_peers"] = top;
    }

    return MakeOk(req.id, j);
  }

  auto HandleSetReservation(const proto::Request& req)
      -> proto::Response {
    if (req.args.size() < 2) {
      return MakeErr(req.id, "missing_args",
          "Usage: set reservation <mac> <address> [hostname]");
    }
    const auto& mac = req.args[0];
    const auto& address = req.args[1];
    const std::string hostname =
        req.args.size() > 2 ? req.args[2] : std::string();

    sc::SystemConfig cfg;
    std::optional<proto::Response> fail;
    if (!LoadSystem(req, &cfg, &fail)) return *fail;

    // Which DHCP server owns this address is a question the model can
    // answer, so the operator is not made to repeat it. When it cannot
    // be answered without guessing, say so rather than pick.
    std::vector<std::string> candidates;
    auto want = sc::ParseIpv4(address);
    if (!want) {
      return MakeErr(req.id, "invalid_address",
          std::format("'{}' is not an IPv4 address", address));
    }
    for (const auto& d : cfg.dhcp) {
      for (const auto* i : cfg.InterfacesInZone(d.bind.zone)) {
        if (i->mode != sc::AddressMode::kStatic) continue;
        auto p = sc::ParseCidr4(i->address);
        if (p && p->Contains(*want)) {
          candidates.push_back(d.bind.zone);
          break;
        }
      }
    }
    if (candidates.empty()) {
      std::string zones;
      for (const auto& d : cfg.dhcp) {
        if (!zones.empty()) zones += ", ";
        zones += d.bind.zone;
      }
      return MakeErr(req.id, "no_zone_for_address",
          std::format("{} is not in the subnet of any zone that "
                      "serves DHCP", address),
          zones.empty()
              ? "no DHCP server is configured"
              : std::format("zones serving DHCP: {}", zones));
    }
    if (candidates.size() > 1) {
      std::string zones;
      for (const auto& z : candidates) {
        if (!zones.empty()) zones += ", ";
        zones += z;
      }
      return MakeErr(req.id, "ambiguous_zone",
          std::format("{} falls in more than one DHCP zone",
                      address),
          zones);
    }
    const auto& zone = candidates.front();

    auto edited = sc::SetDhcpReservation(
        ReadFile(SystemConfigPath()), zone, mac, address, hostname);
    if (!edited) {
      return MakeErr(req.id, "invalid_edit", edited.error());
    }

    json j = {
        {"action", "set reservation"},
        {"mac", sc::NormalizeMac(mac)},
        {"address", address},
        {"hostname", hostname},
        {"zone", zone},
        {"config", SystemConfigPath()},
        {"live", false},
    };
    if (auto f = InstallSystemDocument(req, *edited, &j)) return *f;
    j["applied"] = true;
    j["persisted"] = true;
    // A reservation only takes effect on the client's next DHCP
    // request. Saying so here is the difference between an operator
    // who waits and one who reboots a board for no reason.
    j["note"] =
        "the client keeps its current address until its lease is "
        "renewed";
    return MakeOk(req.id, j);
  }

  auto HandleNoReservation(const proto::Request& req)
      -> proto::Response {
    if (req.args.empty()) {
      return MakeErr(req.id, "missing_args",
                     "Usage: no reservation <mac>");
    }
    auto edited = sc::ClearDhcpReservation(
        ReadFile(SystemConfigPath()), req.args[0]);
    if (!edited) {
      return MakeErr(req.id, "invalid_edit", edited.error());
    }
    json j = {
        {"action", "remove reservation"},
        {"mac", req.args[0]},
        {"config", SystemConfigPath()},
        {"live", false},
    };
    if (auto f = InstallSystemDocument(req, *edited, &j)) return *f;
    j["applied"] = true;
    j["persisted"] = true;
    return MakeOk(req.id, j);
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
    auto stale_before = StaleNetworkdUnits(cfg);
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
    AddArtifactSweep(cfg, stale_before, &body);
    auto pending = PendingRenames(cfg);
    body["pending"] = pending;
    body["pending_note"] = RenameNote(pending);
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

  /// Generated networkd units in the unit directory that the current
  /// model does not name. Read from the directory, not from a record
  /// of what we wrote, so the answer survives a previous session, a
  /// crash, and an `apply` that ran under a different model.
  auto StaleNetworkdUnits(const sc::SystemConfig& cfg)
      -> std::vector<std::string> {
    sc::NetworkdOptions opts;
    opts.dir = cfg_.networkd_dir;
    std::set<std::string> planned;
    for (const auto& u : sc::PlanNetworkd(cfg, opts)) {
      planned.insert(u.path);
    }
    std::vector<std::string> stale;
    std::error_code ec;
    std::filesystem::directory_iterator it(cfg_.networkd_dir, ec);
    if (ec) return stale;
    for (const auto& entry : it) {
      auto name = entry.path().filename().string();
      if (name.rfind("10-f-", 0) != 0) continue;
      auto ext = entry.path().extension().string();
      if (ext != ".link" && ext != ".network") continue;
      auto path = entry.path().string();
      if (planned.count(path) != 0) continue;
      stale.push_back(path);
    }
    std::sort(stale.begin(), stale.end());
    return stale;
  }

  /// Interfaces the model names that the kernel does not have under
  /// that name yet, because a `.link` rename is still pending.
  ///
  /// `apply system` must say this. A reply of "applied, revision 1"
  /// over a config whose `interface=` lines name ports that will not
  /// exist until reboot is true about the files and false about the
  /// box, and the difference is a DHCP server bound to nothing.
  auto PendingRenames(const sc::SystemConfig& cfg) -> json {
    auto ports = sc::ObservePorts();
    json out = json::array();
    for (const auto& p : sc::MatchInterfaces(cfg, ports)) {
      if (p.presence != sc::PortPresence::kPendingRename &&
          p.presence != sc::PortPresence::kNameTakenByOther) {
        continue;
      }
      out.push_back({
          {"interface", p.interface},
          {"current_name", p.current_name},
          {"identity", p.identity},
          {"detail", p.detail},
      });
    }
    return out;
  }

  /// The sentence that turns a pending rename into something an
  /// operator can act on. The handbook says generated files are never
  /// hand-edited, so the recovery cannot be "edit the unit" — it has
  /// to be a sequence, and it has to be written down somewhere the
  /// person reading the apply output can see it.
  static auto RenameNote(const json& pending) -> std::string {
    if (pending.empty()) return "";
    std::string names;
    std::string first_now;
    for (const auto& p : pending) {
      names += (names.empty() ? "" : ", ") +
               p.value("interface", "") + " (currently " +
               p.value("current_name", "?") + ")";
      if (first_now.empty()) first_now = p.value("current_name", "");
    }
    return std::format(
        "PENDING RENAME: {}. Until the rename happens those names "
        "match no device, so every generated file that mentions them "
        "binds nothing — dnsmasq will start cleanly and answer on "
        "loopback. Either reboot, or apply the rename now:\n"
        "  udevadm control --reload\n"
        "  ip link set {} down\n"
        "  udevadm trigger --action=add /sys/class/net/{}\n"
        "Then `show system` must read PRESENT: yes before this "
        "configuration is doing anything.",
        names, first_now.empty() ? "<port>" : first_now,
        first_now.empty() ? "<port>" : first_now);
  }

  /// Record what the sweep actually did, by looking twice.
  ///
  /// A derived file whose interface left the model is not clutter:
  /// udev applies `.link` units in filename order, so a leftover whose
  /// name sorts first wins the rename for a MAC the current model
  /// pins elsewhere — and the port then never gets its configured
  /// name, with nothing logged anywhere.
  auto AddArtifactSweep(const sc::SystemConfig& cfg,
                        const std::vector<std::string>& before,
                        json* body) -> void {
    auto after = StaleNetworkdUnits(cfg);
    std::set<std::string> still(after.begin(), after.end());
    json removed = json::array();
    for (const auto& p : before) {
      if (still.count(p) == 0) removed.push_back(p);
    }
    (*body)["removed"] = removed;
    (*body)["leftover"] = after;
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
    auto stale_before = StaleNetworkdUnits(cfg);

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
      AddArtifactSweep(cfg, stale_before, &body);
      auto pending = PendingRenames(cfg);
      body["pending"] = pending;
      body["pending_note"] = RenameNote(pending);
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
    json removed = json::array();
    for (const auto& p : net->removed) removed.push_back(p);
    json conflicts = json::array();
    for (const auto& p : net->conflicts) conflicts.push_back(p);
    auto pending = PendingRenames(cfg);
    auto pending_note = RenameNote(pending);

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
          {"removed", removed},
          {"leftover", conflicts},
          {"pending", pending},
          {"pending_note", pending_note},
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
        {"removed", removed},
        {"leftover", conflicts},
        {"pending", pending},
        {"pending_note", pending_note},
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
