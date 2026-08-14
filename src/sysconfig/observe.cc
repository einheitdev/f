/// @file observe.cc
/// @brief Read the kernel: which ports exist, and what is bound to what.

#include "f/sysconfig/observe.h"

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <format>
#include <fstream>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace f::sysconfig {
namespace {

namespace fs = std::filesystem;

auto Trim(std::string s) -> std::string {
  while (!s.empty() && (std::isspace(static_cast<unsigned char>(
                            s.back())) != 0)) {
    s.pop_back();
  }
  std::size_t start = 0;
  while (start < s.size() &&
         (std::isspace(static_cast<unsigned char>(s[start])) != 0)) {
    start++;
  }
  return s.substr(start);
}

auto Lower(std::string s) -> std::string {
  for (auto& c : s) {
    c = static_cast<char>(
        std::tolower(static_cast<unsigned char>(c)));
  }
  return s;
}

auto ReadFirstLine(const fs::path& p) -> std::string {
  std::ifstream in(p);
  if (!in) return "";
  std::string line;
  std::getline(in, line);
  return Trim(line);
}

auto ReadWhole(const fs::path& p) -> std::string {
  std::ifstream in(p);
  if (!in) return "";
  std::ostringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

auto Split(const std::string& s) -> std::vector<std::string> {
  std::vector<std::string> out;
  std::istringstream ss(s);
  std::string tok;
  while (ss >> tok) out.push_back(tok);
  return out;
}

auto HexToU32(const std::string& s) -> std::uint32_t {
  return static_cast<std::uint32_t>(std::strtoul(s.c_str(), nullptr,
                                                 16));
}

/// The kernel prints an IPv4 socket address as the host-order value of
/// the network-order word, so the dotted quad comes out of the low byte
/// first.
auto V4FromProc(const std::string& hex) -> std::string {
  auto v = HexToU32(hex);
  return std::format("{}.{}.{}.{}", v & 0xFFU, (v >> 8) & 0xFFU,
                     (v >> 16) & 0xFFU, (v >> 24) & 0xFFU);
}

auto V6FromProc(const std::string& hex) -> std::string {
  if (hex.size() != 32) return "";
  std::array<unsigned char, 16> bytes{};
  for (int word = 0; word < 4; ++word) {
    auto v = HexToU32(hex.substr(static_cast<std::size_t>(word) * 8, 8));
    for (int b = 0; b < 4; ++b) {
      bytes[static_cast<std::size_t>(word) * 4 +
            static_cast<std::size_t>(b)] =
          static_cast<unsigned char>((v >> (8 * b)) & 0xFFU);
    }
  }
  std::array<char, INET6_ADDRSTRLEN> buf{};
  if (inet_ntop(AF_INET6, bytes.data(), buf.data(), buf.size()) ==
      nullptr) {
    return "";
  }
  return buf.data();
}

}  // namespace

auto PortAvailabilityName(PortAvailability a) -> std::string {
  switch (a) {
    case PortAvailability::kObserved:
      return "observed";
    case PortAvailability::kUnreadable:
      break;
  }
  return "the port table could not be read";
}

auto PortPresenceName(PortPresence p) -> std::string {
  switch (p) {
    case PortPresence::kPresentNamed:
      return "yes";
    case PortPresence::kPendingRename:
      return "pending rename";
    case PortPresence::kNameTakenByOther:
      return "WRONG PORT";
    case PortPresence::kAbsent:
      return "no";
    case PortPresence::kUnknown:
      break;
  }
  return "?";
}

auto BindingAvailabilityName(BindingAvailability a) -> std::string {
  switch (a) {
    case BindingAvailability::kObserved:
      return "observed";
    case BindingAvailability::kNoProcess:
      return "not running";
    case BindingAvailability::kUnreadable:
      break;
  }
  return "socket table unreadable";
}

auto Listener::Wildcard() const -> bool {
  return address == "0.0.0.0" || address == "::";
}

auto Listener::Loopback() const -> bool {
  return address == "::1" || address.rfind("127.", 0) == 0;
}

auto Listener::Format() const -> std::string {
  return std::format("{}:{}/{}", address, port, udp ? "udp" : "tcp");
}

auto BindingReport::LoopbackOnly() const -> bool {
  bool any = false;
  for (const auto& l : listeners) {
    if (l.Wildcard()) continue;
    if (!l.Loopback()) return false;
    any = true;
  }
  return any;
}

auto PortTable::FindByName(const std::string& name) const
    -> const Port* {
  for (const auto& p : ports) {
    if (p.name == name) return &p;
  }
  return nullptr;
}

auto PortTable::FindByMac(const std::string& mac) const -> const Port* {
  if (mac.empty()) return nullptr;
  auto want = Lower(mac);
  for (const auto& p : ports) {
    if (!p.mac.empty() && Lower(p.mac) == want) return &p;
  }
  return nullptr;
}

auto PortTable::FindByPath(const std::string& path) const
    -> const Port* {
  if (path.empty()) return nullptr;
  auto want = Lower(path);
  for (const auto& p : ports) {
    if (p.path.empty()) continue;
    auto have = Lower(p.path);
    // systemd's ID_PATH carries a bus prefix we cannot always
    // reconstruct from sysfs alone ("virtio-pci-0000:00:03.0"), so a
    // suffix match counts. A wrong answer here would claim a port is
    // the wrong one, which is worse than saying we do not know.
    if (have == want || (want.size() > have.size() &&
                         want.compare(want.size() - have.size(),
                                      have.size(), have) == 0)) {
      return &p;
    }
  }
  return nullptr;
}

auto PortTable::FindByAddress(const std::string& address) const
    -> const Port* {
  if (address.empty()) return nullptr;
  for (const auto& p : ports) {
    for (const auto& a : p.addresses) {
      if (a == address) return &p;
    }
  }
  return nullptr;
}

auto DevicePathFromLink(const std::string& link) -> std::string {
  // ".../devices/pci0000:00/0000:00:01.0/0000:01:00.0/net/eth0" ->
  // the last bus address before "/net/".
  auto net = link.rfind("/net/");
  if (net == std::string::npos) return "";
  auto head = link.substr(0, net);
  auto slash = head.rfind('/');
  if (slash == std::string::npos) return "";
  auto leaf = head.substr(slash + 1);
  // A PCI bus address is "dddd:bb:dd.f"; anything else we decline to
  // convert rather than guess at.
  if (leaf.size() != 12 || leaf[4] != ':' || leaf[7] != ':' ||
      leaf[10] != '.') {
    return "";
  }
  for (std::size_t i = 0; i < leaf.size(); ++i) {
    if (i == 4 || i == 7 || i == 10) continue;
    if (std::isxdigit(static_cast<unsigned char>(leaf[i])) == 0) {
      return "";
    }
  }
  return "pci-" + leaf;
}

auto SystemInterfaceAddresses()
    -> std::vector<std::pair<std::string, std::string>> {
  std::vector<std::pair<std::string, std::string>> out;
  struct ifaddrs* head = nullptr;
  if (getifaddrs(&head) != 0) return out;
  for (auto* ifa = head; ifa != nullptr; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr == nullptr || ifa->ifa_name == nullptr) continue;
    std::array<char, INET6_ADDRSTRLEN> buf{};
    if (ifa->ifa_addr->sa_family == AF_INET) {
      const auto* sin =
          reinterpret_cast<const sockaddr_in*>(ifa->ifa_addr);
      if (inet_ntop(AF_INET, &sin->sin_addr, buf.data(),
                    buf.size()) == nullptr) {
        continue;
      }
    } else if (ifa->ifa_addr->sa_family == AF_INET6) {
      const auto* sin6 =
          reinterpret_cast<const sockaddr_in6*>(ifa->ifa_addr);
      if (inet_ntop(AF_INET6, &sin6->sin6_addr, buf.data(),
                    buf.size()) == nullptr) {
        continue;
      }
    } else {
      continue;
    }
    out.emplace_back(ifa->ifa_name, buf.data());
  }
  freeifaddrs(head);
  return out;
}

auto ObservePorts(const PortSource& src) -> PortTable {
  PortTable table;
  std::error_code ec;
  if (!fs::exists(src.sys_class_net, ec)) {
    table.availability = PortAvailability::kUnreadable;
    table.detail = std::format("{} is not readable", src.sys_class_net);
    return table;
  }
  fs::directory_iterator it(src.sys_class_net, ec);
  if (ec) {
    table.availability = PortAvailability::kUnreadable;
    table.detail =
        std::format("{}: {}", src.sys_class_net, ec.message());
    return table;
  }
  for (const auto& entry : it) {
    Port p;
    p.name = entry.path().filename().string();
    p.mac = Lower(ReadFirstLine(entry.path() / "address"));
    // The entry itself is the symlink into /sys/devices; read it
    // without resolving, because the relative form is what carries the
    // bus address.
    std::error_code lec;
    auto link = fs::read_symlink(entry.path(), lec);
    if (!lec) p.path = DevicePathFromLink(link.string());
    table.ports.push_back(std::move(p));
  }
  std::sort(table.ports.begin(), table.ports.end(),
            [](const Port& a, const Port& b) {
              return a.name < b.name;
            });

  auto lookup = src.addresses ? src.addresses : SystemInterfaceAddresses;
  for (const auto& [iface, addr] : lookup()) {
    for (auto& p : table.ports) {
      if (p.name == iface) p.addresses.push_back(addr);
    }
  }
  table.availability = PortAvailability::kObserved;
  return table;
}

auto MatchInterfaces(const SystemConfig& cfg, const PortTable& table)
    -> std::vector<InterfacePresence> {
  std::vector<InterfacePresence> out;
  for (const auto& i : cfg.interfaces) {
    InterfacePresence r;
    r.interface = i.name;
    r.identity = i.match.value;
    if (table.availability != PortAvailability::kObserved) {
      r.presence = PortPresence::kUnknown;
      r.detail = table.detail.empty()
                     ? "the port table could not be read"
                     : table.detail;
      out.push_back(std::move(r));
      continue;
    }
    if (i.match.value.empty()) {
      r.presence = PortPresence::kUnknown;
      r.detail =
          "this interface is pinned to no hardware identity, so there "
          "is nothing to look for";
      out.push_back(std::move(r));
      continue;
    }

    const Port* by_identity =
        i.match.kind == MatchKind::kMac
            ? table.FindByMac(i.match.value)
            : table.FindByPath(i.match.value);
    const Port* by_name = table.FindByName(i.name);

    if (by_identity == nullptr) {
      if (i.match.kind == MatchKind::kPath) {
        // A path match we could not reconstruct is unknown, not
        // absent: sysfs alone does not always give systemd's spelling.
        r.presence = PortPresence::kUnknown;
        r.detail = std::format(
            "no port's bus path could be matched against '{}'; path "
            "matches cannot always be verified from sysfs — check "
            "with `udevadm info /sys/class/net/<port>`",
            i.match.value);
        out.push_back(std::move(r));
        continue;
      }
      r.presence = PortPresence::kAbsent;
      r.detail = std::format(
          "no port on this box carries {}", i.match.value);
      out.push_back(std::move(r));
      continue;
    }

    if (by_identity->name == i.name) {
      r.presence = PortPresence::kPresentNamed;
      out.push_back(std::move(r));
      continue;
    }

    r.current_name = by_identity->name;
    if (by_name != nullptr) {
      // The name exists but belongs to different hardware. Every
      // artifact naming this interface is currently pointing at the
      // wrong socket.
      r.presence = PortPresence::kNameTakenByOther;
      r.detail = std::format(
          "'{}' exists but is {} — the port pinned to {} is currently "
          "called {}. Policy naming '{}' is aimed at the wrong port",
          i.name, by_name->mac.empty() ? "different hardware"
                                       : by_name->mac,
          i.match.value, by_identity->name, i.name);
      out.push_back(std::move(r));
      continue;
    }
    r.presence = PortPresence::kPendingRename;
    r.detail = std::format(
        "the port pinned to {} is still called {}; '{}' does not "
        "exist yet, so every generated file naming it matches no "
        "device",
        i.match.value, by_identity->name, i.name);
    out.push_back(std::move(r));
  }
  return out;
}

auto ParseSocketTable(const std::string& text, bool udp, bool v6)
    -> std::vector<SocketRow> {
  std::vector<SocketRow> out;
  std::istringstream ss(text);
  std::string line;
  bool first = true;
  while (std::getline(ss, line)) {
    if (first) {
      // Header row.
      first = false;
      if (line.find("local_address") != std::string::npos) continue;
    }
    auto tok = Split(line);
    if (tok.size() < 10) continue;
    auto colon = tok[1].find(':');
    if (colon == std::string::npos) continue;
    SocketRow row;
    auto addr_hex = tok[1].substr(0, colon);
    row.listener.address =
        v6 ? V6FromProc(addr_hex) : V4FromProc(addr_hex);
    if (row.listener.address.empty()) continue;
    row.listener.port = static_cast<std::uint16_t>(
        std::strtoul(tok[1].substr(colon + 1).c_str(), nullptr, 16));
    row.listener.udp = udp;
    row.state = static_cast<int>(std::strtol(tok[3].c_str(), nullptr,
                                             16));
    row.inode = std::strtoull(tok[9].c_str(), nullptr, 10);
    out.push_back(std::move(row));
  }
  return out;
}

auto SocketInodes(const std::vector<std::string>& fd_targets)
    -> std::vector<std::uint64_t> {
  std::vector<std::uint64_t> out;
  for (const auto& t : fd_targets) {
    constexpr std::string_view kPrefix = "socket:[";
    if (t.rfind(kPrefix, 0) != 0) continue;
    auto close = t.find(']', kPrefix.size());
    if (close == std::string::npos) continue;
    out.push_back(std::strtoull(
        t.substr(kPrefix.size(), close - kPrefix.size()).c_str(),
        nullptr, 10));
  }
  std::sort(out.begin(), out.end());
  out.erase(std::unique(out.begin(), out.end()), out.end());
  return out;
}

auto ObserveListeners(int pid, const ListenerSource& src)
    -> BindingReport {
  BindingReport report;
  if (pid <= 0) {
    report.availability = BindingAvailability::kNoProcess;
    report.detail =
        "no main process, so the daemon holds no sockets at all";
    return report;
  }
  std::error_code ec;
  auto fd_dir = fs::path(src.proc_root) / std::to_string(pid) / "fd";
  fs::directory_iterator it(fd_dir, ec);
  if (ec) {
    report.availability = BindingAvailability::kUnreadable;
    report.detail = std::format(
        "{} could not be read ({}) — root is needed to see another "
        "process's sockets",
        fd_dir.string(), ec.message());
    return report;
  }
  std::vector<std::string> targets;
  for (const auto& entry : it) {
    std::error_code lec;
    auto target = fs::read_symlink(entry.path(), lec);
    if (lec) continue;
    targets.push_back(target.string());
  }
  auto inodes = SocketInodes(targets);
  std::set<std::uint64_t> want(inodes.begin(), inodes.end());

  struct Table {
    const char* name;
    bool udp;
    bool v6;
  };
  static constexpr std::array<Table, 4> kTables{{
      {"tcp", false, false},
      {"udp", true, false},
      {"tcp6", false, true},
      {"udp6", true, true},
  }};
  for (const auto& t : kTables) {
    auto path = fs::path(src.proc_root) / "net" / t.name;
    auto text = ReadWhole(path);
    if (text.empty()) continue;
    for (auto& row : ParseSocketTable(text, t.udp, t.v6)) {
      if (want.count(row.inode) == 0) continue;
      // A TCP socket that is not LISTEN is a conversation, not a
      // binding, and says nothing about where the service answers.
      if (!t.udp && row.state != 0x0A) continue;
      if (row.listener.Wildcard()) report.wildcard = true;
      report.listeners.push_back(row.listener);
    }
  }
  std::sort(report.listeners.begin(), report.listeners.end(),
            [](const Listener& a, const Listener& b) {
              return std::tie(a.address, a.port, a.udp) <
                     std::tie(b.address, b.port, b.udp);
            });
  report.availability = BindingAvailability::kObserved;
  return report;
}

auto ResolveListenerInterfaces(const PortTable& table,
                               BindingReport* report) -> void {
  if (report == nullptr) return;
  report->interfaces.clear();
  if (table.availability != PortAvailability::kObserved) return;
  std::set<std::string> names;
  for (const auto& l : report->listeners) {
    if (l.Wildcard() || l.Loopback()) continue;
    const auto* p = table.FindByAddress(l.address);
    if (p != nullptr) names.insert(p->name);
  }
  report->interfaces.assign(names.begin(), names.end());
}

}  // namespace f::sysconfig
