/// @file test_sysconfig_observe.cc
/// @brief The box as it is, against the box as it was described.
///
/// Every test here exists because the same model produced both halves
/// of a comparison and the comparison therefore always agreed. The
/// load-bearing case is `SameModelTwoRealities`: one system config,
/// two different kernels, and output that has to differ. A status view
/// that re-derives "answers on lan0" from the config it generated
/// cannot fail that test by accident — it can only fail it by actually
/// looking.

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "f/sysconfig/observe.h"
#include "f/sysconfig/parse.h"
#include "f/sysconfig/service_status.h"

namespace f::sysconfig {
namespace {

namespace fs = std::filesystem;

/// The shape the handbook commissions a box in: an uplink and a
/// testnet, services bound to the testnet zone only.
constexpr const char* kOfficeShape = R"YAML(
zones:
  wan:
  testnet:
interfaces:
  wan0:
    mac: "52:54:00:aa:bb:01"
    address: dhcp
    zone: wan
  lan0:
    mac: "52:54:00:aa:bb:02"
    address: 10.10.0.1/24
    zone: testnet
services:
  dhcp:
    - zone: testnet
      range: 10.10.0.100-10.10.0.200
  dns:
    - zone: testnet
      upstream: [9.9.9.9]
)YAML";

auto MustParse(const std::string& yaml) -> SystemConfig {
  auto parsed = ParseSystemConfigString(yaml);
  EXPECT_TRUE(parsed.has_value());
  return parsed.value_or(SystemConfig{});
}

auto WriteFile(const fs::path& p, const std::string& text) -> void {
  fs::create_directories(p.parent_path());
  std::ofstream out(p);
  out << text;
}

/// A fixture sysfs tree: real directories under `devices`, symlinked
/// into `class/net` exactly as the kernel does it, because the symlink
/// target is where the bus path comes from.
class SysfsFixture {
 public:
  SysfsFixture() {
    root_ = fs::temp_directory_path() /
            std::format("f-observe-{}-{}", ::getpid(),
                        ++counter_);
    fs::create_directories(root_ / "class" / "net");
  }
  ~SysfsFixture() {
    std::error_code ec;
    fs::remove_all(root_, ec);
  }
  SysfsFixture(const SysfsFixture&) = delete;
  auto operator=(const SysfsFixture&) -> SysfsFixture& = delete;

  /// @param bus e.g. "0000:01:00.0"; empty means no bus path at all.
  auto AddPort(const std::string& name, const std::string& mac,
               const std::string& bus) -> void {
    auto rel = std::format("../../devices/pci0000:00/{}/net/{}",
                           bus.empty() ? "virtual" : bus, name);
    auto real = root_ / "devices" / "pci0000:00" /
                (bus.empty() ? "virtual" : bus) / "net" / name;
    fs::create_directories(real);
    WriteFile(real / "address", mac + "\n");
    fs::create_symlink(rel, root_ / "class" / "net" / name);
  }

  auto NetDir() const -> std::string {
    return (root_ / "class" / "net").string();
  }

 private:
  fs::path root_;
  static inline int counter_ = 0;
};

/// A fixture /proc: one process holding a chosen set of sockets.
class ProcFixture {
 public:
  ProcFixture() {
    root_ = fs::temp_directory_path() /
            std::format("f-proc-{}-{}", ::getpid(), ++counter_);
    fs::create_directories(root_ / "net");
  }
  ~ProcFixture() {
    std::error_code ec;
    fs::remove_all(root_, ec);
  }
  ProcFixture(const ProcFixture&) = delete;
  auto operator=(const ProcFixture&) -> ProcFixture& = delete;

  auto AddProcessSockets(int pid,
                         const std::vector<std::uint64_t>& inodes)
      -> void {
    auto fd = root_ / std::to_string(pid) / "fd";
    fs::create_directories(fd);
    int n = 3;
    for (auto inode : inodes) {
      fs::create_symlink(std::format("socket:[{}]", inode),
                         fd / std::to_string(n++));
    }
  }

  auto SetTable(const std::string& name, const std::string& body)
      -> void {
    WriteFile(root_ / "net" / name,
              "  sl  local_address rem_address   st tx_queue "
              "rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
                  body);
  }

  auto Root() const -> std::string { return root_.string(); }

 private:
  fs::path root_;
  static inline int counter_ = 0;
};

/// One `/proc/net/tcp` row. The kernel writes the address as the
/// host-order value of a network-order word, which is why the bytes
/// look reversed.
auto Row(int index, const std::string& addr_hex, const char* port_hex,
         const char* state, std::uint64_t inode) -> std::string {
  return std::format(
      "{:5}: {}:{} 00000000:0000 {} 00000000:00000000 "
      "00:00000000 00000000     0        0 {} 1 0 100 0 0 10 0\n",
      index, addr_hex, port_hex, state, inode);
}

// -- pure parsing ------------------------------------------------------

TEST(ObservePathTest, PciLinkBecomesSystemdPathSpelling) {
  EXPECT_EQ(DevicePathFromLink(
                "../../devices/pci0000:00/0000:00:01.0/"
                "0000:01:00.0/net/enp1s0"),
            "pci-0000:01:00.0");
}

/// Anything we cannot convert comes back empty, and the caller renders
/// that as unknown. Guessing here would claim a port is the wrong one.
TEST(ObservePathTest, UnconvertibleShapeIsEmptyNotWrong) {
  EXPECT_EQ(DevicePathFromLink("../../devices/virtual/net/lo"), "");
  EXPECT_EQ(DevicePathFromLink("nonsense"), "");
  EXPECT_EQ(DevicePathFromLink("/net/eth0"), "");
}

TEST(SocketTableTest, Ipv4AddressAndPortAreDecoded) {
  auto rows = ParseSocketTable(
      Row(0, "01000A0A", "0035", "0A", 555), false, false);
  ASSERT_EQ(rows.size(), 1u);
  EXPECT_EQ(rows[0].listener.address, "10.10.0.1");
  EXPECT_EQ(rows[0].listener.port, 53);
  EXPECT_EQ(rows[0].inode, 555u);
  EXPECT_EQ(rows[0].state, 0x0A);
}

TEST(SocketTableTest, Ipv6AddressIsDecoded) {
  // ::1 — the last byte of the fourth word.
  auto rows = ParseSocketTable(
      Row(0, "00000000000000000000000001000000", "0035", "0A", 7),
      false, true);
  ASSERT_EQ(rows.size(), 1u);
  EXPECT_EQ(rows[0].listener.address, "::1");
}

TEST(SocketTableTest, InodesAreExtractedFromFdLinks) {
  auto inodes = SocketInodes({"socket:[42]", "/dev/null",
                              "socket:[7]", "pipe:[9]",
                              "socket:[42]"});
  ASSERT_EQ(inodes.size(), 2u);
  EXPECT_EQ(inodes[0], 7u);
  EXPECT_EQ(inodes[1], 42u);
}

TEST(ListenerTest, WildcardAndLoopbackAreNamedNotInferred) {
  EXPECT_TRUE((Listener{"0.0.0.0", 67, true}).Wildcard());
  EXPECT_TRUE((Listener{"::", 53, false}).Wildcard());
  EXPECT_TRUE((Listener{"127.0.0.1", 53, false}).Loopback());
  EXPECT_TRUE((Listener{"::1", 53, false}).Loopback());
  EXPECT_FALSE((Listener{"10.10.0.1", 53, false}).Loopback());
  EXPECT_FALSE((Listener{"10.10.0.1", 53, false}).Wildcard());
}

// -- port identity -----------------------------------------------------

TEST(PortTableTest, MacMatchIsCaseInsensitive) {
  SysfsFixture sysfs;
  sysfs.AddPort("lan0", "52:54:00:AA:BB:02", "0000:01:00.0");
  PortSource src;
  src.sys_class_net = sysfs.NetDir();
  src.addresses = [] {
    return std::vector<std::pair<std::string, std::string>>{};
  };
  auto table = ObservePorts(src);
  ASSERT_EQ(table.availability, PortAvailability::kObserved);
  EXPECT_NE(table.FindByMac("52:54:00:aa:bb:02"), nullptr);
  EXPECT_NE(table.FindByPath("pci-0000:01:00.0"), nullptr);
  // systemd's spelling carries a bus prefix sysfs does not; a suffix
  // match counts rather than claiming the port is a different one.
  EXPECT_NE(table.FindByPath("virtio-pci-0000:01:00.0"), nullptr);
}

/// The defect this whole file exists for, at its smallest: the port is
/// plugged in, powered, and pinned correctly — and matching by name
/// says it is not there.
TEST(InterfacePresenceTest, PendingRenameIsNotAbsent) {
  SysfsFixture sysfs;
  sysfs.AddPort("wan0", "52:54:00:aa:bb:01", "0000:01:00.0");
  // The testnet port is still under its kernel name: the .link rename
  // has not happened yet.
  sysfs.AddPort("enp1s0f1", "52:54:00:aa:bb:02", "0000:01:00.1");
  PortSource src;
  src.sys_class_net = sysfs.NetDir();
  src.addresses = [] {
    return std::vector<std::pair<std::string, std::string>>{};
  };
  auto out = MatchInterfaces(MustParse(kOfficeShape),
                             ObservePorts(src));
  ASSERT_EQ(out.size(), 2u);
  EXPECT_EQ(out[0].presence, PortPresence::kPresentNamed);
  EXPECT_EQ(out[1].interface, "lan0");
  EXPECT_EQ(out[1].presence, PortPresence::kPendingRename);
  EXPECT_EQ(out[1].current_name, "enp1s0f1");
  EXPECT_NE(out[1].detail.find("enp1s0f1"), std::string::npos)
      << out[1].detail;
  EXPECT_TRUE(out[1].RenamePending());
}

TEST(InterfacePresenceTest, PresentAndNamedIsTheOnlyGreenState) {
  SysfsFixture sysfs;
  sysfs.AddPort("wan0", "52:54:00:aa:bb:01", "0000:01:00.0");
  sysfs.AddPort("lan0", "52:54:00:aa:bb:02", "0000:01:00.1");
  PortSource src;
  src.sys_class_net = sysfs.NetDir();
  src.addresses = [] {
    return std::vector<std::pair<std::string, std::string>>{};
  };
  for (const auto& p :
       MatchInterfaces(MustParse(kOfficeShape), ObservePorts(src))) {
    EXPECT_EQ(p.presence, PortPresence::kPresentNamed) << p.interface;
  }
}

/// The name is right and the hardware behind it is not. This is the
/// case the handbook calls a bypass rather than an outage, and it must
/// never render as `PRESENT: yes`.
TEST(InterfacePresenceTest, NameOnTheWrongHardwareIsShoutedAbout) {
  SysfsFixture sysfs;
  sysfs.AddPort("wan0", "52:54:00:aa:bb:01", "0000:01:00.0");
  // Something else took the name lan0, and the pinned port sits
  // elsewhere.
  sysfs.AddPort("lan0", "52:54:00:99:99:99", "0000:02:00.0");
  sysfs.AddPort("enp3s0", "52:54:00:aa:bb:02", "0000:03:00.0");
  PortSource src;
  src.sys_class_net = sysfs.NetDir();
  src.addresses = [] {
    return std::vector<std::pair<std::string, std::string>>{};
  };
  auto out = MatchInterfaces(MustParse(kOfficeShape),
                             ObservePorts(src));
  ASSERT_EQ(out.size(), 2u);
  EXPECT_EQ(out[1].presence, PortPresence::kNameTakenByOther);
  EXPECT_NE(out[1].detail.find("wrong port"), std::string::npos)
      << out[1].detail;
  EXPECT_NE(PortPresenceName(out[1].presence), "yes");
}

TEST(InterfacePresenceTest, AbsentIsAbsentAndUnreadableIsUnknown) {
  SysfsFixture sysfs;
  sysfs.AddPort("wan0", "52:54:00:aa:bb:01", "0000:01:00.0");
  PortSource src;
  src.sys_class_net = sysfs.NetDir();
  src.addresses = [] {
    return std::vector<std::pair<std::string, std::string>>{};
  };
  auto out = MatchInterfaces(MustParse(kOfficeShape),
                             ObservePorts(src));
  EXPECT_EQ(out[1].presence, PortPresence::kAbsent);

  PortSource missing;
  missing.sys_class_net = "/nonexistent/class/net";
  auto table = ObservePorts(missing);
  EXPECT_EQ(table.availability, PortAvailability::kUnreadable);
  for (const auto& p :
       MatchInterfaces(MustParse(kOfficeShape), table)) {
    EXPECT_EQ(p.presence, PortPresence::kUnknown);
    EXPECT_FALSE(p.detail.empty());
  }
}

// -- listeners ---------------------------------------------------------

TEST(ListenerObservationTest, NotRunningIsNotUnreadable) {
  auto r = ObserveListeners(0);
  EXPECT_EQ(r.availability, BindingAvailability::kNoProcess);
  EXPECT_FALSE(r.detail.empty());
}

TEST(ListenerObservationTest, UnreadableProcIsNotAnEmptyBinding) {
  ListenerSource src;
  src.proc_root = "/nonexistent/proc";
  auto r = ObserveListeners(1234, src);
  EXPECT_EQ(r.availability, BindingAvailability::kUnreadable);
  EXPECT_TRUE(r.listeners.empty());
  EXPECT_NE(r.detail.find("root"), std::string::npos) << r.detail;
}

TEST(ListenerObservationTest, OnlyListeningTcpSocketsCount) {
  ProcFixture proc;
  proc.AddProcessSockets(1234, {555, 556});
  // 555 is LISTEN on 10.10.0.1:53; 556 is an ESTABLISHED conversation
  // and says nothing about where the service answers.
  proc.SetTable("tcp", Row(0, "01000A0A", "0035", "0A", 555) +
                           Row(1, "01000A0A", "C350", "01", 556));
  proc.SetTable("udp", "");
  ListenerSource src;
  src.proc_root = proc.Root();
  auto r = ObserveListeners(1234, src);
  ASSERT_EQ(r.availability, BindingAvailability::kObserved);
  ASSERT_EQ(r.listeners.size(), 1u);
  EXPECT_EQ(r.listeners[0].port, 53);
}

TEST(ListenerObservationTest, WildcardResolvesToNoInterface) {
  ProcFixture proc;
  proc.AddProcessSockets(1234, {900});
  proc.SetTable("udp", Row(0, "00000000", "0043", "07", 900));
  ListenerSource src;
  src.proc_root = proc.Root();
  auto r = ObserveListeners(1234, src);
  ASSERT_EQ(r.availability, BindingAvailability::kObserved);
  EXPECT_TRUE(r.wildcard);

  SysfsFixture sysfs;
  sysfs.AddPort("lan0", "52:54:00:aa:bb:02", "0000:01:00.1");
  PortSource ps;
  ps.sys_class_net = sysfs.NetDir();
  ps.addresses = [] {
    return std::vector<std::pair<std::string, std::string>>{
        {"lan0", "10.10.0.1"}};
  };
  ResolveListenerInterfaces(ObservePorts(ps), &r);
  EXPECT_TRUE(r.interfaces.empty())
      << "a wildcard socket is on every port and therefore evidence "
         "about none";
}

// -- the whole point ---------------------------------------------------

/// One system configuration, two boxes. `show services` used to print
/// byte-identical output for both, because the column it printed was
/// re-derived from the same model that generated the config it was
/// supposed to be reporting on.
TEST(ServiceBindingTest, SameModelTwoRealities) {
  SysfsFixture sysfs;
  sysfs.AddPort("wan0", "52:54:00:aa:bb:01", "0000:01:00.0");
  sysfs.AddPort("lan0", "52:54:00:aa:bb:02", "0000:01:00.1");

  ServiceProbe probe;
  probe.is_active_cmd = "echo active #";
  probe.restarts_cmd = "echo 0 #";
  probe.result_cmd = "echo success #";
  probe.load_state_cmd = "echo loaded #";
  probe.log_cmd = "true #";
  probe.main_pid_cmd = "echo 1234 #";
  probe.ports.sys_class_net = sysfs.NetDir();
  probe.ports.addresses = [] {
    return std::vector<std::pair<std::string, std::string>>{
        {"lan0", "10.10.0.1"}, {"lo", "127.0.0.1"}};
  };

  // Reality A: dnsmasq bound to the testnet port, as intended.
  ProcFixture good;
  good.AddProcessSockets(1234, {555, 900});
  good.SetTable("tcp", Row(0, "01000A0A", "0035", "0A", 555));
  good.SetTable("udp", Row(0, "01000A0A", "0035", "07", 555) +
                           Row(1, "00000000", "0043", "07", 900));
  probe.listeners.proc_root = good.Root();
  auto bound = QueryServices(MustParse(kOfficeShape), probe);
  ASSERT_GE(bound.size(), 1u);
  EXPECT_EQ(bound[0].state, ServiceState::kRunning);
  EXPECT_EQ(bound[0].observed.availability,
            BindingAvailability::kObserved);
  EXPECT_EQ(bound[0].observed.interfaces,
            std::vector<std::string>{"lan0"});
  EXPECT_FALSE(bound[0].Mismatched());
  EXPECT_TRUE(bound[0].MismatchDetail().empty());

  // Reality B: `interface=lan0` named a port that did not exist when
  // dnsmasq started, so DNS fell back to loopback and DHCP is on the
  // wildcard socket it always uses. systemd still says `active`.
  ProcFixture broken;
  broken.AddProcessSockets(1234, {777, 900});
  broken.SetTable("tcp", Row(0, "0100007F", "0035", "0A", 777));
  broken.SetTable("udp", Row(0, "0100007F", "0035", "07", 777) +
                             Row(1, "00000000", "0043", "07", 900));
  probe.listeners.proc_root = broken.Root();
  auto blind = QueryServices(MustParse(kOfficeShape), probe);
  ASSERT_GE(blind.size(), 1u);
  EXPECT_EQ(blind[0].state, ServiceState::kRunning)
      << "systemd is not wrong; it is answering a different question";
  EXPECT_TRUE(blind[0].observed.interfaces.empty());
  EXPECT_TRUE(blind[0].Mismatched());
  // The wildcard DHCP socket is always there, so it must not be
  // allowed to defeat the loopback-only judgement — a definition that
  // let it would never fire on a real dnsmasq.
  EXPECT_TRUE(blind[0].observed.wildcard);
  EXPECT_TRUE(blind[0].observed.LoopbackOnly());
  EXPECT_FALSE(bound[0].observed.LoopbackOnly());
  EXPECT_EQ(blind[0].MissingInterfaces(),
            std::vector<std::string>{"lan0"});
  EXPECT_NE(blind[0].MismatchDetail().find("lan0"),
            std::string::npos);
  EXPECT_NE(blind[0].MismatchDetail().find("127.0.0.1"),
            std::string::npos)
      << blind[0].MismatchDetail();

  // And the thing that must never be true again: the two must not
  // describe themselves the same way.
  EXPECT_NE(bound[0].observed.interfaces,
            blind[0].observed.interfaces);
}

/// An observation we could not make is not a mismatch. Reporting one
/// would train the operator to ignore the loudest line on the screen.
TEST(ServiceBindingTest, UnobservableBindingIsNeverAFault) {
  ServiceProbe probe;
  probe.is_active_cmd = "echo active #";
  probe.restarts_cmd = "echo 0 #";
  probe.result_cmd = "echo success #";
  probe.load_state_cmd = "echo loaded #";
  probe.log_cmd = "true #";
  probe.main_pid_cmd = "echo 1234 #";
  probe.listeners.proc_root = "/nonexistent/proc";
  auto out = QueryServices(MustParse(kOfficeShape), probe);
  ASSERT_GE(out.size(), 1u);
  EXPECT_EQ(out[0].observed.availability,
            BindingAvailability::kUnreadable);
  EXPECT_FALSE(out[0].Mismatched());
  EXPECT_TRUE(out[0].MissingInterfaces().empty());
}

}  // namespace
}  // namespace f::sysconfig
