/// @file observe.h
/// @brief What the box actually has, as distinct from what we asked for.
///
/// Every other header in this directory renders or validates the
/// *model*. This one reads the kernel. The distinction is the whole
/// point: a column whose value is derived from the same model that
/// generated the config cannot be evidence about whether the config
/// worked. It can only ever agree with itself.
///
/// Two observations live here, because the deployment rehearsal found
/// the same defect four times over and both halves of it are here:
///
///  1. **Ports.** Which network devices exist right now, what hardware
///     identity each carries, and what address it holds. An interface
///     in the model is matched to a port by the identity it was pinned
///     to — never by name, because the name is exactly the thing that
///     has not happened yet when a `.link` rename is pending. Matching
///     by name reports `PRESENT: no` for a port that is plugged in,
///     powered, and correctly identified one column to the left.
///
///  2. **Listeners.** What sockets a daemon actually holds. `dnsmasq`
///     with `interface=lan0` naming a device that does not exist starts
///     cleanly, logs nothing alarming, and binds DNS to 127.0.0.1. A
///     status view that re-derives "answers on lan0" from the model
///     prints the same bytes in that case as in the working one.
///
/// Both carry an availability with the (possibly empty) answer, the
/// same shape as `LeaseAvailability`: a renderer must not be able to
/// collapse "nothing there" into "could not ask".

#ifndef INCLUDE_F_SYSCONFIG_OBSERVE_H_
#define INCLUDE_F_SYSCONFIG_OBSERVE_H_

#include <cstdint>
#include <functional>
#include <string>
#include <utility>
#include <vector>

#include "f/sysconfig/model.h"

namespace f::sysconfig {

// -- ports -------------------------------------------------------------

/// Whether the port table could be read at all.
enum class PortAvailability {
  /// The table was read. An empty port list means there are no ports.
  kObserved,
  /// Sysfs was not readable. **Not** the same as "no ports", and must
  /// never render as it.
  kUnreadable,
};

auto PortAvailabilityName(PortAvailability a) -> std::string;

/// One network device as the kernel presents it right now.
struct Port {
  /// The name the kernel currently uses. This is the volatile part.
  std::string name;
  /// Permanent MAC, lowercase colon-separated. Empty for a device that
  /// has none (loopback, some tunnels).
  std::string mac;
  /// Firmware/bus path in systemd's `Path=` spelling, e.g.
  /// "pci-0000:01:00.0". Empty when it could not be derived, which is
  /// reported as unknown rather than guessed at.
  std::string path;
  /// Addresses currently on the device, as literals.
  std::vector<std::string> addresses;
};

/// Every port on the box, plus whether we managed to look.
struct PortTable {
  PortAvailability availability = PortAvailability::kUnreadable;
  /// Why, when the availability is not `kObserved`.
  std::string detail;
  std::vector<Port> ports;

  auto FindByName(const std::string& name) const -> const Port*;
  /// Case-insensitive MAC comparison; the model and sysfs disagree on
  /// case often enough that a case-sensitive compare is a live bug.
  auto FindByMac(const std::string& mac) const -> const Port*;
  auto FindByPath(const std::string& path) const -> const Port*;
  /// The port holding `address`, or null. Used to turn a listening
  /// socket's address into the port it answers on.
  auto FindByAddress(const std::string& address) const -> const Port*;
};

/// Where the port observer reads from. Injected so the whole matching
/// table is testable against a fixture tree with no kernel involved.
struct PortSource {
  std::string sys_class_net = "/sys/class/net";
  /// (interface, address) pairs. Defaults to `getifaddrs`; a test
  /// hands in a fixed list.
  std::function<std::vector<std::pair<std::string, std::string>>()>
      addresses;
};

/// Addresses currently configured on this box, via `getifaddrs`.
auto SystemInterfaceAddresses()
    -> std::vector<std::pair<std::string, std::string>>;

/// Read the port table.
auto ObservePorts(const PortSource& src = {}) -> PortTable;

/// Convert a sysfs device link target into systemd's `Path=` spelling.
/// Pure, so the conversion is testable without sysfs.
/// @param link e.g. "../../devices/pci0000:00/0000:01:00.0/net/eth0".
/// @returns "pci-0000:01:00.0", or empty when the shape is not one we
///     can convert — which is reported as unknown, never as a mismatch.
auto DevicePathFromLink(const std::string& link) -> std::string;

// -- interface identity ------------------------------------------------

/// How the port an interface is pinned to actually presents itself.
enum class PortPresence {
  /// A port with this hardware identity exists and already carries the
  /// configured name. The only state in which artifacts naming this
  /// interface bind anything.
  kPresentNamed,
  /// The port exists — same identity — but under a different name. The
  /// `.link` rename has not happened yet, so every generated file that
  /// names the interface currently matches no device. This is a state
  /// `apply system` must announce, not one an operator discovers when
  /// DHCP stops answering.
  kPendingRename,
  /// A port with the configured *name* exists, but it is not the port
  /// the model pinned: different hardware identity. A firewall pointing
  /// at the wrong port is a bypass, not an outage.
  kNameTakenByOther,
  /// No port on this box carries that hardware identity.
  kAbsent,
  /// The port table could not be read, or the identity is one we cannot
  /// compare. Never rendered as absent.
  kUnknown,
};

auto PortPresenceName(PortPresence p) -> std::string;

/// One model interface, joined to the hardware.
struct InterfacePresence {
  /// The name the model gave it.
  std::string interface;
  /// The identity it was pinned to, as written in the model.
  std::string identity;
  PortPresence presence = PortPresence::kUnknown;
  /// The name the port carries right now, when that is not
  /// `interface`. Empty otherwise.
  std::string current_name;
  /// Sentence for the operator. Always set for anything but
  /// `kPresentNamed`.
  std::string detail;

  /// True when a reboot (or the documented rename dance) is what stands
  /// between this interface and existing.
  auto RenamePending() const -> bool {
    return presence == PortPresence::kPendingRename;
  }
};

/// Join every declared interface to the port table.
auto MatchInterfaces(const SystemConfig& cfg, const PortTable& table)
    -> std::vector<InterfacePresence>;

// -- listeners ---------------------------------------------------------

/// Whether a daemon's sockets could be observed.
enum class BindingAvailability {
  /// The socket table was read. An empty listener list means the
  /// process holds no listening sockets.
  kObserved,
  /// The unit is not running, so there is nothing to bind. Distinct
  /// from "running and bound to nothing", which is the fault.
  kNoProcess,
  /// `/proc` could not be read for that process — no permission, or it
  /// exited between the two reads. Not evidence of anything.
  kUnreadable,
};

auto BindingAvailabilityName(BindingAvailability a) -> std::string;

/// One socket a process is listening on.
struct Listener {
  /// Local address as a literal, e.g. "10.10.0.1", "127.0.0.1",
  /// "0.0.0.0", "::".
  std::string address;
  std::uint16_t port = 0;
  bool udp = false;
  /// True for 0.0.0.0 / ::. A wildcard socket is on every interface and
  /// is therefore evidence about none of them.
  auto Wildcard() const -> bool;
  /// True for 127.0.0.0/8 and ::1.
  auto Loopback() const -> bool;
  auto Format() const -> std::string;
};

/// Where a daemon is actually listening.
struct BindingReport {
  BindingAvailability availability = BindingAvailability::kUnreadable;
  std::string detail;
  std::vector<Listener> listeners;
  /// Ports resolved from the non-wildcard, non-loopback listener
  /// addresses. This — and nothing derived from the model — is the
  /// answer to "where does this service actually answer".
  std::vector<std::string> interfaces;
  /// True when at least one wildcard socket is held. dnsmasq's DHCP
  /// socket is always one of these: DHCP containment is enforced per
  /// received packet, not by binding, so a wildcard tells you nothing
  /// about which segment is served.
  bool wildcard = false;
  /// True when every socket that could name a segment names loopback.
  ///
  /// Wildcard sockets are excluded from the judgement rather than
  /// counted against it: dnsmasq always holds one for DHCP, so a
  /// definition that let a wildcard defeat this would never fire — and
  /// this is exactly the shape of the failure the rehearsal hit.
  /// Running, healthy by systemd, answering nobody.
  auto LoopbackOnly() const -> bool;
};

/// Where the listener observer reads from.
struct ListenerSource {
  std::string proc_root = "/proc";
};

/// One row of a `/proc/net/{tcp,udp}[6]` table, keyed by socket inode.
struct SocketRow {
  std::uint64_t inode = 0;
  Listener listener;
  /// The kernel's `st` column. 0x0A is TCP LISTEN.
  int state = 0;
};

/// Parse a `/proc/net/tcp`-shaped table. Pure.
/// @param text The whole file.
/// @param udp Marks the produced listeners as UDP.
/// @param v6 The address column is a 128-bit IPv6 literal.
auto ParseSocketTable(const std::string& text, bool udp, bool v6)
    -> std::vector<SocketRow>;

/// The socket inodes among a set of `/proc/<pid>/fd` link targets.
/// Pure: the caller does the readlink.
auto SocketInodes(const std::vector<std::string>& fd_targets)
    -> std::vector<std::uint64_t>;

/// Observe what `pid` is listening on.
/// @param pid The daemon's main PID; 0 means "not running".
auto ObserveListeners(int pid, const ListenerSource& src = {})
    -> BindingReport;

/// Fill `report->interfaces` by joining listener addresses to ports.
/// Pure, so the join is testable on its own.
auto ResolveListenerInterfaces(const PortTable& table,
                               BindingReport* report) -> void;

}  // namespace f::sysconfig

#endif  // INCLUDE_F_SYSCONFIG_OBSERVE_H_
