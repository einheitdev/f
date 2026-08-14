/// @file ipv6.h
/// @brief The IPv6 stance, enforced and then observed.
///
/// `ipv6: off` used to mean "we do not send router advertisements".
/// That leaves the interesting direction unstated, and the interesting
/// direction is inbound: a testnet device that autoconfigures v6 from
/// an office RA routes around the v4 NAT and the whole firewall while
/// every v4 counter keeps climbing and everything appears to work.
///
/// So `off` means *incoming RAs do not reach the zone*, and that is
/// made true in three places, because any one of them alone is a
/// promise rather than a mechanism:
///
///  1. **The host stack.** Ports in an `off` zone set `accept_ra=0`
///     and `autoconf=0`. Measured on 6.12: an RA still arrives and is
///     still counted, and no address is formed. That combination is
///     chosen deliberately over `disable_ipv6=1`, which also works but
///     drops the frame before ICMPv6 accounting — it would make the
///     box safe and blind at the same time.
///  2. **Forwarding.** With no zone asking for v6, `all.forwarding`
///     goes to 0, so the kernel is not a v6 router even by accident.
///  3. **The service plane.** dnsmasq never emits an RA into an `off`
///     zone and never answers DHCPv6 there, derived from zone
///     membership the same way the DHCP containment is.
///
/// And then the fourth thing, which is why this file has an observer
/// in it at all: **a refusal that nobody can see is indistinguishable
/// from a network that never spoke.** `ObserveIpv6` reads what the
/// kernel already counted and reports, per zone, how many RAs arrived
/// and how many addresses were formed — so "the gate held" is a
/// number the operator can look at rather than a claim in a document.

#ifndef INCLUDE_F_SYSCONFIG_IPV6_H_
#define INCLUDE_F_SYSCONFIG_IPV6_H_

#include <cstdint>
#include <expected>
#include <string>
#include <vector>

#include "f/sysconfig/model.h"

namespace f::sysconfig {

/// Where the sysctl artifact is installed. systemd re-applies the
/// per-interface prefixes from here when a device appears, which is
/// what makes a setting keyed on an interface name survive a port
/// that shows up after boot.
inline constexpr const char* kIpv6SysctlPath =
    "/etc/sysctl.d/10-f-ipv6.conf";

/// What one interface is set to, and why.
struct Ipv6InterfaceIntent {
  std::string interface;
  std::string zone;
  Ipv6Stance stance = Ipv6Stance::kOff;
  /// True when the kernel may form an address from an upstream RA
  /// here. False for every stance we currently allow.
  bool accepts_ra = false;
  /// True when we advertise a prefix here.
  bool sends_ra = false;
  /// The prefix advertised, when `sends_ra`. Network form, e.g.
  /// "fd00:10:10::".
  std::string advertised_prefix;
};

/// The rendered stance: an artifact plus the intent behind it.
struct Ipv6Plan {
  /// Contents of `kIpv6SysctlPath`.
  std::string sysctl_content;
  std::vector<Ipv6InterfaceIntent> interfaces;
  /// True when v6 forwarding is enabled globally. Only a zone that
  /// asks for v6 turns this on.
  bool forwarding = false;
};

/// Render the stance. Pure: no I/O, no clock, no environment.
auto PlanIpv6(const SystemConfig& cfg) -> Ipv6Plan;

/// Why an observation is missing, carried with the (possibly empty)
/// result so a renderer cannot forget which kind of empty it got.
/// This is the `LeaseAvailability` shape: an empty list always travels
/// with the reason it is empty.
enum class Ipv6Availability {
  /// Counters were read. Zeroes mean zero.
  kObserved,
  /// The model declares no interfaces, so there is nothing to watch.
  kNoInterfaces,
  /// The kernel's per-interface counters were not readable — the
  /// device is not present, or /proc is not mounted. **Not** the same
  /// as "no RAs arrived", and must never render as it.
  kCountersUnreadable,
};

/// Human-readable form of the availability, for the operator.
auto Ipv6AvailabilityName(Ipv6Availability a) -> std::string;

/// What the kernel counted on one interface.
struct Ipv6InterfaceObservation {
  Ipv6InterfaceIntent intent;
  /// True when this interface's counters were readable at all.
  bool counters_read = false;
  /// Router advertisements received on this port since boot. On an
  /// `off` port every one of these is an RA we refused.
  std::uint64_t ras_received = 0;
  /// v6 datagrams received, and the subset the stack discarded.
  std::uint64_t v6_received = 0;
  std::uint64_t v6_discarded = 0;
  /// Global-scope v6 addresses currently on the interface. On an
  /// `off` port this must be empty; a non-empty list is the bypass,
  /// already happening.
  std::vector<std::string> global_addresses;
};

/// The whole picture, per interface, with its availability.
struct Ipv6Report {
  Ipv6Availability availability = Ipv6Availability::kNoInterfaces;
  std::vector<Ipv6InterfaceObservation> interfaces;
  /// True when v6 forwarding is on in the kernel right now.
  bool forwarding = false;
  /// Interfaces whose stance is `off` but which hold a global v6
  /// address anyway. Non-empty means the stance is being violated on
  /// a live box, which is a fault to shout about, not a row in a
  /// table.
  auto Violations() const -> std::vector<std::string>;
  /// Total RAs refused across every `off` interface.
  auto RefusedRas() const -> std::uint64_t;
};

/// Where the observer reads from. Injected so the report can be
/// tested against fixtures without a kernel, and so the same code
/// runs against a netns in the system test.
struct Ipv6Source {
  /// Directory of per-interface SNMP counters.
  std::string snmp6_dir = "/proc/net/dev_snmp6";
  /// The kernel's v6 address table.
  std::string if_inet6_path = "/proc/net/if_inet6";
  /// The global v6 forwarding sysctl.
  std::string forwarding_path =
      "/proc/sys/net/ipv6/conf/all/forwarding";
};

/// Read the live state and join it to the model's intent.
auto ObserveIpv6(const SystemConfig& cfg, const Ipv6Source& src)
    -> Ipv6Report;

/// Options for installing the artifact.
struct Ipv6Options {
  std::string sysctl_path = kIpv6SysctlPath;
  /// Refuse to overwrite an artifact that was hand-edited.
  bool refuse_on_drift = true;
  /// When set, the stance is also pushed into `/proc/sys` directly,
  /// so it takes effect without waiting for a reboot or a udev event.
  /// Empty disables the live push (what the unit tests want).
  std::string proc_sys_root = "/proc/sys";
};

/// What an apply did.
struct Ipv6ApplyReport {
  bool changed = false;
  std::string sysctl_path;
  Ipv6Plan plan;
  /// Settings pushed live, as "net.ipv6.conf.lan0.accept_ra=0".
  std::vector<std::string> applied_live;
  /// Settings that could not be pushed live, with the reason. A
  /// stance that only half-applied says which half.
  std::vector<std::string> failed_live;
};

/// generate -> write -> push live. Never silently partial: anything
/// that could not be set appears in `failed_live`.
auto ApplyIpv6(const SystemConfig& cfg, const Ipv6Options& opts)
    -> std::expected<Ipv6ApplyReport, std::string>;

}  // namespace f::sysconfig

#endif  // INCLUDE_F_SYSCONFIG_IPV6_H_
