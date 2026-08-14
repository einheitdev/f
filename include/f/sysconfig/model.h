/// @file model.h
/// @brief The appliance system configuration model.
///
/// The layering the whole appliance hangs off:
///
///     physical port  ->  interface  ->  zone  ->  services bind here
///
/// Each arrow is a place where a name is assigned and validated.
/// **Services never name a kernel device.** A service carries a zone
/// and nothing else that decides placement, so "DHCP answers on the
/// uplink" is not a configuration mistake you can make — it is a
/// sentence the model has no words for.
///
/// The zone list lives here, not in FWL. A zone is fundamentally
/// *these ports*, which is a system fact; the firewall policy reads it.
/// That also means interfaces, DHCP and DNS come up before any policy
/// exists, which is how a box is actually commissioned.

#ifndef INCLUDE_F_SYSCONFIG_MODEL_H_
#define INCLUDE_F_SYSCONFIG_MODEL_H_

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace f::sysconfig {

/// A location in the system config source. Both 1-based, mirroring
/// FWL's Span so diagnostics read the same on either side.
struct Span {
  int line = 0;
  int column = 0;
};

/// How an interface is pinned to physical hardware.
///
/// Probe order is not an identity. udev renumbering an i350 port
/// repoints the policy underneath itself, and a firewall pointing at
/// the wrong port is a bypass, not an outage — so an interface is
/// pinned to something the hardware carries, assigned once.
enum class MatchKind {
  /// Permanent MAC address, e.g. "52:54:00:11:22:33".
  kMac,
  /// Firmware/bus path, e.g. "pci-0000:01:00.0".
  kPath,
};

/// The hardware identity an interface name is pinned to.
struct HardwareMatch {
  MatchKind kind = MatchKind::kMac;
  std::string value;
};

/// Address configuration for an interface.
enum class AddressMode {
  /// Link is brought up, no L3 address. The normal state for a port
  /// that only carries filtered traffic.
  kUnconfigured,
  /// Operator-assigned address; `address` holds a CIDR.
  kStatic,
  /// The box is a DHCP *client* here. Typically the uplink.
  kDhcpClient,
};

/// One durably-named interface.
struct Interface {
  /// The durable name. The label on the case and the name in the
  /// config are the same string.
  std::string name;
  HardwareMatch match;
  AddressMode mode = AddressMode::kUnconfigured;
  /// CIDR, e.g. "10.10.0.1/24". Only meaningful when mode is kStatic.
  std::string address;
  /// Optional static IPv6 CIDR, e.g. "fd00:10:10::1/64". Only a zone
  /// whose stance is `ra` may carry one: it is the prefix we
  /// advertise, so it exists to be handed out. On an `off` zone it is
  /// a contradiction and is refused rather than ignored.
  std::string address6;
  /// Optional default gateway for a static interface.
  std::string gateway;
  /// The zone this interface belongs to. An interface belongs to
  /// exactly one zone by construction — this is a scalar, not a list,
  /// so "in two zones at once" is unrepresentable. Empty means the
  /// interface is in no zone and carries no zone-bound service.
  std::string zone;
  Span span;
};

/// A zone's stance on IPv6.
///
/// The office is flat L2 and may have router advertisements flying
/// around. A testnet device that autoconfigures v6 from an office RA
/// routes around the v4 firewall entirely while appearing to work, so
/// the stance is stated per zone rather than inherited from whatever
/// the upstream broadcasts.
///
/// The stance is a statement about *both directions*. `off` is not
/// "we do not send RAs" — that would leave the interesting direction
/// unstated, and the interesting direction is inbound.
enum class Ipv6Stance {
  /// No v6 on this zone, in either direction. An RA arriving here is
  /// counted and refused; nothing autoconfigures; no v6 is forwarded.
  /// The safe default.
  kOff,
  /// We are the router on this zone: we send the RAs, and we still
  /// take orders from nobody else's. Requires a v6 prefix on one of
  /// the zone's interfaces — there is nothing to advertise without
  /// one, and an RA config with no prefix is a stance that generates
  /// a config line and delivers nothing.
  kRouterAdvertise,
  /// Full dual stack: accept upstream RAs, forward v6, filter it like
  /// v4. **Refused today** — see validate.h SC030. The datapath cannot
  /// classify an ICMPv6 error as `related`, so `Packet Too Big` cannot
  /// reach a host in the zone; IPv6 routers never fragment, so PMTU
  /// discovery is the only mechanism there is and a path with a
  /// smaller MTU anywhere along it fails completely. It presents as
  /// "the network is slow", which is the failure this whole model
  /// exists to refuse. Representable so the refusal can name it.
  kFull,
};

/// A named grouping of interfaces. Owned by the system config; FWL
/// references these names.
struct Zone {
  std::string name;
  Ipv6Stance ipv6 = Ipv6Stance::kOff;
  Span span;
};

/// A static DHCP reservation, keyed by client MAC.
struct Reservation {
  std::string mac;
  std::string address;
  std::string hostname;
  Span span;
};

/// Where a service runs.
///
/// This struct is deliberately one field wide. It is the reason the
/// rogue-DHCP case is structural: there is nowhere to put an interface
/// name, so the set of interfaces a service touches is *always*
/// derived from the zone, never maintained by hand alongside it.
struct ServiceBinding {
  std::string zone;
  Span span;
};

/// DHCP server, bound to a zone.
struct DhcpServer {
  ServiceBinding bind;
  std::string range_start;
  std::string range_end;
  /// Lease time in seconds.
  std::uint32_t lease_seconds = 43200;
  std::vector<Reservation> reservations;
  /// Optional DNS servers to advertise. Empty means "advertise the
  /// zone's own interface address", which is what you want when the
  /// same box forwards DNS.
  std::vector<std::string> dns_servers;
};

/// DNS forwarder/cache, bound to a zone.
struct DnsForwarder {
  ServiceBinding bind;
  /// Upstream resolvers. Empty means inherit the system resolver,
  /// which on a DHCP uplink is whatever the upstream handed us.
  std::vector<std::string> upstreams;
  /// Reject answers that point into RFC1918 space (dnsmasq
  /// `stop-dns-rebind`).
  bool stop_dns_rebind = true;
};

/// The whole model.
struct SystemConfig {
  std::vector<Zone> zones;
  std::vector<Interface> interfaces;
  std::vector<DhcpServer> dhcp;
  std::vector<DnsForwarder> dns;

  /// Interfaces belonging to `zone`, in declaration order. This is the
  /// single derivation from zone to devices; every backend goes
  /// through it.
  auto InterfacesInZone(const std::string& zone) const
      -> std::vector<const Interface*>;

  /// Interface names belonging to `zone`, in declaration order.
  auto InterfaceNamesInZone(const std::string& zone) const
      -> std::vector<std::string>;

  /// Every declared interface name, in declaration order.
  auto AllInterfaceNames() const -> std::vector<std::string>;

  auto FindZone(const std::string& name) const -> const Zone*;
  auto FindInterface(const std::string& name) const
      -> const Interface*;

  /// True when any DHCP server is bound to `zone`.
  auto ZoneServesDhcp(const std::string& zone) const -> bool;

  /// True when any service at all is bound to `zone`.
  auto ZoneHasService(const std::string& zone) const -> bool;

  /// The stance of the zone `iface` belongs to. An interface in no
  /// zone gets `kOff`: an unzoned port carries no policy, so the only
  /// safe reading of it is the safe one.
  auto StanceOf(const Interface& iface) const -> Ipv6Stance;

  /// True when any zone asks for v6 to move through the box. When no
  /// zone does, v6 forwarding is turned off globally rather than left
  /// at whatever the distribution shipped.
  auto AnyZoneWantsIpv6() const -> bool;
};

/// Severity of a diagnostic.
enum class Severity { kError, kWarning };

/// One validation finding. Named, located, and — for kError —
/// refused, the way FWL reports a bad policy.
struct Diagnostic {
  /// Stable machine-readable id, e.g. "SC003".
  std::string code;
  Severity severity = Severity::kError;
  std::string message;
  Span span;
  /// What to do about it. Optional but strongly preferred.
  std::string hint;

  /// Single-line rendering: `error[SC003]: 12:3: message`.
  auto Format() const -> std::string;
};

/// Result of validating a SystemConfig.
struct ValidationResult {
  std::vector<Diagnostic> diagnostics;

  auto HasErrors() const -> bool;
  auto Errors() const -> std::vector<Diagnostic>;
};

/// Human-readable name for an address mode, as it appears in config
/// and in CLI output.
auto AddressModeName(AddressMode m) -> std::string;

/// Human-readable name for an IPv6 stance.
auto Ipv6StanceName(Ipv6Stance s) -> std::string;

}  // namespace f::sysconfig

#endif  // INCLUDE_F_SYSCONFIG_MODEL_H_
