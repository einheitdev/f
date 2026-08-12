/// @file validate.cc
/// @brief Structural validation: named, located, refused.

#include "f/sysconfig/validate.h"

#include <format>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "f/sysconfig/net.h"

namespace f::sysconfig {
namespace {

class Validator {
 public:
  explicit Validator(const SystemConfig& cfg) : cfg_(cfg) {}

  auto Run() -> ValidationResult {
    CheckZoneNames();
    CheckInterfaceNames();
    CheckHardwareIdentity();
    CheckInterfaceZones();
    CheckAddresses();
    CheckSubnetOverlap();
    CheckServiceZones();
    CheckDhcp();
    CheckDns();
    CheckIpv6();
    return {std::move(diags_)};
  }

 private:
  const SystemConfig& cfg_;
  std::vector<Diagnostic> diags_;

  auto Err(const std::string& code, const Span& span,
           const std::string& msg, const std::string& hint = "")
      -> void {
    diags_.push_back({code, Severity::kError, msg, span, hint});
  }

  auto Warn(const std::string& code, const Span& span,
            const std::string& msg, const std::string& hint = "")
      -> void {
    diags_.push_back({code, Severity::kWarning, msg, span, hint});
  }

  auto CheckZoneNames() -> void {
    std::set<std::string> seen;
    for (const auto& z : cfg_.zones) {
      if (z.name.empty()) {
        Err("SC001", z.span, "a zone must have a name");
        continue;
      }
      if (!seen.insert(z.name).second) {
        Err("SC001", z.span,
            std::format("duplicate zone name '{}'", z.name));
      }
    }
  }

  auto CheckInterfaceNames() -> void {
    std::set<std::string> seen;
    for (const auto& i : cfg_.interfaces) {
      if (i.name.empty()) {
        Err("SC002", i.span, "an interface must have a name");
        continue;
      }
      if (!seen.insert(i.name).second) {
        Err("SC002", i.span,
            std::format("duplicate interface name '{}'", i.name));
      }
    }
  }

  auto CheckHardwareIdentity() -> void {
    std::map<std::string, std::string> owner;
    for (const auto& i : cfg_.interfaces) {
      if (i.match.value.empty()) {
        Err("SC004", i.span,
            std::format(
                "interface '{}' has no hardware identity", i.name),
            "give it `mac:` or `path:` — a name derived from probe "
            "order can be reassigned by udev, and a firewall "
            "pointing at the wrong port is a bypass, not an outage");
        continue;
      }
      if (i.match.kind == MatchKind::kMac &&
          !IsMacAddress(i.match.value)) {
        Err("SC004", i.span,
            std::format("interface '{}': '{}' is not a MAC address",
                        i.name, i.match.value),
            "six colon-separated hex octets, e.g. 52:54:00:11:22:33");
        continue;
      }
      auto key = std::format(
          "{}:{}",
          i.match.kind == MatchKind::kMac ? "mac" : "path",
          i.match.value);
      auto [it, fresh] = owner.emplace(key, i.name);
      if (!fresh) {
        Err("SC003", i.span,
            std::format("interfaces '{}' and '{}' both claim "
                        "hardware {}",
                        it->second, i.name, i.match.value),
            "one physical port, one durable name");
      }
    }
  }

  auto CheckInterfaceZones() -> void {
    for (const auto& i : cfg_.interfaces) {
      if (i.zone.empty()) continue;
      if (cfg_.FindZone(i.zone) == nullptr) {
        Err("SC005", i.span,
            std::format("interface '{}' is in zone '{}', which is "
                        "not declared",
                        i.name, i.zone),
            "declare it under `zones:`");
      }
    }
  }

  auto CheckAddresses() -> void {
    for (const auto& i : cfg_.interfaces) {
      if (i.mode != AddressMode::kStatic) {
        if (!i.gateway.empty() &&
            i.mode == AddressMode::kUnconfigured) {
          Warn("SC011", i.span,
               std::format("interface '{}' has a gateway but no "
                           "address",
                           i.name));
        }
        continue;
      }
      auto pfx = ParseCidr4(i.address);
      if (!pfx) {
        Err("SC010", i.span,
            std::format("interface '{}': '{}' is not an IPv4 "
                        "address with a prefix",
                        i.name, i.address),
            "e.g. 10.10.0.1/24, or `dhcp`, or omit for no address");
        continue;
      }
      if (!i.gateway.empty()) {
        auto gw = ParseIpv4(i.gateway);
        if (!gw) {
          Err("SC011", i.span,
              std::format("interface '{}': gateway '{}' is not an "
                          "IPv4 address",
                          i.name, i.gateway));
        } else if (!pfx->Contains(*gw)) {
          Err("SC011", i.span,
              std::format("interface '{}': gateway {} is outside "
                          "its own subnet {}",
                          i.name, i.gateway, i.address),
              "the next hop has to be reachable on the wire");
        }
      }
    }
  }

  /// Two zones that overlap in address space cannot be routed between
  /// and cannot be told apart by a DHCP server. Same-zone overlap is
  /// odd but sometimes deliberate (two ports on one segment), so it
  /// warns rather than refuses.
  auto CheckSubnetOverlap() -> void {
    struct Entry {
      const Interface* iface;
      Prefix4 pfx;
    };
    std::vector<Entry> entries;
    for (const auto& i : cfg_.interfaces) {
      if (i.mode != AddressMode::kStatic) continue;
      auto p = ParseCidr4(i.address);
      if (p) entries.push_back({&i, *p});
    }
    for (std::size_t a = 0; a < entries.size(); ++a) {
      for (std::size_t b = a + 1; b < entries.size(); ++b) {
        if (!PrefixesOverlap(entries[a].pfx, entries[b].pfx)) {
          continue;
        }
        const auto* ia = entries[a].iface;
        const auto* ib = entries[b].iface;
        auto msg = std::format(
            "subnets overlap: '{}' ({}, zone '{}') and '{}' ({}, "
            "zone '{}')",
            ia->name, ia->address,
            ia->zone.empty() ? "-" : ia->zone, ib->name,
            ib->address, ib->zone.empty() ? "-" : ib->zone);
        if (ia->zone != ib->zone) {
          Err("SC012", ib->span, msg,
              "two zones sharing address space cannot be routed "
              "between, and a DHCP server cannot tell them apart");
        } else {
          Warn("SC012", ib->span, msg);
        }
      }
    }
  }

  /// One place answers "does this service have somewhere to run", for
  /// every service kind.
  auto CheckBinding(const ServiceBinding& bind,
                    const std::string& what) -> void {
    if (bind.zone.empty()) {
      Err("SC020", bind.span,
          std::format("{} is not bound to a zone", what),
          "every service binds to a zone; it never names an "
          "interface");
      return;
    }
    if (cfg_.FindZone(bind.zone) == nullptr) {
      Err("SC020", bind.span,
          std::format("{} is bound to zone '{}', which is not "
                      "declared",
                      what, bind.zone),
          "declare it under `zones:`");
      return;
    }
    if (cfg_.InterfacesInZone(bind.zone).empty()) {
      Err("SC021", bind.span,
          std::format("{} is bound to zone '{}', which has no "
                      "interfaces",
                      what, bind.zone),
          "a service with nowhere to answer is a service that "
          "silently does nothing");
    }
  }

  auto CheckServiceZones() -> void {
    for (const auto& d : cfg_.dhcp) {
      CheckBinding(d.bind, "dhcp server");
    }
    for (const auto& d : cfg_.dns) {
      CheckBinding(d.bind, "dns forwarder");
    }
  }

  /// The zone's own address on the segment it serves. A DHCP server
  /// needs one: it is the subnet the pool must live in and the address
  /// handed out as the gateway.
  auto ZoneSubnet(const std::string& zone) const
      -> std::optional<Prefix4> {
    for (const auto* i : cfg_.InterfacesInZone(zone)) {
      if (i->mode != AddressMode::kStatic) continue;
      auto p = ParseCidr4(i->address);
      if (p) return p;
    }
    return std::nullopt;
  }

  auto CheckDhcp() -> void {
    std::set<std::string> zones_served;
    for (const auto& d : cfg_.dhcp) {
      const auto& zone = d.bind.zone;
      if (zone.empty() || cfg_.FindZone(zone) == nullptr) continue;
      if (!zones_served.insert(zone).second) {
        Err("SC023", d.bind.span,
            std::format("more than one dhcp server bound to zone "
                        "'{}'",
                        zone));
      }

      // The rogue-DHCP structural check. A zone whose port takes its
      // own address from someone else's DHCP server is a zone we are
      // a client on; running a server there makes us the second
      // answer on somebody's network.
      for (const auto* i : cfg_.InterfacesInZone(zone)) {
        if (i->mode == AddressMode::kDhcpClient) {
          Err("SC022", d.bind.span,
              std::format(
                  "dhcp server is bound to zone '{}', but interface "
                  "'{}' in that zone is a dhcp *client*",
                  zone, i->name),
              "we would be answering on a network we are a client "
              "of; move the uplink to its own zone");
        }
      }

      auto subnet = ZoneSubnet(zone);
      if (!subnet) {
        Err("SC024", d.bind.span,
            std::format("dhcp server on zone '{}' has no "
                        "statically addressed interface to serve "
                        "from",
                        zone),
            "give one interface in the zone a static address, e.g. "
            "10.10.0.1/24");
        continue;
      }

      auto start = ParseIpv4(d.range_start);
      auto end = ParseIpv4(d.range_end);
      if (!start || !end) {
        Err("SC025", d.bind.span,
            std::format("dhcp range '{}-{}' on zone '{}' is not "
                        "two IPv4 addresses",
                        d.range_start, d.range_end, zone));
        continue;
      }
      if (*start > *end) {
        Err("SC025", d.bind.span,
            std::format("dhcp range on zone '{}' runs backwards: "
                        "{} > {}",
                        zone, d.range_start, d.range_end));
        continue;
      }
      if (!subnet->Contains(*start) || !subnet->Contains(*end)) {
        Err("SC026", d.bind.span,
            std::format("dhcp range {}-{} is outside zone '{}' "
                        "subnet {}/{}",
                        d.range_start, d.range_end, zone,
                        FormatIpv4(subnet->Network()),
                        subnet->bits),
            "the pool has to be on the segment the server answers "
            "on");
      }

      std::set<std::string> macs;
      for (const auto& r : d.reservations) {
        if (!IsMacAddress(r.mac)) {
          Err("SC027", r.span,
              std::format("reservation '{}' is not a MAC address",
                          r.mac));
          continue;
        }
        if (!macs.insert(r.mac).second) {
          Err("SC027", r.span,
              std::format("duplicate reservation for {}", r.mac));
        }
        auto a = ParseIpv4(r.address);
        if (!a) {
          Err("SC027", r.span,
              std::format("reservation {}: '{}' is not an IPv4 "
                          "address",
                          r.mac, r.address));
          continue;
        }
        if (!subnet->Contains(*a)) {
          Err("SC027", r.span,
              std::format("reservation {} -> {} is outside zone "
                          "'{}' subnet {}/{}",
                          r.mac, r.address, zone,
                          FormatIpv4(subnet->Network()),
                          subnet->bits));
        }
      }
    }
  }

  auto CheckDns() -> void {
    std::set<std::string> zones_served;
    for (const auto& d : cfg_.dns) {
      const auto& zone = d.bind.zone;
      if (zone.empty() || cfg_.FindZone(zone) == nullptr) continue;
      if (!zones_served.insert(zone).second) {
        Err("SC028", d.bind.span,
            std::format("more than one dns forwarder bound to zone "
                        "'{}'",
                        zone));
      }
      for (const auto& u : d.upstreams) {
        if (!ParseIpv4(u)) {
          Err("SC028", d.bind.span,
              std::format("dns upstream '{}' is not an IPv4 "
                          "address",
                          u));
        }
      }
    }
  }

  auto CheckIpv6() -> void {
    for (const auto& z : cfg_.zones) {
      if (z.ipv6 != Ipv6Stance::kRouterAdvertise) continue;
      if (!cfg_.ZoneServesDhcp(z.name)) {
        Err("SC029", z.span,
            std::format("zone '{}' asks for IPv6 router "
                        "advertisements but has no dhcp service to "
                        "send them",
                        z.name),
            "router advertisements come from the same daemon; bind "
            "a dhcp service to this zone or set ipv6: off");
      }
    }
  }
};

}  // namespace

auto Validate(const SystemConfig& cfg) -> ValidationResult {
  return Validator(cfg).Run();
}

}  // namespace f::sysconfig
