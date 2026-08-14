/// @file model.cc
/// @brief Accessors over the system config model.

#include "f/sysconfig/model.h"

#include <algorithm>
#include <format>

namespace f::sysconfig {

auto SystemConfig::InterfacesInZone(const std::string& zone) const
    -> std::vector<const Interface*> {
  std::vector<const Interface*> out;
  if (zone.empty()) return out;
  for (const auto& iface : interfaces) {
    if (iface.zone == zone) out.push_back(&iface);
  }
  return out;
}

auto SystemConfig::InterfaceNamesInZone(
    const std::string& zone) const -> std::vector<std::string> {
  std::vector<std::string> out;
  for (const auto* iface : InterfacesInZone(zone)) {
    out.push_back(iface->name);
  }
  return out;
}

auto SystemConfig::AllInterfaceNames() const
    -> std::vector<std::string> {
  std::vector<std::string> out;
  out.reserve(interfaces.size());
  for (const auto& iface : interfaces) out.push_back(iface.name);
  return out;
}

auto SystemConfig::FindZone(const std::string& name) const
    -> const Zone* {
  for (const auto& z : zones) {
    if (z.name == name) return &z;
  }
  return nullptr;
}

auto SystemConfig::FindInterface(const std::string& name) const
    -> const Interface* {
  for (const auto& i : interfaces) {
    if (i.name == name) return &i;
  }
  return nullptr;
}

auto SystemConfig::ZoneServesDhcp(const std::string& zone) const
    -> bool {
  if (zone.empty()) return false;
  return std::any_of(dhcp.begin(), dhcp.end(),
                     [&](const DhcpServer& d) {
                       return d.bind.zone == zone;
                     });
}

auto SystemConfig::ZoneHasService(const std::string& zone) const
    -> bool {
  if (zone.empty()) return false;
  if (ZoneServesDhcp(zone)) return true;
  return std::any_of(dns.begin(), dns.end(),
                     [&](const DnsForwarder& d) {
                       return d.bind.zone == zone;
                     });
}

auto SystemConfig::StanceOf(const Interface& iface) const
    -> Ipv6Stance {
  const auto* z = FindZone(iface.zone);
  return z != nullptr ? z->ipv6 : Ipv6Stance::kOff;
}

auto SystemConfig::AnyZoneWantsIpv6() const -> bool {
  return std::any_of(zones.begin(), zones.end(), [](const Zone& z) {
    return z.ipv6 != Ipv6Stance::kOff;
  });
}

auto Diagnostic::Format() const -> std::string {
  const char* level = severity == Severity::kError ? "error"
                                                   : "warning";
  std::string head;
  if (span.line > 0) {
    head = std::format("{}[{}]: {}:{}: {}", level, code, span.line,
                       span.column, message);
  } else {
    head = std::format("{}[{}]: {}", level, code, message);
  }
  if (!hint.empty()) head += std::format("\n  hint: {}", hint);
  return head;
}

auto ValidationResult::HasErrors() const -> bool {
  return std::any_of(diagnostics.begin(), diagnostics.end(),
                     [](const Diagnostic& d) {
                       return d.severity == Severity::kError;
                     });
}

auto ValidationResult::Errors() const -> std::vector<Diagnostic> {
  std::vector<Diagnostic> out;
  for (const auto& d : diagnostics) {
    if (d.severity == Severity::kError) out.push_back(d);
  }
  return out;
}

auto AddressModeName(AddressMode m) -> std::string {
  switch (m) {
    case AddressMode::kStatic:
      return "static";
    case AddressMode::kDhcpClient:
      return "dhcp";
    case AddressMode::kUnconfigured:
      break;
  }
  return "none";
}

auto Ipv6StanceName(Ipv6Stance s) -> std::string {
  switch (s) {
    case Ipv6Stance::kRouterAdvertise:
      return "ra";
    case Ipv6Stance::kFull:
      return "full";
    case Ipv6Stance::kOff:
      break;
  }
  return "off";
}

}  // namespace f::sysconfig
