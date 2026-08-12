/// @file networkd.cc
/// @brief Generate systemd-networkd .link and .network units.

#include "f/sysconfig/networkd.h"

#include <format>
#include <sstream>
#include <string>
#include <vector>

namespace f::sysconfig {
namespace {

constexpr const char* kBanner =
    "# GENERATED FROM THE f SYSTEM CONFIGURATION MODEL.\n"
    "# Do not edit; edits are reported as drift, not merged.\n";

/// The .link unit: hardware identity -> durable name.
auto RenderLink(const Interface& iface) -> std::string {
  std::ostringstream o;
  o << kBanner;
  o << std::format("# pins '{}' to the port it was assigned to.\n\n",
                   iface.name);
  o << "[Match]\n";
  if (iface.match.kind == MatchKind::kMac) {
    o << "MACAddress=" << iface.match.value << "\n";
  } else {
    o << "Path=" << iface.match.value << "\n";
  }
  o << "\n[Link]\n";
  o << "Name=" << iface.name << "\n";
  // Without this systemd may apply its own naming policy first and
  // win the race with Name=.
  o << "NamePolicy=\n";
  return o.str();
}

/// The .network unit: addressing for an already-named interface.
auto RenderNetwork(const Interface& iface) -> std::string {
  std::ostringstream o;
  o << kBanner;
  o << std::format("# zone: {}\n\n",
                   iface.zone.empty() ? "(none)" : iface.zone);
  o << "[Match]\n";
  o << "Name=" << iface.name << "\n\n";
  o << "[Network]\n";
  switch (iface.mode) {
    case AddressMode::kDhcpClient:
      o << "DHCP=ipv4\n";
      // The uplink hands us a default route; a testnet must not.
      o << "IPv6AcceptRA=no\n";
      break;
    case AddressMode::kStatic:
      o << "Address=" << iface.address << "\n";
      o << "IPv6AcceptRA=no\n";
      if (!iface.gateway.empty()) {
        o << "Gateway=" << iface.gateway << "\n";
      }
      break;
    case AddressMode::kUnconfigured:
      // Link up, no L3. The normal state for a port that only carries
      // filtered traffic.
      o << "LinkLocalAddressing=no\n";
      o << "IPv6AcceptRA=no\n";
      break;
  }
  o << "ConfigureWithoutCarrier=yes\n";
  o << "\n[Link]\n";
  o << "RequiredForOnline=no\n";
  return o.str();
}

}  // namespace

auto PlanNetworkd(const SystemConfig& cfg,
                  const NetworkdOptions& opts)
    -> std::vector<NetworkdUnit> {
  std::vector<NetworkdUnit> units;
  for (const auto& iface : cfg.interfaces) {
    if (iface.name.empty()) continue;
    if (!iface.match.value.empty()) {
      units.push_back(
          {std::format("{}/10-f-{}.link", opts.dir, iface.name),
           WrapWithDigest(RenderLink(iface)), iface.name});
    }
    units.push_back(
        {std::format("{}/10-f-{}.network", opts.dir, iface.name),
         WrapWithDigest(RenderNetwork(iface)), iface.name});
  }
  return units;
}

auto CheckNetworkdDrift(const std::vector<NetworkdUnit>& units)
    -> std::vector<DriftKind> {
  std::vector<DriftKind> out;
  out.reserve(units.size());
  for (const auto& u : units) {
    out.push_back(CheckArtifactDrift(u.path, u.content));
  }
  return out;
}

auto ApplyNetworkd(const SystemConfig& cfg,
                   const NetworkdOptions& opts)
    -> std::expected<NetworkdReport, std::string> {
  auto units = PlanNetworkd(cfg, opts);
  auto drift = CheckNetworkdDrift(units);

  if (opts.refuse_on_drift) {
    std::string edited;
    for (std::size_t i = 0; i < units.size(); ++i) {
      if (drift[i] == DriftKind::kHandEdited) {
        edited += "\n  " + units[i].path;
      }
    }
    if (!edited.empty()) {
      return std::unexpected(std::format(
          "generated networkd units were edited by hand:{}\nFold "
          "the change into the system config, or re-apply with "
          "force to discard it.",
          edited));
    }
  }

  NetworkdReport report;
  report.units = units;
  for (const auto& u : units) {
    auto installed = InstallArtifact(u.path, u.content);
    if (!installed) return std::unexpected(installed.error());
    if (*installed) report.changed.push_back(u.path);
  }
  return report;
}

}  // namespace f::sysconfig
