/// @file networkd.cc
/// @brief Generate systemd-networkd .link and .network units.

#include "f/sysconfig/networkd.h"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <format>
#include <fstream>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace f::sysconfig {
namespace {

namespace fs = std::filesystem;

auto Lower(std::string s) -> std::string {
  for (auto& c : s) {
    c = static_cast<char>(
        std::tolower(static_cast<unsigned char>(c)));
  }
  return s;
}

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
///
/// `stance` is the zone's IPv6 stance, and it decides two things no
/// v4 key can: whether this port takes an address from somebody else's
/// router advertisement, and whether it carries a v6 address of its
/// own. Neither is inferred from the v4 address mode — an uplink that
/// is a v4 DHCP client is exactly the port an office RA arrives on.
auto RenderNetwork(const Interface& iface, Ipv6Stance stance)
    -> std::string {
  std::ostringstream o;
  o << kBanner;
  o << std::format("# zone: {}   ipv6: {}\n\n",
                   iface.zone.empty() ? "(none)" : iface.zone,
                   Ipv6StanceName(stance));
  o << "[Match]\n";
  o << "Name=" << iface.name << "\n\n";
  o << "[Network]\n";
  switch (iface.mode) {
    case AddressMode::kDhcpClient:
      o << "DHCP=ipv4\n";
      break;
    case AddressMode::kStatic:
      o << "Address=" << iface.address << "\n";
      if (!iface.gateway.empty()) {
        o << "Gateway=" << iface.gateway << "\n";
      }
      break;
    case AddressMode::kUnconfigured:
      // Link up, no v4. The normal state for a port that only carries
      // filtered traffic.
      break;
  }

  // v6 is decided by the stance and by nothing else. No stance we
  // allow accepts an RA: `off` because v6 is not wanted here, `ra`
  // because we are the router on this segment and a router that
  // autoconfigures from a peer has been told what to do by whoever
  // shouted last.
  o << "IPv6AcceptRA=no\n";
  if (!iface.address6.empty()) {
    o << "Address=" << iface.address6 << "\n";
  }
  if (stance == Ipv6Stance::kOff) {
    // A port with no v6 address of its own and no v4 address has no
    // reason to hold a link-local either. Where there IS a v4
    // address the link-local stays: the kernel keeps the ICMPv6
    // counters that `f show ipv6` reads only for an interface that
    // still receives v6, and a refusal nobody can count is
    // indistinguishable from a network that never spoke.
    if (iface.mode == AddressMode::kUnconfigured &&
        iface.address6.empty()) {
      o << "LinkLocalAddressing=no\n";
    } else {
      o << "LinkLocalAddressing=ipv6\n";
    }
    o << "IPv6SendRA=no\n";
  } else {
    o << "LinkLocalAddressing=ipv6\n";
    // We advertise, but through dnsmasq, which is the one daemon that
    // knows the zone's prefix and its DNS answer. Two RA sources on
    // one segment is a race whose winner decides the network.
    o << "IPv6SendRA=no\n";
    o << "IPForward=ipv6\n";
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
         WrapWithDigest(RenderNetwork(iface, cfg.StanceOf(iface))),
         iface.name});
  }
  return units;
}

auto ScanLinkUnits(const std::string& dir) -> std::vector<LinkClaim> {
  std::vector<LinkClaim> out;
  std::error_code ec;
  fs::directory_iterator it(dir, ec);
  if (ec) return out;
  for (const auto& entry : it) {
    if (entry.path().extension() != ".link") continue;
    std::ifstream in(entry.path());
    if (!in) continue;
    LinkClaim claim;
    claim.path = entry.path().string();
    claim.generated = ArtifactIsGenerated(claim.path);
    std::string line;
    while (std::getline(in, line)) {
      auto trimmed = Trim(line);
      if (trimmed.rfind("MACAddress=", 0) == 0) {
        claim.mac = Lower(Trim(trimmed.substr(11)));
      } else if (trimmed.rfind("Name=", 0) == 0) {
        claim.name = Trim(trimmed.substr(5));
      }
    }
    out.push_back(std::move(claim));
  }
  std::sort(out.begin(), out.end(),
            [](const LinkClaim& a, const LinkClaim& b) {
              return a.path < b.path;
            });
  return out;
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

  // Sweep. An interface that left the model leaves its units behind,
  // and a leftover `.link` does not merely sit there: udev applies
  // `.link` files in lexical filename order, so a stale one whose name
  // sorts first silently wins the rename for a MAC the current model
  // pins somewhere else. The port then never gets its configured name,
  // every generated file that names it matches no device, and nothing
  // logs an error.
  std::set<std::string> planned;
  for (const auto& u : units) planned.insert(u.path);
  {
    std::error_code ec;
    fs::directory_iterator it(opts.dir, ec);
    if (!ec) {
      std::vector<std::string> ours;
      for (const auto& entry : it) {
        auto name = entry.path().filename().string();
        if (name.rfind("10-f-", 0) != 0) continue;
        auto ext = entry.path().extension().string();
        if (ext != ".link" && ext != ".network") continue;
        auto path = entry.path().string();
        if (planned.count(path) != 0) continue;
        // Only files carrying our digest header are ours to delete.
        // Anything else with the same name prefix was written by a
        // person, and a person's file is reported, never removed.
        if (!ArtifactIsGenerated(path)) {
          report.conflicts.push_back(path);
          continue;
        }
        ours.push_back(path);
      }
      std::sort(ours.begin(), ours.end());
      for (const auto& path : ours) {
        std::error_code rm;
        if (fs::remove(path, rm)) report.removed.push_back(path);
      }
    }
  }

  // Anything left in the directory that pins one of our MACs to a
  // different name still decides the rename, and it is not ours to
  // delete. Refuse instead: a policy aimed at the wrong port is a
  // bypass, and a warning at the bottom of a screen is not a defence.
  std::string clash;
  for (const auto& claim : ScanLinkUnits(opts.dir)) {
    if (planned.count(claim.path) != 0) continue;
    if (claim.mac.empty()) continue;
    for (const auto& iface : cfg.interfaces) {
      if (iface.match.kind != MatchKind::kMac) continue;
      if (Lower(iface.match.value) != claim.mac) continue;
      if (claim.name == iface.name) continue;
      report.conflicts.push_back(claim.path);
      clash += std::format(
          "\n  {} pins {} to '{}', but the system configuration pins "
          "it to '{}'",
          claim.path, claim.mac, claim.name, iface.name);
    }
  }
  if (!clash.empty() && opts.refuse_on_drift) {
    return std::unexpected(std::format(
        "another .link unit claims a port this configuration also "
        "claims:{}\nudev applies .link files in filename order, so "
        "whichever name sorts first wins and the loser is silent. "
        "Remove the other unit, or re-apply with force to proceed "
        "anyway.",
        clash));
  }
  std::sort(report.conflicts.begin(), report.conflicts.end());
  report.conflicts.erase(
      std::unique(report.conflicts.begin(), report.conflicts.end()),
      report.conflicts.end());
  return report;
}

}  // namespace f::sysconfig
