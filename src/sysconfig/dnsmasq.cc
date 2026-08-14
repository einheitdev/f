/// @file dnsmasq.cc
/// @brief Render, check and install the dnsmasq artifact.

#include "f/sysconfig/dnsmasq.h"

#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <cctype>
#include <cstdio>
#include <filesystem>
#include <format>
#include <fstream>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "f/lease/lease.h"
#include "f/sysconfig/artifact.h"
#include "f/sysconfig/net.h"
#include "f/sysconfig/validate.h"

namespace f::sysconfig {
namespace {

auto RunCapture(const std::string& cmd)
    -> std::pair<int, std::string> {
  std::string out;
  FILE* p = popen((cmd + " 2>&1").c_str(), "r");
  if (p == nullptr) return {-1, "popen failed"};
  std::array<char, 512> buf{};
  while (std::fgets(buf.data(), buf.size(), p) != nullptr) {
    out += buf.data();
  }
  int rc = pclose(p);
  if (rc == -1) return {-1, out};
  return {WIFEXITED(rc) ? WEXITSTATUS(rc) : -1, out};
}

/// The zone's own presence on the segment: prefix plus bare address.
auto ZoneSubnet(const SystemConfig& cfg, const std::string& zone)
    -> std::optional<std::pair<Prefix4, std::string>> {
  for (const auto* i : cfg.InterfacesInZone(zone)) {
    if (i->mode != AddressMode::kStatic) continue;
    auto p = ParseCidr4(i->address);
    if (p) {
      auto slash = i->address.find('/');
      return std::make_pair(*p, i->address.substr(0, slash));
    }
  }
  return std::nullopt;
}

/// dnsmasq tags are [A-Za-z0-9_-]; zone names come from the config so
/// sanitise rather than trust.
auto ZoneTag(const std::string& zone) -> std::string {
  std::string t = "zone_";
  for (char c : zone) {
    t.push_back((std::isalnum(static_cast<unsigned char>(c)) != 0 ||
                 c == '_' || c == '-')
                    ? c
                    : '_');
  }
  return t;
}

}  // namespace

auto PlanDnsmasq(const SystemConfig& cfg) -> DnsmasqPlan {
  DnsmasqPlan plan;

  // Placement is derived here and nowhere else. `allowed` is the union
  // of the interfaces of every zone that has a service bound;
  // `dhcp_ok` is the narrower union over zones with a DHCP server. An
  // interface in neither set is named explicitly in the exclusion list
  // below rather than merely left out, so the artifact states its own
  // containment instead of implying it.
  std::set<std::string> allowed;
  std::set<std::string> dhcp_ok;
  for (const auto& z : cfg.zones) {
    if (!cfg.ZoneHasService(z.name)) continue;
    bool serves_dhcp = cfg.ZoneServesDhcp(z.name);
    for (const auto& n : cfg.InterfaceNamesInZone(z.name)) {
      allowed.insert(n);
      if (serves_dhcp) dhcp_ok.insert(n);
    }
  }
  for (const auto& n : cfg.AllInterfaceNames()) {
    if (allowed.count(n) != 0) {
      plan.allowed_interfaces.push_back(n);
    } else {
      plan.excluded_interfaces.push_back(n);
    }
    if (dhcp_ok.count(n) != 0) plan.dhcp_interfaces.push_back(n);
  }
  plan.needed = !allowed.empty();

  std::ostringstream o;
  o << "# dnsmasq configuration for the f appliance.\n"
    << "#\n"
    << "# GENERATED FROM THE SYSTEM CONFIGURATION MODEL.\n"
    << "# Do not edit. Edits are not merged back; they are "
       "reported as\n"
    << "# drift, and the running daemon keeps the last good "
       "artifact.\n"
    << "#\n"
    << "# Every interface= line below was derived from zone "
       "membership.\n"
    << "# No key in the system config names an interface for a "
       "service.\n"
    << "\n";

  o << "# --- containment "
       "---------------------------------------------\n";
  // bind-dynamic binds per interface rather than a wildcard socket,
  // while still coping with a port that appears after the daemon
  // starts — on an appliance that is the normal case.
  o << "bind-dynamic\n";
  for (const auto& n : plan.allowed_interfaces) {
    o << "interface=" << n << "\n";
  }
  for (const auto& n : plan.excluded_interfaces) {
    o << "except-interface=" << n << "\n";
  }
  // DHCP containment is enforced by dnsmasq per received packet, not
  // by socket binding, so name every non-DHCP interface explicitly.
  {
    std::set<std::string> dhcp_set(plan.dhcp_interfaces.begin(),
                                   plan.dhcp_interfaces.end());
    for (const auto& n : cfg.AllInterfaceNames()) {
      if (dhcp_set.count(n) == 0) {
        o << "no-dhcp-interface=" << n << "\n";
      }
    }
  }
  o << "\n";

  o << "# --- dns "
       "-----------------------------------------------------\n";
  if (cfg.dns.empty()) {
    o << "# no dns forwarder is bound to any zone\n";
    o << "port=0\n";
  } else {
    o << "domain-needed\n";
    o << "bogus-priv\n";
    for (const auto& d : cfg.dns) {
      o << "# zone " << d.bind.zone << "\n";
      if (d.stop_dns_rebind) o << "stop-dns-rebind\n";
      if (!d.upstreams.empty()) {
        o << "no-resolv\n";
        for (const auto& u : d.upstreams) {
          o << "server=" << u << "\n";
        }
      }
    }
  }
  o << "\n";

  o << "# --- dhcp "
       "----------------------------------------------------\n";
  if (cfg.dhcp.empty()) {
    o << "# no dhcp server is bound to any zone\n";
  } else {
    o << "dhcp-authoritative\n";
    // The reader of this file is `show leases`; both sides name the
    // path from the same constant so they cannot drift apart.
    o << "dhcp-leasefile=" << lease::kLeaseFilePath << "\n";
    for (const auto& d : cfg.dhcp) {
      const auto& zone = d.bind.zone;
      auto names = cfg.InterfaceNamesInZone(zone);
      o << "# zone " << zone << " -> ";
      for (std::size_t i = 0; i < names.size(); ++i) {
        o << (i != 0 ? ", " : "") << names[i];
      }
      if (names.empty()) o << "(no interfaces)";
      o << "\n";
      auto subnet = ZoneSubnet(cfg, zone);
      if (!subnet) {
        o << "# refused: zone has no statically addressed "
             "interface\n";
        continue;
      }
      auto tag = ZoneTag(zone);
      o << std::format("dhcp-range=set:{},{},{},{},{}\n", tag,
                       d.range_start, d.range_end,
                       subnet->first.Netmask(), d.lease_seconds);
      o << std::format("dhcp-option=tag:{},option:router,{}\n", tag,
                       subnet->second);
      if (d.dns_servers.empty()) {
        o << std::format(
            "dhcp-option=tag:{},option:dns-server,{}\n", tag,
            subnet->second);
      } else {
        o << std::format("dhcp-option=tag:{},option:dns-server",
                         tag);
        for (const auto& s : d.dns_servers) o << "," << s;
        o << "\n";
      }
      const auto* z = cfg.FindZone(zone);
      if (z != nullptr && z->ipv6 == Ipv6Stance::kRouterAdvertise) {
        o << "enable-ra\n";
      }
      for (const auto& r : d.reservations) {
        o << "dhcp-host=" << r.mac << "," << r.address;
        if (!r.hostname.empty()) o << "," << r.hostname;
        o << "\n";
      }
    }
  }

  plan.content = WrapWithDigest(o.str());
  return plan;
}

auto CheckWithDnsmasq(const std::string& content,
                      const std::string& dnsmasq_path)
    -> std::expected<std::string, Error<BackendError>> {
  std::error_code ec;
  if (!std::filesystem::exists(dnsmasq_path, ec)) {
    return MakeError(
        BackendError::kToolMissing,
        std::format("dnsmasq not found at {}", dnsmasq_path));
  }
  auto tmp = std::filesystem::temp_directory_path() /
             std::format("f-dnsmasq-check-{}.conf", ::getpid());
  {
    std::ofstream out(tmp);
    if (!out) {
      return MakeError(
          BackendError::kWriteFailed,
          std::format("cannot write {}", tmp.string()));
    }
    out << content;
  }
  auto [rc, output] = RunCapture(std::format(
      "{} --test --conf-file={}", dnsmasq_path, tmp.string()));
  std::filesystem::remove(tmp, ec);
  if (rc != 0) {
    return MakeError(
        BackendError::kToolRejected,
        std::format("dnsmasq rejected the generated config: {}",
                    output));
  }
  return output;
}

auto CheckDnsmasqDrift(const SystemConfig& cfg,
                       const std::string& path) -> DriftKind {
  return CheckArtifactDrift(path, PlanDnsmasq(cfg).content);
}

auto ApplyDnsmasq(const SystemConfig& cfg,
                  const DnsmasqOptions& opts)
    -> std::expected<ApplyReport, Error<BackendError>> {
  auto vr = Validate(cfg);
  if (vr.HasErrors()) {
    std::string msg = "system config does not validate:";
    for (const auto& e : vr.Errors()) msg += "\n  " + e.Format();
    return MakeError(BackendError::kModelInvalid, msg);
  }

  auto plan = PlanDnsmasq(cfg);
  auto drift = CheckArtifactDrift(opts.conf_path, plan.content);
  if (opts.refuse_on_drift && drift == DriftKind::kHandEdited) {
    return MakeError(
        BackendError::kDrift,
        std::format(
            "{} was edited by hand. It is a generated artifact, so "
            "the edit would be lost: fold the change into the "
            "system config, or re-apply with force to discard it.",
            opts.conf_path));
  }

  auto check = CheckWithDnsmasq(plan.content, opts.dnsmasq_path);
  if (!check) return std::unexpected(check.error());

  ApplyReport report;
  report.conf_path = opts.conf_path;
  report.check_output = *check;
  report.plan = plan;

  auto installed = InstallArtifact(opts.conf_path, plan.content);
  if (!installed) {
    return MakeError(BackendError::kWriteFailed, installed.error());
  }
  report.changed = *installed;
  return report;
}

}  // namespace f::sysconfig
