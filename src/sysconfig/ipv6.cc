/// @file ipv6.cc
/// @brief Render, install and observe the per-zone IPv6 stance.

#include "f/sysconfig/ipv6.h"

#include <algorithm>
#include <filesystem>
#include <format>
#include <fstream>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "f/sysconfig/artifact.h"
#include "f/sysconfig/net.h"

namespace f::sysconfig {
namespace {

/// Read a whole small file. Empty optional means "could not read",
/// which is never conflated with "read, and it was empty".
auto ReadFile(const std::string& path)
    -> std::optional<std::string> {
  std::ifstream in(path);
  if (!in) return std::nullopt;
  std::ostringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

/// The prefix advertised into a zone: the first interface in it that
/// carries a v6 address.
auto ZonePrefix6(const SystemConfig& cfg, const std::string& zone)
    -> std::string {
  for (const auto* i : cfg.InterfacesInZone(zone)) {
    if (i->address6.empty()) continue;
    auto p = ParseCidr6(i->address6);
    if (p) return p->NetworkString();
  }
  return "";
}

/// Expand `/proc/net/if_inet6`'s 32 hex digits into a printable
/// address. The file gives no colons and no compression, so this does
/// the grouping and leaves compression alone — an operator reading
/// "2001:0db8:..." still recognises it, and never mistaking two
/// spellings for two addresses matters more than looking tidy.
auto ExpandHexAddress(const std::string& hex) -> std::string {
  if (hex.size() != 32) return hex;
  std::string out;
  for (std::size_t i = 0; i < 32; i += 4) {
    if (i != 0) out.push_back(':');
    out += hex.substr(i, 4);
  }
  return out;
}

}  // namespace

auto Ipv6AvailabilityName(Ipv6Availability a) -> std::string {
  switch (a) {
    case Ipv6Availability::kObserved:
      return "observed";
    case Ipv6Availability::kNoInterfaces:
      return "no interfaces are declared";
    case Ipv6Availability::kCountersUnreadable:
      break;
  }
  return "the kernel's counters could not be read";
}

auto PlanIpv6(const SystemConfig& cfg) -> Ipv6Plan {
  Ipv6Plan plan;
  plan.forwarding = cfg.AnyZoneWantsIpv6();

  for (const auto& iface : cfg.interfaces) {
    if (iface.name.empty()) continue;
    Ipv6InterfaceIntent intent;
    intent.interface = iface.name;
    intent.zone = iface.zone;
    intent.stance = cfg.StanceOf(iface);
    // No stance we currently allow takes an address from somebody
    // else's advertisement. `off` refuses because v6 is not wanted
    // here; `ra` refuses because we are the router on this segment and
    // a router that autoconfigures from a peer has just been told what
    // to do by whoever shouted last.
    intent.accepts_ra = false;
    intent.sends_ra =
        intent.stance == Ipv6Stance::kRouterAdvertise;
    if (intent.sends_ra) {
      intent.advertised_prefix = ZonePrefix6(cfg, iface.zone);
    }
    plan.interfaces.push_back(intent);
  }

  std::ostringstream o;
  o << "# IPv6 stance for the f appliance, per zone.\n"
    << "#\n"
    << "# GENERATED FROM THE SYSTEM CONFIGURATION MODEL.\n"
    << "# Do not edit. Edits are reported as drift, not merged.\n"
    << "#\n"
    << "# `off` is enforced here rather than merely declared: an RA\n"
    << "# arriving on one of these ports is received, counted and\n"
    << "# then ignored. accept_ra=0 is chosen over disable_ipv6=1 on\n"
    << "# purpose — both refuse the RA, but disable_ipv6 drops the\n"
    << "# frame before ICMPv6 accounting, which would make the box\n"
    << "# safe and blind at the same time. `f show ipv6` reads the\n"
    << "# counter this setting preserves.\n"
    << "\n";

  o << "# --- global "
       "-------------------------------------------------\n";
  if (plan.forwarding) {
    o << "# a zone asks for v6, so the box is a v6 router\n";
    o << "net.ipv6.conf.all.forwarding = 1\n";
  } else {
    o << "# no zone asks for v6, so the box forwards none of it\n";
    o << "net.ipv6.conf.all.forwarding = 0\n";
  }
  // An interface nobody declared still exists, and the default the
  // distribution ships is "autoconfigure from whatever you hear".
  o << "net.ipv6.conf.default.accept_ra = 0\n";
  o << "net.ipv6.conf.default.autoconf = 0\n";
  o << "net.ipv6.conf.all.accept_ra = 0\n";
  o << "net.ipv6.conf.all.autoconf = 0\n";
  o << "\n";

  o << "# --- per interface "
       "------------------------------------------\n";
  for (const auto& i : plan.interfaces) {
    o << std::format("# {} — zone {} — ipv6 {}\n", i.interface,
                     i.zone.empty() ? "(none)" : i.zone,
                     Ipv6StanceName(i.stance));
    o << std::format("net.ipv6.conf.{}.accept_ra = 0\n",
                     i.interface);
    o << std::format("net.ipv6.conf.{}.autoconf = 0\n", i.interface);
    // accept_ra_defrtr/pinfo are the two halves an RA can still act
    // through on kernels where accept_ra is flipped back by another
    // agent. Setting them costs nothing and removes the dependency on
    // one sysctl staying where we put it.
    o << std::format("net.ipv6.conf.{}.accept_ra_defrtr = 0\n",
                     i.interface);
    o << std::format("net.ipv6.conf.{}.accept_ra_pinfo = 0\n",
                     i.interface);
    if (i.stance == Ipv6Stance::kOff) {
      // Nothing here is v6, so a solicitation is noise as well.
      o << std::format("net.ipv6.conf.{}.forwarding = 0\n",
                       i.interface);
    } else {
      o << std::format("net.ipv6.conf.{}.forwarding = 1\n",
                       i.interface);
    }
    o << "\n";
  }
  if (plan.interfaces.empty()) {
    o << "# (no interfaces are declared)\n";
  }

  plan.sysctl_content = WrapWithDigest(o.str());
  return plan;
}

auto Ipv6Report::Violations() const -> std::vector<std::string> {
  std::vector<std::string> out;
  for (const auto& i : interfaces) {
    if (i.intent.stance != Ipv6Stance::kOff) continue;
    if (i.global_addresses.empty()) continue;
    out.push_back(std::format(
        "{} (zone {}) is ipv6 off but holds {}", i.intent.interface,
        i.intent.zone.empty() ? "(none)" : i.intent.zone,
        i.global_addresses.front()));
  }
  return out;
}

auto Ipv6Report::RefusedRas() const -> std::uint64_t {
  std::uint64_t total = 0;
  for (const auto& i : interfaces) {
    if (i.intent.stance == Ipv6Stance::kOff) {
      total += i.ras_received;
    }
  }
  return total;
}

auto ObserveIpv6(const SystemConfig& cfg, const Ipv6Source& src)
    -> Ipv6Report {
  Ipv6Report report;
  auto plan = PlanIpv6(cfg);

  if (plan.interfaces.empty()) {
    report.availability = Ipv6Availability::kNoInterfaces;
    return report;
  }

  auto fwd = ReadFile(src.forwarding_path);
  report.forwarding = fwd.has_value() && fwd->find('1') == 0;

  // Global addresses, keyed by interface. Scope 0 is global; the
  // link-local a port always has is scope 0x20 and is not evidence of
  // anything, so counting it would make every port look violated.
  std::vector<std::pair<std::string, std::string>> globals;
  if (auto inet6 = ReadFile(src.if_inet6_path); inet6) {
    std::istringstream lines(*inet6);
    std::string line;
    while (std::getline(lines, line)) {
      std::istringstream f(line);
      std::string hex, index, plen, scope, flags, name;
      if (!(f >> hex >> index >> plen >> scope >> flags >> name)) {
        continue;
      }
      if (scope != "00") continue;
      globals.emplace_back(name, ExpandHexAddress(hex));
    }
  }

  bool any_read = false;
  for (const auto& intent : plan.interfaces) {
    Ipv6InterfaceObservation obs;
    obs.intent = intent;

    auto snmp = ReadFile(
        std::format("{}/{}", src.snmp6_dir, intent.interface));
    if (snmp) {
      obs.counters_read = true;
      any_read = true;
      std::istringstream lines(*snmp);
      std::string key;
      std::uint64_t value = 0;
      while (lines >> key >> value) {
        if (key == "Icmp6InRouterAdvertisements") {
          obs.ras_received = value;
        } else if (key == "Ip6InReceives") {
          obs.v6_received = value;
        } else if (key == "Ip6InDiscards") {
          obs.v6_discarded = value;
        }
      }
    }

    for (const auto& [name, addr] : globals) {
      if (name == intent.interface) {
        obs.global_addresses.push_back(addr);
      }
    }
    report.interfaces.push_back(std::move(obs));
  }

  report.availability = any_read
                            ? Ipv6Availability::kObserved
                            : Ipv6Availability::kCountersUnreadable;
  return report;
}

auto ApplyIpv6(const SystemConfig& cfg, const Ipv6Options& opts)
    -> std::expected<Ipv6ApplyReport, std::string> {
  auto plan = PlanIpv6(cfg);
  auto drift = CheckArtifactDrift(opts.sysctl_path,
                                  plan.sysctl_content);
  if (opts.refuse_on_drift && drift == DriftKind::kHandEdited) {
    return std::unexpected(std::format(
        "{} was edited by hand. It is a generated artifact, so the "
        "edit would be lost: fold the change into the system "
        "config, or re-apply with force to discard it.",
        opts.sysctl_path));
  }

  Ipv6ApplyReport report;
  report.sysctl_path = opts.sysctl_path;
  report.plan = plan;

  auto installed = InstallArtifact(opts.sysctl_path,
                                   plan.sysctl_content);
  if (!installed) return std::unexpected(installed.error());
  report.changed = *installed;

  if (opts.proc_sys_root.empty()) return report;

  // Push live. A file in sysctl.d is applied at boot and on device
  // appearance; an operator who just changed the stance is entitled to
  // have it be true now. Every setting either lands in `applied_live`
  // or lands in `failed_live` with its reason — there is no third
  // outcome where a stance quietly did not take.
  auto poke = [&](const std::string& dotted,
                  const std::string& value) {
    std::string path = opts.proc_sys_root;
    if (!path.empty() && path.back() != '/') path.push_back('/');
    for (char c : dotted) path.push_back(c == '.' ? '/' : c);
    std::ofstream out(path);
    if (!out) {
      report.failed_live.push_back(
          std::format("{}={} ({}: not writable)", dotted, value,
                      path));
      return;
    }
    out << value;
    out.flush();
    if (!out) {
      report.failed_live.push_back(std::format(
          "{}={} ({}: write failed)", dotted, value, path));
      return;
    }
    report.applied_live.push_back(
        std::format("{}={}", dotted, value));
  };

  poke("net.ipv6.conf.all.forwarding", plan.forwarding ? "1" : "0");
  poke("net.ipv6.conf.default.accept_ra", "0");
  poke("net.ipv6.conf.default.autoconf", "0");
  for (const auto& i : plan.interfaces) {
    poke(std::format("net.ipv6.conf.{}.accept_ra", i.interface), "0");
    poke(std::format("net.ipv6.conf.{}.autoconf", i.interface), "0");
    poke(std::format("net.ipv6.conf.{}.accept_ra_defrtr",
                     i.interface),
         "0");
    poke(std::format("net.ipv6.conf.{}.accept_ra_pinfo", i.interface),
         "0");
    poke(std::format("net.ipv6.conf.{}.forwarding", i.interface),
         i.stance == Ipv6Stance::kOff ? "0" : "1");
  }
  return report;
}

}  // namespace f::sysconfig
