/// @file parse.cc
/// @brief YAML -> SystemConfig, with located diagnostics.

#include "f/sysconfig/parse.h"

#include <filesystem>
#include <format>
#include <fstream>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include <yaml-cpp/yaml.h>

#include "f/sysconfig/net.h"

namespace f::sysconfig {
namespace {

auto SpanOf(const YAML::Node& n) -> Span {
  auto m = n.Mark();
  if (m.line < 0) return {};
  return {m.line + 1, m.column + 1};
}

/// Collects diagnostics as it walks the document. Parsing continues
/// past a recoverable problem so the operator sees every bad key in
/// one pass instead of one per edit-run cycle.
class Parser {
 public:
  auto Run(const YAML::Node& doc) -> SystemConfig {
    SystemConfig cfg;
    RequireMapKeys(doc, {"zones", "interfaces", "services"},
                   "top level");
    ParseZones(doc["zones"], &cfg);
    ParseInterfaces(doc["interfaces"], &cfg);
    ParseServices(doc["services"], &cfg);
    return cfg;
  }

  auto Diagnostics() const -> const std::vector<Diagnostic>& {
    return diags_;
  }

  auto Failed() const -> bool {
    for (const auto& d : diags_) {
      if (d.severity == Severity::kError) return true;
    }
    return false;
  }

 private:
  std::vector<Diagnostic> diags_;

  auto Err(const std::string& code, const Span& span,
           const std::string& msg, const std::string& hint = "")
      -> void {
    diags_.push_back({code, Severity::kError, msg, span, hint});
  }

  /// Reject any key not in `allowed`, located at the offending key.
  auto RequireMapKeys(const YAML::Node& n,
                      const std::set<std::string>& allowed,
                      const std::string& what) -> void {
    if (!n || !n.IsMap()) return;
    for (const auto& kv : n) {
      auto key = kv.first.as<std::string>("");
      if (allowed.count(key) == 0) {
        std::string list;
        for (const auto& a : allowed) {
          if (!list.empty()) list += ", ";
          list += a;
        }
        Err("SC101", SpanOf(kv.first),
            std::format("unknown key '{}' in {}", key, what),
            std::format("known keys: {}", list));
      }
    }
  }

  auto Str(const YAML::Node& n, const std::string& key)
      -> std::string {
    if (!n[key]) return "";
    return n[key].as<std::string>("");
  }

  auto ParseZones(const YAML::Node& n, SystemConfig* cfg) -> void {
    if (!n) return;
    if (!n.IsMap()) {
      Err("SC102", SpanOf(n),
          "zones must be a map of zone name -> settings");
      return;
    }
    for (const auto& kv : n) {
      Zone z;
      z.name = kv.first.as<std::string>("");
      z.span = SpanOf(kv.first);
      const auto& body = kv.second;
      if (body && body.IsMap()) {
        RequireMapKeys(body, {"ipv6"},
                       std::format("zone '{}'", z.name));
        auto v6 = Str(body, "ipv6");
        if (v6.empty() || v6 == "off" || v6 == "false") {
          z.ipv6 = Ipv6Stance::kOff;
        } else if (v6 == "ra") {
          z.ipv6 = Ipv6Stance::kRouterAdvertise;
        } else {
          Err("SC103", SpanOf(body["ipv6"]),
              std::format("zone '{}': unknown ipv6 stance '{}'",
                          z.name, v6),
              "expected 'off' or 'ra'");
        }
      } else if (body && !body.IsNull()) {
        Err("SC102", SpanOf(body),
            std::format("zone '{}' must be a map or empty", z.name));
      }
      cfg->zones.push_back(z);
    }
  }

  auto ParseInterfaces(const YAML::Node& n, SystemConfig* cfg)
      -> void {
    if (!n) return;
    if (!n.IsMap()) {
      Err("SC102", SpanOf(n),
          "interfaces must be a map of name -> settings");
      return;
    }
    for (const auto& kv : n) {
      Interface iface;
      iface.name = kv.first.as<std::string>("");
      iface.span = SpanOf(kv.first);
      const auto& body = kv.second;
      if (!body || !body.IsMap()) {
        Err("SC102", SpanOf(body ? body : kv.first),
            std::format("interface '{}' must be a map",
                        iface.name));
        cfg->interfaces.push_back(iface);
        continue;
      }
      RequireMapKeys(
          body, {"mac", "path", "address", "gateway", "zone"},
          std::format("interface '{}'", iface.name));

      auto mac = Str(body, "mac");
      auto path = Str(body, "path");
      if (!mac.empty() && !path.empty()) {
        Err("SC104", SpanOf(body["path"]),
            std::format("interface '{}' has both mac and path",
                        iface.name),
            "pin a name to exactly one hardware identity");
      }
      if (!mac.empty()) {
        iface.match = {MatchKind::kMac, NormalizeMac(mac)};
      } else if (!path.empty()) {
        iface.match = {MatchKind::kPath, path};
      }

      auto addr = Str(body, "address");
      if (addr.empty() || addr == "none") {
        iface.mode = AddressMode::kUnconfigured;
      } else if (addr == "dhcp") {
        iface.mode = AddressMode::kDhcpClient;
      } else {
        iface.mode = AddressMode::kStatic;
        iface.address = addr;
      }
      iface.gateway = Str(body, "gateway");
      iface.zone = Str(body, "zone");
      cfg->interfaces.push_back(iface);
    }
  }

  auto ParseServices(const YAML::Node& n, SystemConfig* cfg)
      -> void {
    if (!n) return;
    if (!n.IsMap()) {
      Err("SC102", SpanOf(n),
          "services must be a map of service kind -> list");
      return;
    }
    RequireMapKeys(n, {"dhcp", "dns"}, "services");
    ParseDhcp(n["dhcp"], cfg);
    ParseDns(n["dns"], cfg);
  }

  /// A service body is a map. Note what is *not* in the allowed key
  /// set: there is no `interface`, `interfaces`, `listen` or `device`.
  /// Placement is `zone`, only ever `zone`.
  auto ParseDhcp(const YAML::Node& n, SystemConfig* cfg) -> void {
    if (!n) return;
    if (!n.IsSequence()) {
      Err("SC102", SpanOf(n), "services.dhcp must be a list");
      return;
    }
    for (const auto& item : n) {
      DhcpServer d;
      d.bind.span = SpanOf(item);
      if (!item.IsMap()) {
        Err("SC102", SpanOf(item),
            "each services.dhcp entry must be a map");
        continue;
      }
      RequireMapKeys(item,
                     {"zone", "range", "lease", "reservations",
                      "dns_servers"},
                     "services.dhcp entry");
      d.bind.zone = Str(item, "zone");
      if (item["zone"]) d.bind.span = SpanOf(item["zone"]);

      auto range = Str(item, "range");
      auto dash = range.find('-');
      if (range.empty()) {
        Err("SC105", d.bind.span,
            std::format("dhcp on zone '{}' has no range",
                        d.bind.zone),
            "range: <first>-<last>, e.g. 10.10.0.100-10.10.0.200");
      } else if (dash == std::string::npos) {
        Err("SC105", SpanOf(item["range"]),
            std::format("dhcp range '{}' is not <first>-<last>",
                        range));
      } else {
        d.range_start = range.substr(0, dash);
        d.range_end = range.substr(dash + 1);
      }

      auto lease = Str(item, "lease");
      if (!lease.empty()) {
        auto secs = ParseSeconds(lease);
        if (!secs) {
          Err("SC106", SpanOf(item["lease"]),
              std::format("bad lease duration '{}'", lease),
              "e.g. 600s, 30m, 12h, 2d");
        } else {
          d.lease_seconds = *secs;
        }
      }

      for (const auto& s : item["dns_servers"]) {
        d.dns_servers.push_back(s.as<std::string>(""));
      }

      if (item["reservations"] && !item["reservations"].IsSequence()) {
        Err("SC102", SpanOf(item["reservations"]),
            "reservations must be a list");
      }
      for (const auto& r : item["reservations"]) {
        Reservation res;
        res.span = SpanOf(r);
        if (!r.IsMap()) {
          Err("SC102", res.span,
              "each reservation must be a map");
          continue;
        }
        RequireMapKeys(r, {"mac", "address", "hostname"},
                       "reservation");
        res.mac = NormalizeMac(Str(r, "mac"));
        res.address = Str(r, "address");
        res.hostname = Str(r, "hostname");
        d.reservations.push_back(res);
      }
      cfg->dhcp.push_back(d);
    }
  }

  auto ParseDns(const YAML::Node& n, SystemConfig* cfg) -> void {
    if (!n) return;
    if (!n.IsSequence()) {
      Err("SC102", SpanOf(n), "services.dns must be a list");
      return;
    }
    for (const auto& item : n) {
      DnsForwarder d;
      d.bind.span = SpanOf(item);
      if (!item.IsMap()) {
        Err("SC102", SpanOf(item),
            "each services.dns entry must be a map");
        continue;
      }
      RequireMapKeys(item, {"zone", "upstream", "stop_dns_rebind"},
                     "services.dns entry");
      d.bind.zone = Str(item, "zone");
      if (item["zone"]) d.bind.span = SpanOf(item["zone"]);
      for (const auto& u : item["upstream"]) {
        d.upstreams.push_back(u.as<std::string>(""));
      }
      if (item["stop_dns_rebind"]) {
        d.stop_dns_rebind =
            item["stop_dns_rebind"].as<bool>(true);
      }
      cfg->dns.push_back(d);
    }
  }
};

}  // namespace

auto ParseSystemConfigString(std::string_view yaml)
    -> std::expected<SystemConfig, ParseFailure> {
  YAML::Node doc;
  try {
    doc = YAML::Load(std::string(yaml));
  } catch (const YAML::Exception& ex) {
    Diagnostic d{
        "SC100", Severity::kError,
        std::format("yaml parse: {}", ex.msg),
        {ex.mark.line + 1, ex.mark.column + 1}, ""};
    return std::unexpected(ParseFailure{{d}});
  }
  if (!doc || doc.IsNull()) return SystemConfig{};
  if (!doc.IsMap()) {
    Diagnostic d{"SC102",
                 Severity::kError,
                 "system config must be a YAML map",
                 SpanOf(doc),
                 ""};
    return std::unexpected(ParseFailure{{d}});
  }

  Parser p;
  auto cfg = p.Run(doc);
  if (p.Failed()) {
    return std::unexpected(ParseFailure{p.Diagnostics()});
  }
  return cfg;
}

auto ParseSystemConfigFile(std::string_view path)
    -> std::expected<SystemConfig, ParseFailure> {
  std::string p(path);
  if (!std::filesystem::exists(p)) {
    Diagnostic d{"SC001",
                 Severity::kError,
                 std::format("system config not found: {}", p),
                 {},
                 "write one, or run `f system example` for a "
                 "starting point"};
    return std::unexpected(ParseFailure{{d}});
  }
  std::ifstream in(p);
  if (!in) {
    Diagnostic d{"SC001", Severity::kError,
                 std::format("open {}: failed", p), {}, ""};
    return std::unexpected(ParseFailure{{d}});
  }
  std::ostringstream ss;
  ss << in.rdbuf();
  return ParseSystemConfigString(ss.str());
}

}  // namespace f::sysconfig
