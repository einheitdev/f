/// @file f_sysconf.cc
/// @brief `f-sysconf` — the scriptable seam onto the system config.
///
/// The CLI is the operator surface; this is the same model with a
/// plain argv interface, for firstboot scripts, tests and the times
/// somebody is holding a serial console at 18:00.
///
///   f-sysconf check                 validate, report, exit non-zero
///   f-sysconf show                  the resolved model
///   f-sysconf render dnsmasq        print the derived artifact
///   f-sysconf render networkd       print the derived units
///   f-sysconf status                artifacts vs the model (drift)
///   f-sysconf apply                 generate -> validate -> install

#include <filesystem>
#include <format>
#include <iostream>
#include <string>
#include <vector>

#include <CLI/CLI.hpp>

#include "f/sysconfig/dnsmasq.h"
#include "f/sysconfig/model.h"
#include "f/sysconfig/networkd.h"
#include "f/sysconfig/parse.h"
#include "f/sysconfig/service_status.h"
#include "f/sysconfig/sysctl.h"
#include "f/sysconfig/validate.h"

namespace {

using f::sysconfig::AddressModeName;
using f::sysconfig::ApplyDnsmasq;
using f::sysconfig::ApplyNetworkd;
using f::sysconfig::ApplySysctl;
using f::sysconfig::CheckArtifactDrift;
using f::sysconfig::CheckDnsmasqDrift;
using f::sysconfig::CheckSysctlDrift;
using f::sysconfig::Diagnostic;
using f::sysconfig::DnsmasqOptions;
using f::sysconfig::DriftKind;
using f::sysconfig::DriftKindName;
using f::sysconfig::Ipv6StanceName;
using f::sysconfig::NetworkdOptions;
using f::sysconfig::ParseSystemConfigFile;
using f::sysconfig::PlanDnsmasq;
using f::sysconfig::PlanNetworkd;
using f::sysconfig::PlanSysctl;
using f::sysconfig::QueryServices;
using f::sysconfig::ReadLiveSysctl;
using f::sysconfig::ServiceState;
using f::sysconfig::ServiceStateName;
using f::sysconfig::Severity;
using f::sysconfig::SysctlOptions;
using f::sysconfig::SystemConfig;
using f::sysconfig::Validate;

auto PrintDiagnostics(const std::vector<Diagnostic>& diags) -> void {
  for (const auto& d : diags) {
    std::cerr << d.Format() << "\n";
  }
}

/// Load and validate. Returns nullopt after printing why not.
auto Load(const std::string& path, bool require_valid)
    -> std::optional<SystemConfig> {
  auto parsed = ParseSystemConfigFile(path);
  if (!parsed) {
    PrintDiagnostics(parsed.error().diagnostics);
    return std::nullopt;
  }
  auto result = Validate(*parsed);
  PrintDiagnostics(result.diagnostics);
  if (require_valid && result.HasErrors()) {
    std::cerr << std::format("refused: {} error(s) in {}\n",
                             result.Errors().size(), path);
    return std::nullopt;
  }
  return *parsed;
}

auto ShowModel(const SystemConfig& cfg) -> void {
  std::cout << "zones:\n";
  for (const auto& z : cfg.zones) {
    auto names = cfg.InterfaceNamesInZone(z.name);
    std::cout << std::format("  {:<12} ipv6={:<4} interfaces=",
                             z.name, Ipv6StanceName(z.ipv6));
    if (names.empty()) {
      std::cout << "(none)";
    } else {
      for (std::size_t i = 0; i < names.size(); ++i) {
        std::cout << (i != 0 ? "," : "") << names[i];
      }
    }
    std::cout << "\n";
  }
  std::cout << "interfaces:\n";
  for (const auto& i : cfg.interfaces) {
    std::cout << std::format(
        "  {:<12} {:<5}={:<20} address={:<18} zone={}\n", i.name,
        i.match.kind == f::sysconfig::MatchKind::kMac ? "mac"
                                                      : "path",
        i.match.value.empty() ? "(unpinned)" : i.match.value,
        i.mode == f::sysconfig::AddressMode::kStatic
            ? i.address
            : AddressModeName(i.mode),
        i.zone.empty() ? "(none)" : i.zone);
  }
  std::cout << "services:\n";
  auto plan = PlanDnsmasq(cfg);
  auto join = [](const std::vector<std::string>& v) {
    std::string s;
    for (const auto& e : v) {
      if (!s.empty()) s += ",";
      s += e;
    }
    return s.empty() ? "(none)" : s;
  };
  for (const auto& d : cfg.dhcp) {
    std::cout << std::format(
        "  dhcp   zone={:<10} range={}-{} lease={}s -> {}\n",
        d.bind.zone, d.range_start, d.range_end, d.lease_seconds,
        join(cfg.InterfaceNamesInZone(d.bind.zone)));
  }
  for (const auto& d : cfg.dns) {
    std::cout << std::format("  dns    zone={:<10} -> {}\n",
                             d.bind.zone,
                             join(cfg.InterfaceNamesInZone(
                                 d.bind.zone)));
  }
  if (cfg.dhcp.empty() && cfg.dns.empty()) {
    std::cout << "  (none)\n";
  }
  std::cout << "derived placement:\n";
  std::cout << std::format("  listen   {}\n",
                           join(plan.allowed_interfaces));
  std::cout << std::format("  excluded {}\n",
                           join(plan.excluded_interfaces));
  std::cout << std::format("  dhcp on  {}\n",
                           join(plan.dhcp_interfaces));
}

}  // namespace

auto main(int argc, char** argv) -> int {
  CLI::App app{"f appliance system configuration"};
  app.require_subcommand(1);

  std::string config_path = "/etc/f/system.yaml";
  app.add_option("-c,--config", config_path,
                 "System configuration file");

  DnsmasqOptions dnsmasq_opts;
  NetworkdOptions networkd_opts;
  SysctlOptions sysctl_opts;
  app.add_option("--dnsmasq-conf", dnsmasq_opts.conf_path,
                 "Where the generated dnsmasq config is installed");
  app.add_option("--dnsmasq-bin", dnsmasq_opts.dnsmasq_path,
                 "Path to the dnsmasq binary");
  app.add_option("--networkd-dir", networkd_opts.dir,
                 "Where generated networkd units are installed");
  app.add_option("--sysctl-dir", sysctl_opts.dir,
                 "Where the generated sysctl drop-in is installed");

  bool force = false;
  auto* check = app.add_subcommand("check", "Validate the model");
  auto* show = app.add_subcommand("show", "Show the resolved model");
  auto* status =
      app.add_subcommand("status", "Compare artifacts to the model");
  auto* render =
      app.add_subcommand("render", "Print a derived artifact");
  std::string what;
  render->add_option("what", what, "dnsmasq | networkd | sysctl")
      ->required();
  auto* apply =
      app.add_subcommand("apply", "Generate, validate and install");
  apply->add_flag("--force", force,
                  "Overwrite artifacts that were edited by hand");

  CLI11_PARSE(app, argc, argv);

  if (*check) {
    auto cfg = Load(config_path, true);
    if (!cfg) return 1;
    std::cout << "ok\n";
    return 0;
  }

  if (*show) {
    auto cfg = Load(config_path, false);
    if (!cfg) return 1;
    ShowModel(*cfg);
    return 0;
  }

  if (*render) {
    auto cfg = Load(config_path, true);
    if (!cfg) return 1;
    if (what == "dnsmasq") {
      std::cout << PlanDnsmasq(*cfg).content;
    } else if (what == "networkd") {
      for (const auto& u : PlanNetworkd(*cfg, networkd_opts)) {
        std::cout << std::format("### {}\n{}\n", u.path, u.content);
      }
    } else if (what == "sysctl") {
      auto u = PlanSysctl(*cfg, sysctl_opts);
      std::cout << std::format("### {}\n{}", u.path, u.content);
    } else {
      std::cerr
          << "render: expected 'dnsmasq', 'networkd' or 'sysctl'\n";
      return 2;
    }
    return 0;
  }

  if (*status) {
    auto cfg = Load(config_path, false);
    if (!cfg) return 1;

    std::cout << "artifacts:\n";
    auto d = CheckDnsmasqDrift(*cfg, dnsmasq_opts.conf_path);
    std::cout << std::format("  {:<12} {:<9} {}\n",
                             DriftKindName(d), "dnsmasq",
                             dnsmasq_opts.conf_path);
    bool drifted = d == DriftKind::kHandEdited;
    for (const auto& u : PlanNetworkd(*cfg, networkd_opts)) {
      auto ud = CheckArtifactDrift(u.path, u.content);
      std::cout << std::format("  {:<12} {:<9} {}\n",
                               DriftKindName(ud), "networkd",
                               u.path);
      drifted = drifted || ud == DriftKind::kHandEdited;
    }
    // The drop-in AND the live value, because they fail apart: a
    // correct file the kernel has not read yet is a box that forwards
    // after the next reboot and not now, which is the version of this
    // fault that survives a test.
    {
      auto u = PlanSysctl(*cfg, sysctl_opts);
      auto sd = CheckSysctlDrift(u);
      std::cout << std::format("  {:<12} {:<9} {}\n",
                               DriftKindName(sd), "sysctl", u.path);
      drifted = drifted || sd == DriftKind::kHandEdited;
      auto live = ReadLiveSysctl(sysctl_opts.proc_dir,
                                 "net.ipv4.ip_forward");
      std::cout << std::format(
          "  {:<12} {:<9} net.ipv4.ip_forward = {}\n",
          live == "1" ? "live" : "NOT-APPLIED", "sysctl",
          live.empty() ? "(unreadable)" : live);
      if (live != "1") drifted = true;
    }

    // The other half of "what does the operator see": a service that
    // should be up and is not gets a named state and a reason, never
    // a blank row.
    std::cout << "services:\n";
    bool service_fault = false;
    for (const auto& s : QueryServices(*cfg)) {
      std::string ifaces;
      for (const auto& n : s.interfaces) {
        if (!ifaces.empty()) ifaces += ",";
        ifaces += n;
      }
      std::cout << std::format(
          "  {:<28} {:<28} on {}\n", s.name,
          ServiceStateName(s.state),
          ifaces.empty() ? "(nowhere)" : ifaces);
      if (!s.detail.empty()) {
        std::cout << std::format("      {}\n", s.detail);
      }
      if (s.state == ServiceState::kFailed ||
          s.state == ServiceState::kNotInstalled ||
          s.state == ServiceState::kRestarting ||
          s.state == ServiceState::kStopped ||
          s.state == ServiceState::kUnexpected) {
        service_fault = true;
      }
    }
    if (drifted) return 3;
    return service_fault ? 4 : 0;
  }

  if (*apply) {
    auto cfg = Load(config_path, true);
    if (!cfg) return 1;
    dnsmasq_opts.refuse_on_drift = !force;
    networkd_opts.refuse_on_drift = !force;

    sysctl_opts.refuse_on_drift = !force;
    // Before the interfaces, because it costs nothing and because a
    // box that comes up addressed but not forwarding looks healthy.
    auto sysctl = ApplySysctl(*cfg, sysctl_opts);
    if (!sysctl) {
      std::cerr << sysctl.error() << "\n";
      return 1;
    }
    if (sysctl->changed) {
      std::cout << "wrote " << sysctl->unit.path << "\n";
    }
    for (const auto& k : sysctl->applied) {
      std::cout << "applied " << k << "\n";
    }

    auto net = ApplyNetworkd(*cfg, networkd_opts);
    if (!net) {
      std::cerr << net.error() << "\n";
      return 1;
    }
    for (const auto& p : net->changed) {
      std::cout << "wrote " << p << "\n";
    }

    auto plan = PlanDnsmasq(*cfg);
    if (!plan.needed) {
      std::cout << "no service is bound to any zone; dnsmasq is "
                   "not needed\n";
      return 0;
    }
    auto dm = ApplyDnsmasq(*cfg, dnsmasq_opts);
    if (!dm) {
      std::cerr << dm.error().message << "\n";
      return 1;
    }
    if (dm->changed) {
      std::cout << "wrote " << dm->conf_path << "\n";
    }
    std::cout << std::format("dhcp answers on: {}\n", [&] {
      std::string s;
      for (const auto& n : dm->plan.dhcp_interfaces) {
        if (!s.empty()) s += ",";
        s += n;
      }
      return s.empty() ? "(nowhere)" : s;
    }());
    return 0;
  }

  return 0;
}
