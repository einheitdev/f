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

#include "f/sysconfig/chrony.h"
#include "f/sysconfig/dnsmasq.h"
#include "f/sysconfig/ipv6.h"
#include "f/sysconfig/model.h"
#include "f/sysconfig/networkd.h"
#include "f/sysconfig/parse.h"
#include "f/sysconfig/service_status.h"
#include "f/sysconfig/sysctl.h"
#include "f/sysconfig/storage.h"
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
using f::sysconfig::ApplyChrony;
using f::sysconfig::LogPolicy;
using f::sysconfig::PlanLogging;
using f::sysconfig::PlanRetention;
using f::sysconfig::PruneBundles;
using f::sysconfig::QueryStorage;
using f::sysconfig::RetentionPolicy;
using f::sysconfig::StorageAvailability;
using f::sysconfig::StorageAvailabilityName;
using f::sysconfig::StorageSource;
using f::sysconfig::StorageWarningBanner;
using f::sysconfig::kJournaldDropInPath;
using f::sysconfig::ApplyIpv6;
using f::sysconfig::ChronyOptions;
using f::sysconfig::CheckChronyDrift;
using f::sysconfig::PlanChrony;
using f::sysconfig::QueryTime;
using f::sysconfig::RtcPresenceName;
using f::sysconfig::TimeSource;
using f::sysconfig::TimeTrust;
using f::sysconfig::TimeTrustName;
using f::sysconfig::TimeWarningBanner;
using f::sysconfig::DriftKind;
using f::sysconfig::DriftKindName;
using f::sysconfig::Ipv6Availability;
using f::sysconfig::Ipv6AvailabilityName;
using f::sysconfig::Ipv6Options;
using f::sysconfig::Ipv6Source;
using f::sysconfig::Ipv6Stance;
using f::sysconfig::Ipv6StanceName;
using f::sysconfig::ObserveIpv6;
using f::sysconfig::PlanIpv6;
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

/// The v6 verdict, in the one shape that answers the question an
/// operator actually has: *is the gate holding, and how do you know?*
/// A row of zeroes is only reassuring when it is accompanied by
/// evidence that something was there to refuse.
/// @returns true when the stance is being violated on this box.
auto ReportIpv6(const SystemConfig& cfg, const Ipv6Source& src)
    -> bool {
  auto report = ObserveIpv6(cfg, src);
  std::cout << "ipv6:\n";
  if (report.availability != Ipv6Availability::kObserved) {
    std::cout << std::format("  (nothing observed: {})\n",
                             Ipv6AvailabilityName(
                                 report.availability));
    return false;
  }
  std::cout << std::format("  {:<10} {:<10} {:<8} {:>8} {:>10}  {}\n",
                           "INTERFACE", "ZONE", "STANCE",
                           "RAS SEEN", "V6 FRAMES", "V6 ADDRESSES");
  for (const auto& i : report.interfaces) {
    std::string addrs;
    for (const auto& a : i.global_addresses) {
      if (!addrs.empty()) addrs += ",";
      addrs += a;
    }
    if (!i.counters_read) {
      // Never render an unread counter as a zero: the office may be
      // shouting advertisements at that port right now.
      std::cout << std::format(
          "  {:<10} {:<10} {:<8} {:>8} {:>10}  {}\n",
          i.intent.interface,
          i.intent.zone.empty() ? "-" : i.intent.zone,
          Ipv6StanceName(i.intent.stance), "?", "?",
          "(device not present)");
      continue;
    }
    std::cout << std::format(
        "  {:<10} {:<10} {:<8} {:>8} {:>10}  {}\n",
        i.intent.interface,
        i.intent.zone.empty() ? "-" : i.intent.zone,
        Ipv6StanceName(i.intent.stance), i.ras_received,
        i.v6_received, addrs.empty() ? "(none)" : addrs);
  }
  std::cout << std::format("  forwarding {}\n",
                           report.forwarding ? "on" : "off");

  auto refused = report.RefusedRas();
  if (refused > 0) {
    std::cout << std::format(
        "  {} router advertisement(s) arrived on a zone whose "
        "stance is off, and were refused. Nothing autoconfigured.\n",
        refused);
  } else {
    std::cout << "  no router advertisements have arrived on an off "
                 "zone. That is a quiet network, not proof the gate "
                 "works — `tests/system/test_ipv6_ra_gate.py` is the "
                 "proof.\n";
  }
  auto violations = report.Violations();
  for (const auto& v : violations) {
    std::cerr << std::format("  IPv6 STANCE VIOLATED: {}\n", v);
  }
  return !violations.empty();
}

/// The clock, and whether it can be believed.
///
/// Printed as part of `status` rather than hidden behind its own
/// command, because every other line in that output is stamped in it.
auto ReportTime(const SystemConfig& cfg, const TimeSource& src)
    -> void {
  auto t = QueryTime(cfg, src);
  std::cout << "clock:\n";
  std::cout << std::format("  trust      {}\n",
                           TimeTrustName(t.trust));
  std::cout << std::format("  rtc        {}{}\n",
                           RtcPresenceName(t.rtc),
                           t.rtc_name.empty()
                               ? ""
                               : " — " + t.rtc_name);
  std::cout << std::format("  wall       {}{}\n", t.wall_seconds,
                           t.implausible ? "  (AT THE EPOCH)" : "");
  std::cout << std::format("  uptime     {}s\n", t.uptime_seconds);
  if (!t.reference.empty()) {
    std::cout << std::format("  reference  {}\n", t.reference);
  }
  if (!t.detail.empty()) {
    std::cout << std::format("  {}\n", t.detail);
  }
  auto banner = TimeWarningBanner(t);
  if (!banner.empty()) std::cerr << banner;
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
  Ipv6Options ipv6_opts;
  Ipv6Source ipv6_src;
  ChronyOptions chrony_opts;
  TimeSource time_src;
  StorageSource storage_src;
  std::string journald_path = kJournaldDropInPath;
  app.add_option("--dnsmasq-conf", dnsmasq_opts.conf_path,
                 "Where the generated dnsmasq config is installed");
  app.add_option("--dnsmasq-bin", dnsmasq_opts.dnsmasq_path,
                 "Path to the dnsmasq binary");
  app.add_option("--networkd-dir", networkd_opts.dir,
                 "Where generated networkd units are installed");
  app.add_option("--sysctl-dir", sysctl_opts.dir,
                 "Where the generated sysctl drop-in is installed");
  app.add_option("--compiled-dir", storage_src.retention.compiled_dir,
                 "Directory holding compiled bundles");
  app.add_option("--keep-bundles", storage_src.retention.keep,
                 "How many compiled bundles to keep");
  app.add_option("--journald-dropin", journald_path,
                 "Where the generated journald limits are installed");
  app.add_option("--chrony-conf", chrony_opts.conf_path,
                 "Where the generated chrony config is installed");
  app.add_option("--chronyd-bin", chrony_opts.chronyd_path,
                 "Path to the chronyd binary");
  app.add_option("--rtc-dir", time_src.rtc_dir,
                 "Where RTC devices are enumerated");
  app.add_option("--chronyc-cmd", time_src.chronyc_cmd,
                 "Command that reports the time reference "
                 "(empty to skip)");
  app.add_option("--ipv6-sysctl", ipv6_opts.sysctl_path,
                 "Where the generated IPv6 sysctl file is installed");
  app.add_option("--proc-sys", ipv6_opts.proc_sys_root,
                 "sysctl tree the stance is pushed into live "
                 "(empty to write the file only)");
  app.add_option("--snmp6-dir", ipv6_src.snmp6_dir,
                 "Per-interface IPv6 counters to observe");
  app.add_option("--if-inet6", ipv6_src.if_inet6_path,
                 "Kernel IPv6 address table to observe");
  app.add_option("--v6-forwarding", ipv6_src.forwarding_path,
                 "Global IPv6 forwarding sysctl to observe");

  bool force = false;
  auto* check = app.add_subcommand("check", "Validate the model");
  auto* show = app.add_subcommand("show", "Show the resolved model");
  auto* status =
      app.add_subcommand("status", "Compare artifacts to the model");
  auto* render =
      app.add_subcommand("render", "Print a derived artifact");
  std::string what;
  render->add_option("what", what,
                     "dnsmasq | networkd | sysctl | ipv6 "
                     "| chrony")
      ->required();
  auto* storage = app.add_subcommand(
      "storage", "Disk, bundles, and what logging has lost");
  auto* prune = app.add_subcommand(
      "prune", "Remove compiled bundles beyond the retention limit");
  bool dry_run = false;
  prune->add_flag("--dry-run", dry_run,
                  "Report what would be removed, remove nothing");
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
    } else if (what == "ipv6") {
      std::cout << PlanIpv6(*cfg).sysctl_content;
    } else if (what == "chrony") {
      std::cout << PlanChrony(*cfg).content;
    } else {
      std::cerr << "render: expected 'dnsmasq', 'networkd', 'sysctl', "
                   "'ipv6' or 'chrony'\n";
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
    {
      auto cd = CheckChronyDrift(*cfg, chrony_opts.conf_path);
      std::cout << std::format("  {:<12} {:<9} {}\n",
                               DriftKindName(cd), "chrony",
                               chrony_opts.conf_path);
      drifted = drifted || cd == DriftKind::kHandEdited;
    }
    {
      auto vd = CheckArtifactDrift(ipv6_opts.sysctl_path,
                                   PlanIpv6(*cfg).sysctl_content);
      std::cout << std::format("  {:<12} {:<9} {}\n",
                               DriftKindName(vd), "ipv6",
                               ipv6_opts.sysctl_path);
      drifted = drifted || vd == DriftKind::kHandEdited;
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
    bool violated = ReportIpv6(*cfg, ipv6_src);
    ReportTime(*cfg, time_src);

    // Precedence is deliberate and this order is the argument: a port
    // that is `ipv6 off` and holds a global address is a bypass that
    // is *already happening*, so it outranks a config file somebody
    // edited and a service that will not start. Both of those are
    // faults an operator gets to at his convenience; this one is
    // traffic leaving the building around the firewall.
    if (violated) return 5;
    if (drifted) return 3;
    return service_fault ? 4 : 0;
  }

  if (*storage) {
    auto report = QueryStorage(storage_src);
    std::cout << "storage:\n";
    std::cout << std::format("  availability  {}\n",
                             StorageAvailabilityName(
                                 report.availability));
    if (!report.detail.empty()) {
      std::cout << std::format("  {}\n", report.detail);
    }
    std::cout << std::format(
        "  filesystem    {} MiB free of {} MiB\n",
        report.fs_free_bytes / (1024 * 1024),
        report.fs_total_bytes / (1024 * 1024));
    std::cout << std::format(
        "  bundles       {} using {} KiB, {} beyond the limit of "
        "{}\n",
        report.bundle_count, report.bundle_bytes / 1024,
        report.bundles_over_policy, storage_src.retention.keep);
    // Never a bare zero: "no journal was found" and "the journal is
    // empty" are different, and only one of them is reassuring.
    std::cout << std::format(
        "  journal       {}\n",
        report.journal_read
            ? std::format("{} MiB",
                          report.journal_bytes / (1024 * 1024))
            : std::string("(could not be read)"));
    std::cout << std::format(
        "  dropped logs  {}\n",
        report.suppression_read
            ? std::format("{} message(s) in {} burst(s), 24h",
                          report.suppressed_messages,
                          report.suppression_bursts)
            : std::string("(could not be determined)"));
    auto banner = StorageWarningBanner(report);
    if (!banner.empty()) std::cerr << banner;
    // A box losing log events, or nearly out of room, exits non-zero
    // so a script notices without reading English.
    bool bad = report.Tight() ||
               report.availability ==
                   StorageAvailability::kUnreadable ||
               (report.suppression_read &&
                report.suppressed_messages > 0);
    return bad ? 6 : 0;
  }

  if (*prune) {
    auto plan = PlanRetention(storage_src.retention);
    if (!plan.readable) {
      std::cerr << plan.unreadable_reason << "\n";
      return 1;
    }
    if (dry_run) {
      for (const auto& b : plan.to_remove) {
        std::cout << std::format("would remove {} ({} KiB)\n",
                                 b.name, b.bytes / 1024);
      }
      std::cout << std::format(
          "{} of {} bundle(s) are beyond the limit of {}; {} KiB "
          "reclaimable\n",
          plan.to_remove.size(), plan.bundles.size(),
          storage_src.retention.keep,
          plan.reclaimable_bytes / 1024);
      return 0;
    }
    auto report = PruneBundles(storage_src.retention);
    if (!report) {
      std::cerr << report.error() << "\n";
      return 1;
    }
    for (const auto& n : report->removed) {
      std::cout << "removed " << n << "\n";
    }
    std::cout << std::format("{} bundle(s) removed, {} KiB "
                             "reclaimed\n",
                             report->removed.size(),
                             report->reclaimed_bytes / 1024);
    // A prune that half-worked says which half, on stderr, non-zero.
    for (const auto& f : report->failed) {
      std::cerr << "could not remove " << f << "\n";
    }
    return report->failed.empty() ? 0 : 1;
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

    // The journal limits go in with everything else. An appliance
    // that fills its own disk stops working, and it does it at the
    // office rather than on the bench.
    {
      auto log_plan = PlanLogging(LogPolicy{});
      auto wrote = f::sysconfig::InstallArtifact(journald_path,
                                                 log_plan.content);
      if (!wrote) {
        std::cerr << wrote.error() << "\n";
        return 1;
      }
      if (*wrote) std::cout << "wrote " << journald_path << "\n";
    }

    // The IPv6 stance goes in before any service starts. It is the
    // one setting whose failure looks exactly like success from
    // every v4 counter on the box.
    ipv6_opts.refuse_on_drift = !force;
    auto v6 = ApplyIpv6(*cfg, ipv6_opts);
    if (!v6) {
      std::cerr << v6.error() << "\n";
      return 1;
    }
    if (v6->changed) std::cout << "wrote " << v6->sysctl_path << "\n";
    for (const auto& i : v6->plan.interfaces) {
      std::cout << std::format(
          "ipv6 {}: {} accepts no router advertisement{}\n",
          Ipv6StanceName(i.stance), i.interface,
          i.sends_ra
              ? std::format(" and advertises {}/64",
                            i.advertised_prefix)
              : "");
    }
    if (!v6->failed_live.empty()) {
      // Half a stance is not a stance. Say which half, and say it on
      // stderr with a non-zero exit, because an operator who reads
      // "applied" here will not check again.
      std::cerr << "the IPv6 stance was written but could not be "
                   "applied to the running kernel:\n";
      for (const auto& fmsg : v6->failed_live) {
        std::cerr << "  " << fmsg << "\n";
      }
      std::cerr << "until this is resolved those ports may still "
                   "autoconfigure from an upstream advertisement.\n";
      return 6;
    }

    auto chrony_plan = PlanChrony(*cfg);
    if (chrony_plan.needed) {
      chrony_opts.refuse_on_drift = !force;
      auto ch = ApplyChrony(*cfg, chrony_opts);
      if (!ch) {
        std::cerr << ch.error().message << "\n";
        return 1;
      }
      if (ch->changed) {
        std::cout << "wrote " << ch->conf_path << "\n";
      }
      std::cout << std::format(
          "ntp answers on: {}\n", [&] {
            std::string s;
            for (const auto& a : chrony_plan.bind_addresses) {
              if (!s.empty()) s += ",";
              s += a;
            }
            return s.empty() ? "(nowhere — the server port is "
                               "closed)"
                             : s;
          }());
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
