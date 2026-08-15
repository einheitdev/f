/// @file system_backend.cc
/// @brief confd ConfigBackend over the appliance system configuration.

#include "f/confd/system_backend.h"

#include <sys/wait.h>
#include <unistd.h>

#include <cstring>
#include <filesystem>
#include <format>
#include <fstream>
#include <sstream>
#include <utility>

#include "f/sysconfig/artifact.h"
#include "f/sysconfig/dnsmasq.h"
#include "f/sysconfig/model.h"
#include "f/sysconfig/networkd.h"
#include "f/sysconfig/parse.h"
#include "f/sysconfig/sysctl.h"
#include "f/sysconfig/validate.h"

namespace f::confd {
namespace {

namespace cc = einheit::cli::confd;
namespace sc = f::sysconfig;

using ApplyFailure = einheit::cli::Error<cc::ApplyError>;

auto Fail(cc::ApplyError code, std::string message) -> ApplyFailure {
  return ApplyFailure{code, std::move(message)};
}

auto ReadWholeFile(const std::string& path)
    -> std::expected<std::string, std::string> {
  std::ifstream in(path, std::ios::in | std::ios::binary);
  if (!in) {
    return std::unexpected(std::format("cannot read {}", path));
  }
  std::ostringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

/// Run a command, returning its combined output. Used only by the
/// default activator; everything else in this file is pure I/O on
/// files the appliance owns.
auto RunCommand(const std::vector<std::string>& argv)
    -> std::pair<int, std::string> {
  int fds[2];
  if (pipe(fds) != 0) return {-1, "pipe failed"};
  pid_t pid = fork();
  if (pid < 0) {
    close(fds[0]);
    close(fds[1]);
    return {-1, "fork failed"};
  }
  if (pid == 0) {
    close(fds[0]);
    dup2(fds[1], STDOUT_FILENO);
    dup2(fds[1], STDERR_FILENO);
    close(fds[1]);
    std::vector<char*> args;
    args.reserve(argv.size() + 1);
    for (const auto& a : argv) {
      args.push_back(const_cast<char*>(a.c_str()));
    }
    args.push_back(nullptr);
    execvp(args[0], args.data());
    _exit(127);
  }
  close(fds[1]);
  std::string out;
  char buf[4096];
  ssize_t n = 0;
  while ((n = read(fds[0], buf, sizeof(buf))) > 0) {
    out.append(buf, static_cast<std::size_t>(n));
  }
  close(fds[0]);
  int status = 0;
  waitpid(pid, &status, 0);
  int rc = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
  return {rc, out};
}

auto EndsWith(const std::string& s, const std::string& suffix)
    -> bool {
  return s.size() >= suffix.size() &&
         s.compare(s.size() - suffix.size(), suffix.size(),
                   suffix) == 0;
}

auto FormatDiagnostics(const std::vector<sc::Diagnostic>& diags)
    -> std::string {
  std::string out;
  for (const auto& d : diags) {
    if (d.severity != sc::Severity::kError) continue;
    if (!out.empty()) out += "; ";
    out += d.Format();
  }
  return out;
}

}  // namespace

auto DefaultActivator() -> Activator {
  return [](const Activation& act)
             -> std::expected<std::string, std::string> {
    std::string report;
    if (!act.networkd_changed.empty()) {
      auto [rc, out] = RunCommand({"networkctl", "reload"});
      if (rc != 0) {
        return std::unexpected(std::format(
            "networkctl reload failed ({}): {}", rc, out));
      }
      report += "systemd-networkd reloaded";
      // A .link rename cannot be applied to an interface that is
      // already up and carrying the session; say so rather than
      // renaming the port out from under the operator.
      bool link_changed = false;
      for (const auto& p : act.networkd_changed) {
        if (EndsWith(p, ".link")) link_changed = true;
      }
      if (link_changed) {
        report +=
            " (interface name pinning takes effect on next boot)";
      }
    }
    if (act.dnsmasq_changed) {
      auto [rc, out] = RunCommand(
          {"systemctl", "try-restart", "f-dnsmasq.service"});
      if (rc != 0) {
        return std::unexpected(std::format(
            "restarting f-dnsmasq.service failed ({}): {}", rc,
            out));
      }
      if (!report.empty()) report += "; ";
      // `try-restart` is a no-op that exits 0 when the unit is not
      // running, so its exit code says the command was issued and
      // nothing about the unit. Reporting "restarted" from it meant a
      // dnsmasq that was `failed` when its config was rewritten stayed
      // failed and the operator was told otherwise. Ask what the unit
      // is NOW.
      auto [srv_rc, srv_out] = RunCommand(
          {"systemctl", "is-active", "f-dnsmasq.service"});
      std::string state = srv_out;
      while (!state.empty() &&
             (state.back() == '\n' || state.back() == '\r')) {
        state.pop_back();
      }
      if (state == "active") {
        report += "f-dnsmasq restarted (active)";
      } else if (state == "inactive") {
        // Legitimate on a box that serves neither DHCP nor DNS: the
        // config was written and nothing is running to read it. Said
        // plainly, because "restarted" implies something is serving.
        report += "f-dnsmasq config written, unit not running "
                  "(inactive)";
      } else {
        report += std::format(
            "f-dnsmasq config written but the unit is '{}' — it is "
            "NOT serving the configuration that was just applied "
            "(`systemctl status f-dnsmasq` for why)",
            state.empty() ? "unknown" : state);
      }
      (void)srv_rc;
    }
    if (report.empty()) report = "nothing needed reloading";
    return report;
  };
}

auto NullActivator() -> Activator {
  return [](const Activation&)
             -> std::expected<std::string, std::string> {
    return "not activated (no activator configured)";
  };
}

SystemBackend::SystemBackend(SystemBackendOptions opts)
    : opts_(std::move(opts)) {
  if (!opts_.activate) opts_.activate = DefaultActivator();

  // The baseline is the configuration the box was running when confd
  // first came up. It is what an empty candidate means, so the
  // auto-revert of the very first commit-confirmed has a target. It is
  // recorded on disk: after a restart the file at config_path is
  // whatever the last apply installed, which is exactly not the
  // baseline.
  std::error_code ec;
  std::filesystem::create_directories(opts_.snapshot_dir, ec);
  auto marker =
      std::filesystem::path(opts_.snapshot_dir) / "baseline";
  if (auto existing = ReadWholeFile(marker.string()); existing) {
    baseline_digest_ = *existing;
    while (!baseline_digest_.empty() &&
           (baseline_digest_.back() == '\n' ||
            baseline_digest_.back() == '\r')) {
      baseline_digest_.pop_back();
    }
    return;
  }
  if (auto text = ReadWholeFile(opts_.config_path); text) {
    if (auto d = Snapshot(*text); d) {
      baseline_digest_ = *d;
      (void)sc::InstallArtifact(marker.string(), baseline_digest_);
    }
  }
}

auto SystemBackend::Snapshot(const std::string& text)
    -> std::expected<std::string, std::string> {
  auto digest = sc::BodyDigest(text);
  auto path = std::filesystem::path(opts_.snapshot_dir) /
              (digest + ".yaml");
  auto installed = sc::InstallArtifact(path.string(), text);
  if (!installed) return std::unexpected(installed.error());
  return digest;
}

auto SystemBackend::LoadSnapshot(const std::string& digest) const
    -> std::expected<std::string, std::string> {
  auto path = std::filesystem::path(opts_.snapshot_dir) /
              (digest + ".yaml");
  return ReadWholeFile(path.string());
}

auto SystemBackend::ReadRunning() -> cc::Config {
  cc::Config out;
  auto text = ReadWholeFile(opts_.config_path);
  if (!text) return out;
  auto digest = Snapshot(*text);
  if (!digest) return out;
  out[kConfigKey] = *digest;
  return out;
}

auto SystemBackend::Schema() const
    -> const einheit::cli::schema::Schema& {
  return schema_;
}

auto SystemBackend::LastReport() const -> std::string {
  std::lock_guard<std::mutex> lock(mu_);
  return last_report_;
}

auto SystemBackend::BaselineDigest() const -> std::string {
  return baseline_digest_;
}

auto SystemBackend::Apply(const cc::Candidate& candidate)
    -> std::expected<cc::CommitId, ApplyFailure> {
  // An empty candidate is the runtime's way of saying "revert to
  // before the first commit". For this backend that is the baseline
  // configuration recorded at startup.
  std::string digest;
  if (auto it = candidate.values.find(kConfigKey);
      it != candidate.values.end()) {
    digest = it->second;
  }
  if (digest.empty()) digest = baseline_digest_;
  if (digest.empty()) {
    return std::unexpected(Fail(
        cc::ApplyError::ValidationFailed,
        "no configuration to apply and no baseline recorded"));
  }

  bool force = opts_.force;
  if (auto it = candidate.values.find(kForceKey);
      it != candidate.values.end()) {
    force = it->second == "true" || it->second == "1";
  }

  // Resolve the digest to text. A stored snapshot wins: on a revert
  // the file on disk is the *new* configuration, and the point of the
  // revert is to not use it.
  std::string text;
  if (auto stored = LoadSnapshot(digest); stored) {
    text = *stored;
  } else {
    auto live = ReadWholeFile(opts_.config_path);
    if (!live || sc::BodyDigest(*live) != digest) {
      return std::unexpected(Fail(
          cc::ApplyError::ValidationFailed,
          std::format("no stored configuration for revision {}",
                      digest)));
    }
    text = *live;
    (void)Snapshot(text);
  }

  auto parsed = sc::ParseSystemConfigString(text);
  if (!parsed) {
    return std::unexpected(Fail(
        cc::ApplyError::ValidationFailed,
        FormatDiagnostics(parsed.error().diagnostics)));
  }
  auto validation = sc::Validate(*parsed);
  if (validation.HasErrors()) {
    return std::unexpected(
        Fail(cc::ApplyError::ValidationFailed,
             FormatDiagnostics(validation.diagnostics)));
  }

  // Derived artifacts first: if one of them refuses, the running
  // configuration file is still the old one.
  sc::NetworkdOptions net_opts;
  net_opts.dir = opts_.networkd_dir;
  net_opts.refuse_on_drift = !force;
  auto net = sc::ApplyNetworkd(*parsed, net_opts);
  if (!net) {
    return std::unexpected(
        Fail(cc::ApplyError::HardwareRejected, net.error()));
  }

  // Forwarding travels with the interfaces. A rollback does not need
  // to undo it: `net.ipv4.ip_forward` is a property of the box being a
  // router, not of any one revision of its configuration, and a
  // rollback that turns routing off would cut the session it exists to
  // protect.
  sc::SysctlOptions sysctl_opts;
  sysctl_opts.dir = opts_.sysctl_dir;
  sysctl_opts.proc_dir = opts_.sysctl_proc_dir;
  sysctl_opts.refuse_on_drift = !force;
  auto sysctl = sc::ApplySysctl(*parsed, sysctl_opts);
  if (!sysctl) {
    return std::unexpected(
        Fail(cc::ApplyError::HardwareRejected, sysctl.error()));
  }

  Activation activation;
  activation.networkd_changed = net->changed;
  if (sysctl->changed) {
    activation.networkd_changed.push_back(sysctl->unit.path);
  }

  auto plan = sc::PlanDnsmasq(*parsed);
  std::string dnsmasq_note = "no service is bound to a zone";
  if (plan.needed) {
    sc::DnsmasqOptions dm_opts;
    dm_opts.conf_path = opts_.dnsmasq_conf;
    dm_opts.dnsmasq_path = opts_.dnsmasq_path;
    dm_opts.refuse_on_drift = !force;
    auto dm = sc::ApplyDnsmasq(*parsed, dm_opts);
    if (!dm) {
      auto code =
          dm.error().code == sc::BackendError::kToolMissing
              ? cc::ApplyError::Unavailable
              : cc::ApplyError::HardwareRejected;
      return std::unexpected(Fail(code, dm.error().message));
    }
    activation.dnsmasq_changed = dm->changed;
    dnsmasq_note = dm->changed ? "dnsmasq config rewritten"
                               : "dnsmasq config unchanged";
  }

  // The configuration itself becomes the running one only once
  // everything derived from it is on disk.
  auto installed = sc::InstallArtifact(opts_.config_path, text);
  if (!installed) {
    return std::unexpected(
        Fail(cc::ApplyError::PartialApply,
             std::format("artifacts written but {} not updated: {}",
                         opts_.config_path, installed.error())));
  }

  auto activated = opts_.activate(activation);
  if (!activated) {
    // Written but not live. That is a real, distinct state and the
    // operator has to hear about it, so it is an error rather than a
    // footnote on a success.
    return std::unexpected(Fail(
        cc::ApplyError::PartialApply,
        std::format("configuration written but NOT live: {}",
                    activated.error())));
  }

  std::string report = std::format(
      "revision {}: {} networkd unit(s) written, {}; {}", digest,
      net->changed.size(), dnsmasq_note, *activated);
  {
    std::lock_guard<std::mutex> lock(mu_);
    last_report_ = report;
  }
  return ++generation_;
}

}  // namespace f::confd
