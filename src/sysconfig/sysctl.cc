/// @file sysctl.cc
/// @brief Generate, install and apply the forwarding sysctl.

#include "f/sysconfig/sysctl.h"

#include <algorithm>
#include <filesystem>
#include <format>
#include <fstream>
#include <system_error>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace f::sysconfig {
namespace {

constexpr const char* kBanner =
    "# GENERATED FROM THE f SYSTEM CONFIGURATION MODEL.\n"
    "# Do not edit; edits are reported as drift, not merged.\n";

/// `net.ipv4.ip_forward` -> `net/ipv4/ip_forward`.
auto KeyToPath(const std::string& proc_dir, const std::string& key)
    -> std::string {
  std::string rel = key;
  std::replace(rel.begin(), rel.end(), '.', '/');
  return proc_dir + "/" + rel;
}

}  // namespace

auto PlanSysctlValues(const SystemConfig&)
    -> std::vector<std::pair<std::string, std::string>> {
  // 0, and it used to be 1. See the header for the reversal in full.
  //
  // This is the BOOT-TIME FLOOR, not the running value. The running
  // value belongs to `fd`, which raises it when a bundle is in the
  // packet path and lowers it whenever one is not. What this drop-in
  // guarantees is the state of the box in the window before fd has
  // spoken, and the state of a box on which fd never starts at all: a
  // box that is not filtering does not forward.
  return {{"net.ipv4.ip_forward", "0"}};
}

auto PlanSysctl(const SystemConfig& cfg, const SysctlOptions& opts)
    -> SysctlUnit {
  std::ostringstream o;
  o << kBanner;
  o << "#\n";
  o << "# THE BOOT-TIME FLOOR, NOT THE RUNNING VALUE.\n";
  o << "#\n";
  o << "# This box routes — a policy that sends a packet from one\n";
  o << "# zone to another sends it to a next hop, and Linux will not\n";
  o << "# resolve one with forwarding off — but it routes only while\n";
  o << "# it is filtering. `fd` raises this knob when a compiled\n";
  o << "# bundle is attached to at least one interface and lowers it\n";
  o << "# again the moment one is not, including while it is starting\n";
  o << "# and when it is stopping.\n";
  o << "#\n";
  o << "# So do NOT set this to 1 to 'fix' a box that is not passing\n";
  o << "# traffic. It will be back at 0 within seconds and the reason\n";
  o << "# is in `fctl status` under forwarding, and in the journal:\n";
  o << "#   journalctl -u fd | grep forwarding\n";
  o << "\n";
  for (const auto& [k, v] : PlanSysctlValues(cfg)) {
    o << k << " = " << v << "\n";
  }
  return {std::format("{}/10-f-forwarding.conf", opts.dir),
          WrapWithDigest(o.str())};
}

auto CheckSysctlDrift(const SysctlUnit& unit) -> DriftKind {
  return CheckArtifactDrift(unit.path, unit.content);
}

auto ReadLiveSysctl(const std::string& proc_dir, const std::string& key)
    -> std::string {
  std::ifstream in(KeyToPath(proc_dir, key));
  if (!in) return {};
  std::string value;
  std::getline(in, value);
  // /proc/sys values are whitespace-padded for some keys.
  while (!value.empty() &&
         (value.back() == ' ' || value.back() == '\t' ||
          value.back() == '\r')) {
    value.pop_back();
  }
  return value;
}

auto ApplySysctl(const SystemConfig& cfg, const SysctlOptions& opts)
    -> std::expected<SysctlReport, std::string> {
  auto unit = PlanSysctl(cfg, opts);
  if (opts.refuse_on_drift &&
      CheckSysctlDrift(unit) == DriftKind::kHandEdited) {
    return std::unexpected(std::format(
        "generated sysctl drop-in was edited by hand:\n  {}\nFold the "
        "change into the system config, or re-apply with force to "
        "discard it.",
        unit.path));
  }

  SysctlReport report;
  report.unit = unit;
  auto installed = InstallArtifact(unit.path, unit.content);
  if (!installed) return std::unexpected(installed.error());
  report.changed = *installed;

  if (!opts.apply_live) return report;

  // `report.applied` is empty, always, and that emptiness is the
  // decision rather than an omission.
  //
  // This function used to push every planned value into the running
  // kernel as well as onto disk, on the reasoning that "a drop-in
  // nobody applies until the next reboot is the same silent failure
  // with a longer fuse". That was right while this file decided
  // whether the box forwards. It no longer does: `fd` owns the live
  // value and takes it from whether a bundle is in the packet path.
  //
  // Pushing the floor (0) into a RUNNING kernel would therefore stop
  // a healthy, filtering box from routing — and fd would not put it
  // back, because it deliberately does not fight an operator who
  // lowers this knob. `apply system` is a command an operator runs to
  // change a DNS server; it must not be able to take the office
  // offline as a side effect.
  //
  // Nothing is lost at provisioning time. firstboot applies the
  // system config and then starts fd, and fd's first act is to lower
  // the knob and its last act before readiness is to raise it.
  return report;
}

}  // namespace f::sysconfig
