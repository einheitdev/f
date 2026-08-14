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
  // Unconditional, and that is the decision rather than an oversight.
  //
  // Deriving it — "forward only when two zones carry interfaces" —
  // reads well and creates a second way for the box to be silently
  // non-routing, which is the exact fault this file exists to remove.
  // A single-zone box that forwards nothing is not harmed by being
  // able to.
  return {{"net.ipv4.ip_forward", "1"}};
}

auto PlanSysctl(const SystemConfig& cfg, const SysctlOptions& opts)
    -> SysctlUnit {
  std::ostringstream o;
  o << kBanner;
  o << "#\n";
  o << "# This box routes: a policy that sends a packet from one zone\n";
  o << "# to another sends it to a next hop, and Linux will not resolve\n";
  o << "# a next hop with forwarding off. The XDP datapath asks the\n";
  o << "# same kernel: bpf_fib_lookup() returns FWD_DISABLED and the\n";
  o << "# redirect falls back to forwarding the frame with the\n";
  o << "# destination MAC it arrived carrying, which the far side\n";
  o << "# discards as PACKET_OTHERHOST. Nothing on the wire says so.\n";
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

  // The drop-in is what survives a reboot; this is what makes the box
  // forward before one. Both, or the box works in exactly one of the
  // two states an operator will test in.
  for (const auto& [k, v] : PlanSysctlValues(cfg)) {
    std::string path = KeyToPath(opts.proc_dir, k);
    // A no-op against a real /proc/sys, where every directory already
    // exists. It is here so `proc_dir` is a seam a test can point at a
    // temp tree — an untestable "and then we write the kernel knob" is
    // how this setting went missing in the first place.
    std::error_code ec;
    std::filesystem::create_directories(
        std::filesystem::path(path).parent_path(), ec);
    std::ofstream out(path, std::ios::trunc);
    if (!out) {
      return std::unexpected(std::format(
          "cannot write {} (need root, or the kernel does not have "
          "this knob): the drop-in is installed and will take effect "
          "at the next boot, but this box is not forwarding yet",
          path));
    }
    out << v << "\n";
    if (!out) {
      return std::unexpected(
          std::format("write to {} failed", path));
    }
    out.close();
    report.applied.push_back(k);
  }
  return report;
}

}  // namespace f::sysconfig
