/// @file sysctl.h
/// @brief Kernel settings the appliance's own shape implies.
///
/// One artifact, one setting, and it is not a detail: `net.ipv4.ip_forward`.
///
/// A frame that a policy sends from one zone to another leaves this box
/// addressed to a next hop, which means this box routes. Linux refuses
/// to route with `ip_forward` at 0, and it refuses in the datapath too:
/// `bpf_fib_lookup` — the helper the XDP redirect uses to learn the
/// next hop's MAC — returns `BPF_FIB_LKUP_RET_FWD_DISABLED` and resolves
/// nothing. The redirect then falls back to forwarding the frame with
/// the destination MAC it arrived carrying, which the far side's NIC
/// reports as PACKET_OTHERHOST and its stack drops.
///
/// So this is a property of the box being a router, and it belongs in
/// the model like every other one. It is deliberately NOT a line in the
/// deployment guide: a box that needs an undocumented (or documented!)
/// manual sysctl to pass traffic will be set up wrong, and the failure
/// it produces is silent everywhere except this file.
///
/// IPv4 only, on purpose. v0.4's conntrack, NAT and now its routed
/// forward are all IPv4; enabling v6 forwarding here would claim a
/// capability the datapath does not have, and it changes RA behaviour
/// on every interface as a side effect.

#ifndef INCLUDE_F_SYSCONFIG_SYSCTL_H_
#define INCLUDE_F_SYSCONFIG_SYSCTL_H_

#include <expected>
#include <string>
#include <vector>

#include "f/sysconfig/artifact.h"
#include "f/sysconfig/model.h"

namespace f::sysconfig {

/// One generated sysctl.d drop-in.
struct SysctlUnit {
  std::string path;
  std::string content;
};

/// Where the drop-in goes, and where the live values are written.
struct SysctlOptions {
  std::string dir = "/etc/sysctl.d";
  /// The live kernel knobs. Overridable so a test can point it at a
  /// temp tree instead of the running kernel.
  std::string proc_dir = "/proc/sys";
  bool refuse_on_drift = true;
  /// Write the values to the running kernel as well as to disk. A
  /// drop-in nobody applies until the next reboot is the same silent
  /// failure with a longer fuse.
  bool apply_live = true;
};

/// The key/value pairs the model implies, in file order.
auto PlanSysctlValues(const SystemConfig& cfg)
    -> std::vector<std::pair<std::string, std::string>>;

/// The drop-in the model implies. Pure: no I/O.
auto PlanSysctl(const SystemConfig& cfg, const SysctlOptions& opts)
    -> SysctlUnit;

auto CheckSysctlDrift(const SysctlUnit& unit) -> DriftKind;

struct SysctlReport {
  SysctlUnit unit;
  bool changed = false;
  /// Keys written to the running kernel by this apply.
  std::vector<std::string> applied;
};

/// Install the drop-in and (unless disabled) push the values into the
/// running kernel, so the box forwards now and after a reboot rather
/// than only after one of the two.
auto ApplySysctl(const SystemConfig& cfg, const SysctlOptions& opts)
    -> std::expected<SysctlReport, std::string>;

/// Read one live sysctl through `proc_dir`. Empty when unreadable.
auto ReadLiveSysctl(const std::string& proc_dir, const std::string& key)
    -> std::string;

}  // namespace f::sysconfig

#endif  // INCLUDE_F_SYSCONFIG_SYSCTL_H_
