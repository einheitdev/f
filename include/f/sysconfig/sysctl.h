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
/// ## The value is 0, and it was 1. The reversal, 2026-08-15.
///
/// This file used to plan `ip_forward = 1` unconditionally, and said
/// so: deriving it — "forward only when two zones carry interfaces" —
/// creates a second way for the box to be silently non-routing, which
/// is the fault this file exists to remove.
///
/// That reasoning was not wrong; it was outranked. A box was measured
/// with its compiled bundle removed: `fd` correctly refused to start,
/// attached nothing, and logged why — and the box went on routing,
/// because this drop-in had set the knob at provisioning time and
/// `systemd-sysctl` reapplied it every boot. An unsolicited inbound
/// TCP connection that the healthy box refused with ZERO frames on the
/// inside wire completed with four, and outbound flows left
/// un-masqueraded with inside addresses on them, because the NAT lived
/// in the XDP program that was not there. The operator's call:
///
///   **a box that does not forward is a VISIBLE fault; a box that
///   forwards unfiltered is an INVISIBLE one.**
///
/// The replacement is not the derivation that was rejected. Nothing
/// here counts zones or reads a policy. `fd` sets the live value from
/// one fact it establishes rather than infers — how many interfaces
/// the kernel accepted an XDP program on — and this drop-in is reduced
/// to the boot-time floor for the window before fd has spoken and for
/// the box on which it never starts. The old concern is answered by
/// `RouteMgr` being LOUD rather than by being unconditional: see
/// `f/route_mgr.h` for the invariant, for why the periodic check is
/// asymmetric, and for the `fctl status` row that says why a box has
/// stopped forwarding instead of leaving it to be guessed.
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
  /// Whether this apply may touch the running kernel at all. It
  /// currently touches nothing: every key planned here is owned live
  /// by `fd`, and pushing the boot-time floor into a running kernel
  /// would stop a healthy box routing. See `ApplySysctl`.
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
  /// Keys written to the running kernel by this apply. Empty, and
  /// that is a statement: the live value of every key here belongs to
  /// `fd`. See `ApplySysctl`.
  std::vector<std::string> applied;
};

/// Install the boot-time drop-in. Does not touch the running kernel:
/// the live value of `ip_forward` is fd's, taken from whether a bundle
/// is in the packet path.
auto ApplySysctl(const SystemConfig& cfg, const SysctlOptions& opts)
    -> std::expected<SysctlReport, std::string>;

/// Read one live sysctl through `proc_dir`. Empty when unreadable.
auto ReadLiveSysctl(const std::string& proc_dir, const std::string& key)
    -> std::string;

}  // namespace f::sysconfig

#endif  // INCLUDE_F_SYSCONFIG_SYSCTL_H_
