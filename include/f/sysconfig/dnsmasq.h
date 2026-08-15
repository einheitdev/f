/// @file dnsmasq.h
/// @brief dnsmasq backend: the model's DHCP and DNS, rendered.
///
/// We do not implement DHCP or DNS. dnsmasq is somebody else's daemon
/// and it is good. What we own is the config model above it, and the
/// rule that the generated file is a *derived artifact*:
///
///     generate -> validate -> apply -> confirm
///
/// The file is never hand-edited. A file that has drifted from the
/// model is a fault to report, not something to silently regenerate
/// over — the same treatment FWL gives emitted BPF.
///
/// The interface lists in the generated config are computed from zone
/// membership on every generation. Nothing about them is maintained by
/// hand, which is what makes "DHCP answers on the uplink" a state the
/// system cannot reach rather than one it is trusted not to.

#ifndef INCLUDE_F_SYSCONFIG_DNSMASQ_H_
#define INCLUDE_F_SYSCONFIG_DNSMASQ_H_

#include <expected>
#include <string>
#include <vector>

#include "f/error.h"
#include "f/sysconfig/artifact.h"
#include "f/sysconfig/model.h"

namespace f::sysconfig {

/// What a generation produced, before anything touches the disk.
struct DnsmasqPlan {
  /// False when no service is bound anywhere — dnsmasq should not run
  /// at all rather than run doing nothing.
  bool needed = false;
  /// The complete file contents.
  std::string content;
  /// Interfaces dnsmasq may use, derived from the zones that have any
  /// service bound.
  std::vector<std::string> allowed_interfaces;
  /// Declared interfaces explicitly excluded. Every declared
  /// interface appears in exactly one of these two lists.
  std::vector<std::string> excluded_interfaces;
  /// Interfaces on which DHCP may answer. A strict subset of
  /// `allowed_interfaces`.
  std::vector<std::string> dhcp_interfaces;
  /// Interfaces into which we advertise a v6 prefix — the zones whose
  /// stance is `ra`, and only those.
  std::vector<std::string> ra_interfaces;
  /// Interfaces into which we explicitly refuse to advertise. Every
  /// declared interface is in exactly one of these two lists, so the
  /// artifact states its v6 containment rather than implying it by
  /// omission.
  std::vector<std::string> ra_refused_interfaces;
  /// True when any bound DNS forwarder discards upstream answers that
  /// point into private address space. Carried out of the plan
  /// because its failure mode is a name that silently does not exist,
  /// which no other view of the box would show.
  bool rebind_protection = false;
  /// Domains exempted from that discard.
  std::vector<std::string> rebind_exempt;
};

/// Render the model as a dnsmasq config. Pure: no I/O, no clock, no
/// environment. This is the function the containment tests hammer.
auto PlanDnsmasq(const SystemConfig& cfg) -> DnsmasqPlan;

/// Why a backend operation failed.
enum class BackendError {
  /// The daemon's own config check rejected the generated file.
  kToolRejected,
  /// The daemon binary is not present.
  kToolMissing,
  /// Could not write the artifact.
  kWriteFailed,
  /// The model itself does not validate; nothing was generated.
  kModelInvalid,
  /// The on-disk artifact drifted; refusing to overwrite silently.
  kDrift,
};

/// Run dnsmasq's own config-check mode over `content`.
/// @param content Generated config text.
/// @param dnsmasq_path Path to the dnsmasq binary.
/// @returns dnsmasq's stdout+stderr on success, or the rejection.
auto CheckWithDnsmasq(const std::string& content,
                      const std::string& dnsmasq_path)
    -> std::expected<std::string, Error<BackendError>>;

/// Compare the artifact at `path` against what `cfg` generates.
auto CheckDnsmasqDrift(const SystemConfig& cfg,
                       const std::string& path) -> DriftKind;

/// Where the backend writes and what it shells out to.
struct DnsmasqOptions {
  std::string conf_path = "/etc/f/generated/dnsmasq.conf";
  std::string dnsmasq_path = "/usr/sbin/dnsmasq";
  /// Refuse to overwrite an artifact that was hand-edited.
  bool refuse_on_drift = true;
};

/// Result of a successful apply.
struct ApplyReport {
  /// True when the file on disk changed.
  bool changed = false;
  /// dnsmasq's config-check output, kept for the operator.
  std::string check_output;
  std::string conf_path;
  DnsmasqPlan plan;
};

/// generate -> validate -> write. Restarting the service is the
/// caller's business: a config that validates but a daemon that will
/// not start are two different faults and get two different messages.
auto ApplyDnsmasq(const SystemConfig& cfg,
                  const DnsmasqOptions& opts)
    -> std::expected<ApplyReport, Error<BackendError>>;

}  // namespace f::sysconfig

#endif  // INCLUDE_F_SYSCONFIG_DNSMASQ_H_
