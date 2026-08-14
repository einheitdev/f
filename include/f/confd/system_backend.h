/// @file system_backend.h
/// @brief The appliance system configuration as a confd ConfigBackend.
///
/// `apply system` changes the box's own network: interface names,
/// addresses, which zone a port lives in, which zone DHCP answers on.
/// Every one of those can sever the operator's access to the box they
/// are changing. That is precisely what commit-confirmed exists for —
/// apply, start a timer, and if nobody confirms within the window, put
/// the previous configuration back.
///
/// The timer has to outlive the session that armed it, or it protects
/// nothing: a CLI over SSH dies with the SSH connection, which is the
/// very failure being guarded against. confd's Runtime already owns a
/// correct, durable, restart-surviving implementation of that timer —
/// this class is the other half of its seam: what "apply" means for
/// the f appliance.
///
/// The candidate is one key, `system.config`, whose value is the digest
/// of a system configuration. The text itself lives in a
/// content-addressed snapshot directory, because confd's durable store
/// holds single-token values and a YAML document is not one. That
/// indirection is also what makes a revert exact: the previous
/// revision is restored byte-for-byte, not re-derived.

#ifndef INCLUDE_F_CONFD_SYSTEM_BACKEND_H_
#define INCLUDE_F_CONFD_SYSTEM_BACKEND_H_

#include <expected>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "einheit/cli/confd/config_backend.h"
#include "einheit/cli/schema.h"

namespace f::confd {

/// The candidate key naming what to install: the digest of a system
/// configuration held in the snapshot store.
inline constexpr const char* kConfigKey = "system.config";

/// Optional candidate key, "true" to overwrite generated artifacts
/// that were edited by hand instead of refusing. It is per-revision
/// rather than per-daemon so `apply system force` stays an operator
/// decision. Note the consequence: an auto-revert re-applies the
/// previous revision with *that* revision's setting, so a hand edit
/// made during a confirm window can block the revert. The generated
/// files say not to edit them for exactly this reason.
inline constexpr const char* kForceKey = "system.force";

/// What an apply changed, handed to the activator so it only disturbs
/// the services whose inputs actually moved.
struct Activation {
  /// networkd unit files written by this apply.
  std::vector<std::string> networkd_changed;
  /// True when the generated dnsmasq artifact changed.
  bool dnsmasq_changed = false;
};

/// Makes written artifacts take effect. Returns a description of what
/// it ran (shown to the operator), or why it could not. Injected so a
/// test can prove activation was requested without reconfiguring the
/// host's network.
using Activator = std::function<
    std::expected<std::string, std::string>(const Activation&)>;

/// The activator used on the appliance: reloads systemd-networkd and
/// restarts the generated-config services whose inputs changed.
auto DefaultActivator() -> Activator;

/// An activator that does nothing and says so. For hosts where the
/// operator activates by hand (and for tests).
auto NullActivator() -> Activator;

/// Where the backend reads and writes.
struct SystemBackendOptions {
  /// The running system configuration.
  std::string config_path = "/etc/f/system.yaml";
  /// Content-addressed store of every configuration ever applied.
  std::string snapshot_dir = "/var/lib/f/confd/snapshots";
  /// Generated dnsmasq artifact.
  std::string dnsmasq_conf = "/etc/f/generated/dnsmasq.conf";
  /// dnsmasq binary, used for its own config check.
  std::string dnsmasq_path = "/usr/sbin/dnsmasq";
  /// Generated networkd unit directory.
  std::string networkd_dir = "/etc/systemd/network";
  /// Generated sysctl drop-in directory. The forwarding setting lives
  /// here because a router that does not forward is a configuration
  /// fault, not a deployment note.
  std::string sysctl_dir = "/etc/sysctl.d";
  /// Where the live kernel knobs are written. A test points this at a
  /// temp tree; nothing else should.
  std::string sysctl_proc_dir = "/proc/sys";
  /// Discard hand edits to generated artifacts instead of refusing.
  bool force = false;
  /// How the written artifacts are made live. Defaults to
  /// DefaultActivator().
  Activator activate;
};

/// confd's product seam for the appliance system configuration.
/// Thread-safe: the runtime calls Apply from a client thread and from
/// its own revert timer.
class SystemBackend final
    : public einheit::cli::confd::ConfigBackend {
 public:
  explicit SystemBackend(SystemBackendOptions opts);
  ~SystemBackend() override = default;

  /// Install the configuration named by the candidate's digest:
  /// validate it, write the derived networkd/dnsmasq artifacts, make
  /// the configuration itself the running one, and activate. An empty
  /// candidate means the baseline — the configuration found on the box
  /// when confd first started — so the auto-revert of a first-ever
  /// commit has somewhere to go.
  auto Apply(const einheit::cli::confd::Candidate& candidate)
      -> std::expected<einheit::cli::confd::CommitId,
                       einheit::cli::Error<
                           einheit::cli::confd::ApplyError>> override;

  /// The configuration on disk right now, as a one-key candidate.
  auto ReadRunning() -> einheit::cli::confd::Config override;

  auto Schema() const
      -> const einheit::cli::schema::Schema& override;

  /// What the last successful Apply actually did, in the words the
  /// operator should see (which units were written, what was
  /// reloaded). Empty before the first apply.
  auto LastReport() const -> std::string;

  /// Digest of the baseline configuration — what an empty candidate
  /// resolves to. Exposed for tests and status.
  auto BaselineDigest() const -> std::string;

  /// Record `text` in the snapshot store and return its digest, so a
  /// candidate can name a configuration that is not (yet) the file on
  /// disk.
  auto Snapshot(const std::string& text)
      -> std::expected<std::string, std::string>;

 private:
  auto LoadSnapshot(const std::string& digest) const
      -> std::expected<std::string, std::string>;

  SystemBackendOptions opts_;
  einheit::cli::schema::Schema schema_;
  std::string baseline_digest_;
  mutable std::mutex mu_;
  std::string last_report_;
  einheit::cli::confd::CommitId generation_ = 0;
};

}  // namespace f::confd

#endif  // INCLUDE_F_CONFD_SYSTEM_BACKEND_H_
