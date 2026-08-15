/// @file chrony.h
/// @brief chrony backend: the model's NTP, rendered — and the clock's
///        own trustworthiness, reported.
///
/// Two things live here because they are two halves of one problem.
///
/// The **backend** is the same shape as dnsmasq: a client on the
/// uplink, a server for the zones that ask for one, and the set of
/// addresses it answers on derived from zone membership rather than
/// maintained by hand. When no zone asks for a server, chrony is told
/// `port 0` and does not open the server port at all — the same
/// structural containment as the DHCP gate, one directive wide.
///
/// The **clock status** is here because time is the one dependency
/// every other subsystem has and none of them declare. Conntrack
/// timeouts, rate-limit windows and every log line are stated in it.
/// A board with no battery-backed RTC boots at the epoch and stays
/// there until NTP catches up, so a log gathered at the office to be
/// analysed later can be stamped 1970 — which does not merely look
/// wrong, it destroys the ordering the analysis depends on.
///
/// So the rule for this file is the same one the lease view follows:
/// **the clock reports its own trustworthiness, and an untrusted
/// clock is a named state rather than a number that happens to be
/// small.**

#ifndef INCLUDE_F_SYSCONFIG_CHRONY_H_
#define INCLUDE_F_SYSCONFIG_CHRONY_H_

#include <cstdint>
#include <expected>
#include <string>
#include <vector>

#include "f/sysconfig/dnsmasq.h"
#include "f/sysconfig/model.h"

namespace f::sysconfig {

/// What a chrony generation produced, before anything touches disk.
struct ChronyPlan {
  /// False when nothing wants chrony at all — no upstream to follow
  /// and no zone to serve. It should then not run, rather than run
  /// doing nothing.
  bool needed = false;
  /// The complete file contents.
  std::string content;
  /// Zones we serve time to, in declaration order.
  std::vector<std::string> served_zones;
  /// Addresses the server answers on, derived from zone membership.
  std::vector<std::string> bind_addresses;
  /// Subnets allowed to ask, derived the same way.
  std::vector<std::string> allowed_subnets;
  /// True when the server port is open at all. False means `port 0`,
  /// which is the containment: with no zone asking, there is no
  /// listening socket to leak onto the office network.
  bool serves = false;
  /// Upstream sources we follow.
  std::vector<std::string> upstreams;
};

/// Render the model as a chrony config. Pure: no I/O, no clock, no
/// environment.
auto PlanChrony(const SystemConfig& cfg) -> ChronyPlan;

/// Run chronyd's own config check over `content`.
/// @param near_path Where the real artifact will live. The scratch
///   file is written beside it rather than in /tmp, so the check is
///   subject to the same AppArmor confinement the daemon will be.
auto CheckWithChrony(const std::string& content,
                     const std::string& chronyd_path,
                     const std::string& near_path)
    -> std::expected<std::string, Error<BackendError>>;

/// Compare the artifact at `path` against what `cfg` generates.
auto CheckChronyDrift(const SystemConfig& cfg,
                      const std::string& path) -> DriftKind;

/// Where the backend writes and what it shells out to.
///
/// The default path is **not** `/etc/f/generated/` like every other
/// artifact, and that is deliberate. Debian's stock AppArmor profile
/// confines chronyd to reading `/etc/chrony/{,**}`, so a generated
/// config anywhere else produces `Fatal error : Could not open ... :
/// Permission denied` — on a file the operator can see, read and cat
/// perfectly well, which makes it one of the more baffling ways for a
/// service to refuse to start. Writing where the daemon is already
/// permitted to read is one fewer thing that has to be installed
/// correctly, so the artifact moves rather than the policy.
/// See BUGLOG #30.
struct ChronyOptions {
  std::string conf_path = "/etc/chrony/f-generated.conf";
  std::string chronyd_path = "/usr/sbin/chronyd";
  bool refuse_on_drift = true;
};

/// generate -> validate -> write. Restarting is the caller's business.
auto ApplyChrony(const SystemConfig& cfg, const ChronyOptions& opts)
    -> std::expected<ApplyReport, Error<BackendError>>;

// -- the clock's own trustworthiness ----------------------------------

/// How much the clock can be believed. This is a type rather than a
/// boolean because the three bad cases need different actions, and
/// because a renderer that gets a bare timestamp cannot ask.
enum class TimeTrust {
  /// The kernel says the clock is disciplined by a time source.
  /// Timestamps mean what they say.
  kSynchronised,
  /// A time source is configured and has not converged yet. Normal
  /// for the first seconds after boot; a fault if it persists.
  kNotYetSynchronised,
  /// Nothing is configured to set the clock. It will drift, and on a
  /// board with no battery-backed RTC it never left the epoch.
  kNoTimeSource,
  /// The state could not be determined. **Not** the same as
  /// synchronised, and must never render as it.
  kUnknown,
};

auto TimeTrustName(TimeTrust t) -> std::string;

/// Whether the box has somewhere to keep time across a power cut.
enum class RtcPresence {
  /// A real-time clock device exists.
  kPresent,
  /// No RTC device. Every boot starts from whatever the filesystem
  /// timestamps suggest, which is to say: not from the right time.
  kAbsent,
  /// Could not tell.
  kUnknown,
};

auto RtcPresenceName(RtcPresence p) -> std::string;

/// The whole picture. Every field that can be absent says which kind
/// of absent it is.
struct TimeStatus {
  TimeTrust trust = TimeTrust::kUnknown;
  RtcPresence rtc = RtcPresence::kUnknown;
  /// The RTC device, when there is one, e.g. "rtc0 (rk808-rtc)".
  std::string rtc_name;
  /// Wall-clock seconds since the epoch, as the box believes it.
  std::int64_t wall_seconds = 0;
  /// Seconds since boot. Always trustworthy — it is monotonic and
  /// owes nothing to NTP, which is why it is the fallback ordering
  /// for anything timestamped before the clock was set.
  std::int64_t uptime_seconds = 0;
  /// True when the wall clock is implausibly early: the box is
  /// running at or near the epoch and has not yet been told
  /// otherwise. This is the 1970-log case, detected rather than
  /// waited for.
  bool implausible = false;
  /// The kernel's estimate of maximum error, microseconds. Large is
  /// the normal reading before the first correction.
  std::int64_t max_error_us = 0;
  /// What chronyd says about its reference, when it can be asked.
  /// Empty when chronyc is absent or the daemon is not running.
  std::string reference;
  /// Why the answer is what it is, in one sentence, for the operator.
  std::string detail;

  /// True when a timestamp taken now can be relied upon. The one
  /// question every caller actually has.
  auto Trustworthy() const -> bool {
    return trust == TimeTrust::kSynchronised && !implausible;
  }
};

/// Where the status is read from. Injected so the report can be
/// tested against fixtures rather than against whatever the build
/// machine's clock happens to be doing.
struct TimeSource {
  /// Directory listing RTC devices.
  std::string rtc_dir = "/sys/class/rtc";
  /// Seconds since boot.
  std::string uptime_path = "/proc/uptime";
  /// Command that reports the reference; empty to skip.
  std::string chronyc_cmd = "chronyc -n tracking";
  /// When non-zero, used instead of the real wall clock.
  std::int64_t fake_wall_seconds = 0;
  /// When non-zero, used instead of a real adjtimex() call: 1 means
  /// synchronised, 2 not yet, 3 no source, 4 unknown.
  int fake_trust = 0;
  /// Kernel max-error override for tests, microseconds.
  std::int64_t fake_max_error_us = -1;
};

/// Ask the box what time it is and whether it should be believed.
auto QueryTime(const SystemConfig& cfg, const TimeSource& src)
    -> TimeStatus;

/// The banner a view prints above timestamps it cannot vouch for.
/// Empty when the clock is trustworthy — a warning that is always
/// there is a warning nobody reads.
auto TimeWarningBanner(const TimeStatus& status) -> std::string;

}  // namespace f::sysconfig

#endif  // INCLUDE_F_SYSCONFIG_CHRONY_H_
