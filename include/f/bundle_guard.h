/// @file bundle_guard.h
/// @brief Stopping a bundle that wedges the box from wedging it again.
///
/// `fd.service` carries `Restart=on-failure`, loads whatever
/// `<bundle_dir>/current` points at, and is ordered
/// `Before=network.target` — i.e. before sshd. So a bundle that takes
/// the box down while it is being loaded takes it down on *every*
/// boot, before anyone can reach it to change the symlink. Every other
/// anti-lockout property in this project is defended (commit-confirm
/// in confd, the revert timer, `fd close-forwarding` on ExecStopPost);
/// the bundle load path had nothing.
///
/// **The load cannot report its own failure.** That is the whole
/// design constraint. A bundle that returns an error is the easy case
/// and the loader already handles it. The case that loses a box is the
/// one measured on the rig: a load that pins every core, schedules
/// nothing in userspace, and ends in a watchdog reset or a power
/// cycle. No handler runs. No log line is flushed. The only record
/// that survives is one written to disk *before* the attempt and
/// fsynced.
///
/// So the mechanism is a breadcrumb, not an exception handler:
///
///   1. `BundleGuardBegin` writes an attempt record naming the version
///      about to be loaded and increments its count, then fsyncs it
///      and the directory. This happens before the loader sees the
///      bundle.
///   2. If the record already shows this same version failing
///      `max_attempts` times, the bundle is quarantined and the loader
///      is never called. That is the boot trap being defused, and it
///      works whether the previous attempt returned an error, was
///      SIGKILLed, or took the whole board down.
///   3. `BundleGuardCommit` clears the record and repoints
///      `last-known-good` at the version — but only once the datapath
///      is actually attached, because "the process is still alive" was
///      never the property in question.
///
/// A bundle is therefore quarantined by *not having been observed to
/// work*, which is the only evidence available after a hard reset.
///
/// What happens next — run the last-known-good bundle, or refuse to
/// start and leave the box non-forwarding — is `GuardPolicy`, and it
/// is deliberately a setting rather than a hard-coded answer. Both are
/// defensible and the project's fail-closed stance argues for each of
/// them from a different direction.

#ifndef INCLUDE_F_BUNDLE_GUARD_H_
#define INCLUDE_F_BUNDLE_GUARD_H_

#include <cstdint>
#include <expected>
#include <string>
#include <vector>

namespace f {

/// What to do when `current` is quarantined and cannot be loaded.
enum class GuardPolicy : std::uint8_t {
  /// Load the last bundle this box was observed to attach with, and
  /// say so, loudly and continuously. The box keeps filtering, with a
  /// policy that is not the one the operator last asked for.
  kFallback,
  /// Do not start. `fd` lowers `net.ipv4.ip_forward` on its way out,
  /// so the box is reachable and non-routing. Nothing is enforced
  /// because nothing is forwarded.
  kFailClosed,
};

/// Parse a policy name; anything else is rejected by the caller.
auto ParseGuardPolicy(std::string_view name)
    -> std::expected<GuardPolicy, std::string>;

/// The name a policy is configured under.
auto GuardPolicyName(GuardPolicy policy) -> const char*;

/// Where the guard keeps its state, and how forgiving it is.
struct GuardConfig {
  /// Parent of `current`, `last-known-good` and the attempt record.
  std::string bundle_dir;
  /// How many times a version may be started without ever reaching
  /// "attached" before it is quarantined.
  ///
  /// One would be unforgiving: a power cut during an otherwise
  /// healthy load would condemn a good bundle. Two costs at most one
  /// extra wedge-and-reset cycle — one watchdog timeout — and tolerates
  /// a single fluke. Three is another reset for no more information.
  int max_attempts = 2;
  /// What to do once the ceiling is reached.
  GuardPolicy policy = GuardPolicy::kFallback;
};

/// The record on disk. Absent means "nothing has been started that did
/// not finish", which is the normal state of a healthy box.
struct AttemptRecord {
  /// Version directory name (the `current` symlink's target).
  std::string version;
  /// Starts of this version that never reached attached.
  int attempts = 0;
  /// Wall clock of the first and most recent attempt, seconds.
  std::int64_t first_s = 0;
  std::int64_t last_s = 0;
  /// Why the last attempt failed, when the loader lived long enough to
  /// say. Empty means it did not — which is the interesting case.
  std::string last_error;
  /// False when there was no record to read.
  bool present = false;
};

/// What the guard decided, before any loading happens.
enum class GuardVerdict : std::uint8_t {
  /// Load `version`. It is either fresh or has attempts left.
  kProceed,
  /// `current` has used up its attempts. `version` is the
  /// last-known-good to load instead (policy kFallback).
  kFallback,
  /// `current` has used up its attempts and there is nothing to fall
  /// back to, or the policy says do not.
  kRefuse,
};

/// The guard's answer for one start.
struct GuardDecision {
  GuardVerdict verdict = GuardVerdict::kProceed;
  /// Directory to load, absolute. Empty for kRefuse.
  std::string load_dir;
  /// The version name `load_dir` resolves to.
  std::string version;
  /// The version that was quarantined, when one was.
  std::string quarantined;
  /// The attempt record as it stood before this start.
  AttemptRecord record;
  /// One sentence naming what happened and why, always populated for
  /// anything other than a plain kProceed. This is the text that goes
  /// in the journal and in `fctl status`; a fallback that is not
  /// visible is a box quietly running a policy nobody asked for.
  std::string reason;
};

/// Read the attempt record, if any.
auto ReadAttemptRecord(const GuardConfig& cfg) -> AttemptRecord;

/// Resolve `<bundle_dir>/current` to a version name, or empty.
auto CurrentVersion(const std::string& bundle_dir) -> std::string;

/// Resolve `<bundle_dir>/last-known-good` to a version name, or empty.
///
/// A dangling link resolves to empty: a symlink pointing at a bundle
/// that has been pruned away is not a fallback, and reporting it as
/// one would turn a recoverable boot into a confusing one.
auto LastKnownGood(const std::string& bundle_dir) -> std::string;

/// Decide what to load, and record the attempt before returning.
///
/// Call this before anything touches the bundle. On kProceed the
/// attempt count for `version` has already been incremented and
/// written through to disk, so a load that never returns still leaves
/// evidence that it was tried.
auto BundleGuardBegin(const GuardConfig& cfg) -> GuardDecision;

/// Mark `version` as having reached an attached datapath.
///
/// Clears the attempt record and repoints `last-known-good`. Call it
/// only once the XDP programs are on interfaces — a daemon that is
/// merely still running is exactly the state this whole file exists
/// to distrust.
auto BundleGuardCommit(const GuardConfig& cfg,
                       const std::string& version)
    -> std::expected<void, std::string>;

/// Record why an attempt failed, for the operator who reads the record
/// later. Does not change the count — `BundleGuardBegin` already did
/// that, on purpose, because this call may never happen.
/// Discard this start's attempt record without marking the bundle
/// good.
///
/// For failures that say nothing about the bundle. The count exists to
/// catch a version that takes the board down; a feed file that could
/// not be read is a fact about the filesystem at that moment, not
/// about the policy, and counting it means a transient NFS blip or a
/// permissions mistake quarantines a bundle that has never failed to
/// load. Quarantine is permanent, so the cost of counting the wrong
/// thing is much higher than the cost of not counting.
///
/// Deliberately does NOT write `last-known-good`: nothing was proven
/// to work. It only rewinds a count that should not have advanced.
auto BundleGuardAbandon(const GuardConfig& cfg)
    -> std::expected<void, std::string>;

auto BundleGuardNoteFailure(const GuardConfig& cfg,
                            const std::string& version,
                            const std::string& why) -> void;

/// Point `<bundle_dir>/current` at `version`, atomically.
///
/// Exposed because a fallback has to move the symlink as well as load
/// the other bundle: leaving `current` pointing at the quarantined
/// version means the next boot re-reads a trap that only the attempt
/// record is holding shut.
auto PointCurrentAt(const std::string& bundle_dir,
                    const std::string& version)
    -> std::expected<void, std::string>;

/// Everything a status view needs to say the box is not running what
/// was asked for.
struct GuardStatus {
  std::string current;
  std::string last_known_good;
  std::string running;
  bool degraded = false;
  std::string reason;
  AttemptRecord record;
};

}  // namespace f

#endif  // INCLUDE_F_BUNDLE_GUARD_H_
