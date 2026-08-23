/// @file storage.h
/// @brief Keeping the appliance from filling its own disk, and saying
///        so before it does.
///
/// Two unbounded things, and both grow fastest exactly when the box is
/// working hardest.
///
/// **Compiled bundles.** Every `kReloadProg` writes a new
/// timestamped directory under `/usr/share/f/compiled/` and repoints
/// `current` at it. Nothing ever removed the old ones — the rig
/// carries ~500. Each is small, so this is not an emergency; it is an
/// unbounded set with no policy, which is the same thing arriving
/// slowly.
///
/// **Logs.** Sampled logging on a segment carrying office broadcast
/// storms is a high event rate, and journald's answer to a high event
/// rate is to *silently drop* — `RateLimitBurst` messages per
/// `RateLimitIntervalSec`, then "Suppressed N messages" and nothing
/// else. An appliance that quietly stops recording during the exact
/// minute worth recording is worse than one that stops working, so
/// the rule here is the same as everywhere else in this codebase:
///
/// **a log being dropped may not be invisible.** `StorageReport`
/// carries the suppression count as a first-class number, and every
/// empty answer carries the reason it is empty.

#ifndef INCLUDE_F_SYSCONFIG_STORAGE_H_
#define INCLUDE_F_SYSCONFIG_STORAGE_H_

#include <cstdint>
#include <expected>
#include <string>
#include <vector>

namespace f::sysconfig {

/// Where compiled bundles land and how many to keep.
struct RetentionPolicy {
  std::string compiled_dir = "/usr/share/f/compiled";
  /// How many bundles to keep, newest first. The one `current` points
  /// at is always kept regardless, because deleting the running
  /// policy to save disk space would be an outage caused by tidying.
  std::size_t keep = 10;
};

/// One bundle directory on disk.
struct BundleEntry {
  std::string name;
  std::string path;
  /// Bytes used by the directory's contents.
  std::uint64_t bytes = 0;
  /// Modification time, seconds since the epoch.
  std::int64_t mtime = 0;
  /// True when `current` points here. Never pruned.
  bool is_current = false;
  /// True when `last-known-good` points here. Also never pruned: it is
  /// the bundle `fd` falls back to when `current` will not load, and a
  /// fallback that housekeeping deleted is not a fallback.
  bool is_last_known_good = false;
};

/// What a prune would do, before it does it.
struct RetentionPlan {
  /// Every bundle found, newest first.
  std::vector<BundleEntry> bundles;
  /// Bundles this policy would remove, in the order it would remove
  /// them.
  std::vector<BundleEntry> to_remove;
  /// Bytes the removal would reclaim.
  std::uint64_t reclaimable_bytes = 0;
  /// Bytes used by all bundles.
  std::uint64_t total_bytes = 0;
  /// True when the directory could be read at all. False means the
  /// empty vectors above mean "we could not look", never "there is
  /// nothing there".
  bool readable = false;
  /// Why, when not readable.
  std::string unreadable_reason;
};

/// Work out what to keep. Pure apart from reading directory metadata;
/// removes nothing.
auto PlanRetention(const RetentionPolicy& policy) -> RetentionPlan;

/// What a prune actually did.
struct PruneReport {
  std::vector<std::string> removed;
  std::uint64_t reclaimed_bytes = 0;
  /// Bundles that could not be removed, with the reason. A prune that
  /// half-worked says which half.
  std::vector<std::string> failed;
};

/// Apply the policy. Never removes the bundle `current` points at.
auto PruneBundles(const RetentionPolicy& policy)
    -> std::expected<PruneReport, std::string>;

// -- logs --------------------------------------------------------------

/// How much journal to keep, and whether we are willing to lose
/// events to a rate limiter.
struct LogPolicy {
  /// Cap on the whole journal, e.g. "200M". An appliance's disk is
  /// small and shared with the thing it is meant to be doing.
  std::string max_use = "200M";
  /// Cap on one journal file, so rotation happens often enough that
  /// deleting the oldest reclaims a useful amount.
  std::string max_file_size = "20M";
  /// Keep at least this much free space on the filesystem.
  std::string keep_free = "100M";
  /// Rate limiting. Deliberately stated rather than defaulted: the
  /// distribution default silently discards a burst, and a burst is
  /// exactly what a storm looks like.
  std::string rate_limit_interval = "30s";
  /// 0 disables the limiter entirely — every event is written, and
  /// the disk cap is the only thing bounding it. That is the right
  /// trade for an appliance whose whole purpose is recording what
  /// happened on a hostile segment.
  int rate_limit_burst = 0;
};

/// The generated journald drop-in.
struct LogPlan {
  std::string content;
  LogPolicy policy;
};

auto PlanLogging(const LogPolicy& policy) -> LogPlan;

/// Where the journald drop-in is installed.
inline constexpr const char* kJournaldDropInPath =
    "/etc/systemd/journald.conf.d/10-f.conf";

/// Why a storage observation is missing.
enum class StorageAvailability {
  /// Read. Numbers mean what they say.
  kObserved,
  /// The paths could not be read — not the same as "nothing is
  /// using any space", and must never render as it.
  kUnreadable,
};

auto StorageAvailabilityName(StorageAvailability a) -> std::string;

/// What the box is currently using, and what it has lost.
struct StorageReport {
  StorageAvailability availability = StorageAvailability::kUnreadable;
  /// Filesystem holding the compiled bundles.
  std::uint64_t fs_total_bytes = 0;
  std::uint64_t fs_free_bytes = 0;
  /// Bundles.
  std::size_t bundle_count = 0;
  std::uint64_t bundle_bytes = 0;
  std::size_t bundles_over_policy = 0;
  /// Journal.
  std::uint64_t journal_bytes = 0;
  bool journal_read = false;
  /// Log events journald has discarded to its rate limiter.
  /// **The number this whole file exists for.** Non-zero means the
  /// box stopped recording during an interval somebody will later
  /// want to look at.
  ///
  /// Two caveats that matter operationally, both measured on systemd
  /// 257 in `test_log_storm.py`:
  ///
  ///  - The record is written at the **end** of the rate-limit
  ///    interval, not when discarding starts. A read taken during a
  ///    storm reports zero while messages are being thrown away.
  ///  - Worse, it is written **lazily**: on the next message from
  ///    that source after the interval expires. A box that goes quiet
  ///    after a storm never records that it dropped anything at all.
  ///
  /// Which is the argument for `RateLimitBurst=0` rather than for a
  /// better detector. This number catches a limiter somebody put
  /// back; it is not a thing to rely on.
  std::uint64_t suppressed_messages = 0;
  /// How many separate throttling episodes those messages came from.
  std::uint64_t suppression_bursts = 0;
  bool suppression_read = false;
  /// Reason, when something above could not be read.
  std::string detail;

  /// True when the filesystem is close enough to full that the next
  /// storm is a problem rather than a statistic.
  auto Tight() const -> bool {
    if (fs_total_bytes == 0) return false;
    return fs_free_bytes * 10 < fs_total_bytes;
  }
};

/// Where the storage report reads from. Injected so it can be tested
/// against fixtures rather than against the build machine's disk.
struct StorageSource {
  RetentionPolicy retention;
  /// Command reporting journal disk usage; empty to skip.
  std::string journal_usage_cmd = "journalctl --disk-usage";
  /// Command listing suppression records; empty to skip. The count
  /// is parsed out of each message, so what is reported is what was
  /// actually lost rather than how many times it happened.
  std::string suppressed_cmd =
      "journalctl --since=-24h --no-pager --quiet "
      "--grep='Suppressed [0-9]+ messages'";
};

auto QueryStorage(const StorageSource& src) -> StorageReport;

/// The banner a view prints when the box is losing events or running
/// out of room. Empty when neither is true — a warning that is always
/// there is a warning nobody reads.
auto StorageWarningBanner(const StorageReport& report) -> std::string;

}  // namespace f::sysconfig

#endif  // INCLUDE_F_SYSCONFIG_STORAGE_H_
