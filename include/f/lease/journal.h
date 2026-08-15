/// @file journal.h
/// @brief When each device first appeared, and when it was last seen.
///
/// The lease file cannot answer "is this new?". A lease that was just
/// issued and a lease that has been renewed every twelve hours for a
/// month are the same three fields on disk. So arrival is something
/// that has to be *observed* — recorded the moment a MAC that was not
/// there is there — and the record has to outlive the command that
/// noticed it.
///
/// The one thing this file must not do is guess. The first time the
/// journal runs on a box that has been serving DHCP for a week, every
/// device on it looks brand new, and rendering them as new arrivals
/// would train the operator to ignore the column that exists to catch
/// his eye. So each record carries how its arrival time was come by:
/// watched (exact) or inferred from the lease (an upper bound, and
/// displayed as one). A device is only ever called *new* when we
/// actually saw it turn up.

#ifndef INCLUDE_F_LEASE_JOURNAL_H_
#define INCLUDE_F_LEASE_JOURNAL_H_

#include <cstddef>
#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <vector>

#include "f/error.h"
#include "f/lease/lease.h"

namespace f::lease {

/// Where the device history is kept.
inline constexpr const char* kJournalPath = "/var/lib/f/devices.json";

/// Upper bound on retained records. A busy segment must not grow the
/// journal without limit; the least recently seen device is dropped
/// first, because it is the one whose history is least likely to be
/// asked about.
inline constexpr std::size_t kMaxRecords = 4096;

/// How the arrival time in a record was arrived at.
enum class FirstSeenPrecision {
  /// We watched it turn up: absent at one observation, present at the
  /// next. The timestamp is when we noticed, to within the polling
  /// interval.
  kObserved,
  /// It was already there the first time anything looked. The lease
  /// says when it was last issued, which is an *upper bound* on
  /// arrival — the device may have been on the wire far longer. Shown
  /// with a `>=` so it is never mistaken for a measurement.
  kInferred,
};

auto FirstSeenPrecisionName(FirstSeenPrecision p) -> std::string;

/// What the journal remembers about one MAC.
struct DeviceRecord {
  std::string mac;
  /// The most recent address this MAC held.
  std::string address;
  std::string hostname;
  /// Unix seconds.
  std::int64_t first_seen = 0;
  FirstSeenPrecision precision = FirstSeenPrecision::kInferred;
  /// Unix seconds at the last observation that found it holding a
  /// lease.
  std::int64_t last_seen = 0;
  /// Unix seconds at the most recent observed absent-to-present
  /// transition, or 0 if we have never watched this device turn up.
  /// This — not `first_seen` — is what makes a row worth highlighting:
  /// a board that was unplugged over lunch and came back is a new
  /// arrival even though it is not a new device.
  std::int64_t last_arrival = 0;
  /// Whether the previous observation found it holding a lease.
  /// Persisted so that arrivals and departures are transitions across
  /// invocations, not a set difference recomputed from scratch every
  /// time (which would report the same departure forever).
  bool present = false;
  /// How many times this MAC has been seen on a different address than
  /// the one before. A board that keeps changing address is a fault
  /// worth noticing.
  int address_changes = 0;
};

/// The whole history.
struct Journal {
  std::vector<DeviceRecord> records;

  auto Find(std::string_view mac) const -> const DeviceRecord*;
};

/// What one observation changed. Every field is a *transition*, not a
/// state: a device that has been gone for a week is reported as
/// departed exactly once, on the observation that noticed. Returned
/// rather than logged so the watch loop can say what happened instead
/// of just redrawing.
struct ObserveResult {
  /// MACs that held no lease at the previous observation and hold one
  /// now. Empty on the very first observation by construction — with
  /// no previous look, nothing can be said to have arrived.
  std::vector<std::string> arrived;
  /// MACs that held a lease at the previous observation and do not
  /// now.
  std::vector<std::string> departed;
  /// MACs whose address changed since the last observation.
  std::vector<std::string> readdressed;
  /// True when this journal had no records at all beforehand.
  bool first_observation = false;

  /// True when nothing changed. The watch loop redraws only when this
  /// is false, so a quiet segment does not repaint the terminal every
  /// two seconds and hide the one line that matters.
  auto Quiet() const -> bool {
    return arrived.empty() && departed.empty() &&
           readdressed.empty();
  }
};

/// Fold a set of current leases into the journal.
///
/// @param j Journal to update in place.
/// @param leases Leases read from dnsmasq, right now.
/// @param now Unix seconds.
/// @param lease_seconds The configured lease time, used only to place
///   a first sighting that we did not watch happen: `expiry -
///   lease_seconds` is when the lease was last issued, and therefore
///   an upper bound on when the device arrived. Pass 0 when it is not
///   known, and `now` is used instead — still marked inferred.
/// @param first_observation True when the journal was newly created
///   rather than loaded, i.e. nothing was ever observed before. Every
///   device found is then a discovery, not an arrival.
auto Observe(Journal& j, const std::vector<Lease>& leases,
             std::int64_t now, std::uint32_t lease_seconds,
             bool first_observation) -> ObserveResult;

/// Why the journal could not be loaded.
enum class JournalError {
  /// Nothing at the path. Not a fault: it is how a box starts.
  kAbsent,
  /// Present and unreadable.
  kUnreadable,
  /// Present, readable, and not a journal.
  kCorrupt,
};

/// Load the journal from `path`.
auto LoadJournal(const std::string& path)
    -> std::expected<Journal, Error<JournalError>>;

/// Serialise the journal. Exposed for tests.
auto SerializeJournal(const Journal& j) -> std::string;

/// Parse a serialised journal. Exposed for tests.
auto DeserializeJournal(std::string_view text)
    -> std::expected<Journal, Error<JournalError>>;

/// Write the journal to `path`, creating parent directories, via a
/// temporary file and a rename so a crash cannot leave a half-written
/// history behind.
/// @returns nothing, or why the write failed.
auto SaveJournal(const std::string& path, const Journal& j)
    -> std::expected<void, std::string>;

}  // namespace f::lease

#endif  // INCLUDE_F_LEASE_JOURNAL_H_
