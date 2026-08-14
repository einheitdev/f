/// @file view.h
/// @brief What is on the network, assembled from everything that knows.
///
/// This is the join: the lease file says who holds an address, the
/// journal says since when, and the system configuration says which
/// zone that address is in and whether a reservation was promised.
///
/// The type that matters here is not `Device`, it is
/// `LeaseAvailability`. An empty device list is not information on its
/// own — it means "nothing is leased" or "nothing serves DHCP" or "the
/// file is there and I am not allowed to read it", and those want three
/// different things done about them. Making the renderer take the
/// reason as well as the list is the only way to keep a blank table
/// from being the same picture as a broken one.

#ifndef INCLUDE_F_LEASE_VIEW_H_
#define INCLUDE_F_LEASE_VIEW_H_

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "f/lease/journal.h"
#include "f/lease/lease.h"
#include "f/sysconfig/model.h"

namespace f::lease {

/// Why the lease list looks the way it does. Never inferred from the
/// list being empty.
enum class LeaseAvailability {
  /// The lease file was read. An empty list here means no client holds
  /// a lease.
  kOk,
  /// The model binds no DHCP server to any zone. There is no lease
  /// database and there will not be one until DHCP is configured.
  kNoDhcpConfigured,
  /// DHCP is configured and there is no lease file: dnsmasq has not
  /// started, or no client has ever asked it for an address.
  kNoLeaseFileYet,
  /// The lease file exists and could not be read. This is the case
  /// that must never render as "no devices".
  kUnreadable,
};

auto LeaseAvailabilityName(LeaseAvailability a) -> std::string;

/// Whether arrival times are being recorded.
enum class JournalAvailability {
  /// Loaded and saved.
  kOk,
  /// There was no journal before this call. Everything found is a
  /// discovery rather than an arrival, and every arrival time is an
  /// upper bound.
  kFirstObservation,
  /// The journal was read and could not be written back, so what this
  /// command learned will be forgotten. Arrival detection stops
  /// working from here on, which is worth saying out loud.
  kUnwritable,
  /// The journal is there and could not be read or made sense of.
  kUnreadable,
};

auto JournalAvailabilityName(JournalAvailability a) -> std::string;

/// One device, as the operator should see it.
struct Device {
  std::string mac;
  std::string address;
  std::string hostname;
  /// The zone whose interface subnet contains `address`. Empty when no
  /// declared interface covers it — which for a DHCP lease means the
  /// system configuration and the running dnsmasq disagree.
  std::string zone;
  /// Unix seconds; see `precision`.
  std::int64_t first_seen = 0;
  FirstSeenPrecision precision = FirstSeenPrecision::kInferred;
  std::int64_t last_seen = 0;
  std::int64_t last_arrival = 0;
  /// Lease expiry in unix seconds; 0 for an infinite lease.
  std::int64_t expiry = 0;
  /// True when the device holds a lease right now. False rows are
  /// history: a device that was here and is not.
  bool active = false;
  /// True when the system configuration reserves an address for this
  /// MAC.
  bool reserved = false;
  /// The reserved address, when `reserved`. A mismatch between this
  /// and `address` means the reservation was added after the current
  /// lease was issued and has not taken effect yet.
  std::string reserved_address;
  int address_changes = 0;

  /// True when we watched this device turn up within `window` seconds
  /// of `now`. Inferred first sightings never count: the point of the
  /// flag is that it means something.
  auto IsNew(std::int64_t now, std::int64_t window) const -> bool;
};

/// Everything a lease view found, and everything it could not.
struct DeviceReport {
  std::vector<Device> devices;
  LeaseAvailability leases = LeaseAvailability::kOk;
  JournalAvailability journal = JournalAvailability::kOk;
  /// The concrete reason behind a non-Ok availability — the errno text
  /// or parse message. Empty when everything worked.
  std::string detail;
  std::string lease_path;
  std::string journal_path;
  /// Lines of the lease file that did not parse, verbatim.
  std::vector<std::string> unparsable;
  std::size_t ipv6_skipped = 0;
  /// Transitions this observation noticed.
  ObserveResult changes;

  /// Devices currently holding a lease.
  auto ActiveCount() const -> std::size_t;
};

/// How long after an observed arrival a device is still called new.
inline constexpr std::int64_t kNewWindowSeconds = 900;

/// Join the three sources. Pure: no clock, no filesystem, no daemon.
/// Every case the renderer has to distinguish is decided here, where it
/// can be tested without a box.
/// @param cfg The system configuration (zones, subnets, reservations).
/// @param leases Current leases, or empty when unavailable.
/// @param journal Device history after the observation.
/// @param now Unix seconds.
auto BuildReport(const sysconfig::SystemConfig& cfg,
                 const std::vector<Lease>& leases,
                 const Journal& journal, std::int64_t now)
    -> DeviceReport;

/// Where the reader looks. Injected so tests never touch /var.
struct ViewOptions {
  std::string lease_path = kLeaseFilePath;
  std::string journal_path = kJournalPath;
  /// When false, the journal is read but not written back. Used by
  /// read-only callers so that merely looking does not rewrite
  /// history.
  bool record = true;
};

/// Read the lease file, fold it into the journal, save it, and build
/// the report. This is the one function with side effects, and its
/// side effect — recording that we looked — is the only reason arrival
/// times exist at all.
/// @param cfg The system configuration.
/// @param opts Paths and whether to record.
/// @param now Unix seconds.
auto CollectDevices(const sysconfig::SystemConfig& cfg,
                    const ViewOptions& opts, std::int64_t now)
    -> DeviceReport;

/// Find the devices in `report` matching a free-form operator query: a
/// MAC in any spelling, an IPv4 address, or a hostname (exact, then
/// case-insensitive prefix). Returns every match rather than the first,
/// so an ambiguous query is reported as ambiguous rather than silently
/// resolved to whichever row happened to sort first.
auto MatchDevices(const DeviceReport& report,
                  const std::string& query)
    -> std::vector<const Device*>;

/// Render a duration in seconds as a compact age: `44s`, `12m`, `3h`,
/// `6d`. Used for every elapsed time the CLI prints so they all read
/// the same.
auto FormatAge(std::int64_t seconds) -> std::string;

}  // namespace f::lease

#endif  // INCLUDE_F_LEASE_VIEW_H_
