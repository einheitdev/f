/// @file view.cc
/// @brief Join leases, history and the model into a device view.

#include "f/lease/view.h"

#include <algorithm>
#include <cctype>
#include <format>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "f/sysconfig/net.h"

namespace f::lease {
namespace {

using sysconfig::SystemConfig;

auto Lower(const std::string& s) -> std::string {
  std::string out = s;
  for (auto& c : out) {
    c = static_cast<char>(
        std::tolower(static_cast<unsigned char>(c)));
  }
  return out;
}

/// The zone whose statically addressed interface covers `address`.
auto ZoneForAddress(const SystemConfig& cfg,
                    const std::string& address) -> std::string {
  auto a = sysconfig::ParseIpv4(address);
  if (!a) return "";
  for (const auto& i : cfg.interfaces) {
    if (i.mode != sysconfig::AddressMode::kStatic) continue;
    auto p = sysconfig::ParseCidr4(i.address);
    if (p && p->Contains(*a)) return i.zone;
  }
  return "";
}

/// The shortest configured lease time on the box.
///
/// It bounds a first sighting nobody watched: `expiry - lease_seconds`
/// is when the lease was issued, and the device was certainly there
/// then. Using the *shortest* configured lease makes that instant come
/// out later than reality when zones differ, which understates the
/// device's age — the safe direction for a claim rendered as "here for
/// at least this long".
auto ShortestLeaseSeconds(const SystemConfig& cfg) -> std::uint32_t {
  std::uint32_t best = 0;
  for (const auto& d : cfg.dhcp) {
    if (best == 0 || d.lease_seconds < best) best = d.lease_seconds;
  }
  return best;
}

struct ReservationHit {
  bool found = false;
  std::string address;
};

auto ReservationFor(const SystemConfig& cfg, const std::string& mac)
    -> ReservationHit {
  for (const auto& d : cfg.dhcp) {
    for (const auto& r : d.reservations) {
      if (r.mac == mac) return {true, r.address};
    }
  }
  return {};
}

}  // namespace

auto LeaseAvailabilityName(LeaseAvailability a) -> std::string {
  switch (a) {
    case LeaseAvailability::kOk:
      return "ok";
    case LeaseAvailability::kNoDhcpConfigured:
      return "no-dhcp-configured";
    case LeaseAvailability::kNoLeaseFileYet:
      return "no-lease-file-yet";
    case LeaseAvailability::kUnreadable:
      return "unreadable";
  }
  return "unknown";
}

auto JournalAvailabilityName(JournalAvailability a) -> std::string {
  switch (a) {
    case JournalAvailability::kOk:
      return "ok";
    case JournalAvailability::kFirstObservation:
      return "first-observation";
    case JournalAvailability::kUnwritable:
      return "unwritable";
    case JournalAvailability::kUnreadable:
      return "unreadable";
  }
  return "unknown";
}

auto Device::IsNew(std::int64_t now, std::int64_t window) const
    -> bool {
  if (last_arrival == 0) return false;
  return now >= last_arrival && now - last_arrival <= window;
}

auto DeviceReport::ActiveCount() const -> std::size_t {
  std::size_t n = 0;
  for (const auto& d : devices) {
    if (d.active) ++n;
  }
  return n;
}

auto FormatAge(std::int64_t seconds) -> std::string {
  if (seconds < 0) return "-";
  if (seconds < 60) return std::format("{}s", seconds);
  if (seconds < 3600) return std::format("{}m", seconds / 60);
  if (seconds < 86400) return std::format("{}h", seconds / 3600);
  return std::format("{}d", seconds / 86400);
}

auto BuildReport(const SystemConfig& cfg,
                 const std::vector<Lease>& leases,
                 const Journal& journal, std::int64_t now)
    -> DeviceReport {
  DeviceReport report;

  std::unordered_map<std::string, const Lease*> live;
  for (const auto& l : leases) live[l.mac] = &l;

  for (const auto& r : journal.records) {
    Device d;
    d.mac = r.mac;
    d.hostname = r.hostname;
    d.first_seen = r.first_seen;
    d.precision = r.precision;
    d.last_seen = r.last_seen;
    d.last_arrival = r.last_arrival;
    d.address_changes = r.address_changes;
    auto it = live.find(r.mac);
    if (it != live.end()) {
      d.active = true;
      d.address = it->second->address;
      d.expiry = it->second->expiry;
      if (!it->second->hostname.empty()) {
        d.hostname = it->second->hostname;
      }
    } else {
      // A device with no current lease still has a last known address;
      // showing it is how "it was at .157 an hour ago" survives the
      // lease expiring.
      d.address = r.address;
    }
    d.zone = ZoneForAddress(cfg, d.address);
    auto res = ReservationFor(cfg, d.mac);
    d.reserved = res.found;
    d.reserved_address = res.address;
    report.devices.push_back(std::move(d));
  }

  // A lease with no journal record can only happen when the journal
  // could not be written; show the device anyway rather than lose it,
  // with the history fields honestly blank.
  for (const auto& l : leases) {
    auto known = std::any_of(
        report.devices.begin(), report.devices.end(),
        [&](const Device& d) { return d.mac == l.mac; });
    if (known) continue;
    Device d;
    d.mac = l.mac;
    d.address = l.address;
    d.hostname = l.hostname;
    d.expiry = l.expiry;
    d.active = true;
    d.zone = ZoneForAddress(cfg, d.address);
    auto res = ReservationFor(cfg, d.mac);
    d.reserved = res.found;
    d.reserved_address = res.address;
    report.devices.push_back(std::move(d));
  }

  // Most recent arrival first: the thing just plugged in is the first
  // row, which is the entire point of the view.
  std::sort(report.devices.begin(), report.devices.end(),
            [](const Device& a, const Device& b) {
              if (a.active != b.active) return a.active;
              auto ka = a.last_arrival != 0 ? a.last_arrival
                                            : a.first_seen;
              auto kb = b.last_arrival != 0 ? b.last_arrival
                                            : b.first_seen;
              if (ka != kb) return ka > kb;
              return a.mac < b.mac;
            });
  (void)now;
  return report;
}

auto CollectDevices(const SystemConfig& cfg, const ViewOptions& opts,
                    std::int64_t now) -> DeviceReport {
  Journal journal;
  bool first_observation = false;
  auto journal_state = JournalAvailability::kOk;
  std::string detail;

  auto loaded = LoadJournal(opts.journal_path);
  if (loaded) {
    journal = std::move(*loaded);
  } else if (loaded.error().code == JournalError::kAbsent) {
    first_observation = true;
    journal_state = JournalAvailability::kFirstObservation;
  } else {
    // A journal that will not parse is not a journal we may overwrite:
    // the operator gets to look at it before it is replaced.
    journal_state = JournalAvailability::kUnreadable;
    detail = loaded.error().message;
  }
  const bool may_record =
      opts.record && journal_state != JournalAvailability::kUnreadable;

  std::vector<Lease> current;
  auto lease_state = LeaseAvailability::kOk;
  std::vector<std::string> unparsable;
  std::size_t ipv6_skipped = 0;

  auto read = ReadLeases(opts.lease_path);
  if (read) {
    current = std::move(read->leases);
    unparsable = std::move(read->unparsable);
    ipv6_skipped = read->ipv6_skipped;
  } else if (read.error().code == LeaseError::kAbsent) {
    lease_state = cfg.dhcp.empty()
                      ? LeaseAvailability::kNoDhcpConfigured
                      : LeaseAvailability::kNoLeaseFileYet;
  } else {
    lease_state = LeaseAvailability::kUnreadable;
    if (detail.empty()) detail = read.error().message;
  }

  ObserveResult changes;
  // An *absent* lease file is a real observation: dnsmasq has issued
  // nothing, so nothing is leased. Recording that is what makes the
  // next device to appear an arrival we watched rather than one we
  // found — which is the whole reason the first `show leases` on a
  // fresh box has to write the journal even though it has no rows.
  //
  // An *unreadable* one is not an observation at all. Folding it in
  // would mark every device as departed, so a permissions mistake
  // would quietly erase the history it exists to keep.
  if (lease_state != LeaseAvailability::kUnreadable) {
    changes = Observe(journal, current, now, ShortestLeaseSeconds(cfg),
                      first_observation);
    if (may_record) {
      auto saved = SaveJournal(opts.journal_path, journal);
      if (!saved) {
        journal_state = JournalAvailability::kUnwritable;
        detail = saved.error();
      }
    }
  }

  auto report = BuildReport(cfg, current, journal, now);
  report.lease_path = opts.lease_path;
  report.journal_path = opts.journal_path;
  report.leases = lease_state;
  report.journal = journal_state;
  report.detail = std::move(detail);
  report.unparsable = std::move(unparsable);
  report.ipv6_skipped = ipv6_skipped;
  report.changes = std::move(changes);
  return report;
}

auto MatchDevices(const DeviceReport& report,
                  const std::string& query)
    -> std::vector<const Device*> {
  std::vector<const Device*> out;
  if (query.empty()) return out;

  if (sysconfig::IsMacAddress(query)) {
    auto mac = sysconfig::NormalizeMac(query);
    for (const auto& d : report.devices) {
      if (d.mac == mac) out.push_back(&d);
    }
    return out;
  }
  if (sysconfig::ParseIpv4(query)) {
    for (const auto& d : report.devices) {
      if (d.address == query) out.push_back(&d);
    }
    return out;
  }
  auto q = Lower(query);
  for (const auto& d : report.devices) {
    if (Lower(d.hostname) == q) out.push_back(&d);
  }
  if (!out.empty()) return out;
  for (const auto& d : report.devices) {
    auto h = Lower(d.hostname);
    if (!h.empty() && h.rfind(q, 0) == 0) out.push_back(&d);
  }
  return out;
}

}  // namespace f::lease
