/// @file journal.cc
/// @brief Device history: arrivals, departures, address changes.

#include "f/lease/journal.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <format>
#include <fstream>
#include <set>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

namespace f::lease {
namespace {

using json = nlohmann::json;

/// The journal's own format version. A record written by a newer f
/// than the one reading it is refused as corrupt rather than
/// half-understood.
constexpr int kJournalVersion = 1;

auto PrecisionFromName(const std::string& s) -> FirstSeenPrecision {
  return s == "observed" ? FirstSeenPrecision::kObserved
                         : FirstSeenPrecision::kInferred;
}

}  // namespace

auto FirstSeenPrecisionName(FirstSeenPrecision p) -> std::string {
  return p == FirstSeenPrecision::kObserved ? "observed" : "inferred";
}

auto Journal::Find(std::string_view mac) const
    -> const DeviceRecord* {
  for (const auto& r : records) {
    if (r.mac == mac) return &r;
  }
  return nullptr;
}

auto Observe(Journal& j, const std::vector<Lease>& leases,
             std::int64_t now, std::uint32_t lease_seconds,
             bool first_observation) -> ObserveResult {
  ObserveResult res;
  res.first_observation = first_observation;

  std::unordered_map<std::string, std::size_t> index;
  for (std::size_t i = 0; i < j.records.size(); ++i) {
    index[j.records[i].mac] = i;
  }

  std::set<std::string> present_now;
  for (const auto& l : leases) {
    present_now.insert(l.mac);
    auto it = index.find(l.mac);
    if (it == index.end()) {
      DeviceRecord r;
      r.mac = l.mac;
      r.address = l.address;
      r.hostname = l.hostname;
      r.last_seen = now;
      r.present = true;
      if (first_observation) {
        // Nothing watched this device turn up, so the only honest
        // statement is "no later than when its lease was issued".
        // Without a configured lease time there is no way to work
        // that back, and `now` is the tightest bound we have.
        r.precision = FirstSeenPrecision::kInferred;
        r.first_seen =
            (lease_seconds > 0 && l.expiry > 0)
                ? l.expiry - static_cast<std::int64_t>(lease_seconds)
                : now;
        // A clock skew or a hand-edited lease file must not produce a
        // device that first appeared in the future.
        if (r.first_seen > now) r.first_seen = now;
      } else {
        // The journal existed and did not know this MAC, so it was
        // absent last time anything looked: we watched it arrive.
        r.precision = FirstSeenPrecision::kObserved;
        r.first_seen = now;
        r.last_arrival = now;
        res.arrived.push_back(l.mac);
      }
      index[l.mac] = j.records.size();
      j.records.push_back(std::move(r));
      continue;
    }
    auto& r = j.records[it->second];
    if (!r.address.empty() && r.address != l.address) {
      ++r.address_changes;
      res.readdressed.push_back(l.mac);
    }
    if (!r.present) {
      // Known device, absent last time, here now: it came back, and
      // that is an arrival even though it is not a first sighting.
      r.last_arrival = now;
      res.arrived.push_back(l.mac);
    }
    r.present = true;
    r.address = l.address;
    if (!l.hostname.empty()) r.hostname = l.hostname;
    r.last_seen = now;
  }

  for (auto& r : j.records) {
    if (present_now.count(r.mac) != 0) continue;
    if (r.present) {
      // It held a lease at the previous observation and does not now.
      // Reported once: `present` is cleared here, so the next poll
      // finds nothing to report about it.
      res.departed.push_back(r.mac);
      r.present = false;
    }
  }

  if (j.records.size() > kMaxRecords) {
    std::sort(j.records.begin(), j.records.end(),
              [](const DeviceRecord& a, const DeviceRecord& b) {
                return a.last_seen > b.last_seen;
              });
    j.records.resize(kMaxRecords);
  }
  return res;
}

auto SerializeJournal(const Journal& j) -> std::string {
  json arr = json::array();
  for (const auto& r : j.records) {
    arr.push_back({
        {"mac", r.mac},
        {"address", r.address},
        {"hostname", r.hostname},
        {"first_seen", r.first_seen},
        {"precision", FirstSeenPrecisionName(r.precision)},
        {"last_seen", r.last_seen},
        {"last_arrival", r.last_arrival},
        {"present", r.present},
        {"address_changes", r.address_changes},
    });
  }
  json doc = {
      {"version", kJournalVersion},
      {"devices", arr},
  };
  return doc.dump(2) + "\n";
}

auto DeserializeJournal(std::string_view text)
    -> std::expected<Journal, Error<JournalError>> {
  json doc;
  try {
    doc = json::parse(text);
  } catch (const json::exception& e) {
    return MakeError(JournalError::kCorrupt,
                     std::format("not valid JSON: {}", e.what()));
  }
  if (!doc.is_object() || !doc.contains("devices") ||
      !doc["devices"].is_array()) {
    return MakeError(JournalError::kCorrupt,
                     "not a device journal (no `devices` array)");
  }
  auto version = doc.value("version", 0);
  if (version > kJournalVersion) {
    return MakeError(
        JournalError::kCorrupt,
        std::format("journal is version {}; this build understands "
                    "up to {}",
                    version, kJournalVersion));
  }
  Journal j;
  for (const auto& d : doc["devices"]) {
    if (!d.is_object()) continue;
    DeviceRecord r;
    r.mac = d.value("mac", "");
    if (r.mac.empty()) continue;
    r.address = d.value("address", "");
    r.hostname = d.value("hostname", "");
    r.first_seen = d.value("first_seen", std::int64_t{0});
    r.precision = PrecisionFromName(d.value("precision", "inferred"));
    r.last_seen = d.value("last_seen", std::int64_t{0});
    r.last_arrival = d.value("last_arrival", std::int64_t{0});
    r.present = d.value("present", false);
    r.address_changes = d.value("address_changes", 0);
    j.records.push_back(std::move(r));
  }
  return j;
}

auto LoadJournal(const std::string& path)
    -> std::expected<Journal, Error<JournalError>> {
  std::error_code ec;
  if (!std::filesystem::exists(path, ec)) {
    return MakeError(JournalError::kAbsent,
                     std::format("no device journal at {}", path));
  }
  std::ifstream in(path);
  if (!in) {
    return MakeError(
        JournalError::kUnreadable,
        std::format("cannot read {}: {}", path,
                    std::strerror(errno)));
  }
  std::ostringstream body;
  body << in.rdbuf();
  return DeserializeJournal(body.str());
}

auto SaveJournal(const std::string& path, const Journal& j)
    -> std::expected<void, std::string> {
  std::filesystem::path p(path);
  std::error_code ec;
  if (p.has_parent_path()) {
    std::filesystem::create_directories(p.parent_path(), ec);
    if (ec) {
      return std::unexpected(
          std::format("cannot create {}: {}",
                      p.parent_path().string(), ec.message()));
    }
  }
  auto tmp = p;
  tmp += ".tmp";
  {
    std::ofstream out(tmp, std::ios::trunc);
    if (!out) {
      // Name the destination, not the temporary: the operator wants
      // the path he configured, and the errno tells him what to fix.
      return std::unexpected(std::format(
          "cannot write {}: {}", path, std::strerror(errno)));
    }
    out << SerializeJournal(j);
    out.flush();
    if (!out) {
      std::filesystem::remove(tmp, ec);
      return std::unexpected(
          std::format("write to {} failed", tmp.string()));
    }
  }
  std::filesystem::rename(tmp, p, ec);
  if (ec) {
    std::filesystem::remove(tmp, ec);
    return std::unexpected(std::format(
        "cannot install {}: {}", path, ec.message()));
  }
  return {};
}

}  // namespace f::lease
