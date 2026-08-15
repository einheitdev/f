/// @file counters.cc
/// @brief Name->slot table, the join against the map, and the wire
/// shape for a policy's named `count` statements.

#include "f/counters.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <format>
#include <sstream>
#include <unordered_map>

namespace f {

namespace {

using json = nlohmann::json;

constexpr std::string_view kMarker = "// fwl_counter_table:";

/// The line the emitter writes per counter is `//   <slot>\t<name>`.
/// Returns false for anything else, which is how the block ends.
auto ParseTableRow(std::string_view line, CounterSlot* out) -> bool {
  size_t i = 0;
  auto skip_ws = [&] {
    while (i < line.size() &&
           (line[i] == ' ' || line[i] == '\t' || line[i] == '\r')) {
      i++;
    }
  };
  skip_ws();
  if (line.substr(i, 2) != "//") return false;
  i += 2;
  skip_ws();
  size_t digits_start = i;
  uint64_t slot = 0;
  while (i < line.size() && std::isdigit(static_cast<unsigned char>(
                                line[i])) != 0) {
    slot = slot * 10 + static_cast<uint64_t>(line[i] - '0');
    // A slot number wider than the map can ever be is malformed
    // input, not a big counter.
    if (slot > 0xFFFFFFFFULL) return false;
    i++;
  }
  if (i == digits_start) return false;
  // The separator is a tab, deliberately: a counter name cannot
  // contain one, so the split is unambiguous however the name reads.
  if (i >= line.size() || line[i] != '\t') return false;
  i++;
  auto name = line.substr(i);
  while (!name.empty() &&
         (name.back() == ' ' || name.back() == '\r' ||
          name.back() == '\t')) {
    name.remove_suffix(1);
  }
  while (!name.empty() && name.front() == ' ') {
    name.remove_prefix(1);
  }
  if (name.empty()) return false;
  out->name = std::string(name);
  out->slot = static_cast<uint32_t>(slot);
  return true;
}

}  // namespace

auto CounterAvailabilityName(CounterAvailability a) -> std::string_view {
  switch (a) {
    case CounterAvailability::kRead: return "read";
    case CounterAvailability::kNoneDeclared: return "none_declared";
    case CounterAvailability::kTableUnreadable:
      return "table_unreadable";
    case CounterAvailability::kMapMissing: return "map_missing";
    case CounterAvailability::kBoundUnreadable:
      return "bound_unreadable";
    case CounterAvailability::kTableMapMismatch:
      return "table_map_mismatch";
    case CounterAvailability::kUnknown: return "unknown";
  }
  return "unknown";
}

auto CounterAvailabilityFromName(std::string_view s)
    -> CounterAvailability {
  if (s == "read") return CounterAvailability::kRead;
  if (s == "none_declared") return CounterAvailability::kNoneDeclared;
  if (s == "table_unreadable") {
    return CounterAvailability::kTableUnreadable;
  }
  if (s == "map_missing") return CounterAvailability::kMapMissing;
  if (s == "bound_unreadable") {
    return CounterAvailability::kBoundUnreadable;
  }
  if (s == "table_map_mismatch") {
    return CounterAvailability::kTableMapMismatch;
  }
  return CounterAvailability::kUnknown;
}

auto CounterStateWord(CounterAvailability a) -> std::string_view {
  switch (a) {
    case CounterAvailability::kRead: return "read";
    case CounterAvailability::kNoneDeclared:
      return "no count statements";
    case CounterAvailability::kTableUnreadable: return "names unknown";
    case CounterAvailability::kMapMissing: return "no counter map";
    case CounterAvailability::kBoundUnreadable: return "size unknown";
    case CounterAvailability::kTableMapMismatch: return "stale table";
    case CounterAvailability::kUnknown: return "unknown state";
  }
  return "unknown state";
}

auto CounterLookupName(CounterLookup l) -> std::string_view {
  switch (l) {
    case CounterLookup::kFound: return "found";
    case CounterLookup::kNoSuchName: return "no_such_name";
    case CounterLookup::kCannotTell: return "cannot_tell";
  }
  return "cannot_tell";
}

auto ParseCounterTable(std::string_view c_source)
    -> std::vector<CounterSlot> {
  std::vector<CounterSlot> out;
  size_t marker = c_source.find(kMarker);
  if (marker == std::string_view::npos) return out;
  size_t pos = c_source.find('\n', marker);
  if (pos == std::string_view::npos) return out;
  pos++;
  std::unordered_map<std::string, bool> seen;
  while (pos < c_source.size()) {
    size_t eol = c_source.find('\n', pos);
    size_t end = eol == std::string_view::npos ? c_source.size() : eol;
    CounterSlot row;
    if (!ParseTableRow(c_source.substr(pos, end - pos), &row)) break;
    // The emitter allocates each name once, so a repeat means the file
    // is not what this reader thinks it is. Keep the first — the one
    // the datapath's own lookup would have used — rather than let a
    // later line silently redefine it.
    if (!seen.contains(row.name)) {
      seen[row.name] = true;
      out.push_back(std::move(row));
    }
    if (eol == std::string_view::npos) break;
    pos = eol + 1;
  }
  return out;
}

auto ReadCounterTable(const std::filesystem::path& source)
    -> CounterTable {
  CounterTable t;
  t.source = source.string();
  std::ifstream in(source);
  if (!in) {
    t.read = false;
    t.detail = std::format(
        "{} could not be read, so the slots in this zone's counter map "
        "cannot be given the names the policy wrote",
        t.source);
    return t;
  }
  std::ostringstream ss;
  ss << in.rdbuf();
  // A zone whose policy has no `count` statement gets no table block
  // and no counter map at all — an absent marker is that, not a
  // failure.
  t.slots = ParseCounterTable(ss.str());
  t.read = true;
  return t;
}

auto ReadZoneCounters(std::string_view zone, const CounterTable& table,
                      const CounterMap* map) -> ZoneCounters {
  ZoneCounters z;
  z.zone = std::string(zone);
  if (!table.read) {
    z.availability = CounterAvailability::kTableUnreadable;
    z.detail = table.detail;
    return z;
  }
  if (table.slots.empty()) {
    z.availability = CounterAvailability::kNoneDeclared;
    return z;
  }
  if (map == nullptr) {
    z.availability = CounterAvailability::kMapMissing;
    z.detail = std::format(
        "this zone's policy declares {} counter(s) and the loaded "
        "object has no fwl_counters_{} map to read them from",
        table.slots.size(), z.zone);
    return z;
  }
  z.map_slots = map->Slots();
  if (z.map_slots == 0) {
    z.availability = CounterAvailability::kBoundUnreadable;
    z.detail = std::format(
        "fwl_counters_{} is loaded and its size could not be read from "
        "it. The bound is never assumed: a guessed one is how counters "
        "above it went missing before",
        z.zone);
    return z;
  }
  for (const auto& s : table.slots) {
    if (s.slot >= z.map_slots) {
      z.availability = CounterAvailability::kTableMapMismatch;
      z.detail = std::format(
          "{} names counter '{}' at slot {}, and fwl_counters_{} has "
          "{} slot(s). The generated C in the bundle directory is not "
          "the source of the object that is loaded, so every name this "
          "table gives a slot would be the wrong name — none is "
          "offered. Recompile the policy and reload",
          table.source, s.name, s.slot, z.zone, z.map_slots);
      z.counters.clear();
      return z;
    }
  }
  size_t failed = 0;
  for (const auto& s : table.slots) {
    CounterReading r;
    r.name = s.name;
    r.slot = s.slot;
    auto v = map->Read(s.slot);
    if (v.has_value()) {
      r.read = true;
      r.packets = *v;
    } else {
      failed++;
    }
    z.counters.push_back(std::move(r));
  }
  z.availability = CounterAvailability::kRead;
  if (failed > 0) {
    // Every in-range lookup on a per-CPU array succeeds, so this is an
    // anomaly rather than a routine condition. The rows carry it —
    // `read` false, and a renderer that prints the value as 0 anyway
    // is the defect this whole type exists to prevent.
    z.detail = std::format(
        "{} of {} slot(s) in fwl_counters_{} could not be read; those "
        "rows carry no value rather than a zero",
        failed, table.slots.size(), z.zone);
  }
  return z;
}

auto FindCounter(const std::vector<ZoneCounters>& zones,
                 std::string_view name) -> CounterQuery {
  CounterQuery q;
  bool blind = false;
  for (const auto& z : zones) {
    // A zone whose table could not be read might well declare this
    // counter; nothing here can say it does not.
    if (z.availability == CounterAvailability::kTableUnreadable ||
        z.availability == CounterAvailability::kUnknown) {
      blind = true;
    }
    auto it = std::find_if(
        z.counters.begin(), z.counters.end(),
        [&](const CounterReading& c) { return c.name == name; });
    if (it == z.counters.end()) continue;
    ZoneCounters hit;
    hit.zone = z.zone;
    hit.availability = z.availability;
    hit.detail = z.detail;
    hit.map_slots = z.map_slots;
    hit.counters.push_back(*it);
    q.zones.push_back(std::move(hit));
  }
  if (!q.zones.empty()) {
    q.verdict = CounterLookup::kFound;
  } else if (blind) {
    q.verdict = CounterLookup::kCannotTell;
  } else {
    q.verdict = CounterLookup::kNoSuchName;
  }
  return q;
}

auto ZoneCountersToJson(const std::vector<ZoneCounters>& zones)
    -> nlohmann::json {
  json arr = json::array();
  for (const auto& z : zones) {
    json rows = json::array();
    for (const auto& c : z.counters) {
      rows.push_back({
          {"name", c.name},
          {"slot", c.slot},
          {"read", c.read},
          {"packets", c.packets},
      });
    }
    arr.push_back({
        {"zone", z.zone},
        {"availability",
         std::string(CounterAvailabilityName(z.availability))},
        {"detail", z.detail},
        {"map_slots", z.map_slots},
        {"counters", rows},
    });
  }
  return json{{"zones", arr}};
}

auto ZoneCountersFromJson(const nlohmann::json& j)
    -> std::vector<ZoneCounters> {
  std::vector<ZoneCounters> out;
  const json* arr = nullptr;
  if (j.is_object() && j.contains("zones") && j["zones"].is_array()) {
    arr = &j["zones"];
  } else if (j.is_array()) {
    arr = &j;
  }
  if (arr == nullptr) return out;
  for (const auto& zj : *arr) {
    if (!zj.is_object()) continue;
    ZoneCounters z;
    z.zone = zj.value("zone", std::string{});
    z.availability = CounterAvailabilityFromName(
        zj.value("availability", std::string{}));
    z.detail = zj.value("detail", std::string{});
    z.map_slots = zj.value("map_slots", 0U);
    for (const auto& cj : zj.value("counters", json::array())) {
      if (!cj.is_object()) continue;
      CounterReading c;
      c.name = cj.value("name", std::string{});
      c.slot = cj.value("slot", 0U);
      // A row that does not say it was read was not read. Defaulting
      // this true would turn a missing field into a zero packet count,
      // which is the one wrong answer that looks right.
      c.read = cj.value("read", false);
      c.packets = cj.value("packets", 0ULL);
      if (!c.read) c.packets = 0;
      z.counters.push_back(std::move(c));
    }
    out.push_back(std::move(z));
  }
  return out;
}

}  // namespace f
