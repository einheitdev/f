/// @file test_counters.cc
/// @brief The counter reader, and the four kinds of empty it has to
/// keep apart.
///
/// Every test here is about a distinction. A reader that answers "0"
/// to every question passes none of them, and neither does one that
/// answers "nothing here": zero, not declared, not named and not
/// readable are four different findings about a firewall and the
/// removed v0.1 surface rendered all four the same way.

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "f/counters.h"

namespace {

using f::CounterAvailability;
using f::CounterLookup;
using f::CounterMap;
using f::CounterSlot;
using f::CounterTable;

/// Exactly what fwl's `_emit_counter_table` writes: the marker, then
/// one `//   <slot>\t<name>` line per counter. If the emitter's format
/// moves, this string and the compiler disagree — which is what
/// tests/system/test_named_counters.py catches on a real bundle.
constexpr const char* kEmitted =
    "// fwl_counter_table:\n"
    "//   0\tlan_total\n"
    "//   1\tlan_ssh\n"
    "//   2\t__rate_limit_overflow\n";

/// A counter map that is whatever the test needs it to be.
class FakeMap final : public CounterMap {
 public:
  FakeMap(uint32_t slots, std::map<uint32_t, uint64_t> values)
      : slots_(slots), values_(std::move(values)) {}
  auto Slots() const -> uint32_t override { return slots_; }
  auto Read(uint32_t slot) const -> std::optional<uint64_t> override {
    auto it = values_.find(slot);
    if (it == values_.end()) return std::nullopt;
    return it->second;
  }

 private:
  uint32_t slots_;
  std::map<uint32_t, uint64_t> values_;
};

auto ReadTable(const std::vector<CounterSlot>& slots) -> CounterTable {
  CounterTable t;
  t.slots = slots;
  t.read = true;
  t.source = "lan.bpf.c";
  return t;
}

// -- the table the compiler wrote ------------------------------------

TEST(ParseCounterTable, ReadsTheEmitterFormat) {
  auto slots = f::ParseCounterTable(kEmitted);
  ASSERT_EQ(slots.size(), 3u);
  EXPECT_EQ(slots[0].name, "lan_total");
  EXPECT_EQ(slots[0].slot, 0u);
  EXPECT_EQ(slots[1].name, "lan_ssh");
  EXPECT_EQ(slots[1].slot, 1u);
  // Reserved counters are counters. A rate limit that never fires and
  // one that fires constantly are both worth seeing.
  EXPECT_EQ(slots[2].name, "__rate_limit_overflow");
  EXPECT_EQ(slots[2].slot, 2u);
}

TEST(ParseCounterTable, StopsAtTheEndOfTheBlock) {
  // The generated C carries plenty of other comments. A file-wide
  // scan for "a comment with a number and a word" would name a
  // counter after a fragment of prose.
  std::string src =
      "// fwl_counter_table:\n"
      "//   0\tlan_total\n"
      "\n"
      "//   1\tnot_a_counter\n"
      "struct { } fwl_counters_lan SEC(\".maps\");\n";
  auto slots = f::ParseCounterTable(src);
  ASSERT_EQ(slots.size(), 1u);
  EXPECT_EQ(slots[0].name, "lan_total");
}

TEST(ParseCounterTable, NoMarkerIsNoCounters) {
  EXPECT_TRUE(f::ParseCounterTable("int main() { return 0; }").empty());
}

TEST(ParseCounterTable, RequiresTheTabSeparator) {
  // Two spaces, not a tab: not the emitter's output, so not a row.
  EXPECT_TRUE(
      f::ParseCounterTable("// fwl_counter_table:\n//   0  x\n")
          .empty());
}

TEST(ReadCounterTable, MissingFileIsNotReadRatherThanEmpty) {
  auto t = f::ReadCounterTable("/nonexistent/zone.bpf.c");
  EXPECT_FALSE(t.read);
  EXPECT_FALSE(t.detail.empty());
  EXPECT_NE(t.detail.find("/nonexistent/zone.bpf.c"),
            std::string::npos);
}

TEST(ReadCounterTable, PolicyWithNoCountIsReadAndEmpty) {
  auto path = std::filesystem::temp_directory_path() /
              "f_counters_no_table.bpf.c";
  {
    std::ofstream f(path);
    f << "// nothing to count here\nint x;\n";
  }
  auto t = f::ReadCounterTable(path);
  EXPECT_TRUE(t.read);
  EXPECT_TRUE(t.slots.empty());
  std::filesystem::remove(path);
}

// -- the join, and the four kinds of empty ---------------------------

TEST(ReadZoneCounters, ZeroIsANumberNotAnAbsence) {
  FakeMap map(2, {{0, 0}, {1, 0}});
  auto z = f::ReadZoneCounters(
      "lan", ReadTable({{"lan_total", 0}, {"lan_ssh", 1}}), &map);
  EXPECT_EQ(z.availability, CounterAvailability::kRead);
  ASSERT_EQ(z.counters.size(), 2u);
  EXPECT_TRUE(z.counters[0].read);
  EXPECT_EQ(z.counters[0].packets, 0u);
  EXPECT_TRUE(z.counters[1].read);
}

TEST(ReadZoneCounters, DeclaresNoneIsItsOwnState) {
  auto z = f::ReadZoneCounters("wan", ReadTable({}), nullptr);
  EXPECT_EQ(z.availability, CounterAvailability::kNoneDeclared);
  EXPECT_TRUE(z.counters.empty());
}

TEST(ReadZoneCounters, UnreadableTableIsNotNoCounters) {
  CounterTable t;
  t.read = false;
  t.source = "lan.bpf.c";
  t.detail = "lan.bpf.c could not be read";
  FakeMap map(4, {{0, 99}});
  auto z = f::ReadZoneCounters("lan", t, &map);
  EXPECT_EQ(z.availability, CounterAvailability::kTableUnreadable);
  // Values exist in the map and are deliberately not offered: without
  // the table they are slot numbers, which is what bpftool already
  // gives and what nobody can act on.
  EXPECT_TRUE(z.counters.empty());
  EXPECT_FALSE(z.detail.empty());
}

TEST(ReadZoneCounters, DeclaredCountersWithNoMapSayThat) {
  auto z = f::ReadZoneCounters("lan", ReadTable({{"lan_total", 0}}),
                               nullptr);
  EXPECT_EQ(z.availability, CounterAvailability::kMapMissing);
  EXPECT_NE(z.detail.find("fwl_counters_lan"), std::string::npos);
  EXPECT_TRUE(z.counters.empty());
}

TEST(ReadZoneCounters, BoundComesFromTheMap) {
  FakeMap map(9000, {{0, 5}});
  auto z =
      f::ReadZoneCounters("lan", ReadTable({{"lan_total", 0}}), &map);
  EXPECT_EQ(z.map_slots, 9000u);
  ASSERT_EQ(z.counters.size(), 1u);
  EXPECT_EQ(z.counters[0].packets, 5u);
}

TEST(ReadZoneCounters, UnreadableBoundIsNotZeroCounters) {
  // Slots() == 0 is "could not ask the kernel", which is the state a
  // guessed literal used to paper over.
  FakeMap map(0, {{0, 5}});
  auto z =
      f::ReadZoneCounters("lan", ReadTable({{"lan_total", 0}}), &map);
  EXPECT_EQ(z.availability, CounterAvailability::kBoundUnreadable);
  EXPECT_TRUE(z.counters.empty());
}

TEST(ReadZoneCounters, TableNamingASlotTheMapLacksOffersNoNames) {
  // The .bpf.c on disk is not the source of the loaded object. Every
  // pairing derived from it would be plausible and wrong.
  FakeMap map(2, {{0, 1}, {1, 2}});
  auto z = f::ReadZoneCounters(
      "lan", ReadTable({{"lan_total", 0}, {"lan_ssh", 7}}), &map);
  EXPECT_EQ(z.availability, CounterAvailability::kTableMapMismatch);
  EXPECT_TRUE(z.counters.empty());
  EXPECT_NE(z.detail.find("lan_ssh"), std::string::npos);
  EXPECT_NE(z.detail.find("slot 7"), std::string::npos);
}

TEST(ReadZoneCounters, AFailedSlotLookupIsNotAZero) {
  // In range, and the lookup failed: the row carries no value at all.
  FakeMap map(2, {{0, 12}});
  auto z = f::ReadZoneCounters(
      "lan", ReadTable({{"lan_total", 0}, {"lan_ssh", 1}}), &map);
  EXPECT_EQ(z.availability, CounterAvailability::kRead);
  ASSERT_EQ(z.counters.size(), 2u);
  EXPECT_TRUE(z.counters[0].read);
  EXPECT_EQ(z.counters[0].packets, 12u);
  EXPECT_FALSE(z.counters[1].read);
  EXPECT_NE(z.detail.find("could not be read"), std::string::npos);
}

// -- asking for one counter by name ----------------------------------

TEST(FindCounter, FoundCarriesTheZoneItLivesIn) {
  FakeMap lan(1, {{0, 4}});
  std::vector<f::ZoneCounters> zones = {
      f::ReadZoneCounters("lan", ReadTable({{"lan_total", 0}}), &lan),
      f::ReadZoneCounters("wan", ReadTable({}), nullptr),
  };
  auto q = f::FindCounter(zones, "lan_total");
  EXPECT_EQ(q.verdict, CounterLookup::kFound);
  ASSERT_EQ(q.zones.size(), 1u);
  EXPECT_EQ(q.zones[0].zone, "lan");
  ASSERT_EQ(q.zones[0].counters.size(), 1u);
  EXPECT_EQ(q.zones[0].counters[0].packets, 4u);
}

TEST(FindCounter, AbsentFromEveryReadableTableIsNoSuchName) {
  FakeMap lan(1, {{0, 4}});
  std::vector<f::ZoneCounters> zones = {
      f::ReadZoneCounters("lan", ReadTable({{"lan_total", 0}}), &lan),
  };
  auto q = f::FindCounter(zones, "wan_total");
  EXPECT_EQ(q.verdict, CounterLookup::kNoSuchName);
  EXPECT_TRUE(q.zones.empty());
}

TEST(FindCounter, AnUnnameableZoneMakesAbsenceUnprovable) {
  CounterTable blind;
  blind.read = false;
  blind.detail = "wan.bpf.c could not be read";
  FakeMap lan(1, {{0, 4}});
  std::vector<f::ZoneCounters> zones = {
      f::ReadZoneCounters("lan", ReadTable({{"lan_total", 0}}), &lan),
      f::ReadZoneCounters("wan", blind, nullptr),
  };
  auto q = f::FindCounter(zones, "wan_total");
  EXPECT_EQ(q.verdict, CounterLookup::kCannotTell);
  EXPECT_TRUE(q.zones.empty());
}

TEST(FindCounter, ExistsButUnreadableIsFoundWithNoNumber) {
  FakeMap broken(2, {});
  std::vector<f::ZoneCounters> zones = {
      f::ReadZoneCounters("lan", ReadTable({{"lan_total", 0}}),
                          &broken),
  };
  auto q = f::FindCounter(zones, "lan_total");
  EXPECT_EQ(q.verdict, CounterLookup::kFound);
  ASSERT_EQ(q.zones.size(), 1u);
  ASSERT_EQ(q.zones[0].counters.size(), 1u);
  EXPECT_FALSE(q.zones[0].counters[0].read);
}

// -- the wire --------------------------------------------------------

TEST(CountersWire, RoundTripsNamesValuesAndReasons) {
  FakeMap lan(2, {{0, 7}});
  std::vector<f::ZoneCounters> zones = {
      f::ReadZoneCounters(
          "lan", ReadTable({{"lan_total", 0}, {"lan_ssh", 1}}), &lan),
      f::ReadZoneCounters("wan", ReadTable({}), nullptr),
  };
  auto back = f::ZoneCountersFromJson(f::ZoneCountersToJson(zones));
  ASSERT_EQ(back.size(), 2u);
  EXPECT_EQ(back[0].zone, "lan");
  EXPECT_EQ(back[0].availability, CounterAvailability::kRead);
  EXPECT_EQ(back[0].map_slots, 2u);
  ASSERT_EQ(back[0].counters.size(), 2u);
  EXPECT_EQ(back[0].counters[0].name, "lan_total");
  EXPECT_EQ(back[0].counters[0].packets, 7u);
  EXPECT_TRUE(back[0].counters[0].read);
  EXPECT_FALSE(back[0].counters[1].read);
  EXPECT_EQ(back[1].availability, CounterAvailability::kNoneDeclared);
}

TEST(CountersWire, AMissingReadFlagIsNotAZeroReading) {
  auto j = nlohmann::json::parse(R"({"zones":[{
      "zone":"lan","availability":"read","detail":"","map_slots":1,
      "counters":[{"name":"lan_total","slot":0}]}]})");
  auto back = f::ZoneCountersFromJson(j);
  ASSERT_EQ(back.size(), 1u);
  ASSERT_EQ(back[0].counters.size(), 1u);
  EXPECT_FALSE(back[0].counters[0].read);
}

TEST(CountersWire, AnAvailabilityThisBuildLacksIsUnknownNotRead) {
  auto j = nlohmann::json::parse(R"({"zones":[{
      "zone":"lan","availability":"something_newer","counters":[]}]})");
  auto back = f::ZoneCountersFromJson(j);
  ASSERT_EQ(back.size(), 1u);
  EXPECT_EQ(back[0].availability, CounterAvailability::kUnknown);
  // ...and an unknown zone is one the search is blind to.
  EXPECT_EQ(f::FindCounter(back, "anything").verdict,
            CounterLookup::kCannotTell);
}

TEST(CountersWire, EveryAvailabilityHasADistinctWord) {
  const CounterAvailability all[] = {
      CounterAvailability::kRead,
      CounterAvailability::kNoneDeclared,
      CounterAvailability::kTableUnreadable,
      CounterAvailability::kMapMissing,
      CounterAvailability::kBoundUnreadable,
      CounterAvailability::kTableMapMismatch,
      CounterAvailability::kUnknown,
  };
  std::vector<std::string> seen;
  for (auto a : all) {
    auto w = std::string(f::CounterAvailabilityName(a));
    EXPECT_FALSE(w.empty());
    for (const auto& s : seen) EXPECT_NE(s, w);
    seen.push_back(w);
  }
}

}  // namespace
