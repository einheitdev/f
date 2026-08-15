/// @file counters.h
/// @brief Reading a policy's named `count` statements back off a box.
///
/// A policy says `count wan_total`. The emitter allocates that name a
/// slot in the zone's own `fwl_counters_<zone>` per-CPU array and
/// writes the name beside the slot into the zone's generated C, as a
/// `// fwl_counter_table:` comment block. Until this module existed
/// nothing on the box read either one: the counters moved and the only
/// way to see them was `bpftool map dump`, which gives slot numbers and
/// no names.
///
/// The identity here is the NAME. There is deliberately no API that
/// pairs a counter with a rule by position, because that is exactly how
/// the removed v0.1 surface got it wrong — it walked a rule list and a
/// counter array in step while the datapath keyed them differently, so
/// every number it printed was attributed to the wrong rule and looked
/// entirely plausible. A name travels with its value from the compiler
/// that allocated it to the operator reading it, and nothing in between
/// re-derives the pairing.

#ifndef INCLUDE_F_COUNTERS_H_
#define INCLUDE_F_COUNTERS_H_

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

namespace f {

/// One `count <name>` statement and the slot the emitter gave it.
struct CounterSlot {
  std::string name;
  uint32_t slot = 0;
};

/// A zone's name->slot table, and whether it was read at all.
///
/// `read` is not a convenience flag. An empty `slots` on a table that
/// was read means "this zone's policy declares no counters", which is a
/// fact about the policy; an empty `slots` on a table that was not read
/// means "we cannot say what this zone counts", which is a fact about
/// this box. Collapsing the two is what makes a reader answer "no
/// counters" to a question it never managed to ask.
struct CounterTable {
  std::vector<CounterSlot> slots;
  bool read = false;
  /// The generated C the table came from, named so a failure can say
  /// which file it could not read.
  std::string source;
  /// One sentence on why `read` is false. Empty when it is true.
  std::string detail;
};

/// Why a zone's counter list looks the way it does.
///
/// Availability is a type, not a convention — the same decision
/// `LeaseAvailability` makes, for the same reason: an empty (or
/// all-zero) counter list must travel with the reason it is empty, so
/// a renderer cannot forget which kind of empty it got. "Every counter
/// reads zero" and "nothing could be read" are opposite findings about
/// a firewall and they render identically if the reason is dropped.
enum class CounterAvailability : uint8_t {
  /// The table and the map were both read; the values are the box's.
  kRead,
  /// This zone's policy contains no `count` statement. Nothing is
  /// wrong; there is nothing to show.
  kNoneDeclared,
  /// The zone's generated C could not be read or carries no counter
  /// table, so the slots in its map cannot be given names. Slot
  /// numbers with no names is what `bpftool map dump` already gives.
  kTableUnreadable,
  /// The policy declares counters and the loaded object has no
  /// `fwl_counters_<zone>` map to read them from.
  kMapMissing,
  /// The map is there and its bound could not be read from it. The
  /// bound is never assumed: a literal 256 against a 10000-slot map is
  /// how the removed surface hid every counter from 256 up.
  kBoundUnreadable,
  /// The table names a slot the map does not have. The generated C in
  /// the bundle directory is then not the source of the object that is
  /// loaded, and every name/value pairing derived from it would be
  /// wrong — so none is offered.
  kTableMapMismatch,
  /// The daemon reported a state this build has no word for. Reachable
  /// only across a version skew — an `einheit-f` older than the `fd`
  /// it is talking to. It is a state rather than a fallback to one of
  /// the others because guessing which one would put a sentence in
  /// front of the operator that nothing on the box supports.
  kUnknown,
};

/// A short machine token for `a` — the wire word, and what a test
/// asserts on.
auto CounterAvailabilityName(CounterAvailability a) -> std::string_view;

/// One named counter as it was found.
struct CounterReading {
  std::string name;
  uint32_t slot = 0;
  /// False when this slot's value could not be read. `packets` is then
  /// meaningless and a renderer must not print it as a number.
  bool read = false;
  /// Packets that hit the rule naming this counter, summed over CPUs.
  uint64_t packets = 0;
};

/// One zone's counters, with the reason they look the way they do.
struct ZoneCounters {
  std::string zone;
  CounterAvailability availability = CounterAvailability::kMapMissing;
  /// One sentence naming what could not be done, when anything could
  /// not be. Empty on kRead and kNoneDeclared.
  std::string detail;
  /// The bound as THE MAP reports it, never a constant.
  uint32_t map_slots = 0;
  std::vector<CounterReading> counters;
};

/// The per-CPU counter array, as the join below needs to see it.
///
/// An interface rather than a bare descriptor so the join is testable
/// without CAP_BPF. Every decision it makes — a slot the map does not
/// have, a lookup that fails, a bound that could not be read — is
/// reachable from a unit test here, and none of them is reachable
/// through a real map without root and a policy contrived to provoke
/// it. The libbpf implementation is `BpfCounterMap` in bpf_loader.cc.
class CounterMap {
 public:
  virtual ~CounterMap() = default;
  /// How many slots THE MAP has. 0 means the bound could not be read.
  virtual auto Slots() const -> uint32_t = 0;
  /// The sum of slot `slot` across every CPU, or nullopt when the
  /// lookup failed.
  virtual auto Read(uint32_t slot) const -> std::optional<uint64_t> = 0;
};

/// Parse the `// fwl_counter_table:` block out of emitted C.
///
/// Only the run of comment lines immediately after the marker is read.
/// A file-wide scan for "a comment holding a number and a word" would
/// pick up any other comment of that shape, and the failure would be a
/// counter named after a fragment of prose — plausible, wrong, and
/// invisible.
auto ParseCounterTable(std::string_view c_source)
    -> std::vector<CounterSlot>;

/// Read `source` and parse its counter table.
auto ReadCounterTable(const std::filesystem::path& source)
    -> CounterTable;

/// Join a zone's table against its map.
///
/// `map` is null when the zone has no counter map at all. The result
/// always carries a reason, including in the cases where it also
/// carries numbers.
auto ReadZoneCounters(std::string_view zone, const CounterTable& table,
                      const CounterMap* map) -> ZoneCounters;

/// What a search for one counter name found.
enum class CounterLookup : uint8_t {
  /// At least one zone declares a counter of that name.
  kFound,
  /// Every zone's table was read and none of them names it. This is a
  /// fact about the policy: there is no such counter.
  kNoSuchName,
  /// It was not found, and at least one zone's table could not be
  /// read — so its absence is not established. "I did not find it" and
  /// "it is not there" are different answers and the operator gets the
  /// one that is true.
  kCannotTell,
};

auto CounterLookupName(CounterLookup l) -> std::string_view;

/// The result of asking for one counter by name.
struct CounterQuery {
  CounterLookup verdict = CounterLookup::kNoSuchName;
  /// The zones that declare it, each carrying its own availability —
  /// so a counter that exists in a zone whose map could not be read is
  /// `kFound` with no number, not a zero.
  std::vector<ZoneCounters> zones;
};

/// Find `name` across `zones`.
auto FindCounter(const std::vector<ZoneCounters>& zones,
                 std::string_view name) -> CounterQuery;

/// The wire shape, defined once so the daemon that writes it and the
/// CLI that reads it cannot drift. Note what is on the wire: a name
/// beside its value, per zone. There is no index a consumer could pair
/// against something else.
auto ZoneCountersToJson(const std::vector<ZoneCounters>& zones)
    -> nlohmann::json;

/// The inverse. Anything the payload does not carry comes back as
/// "could not be read" rather than as a zero.
auto ZoneCountersFromJson(const nlohmann::json& j)
    -> std::vector<ZoneCounters>;

}  // namespace f

#endif  // INCLUDE_F_COUNTERS_H_
