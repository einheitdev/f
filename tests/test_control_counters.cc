/// @file test_control_counters.cc
/// @brief The control-socket handlers that report rules and counters.
///
/// Two defects, one class: a number that looks authoritative and is
/// not.
///
///  1. `kGetRules` reported `counters[idx]` beside the rule at
///     iteration position `idx`, while bpf/fw.bpf.c keys `counters`
///     by MATCH TIER and never by rule index. Every number was next
///     to the wrong rule.
///  2. `kGetCounters` / `kClearCounters` iterated a literal 256 while
///     the map declares 10000 slots. Everything from 256 up counted
///     invisibly and could not be zeroed.
///
/// The tests that need a real map create one and skip without
/// CAP_BPF; the ones about what the daemon SAYS when it has no
/// datapath at all need nothing, and those are the ones that run on
/// every box, because that is the state every v0.4 deployment is in.

#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <vector>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <nlohmann/json.hpp>

#include "f/engine.h"
#include "f/protocol.h"
#include "f/types.h"

namespace f {
namespace {

using json = nlohmann::json;

/// One control frame: the command byte, then its payload.
auto Frame(Cmd cmd, const std::string& payload = "") -> std::string {
  return std::string(1, static_cast<char>(cmd)) + payload;
}

auto Ask(Engine& e, Cmd cmd, const std::string& payload = "") -> json {
  return json::parse(HandleControlRequest(e, Frame(cmd, payload)));
}

auto Cpus() -> int {
  int n = libbpf_num_possible_cpus();
  return n < 1 ? 1 : n;
}

/// A per-CPU array shaped exactly like bpf/fw.bpf.c's `counters`:
/// 10000 slots of RuleCounter. Returns -1 when the kernel will not
/// give us one.
auto MakeCountersMap(uint32_t slots = 10000) -> int {
  LIBBPF_OPTS(bpf_map_create_opts, opts);
  return bpf_map_create(BPF_MAP_TYPE_PERCPU_ARRAY, "counters",
                        sizeof(uint32_t), sizeof(RuleCounter),
                        slots, &opts);
}

/// A hash shaped like `rules_a`.
auto MakeRulesMap() -> int {
  LIBBPF_OPTS(bpf_map_create_opts, opts);
  return bpf_map_create(BPF_MAP_TYPE_HASH, "rules_a",
                        sizeof(RuleKey), sizeof(RuleValue),
                        1024, &opts);
}

/// Put `packets`/`bytes` on CPU 0 of slot `slot`.
auto WriteCounter(int fd, uint32_t slot, uint64_t packets,
                  uint64_t bytes) -> bool {
  std::vector<RuleCounter> per_cpu(Cpus());
  per_cpu[0].packets = packets;
  per_cpu[0].bytes = bytes;
  return bpf_map_update_elem(fd, &slot, per_cpu.data(),
                             BPF_ANY) == 0;
}

/// Sum slot `slot` across CPUs, straight from the map — the
/// independent read the assertions about clearing need, so that
/// "cleared" is checked against the map and not against the reply
/// that claims it.
auto ReadCounter(int fd, uint32_t slot) -> RuleCounter {
  std::vector<RuleCounter> per_cpu(Cpus());
  RuleCounter out{};
  if (bpf_map_lookup_elem(fd, &slot, per_cpu.data()) != 0) return out;
  for (int c = 0; c < Cpus(); c++) {
    out.packets += per_cpu[c].packets;
    out.bytes += per_cpu[c].bytes;
  }
  return out;
}

/// Find the entry with `id` in a kGetCounters reply.
auto FindId(const json& arr, uint32_t id) -> json {
  for (const auto& c : arr) {
    if (c.value("id", 0u) == id) return c;
  }
  return json();
}

class BpfMapTest : public ::testing::Test {
 protected:
  void SetUp() override {
    counters_fd_ = MakeCountersMap();
    if (counters_fd_ < 0) {
      GTEST_SKIP() << "bpf_map_create failed (need root/CAP_BPF)";
    }
    e_.bpf.counters_fd = counters_fd_;
  }
  void TearDown() override {
    if (counters_fd_ >= 0) close(counters_fd_);
    if (rules_fd_ >= 0) close(rules_fd_);
  }
  Engine e_;
  int counters_fd_ = -1;
  int rules_fd_ = -1;
};

// --- the iteration cap ------------------------------------------------

TEST_F(BpfMapTest, CounterSlotsComeFromTheMapNotFromALiteral) {
  // The whole fix in one assertion: the reader's bound is the map's
  // own size. A second declaration of it anywhere is a second thing
  // to forget.
  EXPECT_EQ(CountersMapSlots(counters_fd_), 10000u);
  EXPECT_EQ(CountersMapSlots(-1), 0u);
}

TEST_F(BpfMapTest, ACounterBeyond256IsVisible) {
  // Slot 7 is the vacuity guard and it is not decoration. A truncated
  // iteration and a map nobody ever wrote to both answer with zeros,
  // and they are indistinguishable unless something below the old
  // bound is asserted NON-zero in the same reply. Slot 7 proves the
  // reader works; slot 300 is the claim.
  ASSERT_TRUE(WriteCounter(counters_fd_, 7, 11, 22));
  ASSERT_TRUE(WriteCounter(counters_fd_, 300, 4242, 606060));
  // ...and that the writes landed, so a failed write cannot be read
  // as a failed report.
  ASSERT_EQ(ReadCounter(counters_fd_, 7).packets, 11u);
  ASSERT_EQ(ReadCounter(counters_fd_, 300).packets, 4242u);

  auto arr = Ask(e_, Cmd::kGetCounters);
  ASSERT_TRUE(arr.is_array()) << arr.dump();

  auto below = FindId(arr, 7);
  ASSERT_FALSE(below.is_null()) << "slot 7 missing: " << arr.dump();
  EXPECT_EQ(below.value("packets", 0ULL), 11u);
  EXPECT_EQ(below.value("bytes", 0ULL), 22u);

  auto beyond = FindId(arr, 300);
  ASSERT_FALSE(beyond.is_null())
      << "slot 300 not surfaced — the iteration is capped below the "
         "map's size: " << arr.dump();
  EXPECT_EQ(beyond.value("packets", 0ULL), 4242u);
  EXPECT_EQ(beyond.value("bytes", 0ULL), 606060u);
}

TEST_F(BpfMapTest, ACounterBeyond256IsClearable) {
  ASSERT_TRUE(WriteCounter(counters_fd_, 7, 11, 22));
  ASSERT_TRUE(WriteCounter(counters_fd_, 300, 4242, 606060));
  ASSERT_TRUE(WriteCounter(counters_fd_, 9999, 5, 6));
  // Non-zero first, or "it reads zero afterwards" says nothing.
  ASSERT_EQ(ReadCounter(counters_fd_, 300).packets, 4242u);
  ASSERT_EQ(ReadCounter(counters_fd_, 9999).packets, 5u);

  auto reply = Ask(e_, Cmd::kClearCounters);
  ASSERT_FALSE(reply.contains("error")) << reply.dump();
  EXPECT_EQ(reply.value("cleared", 0u), 10000u);

  // Read the map, not the reply: the reply is the claim under test.
  EXPECT_EQ(ReadCounter(counters_fd_, 7).packets, 0u);
  EXPECT_EQ(ReadCounter(counters_fd_, 300).packets, 0u)
      << "slot 300 kept its count — clear-counters is capped below "
         "the map's size";
  EXPECT_EQ(ReadCounter(counters_fd_, 300).bytes, 0u);
  EXPECT_EQ(ReadCounter(counters_fd_, 9999).packets, 0u);
}

TEST_F(BpfMapTest, AShorterMapIsIteratedToItsOwnLength) {
  // The bound follows the map in both directions: shrink `counters`
  // and the reader shrinks with it rather than reading 10000 slots
  // that are not there. This is what makes the two unable to
  // disagree again.
  int small = MakeCountersMap(64);
  ASSERT_GE(small, 0);
  Engine e;
  e.bpf.counters_fd = small;
  ASSERT_TRUE(WriteCounter(small, 63, 77, 88));
  auto reply = Ask(e, Cmd::kClearCounters);
  EXPECT_EQ(reply.value("cleared", 0u), 64u);
  EXPECT_EQ(ReadCounter(small, 63).packets, 0u);
  close(small);
}

// --- the pairing ------------------------------------------------------

TEST_F(BpfMapTest, RulesCarryNoCounterTheDatapathDoesNotKeepPerRule) {
  // bpf/fw.bpf.c increments counters[0] for every packet and
  // counters[k+1] for match tier k. Those are the numbers below.
  // Paired with rules by iteration order — which is what this
  // handler used to do — rule 0 would show 1000 (all traffic seen),
  // rule 1 would show 500 (everything matched at tier 0, whichever
  // rules those were) and rule 2 would show 250. Three confident
  // numbers, none of them about the rule beside it.
  rules_fd_ = MakeRulesMap();
  ASSERT_GE(rules_fd_, 0);
  e_.bpf.rules_a_fd = rules_fd_;
  e_.rules.active_table = 0;

  for (uint16_t port : {80, 443, 8080}) {
    RuleKey k{};
    k.dst_port = port;
    k.proto = 6;
    RuleValue v{};
    v.action = 1;
    ASSERT_EQ(bpf_map_update_elem(rules_fd_, &k, &v, BPF_ANY), 0);
  }
  ASSERT_TRUE(WriteCounter(counters_fd_, 0, 1000, 100000));
  ASSERT_TRUE(WriteCounter(counters_fd_, 1, 500, 50000));
  ASSERT_TRUE(WriteCounter(counters_fd_, 2, 250, 25000));

  auto arr = Ask(e_, Cmd::kGetRules);
  ASSERT_TRUE(arr.is_array()) << arr.dump();
  // Vacuity guard: the rules really are there, so "no rule carries a
  // counter" cannot pass on an empty list.
  ASSERT_EQ(arr.size(), 3u) << arr.dump();

  // And the tier counters really are non-zero, so "no rule carries a
  // counter" cannot pass because there was nothing to mispair.
  auto counters = Ask(e_, Cmd::kGetCounters);
  ASSERT_FALSE(FindId(counters, 0).is_null()) << counters.dump();
  EXPECT_EQ(FindId(counters, 0).value("packets", 0ULL), 1000u);
  EXPECT_EQ(FindId(counters, 1).value("packets", 0ULL), 500u);

  for (const auto& r : arr) {
    EXPECT_FALSE(r.contains("packets"))
        << "a rule carries a packet count the datapath keeps per "
           "match tier, not per rule: " << r.dump();
    EXPECT_FALSE(r.contains("bytes")) << r.dump();
    // The rule itself is still reported — the fix removes a wrong
    // number, not the answer.
    EXPECT_TRUE(r.contains("action")) << r.dump();
    EXPECT_TRUE(r.contains("dst_port")) << r.dump();
  }
}

// --- what the daemon says with no single-program datapath -------------
//
// This is the state of every v0.4 box: EngineInit takes the
// multi-zone branch and never assigns `e.bpf`, so every descriptor in
// it is -1. No root needed — the point is precisely that nothing is
// loaded.

class NoDatapathTest : public ::testing::Test {
 protected:
  Engine e_;  // default: every fd in e_.bpf is -1
};

TEST_F(NoDatapathTest, GetRulesRefusesInsteadOfAnsweringEmpty) {
  auto reply = Ask(e_, Cmd::kGetRules);
  ASSERT_TRUE(reply.is_object())
      << "an array here renders as \"no rules loaded\", which is a "
         "statement about the operator's policy made by a handler "
         "that never looked at it: " << reply.dump();
  ASSERT_TRUE(reply.contains("error")) << reply.dump();
  EXPECT_NE(reply["error"].get<std::string>().find("fwl_counters"),
            std::string::npos)
      << "the refusal must say where the real counters are: "
      << reply.dump();
}

TEST_F(NoDatapathTest, GetCountersRefusesInsteadOfAnsweringEmpty) {
  auto reply = Ask(e_, Cmd::kGetCounters);
  ASSERT_TRUE(reply.is_object()) << reply.dump();
  EXPECT_TRUE(reply.contains("error")) << reply.dump();
}

TEST_F(NoDatapathTest, ClearCountersRefusesInsteadOfClaimingZero) {
  // `{"cleared":0}` renders as "cleared 0 counter slots" with an OK
  // marker beside it — a successful clear of a map this daemon does
  // not have, on a box whose fwl_counters_<zone> map is untouched.
  auto reply = Ask(e_, Cmd::kClearCounters);
  ASSERT_TRUE(reply.is_object()) << reply.dump();
  EXPECT_TRUE(reply.contains("error")) << reply.dump();
  EXPECT_FALSE(reply.contains("cleared")) << reply.dump();
}

TEST_F(NoDatapathTest, ApplyConfigRefusesInsteadOfInstallingNothing) {
  // Every bpf_map_update_elem(-1, ...) fails EBADF, the loop's
  // `continue` swallows it, and the reply was
  // `{"rules_installed":0}` — no error field, so f-api answers 200
  // to a PUT that wrote nothing anywhere.
  json cfg{{"default_action", 1},
           {"rules", json::array({
               json{{"dst_port", 80}, {"proto", 6}, {"action", 0}}})}};
  auto reply = Ask(e_, Cmd::kApplyConfig, cfg.dump());
  ASSERT_TRUE(reply.is_object()) << reply.dump();
  EXPECT_TRUE(reply.contains("error")) << reply.dump();
  EXPECT_FALSE(reply.contains("rules_installed")) << reply.dump();
}

TEST_F(NoDatapathTest, UnrelatedHandlersStillAnswer) {
  // The guard is on the four handlers that read the single-program
  // maps and nowhere else. A guard that refused everything would
  // pass every test above while breaking the box.
  auto zones = Ask(e_, Cmd::kGetZones);
  EXPECT_TRUE(zones.is_array()) << zones.dump();
  auto fw = Ask(e_, Cmd::kGetFirewall);
  EXPECT_TRUE(fw.is_object()) << fw.dump();
  EXPECT_FALSE(fw.contains("error")) << fw.dump();
}

}  // namespace
}  // namespace f
