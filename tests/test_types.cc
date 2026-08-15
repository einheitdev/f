/// @file test_types.cc
/// @brief Struct layout and size assertions for shared types.
///
/// Seven of these covered `LpmKey`, `RuleKey`, `RuleValue`,
/// `RuleCounter`, `FwConfig` and `Action` — the map ABI of
/// `bpf/fw.bpf.c`, the v0.1 single-program datapath. They were checking
/// that two halves of one deleted program agreed with each other.
///
/// What is left is the ABI that still has two sides: these structs are
/// how the daemon reads maps the FWL emitter declares, so a layout
/// change here is a real compiler/daemon disagreement.

#include <gtest/gtest.h>

#include <cstddef>

#include "f/types.h"

namespace f {

TEST(TypesTest, ConnKeySize) {
  EXPECT_EQ(sizeof(ConnKey), 16);
}

TEST(TypesTest, ConnValueSize) {
  EXPECT_EQ(sizeof(ConnValue), 24);
}

TEST(TypesTest, ConnKeyFieldOffsets) {
  // Byte-compatible with the emitter's `struct conn_key`. The daemon's
  // conntrack GC deletes by this key, so a disagreement does not fail
  // loudly — it sweeps the wrong entries, or none.
  EXPECT_EQ(offsetof(ConnKey, src_addr), 0);
  EXPECT_EQ(offsetof(ConnKey, dst_addr), 4);
  EXPECT_EQ(offsetof(ConnKey, src_port), 8);
  EXPECT_EQ(offsetof(ConnKey, dst_port), 10);
  EXPECT_EQ(offsetof(ConnKey, proto), 12);
}

TEST(TypesTest, FwlNatKeyFieldOffsets) {
  // Byte-compatible with the emitter's `struct fwl_nat_key`; `show nat`
  // and the mapping GC both read the shared `fwl_nat` map through it.
  EXPECT_EQ(sizeof(FwlNatKey), 16);
  EXPECT_EQ(offsetof(FwlNatKey, src_addr), 0);
  EXPECT_EQ(offsetof(FwlNatKey, dst_addr), 4);
  EXPECT_EQ(offsetof(FwlNatKey, src_port), 8);
  EXPECT_EQ(offsetof(FwlNatKey, dst_port), 10);
  EXPECT_EQ(offsetof(FwlNatKey, proto), 12);
}

TEST(TypesTest, FwlNatValueFieldOffsets) {
  EXPECT_EQ(offsetof(FwlNatValue, last_seen_ns), 0);
  EXPECT_EQ(offsetof(FwlNatValue, new_addr), 8);
  EXPECT_EQ(offsetof(FwlNatValue, new_port), 12);
  EXPECT_EQ(offsetof(FwlNatValue, nat_type), 14);
}

TEST(TypesTest, ProtoValues) {
  EXPECT_EQ(static_cast<uint8_t>(Proto::kAny), 0);
  EXPECT_EQ(static_cast<uint8_t>(Proto::kIcmp), 1);
  EXPECT_EQ(static_cast<uint8_t>(Proto::kTcp), 6);
  EXPECT_EQ(static_cast<uint8_t>(Proto::kUdp), 17);
}

}  // namespace f
