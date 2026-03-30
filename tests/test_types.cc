/// @file test_types.cc
/// @brief Struct layout and size assertions for shared types.

#include <gtest/gtest.h>

#include <cstddef>

#include "f/types.h"

namespace f {

TEST(TypesTest, LpmKeySize) {
  EXPECT_EQ(sizeof(LpmKey), 8);
}

TEST(TypesTest, RuleKeySize) {
  EXPECT_EQ(sizeof(RuleKey), 16);
}

TEST(TypesTest, RuleValueSize) {
  EXPECT_EQ(sizeof(RuleValue), 8);
}

TEST(TypesTest, RuleCounterSize) {
  EXPECT_EQ(sizeof(RuleCounter), 16);
}

TEST(TypesTest, ConnKeySize) {
  EXPECT_EQ(sizeof(ConnKey), 16);
}

TEST(TypesTest, ConnValueSize) {
  EXPECT_EQ(sizeof(ConnValue), 24);
}

TEST(TypesTest, FwConfigSize) {
  EXPECT_EQ(sizeof(FwConfig), 8);
}

TEST(TypesTest, RuleKeyFieldOffsets) {
  EXPECT_EQ(offsetof(RuleKey, src_addr), 0);
  EXPECT_EQ(offsetof(RuleKey, dst_addr), 4);
  EXPECT_EQ(offsetof(RuleKey, src_port), 8);
  EXPECT_EQ(offsetof(RuleKey, dst_port), 10);
  EXPECT_EQ(offsetof(RuleKey, proto), 12);
}

TEST(TypesTest, FwConfigFieldOffsets) {
  EXPECT_EQ(offsetof(FwConfig, default_action), 0);
  EXPECT_EQ(offsetof(FwConfig, active_table), 1);
  EXPECT_EQ(offsetof(FwConfig, conntrack_enabled), 2);
  EXPECT_EQ(offsetof(FwConfig, conntrack_timeout_s), 4);
}

TEST(TypesTest, ActionValues) {
  EXPECT_EQ(static_cast<uint8_t>(Action::kDrop), 0);
  EXPECT_EQ(static_cast<uint8_t>(Action::kAllow), 1);
  EXPECT_EQ(static_cast<uint8_t>(Action::kRateLimit), 2);
}

TEST(TypesTest, ProtoValues) {
  EXPECT_EQ(static_cast<uint8_t>(Proto::kAny), 0);
  EXPECT_EQ(static_cast<uint8_t>(Proto::kIcmp), 1);
  EXPECT_EQ(static_cast<uint8_t>(Proto::kTcp), 6);
  EXPECT_EQ(static_cast<uint8_t>(Proto::kUdp), 17);
}

}  // namespace f
