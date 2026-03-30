/// @file test_protocol.cc
/// @brief Serialization round-trip tests for protocol types.

#include <gtest/gtest.h>

#include <cstring>

#include "f/protocol.h"

namespace f {

TEST(ProtocolTest, FrameMessageLength) {
  uint8_t payload[] = {1, 2, 3};
  auto framed = FrameMessage(payload);
  EXPECT_EQ(framed.size(), 4 + 3);

  uint32_t len = ReadFrameLength(framed);
  EXPECT_EQ(len, 3u);
}

TEST(ProtocolTest, FrameMessageEmpty) {
  auto framed = FrameMessage({});
  EXPECT_EQ(framed.size(), 4u);
  EXPECT_EQ(ReadFrameLength(framed), 0u);
}

TEST(ProtocolTest, ConfigMsgRoundTrip) {
  ConfigMsg msg{};
  msg.cmd = Cmd::kApplyConfig;
  msg.default_action = 1;
  msg.conntrack_enabled = 1;
  msg.conntrack_timeout_s = 300;
  msg.rule_count = 42;

  auto serialized = SerializeConfigMsg(msg);
  ASSERT_GE(serialized.size(), 4 + sizeof(ConfigMsg));

  uint32_t len = ReadFrameLength(serialized);
  EXPECT_EQ(len, sizeof(ConfigMsg));

  auto deserialized = DeserializeConfigMsg(
      std::span<const uint8_t>(
          serialized.data() + 4, len));

  EXPECT_EQ(deserialized.cmd, Cmd::kApplyConfig);
  EXPECT_EQ(deserialized.default_action, 1);
  EXPECT_EQ(deserialized.conntrack_enabled, 1);
  EXPECT_EQ(deserialized.conntrack_timeout_s, 300u);
  EXPECT_EQ(deserialized.rule_count, 42u);
}

TEST(ProtocolTest, StatusResponseRoundTrip) {
  StatusResponse resp{};
  resp.pid = 12345;
  resp.uptime_s = 3600;
  resp.active_table = 1;
  resp.rule_count = 10;
  resp.iface_count = 2;

  auto serialized = SerializeStatusResponse(resp);
  ASSERT_GE(serialized.size(),
            4 + sizeof(StatusResponse));

  uint32_t len = ReadFrameLength(serialized);
  EXPECT_EQ(len, sizeof(StatusResponse));

  auto deserialized = DeserializeStatusResponse(
      std::span<const uint8_t>(
          serialized.data() + 4, len));

  EXPECT_EQ(deserialized.pid, 12345u);
  EXPECT_EQ(deserialized.uptime_s, 3600u);
  EXPECT_EQ(deserialized.active_table, 1);
  EXPECT_EQ(deserialized.rule_count, 10u);
  EXPECT_EQ(deserialized.iface_count, 2u);
}

TEST(ProtocolTest, CmdValues) {
  EXPECT_EQ(static_cast<uint8_t>(Cmd::kApplyConfig), 1);
  EXPECT_EQ(static_cast<uint8_t>(Cmd::kGetCounters), 2);
  EXPECT_EQ(static_cast<uint8_t>(Cmd::kGetStatus), 3);
  EXPECT_EQ(static_cast<uint8_t>(Cmd::kReloadProg), 4);
  EXPECT_EQ(static_cast<uint8_t>(Cmd::kStop), 5);
}

}  // namespace f
