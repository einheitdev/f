/// @file test_protocol.cc
/// @brief The control-socket opcodes.
///
/// What was here was mostly the v0.1 wire format: a `[4B LE
/// length][payload]` framing (`FrameMessage`), a `ConfigMsg` carrying a
/// rule count, and a `StatusResponse` carrying `active_table` and
/// `rule_count`. All three described the Unix-socket protocol of the
/// single-program datapath. Nothing spoke it — the daemon has been on
/// ZMQ with a one-byte opcode and a JSON reply since v0.2, and the
/// framing helpers had no caller outside this file — and it has been
/// removed with the datapath.
///
/// What is left is the one thing about this header that a change can
/// still break at a distance: the opcode NUMBERS. An older `einheit-f`
/// against a newer box sends the number it was compiled with.

#include <gtest/gtest.h>

#include <cstdint>

#include "f/protocol.h"

namespace f {
namespace {

TEST(ProtocolTest, SurvivingOpcodesKeepTheirNumbers) {
  // These are on the wire between an installed CLI and an installed
  // daemon, which are upgraded separately. Renumbering is a protocol
  // break; this test is what makes it a deliberate one.
  EXPECT_EQ(static_cast<uint8_t>(Cmd::kGetStatus), 3);
  EXPECT_EQ(static_cast<uint8_t>(Cmd::kReloadProg), 4);
  EXPECT_EQ(static_cast<uint8_t>(Cmd::kStop), 5);
  EXPECT_EQ(static_cast<uint8_t>(Cmd::kGetZones), 9);
  EXPECT_EQ(static_cast<uint8_t>(Cmd::kGetNat), 10);
  EXPECT_EQ(static_cast<uint8_t>(Cmd::kGetConntrack), 11);
}

TEST(ProtocolTest, RetiredOpcodesAreNotReused) {
  // 1, 2, 6, 7 and 8 were kApplyConfig, kGetCounters, kGetFirewall,
  // kGetRules and kClearCounters. Handing one of those numbers to a new
  // command would answer an old CLI's question with a different
  // command's reply — the failure would be a wrong answer, not a
  // refusal, which is the worse of the two. They stay retired; fd
  // answers them `unknown command`.
  for (uint8_t retired : {1, 2, 6, 7, 8}) {
    for (auto live : {Cmd::kGetStatus, Cmd::kReloadProg, Cmd::kStop,
                      Cmd::kGetZones, Cmd::kGetNat,
                      Cmd::kGetConntrack}) {
      EXPECT_NE(static_cast<uint8_t>(live), retired)
          << "opcode " << static_cast<int>(retired)
          << " belonged to the v0.1 single-program surface";
    }
  }
}

}  // namespace
}  // namespace f
