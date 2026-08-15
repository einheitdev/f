/// @file protocol.h
/// @brief Control socket command opcodes.

#ifndef INCLUDE_F_PROTOCOL_H_
#define INCLUDE_F_PROTOCOL_H_

#include <cstdint>

namespace f {

// ============================================================================
// Commands
// ============================================================================

/// The one-byte opcode a control request opens with. A request is
/// `[1B Cmd][payload]` over the ZMQ REP socket; the reply is JSON.
///
/// The gaps are deliberate and the numbers do not move. 1, 2, 6, 7 and
/// 8 were kApplyConfig, kGetCounters, kGetFirewall, kGetRules and
/// kClearCounters — the control surface of the v0.1 single-program
/// datapath, removed with it. Renumbering the survivors would make an
/// older `einheit-f` on an upgraded box send 7 and be answered as if it
/// had asked something else. Retired, they fall through to `default:`
/// and are told `unknown command`, which is the answer.
enum class Cmd : uint8_t {
  kGetStatus = 3,
  kReloadProg = 4,
  kStop = 5,
  // v0.4 multi-zone bundle introspection.
  kGetZones = 9,
  kGetNat = 10,
  kGetConntrack = 11,
};

}  // namespace f

#endif  // INCLUDE_F_PROTOCOL_H_
