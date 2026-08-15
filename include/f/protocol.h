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
  /// The loaded policy's own named counters: every `count <name>` in
  /// every zone, read out of that zone's `fwl_counters_<zone>` map and
  /// presented under the name the policy gave it.
  ///
  /// A NEW number rather than a reuse of 2 (`kGetCounters`), which
  /// asked the v0.1 datapath about a different map with a different
  /// key. An old `einheit-f` sending 2 to this daemon must hear
  /// `unknown command` and not be answered with counters keyed a way
  /// it does not expect.
  kGetFwlCounters = 12,
  /// The loaded policy's RULES: every zone's rules in policy order,
  /// with the action and the match the compiler wrote into the bundle
  /// manifest, captured at load beside the object they were compiled
  /// into — plus the identity of the policy text the bundle came from,
  /// so a consumer can tell a live policy from an edited file.
  ///
  /// A NEW number again, for the reason 12 was: 7 was `kGetRules`, and
  /// it paired counters with rules by iteration order while the
  /// datapath keyed them by match tier, so every number it showed was
  /// wrong and next to the wrong rule. An old `einheit-f` sending 7
  /// must hear `unknown command`, not a reply in a shape it will
  /// misread.
  kGetFwlRules = 13,
};

}  // namespace f

#endif  // INCLUDE_F_PROTOCOL_H_
