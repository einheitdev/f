/// @file protocol.h
/// @brief Control socket binary protocol types.

#ifndef INCLUDE_F_PROTOCOL_H_
#define INCLUDE_F_PROTOCOL_H_

#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <vector>

#include "f/types.h"

namespace f {

// ============================================================================
// Commands
// ============================================================================

enum class Cmd : uint8_t {
  kApplyConfig = 1,
  kGetCounters = 2,
  kGetStatus = 3,
  kReloadProg = 4,
  kStop = 5,
};

// ============================================================================
// Wire messages — flat structs, no padding surprises.
// Wire format: [4B little-endian length][payload].
// ============================================================================

struct ConfigMsg {
  Cmd cmd;
  uint8_t pad[3];
  uint8_t default_action;
  uint8_t conntrack_enabled;
  uint8_t pad2[2];
  uint32_t conntrack_timeout_s;
  uint32_t rule_count;
};

struct StatusResponse {
  uint32_t pid;
  uint64_t uptime_s;
  uint8_t active_table;
  uint8_t pad[3];
  uint32_t rule_count;
  uint32_t iface_count;
};

struct CounterResponse {
  uint32_t count;
};

// ============================================================================
// Serialization helpers
// ============================================================================

/// Encode a 4-byte little-endian length prefix + payload.
inline auto FrameMessage(std::span<const uint8_t> payload)
    -> std::vector<uint8_t> {
  uint32_t len = static_cast<uint32_t>(payload.size());
  std::vector<uint8_t> out(sizeof(len) + len);
  std::memcpy(out.data(), &len, sizeof(len));
  std::memcpy(out.data() + sizeof(len), payload.data(), len);
  return out;
}

/// Read a 4-byte little-endian length prefix.
inline auto ReadFrameLength(std::span<const uint8_t> buf)
    -> uint32_t {
  uint32_t len = 0;
  if (buf.size() >= sizeof(len)) {
    std::memcpy(&len, buf.data(), sizeof(len));
  }
  return len;
}

/// Serialize a ConfigMsg to bytes.
inline auto SerializeConfigMsg(const ConfigMsg& msg)
    -> std::vector<uint8_t> {
  std::vector<uint8_t> buf(sizeof(msg));
  std::memcpy(buf.data(), &msg, sizeof(msg));
  return FrameMessage(buf);
}

/// Deserialize a ConfigMsg from a payload (after frame header).
inline auto DeserializeConfigMsg(
    std::span<const uint8_t> payload) -> ConfigMsg {
  ConfigMsg msg{};
  if (payload.size() >= sizeof(msg)) {
    std::memcpy(&msg, payload.data(), sizeof(msg));
  }
  return msg;
}

/// Serialize a StatusResponse to bytes.
inline auto SerializeStatusResponse(
    const StatusResponse& resp) -> std::vector<uint8_t> {
  std::vector<uint8_t> buf(sizeof(resp));
  std::memcpy(buf.data(), &resp, sizeof(resp));
  return FrameMessage(buf);
}

/// Deserialize a StatusResponse from a payload.
inline auto DeserializeStatusResponse(
    std::span<const uint8_t> payload) -> StatusResponse {
  StatusResponse resp{};
  if (payload.size() >= sizeof(resp)) {
    std::memcpy(&resp, payload.data(), sizeof(resp));
  }
  return resp;
}

}  // namespace f

#endif  // INCLUDE_F_PROTOCOL_H_
