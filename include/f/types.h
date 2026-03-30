/// @file types.h
/// @brief Shared BPF/userspace data types.
///
/// This header is included by both the BPF C program (clang -target
/// bpf) and C++23 userspace code.  Use __cplusplus guards for C++
/// features.

#ifndef INCLUDE_F_TYPES_H_
#define INCLUDE_F_TYPES_H_

#ifdef __cplusplus
#include <cstdint>
#elif defined(__BPF__)
// BPF target: use kernel types, no libc.
#include <linux/types.h>
typedef __u8  uint8_t;
typedef __u16 uint16_t;
typedef __u32 uint32_t;
typedef __u64 uint64_t;
#else
#include <stdint.h>
#endif

// ============================================================================
// Enums — enum class in C++, plain enum in C.
// ============================================================================

#ifdef __cplusplus
namespace f {

enum class Action : uint8_t {
  kDrop = 0,
  kAllow = 1,
  kRateLimit = 2,
};

enum class Proto : uint8_t {
  kAny = 0,
  kIcmp = 1,
  kTcp = 6,
  kUdp = 17,
};

#else

enum Action {
  ACTION_DROP = 0,
  ACTION_ALLOW = 1,
  ACTION_RATE_LIMIT = 2,
};

enum Proto {
  PROTO_ANY = 0,
  PROTO_ICMP = 1,
  PROTO_TCP = 6,
  PROTO_UDP = 17,
};

#endif

// ============================================================================
// Shared structs — identical layout in C and C++.
// ============================================================================

/// LPM trie key for CIDR matching.
struct LpmKey {
  uint32_t prefixlen;
  uint32_t addr;
};

/// Exact-match rule key (5-tuple).
struct RuleKey {
  uint32_t src_addr;
  uint32_t dst_addr;
  uint16_t src_port;
  uint16_t dst_port;
  uint8_t proto;
  uint8_t pad[3];
};

/// Rule action and parameters.
struct RuleValue {
  uint8_t action;
  uint8_t pad[3];
  uint32_t rate_pps;
};

/// Per-rule packet/byte counters (per-CPU array element).
struct RuleCounter {
  uint64_t packets;
  uint64_t bytes;
};

/// Connection tracking key.
struct ConnKey {
  uint32_t src_addr;
  uint32_t dst_addr;
  uint16_t src_port;
  uint16_t dst_port;
  uint8_t proto;
  uint8_t pad[3];
};

/// Connection tracking value.
struct ConnValue {
  uint64_t last_seen_ns;
  uint64_t packets;
  uint8_t state;
  uint8_t pad[7];
};

/// Global firewall config (array map, 1 entry).
struct FwConfig {
  uint8_t default_action;
  uint8_t active_table;
  uint8_t conntrack_enabled;
  uint8_t pad;
  uint32_t conntrack_timeout_s;
};

#ifdef __cplusplus
}  // namespace f
#endif

#endif  // INCLUDE_F_TYPES_H_
