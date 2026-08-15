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

// NAT reply-mapping entry in the shared `fwl_nat` map. Byte-compatible
// with `struct fwl_nat_key`/`fwl_nat_value` the FWL emitter generates.
// Ports are host byte order (the emitter stores bpf_ntohs'd values);
// addresses are network byte order.
struct FwlNatKey {
  uint32_t src_addr;
  uint32_t dst_addr;
  uint16_t src_port;
  uint16_t dst_port;
  uint8_t proto;
  uint8_t pad[3];
};
struct FwlNatValue {
  /// Monotonic (bpf_ktime_get_ns) stamp of the last datapath touch:
  /// the egress rewrite that keeps using the mapping, or the de-NAT of
  /// one of its replies. This is what the daemon ages the table on —
  /// without it `fwl_nat` is monotone and its 65536 entries are a
  /// lifetime budget of translated flows rather than a concurrency
  /// budget (measured on the rig: 3613 entries/h at ~1 new flow/s).
  uint64_t last_seen_ns;
  uint32_t new_addr;
  uint16_t new_port;
  uint8_t nat_type;
  uint8_t pad;
};

/// Slots in the shared `fwl_nat_stats` per-CPU array. Numbered by the
/// FWL emitter's NAT header, not by any policy, so slot i means the
/// same event under every compilation.
enum FwlNatStat : uint32_t {
  kFwlNatStatInstalled = 0,   ///< reply mappings claimed
  kFwlNatStatRealloc = 1,     ///< source port moved to avoid a collision
  kFwlNatStatRefused = 2,     ///< no mapping could be claimed; packet dropped
  kFwlNatStatTableFull = 3,   ///< the refusal was the table hitting its cap
  kFwlNatStatDenat = 4,       ///< return packets translated back
  /// ICMP errors translated off their embedded datagram (RFC 5508).
  /// A SUBSET of kFwlNatStatDenat, not a separate event: an error is a
  /// return-direction translation like any other. Counted apart
  /// because it is the one whose absence looks like nothing at all —
  /// path-MTU discovery fails as "the network is slow", with no drop,
  /// no log, and every other counter still climbing.
  kFwlNatStatIcmpErr = 5,
  kFwlNatStatSlots = 6,
};

/// Slots in the shared `fwl_route_stats` per-CPU array, numbered by the
/// FWL emitter's routing header.
///
/// A `redirect to <zone>` forwards the frame with whatever destination
/// MAC it arrived carrying unless the box's own routing table says the
/// destination is reachable through that zone. Which of the two
/// happened is invisible on the wire to anything that captures
/// promiscuously — a frame addressed to the wrong MAC is on the cable
/// and in the tcpdump, and only the far side's stack discards it — so
/// the count is the operator's only view of whether this box is
/// routing or bridging.
enum FwlRouteStat : uint32_t {
  /// Next hop resolved through the zone the policy named; the frame
  /// was re-addressed and its TTL decremented.
  kFwlRouteStatRouted = 0,
  /// No usable route out that zone: forwarded L2-adjacent, exactly as
  /// a redirect did before routing existed. Correct for a zone hop on
  /// one segment, and a black hole for a masqueraded flow.
  kFwlRouteStatBridged = 1,
  /// The routing table was consulted and said no (blackhole,
  /// unreachable, prohibited). Dropped.
  kFwlRouteStatNoRoute = 2,
  /// Route known, next-hop MAC not. Handed to the stack so it can ARP.
  kFwlRouteStatNoNeigh = 3,
  /// TTL would have reached zero. Handed to the stack, which owns the
  /// ICMP time-exceeded.
  kFwlRouteStatTtl = 4,
  /// A route exists but leaves through a DIFFERENT interface than the
  /// zone the policy named. Forwarded L2-adjacent rather than stamped
  /// with a next hop that lives on another segment.
  kFwlRouteStatOffZone = 5,
  kFwlRouteStatSlots = 6,
};

/// Slots in the shared `fwl_egress_stats` per-CPU array, numbered by
/// the FWL emitter's egress-tracker header.
///
/// The tracker runs at the TC clsact egress hook and answers one
/// question per packet: did this box ORIGINATE this flow? XDP conntrack
/// only ever sees ingress, so without it a reply to the box's own DNS
/// query reads NEW and `default drop` eats it (measured: l12_01).
enum FwlEgressStat : uint32_t {
  /// Packets at the hook. The denominator; without it the rows below
  /// cannot be told from an idle interface.
  kFwlEgressStatSeen = 0,
  /// No socket on the skb: this box FORWARDED the packet rather than
  /// sent it. Deliberately not tracked — creating an entry for a
  /// forwarded flow would admit its replies, which is a policy change
  /// made by a component whose job is to observe.
  kFwlEgressStatNotLocal = 1,
  /// Locally originated but outside what v0.4 conntrack keys: not
  /// IPv4, a non-first fragment, or a protocol other than TCP/UDP/ICMP.
  kFwlEgressStatUntracked = 2,
  /// A conntrack entry created — one flow this box started.
  kFwlEgressStatTracked = 3,
  /// An existing entry re-stamped, in either direction. This is what
  /// keeps the occupancy cost at one entry per originated flow: a reply
  /// the box sends to a client refreshes the entry that client's own
  /// query created instead of adding its reverse.
  kFwlEgressStatRefreshed = 4,
  /// The insert failed — conntrack is at its cap. The packet still goes
  /// out and its reply will be dropped, so this is the one slot here
  /// that is an error rather than an accounting row.
  kFwlEgressStatRefused = 5,
  kFwlEgressStatSlots = 6,
};

// Per-zone masquerade config (`fwl_nat_cfg`, slot 0). `masq_addr` is the
// network-byte-order source the XDP masquerade action rewrites to.
struct FwlNatCfg {
  uint32_t masq_addr;
};

/// Global firewall config (array map, 1 entry).
struct FwConfig {
  uint8_t default_action;
  uint8_t active_table;
  uint8_t conntrack_enabled;
  uint8_t pad;
  uint32_t conntrack_timeout_s;
};

// ============================================================================
// Ring buffer event — XDP → slow path.
// ============================================================================

#ifdef __cplusplus
enum class EventType : uint8_t {
  kNewConn = 1,
  kRateExceeded = 2,
  kUnknownProto = 3,
};
#else
enum EventType {
  EVENT_NEW_CONN = 1,
  EVENT_RATE_EXCEEDED = 2,
  EVENT_UNKNOWN_PROTO = 3,
};
#endif

/// Fixed-size event sent from XDP to userspace.
struct Event {
  uint8_t type;
  uint8_t proto;
  uint16_t src_port;
  uint16_t dst_port;
  uint16_t pkt_len;
  uint32_t src_addr;
  uint32_t dst_addr;
  uint64_t timestamp_ns;
  // First 64 bytes of L4+ payload for inspection.
  uint8_t payload[64];
};

#ifdef __cplusplus
}  // namespace f
#endif

#endif  // INCLUDE_F_TYPES_H_
