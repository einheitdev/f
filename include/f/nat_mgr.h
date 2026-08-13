/// @file nat_mgr.h
/// @brief NAT reply-mapping table: occupancy, reclamation, visibility.

#ifndef INCLUDE_F_NAT_MGR_H_
#define INCLUDE_F_NAT_MGR_H_

#include <cstdint>

#include "f/component.h"
#include "f/types.h"

namespace f {

/// The shared `fwl_nat` reply-mapping table, from the daemon's side.
///
/// ## Why this exists
///
/// `fwl_nat` had no collector anywhere. It is `MapLifetime::FLOW`, so
/// it also survives a process restart — measured on the rig (l11_02): a
/// flood that drained conntrack 65536 -> 0 released not one NAT entry,
/// and `systemctl restart fd` did not clear it either. At the cap the
/// outbound half of a new flow still translates perfectly while its
/// reply is left addressed to the firewall's own WAN address, so the
/// symptom is "new connections hang, old ones are fine" with nothing
/// logged, nothing counted, and no NAT section in `fctl status` to see
/// it in. Fill rate at ~1 new flow/s was 3613 entries/h: 17 hours from
/// deployment to a broken network.
///
/// ## What a mapping's lifetime is tied to
///
/// A mapping is meaningful exactly while its flow exists, so the flow
/// is what decides — not a timer of this table's own, and not eviction
/// under pressure. Every mapping has a conntrack entry behind it
/// carrying the POST-NAT 5-tuple (`fwl_snat_egress` and
/// `fwl_dnat_ingress` both insert one), and that entry is the reverse
/// of the mapping's own key. So the anchor for a mapping is
/// `Anchor(key)` — a single conntrack lookup — and conntrack's GC is
/// the one authority on when a flow is over.
///
/// Three things had to be true before that hook was sound, and were
/// not:
///
///  1. the destination-NAT path inserted no conntrack entry at all, so
///     half the mappings had no anchor. It does now.
///  2. an FWL-emitted program never refreshed `last_seen_ns`, so
///     conntrack's "idle timeout" was really a lifetime cap and the
///     anchor of a busy flow vanished 300 s after its FIRST packet.
///     Both the conntrack lookup and the NAT egress path stamp it now.
///  3. the anchor insert can fail silently when conntrack is at its own
///     cap, leaving a live mapping unanchored.
///
/// (3) cannot be fixed at the source, so reclamation carries a second
/// condition that closes it: a mapping is reclaimed only when its
/// anchor is gone AND the mapping itself has carried no traffic for at
/// least `grace_s`. `last_seen_ns` in `FwlNatValue` is stamped by every
/// datapath touch, so a mapping that is still carrying traffic is never
/// reclaimed whatever conntrack says. Freeing is driven by flow end;
/// the stamp only guarantees we never break a live flow to do it.
///
/// ## At the cap
///
/// Refuse and say so. The datapath claims mappings with BPF_NOEXIST and
/// drops the packet when it cannot get one (counted in
/// `fwl_nat_stats`); this manager makes the pressure visible before
/// that point — occupancy in `fctl status`, a WARN when the table
/// crosses `warn_pct`, and an ERROR naming the refusals when any are
/// seen. Nothing here ever evicts a live mapping to make room: losing
/// new connections loudly is recoverable, and killing a running
/// transfer at random is not.
struct NatMgr : Component {
  /// `fwl_nat` — the reply-mapping table. -1 when the loaded policy
  /// uses no NAT.
  int map_fd = -1;
  /// `fwl_nat_stats` — the datapath's per-CPU event tally.
  int stats_fd = -1;
  /// The conntrack table the mappings are anchored in. Set from
  /// ConntrackMgr so the two can never drift apart.
  int conntrack_fd = -1;
  /// `max_entries` of `fwl_nat`, read from the map itself rather than
  /// assumed, so occupancy is a percentage of the real cap.
  uint32_t max_entries = 0;

  bool enabled = false;
  /// Minimum idle time before an unanchored mapping may be reclaimed.
  /// A guard against reclaiming a live flow whose anchor insert lost a
  /// race or hit a full conntrack table — not a lifetime of its own.
  uint32_t grace_s = 30;
  uint64_t last_gc_ns = 0;

  uint64_t total_reclaimed = 0;
  /// Highest occupancy seen since the daemon started, so a table that
  /// filled and drained between two `fctl status` calls still shows.
  uint32_t high_water = 0;
  /// Occupancy percentage at which the last warning fired, so the log
  /// says something on the way up and does not repeat every sweep.
  uint32_t warned_at_pct = 0;
  uint32_t warn_pct = 80;
  /// Refusals already reported, so each new one is logged once.
  uint64_t reported_refusals = 0;

  auto GetState() const -> nlohmann::json override;
  auto SetState(const nlohmann::json& j) -> bool override;

  /// Count the live mappings. -1 is impossible; 0 when there is no map.
  auto Entries() const -> uint32_t;

  /// Sum one `fwl_nat_stats` slot across every CPU.
  auto Stat(FwlNatStat slot) const -> uint64_t;

  /// Reclaim every mapping whose flow is over. Returns the number
  /// freed. `timeout_ns` is conntrack's idle timeout, used only for the
  /// grace comparison's upper bound in the log message.
  auto RunGc(uint64_t now_ns) -> uint32_t;

  /// Run a sweep and report on the table's state. Called from the
  /// engine loop right after conntrack's own sweep, so the anchors this
  /// pass reads are already the post-sweep truth.
  auto MaybeRunGc(uint64_t now_ns, uint32_t gc_interval_s) -> uint32_t;

  /// The conntrack key a mapping is anchored by: the mapping's own key
  /// with the two endpoints swapped. `fwl_snat_egress` inserts exactly
  /// this tuple, and so does `fwl_dnat_ingress`.
  static auto Anchor(const FwlNatKey& k) -> ConnKey;
};

}  // namespace f

#endif  // INCLUDE_F_NAT_MGR_H_
