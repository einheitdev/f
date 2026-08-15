/// @file egress_mgr.h
/// @brief What the egress conntrack tracker did, from the daemon's side.

#ifndef INCLUDE_F_EGRESS_MGR_H_
#define INCLUDE_F_EGRESS_MGR_H_

#include <cstdint>
#include <string>
#include <vector>

#include "f/component.h"
#include "f/types.h"

namespace f {

/// The egress tracker's tally, and the one failure it can have.
///
/// ## Why this is a section and not a log line
///
/// The whole class of defect this feature closes was invisible: a box
/// whose DNS forwarder cannot resolve anything, whose clock never sets,
/// and whose every counter keeps climbing, with no drop attributed to
/// anything. A fix for that must not itself be able to stop working
/// quietly, and it has exactly one way to: `refused`.
///
/// `refused` means an insert into `conntrack` failed, which in practice
/// means the table is at its cap. The packet still goes out, the reply
/// still arrives, and `default drop` eats it — the original symptom,
/// restored, by a mechanism that is working exactly as designed. It is
/// counted per-CPU by the datapath and turned into an ERROR here.
///
/// ## What it costs the table
///
/// One conntrack entry per flow the box ORIGINATES, and only those: the
/// tracker probes both directions of the 5-tuple before creating
/// anything, so a reply the box sends to a client that queried it
/// refreshes the entry the client's own query made rather than adding a
/// second. Against the two-entries-per-NAT-mapping load that already
/// makes conntrack the binding constraint (l11_02), an appliance's own
/// flows are a small constant: a DNS forwarder holds a handful of
/// upstream sockets, NTP one, updates a few at a time.
struct EgressMgr : Component {
  /// `fwl_egress_stats` — the hook's per-CPU tally. -1 when no tracker
  /// is attached.
  int stats_fd = -1;
  /// True when a tracker is attached to at least one interface.
  bool enabled = false;
  /// True when the loaded bundle DECLARES a tracker — the compiler's
  /// own answer to "does this policy read conntrack(pkt).state", taken
  /// from the manifest rather than re-derived here.
  ///
  /// It used to be `conntrack_fd >= 0`, which is a different question
  /// with a different answer: every NAT bundle carries the conntrack
  /// map, because `fwl_snat_egress` inserts the post-NAT tuple, so a
  /// masquerade-only policy that never asks `conntrack(pkt).state` said
  /// yes. On such a box — healthy, correct, nothing to fix — `fd`
  /// logged an ERROR every load and `fctl status` rendered a red row
  /// saying its DNS was being dropped. Training the operator to ignore
  /// this row is the one outcome that would undo the whole feature.
  bool tracker_declared = false;
  /// True when the manifest has no `egress_tracker` key at all: a
  /// bundle compiled before the hook existed. A THIRD state, not a
  /// second one — from such a manifest it cannot be known whether the
  /// policy reads conntrack state, so what is reported is that the
  /// question is unanswered, and not a guess at the answer.
  bool bundle_predates_tracker = false;
  /// The interfaces the tracker was attached to, by name and by index.
  /// Reported because "enabled" on its own repeats the mistake of
  /// counting programs instead of attachments.
  std::vector<std::string> interfaces;
  std::vector<int> ifindexes;
  /// The loaded tracker's program id, so the live query below asks
  /// about this daemon's filter and not about whatever sits in the
  /// slot.
  uint32_t prog_id = 0;

  /// Refusals already reported, so each new batch is logged once.
  uint64_t reported_refusals = 0;

  auto GetState() const -> nlohmann::json override;
  auto SetState(const nlohmann::json& j) -> bool override;

  /// Sum one `fwl_egress_stats` slot across every CPU.
  auto Stat(FwlEgressStat slot) const -> uint64_t;

  /// How many of `ifindexes` carry the filter RIGHT NOW, asked of the
  /// kernel rather than remembered from the load. `fctl status`'s
  /// `xdp_attached` is a live query for the same reason: a hook removed
  /// out of band must show as removed, or the status line is
  /// bookkeeping being reported as a measurement.
  auto AttachedNow() const -> uint32_t;

  /// Turn a moved `refused` count into a log line. Called from the
  /// engine's periodic sweep, beside RouteMgr::Report.
  auto Report() -> void;
};

}  // namespace f

#endif  // INCLUDE_F_EGRESS_MGR_H_
