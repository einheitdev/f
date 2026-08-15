/// @file egress_mgr.cc
/// @brief Reporting for the egress conntrack tracker.

#include "f/egress_mgr.h"

#include "f/tc_egress.h"

#include <string>
#include <vector>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <spdlog/spdlog.h>

namespace f {

namespace {

/// Number of possible CPUs, for reading a per-CPU array. libbpf's
/// helper is the authority; a wrong value reads a short buffer and
/// under-counts silently.
auto NumPossibleCpus() -> int {
  static const int n = [] {
    int v = libbpf_num_possible_cpus();
    return v > 0 ? v : 1;
  }();
  return n;
}

}  // namespace

auto EgressMgr::Stat(FwlEgressStat slot) const -> uint64_t {
  if (stats_fd < 0) return 0;
  std::vector<uint64_t> per_cpu(
      static_cast<size_t>(NumPossibleCpus()), 0);
  uint32_t k = static_cast<uint32_t>(slot);
  if (bpf_map_lookup_elem(stats_fd, &k, per_cpu.data()) != 0) {
    return 0;
  }
  uint64_t total = 0;
  for (uint64_t v : per_cpu) total += v;
  return total;
}

auto EgressMgr::AttachedNow() const -> uint32_t {
  uint32_t n = 0;
  for (int idx : ifindexes) {
    if (EgressFilterPresent(idx, prog_id)) n++;
  }
  return n;
}

auto EgressMgr::GetState() const -> nlohmann::json {
  nlohmann::json j;
  j["enabled"] = enabled;
  j["interfaces"] = interfaces;
  // Live, not remembered. `interfaces` says what this daemon attached
  // to; `attached` says what the kernel has now. They differ exactly
  // when somebody removed the filter behind the daemon's back, and a
  // status line that could not show that difference would be the same
  // kind of claim as the "1 zone program(s)" line that was true of a
  // firewall attached to nothing.
  j["attached"] = AttachedNow();
  // Why it is off, when it is off. "enabled": false covers three
  // different boxes — one whose policy asks no conntrack question and
  // needs no tracker, one running a bundle compiled before the tracker
  // existed (whose own DNS its own policy may be dropping), and one
  // whose hook was removed behind the daemon's back. Reporting one flag
  // would make them indistinguishable from the CLI, which is the exact
  // shape of the defect this feature closes.
  j["tracker_declared"] = tracker_declared;
  j["bundle_predates_tracker"] = bundle_predates_tracker;
  j["seen"] = Stat(kFwlEgressStatSeen);
  j["not_local"] = Stat(kFwlEgressStatNotLocal);
  j["untracked"] = Stat(kFwlEgressStatUntracked);
  j["tracked"] = Stat(kFwlEgressStatTracked);
  j["refreshed"] = Stat(kFwlEgressStatRefreshed);
  j["refused"] = Stat(kFwlEgressStatRefused);
  return j;
}

auto EgressMgr::SetState(const nlohmann::json&) -> bool { return true; }

auto EgressMgr::Report() -> void {
  if (!enabled) return;
  uint64_t refused = Stat(kFwlEgressStatRefused);
  if (refused > reported_refusals) {
    spdlog::error(
        "egress: {} flow(s) this box originated could NOT be tracked — "
        "the conntrack table is at its cap. Their replies read NEW and "
        "this policy will drop them, so DNS forwarding, NTP and "
        "updates fail from here on with nothing else to show for it. "
        "Raise conntrack capacity or lower conntrack.timeout_s.",
        refused - reported_refusals);
    reported_refusals = refused;
  }
}

}  // namespace f
