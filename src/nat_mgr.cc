/// @file nat_mgr.cc
/// @brief NAT reply-mapping occupancy, reclamation and reporting.

#include "f/nat_mgr.h"

#include <cstring>
#include <vector>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <spdlog/spdlog.h>
#include <unistd.h>

namespace f {

namespace {

/// Number of possible CPUs, for reading a per-CPU array. libbpf's
/// helper is the authority; a wrong value reads a short buffer and
/// under-counts silently, which is exactly the class of failure this
/// whole component exists to end.
auto NumPossibleCpus() -> int {
  static const int n = [] {
    int v = libbpf_num_possible_cpus();
    return v > 0 ? v : 1;
  }();
  return n;
}

}  // namespace

auto NatMgr::Anchor(const FwlNatKey& k) -> ConnKey {
  // The mapping key is the REPLY direction; the conntrack entry the
  // datapath inserts is the post-NAT FORWARD direction. One is the
  // other with both endpoints swapped — addresses and ports together.
  ConnKey c{};
  c.src_addr = k.dst_addr;
  c.dst_addr = k.src_addr;
  c.src_port = k.dst_port;
  c.dst_port = k.src_port;
  c.proto = k.proto;
  return c;
}

auto NatMgr::Entries() const -> uint32_t {
  if (map_fd < 0) return 0;
  uint32_t n = 0;
  FwlNatKey key{}, next{};
  while (bpf_map_get_next_key(map_fd, &key, &next) == 0) {
    n++;
    key = next;
  }
  return n;
}

auto NatMgr::Stat(FwlNatStat slot) const -> uint64_t {
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

auto NatMgr::GetState() const -> nlohmann::json {
  uint32_t entries = Entries();
  uint32_t pct = max_entries > 0
                     ? static_cast<uint32_t>(
                           (static_cast<uint64_t>(entries) * 100) /
                           max_entries)
                     : 0;
  uint64_t refused = Stat(kFwlNatStatRefused);
  return {
      {"enabled", enabled},
      {"entries", entries},
      {"max_entries", max_entries},
      {"occupancy_pct", pct},
      {"high_water", high_water > entries ? high_water : entries},
      {"grace_s", grace_s},
      {"total_reclaimed", total_reclaimed},
      // The datapath's own tally. `refused` is the one that means a
      // packet was dropped rather than misdelivered; `table_full` says
      // the refusal was the cap rather than a port collision the
      // fallback could not resolve.
      {"installed", Stat(kFwlNatStatInstalled)},
      {"port_reallocated", Stat(kFwlNatStatRealloc)},
      {"refused", refused},
      {"table_full", Stat(kFwlNatStatTableFull)},
      {"denat", Stat(kFwlNatStatDenat)},
  };
}

auto NatMgr::SetState(const nlohmann::json& j) -> bool {
  if (j.contains("grace_s")) {
    grace_s = j["grace_s"].get<uint32_t>();
  }
  if (j.contains("warn_pct")) {
    warn_pct = j["warn_pct"].get<uint32_t>();
  }
  return true;
}

auto NatMgr::RunGc(uint64_t now_ns) -> uint32_t {
  if (map_fd < 0 || !enabled) return 0;
  uint64_t grace_ns =
      static_cast<uint64_t>(grace_s) * 1'000'000'000ULL;

  FwlNatKey key{}, next{};
  FwlNatValue val{};
  std::vector<FwlNatKey> dead;
  uint32_t live = 0;
  while (bpf_map_get_next_key(map_fd, &key, &next) == 0) {
    key = next;
    live++;
    if (bpf_map_lookup_elem(map_fd, &next, &val) != 0) continue;
    // Condition 1: the flow is over. Conntrack is the only authority
    // on that, and its own GC has already run this tick.
    if (conntrack_fd >= 0) {
      ConnKey anchor = Anchor(next);
      ConnValue cv{};
      if (bpf_map_lookup_elem(conntrack_fd, &anchor, &cv) == 0) {
        continue;  // still anchored: the flow is alive
      }
    }
    // Condition 2: and the mapping itself has gone quiet. This is what
    // makes "free when the flow ends" safe in the one case where the
    // anchor lies — a conntrack table at its own cap silently refuses
    // the insert, and the mapping would otherwise be reclaimed out
    // from under traffic that is still flowing.
    if (now_ns <= val.last_seen_ns ||
        now_ns - val.last_seen_ns < grace_ns) {
      continue;
    }
    dead.push_back(next);
  }

  uint32_t freed = 0;
  for (const auto& k : dead) {
    if (bpf_map_delete_elem(map_fd, &k) == 0) freed++;
  }
  total_reclaimed += freed;
  if (live > high_water) high_water = live;
  return freed;
}

auto NatMgr::MaybeRunGc(uint64_t now_ns, uint32_t gc_interval_s)
    -> uint32_t {
  if (!enabled || gc_interval_s == 0) return 0;
  uint64_t interval_ns =
      static_cast<uint64_t>(gc_interval_s) * 1'000'000'000ULL;
  if (last_gc_ns != 0 && now_ns - last_gc_ns < interval_ns) {
    return 0;
  }
  last_gc_ns = now_ns;
  uint32_t freed = RunGc(now_ns);

  // --- the loud half ------------------------------------------------
  // Every one of this table's failures used to be silent, which is why
  // they survived a 48 h soak, a NAT soak and 1434 corpus cases. A
  // refusal means a packet was DROPPED to avoid misdelivering somebody
  // else's traffic; it is never routine and it is always logged.
  uint64_t refused = Stat(kFwlNatStatRefused);
  if (refused > reported_refusals) {
    uint64_t full = Stat(kFwlNatStatTableFull);
    spdlog::error(
        "NAT: refused {} mapping(s) since the last sweep — those "
        "packets were DROPPED. {} of {} total refusals were the "
        "{}-entry fwl_nat table being FULL; the rest were source-port "
        "collisions no free port in 49152-65535 could resolve. New "
        "connections through the NAT are failing.",
        refused - reported_refusals, full, refused, max_entries);
    reported_refusals = refused;
  }

  uint32_t entries = Entries();
  if (entries > high_water) high_water = entries;
  uint32_t pct = max_entries > 0
                     ? static_cast<uint32_t>(
                           (static_cast<uint64_t>(entries) * 100) /
                           max_entries)
                     : 0;
  if (pct >= warn_pct && pct > warned_at_pct) {
    spdlog::warn(
        "NAT: fwl_nat is {}% full ({} of {} mappings). Reclaimed {} "
        "this sweep, {} in total. At 100% new connections are refused "
        "and dropped, not queued.",
        pct, entries, max_entries, freed, total_reclaimed);
    warned_at_pct = pct;
  } else if (pct + 10 < warned_at_pct) {
    // Fell well back below the last warning: re-arm, so the next climb
    // is reported instead of being swallowed as "already warned".
    spdlog::info("NAT: fwl_nat back down to {}% ({} mappings).", pct,
                 entries);
    warned_at_pct = 0;
  }
  if (freed > 0) {
    spdlog::debug("NAT gc: reclaimed {} mapping(s), {} live.", freed,
                  entries);
  }
  return freed;
}

}  // namespace f
