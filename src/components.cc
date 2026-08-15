/// @file components.cc
/// @brief Component GetState/SetState implementations.

#include "f/conntrack_mgr.h"
#include "f/iface_mgr.h"

#include <arpa/inet.h>
#include <cstring>
#include <vector>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

namespace f {

// ============================================================
// IfaceMgr
// ============================================================

namespace {

/// True when the kernel currently has an XDP program on `ifindex`.
///
/// This used to be reported as the literal `true` for every tracked
/// interface, which made `fctl status` structurally incapable of
/// reporting a disarmed firewall: after an external detach (another
/// tool, `ip link set xdp off`, an interface replaced underneath us)
/// the daemon still claimed every interface was attached while
/// traffic passed unfiltered. Verified on hardware —
/// tests/system/hw/l8_03_attach_truth.sh saw 50/50 previously
/// dropped frames leak while status reported attached.
///
/// Asking the kernel costs one netlink round-trip per interface on a
/// status call, which is the right trade for a field whose entire
/// purpose is to answer "is the firewall actually on".
auto XdpAttached(int ifindex) -> bool {
  __u32 prog_id = 0;
  if (bpf_xdp_query_id(ifindex, 0, &prog_id) != 0) {
    return false;
  }
  return prog_id != 0;
}

}  // namespace

auto IfaceMgr::GetState() const -> nlohmann::json {
  auto arr = nlohmann::json::array();
  for (uint32_t i = 0; i < count; i++) {
    arr.push_back({
        {"name", interfaces[i].name},
        {"ifindex", interfaces[i].ifindex},
        {"xdp_attached", XdpAttached(interfaces[i].ifindex)},
    });
  }
  return {{"interfaces", arr}, {"count", count}};
}

auto IfaceMgr::SetState(const nlohmann::json& j)
    -> bool {
  (void)j;
  return false;
}

// ============================================================
// ConntrackMgr
// ============================================================

auto ConntrackMgr::GetState() const -> nlohmann::json {
  uint32_t entries = 0;
  if (map_fd >= 0) {
    ConnKey key{}, next{};
    while (bpf_map_get_next_key(
               map_fd, &key, &next) == 0) {
      entries++;
      key = next;
    }
  }
  return {
      {"enabled", enabled},
      {"timeout_s", timeout_s},
      {"gc_interval_s", gc_interval_s},
      {"entries", entries},
      {"total_evicted", total_evicted},
  };
}

auto ConntrackMgr::SetState(const nlohmann::json& j)
    -> bool {
  if (j.contains("enabled")) {
    enabled = j["enabled"].get<bool>();
  }
  if (j.contains("timeout_s")) {
    timeout_s = j["timeout_s"].get<uint32_t>();
  }
  if (j.contains("gc_interval_s")) {
    gc_interval_s = j["gc_interval_s"].get<uint32_t>();
  }
  return true;
}

auto ConntrackMgr::RunGc(uint64_t now_ns) -> uint32_t {
  if (map_fd < 0 || !enabled || timeout_s == 0) {
    return 0;
  }
  uint64_t timeout_ns =
      static_cast<uint64_t>(timeout_s) * 1'000'000'000ULL;
  ConnKey key{}, next{};
  ConnValue val{};
  std::vector<ConnKey> stale;
  while (bpf_map_get_next_key(
             map_fd, &key, &next) == 0) {
    if (bpf_map_lookup_elem(
            map_fd, &next, &val) == 0) {
      if (now_ns > val.last_seen_ns &&
          now_ns - val.last_seen_ns > timeout_ns) {
        stale.push_back(next);
      }
    }
    key = next;
  }
  uint32_t evicted = 0;
  for (const auto& k : stale) {
    if (bpf_map_delete_elem(map_fd, &k) == 0) {
      evicted++;
    }
  }
  total_evicted += evicted;
  return evicted;
}

auto ConntrackMgr::MaybeRunGc(uint64_t now_ns)
    -> uint32_t {
  if (!enabled || gc_interval_s == 0) {
    return 0;
  }
  uint64_t interval_ns =
      static_cast<uint64_t>(gc_interval_s) * 1'000'000'000ULL;
  if (last_gc_ns != 0 &&
      now_ns - last_gc_ns < interval_ns) {
    return 0;
  }
  last_gc_ns = now_ns;
  return RunGc(now_ns);
}

}  // namespace f
