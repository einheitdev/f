/// @file components.cc
/// @brief Component GetState/SetState implementations.

#include "f/conntrack_mgr.h"
#include "f/iface_mgr.h"
#include "f/rule_table.h"

#include <arpa/inet.h>
#include <cstring>
#include <vector>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

namespace f {

namespace {

auto IpStr(uint32_t addr) -> std::string {
  if (addr == 0) return "*";
  char buf[INET_ADDRSTRLEN];
  struct in_addr in;
  in.s_addr = addr;
  inet_ntop(AF_INET, &in, buf, sizeof(buf));
  return buf;
}

auto ProtoStr(uint8_t p) -> std::string {
  switch (p) {
    case 6: return "tcp";
    case 17: return "udp";
    case 1: return "icmp";
    default: return "*";
  }
}

auto ActionStr(uint8_t a) -> std::string {
  switch (a) {
    case 0: return "drop";
    case 1: return "allow";
    case 2: return "rate_limit";
    default: return "?";
  }
}

}  // namespace

// ============================================================
// RuleTable
// ============================================================

auto RuleTable::GetState() const -> nlohmann::json {
  using json = nlohmann::json;
  json j;
  j["active_table"] = active_table == 0 ? "A" : "B";

  // Read rules from active table.
  int map_fd = active_table == 0
                   ? rules_a_fd : rules_b_fd;
  auto rules = json::array();
  if (map_fd >= 0) {
    RuleKey key{}, next{};
    RuleValue val{};
    while (bpf_map_get_next_key(
               map_fd, &key, &next) == 0) {
      if (bpf_map_lookup_elem(
              map_fd, &next, &val) == 0) {
        rules.push_back({
            {"src", IpStr(next.src_addr)},
            {"dst", IpStr(next.dst_addr)},
            {"src_port", next.src_port},
            {"dst_port", next.dst_port},
            {"proto", ProtoStr(next.proto)},
            {"action", ActionStr(val.action)},
        });
      }
      key = next;
    }
  }
  j["rules"] = rules;
  j["count"] = rules.size();

  // Read total counter (index 0).
  if (counters_fd >= 0) {
    int ncpus = libbpf_num_possible_cpus();
    if (ncpus < 1) ncpus = 1;
    std::vector<RuleCounter> pc(ncpus);
    uint32_t idx = 0;
    RuleCounter total{};
    if (bpf_map_lookup_elem(
            counters_fd, &idx, pc.data()) == 0) {
      for (int c = 0; c < ncpus; c++) {
        total.packets += pc[c].packets;
        total.bytes += pc[c].bytes;
      }
    }
    j["total_packets"] = total.packets;
    j["total_bytes"] = total.bytes;
  }

  return j;
}

auto RuleTable::SetState(const nlohmann::json& j)
    -> bool {
  // Could implement rule push via SetState in future.
  (void)j;
  return false;
}

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
