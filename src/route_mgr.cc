/// @file route_mgr.cc
/// @brief Reporting for the datapath's routed/bridged forward tally.

#include "f/route_mgr.h"

#include <fstream>
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

auto RouteMgr::Stat(FwlRouteStat slot) const -> uint64_t {
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

auto RouteMgr::Forwarding() const -> bool {
  std::ifstream in(proc_dir + "/net/ipv4/ip_forward");
  std::string value;
  if (in) std::getline(in, value);
  // An unreadable knob is not the same as a knob set to 0, and for
  // this question it has to fail the same way: "I could not look" must
  // never be reported as "forwarding is on".
  return value == "1";
}

auto RouteMgr::CheckForwarding(bool policy_redirects) -> void {
  if (!policy_redirects || Forwarding()) return;
  // Not a warning. This policy forwards packets between zones and this
  // kernel will not route them, so every forward leaves carrying the
  // destination MAC it arrived with and the far side drops it. The
  // symptom is "the firewall passes nothing" with every FWL counter
  // climbing, which is why it has to be said here rather than inferred
  // from a capture.
  spdlog::error(
      "route: this policy redirects between zones but "
      "net.ipv4.ip_forward is 0, so no next hop can be resolved and "
      "every forwarded frame keeps the destination MAC it arrived "
      "with. Run `einheit-f apply system` (or `f-sysconf apply`) to "
      "install and apply the forwarding drop-in.");
}

auto RouteMgr::GetState() const -> nlohmann::json {
  return {
      {"enabled", enabled},
      {"ip_forward", Forwarding()},
      // The two that matter, and they are reported together because
      // either one alone is unreadable: 1000 routed / 0 bridged is a
      // gateway, 0 routed / 1000 bridged is a bridge, and a
      // masquerading policy showing the second is the black hole.
      {"routed", Stat(kFwlRouteStatRouted)},
      {"bridged", Stat(kFwlRouteStatBridged)},
      {"no_route", Stat(kFwlRouteStatNoRoute)},
      {"no_neigh", Stat(kFwlRouteStatNoNeigh)},
      {"ttl_expired", Stat(kFwlRouteStatTtl)},
      {"off_zone", Stat(kFwlRouteStatOffZone)},
  };
}

auto RouteMgr::SetState(const nlohmann::json&) -> bool { return true; }

auto RouteMgr::Report() -> void {
  if (!enabled) return;
  uint64_t no_route = Stat(kFwlRouteStatNoRoute);
  if (no_route > reported_no_route) {
    spdlog::error(
        "route: {} forwarded packet(s) dropped — this box's routing "
        "table says the destination is unreachable or blackholed. "
        "Check the default route on the redirect destination zone.",
        no_route - reported_no_route);
    reported_no_route = no_route;
  }
  uint64_t no_neigh = Stat(kFwlRouteStatNoNeigh);
  if (no_neigh > reported_no_neigh) {
    // Not a drop by us — the stack gets the packet and sends the ARP.
    // It is still worth a line, because for a SOURCE-TRANSLATED frame
    // the stack discards it as a martian source (its source is one of
    // our own addresses), so the resolution happens and that packet
    // does not survive it.
    spdlog::warn(
        "route: {} forwarded packet(s) had no neighbour entry for "
        "their next hop and went to the stack to be resolved. A "
        "translated packet does not survive that trip; if this keeps "
        "climbing, the next hop is not answering ARP.",
        no_neigh - reported_no_neigh);
    reported_no_neigh = no_neigh;
  }
}

}  // namespace f
