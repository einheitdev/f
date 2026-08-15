/// @file route_mgr.cc
/// @brief Reporting for the datapath's routed/bridged forward tally.

#include "f/route_mgr.h"

#include <filesystem>
#include <format>
#include <fstream>
#include <string>
#include <string_view>
#include <system_error>
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

auto RouteMgr::WriteForwarding(bool on) const
    -> std::expected<void, std::string> {
  std::string path = proc_dir + "/net/ipv4/ip_forward";
  // A no-op against a real /proc/sys. It is here so `proc_dir` is a
  // seam a test can point at a temp tree — the whole reason this knob
  // was previously written by a component with no test seam is how it
  // came to be written unconditionally.
  std::error_code ec;
  std::filesystem::create_directories(
      std::filesystem::path(path).parent_path(), ec);
  std::ofstream out(path, std::ios::trunc);
  if (!out) {
    return std::unexpected(
        std::format("cannot open {} for writing", path));
  }
  out << (on ? "1" : "0") << "\n";
  out.close();
  if (!out) {
    return std::unexpected(std::format("write to {} failed", path));
  }
  return {};
}

auto RouteMgr::SetForwarding(bool on, std::string_view why) -> void {
  desired_forwarding = on;
  forwarding_reason = std::string(why);
  bool was = Forwarding();
  auto wrote = WriteForwarding(on);
  if (!wrote) {
    // Refusing to forward is the safe half of this and refusing to
    // STOP forwarding is not, so the two failures are not the same
    // event and are not logged as one.
    if (on) {
      spdlog::error(
          "forwarding: could not raise net.ipv4.ip_forward ({}). The "
          "datapath is armed but this box will not route between "
          "zones.",
          wrote.error());
      forwarding_reason = std::format(
          "COULD NOT RAISE net.ipv4.ip_forward: {}", wrote.error());
    } else {
      spdlog::critical(
          "forwarding: could not lower net.ipv4.ip_forward ({}). This "
          "box may still be FORWARDING WITHOUT FILTERING. Set it by "
          "hand: sysctl -w net.ipv4.ip_forward=0",
          wrote.error());
      forwarding_reason = std::format(
          "COULD NOT LOWER net.ipv4.ip_forward: {}", wrote.error());
    }
    return;
  }
  if (was == on) return;
  if (on) {
    spdlog::info(
        "forwarding: net.ipv4.ip_forward 0 -> 1 ({}).", why);
  } else {
    // Not a warning. A box that has stopped forwarding is a visible
    // fault by design, and this line is the thing that makes it
    // visible — the operator's alternative is a silence that looks
    // exactly like a cable problem.
    spdlog::error(
        "forwarding: net.ipv4.ip_forward 1 -> 0 ({}). This box is NOT "
        "routing between zones. It fails CLOSED: f not filtering must "
        "not mean traffic forwarded unfiltered.",
        why);
  }
}

auto RouteMgr::MaybeReassertForwarding(uint64_t now_ns) -> void {
  if (last_forwarding_check_ns != 0 &&
      now_ns - last_forwarding_check_ns <
          forwarding_recheck_s * 1000000000ULL) {
    return;
  }
  last_forwarding_check_ns = now_ns;
  bool live = Forwarding();
  if (live == desired_forwarding) {
    forwarding_overridden = false;
    return;
  }

  if (live && !desired_forwarding) {
    // The unsafe direction, and the only one this daemon corrects.
    // Something raised the knob on a box whose datapath is not armed,
    // which is the entire finding this fail-closed work exists for:
    // an unfiltered router that looks like a firewall.
    forwarding_corrections++;
    spdlog::error(
        "forwarding: net.ipv4.ip_forward was raised to 1 by something "
        "other than fd while the datapath is NOT armed ({}). Putting "
        "it back to 0 — this box must not forward what it is not "
        "filtering. Correction #{}; look for another sysctl drop-in.",
        forwarding_reason, forwarding_corrections);
    auto wrote = WriteForwarding(false);
    if (!wrote) {
      spdlog::critical("forwarding: re-assert failed: {}",
                       wrote.error());
    }
    return;
  }

  // The safe direction, and it is REPORTED rather than fought.
  //
  // fd wants forwarding and something turned it off. Writing it back
  // would make this daemon un-overridable — an operator (or a test's
  // own control, which is how several hardware scenarios prove frames
  // reached the wire and no socket took them) could not hold the box
  // non-routing while fd runs. So it stands, and the ONLY thing that
  // matters is that it is not silent: the original objection to
  // deriving this knob was never "the box might not route", it was
  // "the box might not route and nothing says why". This says why,
  // once per occurrence, and `fctl status` carries it continuously.
  if (!forwarding_overridden) {
    forwarding_overridden = true;
    spdlog::error(
        "forwarding: this daemon raised net.ipv4.ip_forward when the "
        "datapath came up and something has since set it to 0. The "
        "datapath is armed and filtering, and this box is NOT routing "
        "between zones: every redirect leaves carrying the MAC it "
        "arrived with and the far side drops it. fd does not override "
        "this — restore it with `sysctl -w net.ipv4.ip_forward=1`, or "
        "find what set it to 0.");
  }
}

auto RouteMgr::GetState() const -> nlohmann::json {
  return {
      {"enabled", enabled},
      {"ip_forward", Forwarding()},
      // The live knob above answers "is this box routing"; these three
      // answer "and is that what the firewall decided". They differ
      // for exactly as long as it takes the sweep to notice, and an
      // operator staring at a box that has stopped passing traffic
      // needs the reason more than the bit.
      {"forwarding_desired", desired_forwarding},
      {"forwarding_reason", forwarding_reason},
      {"forwarding_corrections", forwarding_corrections},
      {"forwarding_overridden", forwarding_overridden},
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
