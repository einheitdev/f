/// @file route_mgr.h
/// @brief What a `redirect to <zone>` actually did to each frame.

#ifndef INCLUDE_F_ROUTE_MGR_H_
#define INCLUDE_F_ROUTE_MGR_H_

#include <cstdint>
#include <string>

#include "f/component.h"
#include "f/types.h"

namespace f {

/// The datapath's routing tally, from the daemon's side.
///
/// ## Why this exists
///
/// `redirect to <zone>` used to be a bare `bpf_redirect_map()`: the
/// frame left the box carrying the destination MAC it arrived with.
/// For a zone hop on one L2 segment that is right. For a hop that
/// crosses a subnet — which is every masquerade, since translating the
/// source to your own address and then handing the frame to a MAC you
/// never addressed is not a coherent thing to do — it means the next
/// hop's NIC reports PACKET_OTHERHOST and its stack drops the frame
/// before any socket sees it.
///
/// The reason that survived 1822 unit cases, eleven `l11_*` hardware
/// scenarios and a NAT soak is that **no oracle ever required the far
/// side to accept anything.** Every masquerade witness was a
/// promiscuous AF_PACKET socket, which counts frames a real IP stack
/// discards. So the box's own view has to say which of the two
/// happened, because the wire cannot: `routed` versus `bridged` is the
/// whole difference between a working gateway and a silent one, and
/// both look identical in a capture.
///
/// A routed forward is only taken when the box's routing table
/// resolves the destination THROUGH THE ZONE THE POLICY NAMED. A box
/// with a default route resolves every destination, so without that
/// check a zone-to-zone hop on an unrouted segment would be stamped
/// with the default gateway's MAC — a different segment entirely.
/// `off_zone` counts exactly that near-miss.
struct RouteMgr : Component {
  /// `fwl_route_stats` — the datapath's per-CPU tally. -1 when the
  /// loaded policy contains no redirect at all.
  int stats_fd = -1;
  bool enabled = false;

  /// Counters already reported, so each new drop is logged once.
  uint64_t reported_no_route = 0;
  uint64_t reported_no_neigh = 0;

  /// Where the live kernel knobs are read from. Overridable so a test
  /// can point it at a temp tree.
  std::string proc_dir = "/proc/sys";

  /// `net.ipv4.ip_forward`, read fresh on every call. The datapath
  /// cannot route with this at 0 — `bpf_fib_lookup` answers
  /// FWD_DISABLED and resolves no next hop — so a policy that
  /// redirects and a kernel that does not forward is a firewall that
  /// quietly bridges everything, and the wire will not say it.
  ///
  /// Read live rather than cached at load, because it is a property of
  /// the running kernel and anyone with root can change it between two
  /// `fctl status` calls. A cached copy reports the box as it was when
  /// the policy loaded, which is the state an operator is least
  /// interested in. (Found by the hardware scenario, which turns it
  /// off as a control and expects the status line to follow.)
  auto Forwarding() const -> bool;

  /// Read `net.ipv4.ip_forward` and log about it when this policy can
  /// redirect. Called once per bundle load.
  auto CheckForwarding(bool policy_redirects) -> void;

  auto GetState() const -> nlohmann::json override;
  auto SetState(const nlohmann::json& j) -> bool override;

  /// Sum one `fwl_route_stats` slot across every CPU.
  auto Stat(FwlRouteStat slot) const -> uint64_t;

  /// Log the conditions that mean packets were lost or degraded, once
  /// per new occurrence. Called from the engine's periodic sweep.
  auto Report() -> void;
};

}  // namespace f

#endif  // INCLUDE_F_ROUTE_MGR_H_
