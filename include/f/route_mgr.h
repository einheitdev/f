/// @file route_mgr.h
/// @brief What a `redirect to <zone>` actually did to each frame.

#ifndef INCLUDE_F_ROUTE_MGR_H_
#define INCLUDE_F_ROUTE_MGR_H_

#include <cstdint>
#include <expected>
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
///
/// ## And who decides whether this kernel forwards at all
///
/// This component also OWNS `net.ipv4.ip_forward` rather than merely
/// reading it, and that is a reversal of an earlier decision recorded
/// in `sysconfig/sysctl.h`. The invariant it now keeps is one line:
///
///   **the kernel forwards if and only if this daemon has a bundle in
///   the packet path on at least one interface.**
///
/// It is not derived from the policy — not from the zone count, not
/// from whether any zone redirects. That derivation was rejected, and
/// is still rejected, because a box can be silently non-routing for a
/// reason nobody can see in the source. What replaced it is a FACT the
/// daemon establishes rather than infers: the attach either happened
/// or it did not, and `e.ifaces.count` is the kernel's own answer.
///
/// The periodic check is ASYMMETRIC, and that asymmetry is the whole
/// answer to the objection the old unconditional setting was raised
/// against. A knob found at 1 on an unarmed box is put back to 0 —
/// that is the unfiltered router, and nothing may hold it open. A knob
/// found at 0 on an ARMED box is left exactly where it is and REPORTED
/// — loudly, in the journal and in every `fctl status` from then on.
///
/// Writing that one back too would read as symmetry and would be
/// wrong twice over: it would make the daemon un-overridable by the
/// operator whose box it is, and it would break the controls in the
/// hardware scenarios, several of which prove "these frames were on
/// the wire and no socket took one" precisely by holding forwarding
/// down under a running fd. The original objection to deriving this
/// knob was never "the box might not route"; it was "the box might
/// not route and nothing anywhere says why". A box that does not
/// forward is a visible fault — so make it visible, and do not make
/// it unreachable.
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

  // There is no `CheckForwarding(policy_redirects)` any more. It read
  // the knob at load time and told the operator to run `f-sysconf
  // apply` if it was 0 — advice that is now wrong in both halves.
  // Nobody but this daemon sets the live value, and at the moment it
  // used to be called the value is ALWAYS 0, because fd lowers it on
  // the way in and does not raise it until the attach has succeeded.
  // Kept as a comment rather than deleted silently: the old rationale
  // is quoted in half a dozen places and this is where it stops being
  // true.

  /// What this daemon has decided the knob should be. False until a
  /// bundle is attached to at least one interface, and false again the
  /// moment one is not — including while `fd` is still starting up.
  bool desired_forwarding = false;

  /// Why it is where it is, in words an operator can act on. Carried
  /// into `fctl status` so that a box which has stopped forwarding
  /// SAYS SO rather than merely stopping.
  std::string forwarding_reason =
      "fd has not armed the datapath yet";

  /// How many times this daemon has had to put the knob back DOWN.
  /// Nonzero means something else on the box raised it while nothing
  /// was filtering.
  uint64_t forwarding_corrections = 0;

  /// True while the live knob is 0 and this daemon wants 1: forwarding
  /// was turned off behind fd's back and fd is not fighting it. The
  /// one state in which a healthy, filtering box passes nothing.
  bool forwarding_overridden = false;

  /// Steady-clock ns of the last re-assert check. 0 = never.
  uint64_t last_forwarding_check_ns = 0;

  /// How often the knob is re-read and put back. Short enough that a
  /// box does not sit non-routing for long, long enough to be free.
  uint64_t forwarding_recheck_s = 5;

  /// Decide the knob and write it. `why` is kept for reporting whether
  /// or not the write was needed, so the status line explains a state
  /// this daemon merely agrees with as well as one it just caused.
  auto SetForwarding(bool on, std::string_view why) -> void;

  /// Check the live knob against the decision, correct it downward,
  /// and report an upward override. Called from the engine's periodic
  /// sweep; rate-limited to `forwarding_recheck_s`.
  auto MaybeReassertForwarding(uint64_t now_ns) -> void;

  /// The raw write. Separate so a test can point `proc_dir` at a temp
  /// tree and so the failure has one place to be reported from.
  auto WriteForwarding(bool on) const
      -> std::expected<void, std::string>;

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
