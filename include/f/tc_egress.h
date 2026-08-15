/// @file tc_egress.h
/// @brief The TC clsact egress hook that tracks flows the box starts.

#ifndef INCLUDE_F_TC_EGRESS_H_
#define INCLUDE_F_TC_EGRESS_H_

#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <vector>

#include "f/bpf_error.h"
#include "f/error.h"

struct bpf_object;

namespace f {

/// One interface the egress tracker is to be attached to. Carried with
/// its name because every message this file can produce has to say
/// which interface it is about, and an ifindex is not that.
struct EgressTarget {
  int ifindex = 0;
  std::string name;
};

/// A loaded and attached egress tracker.
///
/// ## Why a second attach point exists at all
///
/// XDP conntrack only ever sees INGRESS. A flow the box itself
/// originates — the DNS query its forwarder sends upstream, the NTP
/// exchange that sets its clock, the update it fetches — leaves through
/// the local stack, which no XDP program is attached to, so no
/// conntrack entry is created. The reply arrives on the WAN port, reads
/// NEW, and `default drop` eats it. Measured on the rig before this
/// existed (tests/system/hw/l12_01_box_originated_flows.sh): 5 requests
/// out of the box's own WAN address, 5 replies at the port by datapath
/// counter, 0 survived, conntrack 0 -> 0. A firewall that cannot
/// resolve a name or set its own clock is not deployable.
///
/// ## Why the qdisc layer, measured rather than argued
///
/// The clsact egress hook saw 5/5 of what the local stack sent and 0 of
/// 13 frames the XDP datapath forwarded out the same port, because
/// `bpf_redirect_map()` leaves through `ndo_xdp_xmit`, below the qdisc
/// layer entirely. So it covers precisely the gap and costs the
/// forwarding fast path nothing — it cannot even see it.
///
/// The neater-looking alternative, `bpf_sk_lookup_udp()` from XDP (no
/// second copy of the state at all), is refuted by measurement on the
/// same bench: it can only tell a reply from an unsolicited arrival
/// when the socket carries a peer, and dnsmasq's upstream sockets are
/// unconnected 2/2. Admitting on an unconnected match would open every
/// bound port to the WAN.
struct EgressTracker {
  /// The loaded object, owned here and closed by CloseEgressTracker.
  ::bpf_object* obj = nullptr;
  int prog_fd = -1;
  /// The kernel id of the loaded program, so "is our filter still on
  /// this interface" is a question about OUR program and not about
  /// whatever occupies the slot.
  uint32_t prog_id = 0;
  /// `fwl_egress_stats` — the hook's own per-CPU tally. Read by
  /// EgressMgr for `fctl status` and for the log line that fires when
  /// an insert is refused.
  int stats_fd = -1;
  /// The interfaces the filter is actually on. This is the number that
  /// answers "is box-originated tracking in the path"; the fact that an
  /// object loaded answers nothing about it.
  std::vector<int> ifindexes;
  std::vector<std::string> interfaces;
  /// Interfaces whose clsact qdisc this daemon created, and therefore
  /// the only ones it may destroy. Removing a qdisc somebody else put
  /// there would take their ingress filter with it.
  ///
  /// Known residual, recorded rather than papered over: after `fd` is
  /// killed and restarted, the qdisc it made in a previous life is
  /// already there, `bpf_tc_hook_create` answers -EEXIST, and this
  /// process cannot tell it from one the operator made. It therefore
  /// does not claim it, and a `systemctl stop` after such a restart
  /// leaves an empty clsact behind. That is the deliberate direction to
  /// be wrong in: an empty qdisc costs nothing, and destroying one we
  /// did not create would silently remove somebody's ingress filter.
  std::vector<int> created_qdisc;

  /// True when a tracker is loaded and attached somewhere.
  auto Attached() const -> bool { return !ifindexes.empty(); }
};

/// The egress object the bundle at `bundle_dir` declares, as an
/// absolute path, or the empty string when it declares none.
///
/// A bundle whose policy never reads `conntrack(pkt).state` has no
/// conntrack map to write into and therefore no tracker; so does any
/// bundle compiled before the tracker existed. The two are different
/// situations and BundleDeclaresEgressTracker separates them.
auto BundleEgressObject(std::string_view bundle_dir) -> std::string;

/// True when the manifest carries an `egress_tracker` entry at all —
/// i.e. was compiled by an `fwl` that knows about the hook.
///
/// The distinction matters on upgrade: an `fd` with this code and a
/// bundle without the field must not silently behave like a box that
/// has egress tracking. It has to say that flows it originates are
/// untracked and that recompiling the policy is the fix.
auto BundleDeclaresEgressTracker(std::string_view bundle_dir) -> bool;

/// True when the manifest carries an `egress_tracker` key AT ALL,
/// including the explicit `null` a policy that needs no tracker gets.
///
/// This is the only question an old manifest cannot answer, and it is
/// the one that decides whether to warn. `BundleDeclaresEgressTracker`
/// answers "does this bundle have a tracker"; this answers "was this
/// bundle compiled by an `fwl` that would have said so".
auto ManifestHasEgressField(std::string_view bundle_dir) -> bool;

/// The name of the program to attach, from the manifest, or the
/// built-in default for a manifest that does not name one.
auto BundleEgressProgram(std::string_view bundle_dir) -> std::string;

/// Load the bundle's egress tracker and attach it to every target.
///
/// `targets` is the set of interfaces the bundle's XDP programs were
/// attached to: exactly the ports on which a reply to a flow this box
/// originated would be judged, and therefore exactly the ports whose
/// egress has to be tracked.
///
/// Returns an error, never a half-attached tracker:
///
///  * a bundle that declares a tracker whose object failed to compile
///    (`"object": null`) is refused, for the same reason a zone program
///    with no object is;
///  * an attach that fails on ANY target is rolled back and refused.
///    Unlike a zone interface that may simply not exist on this host,
///    every one of these interfaces demonstrably does — XDP just
///    attached to it — so there is no benign reason for a strict
///    subset, and a strict subset is a box whose DNS works on one port
///    and not another;
///  * attaching to zero interfaces is an error whatever the reason. A
///    second attach point must never report success having attached to
///    nothing: that is the rule the XDP path gained after a load
///    reported "1 zone program(s)" while every packet on the box flowed
///    unfiltered, and a copy of the same defect one layer over would be
///    worse, not better, for being newer.
///
/// The attach is atomic per interface (`BPF_TC_F_REPLACE` on a fixed
/// handle/priority), so a hot reload never leaves a window in which the
/// interface has no tracker — the same property ReplaceXdp gives the
/// datapath.
///
/// `previous` is the tracker being replaced on a hot reload, or nullptr
/// on a cold boot. It is consulted for ONE thing: which clsact qdiscs
/// this daemon created. `bpf_tc_hook_create` answers -EEXIST for a
/// qdisc that is already there, which on a reload is always — so
/// without carrying ownership forward, a box that had reloaded once
/// would leave an orphan clsact behind at `systemctl stop` while a box
/// that had not would clean up. Two different end states from the same
/// command, decided by history, is the shape of l8_05.
auto AttachEgressTracker(std::string_view bundle_dir,
                         std::string_view pin_root,
                         const std::vector<EgressTarget>& targets,
                         const EgressTracker* previous = nullptr)
    -> std::expected<EgressTracker, Error<BpfError>>;

/// Remove the filter from every interface in `t`, and the clsact qdisc
/// from those this daemon created it on. Leaves `t`'s object open.
auto DetachEgressTracker(const EgressTracker& t) -> void;

/// Remove this daemon's egress filter from one interface. Used by the
/// reload path for an interface the previous bundle covered and the new
/// one does not — the exact analogue of its DetachXdp call, and missing
/// it would leave a tracker running with no bundle behind it.
auto DetachEgressOn(int ifindex) -> void;

/// Remove this daemon's egress filter from `ifindex`, and destroy the
/// clsact qdisc as well when `owned` says this daemon created it.
///
/// The reload path needs the second half: an interface the previous
/// bundle covered and the new one does not never re-enters the new
/// tracker's `created_qdisc`, so removing only the filter orphaned a
/// qdisc this daemon made — and the next boot then sees -EEXIST and
/// disowns it for good.
auto RemoveEgressFrom(int ifindex, const EgressTracker& owner) -> void;

/// True when THIS daemon's egress filter is on `ifindex` right now,
/// asked of the kernel.
///
/// The daemon's own record of what it attached is not an answer to
/// this: a filter can be removed out of band, and a status line built
/// from load-time bookkeeping would keep reporting a hook that is not
/// there. `fctl status`'s `xdp_attached` is a live query for exactly
/// the same reason, and the two must not be different kinds of claim.
/// `prog_id` is the loaded tracker's kernel id; pass 0 to ask only
/// whether the slot is occupied by anything at all, which is what the
/// "is there a stale filter to clean up" question needs.
auto EgressFilterPresent(int ifindex, uint32_t prog_id = 0) -> bool;

/// Close the object an AttachEgressTracker call opened. Detaches
/// nothing: on a hot reload the new tracker has already replaced the
/// old filter in place, and detaching here would tear down the new one.
auto CloseEgressTracker(EgressTracker& t) -> void;

}  // namespace f

#endif  // INCLUDE_F_TC_EGRESS_H_
