/// @file neigh_mgr.h
/// @brief Resolving the next hops a masquerading box cannot resolve.

#ifndef INCLUDE_F_NEIGH_MGR_H_
#define INCLUDE_F_NEIGH_MGR_H_

#include <cstdint>
#include <expected>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "f/component.h"

namespace f {

/// One next hop, exactly as the datapath recorded it: the egress
/// interface `bpf_fib_lookup` chose and the address it would have
/// needed a MAC for. Network byte order, because that is what came out
/// of the packet and out of the FIB.
struct NextHop {
  int ifindex = 0;
  uint32_t addr_be = 0;

  auto operator<=>(const NextHop&) const = default;
};

/// Dotted-quad for a network-order address. Reporting only.
auto NextHopAddrString(uint32_t addr_be) -> std::string;

/// What the kernel's neighbour table says about a next hop.
///
/// The three values are not a summary — they are the distinction that
/// makes the original finding legible. A box that had dropped seven
/// forwarded frames held NO entry of any state for its next hop, which
/// is `kAbsent`: not a resolution that failed, a resolution that was
/// never attempted. Telling that apart from `kIncomplete` is how this
/// daemon knows whether it is looking at its own defect or at a next
/// hop that is not answering ARP.
enum class NeighState : uint8_t {
  /// No entry at all. Nothing has asked for this address.
  kAbsent,
  /// An entry exists and is not usable — INCOMPLETE, FAILED, NONE.
  /// Something asked and has not been answered.
  kIncomplete,
  /// NUD_VALID: PERMANENT, NOARP, REACHABLE, PROBE, STALE or DELAY.
  /// The exact set `bpf_fib_lookup` accepts before it will return a
  /// dmac, so this value means "the datapath can route through it now"
  /// and not merely "there is a row in the table".
  kUsable,
};

/// The kernel's neighbour table, behind an interface.
///
/// Injected rather than called directly for the reason the rest of this
/// daemon separates its seams: the logic that decides WHEN to ask the
/// kernel to resolve something must be testable without root, and the
/// code that talks rtnetlink must be exercised against a real kernel
/// rather than against a mock that agrees with it. So the policy is
/// unit-tested here and the mechanism is measured in
/// `fwl/tests/system/cold_neighbour_netns.py`, which is the same split
/// `fail_closed_netns.py` uses for `/proc/sys`.
struct NeighKernel {
  virtual ~NeighKernel() = default;

  /// What the table holds for `nh` right now.
  virtual auto State(const NextHop& nh) -> NeighState = 0;

  /// Ask the kernel to resolve `nh`.
  ///
  /// This daemon sends NOTHING itself. The request is an rtnetlink
  /// RTM_NEWNEIGH carrying NTF_USE, which makes the kernel run
  /// `neigh_event_send()` on the entry — the same call a packet leaving
  /// through an unresolved next hop would make. The kernel then emits
  /// the ARP it would have emitted for that packet, under its own
  /// `ucast_solicit` / `mcast_solicit` / `retrans_time_ms` limits, and
  /// nothing here can outrun them.
  ///
  /// That is deliberate and it is the whole argument for this being an
  /// acceptable thing for a firewall daemon to do. The alternative
  /// shape — originate a UDP datagram at the next hop so the stack ARPs
  /// on the way out — puts an IP packet of the daemon's own invention
  /// on a customer's wire, has to choose a port and a payload, and is
  /// indistinguishable at the far end from a scan.
  virtual auto Solicit(const NextHop& nh)
      -> std::expected<void, std::string> = 0;
};

/// The `fwl_neigh_wanted` map the datapath writes, behind an interface.
///
/// Same reason as `NeighKernel`: a unit test cannot create a BPF map
/// without privilege, and a manager that could only be tested with root
/// would not be tested.
struct NeighWanted {
  virtual ~NeighWanted() = default;

  /// Every next hop the datapath has recorded, with the CLOCK_MONOTONIC
  /// nanoseconds at which it last wanted it (`bpf_ktime_get_ns`).
  virtual auto Entries()
      -> std::vector<std::pair<NextHop, uint64_t>> = 0;

  /// Drop one entry. Called when the next hop resolved, when it went
  /// stale, and when it names an interface the datapath is not on.
  virtual auto Forget(const NextHop& nh) -> void = 0;
};

/// Build the rtnetlink-backed neighbour table accessor.
auto MakeNetlinkNeighKernel() -> std::unique_ptr<NeighKernel>;

/// Build the accessor for a live `fwl_neigh_wanted` map fd. The fd
/// stays owned by the bundle handles; this does not close it.
auto MakeBpfNeighWanted(int map_fd) -> std::unique_ptr<NeighWanted>;

/// Makes a masquerading box able to resolve its own next hop.
///
/// ## The finding
///
/// A box that masquerades cannot resolve a next hop from the traffic it
/// forwards, at all. `bpf_fib_lookup` answers NO_NEIGH, the datapath
/// hands the frame to the stack precisely so the stack will ARP for it,
/// and the stack does not: the source has already been translated to
/// one of this box's own addresses and `fib_validate_source` discards
/// the frame as a martian before anything asks for a neighbour. So no
/// ARP is sent, the table stays empty, and the next frame meets the
/// same empty table. Measured under qemu on 2026-08-15, twice: seven
/// forwarded frames across a TCP client's whole retry window, `routed`
/// 0, nothing on the far wire, and afterwards no neighbour entry of any
/// state for that next hop.
///
/// A reboot empties the neighbour table. So a masquerading appliance
/// comes back from a power cut with every field reading healthy and
/// carries nothing, until something the box ITSELF originates happens
/// to go the same way. On the office box chrony or dnsmasq would
/// probably do it by accident — and failing closed makes that luck less
/// likely rather than more, because a box that is not forwarding is
/// also not answering the queries that would have resolved the hop.
///
/// ## Why this shape and not the other one
///
/// The alternative was for `fd` to resolve every next hop it can
/// enumerate from the routing table the moment it arms the datapath.
/// That is simpler and it does not work here: it can only reach next
/// hops a route NAMES, which means gateways. In the topology the defect
/// was actually measured in — and in every one-segment office, and in
/// both netns benches in this tree — the destination is on-link and its
/// next hop is the destination itself, which no routing table
/// enumerates and no daemon can guess without ARP-scanning a subnet.
/// A fix that cannot go green on the bench that produced the finding is
/// not a fix.
///
/// What this does instead is take the answer the datapath already has.
/// `bpf_fib_lookup` has resolved the route by the time it reports
/// NO_NEIGH — the next hop is in `fib.ipv4_dst` and the egress device
/// in `fib.ifindex` — so the datapath records the pair and this drains
/// it. Demand-driven, and therefore complete: it reaches an on-link
/// destination and a gateway by the same path, because the FIB does not
/// distinguish them at this point.
///
/// The cost is that the FIRST frame is still lost. That is honest and
/// it is why `no_neigh` still counts and `Report()` still fires — the
/// symptom becomes rare, not invisible. What the client sees is one
/// dropped SYN and a retransmit that crosses.
///
/// ## What bounds it
///
/// This component makes the daemon a thing that puts frames on a
/// customer's wire, which needs a bound that can be stated rather than
/// hoped for. Three, and each is enforced somewhere a reader can check:
///
///   1. **The address set.** Only what the datapath recorded, and the
///      datapath records only a next hop out of the interface the
///      policy's own `redirect` named (`fwl_route_l2`, the same test
///      `off_zone` makes one branch down). So an address can only be
///      solicited if a loaded policy routes to it.
///   2. **The interface set.** `datapath_ifindexes` is `e.ifaces` — the
///      interfaces the KERNEL accepted an XDP program on, the same fact
///      `ip_forward` is derived from. An entry naming anything else is
///      dropped and reported, never solicited. This is what keeps the
///      management port out of it on a box where something has gone
///      wrong upstream of here, rather than by argument.
///   3. **The rate.** One solicitation per next hop per
///      `solicit_interval_s`, from this side; the kernel's own ARP
///      retransmit limits on the other. And the map is capped at 64
///      entries by the emitter, so the worst case is a fixed number.
///
/// A next hop that has not been re-recorded by the datapath for
/// `stale_after_s` is forgotten. Otherwise a gateway that was replaced
/// would be solicited for the life of the process by a box that has
/// stopped routing to it.
struct NeighMgr : Component {
  /// The datapath's queue, and the kernel. Null until a bundle that can
  /// redirect is attached; `enabled` is the readable form of that.
  std::unique_ptr<NeighWanted> wanted;
  std::unique_ptr<NeighKernel> kernel;
  bool enabled = false;

  /// The interfaces the datapath is attached to. Nothing outside this
  /// set is ever solicited — see bound (2) above.
  std::vector<int> datapath_ifindexes;

  /// How often the queue is drained. Short, because the thing waiting
  /// on it is a TCP client's first retransmit: a drain interval longer
  /// than about a second turns "one lost SYN" into "the connection
  /// timed out", which is the symptom this exists to remove.
  uint64_t drain_interval_ms = 200;

  /// How often ONE next hop may be solicited. The kernel throttles
  /// anyway — `neigh_event_send` on an entry that is already probing
  /// does nothing — but a bound that depends on the kernel's internals
  /// is not a bound this file can state.
  uint64_t solicit_interval_s = 1;

  /// How long a next hop the datapath has stopped asking for is kept.
  uint64_t stale_after_s = 60;

  uint64_t last_drain_ns = 0;

  /// Tallies, all reported. `solicited` is how many times this daemon
  /// asked; `resolved` is how many next hops went from unresolved to
  /// usable while it was asking; `failed` is netlink refusing;
  /// `off_datapath` is bound (2) firing, which should be unreachable.
  uint64_t solicited = 0;
  uint64_t resolved = 0;
  uint64_t failed = 0;
  uint64_t off_datapath = 0;
  uint64_t forgotten_stale = 0;

  /// This daemon's own throttle, per next hop. Not the kernel's.
  std::map<NextHop, uint64_t> last_solicit_ns;

  /// The next hops that were still not usable at the last drain, in the
  /// order they were read. Carried into `fctl status`, because a box
  /// that is asking and not being answered is a wiring fault and the
  /// operator needs the ADDRESS, not a count.
  std::vector<NextHop> outstanding;

  /// Next hops already named in the journal, so a gateway that is down
  /// produces one line rather than five a second.
  std::map<NextHop, bool> reported;

  /// Drain the queue if `drain_interval_ms` has passed. Called from the
  /// engine's periodic sweep.
  auto MaybeResolve(uint64_t now_ns) -> void;

  /// The drain itself, unconditional. Separate so a test does not have
  /// to simulate the passage of time to exercise the decision.
  auto Resolve(uint64_t now_ns) -> void;

  /// Whether `ifindex` is one the datapath is attached to.
  auto OnDatapath(int ifindex) const -> bool;

  auto GetState() const -> nlohmann::json override;
  auto SetState(const nlohmann::json& j) -> bool override;
};

}  // namespace f

#endif  // INCLUDE_F_NEIGH_MGR_H_
