/// @file bpf_loader.h
/// @brief BPF program loading, attaching, and map management.

#ifndef INCLUDE_F_BPF_LOADER_H_
#define INCLUDE_F_BPF_LOADER_H_

#include <array>
#include <cstdint>
#include <expected>
#include <map>
#include <string>
#include <string_view>
#include <vector>

#include "f/bpf_error.h"
#include "f/counters.h"
#include "f/error.h"
#include "f/tc_egress.h"

// libbpf handle; opaque here so the header stays libbpf-free.
struct bpf_object;

namespace f {

// There was a second datapath here: `LoadProgram`, `BpfHandles` and a
// search list ending in `/usr/lib/f/fw.bpf.o`, loading the v0.1
// single-program `bpf/fw.bpf.c` when no multi-zone bundle was staged.
// It is gone, and the whole point of removing it rather than repairing
// it is what it did when it ran. Measured on deb-03 against master
// `dc0b0fc`: with `current` moved aside, `fd` loaded
// `/usr/lib/f/fw.bpf.o`, attached it to a real NIC in native mode,
// reported READY to systemd, and passed every packet — because
// `LoadProgram` seeded the config map with `default_action = kAllow`
// so that the daemon "would not lock itself out before rules are
// configured". A firewall whose fallback is ALLOW is worse than a
// firewall that will not start: `systemctl status` said active,
// `show zones` said attached, and nothing anywhere said the policy on
// that box was not the operator's.
//
// A bundle that cannot be loaded is now a daemon that refuses to run.
// That is the same rule the zero-interface fix established one level
// down (BUGLOG #43): there is no configuration in which "up, and not
// enforcing the configured policy" is the correct outcome.

/// Detach the XDP program from an interface.
auto DetachXdp(int ifindex)
    -> std::expected<void, Error<BpfError>>;

/// Atomically replace the XDP program on `ifindex`: swap `old_prog_fd`
/// for `new_prog_fd` in a single kernel op (XDP_FLAGS_REPLACE), failing
/// if the attached program is not `old_prog_fd`. Pass `old_prog_fd < 0`
/// to attach without the replace constraint. The zero-drop hot-reload
/// primitive used by ApplyBundle's single-program swap.
auto ReplaceXdp(int ifindex, int new_prog_fd, int old_prog_fd)
    -> std::expected<void, Error<BpfError>>;

// --- v0.4 § 6.2 multi-zone bundle loading ---------------------------

/// One loaded zone program within a multi-zone bundle.
struct ZoneProgramHandle {
  std::string zone;            ///< zone name (the @xdp argument)
  int prog_fd = -1;            ///< the XDP program fd (fwl_prog)
  std::vector<int> ifindexes;  ///< interfaces it was attached to
  std::vector<std::string> interfaces;  ///< zone interface names
  std::vector<std::string> redirects_to;  ///< redirect destinations
  bool masquerades = false;    ///< true if this zone masquerades
  /// This zone's private `fwl_counters_<zone>` per-CPU array, or -1
  /// when the policy declares no `count` statement (the emitter then
  /// declares no map at all).
  int counters_fd = -1;
  /// This zone's masquerade source slot (`fwl_nat_cfg_<zone>`), or -1
  /// when the object carries no NAT machinery at all.
  ///
  /// PER ZONE, because the address it holds is: `masquerade` means
  /// "translate to the address of the zone this one redirects to", and
  /// nothing makes two masquerading zones redirect to the same place —
  /// `deploy/firstboot` writes `masquerade` + `redirect to <uplink>`
  /// for every non-uplink zone, and a box with two uplinks names two.
  /// While the map was pinned under the bundle-global name
  /// `fwl_nat_cfg` it was ONE kernel map with one slot 0 and this loop
  /// wrote it once per masquerading zone, so the last zone loaded
  /// decided what every masquerading program in the bundle translated
  /// to.
  ///
  /// On a bundle compiled before the split this points at that one
  /// shared map, for every zone, and `ZoneBundleHandles::legacy_nat_cfg`
  /// says so — see the comment on that field.
  int nat_cfg_fd = -1;
  /// The masquerade source address this loader wrote into that slot,
  /// or 0 when it wrote none (this zone does not masquerade, or no
  /// redirect-destination interface carried an IPv4 address).
  uint32_t masq_addr = 0;
  /// The name->slot table for that map, read from the same bundle
  /// directory, in the same call, as the object it describes.
  ///
  /// Captured at LOAD time on purpose. Re-reading the bundle directory
  /// later to name the slots of a map loaded earlier is a second
  /// derivation of one pairing, and a reload between the two answers
  /// it differently — the counter names would then belong to a policy
  /// that is no longer in the packet path while the values belong to
  /// one that is. The table and the descriptor come from one load or
  /// neither does.
  CounterTable counters;
};

/// Result of loading a multi-zone bundle: one entry per @xdp block.
struct ZoneBundleHandles {
  std::vector<ZoneProgramHandle> programs;
  /// The shared, bpffs-pinned conntrack map fd (cross-zone state), or
  /// -1 when no zone program uses conntrack.
  int conntrack_fd = -1;
  /// The shared, bpffs-pinned NAT reply-mapping map fd (`fwl_nat`), or
  /// -1 when no zone program uses NAT. Read to report active
  /// translations (`show nat`).
  int nat_fd = -1;
  /// The shared `fwl_nat_stats` per-CPU tally fd, or -1. Counts what
  /// the datapath did with the table: mappings claimed, source ports
  /// reallocated around a collision, and allocations REFUSED (a
  /// refusal means the packet was dropped). Read by NatMgr for
  /// `fctl status` and for the log line that fires when refusals move.
  int nat_stats_fd = -1;
  /// The shared `fwl_route_stats` per-CPU tally fd, or -1 when no zone
  /// program can redirect. Says whether a forwarded frame was ROUTED
  /// (next hop resolved through the zone the policy named, MACs
  /// rewritten, TTL decremented) or BRIDGED (forwarded with the header
  /// it arrived with). A masquerading gateway whose forwards are all
  /// bridged is a black hole, and nothing on the wire says so.
  int route_stats_fd = -1;
  /// True when this bundle was compiled before the masquerade source
  /// became per zone, so every object resolves ONE bundle-global
  /// `fwl_nat_cfg` and every `ZoneProgramHandle::nat_cfg_fd` names the
  /// same kernel map.
  ///
  /// The loader still seeds it — an `fd` upgrade must not turn
  /// masquerade into a silent no-op on a bundle staged by an older
  /// `fwl`, which is the same rule `ManifestStatesMasquerade` follows
  /// — but on such a bundle two masquerading zones with different
  /// redirect destinations cannot both be right, so the loader says
  /// which one it overwrote instead of leaving that to be discovered
  /// on the wire. Recompiling the policy is the fix; nothing here can
  /// be.
  bool legacy_nat_cfg = false;
  /// The loaded bpf_object per zone; owned by this bundle and closed
  /// by CloseZoneBundle once the bundle is replaced or shut down.
  std::vector<::bpf_object*> objs;
  /// The bundle's TC clsact egress conntrack tracker, attached to every
  /// interface above. Empty (`Attached()` false) for a bundle whose
  /// policy never reads conntrack, and for one compiled before the
  /// tracker existed. See f/tc_egress.h for why the second attach point
  /// exists and why it is at the qdisc layer.
  EgressTracker egress;
};

/// Load every zone program in a `fwl compile --bundle` directory.
///
/// Reads `<bundle_dir>/manifest.json` (zones, per-zone `<zone>.bpf.o`,
/// and redirect topology), opens each object under the common
/// `pin_root` so the `LIBBPF_PIN_BY_NAME` shared maps — above all
/// `conntrack` — resolve to a single kernel map across every zone
/// program, loads it, populates each `fwl_devmap_<dest>` with the
/// destination zone's interface ifindexes, and attaches the program to
/// every interface in its own zone. A zone interface that does not yet
/// exist on the host is skipped with a warning (interfaces may appear
/// after boot), not treated as a fatal error.
///
/// This is the only way a policy is loaded; the per-program
/// load/attach/devmap mechanism is exercised end-to-end by
/// tests/system/zone_redirect_netns.sh.
///
/// `replace`: a previously loaded bundle whose programs are still
/// attached. When given, each interface present in both bundles is
/// swapped atomically (XDP_FLAGS_REPLACE) instead of detach+attach —
/// the hot-reload zero-loss primitive; a detach/attach cycle resets
/// real NICs (igb takes the link down for seconds) and leaves a window
/// in which the interface has no XDP program at all. Interfaces only
/// in the old bundle are left attached — the caller detaches them
/// after adopting the new handles.
///
/// A fresh attach prefers native (driver) XDP and falls back to
/// generic (SKB) mode; some NICs have no native XDP at all — the
/// RTL8125 (`r8169`) rejects a native attach outright — and there the
/// program must run generic or not run.
///
/// A load that ends with ZERO interfaces attached is an error, always.
/// Loading and attaching are different jobs, and a count of the first
/// is not evidence about the second: the failure this rule exists to
/// close reported "1 zone program(s)" — which was true — while every
/// packet on the box flowed unfiltered. There is no bundle for which
/// "attached to nothing" is a correct outcome, whatever the manifest
/// said, so the caller never has to know why the interface list came
/// out empty to know the firewall is not up.
auto LoadZoneBundle(std::string_view bundle_dir,
                    std::string_view pin_root,
                    const ZoneBundleHandles* replace = nullptr)
    -> std::expected<ZoneBundleHandles, Error<BpfError>>;

/// Close every bpf_object a LoadZoneBundle call opened for `handles`.
/// Detaches nothing — swap or detach first.
auto CloseZoneBundle(ZoneBundleHandles& handles) -> void;

/// The map properties libbpf compares when it reuses an existing bpffs
/// pin. A difference in any of them makes the second zone object's
/// load fail with -EINVAL — reported by libbpf as nothing more useful
/// than "Invalid argument".
struct PinnedMapShape {
  uint32_t type = 0;
  uint32_t key_size = 0;
  uint32_t value_size = 0;
  uint32_t max_entries = 0;
  uint32_t map_flags = 0;
};

/// One sentence explaining a pinned-map shape conflict.
///
/// `want` is what the zone now loading declares; `have` is what the
/// map already pinned under that name actually is. `owner` describes
/// who holds the existing pin — "zone 'a'" when this bundle load
/// pinned it, or a path when it is left over from an earlier load.
/// Returns the empty string when the shapes agree: there is then
/// nothing to explain and the caller should keep its own message.
///
/// Exposed for unit tests; the loader calls it on every failed zone
/// object load.
auto DescribePinConflict(std::string_view map_name,
                         std::string_view loading_zone,
                         std::string_view owner,
                         const PinnedMapShape& want,
                         const PinnedMapShape& have) -> std::string;

/// Which incarnation of the daemon left the pins being reconciled, and
/// therefore what a pin that cannot be reused costs.
enum class PinPolicy : uint8_t {
  /// Cold boot. The pins belong to a PREVIOUS `fd` process: this one
  /// has no in-memory state to match them against and nothing attached
  /// to fall back to. A pin that cannot be reused is removed, because
  /// the alternative is a daemon that will not start — and a firewall
  /// that is down filters nothing at all.
  kColdBoot,
  /// Hot reload. The pins belong to the policy this same process has
  /// attached and running. A pin that cannot be reused is LEFT ALONE:
  /// the load then fails, ExplainPinConflict says which map and which
  /// definitions, and the running policy stays up. There is a fallback
  /// here, so silently destroying live state to force the new bundle
  /// in would be the wrong trade.
  kReload,
};

/// What ReconcilePinnedMaps did, for the journal and for tests.
struct PinReconcileReport {
  /// Pins removed: policy-scoped leftovers, plus (kColdBoot only) any
  /// persistent pin the incoming bundle cannot reuse.
  std::vector<std::string> discarded;
  /// Persistent pins carried into the load, definition checked.
  std::vector<std::string> adopted;
  /// Entries dropped from an adopted conntrack map because the
  /// daemon's own GC rule had already condemned them (kColdBoot only).
  uint32_t conntrack_swept = 0;
};

/// A live `fwl_counters_<zone>` per-CPU array, seen as the counter
/// join needs to see it.
///
/// The bound is taken from the map at construction (`bpf_map_get_info`)
/// and is 0 when the kernel could not be asked — never a default and
/// never a literal. A literal 256 here against a map declared with
/// 10000 slots is a defect this project has already shipped once: it
/// hid every counter from 256 up, accruing packets that no view could
/// surface.
class BpfCounterMap final : public CounterMap {
 public:
  /// `fd` may be negative; `Slots()` is then 0 and every read fails.
  explicit BpfCounterMap(int fd);
  auto Slots() const -> uint32_t override { return slots_; }
  auto Read(uint32_t slot) const -> std::optional<uint64_t> override;

 private:
  int fd_ = -1;
  uint32_t slots_ = 0;
  int ncpus_ = 1;
};

/// The persistent map names assumed for a bundle whose manifest predates
/// `persistent_maps` (compiled by an older `fwl`).
///
/// MUST equal `emitter.persistent_map_names()`;
/// fwl/tests/unit/test_map_lifetime.py reads this function's source and
/// fails if the two drift.
auto DefaultPersistentMapNames() -> std::vector<std::string>;

/// The `persistent_maps` list from `<bundle_dir>/manifest.json`, or
/// DefaultPersistentMapNames() when the manifest is missing the field.
auto ReadPersistentMapNames(std::string_view bundle_dir)
    -> std::vector<std::string>;

/// What a bundle asks the loader to attach, and where.
///
/// The manifest's `zones` array does not answer this on its own. A
/// unit written in the simple form — `@xdp(eth0)` with no `zone`
/// declaration, which FWL_V04_SPEC.md § 6.2 defines as "one implicit
/// zone whose name is the @xdp argument" — declares no zones at all,
/// so its `zones` array is `[]` while its `programs` array names
/// `eth0`. Reading only the array yielded an empty interface list for
/// that program, and the loader attached it to nothing and returned
/// success.
struct BundleAttachPlan {
  /// Zone name -> the interface names belonging to it. Carries every
  /// DECLARED zone, including one with no `@xdp` block of its own (it
  /// is still a redirect destination, and its interfaces are what
  /// fills the destination devmap), plus one implicit entry per `@xdp`
  /// block whose zone is not declared — the simple form, where the
  /// zone name IS the interface name.
  std::map<std::string, std::vector<std::string>> zone_interfaces;
  /// Zone programs for which the manifest names no interface at all.
  /// This is a malformed bundle — a compiler/daemon contract
  /// disagreement — and is a different thing from a host that is
  /// missing a NIC the manifest did name.
  std::vector<std::string> zones_without_interfaces;
};

/// Derive the attach plan from `<bundle_dir>/manifest.json`.
///
/// Exposed so the whole manifest-to-interfaces derivation is testable
/// without bpffs, root, or a compiled object. An unreadable or
/// unparseable manifest yields an empty plan; LoadZoneBundle reports
/// those cases itself with the parse error attached.
auto PlanBundleAttach(std::string_view bundle_dir) -> BundleAttachPlan;

/// True when the bundle's manifest states, per program, which zones
/// masquerade (the `masquerades` flag).
///
/// The flag is what decides whose address is written into a zone's
/// `fwl_nat_cfg_<zone>`, because the map's presence decides nothing:
/// every object in a NAT bundle carries one, since the NAT helper
/// block is emitted whole into any object that carries NAT at all. A
/// bundle compiled before the flag existed answers the
/// question not at all, and there the loader falls back to the old
/// presence rule rather than seeding nothing — an `fd` upgrade must
/// not silently turn every masquerade in an already-deployed bundle
/// into a no-op. Exposed so that fallback is testable without bpffs.
///
/// The two fallbacks compose, and it is worth stating how. A bundle
/// that predates the flag also predates the per-zone map, so its
/// fallback seeding writes every masquerading zone's address into the
/// one shared slot — the old behaviour exactly, which is the point.
/// A bundle that has the flag but not the per-zone map (compiled in
/// between) is gated correctly and still shares the slot; the loader
/// logs an error naming both zones when the second write changes the
/// value, because nothing in a one-slot map can be right for two
/// uplinks. On a current bundle the fallback seeding, if it ever fired
/// again, would write into each zone's OWN map and could no longer
/// take another zone down with it.
auto ManifestStatesMasquerade(std::string_view bundle_dir) -> bool;

/// The names a zone object's masquerade source map may go by, in the
/// order the loader tries them.
///
/// [0] is `fwl_nat_cfg_<zone>`, which is what `fwl` emits: the address
/// is a per-zone fact — "translate to the address of the zone THIS one
/// redirects to" — and two masquerading zones need not name the same
/// uplink. [1] is the historical bundle-global `fwl_nat_cfg`, one
/// kernel map with one slot 0 shared by every object, where the last
/// zone loaded decided what all of them translated to.
///
/// The second name is not dead code and must not be removed: a bundle
/// staged by an older `fwl` carries only that map, and an `fd` upgrade
/// that could not find it would turn every masquerade in an
/// already-deployed bundle into a silent no-op — the same rule, and
/// the same reason, as `ManifestStatesMasquerade`'s fallback.
///
/// Exposed so the preference order is testable without an object.
auto NatCfgMapNames(std::string_view zone)
    -> std::array<std::string, 2>;

/// What to do with one pin found under the root, given what the bundle
/// about to load declares.
enum class PinVerdict : uint8_t {
  kAdopt,    ///< carry it into the load: same name, same definition
  kDiscard,  ///< remove it: stale by policy, by name, or by definition
  kDefer,    ///< leave it for the loader to fail on (reload only)
};

/// The whole cold-boot/reload pin decision, as one pure function.
///
/// `persistent` is the bundle's `persistent_maps`. `declared` is the
/// definition the incoming bundle gives this name, or nullptr when no
/// zone object declares it at all. `existing` is what is actually
/// pinned. Exposed so the decision is testable without bpffs or root;
/// ReconcilePinnedMaps is the loop that applies it.
auto DecidePinFate(std::string_view name,
                   const std::vector<std::string>& persistent,
                   const PinnedMapShape* declared,
                   const PinnedMapShape& existing,
                   PinPolicy policy) -> PinVerdict;

/// Reconcile the pins under `pin_root` against the bundle at
/// `bundle_dir`, before it is loaded.
///
/// A pinned map outlives the process that made it: bpffs holds a
/// reference, so every pin an `fd` incarnation left behind is still
/// there for the next one. Only a reboot clears it (bpffs is a fresh
/// mount), which is why the symptom of getting this wrong is the
/// especially nasty "works after a reboot, fails after a restart".
///
/// Two questions decide each pin, and they are different questions:
///
///   Do the CONTENTS still mean anything? Answered per map by
///   `_MAP_KINDS`' MapLifetime and carried in the manifest as
///   `persistent_maps`. Only flow-keyed state qualifies — conntrack and
///   fwl_nat. Everything else is numbered, sized or populated by one
///   compilation, and adopting it reports a dead policy's numbers
///   against live rules (or, when the shape moved, fails the load).
///
///   Does the DEFINITION still match? A name that survives the first
///   question is still only adoptable if the incoming bundle declares
///   it exactly as it is pinned — the same check libbpf makes, made
///   before libbpf gets a chance to answer it with -EINVAL and no
///   detail. Adopting without it would reintroduce the load failure
///   through the map that is allowed to persist.
///
/// The sweep is an ALLOWLIST of what survives, not a blocklist of what
/// goes: a map added to the emitter and forgotten here is discarded,
/// which costs state at worst, where the previous prefix-blocklist
/// adopted it and was silently wrong.
///
/// On kColdBoot an adopted conntrack map is also swept of entries older
/// than `conntrack_timeout_s` — the rule the daemon's GC applies
/// anyway, applied here so it lands BEFORE the datapath is armed rather
/// than up to one GC interval after. Without it, a table adopted after
/// a long stop would answer ESTABLISHED for flows that ended hours ago.
/// Removing a pin never disturbs a program still using that map: an
/// attached XDP program holds its own reference, which is what keeps
/// the datapath filtering while `fd` is dead.
auto ReconcilePinnedMaps(std::string_view bundle_dir,
                         std::string_view pin_root,
                         PinPolicy policy,
                         uint32_t conntrack_timeout_s)
    -> PinReconcileReport;

/// One LPM-trie entry parsed from a bundle's geoip.json.
struct GeoipTrieEntry {
  uint32_t prefixlen = 0;
  bool v6 = false;
  /// Network-order address bytes; the first 4 are used for v4.
  uint8_t addr[16] = {};
};

/// Parsed geoip.json: trie map name -> its prefix entries.
using GeoipTries =
    std::map<std::string, std::vector<GeoipTrieEntry>>;

/// First IPv4 address (network byte order) configured on any of the
/// named interfaces, or 0 when none carries one. The masquerade
/// source: the daemon writes this into the masquerading zone's OWN
/// `fwl_nat_cfg_<zone>` map so its `masquerade` rules translate to the
/// address of the zone it redirects to. Resolved per masquerading
/// zone, from that zone's own `redirects_to`, because two of them need
/// not name the same uplink.
auto FirstZoneIpv4(const std::vector<std::string>& ifaces) -> uint32_t;

/// Parse `<bundle_dir>/geoip.json` (written by `fwl compile --bundle
/// --geoip`). Returns an empty map when the file is absent — a bundle
/// without geoip() calls has no geoip.json. Malformed JSON or an
/// unparseable prefix is an error: silently loading empty tries would
/// make every geoip() rule a no-op, which is exactly the failure mode
/// the bundle file exists to prevent.
auto ParseGeoipFile(std::string_view bundle_dir)
    -> std::expected<GeoipTries, Error<BpfError>>;

/// True when `<bundle_dir>/manifest.json` describes a multi-zone bundle
/// (a non-empty "zones" array and a non-empty "programs" array). The
/// cold-boot (EngineInit) and hot-reload (ApplyBundle) paths use this
/// to route to LoadZoneBundle instead of the single-program loader.
/// Returns false when the manifest is missing or unparseable.
auto IsMultiZoneBundle(std::string_view bundle_dir) -> bool;

/// Detach every program in a previously loaded zone bundle from its
/// interfaces. Best-effort: logs and continues on per-interface error.
/// Used before a hot-reload re-attaches a new bundle.
auto DetachZoneBundle(const ZoneBundleHandles& handles) -> void;

}  // namespace f

#endif  // INCLUDE_F_BPF_LOADER_H_
