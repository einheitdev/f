/// @file bpf_loader.h
/// @brief BPF program loading, attaching, and map management.

#ifndef INCLUDE_F_BPF_LOADER_H_
#define INCLUDE_F_BPF_LOADER_H_

#include <cstdint>
#include <expected>
#include <map>
#include <string>
#include <string_view>
#include <vector>

#include "f/error.h"

// libbpf handle; opaque here so the header stays libbpf-free.
struct bpf_object;

namespace f {

enum class BpfError : uint8_t {
  kLoadFailed,
  kAttachFailed,
  kDetachFailed,
  kPinFailed,
  kUnpinFailed,
  kMapUpdateFailed,
  kMapLookupFailed,
  kMapDeleteFailed,
  kMapIterFailed,
};

/// File descriptors for all BPF maps and the program.
struct BpfHandles {
  int prog_fd = -1;
  int rules_a_fd = -1;
  int rules_b_fd = -1;
  int cidr_a_fd = -1;
  int cidr_b_fd = -1;
  int conntrack_fd = -1;
  int counters_fd = -1;
  int config_fd = -1;
  int events_fd = -1;
};

/// Load the BPF program and return map file descriptors.
///
/// `bundle_dir` is the parent of the `current` symlink the
/// reload pipeline maintains (`/usr/share/f/compiled` by default).
/// When set, `<bundle_dir>/current/main.bpf.o` is tried first;
/// otherwise the loader falls back to the built-in fw.bpf.o
/// search paths. Empty string disables the bundle path entirely
/// (used by tests that want the v0.1 search behaviour).
auto LoadProgram(std::string_view bundle_dir = "")
    -> std::expected<BpfHandles, Error<BpfError>>;

/// Load a single XDP program from a specific object path. Used by the
/// hot-reload path to stage a new program before atomically swapping
/// it in. Unlike LoadProgram this ignores the cold-boot search list and
/// keeps its own bpf_object alive (close it via UnloadProgram), so the
/// running program is untouched until the swap succeeds.
auto LoadProgramFromPath(std::string_view obj_path)
    -> std::expected<BpfHandles, Error<BpfError>>;

/// Close the bpf_object a prior LoadProgramFromPath opened for `h`
/// (looked up by prog_fd). No-op when `h` was not produced by
/// LoadProgramFromPath.
auto UnloadProgram(const BpfHandles& h) -> void;

/// Resolve which BPF object the loader will pick, without
/// actually opening it. Returns the empty string when nothing on
/// the search list exists. Exposed for unit tests; the live
/// loader uses the same logic.
auto ResolveBpfObjPath(std::string_view bundle_dir) -> std::string;

/// Attach the XDP program to an interface.
auto AttachXdp(const BpfHandles& h, int ifindex)
    -> std::expected<void, Error<BpfError>>;

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

/// Pin all maps to bpffs for persistence across restarts.
auto PinMaps(const BpfHandles& h,
             std::string_view pin_path)
    -> std::expected<void, Error<BpfError>>;

/// Remove pinned maps from bpffs.
auto UnpinMaps(std::string_view pin_path)
    -> std::expected<void, Error<BpfError>>;

// --- v0.4 § 6.2 multi-zone bundle loading ---------------------------

/// One loaded zone program within a multi-zone bundle.
struct ZoneProgramHandle {
  std::string zone;            ///< zone name (the @xdp argument)
  int prog_fd = -1;            ///< the XDP program fd (fwl_prog)
  std::vector<int> ifindexes;  ///< interfaces it was attached to
};

/// Result of loading a multi-zone bundle: one entry per @xdp block.
struct ZoneBundleHandles {
  std::vector<ZoneProgramHandle> programs;
  /// The shared, bpffs-pinned conntrack map fd (cross-zone state), or
  /// -1 when no zone program uses conntrack.
  int conntrack_fd = -1;
  /// The loaded bpf_object per zone; owned by this bundle and closed
  /// by CloseZoneBundle once the bundle is replaced or shut down.
  std::vector<::bpf_object*> objs;
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
/// This is the multi-program analogue of LoadProgram + AttachXdp; the
/// per-program load/attach/devmap mechanism is exercised end-to-end by
/// tests/system/zone_redirect_netns.sh.
/// `replace`: a previously loaded bundle whose programs are still
/// attached. When given, each interface present in both bundles is
/// swapped atomically (XDP_FLAGS_REPLACE) instead of detach+attach —
/// the hot-reload zero-loss primitive; a detach/attach cycle resets
/// real NICs (igb takes the link down for seconds). Interfaces only
/// in the old bundle are left attached — the caller detaches them
/// after adopting the new handles.
auto LoadZoneBundle(std::string_view bundle_dir,
                    std::string_view pin_root,
                    const ZoneBundleHandles* replace = nullptr)
    -> std::expected<ZoneBundleHandles, Error<BpfError>>;

/// Close every bpf_object a LoadZoneBundle call opened for `handles`.
/// Detaches nothing — swap or detach first.
auto CloseZoneBundle(ZoneBundleHandles& handles) -> void;

/// Remove the bpffs pins of zone-PRIVATE maps (fwl_counters_*,
/// fwl_rl_*, fwl_geoip_*, fwl_log_sample*) under `pin_root`, keeping
/// the shared cross-reload state (conntrack, fwl_nat, fwl_nat_cfg,
/// fwl_log_events). A reload's new objects must create fresh private
/// maps — their shape follows the policy — while attached programs
/// keep their own references until swapped out. Leaving a private pin
/// behind is not a leak but a load failure: the next policy sizes the
/// map from its own analysis and libbpf rejects the mismatched reuse.
auto UnpinZonePrivateMaps(std::string_view pin_root) -> void;

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
/// source: the daemon writes this into the bundle's `fwl_nat_cfg`
/// map so `masquerade` rules translate to the egress zone's address.
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
