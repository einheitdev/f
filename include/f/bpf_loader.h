/// @file bpf_loader.h
/// @brief BPF program loading, attaching, and map management.

#ifndef INCLUDE_F_BPF_LOADER_H_
#define INCLUDE_F_BPF_LOADER_H_

#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <vector>

#include "f/error.h"

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
auto LoadZoneBundle(std::string_view bundle_dir,
                    std::string_view pin_root)
    -> std::expected<ZoneBundleHandles, Error<BpfError>>;

}  // namespace f

#endif  // INCLUDE_F_BPF_LOADER_H_
