/// @file bpf_loader.h
/// @brief BPF program loading, attaching, and map management.

#ifndef INCLUDE_F_BPF_LOADER_H_
#define INCLUDE_F_BPF_LOADER_H_

#include <cstdint>
#include <expected>
#include <string>
#include <string_view>

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
auto LoadProgram()
    -> std::expected<BpfHandles, Error<BpfError>>;

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

}  // namespace f

#endif  // INCLUDE_F_BPF_LOADER_H_
