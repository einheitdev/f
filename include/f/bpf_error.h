/// @file bpf_error.h
/// @brief The BPF-layer error code, shared by the loader and the hooks.
///
/// Split out of bpf_loader.h so a second attach point (f/tc_egress.h)
/// can report failures in the same vocabulary without the loader having
/// to include it and it having to include the loader.

#ifndef INCLUDE_F_BPF_ERROR_H_
#define INCLUDE_F_BPF_ERROR_H_

#include <cstdint>

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
  /// A `table`'s `source` file could not be read, or what it held was
  /// not something the table could be filled from. Distinct from
  /// kLoadFailed on purpose: the bundle is fine and the policy is
  /// fine, and something upstream of the box -- an NFS blip, a feeder
  /// that has not written yet, a permissions change -- is not. A
  /// bundle-health guard that counts failed loads must be able to
  /// tell "this artifact will never work" from "this artifact could
  /// not reach its data just now", or a transient quarantines a good
  /// policy.
  kFeedUnavailable,
};

}  // namespace f

#endif  // INCLUDE_F_BPF_ERROR_H_
