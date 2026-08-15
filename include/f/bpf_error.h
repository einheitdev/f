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
};

}  // namespace f

#endif  // INCLUDE_F_BPF_ERROR_H_
