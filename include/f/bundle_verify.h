/// @file bundle_verify.h
/// @brief Asking the kernel whether it will take a bundle, without
///        making that bundle `current`.
///
/// The order of operations that lost the rig three times was: compile,
/// point `current` at the result, restart `fd`, find out. Every step
/// after the first is irreversible from a box that has stopped
/// answering. This is the same question asked in the opposite order —
/// the programs are loaded into the kernel and closed again, nothing
/// is attached, no pin under the daemon's own root is touched, and
/// `current` is not moved.
///
/// **The exit status is not the answer.** That lesson is
/// `tests/system/hw/l13_03_acl_scale.py:probe_verifier`'s, and it was
/// expensive: an earlier probe read `$?` and reported "verifier
/// accepted in 0.1 s" for every rule count up to 2,500 while the same
/// program, loaded by hand, ran for minutes and took the board out. So
/// acceptance here requires evidence that a program exists — a file
/// descriptor the kernel will describe, with a non-zero translated
/// size — and a pass that arrives implausibly fast is reported as
/// such rather than believed.

#ifndef INCLUDE_F_BUNDLE_VERIFY_H_
#define INCLUDE_F_BUNDLE_VERIFY_H_

#include <cstdint>
#include <expected>
#include <string>
#include <vector>

namespace f {

/// One program the kernel was asked to accept.
struct VerifiedProgram {
  std::string zone;
  std::string object;
  /// Program name as it appears in the object.
  std::string program;
  bool loaded = false;
  /// Bytes of translated (post-verifier) instruction stream. Zero on a
  /// load the kernel claims to have accepted but left nothing behind,
  /// which this module treats as a failure.
  std::uint32_t xlated_bytes = 0;
  std::uint32_t jited_bytes = 0;
  /// Why, when `loaded` is false. Carries the verifier log when there
  /// is one — that text is the only thing that names the instruction
  /// the kernel objected to.
  std::string why;
};

/// What a verification run found.
struct VerifyReport {
  std::string bundle_dir;
  std::vector<VerifiedProgram> programs;
  /// Seconds the whole load took. Reported because it is the number
  /// that tells an operator a policy is close to the edge: on the rig
  /// a 2,500-rule program verified in 3.0 s and a 10,000-rule one
  /// never finished.
  double seconds = 0.0;
  /// True only when every program loaded AND left a program behind.
  bool ok = false;
  /// One sentence, always populated.
  std::string summary;
};

/// Load every program in `bundle_dir` and close it again.
///
/// `scratch_pin_root` is where the bundle's `LIBBPF_PIN_BY_NAME` maps
/// are resolved. It must NOT be the running daemon's pin root: a
/// verification that adopted the live conntrack pin would be checking
/// the bundle against state it is not entitled to change, and one that
/// created pins under the live root would leave the next real load
/// reusing maps a check made. The directory is created and removed
/// here.
auto VerifyBundle(const std::string& bundle_dir,
                  const std::string& scratch_pin_root)
    -> std::expected<VerifyReport, std::string>;

}  // namespace f

#endif  // INCLUDE_F_BUNDLE_VERIFY_H_
