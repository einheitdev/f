/// @file artifact.h
/// @brief Derived artifacts: digest, drift detection, atomic install.
///
/// Every file a backend writes is derived from the model. Three rules
/// hold for all of them, so they live here rather than once per
/// backend:
///
///  1. The file carries a digest of its own body, so an edit is
///     detectable.
///  2. Drift is *reported*, never silently regenerated over. A stale
///     artifact and a hand-edited one are different faults.
///  3. Installation is temp-file + rename, so a crash mid-write cannot
///     leave a daemon reading half a config.

#ifndef INCLUDE_F_SYSCONFIG_ARTIFACT_H_
#define INCLUDE_F_SYSCONFIG_ARTIFACT_H_

#include <cstdint>
#include <expected>
#include <string>

namespace f::sysconfig {

/// How an on-disk artifact relates to the model that should own it.
enum class DriftKind {
  /// On disk and identical to what the model generates now.
  kNone,
  /// Nothing on disk yet.
  kAbsent,
  /// The body does not match the digest the file carries — somebody
  /// edited a generated file.
  kHandEdited,
  /// Self-consistent, but generated from an older model.
  kStale,
};

auto DriftKindName(DriftKind k) -> std::string;

/// FNV-1a 64, rendered as 16 hex digits. This guards against a
/// well-meaning operator editing a generated file, not against
/// tampering — anyone who can write the artifact directory already
/// owns the box.
auto BodyDigest(const std::string& body) -> std::string;

/// Prepend the digest header to a rendered body.
auto WrapWithDigest(const std::string& body) -> std::string;

/// Compare the file at `path` against `expected` (a full
/// digest-wrapped document).
auto CheckArtifactDrift(const std::string& path,
                        const std::string& expected) -> DriftKind;

/// Write `content` to `path` atomically, creating parent directories.
/// @returns true when the file's contents changed, or an error string.
auto InstallArtifact(const std::string& path,
                     const std::string& content)
    -> std::expected<bool, std::string>;

}  // namespace f::sysconfig

#endif  // INCLUDE_F_SYSCONFIG_ARTIFACT_H_
