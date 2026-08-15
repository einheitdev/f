/// @file reload.h
/// @brief Reload pipeline: compile source → apply bundle atomically.

#ifndef INCLUDE_F_RELOAD_H_
#define INCLUDE_F_RELOAD_H_

#include <cstdint>
#include <expected>
#include <string>
#include <string_view>

#include "f/error.h"

namespace f {

struct Engine;

enum class ReloadError : uint8_t {
  /// Subprocess exec or I/O failed.
  kSpawnFailed,
  /// `fwl compile` returned a non-ok envelope.
  kCompileFailed,
  /// manifest.json missing, unparseable, or violates schema.
  kManifestInvalid,
  /// Loading or attaching the bundle failed against the engine.
  kApplyFailed,
  /// Filesystem error.
  kIoError,
};

struct ReloadResult {
  /// Bundle version string from manifest (e.g. "20260414T200000Z").
  std::string version;
  /// True once the new bundle's programs are the ones attached.
  bool program_updated = false;
};

// `rules_installed` was here, and it was always 0 on a bundle: it
// counted rows written into the v0.1 `rules_a` map, and a bundle
// carries its rules compiled into the BPF objects. `commit` reported
// "0 rules installed" for every successful policy change on every box.
// A number that cannot be anything but zero is not a measurement.

/// Compile the current source into a new bundle and apply it.
/// On any failure, no state changes are visible to the data plane.
auto ReloadFromSource(Engine& e)
    -> std::expected<ReloadResult, Error<ReloadError>>;

/// Invoke `fwl compile --bundle` as a subprocess. Returns the
/// stdout envelope string. Public for testability.
auto RunCompiler(std::string_view fwl_path,
                 std::string_view source_path,
                 std::string_view output_dir)
    -> std::expected<std::string, Error<ReloadError>>;

/// Apply an already-built bundle directory to the engine: reads
/// manifest.json, reconciles the pins, loads every zone program and
/// swaps it onto its interfaces atomically. Public for testability.
auto ApplyBundle(Engine& e, std::string_view bundle_dir)
    -> std::expected<ReloadResult, Error<ReloadError>>;

}  // namespace f

#endif  // INCLUDE_F_RELOAD_H_
