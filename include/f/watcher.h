/// @file watcher.h
/// @brief File-watcher thread: polls an FWL source for mtime
/// changes and signals the main thread to reload.

#ifndef INCLUDE_F_WATCHER_H_
#define INCLUDE_F_WATCHER_H_

#include <atomic>
#include <chrono>
#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <thread>

#include "f/error.h"

namespace f {

enum class WatcherError : uint8_t {
  kSourceNotFound,
  kInvalidConfig,
};

/// File-watcher state. Polls `source_path` mtime every `interval`
/// and sets `reload_requested` when it changes. The main thread
/// consumes the flag and triggers a reload.
struct Watcher {
  /// Path to the FWL source file to watch.
  std::string source_path;

  /// Directory where compiled bundles are deposited.
  /// Each bundle lands in a timestamped subdirectory.
  std::string compiled_dir;

  /// Path to the `fwl` binary (for invoking compile).
  std::string fwl_path = "fwl";

  /// Polling interval.
  std::chrono::seconds interval{5};

  /// Set by the watcher when a change is detected. The main
  /// thread atomically exchanges this for false to consume.
  std::atomic<bool> reload_requested{false};

  /// Last observed mtime in nanoseconds since epoch.
  int64_t last_mtime_ns = 0;

  /// True once WatcherStart has launched the thread.
  std::atomic<bool> running{false};

  std::jthread thread;
};

/// Configure the watcher. Records the initial mtime as baseline
/// so the first observed change triggers a reload.
auto WatcherInit(Watcher& w,
                 std::string_view source_path,
                 std::string_view compiled_dir,
                 std::chrono::seconds interval)
    -> std::expected<void, Error<WatcherError>>;

/// Launch the background polling thread.
auto WatcherStart(Watcher& w) -> void;

/// Stop and join the background thread.
auto WatcherStop(Watcher& w) -> void;

/// Check the source file mtime once. If changed, set
/// `reload_requested` and update `last_mtime_ns`. Returns true
/// if a change was detected. Public for testing.
auto WatcherCheckOnce(Watcher& w) -> bool;

/// Atomically clear `reload_requested` and return its previous
/// value. The main thread calls this each loop iteration.
auto WatcherConsumeReload(Watcher& w) -> bool;

}  // namespace f

#endif  // INCLUDE_F_WATCHER_H_
