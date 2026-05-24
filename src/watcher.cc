/// @file watcher.cc
/// @brief File-watcher thread implementation.

#include "f/watcher.h"

#include <sys/stat.h>

#include <filesystem>
#include <format>

#include <spdlog/spdlog.h>

namespace f {
namespace {

/// Read the mtime of `path` as nanoseconds since epoch. Returns
/// 0 if the file doesn't exist or cannot be stat'd.
auto StatMtimeNs(std::string_view path) -> int64_t {
  struct stat st{};
  if (::stat(std::string(path).c_str(), &st) != 0) {
    return 0;
  }
  return static_cast<int64_t>(st.st_mtim.tv_sec)
       * 1'000'000'000
       + static_cast<int64_t>(st.st_mtim.tv_nsec);
}

}  // namespace

auto WatcherInit(Watcher& w,
                 std::string_view source_path,
                 std::string_view compiled_dir,
                 std::chrono::seconds interval)
    -> std::expected<void, Error<WatcherError>> {
  if (source_path.empty()) {
    return MakeError(WatcherError::kInvalidConfig,
                     "watcher source_path is empty");
  }
  if (compiled_dir.empty()) {
    return MakeError(WatcherError::kInvalidConfig,
                     "watcher compiled_dir is empty");
  }

  w.source_path = std::string(source_path);
  w.compiled_dir = std::string(compiled_dir);
  w.interval = interval;

  // Pre-record the current mtime so the first tick doesn't
  // fire a spurious reload against unchanged content.
  w.last_mtime_ns = StatMtimeNs(w.source_path);
  if (w.last_mtime_ns == 0) {
    return MakeError(
        WatcherError::kSourceNotFound,
        std::format("source not found: {}", w.source_path));
  }

  // Create the compiled directory up-front — the reload handler
  // writes versioned subdirs into it.
  std::error_code ec;
  std::filesystem::create_directories(w.compiled_dir, ec);
  if (ec) {
    spdlog::warn("watcher: create {} failed: {}",
                 w.compiled_dir, ec.message());
  }

  return {};
}

auto WatcherCheckOnce(Watcher& w) -> bool {
  int64_t now = StatMtimeNs(w.source_path);
  if (now == 0) {
    // File may have been removed; wait for it to come back.
    return false;
  }
  if (now == w.last_mtime_ns) {
    return false;
  }
  w.last_mtime_ns = now;
  w.reload_requested.store(true, std::memory_order_release);
  spdlog::info("watcher: change detected on {}", w.source_path);
  return true;
}

auto WatcherConsumeReload(Watcher& w) -> bool {
  return w.reload_requested.exchange(
      false, std::memory_order_acq_rel);
}

auto WatcherStart(Watcher& w) -> void {
  w.running.store(true);
  w.thread = std::jthread([&w](std::stop_token st) {
    spdlog::info("watcher: started, interval={}s, source={}",
                 w.interval.count(), w.source_path);
    while (!st.stop_requested()) {
      // Sleep in small slices so stop requests don't wait
      // the full interval.
      auto deadline =
          std::chrono::steady_clock::now() + w.interval;
      while (std::chrono::steady_clock::now() < deadline
             && !st.stop_requested()) {
        std::this_thread::sleep_for(
            std::chrono::milliseconds(100));
      }
      if (st.stop_requested()) {
        break;
      }
      WatcherCheckOnce(w);
    }
    spdlog::info("watcher: stopped");
  });
}

auto WatcherStop(Watcher& w) -> void {
  if (!w.running.load()) {
    return;
  }
  w.running.store(false);
  if (w.thread.joinable()) {
    w.thread.request_stop();
    w.thread.join();
  }
}

}  // namespace f
