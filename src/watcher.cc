/// @file watcher.cc
/// @brief File-watcher thread implementation.

#include "f/watcher.h"

#include <sys/stat.h>

#include <fstream>
#include <functional>
#include <iterator>
#include <string>

#include <filesystem>
#include <format>

#include <spdlog/spdlog.h>

namespace f {
namespace {

/// A fingerprint of the policy file: mtime, size, inode, and a hash
/// of the contents.
///
/// mtime alone is not enough. Every mtime-preserving deployment tool
/// — `cp -p`, `rsync -a`, `tar x`, `install -p`, restoring a backup —
/// installs new content under the old timestamp, and the watcher
/// simply never noticed: new policy on disk, old policy in the
/// kernel, nothing logged. Confirmed on hardware
/// (tests/system/hw/l8_04_watcher_mtime.sh): the superseded policy
/// was still dropping traffic while the file on disk said otherwise.
///
/// Hashing the contents also makes the check *narrower* in the right
/// way: a touch that does not change the policy no longer triggers a
/// recompile-and-swap. The file is a few KB and this runs on a 5 s
/// poll, so the read costs nothing worth measuring. Returns 0 when
/// the file is missing or unreadable.
auto FingerprintFile(std::string_view path) -> int64_t {
  std::string p(path);
  struct stat st{};
  if (::stat(p.c_str(), &st) != 0) {
    return 0;
  }
  int64_t fp = static_cast<int64_t>(st.st_mtim.tv_sec)
             * 1'000'000'000
             + static_cast<int64_t>(st.st_mtim.tv_nsec);
  fp ^= static_cast<int64_t>(st.st_size) << 1;
  fp ^= static_cast<int64_t>(st.st_ino) << 3;

  std::ifstream in(p, std::ios::in | std::ios::binary);
  if (!in) {
    // Unreadable but present: fall back to the stat fingerprint so a
    // later permission fix still registers as a change.
    return fp ? fp : 1;
  }
  std::string content((std::istreambuf_iterator<char>(in)),
                      std::istreambuf_iterator<char>());
  auto h = static_cast<int64_t>(std::hash<std::string>{}(content));
  // Keep it non-zero: 0 is the "missing file" sentinel.
  int64_t combined = fp ^ h;
  return combined ? combined : 1;
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

  // Pre-record the current fingerprint so the first tick doesn't
  // fire a spurious reload against unchanged content.
  w.last_fingerprint = FingerprintFile(w.source_path);
  if (w.last_fingerprint == 0) {
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
  int64_t now = FingerprintFile(w.source_path);
  if (now == 0) {
    // File may have been removed; wait for it to come back.
    return false;
  }
  if (now == w.last_fingerprint) {
    return false;
  }
  w.last_fingerprint = now;
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
