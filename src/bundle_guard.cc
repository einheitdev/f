/// @file bundle_guard.cc
/// @brief Implementation of the bundle load guard. See bundle_guard.h
///        for why this is a breadcrumb on disk and not an error
///        handler.

#include "f/bundle_guard.h"

#include <fcntl.h>
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <format>
#include <sstream>
#include <string>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

namespace f {
namespace {

namespace fs = std::filesystem;
using json = nlohmann::json;

constexpr const char* kAttemptFile = ".load-attempt.json";
constexpr const char* kCurrentLink = "current";
constexpr const char* kLkgLink = "last-known-good";

auto NowS() -> std::int64_t {
  return std::chrono::duration_cast<std::chrono::seconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

/// Resolve a symlink under `root` to the bare name it points at.
///
/// Only the filename, because that is what `current` is written as —
/// a relative link to a sibling directory — and because a name is what
/// the attempt record compares against. A link whose target does not
/// exist resolves to empty.
auto ResolveLink(const std::string& root, const char* name)
    -> std::string {
  if (root.empty()) return {};
  std::error_code ec;
  fs::path link = fs::path(root) / name;
  if (!fs::is_symlink(link, ec)) {
    // A plain directory in place of the symlink is what a hand-staged
    // box sometimes has. Treat it as a version named `current`: it is
    // still a thing that can be loaded and still a thing that can trap
    // the boot.
    if (fs::is_directory(link, ec)) return name;
    return {};
  }
  auto target = fs::read_symlink(link, ec);
  if (ec) return {};
  auto version = target.filename().string();
  if (version.empty()) return {};
  if (!fs::exists(fs::path(root) / version, ec)) return {};
  return version;
}

/// Write `text` to `path` and make sure it survives a power cut.
///
/// The whole point of the attempt record is that it outlives a board
/// that stops being scheduled, so a buffered write into page cache is
/// not good enough: the write, the file and the directory entry are
/// all fsynced before this returns. It costs a few milliseconds once
/// per daemon start.
auto WriteDurable(const fs::path& path, const std::string& text)
    -> std::expected<void, std::string> {
  auto tmp = path;
  tmp += ".new";
  int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd < 0) {
    return std::unexpected(
        std::format("open {}: {}", tmp.string(), ::strerror(errno)));
  }
  const char* p = text.data();
  std::size_t left = text.size();
  while (left > 0) {
    ssize_t n = ::write(fd, p, left);
    if (n <= 0) {
      ::close(fd);
      ::unlink(tmp.c_str());
      return std::unexpected(
          std::format("write {}: {}", tmp.string(), ::strerror(errno)));
    }
    p += n;
    left -= static_cast<std::size_t>(n);
  }
  ::fsync(fd);
  ::close(fd);
  std::error_code ec;
  fs::rename(tmp, path, ec);
  if (ec) {
    fs::remove(tmp, ec);
    return std::unexpected(
        std::format("rename {}: {}", path.string(), ec.message()));
  }
  // The rename itself is only durable once the directory is.
  int dir_fd = ::open(path.parent_path().c_str(), O_RDONLY | O_DIRECTORY);
  if (dir_fd >= 0) {
    ::fsync(dir_fd);
    ::close(dir_fd);
  }
  return {};
}

auto RecordPath(const GuardConfig& cfg) -> fs::path {
  return fs::path(cfg.bundle_dir) / kAttemptFile;
}

auto WriteRecord(const GuardConfig& cfg, const AttemptRecord& r)
    -> std::expected<void, std::string> {
  json j{
      {"version", r.version},
      {"attempts", r.attempts},
      {"first_s", r.first_s},
      {"last_s", r.last_s},
      {"last_error", r.last_error},
  };
  return WriteDurable(RecordPath(cfg), j.dump(2) + "\n");
}

}  // namespace

auto ParseGuardPolicy(std::string_view name)
    -> std::expected<GuardPolicy, std::string> {
  if (name == "fallback") return GuardPolicy::kFallback;
  if (name == "fail-closed" || name == "closed") {
    return GuardPolicy::kFailClosed;
  }
  return std::unexpected(std::format(
      "unknown bundle-failure policy '{}': it is 'fallback' (run the "
      "last bundle this box was seen to attach, and say so) or "
      "'fail-closed' (do not start; the box stays reachable and stops "
      "forwarding)",
      name));
}

auto GuardPolicyName(GuardPolicy policy) -> const char* {
  return policy == GuardPolicy::kFallback ? "fallback" : "fail-closed";
}

auto CurrentVersion(const std::string& bundle_dir) -> std::string {
  return ResolveLink(bundle_dir, kCurrentLink);
}

auto LastKnownGood(const std::string& bundle_dir) -> std::string {
  return ResolveLink(bundle_dir, kLkgLink);
}

auto ReadAttemptRecord(const GuardConfig& cfg) -> AttemptRecord {
  AttemptRecord r;
  std::ifstream in(RecordPath(cfg));
  if (!in) return r;
  std::ostringstream ss;
  ss << in.rdbuf();
  try {
    auto j = json::parse(ss.str());
    r.version = j.value("version", std::string{});
    r.attempts = j.value("attempts", 0);
    r.first_s = j.value("first_s", std::int64_t{0});
    r.last_s = j.value("last_s", std::int64_t{0});
    r.last_error = j.value("last_error", std::string{});
    r.present = true;
  } catch (const std::exception& ex) {
    // A corrupt record is not a reason to load a bundle that may be
    // the thing that corrupted it. Report it as present with the
    // attempts exhausted so the caller takes the cautious branch, and
    // say why.
    r.present = true;
    r.version = CurrentVersion(cfg.bundle_dir);
    r.attempts = cfg.max_attempts;
    r.last_error =
        std::format("attempt record unreadable ({}); treating this "
                    "bundle as unproven",
                    ex.what());
  }
  return r;
}

auto PointCurrentAt(const std::string& bundle_dir,
                    const std::string& version)
    -> std::expected<void, std::string> {
  if (bundle_dir.empty() || version.empty()) {
    return std::unexpected("no bundle directory or version");
  }
  fs::path root(bundle_dir);
  auto link = root / kCurrentLink;
  auto tmp = root / ".current.new";
  std::error_code ec;
  fs::remove(tmp, ec);
  fs::create_symlink(version, tmp, ec);
  if (ec) {
    return std::unexpected(
        std::format("symlink {}: {}", tmp.string(), ec.message()));
  }
  fs::rename(tmp, link, ec);
  if (ec) {
    fs::remove(tmp, ec);
    return std::unexpected(
        std::format("rename {}: {}", link.string(), ec.message()));
  }
  int dir_fd = ::open(root.c_str(), O_RDONLY | O_DIRECTORY);
  if (dir_fd >= 0) {
    ::fsync(dir_fd);
    ::close(dir_fd);
  }
  return {};
}

auto BundleGuardBegin(const GuardConfig& cfg) -> GuardDecision {
  GuardDecision d;
  auto current = CurrentVersion(cfg.bundle_dir);
  d.record = ReadAttemptRecord(cfg);
  if (current.empty()) {
    // Nothing staged. Not this module's failure to report — the loader
    // has a much better sentence for it — so proceed and let it.
    d.verdict = GuardVerdict::kProceed;
    d.load_dir = (fs::path(cfg.bundle_dir) / kCurrentLink).string();
    return d;
  }

  const bool same = d.record.present && d.record.version == current;
  const int used = same ? d.record.attempts : 0;
  if (used < cfg.max_attempts) {
    AttemptRecord next;
    next.version = current;
    next.attempts = used + 1;
    next.first_s = same && d.record.first_s ? d.record.first_s : NowS();
    next.last_s = NowS();
    next.last_error = same ? d.record.last_error : std::string{};
    auto wrote = WriteRecord(cfg, next);
    if (!wrote) {
      // A guard that cannot write its breadcrumb cannot protect the
      // next boot, and pretending otherwise is worse than saying so.
      // The load still goes ahead: refusing to start because a
      // filesystem is read-only would turn a degraded box into a dead
      // one.
      spdlog::error(
          "bundle guard: could not record this load attempt ({}). If "
          "this bundle takes the box down, the next boot will try it "
          "again -- there is nothing on disk to stop it.",
          wrote.error());
    }
    d.verdict = GuardVerdict::kProceed;
    d.version = current;
    d.load_dir = (fs::path(cfg.bundle_dir) / current).string();
    if (used > 0) {
      d.reason = std::format(
          "bundle '{}' has been started {} time(s) without the "
          "datapath ever coming up; this is attempt {} of {}{}",
          current, used, used + 1, cfg.max_attempts,
          d.record.last_error.empty()
              ? std::string{}
              : std::format(". Last failure: {}", d.record.last_error));
    }
    return d;
  }

  // Quarantine. Note that this is reached without the bundle having
  // been touched, which is the point: whatever it does to this box, it
  // does not get to do it a third time.
  d.quarantined = current;
  auto lkg = LastKnownGood(cfg.bundle_dir);
  const std::string history =
      d.record.last_error.empty()
          ? std::string(
                "the daemon never lived long enough to say why -- the "
                "load took the box with it")
          : std::format("last failure: {}", d.record.last_error);

  if (cfg.policy == GuardPolicy::kFailClosed || lkg.empty() ||
      lkg == current) {
    d.verdict = GuardVerdict::kRefuse;
    d.reason = std::format(
        "bundle '{}' has been started {} times and the datapath never "
        "came up ({}). It will not be tried again. Policy is '{}'{}. "
        "Point {}/current at a bundle that works, or compile a new "
        "one; `fd verify-bundle <dir>` answers whether the kernel will "
        "take it without making it current.",
        current, d.record.attempts, history,
        GuardPolicyName(cfg.policy),
        lkg.empty() || lkg == current
            ? " and there is no last-known-good to fall back to"
            : "",
        cfg.bundle_dir);
    return d;
  }

  d.verdict = GuardVerdict::kFallback;
  d.version = lkg;
  d.load_dir = (fs::path(cfg.bundle_dir) / lkg).string();
  // The fallback gets a breadcrumb of its own, starting at one. A
  // last-known-good that has stopped being good — a kernel upgrade
  // that no longer takes it, a pin it can no longer reuse — must be
  // counted from its first attempt too, or the box loops on the
  // fallback instead of on `current` and nothing is better.
  {
    AttemptRecord fresh;
    fresh.version = lkg;
    fresh.attempts = 1;
    fresh.first_s = NowS();
    fresh.last_s = fresh.first_s;
    fresh.last_error = std::format(
        "loaded as the fallback after '{}' was quarantined", current);
    auto wrote = WriteRecord(cfg, fresh);
    if (!wrote) {
      spdlog::error("bundle guard: could not record the fallback "
                    "attempt ({}).", wrote.error());
    }
  }
  d.reason = std::format(
      "bundle '{}' has been started {} times and the datapath never "
      "came up ({}). Falling back to last-known-good '{}'. THIS BOX IS "
      "NOT RUNNING THE POLICY IT WAS LAST GIVEN.",
      current, d.record.attempts, history, lkg);
  return d;
}

auto BundleGuardCommit(const GuardConfig& cfg,
                       const std::string& version)
    -> std::expected<void, std::string> {
  if (cfg.bundle_dir.empty()) {
    return std::unexpected("no bundle directory");
  }
  std::error_code ec;
  fs::remove(RecordPath(cfg), ec);
  if (version.empty() || version == kCurrentLink) {
    // Nothing nameable to remember. Clearing the attempt record is
    // still right: this start worked.
    return {};
  }
  fs::path root(cfg.bundle_dir);
  auto link = root / kLkgLink;
  auto tmp = root / ".last-known-good.new";
  fs::remove(tmp, ec);
  fs::create_symlink(version, tmp, ec);
  if (ec) {
    return std::unexpected(
        std::format("symlink {}: {}", tmp.string(), ec.message()));
  }
  fs::rename(tmp, link, ec);
  if (ec) {
    fs::remove(tmp, ec);
    return std::unexpected(
        std::format("rename {}: {}", link.string(), ec.message()));
  }
  int dir_fd = ::open(root.c_str(), O_RDONLY | O_DIRECTORY);
  if (dir_fd >= 0) {
    ::fsync(dir_fd);
    ::close(dir_fd);
  }
  return {};
}

auto BundleGuardNoteFailure(const GuardConfig& cfg,
                            const std::string& version,
                            const std::string& why) -> void {
  auto r = ReadAttemptRecord(cfg);
  if (!r.present || r.version != version) {
    // A record for some other version says nothing about this one.
    // Start a fresh one at a single failed attempt rather than
    // inheriting a count that was counting something else.
    r = AttemptRecord{};
    r.version = version;
    r.attempts = 1;
    r.first_s = NowS();
    r.present = true;
  }
  r.last_s = NowS();
  r.last_error = why;
  auto wrote = WriteRecord(cfg, r);
  if (!wrote) {
    spdlog::warn("bundle guard: could not record why '{}' failed: {}",
                 version, wrote.error());
  }
}

}  // namespace f
