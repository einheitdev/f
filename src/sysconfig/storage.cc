/// @file storage.cc
/// @brief Bundle retention, log quota, and what has been lost.

#include "f/sysconfig/storage.h"

#include <sys/statvfs.h>
#include <sys/wait.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <format>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace f::sysconfig {
namespace {

auto RunCapture(const std::string& cmd)
    -> std::pair<int, std::string> {
  std::string out;
  FILE* p = popen((cmd + " 2>/dev/null").c_str(), "r");
  if (p == nullptr) return {-1, ""};
  std::array<char, 512> buf{};
  while (std::fgets(buf.data(), buf.size(), p) != nullptr) {
    out += buf.data();
  }
  int rc = pclose(p);
  return {rc == -1 ? -1 : (WIFEXITED(rc) ? WEXITSTATUS(rc) : -1),
          out};
}

/// Bytes used by everything under `dir`. Symlinks are not followed:
/// `current` is one, and counting the bundle it points at twice would
/// make the reclaimable figure a lie.
auto DirectoryBytes(const std::filesystem::path& dir)
    -> std::uint64_t {
  std::uint64_t total = 0;
  std::error_code ec;
  for (auto it = std::filesystem::recursive_directory_iterator(
           dir, std::filesystem::directory_options::
                    skip_permission_denied,
           ec);
       it != std::filesystem::recursive_directory_iterator(); ) {
    if (ec) break;
    if (it->is_regular_file(ec)) {
      auto size = it->file_size(ec);
      if (!ec) total += size;
    }
    it.increment(ec);
  }
  return total;
}

}  // namespace

auto PlanRetention(const RetentionPolicy& policy) -> RetentionPlan {
  RetentionPlan plan;
  std::error_code ec;
  std::filesystem::path root(policy.compiled_dir);
  if (!std::filesystem::exists(root, ec)) {
    plan.unreadable_reason =
        std::format("{} does not exist", policy.compiled_dir);
    return plan;
  }

  // Where `current` points, resolved once. A bundle is never removed
  // just because it is old: deleting the running policy to save disk
  // space would be an outage caused by tidying up.
  std::string current;
  auto link = root / "current";
  if (std::filesystem::is_symlink(link, ec)) {
    auto target = std::filesystem::read_symlink(link, ec);
    if (!ec) current = target.filename().string();
  }

  std::vector<BundleEntry> entries;
  for (const auto& e :
       std::filesystem::directory_iterator(root, ec)) {
    if (ec) break;
    if (std::filesystem::is_symlink(e.path(), ec)) continue;
    if (!e.is_directory(ec)) continue;
    BundleEntry b;
    b.name = e.path().filename().string();
    b.path = e.path().string();
    b.is_current = (b.name == current);
    b.bytes = DirectoryBytes(e.path());
    auto t = std::filesystem::last_write_time(e.path(), ec);
    if (!ec) {
      b.mtime = std::chrono::duration_cast<std::chrono::seconds>(
                    t.time_since_epoch())
                    .count();
    }
    entries.push_back(std::move(b));
  }
  plan.readable = true;

  // Newest first. Version ids are timestamps, so the name is a better
  // ordering than mtime — a file touched by a backup does not make a
  // bundle newer than one compiled after it.
  std::sort(entries.begin(), entries.end(),
            [](const BundleEntry& a, const BundleEntry& b) {
              if (a.name != b.name) return a.name > b.name;
              return a.mtime > b.mtime;
            });

  std::size_t kept = 0;
  for (auto& b : entries) {
    plan.total_bytes += b.bytes;
    bool keep = b.is_current || kept < policy.keep;
    if (keep) {
      if (!b.is_current || kept < policy.keep) ++kept;
    } else {
      plan.reclaimable_bytes += b.bytes;
      plan.to_remove.push_back(b);
    }
    plan.bundles.push_back(std::move(b));
  }
  return plan;
}

auto PruneBundles(const RetentionPolicy& policy)
    -> std::expected<PruneReport, std::string> {
  auto plan = PlanRetention(policy);
  if (!plan.readable) return std::unexpected(plan.unreadable_reason);

  PruneReport report;
  for (const auto& b : plan.to_remove) {
    std::error_code ec;
    std::filesystem::remove_all(b.path, ec);
    if (ec) {
      report.failed.push_back(
          std::format("{}: {}", b.path, ec.message()));
      continue;
    }
    report.removed.push_back(b.name);
    report.reclaimed_bytes += b.bytes;
  }
  return report;
}

auto PlanLogging(const LogPolicy& policy) -> LogPlan {
  LogPlan plan;
  plan.policy = policy;
  std::ostringstream o;
  o << "# journald limits for the f appliance.\n"
    << "#\n"
    << "# GENERATED FROM THE f STORAGE POLICY.\n"
    << "# Do not edit; edits are reported as drift, not merged.\n"
    << "#\n"
    << "# An appliance that fills its own disk stops working, and it\n"
    << "# will do it at the office rather than on the bench. These\n"
    << "# caps are what bounds that.\n"
    << "\n"
    << "[Journal]\n"
    << "Storage=persistent\n"
    << std::format("SystemMaxUse={}\n", policy.max_use)
    << std::format("SystemMaxFileSize={}\n", policy.max_file_size)
    << std::format("SystemKeepFree={}\n", policy.keep_free)
    << "\n"
    << "# Rate limiting, stated rather than defaulted.\n"
    << "#\n"
    << "# journald ships a limiter that discards a burst and records\n"
    << "# only 'Suppressed N messages'. A burst is exactly what a\n"
    << "# broadcast storm looks like, so the default trades away the\n"
    << "# minute most worth having. Burst=0 disables the limiter: the\n"
    << "# disk cap above is then the only bound, which is the right\n"
    << "# trade for a box whose purpose is recording what happened on\n"
    << "# a hostile segment.\n"
    << "#\n"
    << "# `f show storage` reports the suppression count either way,\n"
    << "# so a limiter that is on is never silently on.\n"
    << std::format("RateLimitIntervalSec={}\n",
                   policy.rate_limit_interval)
    << std::format("RateLimitBurst={}\n", policy.rate_limit_burst);
  plan.content = o.str();
  return plan;
}

auto StorageAvailabilityName(StorageAvailability a) -> std::string {
  switch (a) {
    case StorageAvailability::kObserved:
      return "observed";
    case StorageAvailability::kUnreadable:
      break;
  }
  return "the paths could not be read";
}

auto QueryStorage(const StorageSource& src) -> StorageReport {
  StorageReport report;

  auto plan = PlanRetention(src.retention);
  if (!plan.readable) {
    report.detail = plan.unreadable_reason;
  } else {
    report.availability = StorageAvailability::kObserved;
    report.bundle_count = plan.bundles.size();
    report.bundle_bytes = plan.total_bytes;
    report.bundles_over_policy = plan.to_remove.size();
  }

  struct statvfs vfs{};
  if (::statvfs(src.retention.compiled_dir.c_str(), &vfs) == 0) {
    report.fs_total_bytes =
        static_cast<std::uint64_t>(vfs.f_blocks) * vfs.f_frsize;
    report.fs_free_bytes =
        static_cast<std::uint64_t>(vfs.f_bavail) * vfs.f_frsize;
  }
  // The zeros left behind by a failed statvfs are not "a filesystem
  // with no space"; `Tight()` reads a zero total as "unknown" for
  // exactly this reason, and the availability above already says the
  // paths could not be read.

  if (!src.journal_usage_cmd.empty()) {
    auto [rc, out] = RunCapture(src.journal_usage_cmd);
    if (rc == 0) {
      // "Archived and active journals take up 96.0M in the file
      // system." Parse the number and unit rather than the sentence,
      // which systemd has reworded before.
      double value = 0;
      char unit = 0;
      auto pos = out.find_first_of("0123456789");
      if (pos != std::string::npos &&
          std::sscanf(out.c_str() + pos, "%lf%c", &value, &unit) >=
              1) {
        std::uint64_t mult = 1;
        switch (unit) {
          case 'K': mult = 1024ULL; break;
          case 'M': mult = 1024ULL * 1024; break;
          case 'G': mult = 1024ULL * 1024 * 1024; break;
          default: mult = 1; break;
        }
        report.journal_bytes =
            static_cast<std::uint64_t>(value * mult);
        report.journal_read = true;
      }
    }
  }

  if (!src.suppressed_cmd.empty()) {
    auto [rc, out] = RunCapture(src.suppressed_cmd);
    // grep-style commands exit 1 for "no matches", which is the good
    // outcome and must not read as a failed read.
    if (rc == 0 || rc == 1) {
      report.suppression_read = true;
      std::istringstream lines(out);
      std::string line;
      while (std::getline(lines, line)) {
        if (line.empty()) continue;
        ++report.suppression_bursts;
        // "Suppressed 4814 messages from session-151.scope" — the
        // count is in the message, so report what was actually lost
        // rather than how many times it happened.
        auto at = line.find("Suppressed ");
        if (at == std::string::npos) continue;
        report.suppressed_messages +=
            std::strtoull(line.c_str() + at + 11, nullptr, 10);
      }
    }
  }

  return report;
}

auto StorageWarningBanner(const StorageReport& report)
    -> std::string {
  std::string out;
  if (report.availability == StorageAvailability::kUnreadable) {
    out += std::format(
        "STORAGE COULD NOT BE READ{}{}. That is not the same as "
        "nothing being used, and it is not the same as nothing "
        "being lost.\n",
        report.detail.empty() ? "" : ": ", report.detail);
  }
  if (report.suppression_read && report.suppressed_messages > 0) {
    out += std::format(
        "LOG EVENTS HAVE BEEN DROPPED. journald's rate limiter "
        "discarded {} message(s) across {} burst(s) in the last 24 "
        "hours — the box stopped recording during exactly the "
        "intervals most worth having. Set RateLimitBurst=0 and "
        "re-apply.\n",
        report.suppressed_messages, report.suppression_bursts);
  }
  if (!report.suppression_read) {
    out +=
        "whether log events are being dropped could not be "
        "determined, which is not the same as none being dropped.\n";
  }
  if (report.Tight()) {
    out += std::format(
        "DISK IS {}% FULL. An appliance that fills its own disk "
        "stops working; run `prune` to reclaim old bundles.\n",
        report.fs_total_bytes == 0
            ? 0
            : 100 - (report.fs_free_bytes * 100 /
                     report.fs_total_bytes));
  }
  return out;
}

}  // namespace f::sysconfig
