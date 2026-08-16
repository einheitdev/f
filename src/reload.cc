/// @file reload.cc
/// @brief Reload pipeline implementation.

#include "f/reload.h"

#include <spawn.h>
#include <sys/wait.h>
#include <net/if.h>
#include <unistd.h>

#include <chrono>
#include <cstring>
#include <filesystem>
#include <format>
#include <fstream>
#include <set>
#include <sstream>
#include <vector>

#include "f/sysconfig/storage.h"

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include "f/engine.h"

extern char** environ;

namespace f {
namespace {

using json = nlohmann::json;

auto ReadFileAll(const std::filesystem::path& p)
    -> std::expected<std::string, std::string> {
  std::ifstream in(p, std::ios::in | std::ios::binary);
  if (!in) {
    return std::unexpected(
        std::format("open {} failed", p.string()));
  }
  std::ostringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

/// Generate a UTC version string: 20260414T200000Z.
auto MakeVersionId() -> std::string {
  auto now = std::chrono::system_clock::now();
  auto t = std::chrono::system_clock::to_time_t(now);
  struct tm tm_utc{};
  gmtime_r(&t, &tm_utc);
  char buf[32];
  std::strftime(buf, sizeof(buf), "%Y%m%dT%H%M%SZ", &tm_utc);
  return buf;
}

/// Update /path/current → /path/<version> atomically.
auto UpdateCurrentSymlink(const std::filesystem::path& compiled_dir,
                          std::string_view version) -> void {
  auto link = compiled_dir / "current";
  auto tmp = compiled_dir / ".current.new";
  std::error_code ec;
  std::filesystem::remove(tmp, ec);
  std::filesystem::create_symlink(version, tmp, ec);
  if (ec) {
    spdlog::warn("reload: create symlink {}: {}",
                 tmp.string(), ec.message());
    return;
  }
  std::filesystem::rename(tmp, link, ec);
  if (ec) {
    spdlog::warn("reload: rename symlink {}: {}",
                 link.string(), ec.message());
    std::filesystem::remove(tmp);
  }
}

}  // namespace

auto RunCompiler(std::string_view fwl_path,
                 std::string_view source_path,
                 std::string_view output_dir)
    -> std::expected<std::string, Error<ReloadError>> {
  // Build argv: fwl compile <source> --bundle <output_dir>
  // [--geoip /etc/f/geoip.json]. The geoip data file is passed
  // whenever the conventional path exists — the compiler ignores it
  // for programs without geoip(), and a geoip() program without it
  // is a hard compile error (silently empty tries never match).
  std::string fwl(fwl_path);
  std::string src(source_path);
  std::string out(output_dir);
  static const std::string kGeoipData = "/etc/f/geoip.json";
  std::vector<char*> argv{
      fwl.data(),
      const_cast<char*>("compile"),
      src.data(),
      const_cast<char*>("--bundle"),
      out.data(),
  };
  if (std::filesystem::exists(kGeoipData)) {
    argv.push_back(const_cast<char*>("--geoip"));
    argv.push_back(const_cast<char*>(kGeoipData.c_str()));
  }
  argv.push_back(nullptr);

  // Pipe for capturing stdout (error context on failure).
  int stdout_pipe[2] = {-1, -1};
  if (pipe(stdout_pipe) != 0) {
    return MakeError(ReloadError::kSpawnFailed,
                     std::format("pipe: {}", strerror(errno)));
  }

  posix_spawn_file_actions_t actions;
  posix_spawn_file_actions_init(&actions);
  posix_spawn_file_actions_adddup2(
      &actions, stdout_pipe[1], STDOUT_FILENO);
  posix_spawn_file_actions_addclose(&actions, stdout_pipe[0]);
  posix_spawn_file_actions_addclose(&actions, stdout_pipe[1]);

  pid_t pid = 0;
  int rc = posix_spawnp(&pid, fwl.c_str(),
                        &actions, nullptr,
                        argv.data(), environ);
  posix_spawn_file_actions_destroy(&actions);
  close(stdout_pipe[1]);

  if (rc != 0) {
    close(stdout_pipe[0]);
    return MakeError(
        ReloadError::kSpawnFailed,
        std::format("spawn {}: {}", fwl, strerror(rc)));
  }

  // Drain stdout.
  std::string stdout_buf;
  char chunk[4096];
  ssize_t n;
  while ((n = read(stdout_pipe[0], chunk, sizeof(chunk))) > 0) {
    stdout_buf.append(chunk, static_cast<size_t>(n));
  }
  close(stdout_pipe[0]);

  int status = 0;
  waitpid(pid, &status, 0);

  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    // Subprocess failed — envelope (if any) names the cause.
    std::string msg = stdout_buf.empty()
        ? std::format(
              "compile exit={}",
              WIFEXITED(status) ? WEXITSTATUS(status) : -1)
        : stdout_buf;
    return MakeError(ReloadError::kCompileFailed, std::move(msg));
  }

  return stdout_buf;
}

auto ApplyBundle(Engine& e, std::string_view bundle_dir)
    -> std::expected<ReloadResult, Error<ReloadError>> {
  std::filesystem::path dir(bundle_dir);

  // Read manifest for metadata + validation.
  auto manifest_txt = ReadFileAll(dir / "manifest.json");
  if (!manifest_txt) {
    return MakeError(ReloadError::kManifestInvalid,
                     manifest_txt.error());
  }
  json manifest;
  try {
    manifest = json::parse(*manifest_txt);
  } catch (const std::exception& ex) {
    return MakeError(ReloadError::kManifestInvalid,
                     std::format("parse manifest: {}",
                                 ex.what()));
  }
  if (!manifest.contains("version")) {
    return MakeError(ReloadError::kManifestInvalid,
                     "manifest missing version");
  }

  // v0.4 § 6.2: a multi-zone bundle carries its policy compiled into
  // per-zone BPF objects (one `<zone>.bpf.o` per @xdp block) and shared
  // bpffs-pinned maps — there is no rules.json / map-based rule set to
  // apply. Route it to the zone loader instead of the single-program
  // rule-application path below.
  if (IsMultiZoneBundle(dir.string())) {
    // Hot reload: swap each already-attached interface to the new
    // bundle's program atomically (XDP_FLAGS_REPLACE). Detaching
    // first would reset the NIC (igb drops the link for seconds) and
    // leave a policy-off window — measured on the i350 rig.
    //
    // The new objects need fresh policy-scoped maps (their shape and
    // their slot meanings follow the new policy); the flow-keyed pins
    // — conntrack, fwl_nat — stay, so established connections survive
    // the policy change. That preservation is the point of the
    // distinction and must not be traded away: a firewall that drops
    // every established connection when a rule is edited is not
    // reloadable in production.
    //
    // kReload: a pin whose definition the new bundle disagrees with is
    // NOT removed here. The currently attached policy is still running
    // and is a real fallback, so the load is allowed to fail and say
    // which map and which numbers — see PinPolicy for why cold boot
    // decides that trade the other way.
    auto pins = ReconcilePinnedMaps(dir.string(), e.pin_path,
                                    PinPolicy::kReload,
                                    e.conntrack.timeout_s);
    spdlog::info("reload: pins adopted={} discarded={}",
                 pins.adopted.size(), pins.discarded.size());
    const ZoneBundleHandles* old =
        e.zone_bundle.programs.empty() ? nullptr : &e.zone_bundle;
    auto loaded = LoadZoneBundle(dir.string(), e.pin_path, old);
    if (!loaded) {
      // The old bundle is still attached and intact.
      return MakeError(ReloadError::kApplyFailed,
                       std::format("LoadZoneBundle: {}",
                                   loaded.error().message));
    }
    // Interfaces the old bundle covered but the new one does not:
    // nothing replaced them, detach explicitly.
    std::set<int> covered;
    for (const auto& np : loaded->programs) {
      covered.insert(np.ifindexes.begin(), np.ifindexes.end());
    }
    for (const auto& op : e.zone_bundle.programs) {
      for (int idx : op.ifindexes) {
        if (!covered.contains(idx)) {
          DetachXdp(idx);
          // Both attach points come off together. The new tracker was
          // attached to the interfaces the new bundle covers, so this
          // one still carries the OLD bundle's filter — a tracker with
          // no bundle behind it, writing conntrack entries that the
          // policy which would have read them is no longer on. The
          // qdisc goes with it when this daemon is the one that made
          // it; the old tracker's own record is what says so.
          RemoveEgressFrom(idx, e.zone_bundle.egress);
        }
      }
    }
    CloseZoneBundle(e.zone_bundle);
    e.zone_bundle = *loaded;
    if (e.zone_bundle.conntrack_fd >= 0) {
      e.conntrack.map_fd = e.zone_bundle.conntrack_fd;
      // Mirror EngineInit: a reload must not leave GC switched off
      // (see the note there — it never ran in bundle mode at all).
      e.conntrack.enabled = true;
    }
    // Same reason, same defect class: the NAT table's fds belong to the
    // bundle that was just swapped in. Left pointing at the old
    // bundle's maps, the sweep would collect a table nothing is using
    // and the status section would report it — the map is FLOW-lifetime
    // and its pin is adopted, so the numbers would look plausible.
    AttachNatMgr(e);
    // Same reason, second attach point. Left out, `e.egress.stats_fd`
    // still pointed into the object CloseZoneBundle had just closed:
    // every egress counter in `fctl status` read 0 for the rest of the
    // process's life and EgressMgr::Report could never fire, so the one
    // failure this whole feature exists to surface — a refused insert
    // because conntrack is full — was permanently silent after the
    // first reload. The manager's own doc comment said it was called
    // from both places; it was not.
    AttachEgressMgr(e, dir.string());
    // Re-derive the tracked interface list from the bundle that is
    // now attached. Leaving it stale made `fctl status` describe the
    // boot-time topology forever, and gave EngineStop the wrong set
    // to detach.
    e.ifaces.count = 0;
    for (const auto& prog : e.zone_bundle.programs) {
      for (int idx : prog.ifindexes) {
        if (e.ifaces.count >= sizeof(e.ifaces.interfaces) /
                                  sizeof(e.ifaces.interfaces[0])) {
          break;
        }
        auto& entry = e.ifaces.interfaces[e.ifaces.count];
        entry.ifindex = idx;
        if_indextoname(static_cast<unsigned int>(idx), entry.name);
        e.ifaces.count++;
      }
    }
    // Third site of the defect the two calls above document, and it
    // was the one still open: RouteMgr was attached at cold boot only.
    // After a reload `stats_fd` pointed into the object
    // `CloseZoneBundle` had just closed, so every routed/bridged
    // number in `fctl status` read 0 for the rest of the process's
    // life and `Report()` could never fire — and routed-versus-bridged
    // is invisible in a capture, so nothing else would have said so.
    // It also resets the watermarks, which a POLICY-lifetime map needs
    // (the new bundle counts from zero).
    AttachRouteMgr(e);
    // Fourth site, and it is deliberately here rather than folded into
    // the call above: the queue is a POLICY-lifetime map, so after a
    // reload it is a NEW kernel map and the old fd names a closed
    // object. Left stale, this daemon would drain a queue nothing
    // writes to and the box would go back to healing only by luck —
    // silently, because a queue that is always empty and a box with
    // nothing to resolve read identically.
    AttachNeighMgr(e);
    // The datapath just changed shape, so the forwarding decision is
    // re-taken from the interface count above. A reload that ends up
    // attached to nothing closes the box; there is no reload path that
    // leaves a stale "yes" behind.
    SetForwardingFromDatapath(e, "reload");
    ReloadResult out{};
    out.version = manifest["version"].get<std::string>();
    out.program_updated = true;
    // The interface count is the one that answers "is the new policy
    // in the packet path". A program count on its own read the same
    // whether every interface had been swapped or none had.
    spdlog::info("reload: multi-zone bundle hot-swapped, "
                 "{} zone program(s) on {} interface(s), atomic swap",
                 e.zone_bundle.programs.size(), e.ifaces.count);
    return out;
  }

  // There is no other kind of bundle. What followed here read
  // `rules.json` into a ConfigMsg, called ApplyConfig and hot-swapped a
  // `main.bpf.o` — the v0.1 single-program apply. `fwl compile
  // --bundle` writes neither file: the grammar requires at least one
  // `@xdp` block (`program : zone_decl* function_def* xdp_block+`), so
  // `programs` is never empty and IsMultiZoneBundle is never false for
  // anything the compiler produces. Reaching here means the manifest
  // came from somewhere else.
  return MakeError(
      ReloadError::kManifestInvalid,
      std::format(
          "{} has a manifest with no @xdp programs in it. Every bundle "
          "`fwl compile --bundle` writes names at least one; this one "
          "was not written by it. The running policy is untouched.",
          dir.string()));
}

auto ReloadFromSource(Engine& e)
    -> std::expected<ReloadResult, Error<ReloadError>> {
  if (e.watcher.source_path.empty()
      || e.watcher.compiled_dir.empty()) {
    return MakeError(ReloadError::kIoError,
                     "watcher not configured");
  }

  auto version = MakeVersionId();
  auto bundle_dir =
      std::filesystem::path(e.watcher.compiled_dir) / version;

  std::error_code ec;
  std::filesystem::create_directories(bundle_dir, ec);
  if (ec) {
    return MakeError(
        ReloadError::kIoError,
        std::format("mkdir {}: {}",
                    bundle_dir.string(), ec.message()));
  }

  spdlog::info("reload: compiling {} -> {}",
               e.watcher.source_path, bundle_dir.string());

  // v0.4: `fwl compile --bundle` signals success via exit status
  // and the bundle's manifest.json (validated in ApplyBundle) —
  // there is no JSON envelope on stdout anymore.
  auto compiled = RunCompiler(
      e.watcher.fwl_path,
      e.watcher.source_path,
      bundle_dir.string());
  if (!compiled) {
    return std::unexpected(compiled.error());
  }

  auto applied = ApplyBundle(e, bundle_dir.string());
  if (!applied) {
    return std::unexpected(applied.error());
  }

  UpdateCurrentSymlink(e.watcher.compiled_dir, version);

  // Bound the set here, because here is where it grows. Every reload
  // writes a new timestamped bundle and nothing ever removed the old
  // ones — the rig accumulated ~500. Pruning after the symlink move
  // means the running policy is already `current` and therefore
  // never a candidate: tidying up must not be able to cause an
  // outage. A failure to prune is logged and not propagated, because
  // a reload that worked did work.
  sysconfig::RetentionPolicy retention;
  retention.compiled_dir = e.watcher.compiled_dir;
  auto pruned = sysconfig::PruneBundles(retention);
  if (!pruned) {
    spdlog::warn("reload: could not prune old bundles: {}",
                 pruned.error());
  } else if (!pruned->removed.empty()) {
    spdlog::info(
        "reload: pruned {} old bundle(s), {} KiB reclaimed "
        "(keeping {})",
        pruned->removed.size(), pruned->reclaimed_bytes / 1024,
        retention.keep);
  }
  for (const auto& f : pruned ? pruned->failed
                              : std::vector<std::string>{}) {
    spdlog::warn("reload: could not remove {}", f);
  }

  spdlog::info("reload: ok version={}", applied->version);
  return applied;
}

}  // namespace f
