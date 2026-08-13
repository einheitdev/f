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

namespace {

/// Atomically swap XDP on every attached interface from
/// `old_prog_fd` to `new_prog_fd`. On first failure, roll
/// back any interfaces that already flipped.
auto SwapXdpEverywhere(Engine& e,
                       int old_prog_fd,
                       int new_prog_fd)
    -> std::expected<void, Error<ReloadError>> {
  std::vector<int> flipped;
  for (uint32_t i = 0; i < e.ifaces.count; i++) {
    int ifindex = e.ifaces.interfaces[i].ifindex;
    auto r = ReplaceXdp(ifindex, new_prog_fd, old_prog_fd);
    if (!r) {
      // Roll back any interfaces already on the new prog.
      for (int done : flipped) {
        ReplaceXdp(done, old_prog_fd, new_prog_fd);
      }
      return MakeError(ReloadError::kApplyFailed,
                       r.error().message);
    }
    flipped.push_back(ifindex);
  }
  return {};
}

}  // namespace

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
    ReloadResult out{};
    out.version = manifest["version"].get<std::string>();
    out.rules_installed = 0;
    out.program_updated = true;
    spdlog::info("reload: multi-zone bundle hot-swapped, "
                 "{} zone program(s), atomic swap",
                 e.zone_bundle.programs.size());
    return out;
  }

  // Read rules.json.
  auto rules_txt = ReadFileAll(dir / "rules.json");
  if (!rules_txt) {
    return MakeError(ReloadError::kRulesInvalid,
                     rules_txt.error());
  }
  json rules;
  try {
    rules = json::parse(*rules_txt);
  } catch (const std::exception& ex) {
    return MakeError(ReloadError::kRulesInvalid,
                     std::format("parse rules: {}",
                                 ex.what()));
  }

  // Translate to ConfigMsg + rule_data blob.
  ConfigMsg msg{};
  msg.default_action = rules.value("default_action", 1);
  msg.conntrack_enabled = rules.value("conntrack_enabled", 0);
  msg.conntrack_timeout_s =
      rules.value("conntrack_timeout_s", 300);

  std::vector<std::byte> rule_data;
  uint32_t count = 0;
  if (rules.contains("rules") && rules["rules"].is_array()) {
    for (const auto& r : rules["rules"]) {
      // Only exact entries are applied here; CIDR entries are
      // deferred until LPM-map loading lands in the engine.
      if (r.value("type", std::string()) != "exact") {
        continue;
      }
      const auto& k = r["key"];
      const auto& v = r["value"];
      RuleKey key{};
      key.src_addr = k.value("src_addr", 0u);
      key.dst_addr = k.value("dst_addr", 0u);
      key.src_port = k.value("src_port", 0);
      key.dst_port = k.value("dst_port", 0);
      key.proto = k.value("proto", 0);
      RuleValue val{};
      val.action = v.value("action", 0);
      val.rate_pps = v.value("rate_pps", 0u);
      auto* kp = reinterpret_cast<const std::byte*>(&key);
      rule_data.insert(rule_data.end(), kp, kp + sizeof(key));
      auto* vp = reinterpret_cast<const std::byte*>(&val);
      rule_data.insert(rule_data.end(), vp, vp + sizeof(val));
      count++;
    }
  }
  msg.rule_count = count;

  auto res = ApplyConfig(e, msg, rule_data);
  if (!res) {
    return MakeError(ReloadError::kApplyFailed,
                     res.error().message);
  }

  ReloadResult out{};
  out.version = manifest["version"].get<std::string>();
  out.rules_installed = *res;
  out.program_updated = false;

  // If the bundle includes a compiled BPF program, hot-swap it.
  if (manifest.value("has_program", false)
      && manifest.contains("program")) {
    std::string rel = manifest["program"].value(
        "path", std::string("main.bpf.o"));
    auto obj_path = (dir / rel).string();

    auto new_bpf = LoadProgramFromPath(obj_path);
    if (!new_bpf) {
      return MakeError(
          ReloadError::kApplyFailed,
          std::format("load {}: {}", obj_path,
                      new_bpf.error().message));
    }

    auto swap = SwapXdpEverywhere(
        e, e.bpf.prog_fd, new_bpf->prog_fd);
    if (!swap) {
      UnloadProgram(*new_bpf);
      return std::unexpected(swap.error());
    }

    // Succeeded: release the old program, promote the new
    // handles to the engine. Note that pinned maps on the
    // filesystem may now be out of sync with the active
    // program — coordinating that is a future decision.
    UnloadProgram(e.bpf);
    e.bpf = *new_bpf;
    out.program_updated = true;
  }

  return out;
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
  spdlog::info(
      "reload: ok version={} rules_installed={}",
      applied->version, applied->rules_installed);
  return applied;
}

}  // namespace f
