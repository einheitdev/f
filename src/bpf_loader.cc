/// @file bpf_loader.cc
/// @brief BPF program loading, attaching, and map management.
///
/// Uses libbpf's generic object API so the build doesn't depend
/// on a generated skeleton header.  The skeleton path is preferred
/// when available, but this file compiles without bpftool.

#include "f/bpf_loader.h"

#include <arpa/inet.h>

#include <cerrno>
#include <cstring>
#include <filesystem>
#include <format>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <system_error>
#include <vector>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include "f/types.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <net/if.h>

namespace f {

namespace {

struct bpf_object* g_obj = nullptr;

// Objects opened by LoadProgramFromPath, keyed by their program fd.
// BpfHandles carries fds only (not the bpf_object*), so UnloadProgram
// uses this to find and close the right object on a hot-swap.
std::map<int, struct bpf_object*> g_path_objs;

auto FindMap(struct bpf_object* obj, const char* name)
    -> int {
  struct bpf_map* map = bpf_object__find_map_by_name(
      obj, name);
  return map ? bpf_map__fd(map) : -1;
}

}  // namespace

namespace {

auto BuildSearchPaths(std::string_view bundle_dir)
    -> std::vector<std::string> {
  std::vector<std::string> paths;
  if (!bundle_dir.empty()) {
    auto current_link =
        std::filesystem::path(bundle_dir) / "current" / "main.bpf.o";
    paths.push_back(current_link.string());
  }
  paths.emplace_back("fw.bpf.o");
  paths.emplace_back("build/fw.bpf.o");
  paths.emplace_back("../bpf/fw.bpf.o");
  paths.emplace_back("/usr/lib/f/fw.bpf.o");
  return paths;
}

}  // namespace

auto ResolveBpfObjPath(std::string_view bundle_dir) -> std::string {
  for (const auto& path : BuildSearchPaths(bundle_dir)) {
    std::error_code ec;
    if (std::filesystem::exists(path, ec) && !ec) {
      return path;
    }
  }
  return {};
}

auto LoadProgram(std::string_view bundle_dir)
    -> std::expected<BpfHandles, Error<BpfError>> {
  // Cold-boot bundle auto-load (Phase 2 hardening): when a bundle
  // directory is provided, prefer the symlink the reload pipeline
  // maintains. This lets a freshly-restarted daemon resume the
  // previously-compiled FWL program without going through a full
  // recompile cycle.
  std::string loaded_from = ResolveBpfObjPath(bundle_dir);
  if (!loaded_from.empty()) {
    g_obj = bpf_object__open(loaded_from.c_str());
  }

  if (!g_obj) {
    return MakeError(BpfError::kLoadFailed,
        "fw.bpf.o not found — compile the BPF program "
        "first (clang -target bpf)");
  }
  spdlog::info("Loaded BPF object from {}", loaded_from);

  int err = bpf_object__load(g_obj);
  if (err) {
    bpf_object__close(g_obj);
    g_obj = nullptr;
    return MakeError(BpfError::kLoadFailed,
        std::format("bpf_object__load failed: {}",
                    std::strerror(-err)));
  }

  // The v0.2 FWL emitter names the XDP entry point `fwl_prog`;
  // the legacy v0.1 `bpf/fw.bpf.c` uses `fw_prog`. Try the v0.2
  // name first so freshly-compiled bundles load, fall back to the
  // v0.1 name so the cold-boot search list (no bundle) still works.
  struct bpf_program* prog =
      bpf_object__find_program_by_name(g_obj, "fwl_prog");
  if (!prog) {
    prog = bpf_object__find_program_by_name(g_obj, "fw_prog");
  }
  if (!prog) {
    bpf_object__close(g_obj);
    g_obj = nullptr;
    return MakeError(BpfError::kLoadFailed,
        "neither fwl_prog nor fw_prog found in BPF object");
  }

  BpfHandles h;
  h.prog_fd = bpf_program__fd(prog);
  h.rules_a_fd = FindMap(g_obj, "rules_a");
  h.rules_b_fd = FindMap(g_obj, "rules_b");
  h.cidr_a_fd = FindMap(g_obj, "cidr_a");
  h.cidr_b_fd = FindMap(g_obj, "cidr_b");
  h.conntrack_fd = FindMap(g_obj, "conntrack");
  h.counters_fd = FindMap(g_obj, "counters");
  h.config_fd = FindMap(g_obj, "config");
  h.events_fd = FindMap(g_obj, "events");

  // Initialize config map with defaults.
  uint32_t key = 0;
  FwConfig cfg{};
  // Default ALLOW so we don't lock ourselves out before
  // rules are configured.
  cfg.default_action =
      static_cast<uint8_t>(Action::kAllow);
  cfg.active_table = 0;
  cfg.conntrack_enabled = 0;
  cfg.conntrack_timeout_s = 300;
  bpf_map_update_elem(h.config_fd, &key, &cfg, BPF_ANY);

  return h;
}

auto LoadProgramFromPath(std::string_view obj_path)
    -> std::expected<BpfHandles, Error<BpfError>> {
  // Open a fresh, independent object (not the cold-boot g_obj) so the
  // currently-running program stays loaded until the swap succeeds.
  std::string path(obj_path);
  struct bpf_object* obj = bpf_object__open(path.c_str());
  if (!obj) {
    return MakeError(BpfError::kLoadFailed,
        std::format("open {} failed", path));
  }
  int err = bpf_object__load(obj);
  if (err) {
    bpf_object__close(obj);
    return MakeError(BpfError::kLoadFailed,
        std::format("load {} failed: {}", path,
                    std::strerror(-err)));
  }
  // v0.2+ emitter names the entry `fwl_prog`; legacy is `fw_prog`.
  struct bpf_program* prog =
      bpf_object__find_program_by_name(obj, "fwl_prog");
  if (!prog) {
    prog = bpf_object__find_program_by_name(obj, "fw_prog");
  }
  if (!prog) {
    bpf_object__close(obj);
    return MakeError(BpfError::kLoadFailed,
        std::format("neither fwl_prog nor fw_prog in {}", path));
  }

  BpfHandles h;
  h.prog_fd = bpf_program__fd(prog);
  h.rules_a_fd = FindMap(obj, "rules_a");
  h.rules_b_fd = FindMap(obj, "rules_b");
  h.cidr_a_fd = FindMap(obj, "cidr_a");
  h.cidr_b_fd = FindMap(obj, "cidr_b");
  h.conntrack_fd = FindMap(obj, "conntrack");
  h.counters_fd = FindMap(obj, "counters");
  h.config_fd = FindMap(obj, "config");
  h.events_fd = FindMap(obj, "events");
  g_path_objs[h.prog_fd] = obj;
  return h;
}

auto UnloadProgram(const BpfHandles& h) -> void {
  auto it = g_path_objs.find(h.prog_fd);
  if (it != g_path_objs.end()) {
    bpf_object__close(it->second);
    g_path_objs.erase(it);
  }
}

auto AttachXdp(const BpfHandles& h, int ifindex)
    -> std::expected<void, Error<BpfError>> {
  int err = bpf_xdp_attach(
      ifindex, h.prog_fd, 0, nullptr);
  if (err) {
    return MakeError(BpfError::kAttachFailed,
        std::format("bpf_xdp_attach ifindex={} failed: {}",
                    ifindex, std::strerror(-err)));
  }
  return {};
}

auto DetachXdp(int ifindex)
    -> std::expected<void, Error<BpfError>> {
  int err = bpf_xdp_detach(ifindex, 0, nullptr);
  if (err) {
    return MakeError(BpfError::kDetachFailed,
        std::format("bpf_xdp_detach ifindex={} failed: {}",
                    ifindex, std::strerror(-err)));
  }
  return {};
}

auto ReplaceXdp(int ifindex, int new_prog_fd, int old_prog_fd)
    -> std::expected<void, Error<BpfError>> {
  // Atomic swap: the kernel replaces old_prog_fd with new_prog_fd on
  // ifindex in one operation, failing (EEXIST) if the currently
  // attached program is not old_prog_fd. This is the zero-drop hot
  // reload primitive. old_prog_fd < 0 means "attach if nothing is
  // there yet" (no REPLACE constraint).
  LIBBPF_OPTS(bpf_xdp_attach_opts, opts);
  __u32 flags = 0;
  if (old_prog_fd >= 0) {
    opts.old_prog_fd = old_prog_fd;
    flags = XDP_FLAGS_REPLACE;
  }
  int err = bpf_xdp_attach(ifindex, new_prog_fd, flags, &opts);
  if (err) {
    return MakeError(BpfError::kAttachFailed,
        std::format("replace xdp on ifindex={} failed: {}",
                    ifindex, std::strerror(-err)));
  }
  return {};
}

auto PinMaps(const BpfHandles& h,
             std::string_view pin_path)
    -> std::expected<void, Error<BpfError>> {
  std::error_code ec;
  std::filesystem::create_directories(pin_path, ec);
  if (ec) {
    return MakeError(BpfError::kLoadFailed,
        std::format("create pin path {}: {}",
                    pin_path, ec.message()));
  }
  std::string base(pin_path);

  struct MapPin {
    int fd;
    const char* name;
  };
  MapPin pins[] = {
      {h.rules_a_fd, "rules_a"},
      {h.rules_b_fd, "rules_b"},
      {h.cidr_a_fd, "cidr_a"},
      {h.cidr_b_fd, "cidr_b"},
      {h.conntrack_fd, "conntrack"},
      {h.counters_fd, "counters"},
      {h.config_fd, "config"},
      {h.events_fd, "events"},
  };

  for (const auto& p : pins) {
    // v0.2 FWL bundles don't carry the legacy rule-table /
    // conntrack maps (their machinery now lives per-rule inside
    // the program). FindMap returns -1 for absent maps; skip
    // pinning those rather than failing the whole step.
    if (p.fd < 0) continue;
    std::string path = base + "/" + p.name;
    int err = bpf_obj_pin(p.fd, path.c_str());
    if (err) {
      return MakeError(BpfError::kPinFailed,
          std::format("pin {} failed: {}",
                      path, std::strerror(-err)));
    }
  }
  return {};
}

auto UnpinMaps(std::string_view pin_path)
    -> std::expected<void, Error<BpfError>> {
  std::error_code ec;
  std::filesystem::remove_all(pin_path, ec);
  if (ec) {
    return MakeError(BpfError::kUnpinFailed,
        std::format("remove_all {} failed: {}",
                    pin_path, ec.message()));
  }
  return {};
}

// --- v0.4 § 6.2 multi-zone bundle loading ---------------------------

namespace {

// Loaded zone objects are kept alive for the daemon's lifetime, exactly
// like the single-program g_obj. Closing them would detach the maps.
std::vector<struct bpf_object*> g_zone_objs;

// v0.4 § 6.6: resolve the program to attach for one loaded zone object,
// wiring a split pipeline if present.
//
// A single-program zone exposes `fwl_prog`. A split zone instead holds
// N `fwl_stage_i` XDP programs chained through the `fwl_stages`
// prog_array; the daemon must populate that array (index i -> stage i's
// program fd) before attaching, then attach stage 0 as the pipeline
// entry. Returns the entry program, or nullptr if neither shape is
// found.
auto ResolveZoneEntryProgram(struct bpf_object* obj,
                             const std::string& zone)
    -> struct bpf_program* {
  struct bpf_program* prog =
      bpf_object__find_program_by_name(obj, "fwl_prog");
  if (prog) return prog;

  int arr_fd = FindMap(obj, "fwl_stages");
  if (arr_fd < 0) return nullptr;  // not a split object either

  struct bpf_program* entry = nullptr;
  int n_stages = 0;
  for (uint32_t i = 0;; ++i) {
    std::string name = "fwl_stage_" + std::to_string(i);
    struct bpf_program* stage =
        bpf_object__find_program_by_name(obj, name.c_str());
    if (!stage) break;
    int fd = bpf_program__fd(stage);
    if (i == 0) entry = stage;
    uint32_t key = i;
    uint32_t val = static_cast<uint32_t>(fd);
    if (bpf_map_update_elem(arr_fd, &key, &val, BPF_ANY) != 0) {
      spdlog::error("zone '{}' prog_array update stage {} failed", zone, i);
      return nullptr;
    }
    ++n_stages;
  }
  if (entry) {
    spdlog::info("zone '{}' split pipeline: {} stages wired", zone,
                 n_stages);
  }
  return entry;
}

// Resolve a zone's interface names to ifindexes. Absent interfaces
// (if_nametoindex == 0) are skipped with a warning rather than failing
// the load — a zone's NIC may appear after boot.
auto ResolveZoneIfindexes(const std::vector<std::string>& ifaces)
    -> std::vector<int> {
  std::vector<int> out;
  for (const auto& name : ifaces) {
    unsigned int idx = if_nametoindex(name.c_str());
    if (idx == 0) {
      spdlog::warn("zone interface '{}' not present yet; skipping", name);
      continue;
    }
    out.push_back(static_cast<int>(idx));
  }
  return out;
}

}  // namespace

auto ParseGeoipFile(std::string_view bundle_dir)
    -> std::expected<GeoipTries, Error<BpfError>> {
  using nlohmann::json;
  std::filesystem::path path =
      std::filesystem::path(bundle_dir) / "geoip.json";
  GeoipTries tries;
  std::ifstream gf(path);
  if (!gf) {
    // Absent file: the bundle has no geoip() calls.
    return tries;
  }
  std::stringstream ss;
  ss << gf.rdbuf();
  json doc;
  try {
    doc = json::parse(ss.str());
  } catch (const std::exception& e) {
    return MakeError(BpfError::kLoadFailed,
        std::format("parse geoip.json: {}", e.what()));
  }
  for (const auto& t : doc.value("tries", json::array())) {
    std::string map_name = t.at("map").get<std::string>();
    bool v6 = t.value("family", "ipv4") == "ipv6";
    std::vector<GeoipTrieEntry>& entries = tries[map_name];
    for (const auto& p : t.value("prefixes", json::array())) {
      std::string cidr = p.get<std::string>();
      auto slash = cidr.find('/');
      if (slash == std::string::npos) {
        return MakeError(BpfError::kLoadFailed,
            std::format("geoip.json prefix '{}' has no /len", cidr));
      }
      GeoipTrieEntry entry;
      entry.v6 = v6;
      entry.prefixlen = static_cast<uint32_t>(
          std::stoul(cidr.substr(slash + 1)));
      std::string addr = cidr.substr(0, slash);
      int rc = v6
          ? inet_pton(AF_INET6, addr.c_str(), entry.addr)
          : inet_pton(AF_INET, addr.c_str(), entry.addr);
      if (rc != 1) {
        return MakeError(BpfError::kLoadFailed,
            std::format("geoip.json address '{}' unparseable", addr));
      }
      uint32_t max_len = v6 ? 128 : 32;
      if (entry.prefixlen > max_len) {
        return MakeError(BpfError::kLoadFailed,
            std::format("geoip.json prefix '{}' length out of range",
                        cidr));
      }
      entries.push_back(entry);
    }
  }
  return tries;
}

namespace {

/// Insert one trie's entries into a loaded zone object's map. Pinned
/// by-name maps are shared across zone objects, so `done` dedupes.
auto PopulateGeoipTrie(struct bpf_object* obj,
                       const std::string& map_name,
                       const std::vector<GeoipTrieEntry>& entries,
                       std::set<std::string>& done) -> void {
  if (done.contains(map_name)) {
    return;
  }
  int map_fd = FindMap(obj, map_name.c_str());
  if (map_fd < 0) {
    return;
  }
  done.insert(map_name);
  uint8_t one = 1;
  size_t written = 0;
  for (const auto& e : entries) {
    // Kernel LPM key: __u32 prefixlen (host order) + address bytes.
    uint8_t key[20] = {};
    std::memcpy(key, &e.prefixlen, sizeof(e.prefixlen));
    std::memcpy(key + 4, e.addr, e.v6 ? 16 : 4);
    if (bpf_map_update_elem(map_fd, key, &one, BPF_ANY) == 0) {
      written++;
    }
  }
  spdlog::info("geoip trie '{}': {} of {} prefixes loaded", map_name,
               written, entries.size());
}

}  // namespace

auto LoadZoneBundle(std::string_view bundle_dir,
                    std::string_view pin_root)
    -> std::expected<ZoneBundleHandles, Error<BpfError>> {
  using nlohmann::json;
  std::filesystem::path dir(bundle_dir);

  auto geoip = ParseGeoipFile(bundle_dir);
  if (!geoip) {
    return std::unexpected(geoip.error());
  }
  std::set<std::string> geoip_done;

  std::ifstream mf(dir / "manifest.json");
  if (!mf) {
    return MakeError(BpfError::kLoadFailed,
        std::format("open {}/manifest.json failed", bundle_dir));
  }
  std::stringstream ss;
  ss << mf.rdbuf();
  json manifest;
  try {
    manifest = json::parse(ss.str());
  } catch (const std::exception& e) {
    return MakeError(BpfError::kLoadFailed,
        std::format("parse manifest.json: {}", e.what()));
  }

  // zone name -> resolved ifindexes (egress targets for redirect, and
  // ingress interfaces to attach each program to).
  std::map<std::string, std::vector<int>> zone_ifindexes;
  for (const auto& z : manifest.value("zones", json::array())) {
    std::vector<std::string> ifaces;
    for (const auto& i : z.value("interfaces", json::array())) {
      ifaces.push_back(i.get<std::string>());
    }
    zone_ifindexes[z.at("name").get<std::string>()] =
        ResolveZoneIfindexes(ifaces);
  }

  // Common pin root so LIBBPF_PIN_BY_NAME maps (conntrack, devmaps)
  // resolve to one kernel map across every zone object. Fails without
  // privileges (bpffs is root-owned) — surface that as a load error
  // rather than an exception.
  std::string pin_root_str(pin_root);
  std::error_code ec;
  std::filesystem::create_directories(pin_root_str, ec);
  if (ec) {
    return MakeError(BpfError::kLoadFailed,
        std::format("create pin root {}: {}",
                    pin_root_str, ec.message()));
  }

  ZoneBundleHandles handles;
  for (const auto& p : manifest.value("programs", json::array())) {
    if (p.value("object", json()).is_null()) {
      // The bundle was emitted without a compiled object (clang
      // unavailable at compile time); nothing to load for this zone.
      spdlog::warn("zone '{}' has no compiled object; skipping",
                   p.value("zone", std::string{}));
      continue;
    }
    std::string zone = p.at("zone").get<std::string>();
    std::string obj_name = p.at("object").get<std::string>();
    std::string obj_path = (dir / obj_name).string();

    LIBBPF_OPTS(bpf_object_open_opts, open_opts);
    open_opts.pin_root_path = pin_root_str.c_str();
    struct bpf_object* obj =
        bpf_object__open_file(obj_path.c_str(), &open_opts);
    if (!obj) {
      return MakeError(BpfError::kLoadFailed,
          std::format("open {} failed", obj_path));
    }
    int err = bpf_object__load(obj);
    if (err) {
      bpf_object__close(obj);
      return MakeError(BpfError::kLoadFailed,
          std::format("load {} failed: {}", obj_path,
                      std::strerror(-err)));
    }
    g_zone_objs.push_back(obj);

    // v0.4 § 6.6: `fwl_prog` for a single-program zone, or the wired
    // `fwl_stage_0` entry of a split tail-call pipeline.
    struct bpf_program* prog = ResolveZoneEntryProgram(obj, zone);
    if (!prog) {
      return MakeError(BpfError::kLoadFailed,
          std::format("no fwl_prog / fwl_stage_0 entry in {}", obj_path));
    }

    ZoneProgramHandle zh;
    zh.zone = zone;
    zh.prog_fd = bpf_program__fd(prog);

    // Capture the shared conntrack fd from whichever zone defines it.
    if (handles.conntrack_fd < 0) {
      int ct = FindMap(obj, "conntrack");
      if (ct >= 0) handles.conntrack_fd = ct;
    }

    // Populate this object's geoip LPM tries from the bundle's
    // geoip.json (no-op for bundles without geoip() calls).
    for (const auto& [map_name, entries] : *geoip) {
      PopulateGeoipTrie(obj, map_name, entries, geoip_done);
    }

    // Populate each redirect destination's devmap with that zone's
    // egress ifindexes (key i -> ifindex of the i-th interface).
    for (const auto& dest : p.value("redirects_to", json::array())) {
      std::string dest_zone = dest.get<std::string>();
      std::string map_name = "fwl_devmap_" + dest_zone;
      int map_fd = FindMap(obj, map_name.c_str());
      if (map_fd < 0) continue;
      const auto& targets = zone_ifindexes[dest_zone];
      for (uint32_t i = 0; i < targets.size(); ++i) {
        uint32_t key = i;
        uint32_t val = static_cast<uint32_t>(targets[i]);
        bpf_map_update_elem(map_fd, &key, &val, BPF_ANY);
      }
      spdlog::info("zone '{}' devmap -> '{}' ({} ifaces)", zone,
                   dest_zone, targets.size());
    }

    // Attach the program to every interface in its own zone.
    for (int ifindex : zone_ifindexes[zone]) {
      int aerr = bpf_xdp_attach(ifindex, zh.prog_fd, 0, nullptr);
      if (aerr) {
        return MakeError(BpfError::kAttachFailed,
            std::format("attach zone '{}' to ifindex {} failed: {}",
                        zone, ifindex, std::strerror(-aerr)));
      }
      zh.ifindexes.push_back(ifindex);
    }
    spdlog::info("loaded zone '{}' ({}) on {} interface(s)", zone,
                 obj_name, zh.ifindexes.size());
    handles.programs.push_back(std::move(zh));
  }

  return handles;
}

auto IsMultiZoneBundle(std::string_view bundle_dir) -> bool {
  using nlohmann::json;
  std::filesystem::path dir(bundle_dir);
  std::ifstream mf(dir / "manifest.json");
  if (!mf) {
    return false;
  }
  std::stringstream ss;
  ss << mf.rdbuf();
  json manifest;
  try {
    manifest = json::parse(ss.str());
  } catch (const std::exception&) {
    return false;
  }
  // A v0.4 bundle carries a non-empty "programs" array (one entry
  // per @xdp block); the legacy single-program manifest has none.
  // "zones" stays empty when the source declares no named zones, so
  // it must not gate the routing signal for the cold-boot and
  // hot-reload paths.
  return !manifest.value("programs", json::array()).empty();
}

auto DetachZoneBundle(const ZoneBundleHandles& handles) -> void {
  for (const auto& prog : handles.programs) {
    for (int ifindex : prog.ifindexes) {
      int err = bpf_xdp_detach(ifindex, 0, nullptr);
      if (err) {
        spdlog::warn("detach zone '{}' from ifindex {} failed: {}",
                     prog.zone, ifindex, std::strerror(-err));
      }
    }
  }
}

}  // namespace f
