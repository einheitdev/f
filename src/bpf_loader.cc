/// @file bpf_loader.cc
/// @brief BPF program loading, attaching, and map management.
///
/// Uses libbpf's generic object API so the build doesn't depend
/// on a generated skeleton header.  The skeleton path is preferred
/// when available, but this file compiles without bpftool.

#include "f/bpf_loader.h"

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netinet/in.h>

#include <sys/utsname.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <format>
#include <fstream>
#include <map>
#include <optional>
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
#include <sys/socket.h>

namespace f {

namespace {

auto FindMap(struct bpf_object* obj, const char* name)
    -> int {
  struct bpf_map* map = bpf_object__find_map_by_name(
      obj, name);
  return map ? bpf_map__fd(map) : -1;
}

// Attach an XDP program to `ifindex`, preferring native (driver) mode
// but falling back to generic (SKB) mode. Native is line-rate, but some
// NICs have no native XDP — notably the RTL8125 (`r8169`), which rejects
// a native attach outright — and there the program must run in generic
// mode to work at all. Returns 0 on success (sets *generic to whether
// the fallback was used), else the errno from the generic attempt.
auto AttachXdpFallback(int ifindex, int prog_fd, bool* generic) -> int {
  int err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_DRV_MODE, nullptr);
  if (!err) {
    if (generic) *generic = false;
    return 0;
  }
  int gerr = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, nullptr);
  if (!gerr) {
    if (generic) *generic = true;
    return 0;
  }
  return gerr;
}

}  // namespace

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

// --- v0.4 § 6.2 multi-zone bundle loading ---------------------------

namespace {

// Loaded zone objects are kept alive for the daemon's lifetime;
// closing one would detach its maps.

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

auto FirstZoneIpv4(const std::vector<std::string>& ifaces)
    -> uint32_t {
  struct ifaddrs* addrs = nullptr;
  if (getifaddrs(&addrs) != 0) {
    return 0;
  }
  uint32_t found = 0;
  for (const auto& want : ifaces) {
    for (struct ifaddrs* a = addrs; a != nullptr; a = a->ifa_next) {
      if (a->ifa_addr == nullptr ||
          a->ifa_addr->sa_family != AF_INET ||
          want != a->ifa_name) {
        continue;
      }
      found = reinterpret_cast<struct sockaddr_in*>(a->ifa_addr)
                  ->sin_addr.s_addr;
      break;
    }
    if (found != 0) {
      break;
    }
  }
  freeifaddrs(addrs);
  return found;
}

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

/// The shape a zone object declares for `map`, before it is loaded.
auto DeclaredShape(const struct bpf_map* map) -> PinnedMapShape {
  PinnedMapShape shape;
  shape.type = static_cast<uint32_t>(bpf_map__type(map));
  shape.key_size = bpf_map__key_size(map);
  shape.value_size = bpf_map__value_size(map);
  shape.max_entries = bpf_map__max_entries(map);
  shape.map_flags = bpf_map__map_flags(map);
  return shape;
}

/// The shape of the map already pinned at `path`, if one is there.
auto PinnedShape(const std::string& path)
    -> std::optional<PinnedMapShape> {
  int fd = bpf_obj_get(path.c_str());
  if (fd < 0) {
    return std::nullopt;
  }
  struct bpf_map_info info = {};
  uint32_t len = sizeof(info);
  int rc = bpf_map_get_info_by_fd(fd, &info, &len);
  ::close(fd);
  if (rc != 0) {
    return std::nullopt;
  }
  PinnedMapShape shape;
  shape.type = info.type;
  shape.key_size = info.key_size;
  shape.value_size = info.value_size;
  shape.max_entries = info.max_entries;
  shape.map_flags = info.map_flags;
  return shape;
}

/// Note which zone pinned each map name, so a later conflict can name
/// the zone the operator has to compare against rather than a path.
auto RecordPinnedMaps(struct bpf_object* obj,
                      const std::string& pin_root,
                      const std::string& zone,
                      std::map<std::string, std::string>& pinned_by)
    -> void {
  struct bpf_map* map = nullptr;
  bpf_object__for_each_map(map, obj) {
    const char* name = bpf_map__name(map);
    if (name == nullptr) {
      continue;
    }
    std::error_code ec;
    if (!std::filesystem::exists(pin_root + "/" + name, ec) || ec) {
      continue;
    }
    pinned_by.emplace(name, zone);
  }
}

/// Turn a failed zone-object load into a sentence naming the map and
/// the conflicting zones.
///
/// libbpf validates a map's definition against the pin it is reusing
/// and returns -EINVAL when they differ. That error names nothing, so
/// what reaches the operator is "load b.bpf.o failed: Invalid
/// argument" for a fault that is entirely specific: one map, two
/// zones, one number. Returns the empty string when no pinned map
/// disagrees — the failure was something else and the caller keeps
/// its own message.
auto ExplainPinConflict(
    struct bpf_object* obj, const std::string& pin_root,
    const std::string& zone,
    const std::map<std::string, std::string>& pinned_by) -> std::string {
  struct bpf_map* map = nullptr;
  bpf_object__for_each_map(map, obj) {
    const char* name = bpf_map__name(map);
    if (name == nullptr) {
      continue;
    }
    std::string path = pin_root + "/" + name;
    std::error_code ec;
    if (!std::filesystem::exists(path, ec) || ec) {
      continue;
    }
    auto existing = PinnedShape(path);
    if (!existing) {
      continue;
    }
    auto owner = pinned_by.find(name);
    std::string held_by = owner == pinned_by.end()
        ? std::format("the pin left at {} by an earlier load", path)
        : std::format("zone '{}'", owner->second);
    std::string message = DescribePinConflict(
        name, zone, held_by, DeclaredShape(map), *existing);
    if (!message.empty()) {
      return message;
    }
  }
  return {};
}

}  // namespace

BpfCounterMap::BpfCounterMap(int fd) : fd_(fd) {
  if (fd_ < 0) return;
  struct bpf_map_info info = {};
  uint32_t len = sizeof(info);
  if (bpf_obj_get_info_by_fd(fd_, &info, &len) != 0) {
    // A descriptor we hold and cannot describe. Leaving the bound at
    // zero is what makes the caller say so; returning a guess is how
    // counters above the guess stopped being reported at all.
    slots_ = 0;
    return;
  }
  slots_ = info.max_entries;
  ncpus_ = libbpf_num_possible_cpus();
  if (ncpus_ < 1) ncpus_ = 1;
}

auto BpfCounterMap::Read(uint32_t slot) const
    -> std::optional<uint64_t> {
  if (fd_ < 0 || slot >= slots_) return std::nullopt;
  std::vector<uint64_t> per_cpu(static_cast<size_t>(ncpus_), 0);
  if (bpf_map_lookup_elem(fd_, &slot, per_cpu.data()) != 0) {
    return std::nullopt;
  }
  uint64_t total = 0;
  for (uint64_t v : per_cpu) total += v;
  return total;
}

auto DefaultPersistentMapNames() -> std::vector<std::string> {
  // Mirrors emitter.persistent_map_names() for bundles compiled before
  // manifests carried `persistent_maps`. Keep in step with the
  // registry; test_map_lifetime.py reads this list back out of this
  // file and fails when it drifts.
  return {"conntrack", "fwl_nat"};
}

auto ReadPersistentMapNames(std::string_view bundle_dir)
    -> std::vector<std::string> {
  using nlohmann::json;
  std::ifstream mf(std::filesystem::path(bundle_dir) / "manifest.json");
  if (!mf) {
    return DefaultPersistentMapNames();
  }
  std::stringstream ss;
  ss << mf.rdbuf();
  json manifest;
  try {
    manifest = json::parse(ss.str());
  } catch (const std::exception&) {
    return DefaultPersistentMapNames();
  }
  if (!manifest.contains("persistent_maps") ||
      !manifest["persistent_maps"].is_array()) {
    // An older bundle. Falling back rather than sweeping everything
    // matters: treating a pre-upgrade bundle as "nothing persists"
    // would drop the conntrack table on the first reload after a
    // package upgrade, which is precisely the outage this whole
    // mechanism exists to avoid.
    return DefaultPersistentMapNames();
  }
  std::vector<std::string> names;
  for (const auto& n : manifest["persistent_maps"]) {
    if (n.is_string()) {
      names.push_back(n.get<std::string>());
    }
  }
  return names;
}

namespace {

/// Comma-separated, for a message that has to name several things.
auto Join(const std::vector<std::string>& items) -> std::string {
  std::string out;
  for (size_t i = 0; i < items.size(); ++i) {
    out += (i == 0 ? "" : ", ");
    out += items[i];
  }
  return out;
}

/// The attach plan, from an already-parsed manifest.
///
/// The one place that answers "which interfaces does this bundle want
/// its programs on". Both the declared-zone form and the simple
/// `@xdp(<iface>)` form are read here, so no caller has to remember
/// that the second one exists — which is exactly what went wrong when
/// only `manifest["zones"]` was consulted.
auto PlanFromManifest(const nlohmann::json& manifest)
    -> BundleAttachPlan {
  using nlohmann::json;
  BundleAttachPlan plan;
  for (const auto& z : manifest.value("zones", json::array())) {
    std::vector<std::string> ifaces;
    for (const auto& i : z.value("interfaces", json::array())) {
      if (i.is_string()) {
        ifaces.push_back(i.get<std::string>());
      }
    }
    plan.zone_interfaces[z.value("name", std::string{})] =
        std::move(ifaces);
  }
  for (const auto& p : manifest.value("programs", json::array())) {
    std::string zone = p.value("zone", std::string{});
    if (zone.empty()) {
      continue;
    }
    if (!plan.zone_interfaces.contains(zone)) {
      // The simple form (FWL_V04_SPEC.md § 6.2, and § "Hook" of the
      // v0.1 spec, where `@xdp(<interface>)` is spelled out): no zone
      // was declared, so the @xdp argument is a bare interface name
      // and the implicit zone has exactly that one interface.
      // `fwl` writes this row into the manifest itself now; deriving
      // it here as well is what keeps a bundle compiled by an older
      // `fwl` — one already staged at <bundle_dir>/current, which a
      // package upgrade does not recompile — attaching to the
      // interface it names instead of refusing to load.
      plan.zone_interfaces[zone] = {zone};
      continue;
    }
    if (plan.zone_interfaces[zone].empty()) {
      plan.zones_without_interfaces.push_back(zone);
    }
  }
  return plan;
}

}  // namespace

auto PlanBundleAttach(std::string_view bundle_dir) -> BundleAttachPlan {
  using nlohmann::json;
  std::ifstream mf(std::filesystem::path(bundle_dir) / "manifest.json");
  if (!mf) {
    return {};
  }
  std::stringstream ss;
  ss << mf.rdbuf();
  try {
    return PlanFromManifest(json::parse(ss.str()));
  } catch (const std::exception&) {
    return {};
  }
}

auto NatCfgMapNames(std::string_view zone)
    -> std::array<std::string, 2> {
  return {std::string("fwl_nat_cfg_") + std::string(zone),
          std::string("fwl_nat_cfg")};
}

auto ManifestStatesMasquerade(std::string_view bundle_dir) -> bool {
  using nlohmann::json;
  std::ifstream mf(std::filesystem::path(bundle_dir) / "manifest.json");
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
  for (const auto& p : manifest.value("programs", json::array())) {
    if (p.contains("masquerades")) {
      // One program stating it is enough: `fwl` writes the field for
      // every program or for none, so a single occurrence identifies a
      // manifest that answers the question — and `false` on the other
      // programs is then a real answer, not a missing one.
      return true;
    }
  }
  return false;
}

auto DecidePinFate(std::string_view name,
                   const std::vector<std::string>& persistent,
                   const PinnedMapShape* declared,
                   const PinnedMapShape& existing,
                   PinPolicy policy) -> PinVerdict {
  bool may_persist = false;
  for (const auto& p : persistent) {
    if (p == name) {
      may_persist = true;
      break;
    }
  }
  if (!may_persist) {
    // Numbered, sized or populated by the compilation that pinned it.
    return PinVerdict::kDiscard;
  }
  if (declared == nullptr) {
    // Flow-keyed, but no zone in the incoming bundle uses it. Nothing
    // will read it, nothing will age it out (conntrack GC only runs
    // while a bundle carries the map), and it would be adopted with
    // entries of arbitrary age by whichever later policy re-adds it.
    return PinVerdict::kDiscard;
  }
  bool same = declared->type == existing.type &&
              declared->key_size == existing.key_size &&
              declared->value_size == existing.value_size &&
              declared->max_entries == existing.max_entries &&
              declared->map_flags == existing.map_flags;
  if (same) {
    return PinVerdict::kAdopt;
  }
  // The definition moved — a compiler upgrade that changed a struct or
  // a capacity, or something else pinned at this name. libbpf will
  // refuse to reuse it, so the state is unreachable either way; all
  // that is left to decide is who finds out.
  return policy == PinPolicy::kColdBoot ? PinVerdict::kDiscard
                                        : PinVerdict::kDefer;
}

namespace {

/// The pins the bundle at `bundle_dir` will try to reuse, and the
/// definition each of its zone objects declares for them.
///
/// Opens each zone object WITHOUT loading it: opening resolves the
/// pin-by-name paths and parses the map definitions, which is all this
/// needs, and it runs no verifier and creates no maps. An object that
/// will not even open is skipped — the load proper is where that gets
/// reported.
auto BundlePinnedDeclarations(const std::string& bundle_dir,
                              const std::string& pin_root)
    -> std::map<std::string, PinnedMapShape> {
  using nlohmann::json;
  std::map<std::string, PinnedMapShape> declared;
  std::filesystem::path dir(bundle_dir);
  std::ifstream mf(dir / "manifest.json");
  if (!mf) {
    return declared;
  }
  std::stringstream ss;
  ss << mf.rdbuf();
  json manifest;
  try {
    manifest = json::parse(ss.str());
  } catch (const std::exception&) {
    return declared;
  }
  // Every object in the bundle, not only the zone programs. The egress
  // tracker declares the same pinned `conntrack` map, so a
  // reconciliation that could not see it would be reasoning about a
  // strict subset of what the load is about to reuse.
  std::vector<std::string> objects;
  for (const auto& p : manifest.value("programs", json::array())) {
    if (!p.value("object", json()).is_null()) {
      objects.push_back(p.at("object").get<std::string>());
    }
  }
  auto egress = manifest.value("egress_tracker", json());
  if (egress.is_object() && egress.value("object", json()).is_string()) {
    objects.push_back(egress["object"].get<std::string>());
  }
  for (const auto& object : objects) {
    std::string obj_path = (dir / object).string();
    LIBBPF_OPTS(bpf_object_open_opts, open_opts);
    open_opts.pin_root_path = pin_root.c_str();
    struct bpf_object* obj =
        bpf_object__open_file(obj_path.c_str(), &open_opts);
    if (!obj) {
      continue;
    }
    struct bpf_map* map = nullptr;
    bpf_object__for_each_map(map, obj) {
      // Only maps that pin by name can collide with bpffs; an
      // object-private map (fwl_scratch, fwl_stages) has no pin path
      // and must not be mistaken for one that does.
      if (bpf_map__pin_path(map) == nullptr) {
        continue;
      }
      const char* name = bpf_map__name(map);
      if (name == nullptr) {
        continue;
      }
      // First declaration wins. Two zones declaring one pinned name
      // differently is a compile error (_check_bundle_pinned_maps);
      // should one reach here anyway, the load reports it properly.
      declared.emplace(name, DeclaredShape(map));
    }
    bpf_object__close(obj);
  }
  return declared;
}

/// Drop the entries of an adopted conntrack map that the daemon's GC
/// would already have condemned.
///
/// Same rule, same clock: the program stamps last_seen_ns with
/// bpf_ktime_get_ns() (CLOCK_MONOTONIC), which survives a process
/// restart and resets only on reboot — where bpffs is empty and there
/// is nothing to adopt. So the ages an adopted table carries are
/// directly comparable with the ones the incoming program will write.
auto SweepAdoptedConntrack(const std::string& path,
                           uint32_t timeout_s) -> uint32_t {
  if (timeout_s == 0) {
    return 0;
  }
  int fd = bpf_obj_get(path.c_str());
  if (fd < 0) {
    return 0;
  }
  auto now_ns = static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          std::chrono::steady_clock::now().time_since_epoch())
          .count());
  uint64_t timeout_ns =
      static_cast<uint64_t>(timeout_s) * 1'000'000'000ULL;
  ConnKey key{}, next{};
  ConnValue val{};
  std::vector<ConnKey> stale;
  while (bpf_map_get_next_key(fd, &key, &next) == 0) {
    if (bpf_map_lookup_elem(fd, &next, &val) == 0 &&
        now_ns > val.last_seen_ns &&
        now_ns - val.last_seen_ns > timeout_ns) {
      stale.push_back(next);
    }
    key = next;
  }
  uint32_t evicted = 0;
  for (const auto& k : stale) {
    if (bpf_map_delete_elem(fd, &k) == 0) {
      evicted++;
    }
  }
  ::close(fd);
  return evicted;
}

}  // namespace

auto ReconcilePinnedMaps(std::string_view bundle_dir,
                         std::string_view pin_root,
                         PinPolicy policy,
                         uint32_t conntrack_timeout_s)
    -> PinReconcileReport {
  PinReconcileReport report;
  std::string root(pin_root);
  std::error_code ec;
  std::filesystem::directory_iterator it(root, ec);
  if (ec) {
    // No pin root yet: a first boot, or bpffs freshly mounted. Nothing
    // to reconcile.
    return report;
  }
  auto persistent = ReadPersistentMapNames(bundle_dir);
  auto declared = BundlePinnedDeclarations(std::string(bundle_dir), root);

  for (const auto& entry : it) {
    auto name = entry.path().filename().string();
    auto existing = PinnedShape(entry.path().string());
    if (!existing) {
      // Not a map pin we can inspect (a directory, or a pin we cannot
      // open). Leave it: removing what we cannot identify is worse
      // than leaving it, and it cannot be adopted either.
      continue;
    }
    auto found = declared.find(name);
    const PinnedMapShape* want =
        found == declared.end() ? nullptr : &found->second;
    switch (DecidePinFate(name, persistent, want, *existing, policy)) {
      case PinVerdict::kDiscard: {
        std::error_code rm_ec;
        std::filesystem::remove(entry.path(), rm_ec);
        report.discarded.push_back(name);
        break;
      }
      case PinVerdict::kAdopt: {
        report.adopted.push_back(name);
        if (policy == PinPolicy::kColdBoot && name == "conntrack") {
          report.conntrack_swept += SweepAdoptedConntrack(
              entry.path().string(), conntrack_timeout_s);
        }
        break;
      }
      case PinVerdict::kDefer:
        break;
    }
  }
  return report;
}

auto DescribePinConflict(std::string_view map_name,
                         std::string_view loading_zone,
                         std::string_view owner,
                         const PinnedMapShape& want,
                         const PinnedMapShape& have) -> std::string {
  std::vector<std::string> diffs;
  auto note = [&](std::string_view field, uint32_t a, uint32_t b) {
    if (a != b) {
      diffs.push_back(std::format("{} {} vs {}", field, a, b));
    }
  };
  note("type", want.type, have.type);
  note("key_size", want.key_size, have.key_size);
  note("value_size", want.value_size, have.value_size);
  note("max_entries", want.max_entries, have.max_entries);
  note("map_flags", want.map_flags, have.map_flags);
  if (diffs.empty()) {
    return {};
  }
  std::string joined;
  for (size_t i = 0; i < diffs.size(); ++i) {
    joined += (i == 0 ? "" : ", ");
    joined += diffs[i];
  }
  return std::format(
      "zone '{}' declares map '{}' differently from {}, which holds "
      "the same pinned name: {}. A pinned name is ONE kernel map, so "
      "libbpf refuses to reuse a pin whose definition differs "
      "(-EINVAL, \"parameter mismatch\"). If this map holds per-zone "
      "state its name must carry the zone; if it is bundle-wide "
      "state, every zone must declare it identically (size it from a "
      "constant, not from a per-zone rule or counter count).",
      loading_zone, map_name, owner, joined);
}

auto CloseZoneBundle(ZoneBundleHandles& handles) -> void {
  for (auto* obj : handles.objs) {
    if (obj != nullptr) {
      bpf_object__close(obj);
    }
  }
  // Closed, not detached — the same contract as the zone objects above.
  // On a hot reload the incoming tracker has already replaced this
  // filter in place (one fixed handle/priority), so detaching here
  // would tear down the NEW one and leave the box's own flows
  // untracked with a load that said "ok".
  CloseEgressTracker(handles.egress);
  handles.egress.ifindexes.clear();
  handles.egress.interfaces.clear();
  handles.egress.created_qdisc.clear();
  handles.objs.clear();
  handles.programs.clear();
  handles.conntrack_fd = -1;
  handles.nat_fd = -1;
  handles.nat_stats_fd = -1;
  handles.route_stats_fd = -1;
  handles.neigh_wanted_fd = -1;
  handles.legacy_nat_cfg = false;
}

// See bpf_loader.h for what these two are for.
auto RunningKernelRelease() -> std::string {
  struct utsname u = {};
  if (::uname(&u) != 0) return {};
  return u.release;
}

auto KernelAtLeast(const std::string& release, const std::string& floor)
    -> bool {
  auto parts = [](const std::string& text) {
    std::vector<int> out;
    int value = 0;
    bool seen = false;
    for (char c : text) {
      if (c >= '0' && c <= '9') {
        value = value * 10 + (c - '0');
        seen = true;
        continue;
      }
      if (seen) out.push_back(value);
      value = 0;
      seen = false;
      // Only the leading dotted numbers are a version; `6.18.43-rk` is
      // three components, not four.
      if (c != '.') break;
    }
    if (seen) out.push_back(value);
    return out;
  };
  auto have = parts(release);
  auto want = parts(floor);
  if (have.empty() || want.empty()) return true;
  for (std::size_t i = 0; i < want.size(); ++i) {
    int h = i < have.size() ? have[i] : 0;
    if (h != want[i]) return h > want[i];
  }
  return true;
}

auto LoadZoneBundle(std::string_view bundle_dir,
                    std::string_view pin_root,
                    const ZoneBundleHandles* replace)
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

  // Before anything is opened: does this kernel have the instructions
  // these objects were assembled with?
  //
  // `fwl compile` builds for clang's default BPF ISA, which loads on
  // every kernel this project supports. A zone too large to assemble
  // inside LLVM's signed 16-bit branch offset is built with
  // `-mcpu=v4` instead, whose `gotol` the kernel gained in 6.6, and
  // the manifest records the floor. Without this check the failure is
  // a verifier rejection naming an opcode -- true, useless, and
  // indistinguishable from a policy the verifier disliked on its
  // merits.
  // `is_string()` rather than `value(...)`: every bundle built for the
  // default instruction set writes `"min_kernel": null`, and
  // nlohmann's `value()` THROWS on a present-but-null key rather than
  // returning the default. That threw out of the middle of a load, so
  // fd died by std::terminate with the bundle half-open -- no error
  // return, no journal line, and to the guard indistinguishable from a
  // board that stopped being scheduled.
  if (manifest.contains("min_kernel") &&
      manifest["min_kernel"].is_string()) {
    const auto floor = manifest["min_kernel"].get<std::string>();
    auto running = RunningKernelRelease();
    if (!KernelAtLeast(running, floor)) {
      return MakeError(BpfError::kLoadFailed,
          std::format(
              "bundle {} was compiled for BPF ISA {} and needs kernel "
              "{} or newer; this box runs {}. A zone in this policy is "
              "too large to assemble with the default instruction set. "
              "Recompile it on a box with a matching kernel, split the "
              "policy across zones, or express the bulk of it as a "
              "table rather than as rules.",
              bundle_dir,
              manifest["bpf_isa"].is_string()
                  ? manifest["bpf_isa"].get<std::string>()
                  : std::string{"a newer one"},
              floor,
              running.empty() ? "an unreadable version" : running));
    }
  }

  // zone name -> resolved ifindexes (egress targets for redirect, and
  // ingress interfaces to attach each program to). Interface names are
  // kept too: the masquerade config needs the egress zone's address.
  //
  // Read through PlanFromManifest rather than off manifest["zones"]
  // directly. The array answers this question only for a unit that
  // declares zones; the simple `@xdp(eth0)` form leaves it empty and
  // names its interface in the program entry instead, and reading
  // just the array gave every such bundle zero interfaces to attach
  // to — reported as a successful load.
  auto plan = PlanFromManifest(manifest);
  if (!plan.zones_without_interfaces.empty()) {
    // Distinct from a NIC that is not present yet: the manifest names
    // no interface for this program at all, so there is nothing to
    // wait for and nothing to resolve. Refuse before opening a single
    // object — the bundle is malformed and no amount of loading will
    // make it enforce anything.
    return MakeError(BpfError::kLoadFailed,
        std::format("bundle {}: manifest names no interface for zone "
                    "program(s) [{}] — a zone program with no "
                    "interface can never be attached, so this bundle "
                    "cannot enforce anything",
                    bundle_dir, Join(plan.zones_without_interfaces)));
  }
  std::map<std::string, std::vector<int>> zone_ifindexes;
  std::map<std::string, std::vector<std::string>> zone_ifnames;
  for (const auto& [zname, ifaces] : plan.zone_interfaces) {
    zone_ifindexes[zname] = ResolveZoneIfindexes(ifaces);
    zone_ifnames[zname] = ifaces;
  }

  // Pre-flight the outcome this whole function exists to produce: is
  // there a single interface on this host for any of the programs to
  // land on? Asked here, before a pin root is created or an object is
  // opened, because the answer does not depend on any of that and
  // because refusing early leaves the running policy — and bpffs —
  // untouched. The same condition is re-checked after the attach loop;
  // this one is not the guarantee, it is the early, specific message.
  std::vector<std::string> attachable;
  std::vector<std::string> wanted;
  size_t resolvable = 0;
  for (const auto& p : manifest.value("programs", json::array())) {
    if (p.value("object", json()).is_null()) {
      continue;
    }
    std::string zone = p.value("zone", std::string{});
    auto it = zone_ifindexes.find(zone);
    if (it == zone_ifindexes.end()) {
      continue;
    }
    attachable.push_back(zone);
    wanted.push_back(
        std::format("{} [{}]", zone, Join(zone_ifnames[zone])));
    resolvable += it->second.size();
  }
  if (!attachable.empty() && resolvable == 0) {
    return MakeError(BpfError::kAttachFailed,
        std::format("bundle {} names {} zone program(s) and not one of "
                    "their interfaces exists on this host, so it would "
                    "attach to ZERO interfaces and no packet would be "
                    "inspected. Wanted: {}. Refusing the load rather "
                    "than reporting a firewall that is not there — "
                    "check the interfaces the policy names against "
                    "`ip link`.",
                    bundle_dir, attachable.size(), Join(wanted)));
  }

  // Common pin root so LIBBPF_PIN_BY_NAME maps (conntrack, fwl_nat,
  // the tallies) resolve to one kernel map across every zone object.
  // NOT the devmaps: a devmap cannot be reused from a pin at all (the
  // kernel forces BPF_F_RDONLY_PROG in dev_map_alloc and libbpf
  // compares that against the object's declared map_flags of 0), so
  // the compiler leaves them unpinned and each object gets its own —
  // populated below, per object, from the manifest. Fails without
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

  // Hot-reload swap targets: ifindex -> the currently attached
  // program from the bundle being replaced.
  std::map<int, int> old_prog_by_ifindex;
  if (replace != nullptr) {
    for (const auto& prev : replace->programs) {
      for (int idx : prev.ifindexes) {
        old_prog_by_ifindex[idx] = prev.prog_fd;
      }
    }
  }
  // Interfaces already flipped/attached to NEW programs, for rollback
  // when a later step fails: replaced ones swap back to the old
  // program, freshly attached ones detach.
  std::vector<std::pair<int, int>> flipped;
  std::vector<int> fresh_attached;

  // Which zone pinned each map name, so a shape conflict on a later
  // object can name the zone to compare against, not just a path.
  std::map<std::string, std::string> pinned_by;

  // Whether this bundle names its masquerade sources at all.
  const bool manifest_states_masq = ManifestStatesMasquerade(bundle_dir);

  ZoneBundleHandles handles;
  // The policy text this bundle was compiled from, taken from the
  // manifest already parsed above rather than looked up later. It is
  // the other half of the drift answer: the digest of what was
  // compiled, against which a consumer weighs the digest of what is on
  // disk now.
  handles.policy_source = ParsePolicySource(manifest);
  auto bail = [&](BpfError code, std::string message)
      -> std::unexpected<Error<BpfError>> {
    for (const auto& [idx, old_fd] : flipped) {
      ReplaceXdp(idx, old_fd, -1);
    }
    for (int idx : fresh_attached) {
      bpf_xdp_detach(idx, 0, nullptr);
    }
    CloseZoneBundle(handles);
    return MakeError(code, std::move(message));
  };

  for (const auto& p : manifest.value("programs", json::array())) {
    if (p.value("object", json()).is_null()) {
      // The bundle was emitted without a compiled object (clang
      // unavailable at compile time); nothing to load for this zone.
      spdlog::warn("zone '{}' has no compiled object; skipping",
                   p.value("zone", std::string{}));
      continue;
    }
    // `json::at` throws on a missing key, and this function returns
    // std::expected precisely so control paths do not. A manifest
    // entry with no zone is a malformed bundle, which is a refusal,
    // not an exception out of the middle of a load.
    std::string zone = p.value("zone", std::string{});
    if (zone.empty() || !zone_ifnames.contains(zone)) {
      return bail(BpfError::kLoadFailed,
          std::format("bundle {}: program entry names no zone this "
                      "manifest declares ({}) — it cannot be attached "
                      "to anything",
                      bundle_dir, p.dump()));
    }
    std::string obj_name = p.value("object", std::string{});
    std::string obj_path = (dir / obj_name).string();

    LIBBPF_OPTS(bpf_object_open_opts, open_opts);
    open_opts.pin_root_path = pin_root_str.c_str();
    struct bpf_object* obj =
        bpf_object__open_file(obj_path.c_str(), &open_opts);
    if (!obj) {
      return bail(BpfError::kLoadFailed,
          std::format("open {} failed", obj_path));
    }
    int err = bpf_object__load(obj);
    if (err) {
      // -EINVAL here is usually a pinned map this zone declares
      // differently from the zone that pinned it. Say which map and
      // which zones before the object goes away.
      std::string conflict =
          ExplainPinConflict(obj, pin_root_str, zone, pinned_by);
      bpf_object__close(obj);
      if (!conflict.empty()) {
        return bail(BpfError::kLoadFailed,
            std::format("load {} failed: {}", obj_path, conflict));
      }
      return bail(BpfError::kLoadFailed,
          std::format("load {} failed: {}", obj_path,
                      std::strerror(-err)));
    }
    handles.objs.push_back(obj);
    RecordPinnedMaps(obj, pin_root_str, zone, pinned_by);

    // v0.4 § 6.6: `fwl_prog` for a single-program zone, or the wired
    // `fwl_stage_0` entry of a split tail-call pipeline.
    struct bpf_program* prog = ResolveZoneEntryProgram(obj, zone);
    if (!prog) {
      return bail(BpfError::kLoadFailed,
          std::format("no fwl_prog / fwl_stage_0 entry in {}",
                      obj_path));
    }

    ZoneProgramHandle zh;
    zh.zone = zone;
    zh.prog_fd = bpf_program__fd(prog);
    zh.masquerades = p.value("masquerades", false);
    for (const auto& d : p.value("redirects_to", json::array())) {
      zh.redirects_to.push_back(d.get<std::string>());
    }
    // The zone's interface names (for `show zones`); some may not be
    // present on the host yet. From the same plan the attach uses, so
    // what the operator is shown and what the loader acts on cannot
    // disagree — the simple `@xdp(eth0)` form used to render an empty
    // interface list here for the same reason it attached to nothing.
    zh.interfaces = zone_ifnames[zone];

    // The zone's own named counters. Both halves are taken here, in
    // one place, from one bundle: the descriptor out of the object
    // that was just loaded, and the name->slot table out of the
    // generated C that object was compiled from. A consumer that
    // re-derived either half later would be pairing a name from one
    // policy with a value from another — which is the failure that
    // made the whole v0.1 counter surface print plausible numbers
    // against the wrong rules.
    //
    // A policy with no `count` statement declares no map and emits no
    // table: -1 and an empty (but READ) table, which the reader
    // reports as "declares no counters" rather than as a failure.
    zh.counters_fd = FindMap(obj, ("fwl_counters_" + zone).c_str());
    zh.counters = ReadCounterTable(
        dir / p.value("source", zone + ".bpf.c"));

    // This zone's rules, from the manifest entry `p` that named the
    // object two statements up — the same parse, the same call, the
    // same bundle. Nothing reads the bundle directory again to answer
    // "what rules is this box running": a reload between the load and
    // the answer would otherwise hand an operator one policy's rules
    // beside another policy's program, and the two are indistinguish-
    // able on the screen. A bundle compiled before this metadata
    // existed yields kNotEmitted — "cannot say", never "no rules".
    zh.rules = ParseRuleTable(p, zone);

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

    // Capture the shared NAT reply-mapping fd; `show nat` reads the
    // live translations out of it, and NatMgr sweeps it.
    if (handles.nat_fd < 0) {
      int nf = FindMap(obj, "fwl_nat");
      if (nf >= 0) handles.nat_fd = nf;
    }

    // ...and the datapath's own tally of what happened to it. A
    // refusal counted here is a packet the program DROPPED rather than
    // translate into a mapping it could not claim; without the fd the
    // daemon cannot report it, and an unreportable failure is the
    // exact shape of every defect l11_01/l11_02 found.
    if (handles.nat_stats_fd < 0) {
      int ns = FindMap(obj, "fwl_nat_stats");
      if (ns >= 0) handles.nat_stats_fd = ns;
    }

    // And the routing tally, for the same reason one slot up: whether
    // a redirect re-addressed the frame to a next hop or handed it on
    // with the MAC it arrived with is not observable from the wire by
    // anything that captures promiscuously. This map is the only place
    // the difference is written down.
    if (handles.route_stats_fd < 0) {
      int rs = FindMap(obj, "fwl_route_stats");
      if (rs >= 0) handles.route_stats_fd = rs;
    }

    // ...and the queue of next hops that tally could not name. The
    // counter says a forward was lost; only this says WHICH address the
    // box needed a MAC for, and it is the one thing a masquerading box
    // cannot work out for itself once the packet is gone. `fd` drains
    // it and asks the kernel to resolve what is in it (neigh_mgr.cc).
    // Absent on a bundle compiled before the map existed, which is a
    // reported state and not a load failure — such a box behaves as it
    // did before, healing only by luck.
    if (handles.neigh_wanted_fd < 0) {
      int nw = FindMap(obj, "fwl_neigh_wanted");
      if (nw >= 0) handles.neigh_wanted_fd = nw;
    }

    // masquerade (v0.4 § NAT): the program translates sources to "the
    // WAN interface address" — the first IPv4 on the redirect
    // destination zone. THIS zone's redirect destination, into THIS
    // zone's own map.
    //
    // The map is per zone because the address is. `masquerade` means
    // "translate to the address of the zone this one redirects to",
    // and nothing makes two masquerading zones redirect to the same
    // place: `deploy/firstboot` writes `masquerade` + `redirect to
    // <uplink>` for every non-uplink zone, and a box with two uplinks
    // names two. While the map was pinned under the bundle-global name
    // `fwl_nat_cfg` this loop wrote one kernel slot once per
    // masquerading zone, so the last zone loaded decided what every
    // masquerading program in the bundle translated to — measured on
    // the rig as `zone 'ina' masquerade address 10.99.210.2` followed
    // by `zone 'inb' masquerade address 10.99.31.1`, after which
    // neither zone forwarded.
    //
    // The map's PRESENCE is still not the signal. Every object in a
    // NAT bundle embeds one, because the NAT helper block is emitted
    // whole into any object that carries NAT at all, so seeding from
    // presence alone also seeded from the WAN program — whose redirect
    // destination is the LAN. The manifest's per-program `masquerades`
    // flag is the compiler's answer to "which zone is a masquerade
    // source", and it is the only thing consulted here — unless the
    // bundle predates the flag, in which case it answers nothing and
    // the old presence rule is the lesser wrong (see
    // ManifestStatesMasquerade).
    //
    // The name is looked up per zone FIRST and falls back to the old
    // bundle-global one, for the same reason and with the same rule: a
    // bundle staged by an older `fwl` still has to masquerade after an
    // `fd` upgrade. On such a bundle every zone resolves one map, so
    // the overwrite is still there — and is named below rather than
    // left to be found on the wire.
    const auto nat_cfg_names = NatCfgMapNames(zone);
    int nat_cfg_fd = FindMap(obj, nat_cfg_names[0].c_str());
    if (nat_cfg_fd < 0) {
      nat_cfg_fd = FindMap(obj, nat_cfg_names[1].c_str());
      if (nat_cfg_fd >= 0) {
        handles.legacy_nat_cfg = true;
      }
    }
    zh.nat_cfg_fd = nat_cfg_fd;
    if (nat_cfg_fd >= 0 && (zh.masquerades || !manifest_states_masq)) {
      uint32_t masq_addr = 0;
      std::string masq_zone;
      for (const auto& dest : zh.redirects_to) {
        auto dest_it = zone_ifnames.find(dest);
        if (dest_it == zone_ifnames.end()) {
          continue;
        }
        masq_addr = FirstZoneIpv4(dest_it->second);
        if (masq_addr != 0) {
          masq_zone = dest;
          break;
        }
      }
      if (masq_addr != 0) {
        uint32_t key = 0;
        FwlNatCfg cfg{masq_addr};
        bpf_map_update_elem(nat_cfg_fd, &key, &cfg, BPF_ANY);
        zh.masq_addr = masq_addr;
        char buf[INET_ADDRSTRLEN] = {};
        inet_ntop(AF_INET, &masq_addr, buf, sizeof(buf));
        spdlog::info("zone '{}' masquerade address {} (zone '{}')",
                     zone, buf, masq_zone);
        // On a pre-split bundle every zone's write lands on the same
        // slot, so a second masquerading zone that resolves a
        // DIFFERENT address has just silently taken the first one's
        // traffic with it. Nothing here can fix that — the map has one
        // slot — so say it, name both zones, and say what does.
        if (handles.legacy_nat_cfg) {
          for (const auto& prev : handles.programs) {
            if (prev.masq_addr != 0 && prev.masq_addr != masq_addr) {
              char pbuf[INET_ADDRSTRLEN] = {};
              inet_ntop(AF_INET, &prev.masq_addr, pbuf, sizeof(pbuf));
              spdlog::error(
                  "bundle {} predates the per-zone masquerade address "
                  "and carries one bundle-wide slot: zone '{}' just "
                  "overwrote zone '{}'s address {} with {}, so BOTH "
                  "zones now translate to {}. Recompile the policy "
                  "with this version of fwl",
                  bundle_dir, zone, prev.zone, pbuf, buf, buf);
              break;
            }
          }
        }
      } else {
        spdlog::warn(
            "zone '{}' uses masquerade but no redirect-destination "
            "zone interface carries an IPv4 address; masquerade "
            "rules will not translate",
            zone);
      }
    }

    // Populate each redirect destination's devmap with that zone's
    // egress ifindexes (key i -> ifindex of the i-th interface).
    //
    // THIS object's copy, and that is the whole reason devmaps are not
    // pinned. Two inside zones redirecting to one uplink both declare
    // `fwl_devmap_<uplink>`; under a bundle-global pin the second one
    // failed to load ("parameter mismatch", map_flags 0 vs 128 — the
    // kernel forces BPF_F_RDONLY_PROG in dev_map_alloc and libbpf's
    // reuse check compares it), which is every gateway with more than
    // one inside zone. This loop already fills each object separately,
    // so the copies agree without ever being one map.
    for (const auto& dest : p.value("redirects_to", json::array())) {
      std::string dest_zone = dest.get<std::string>();
      // A destination the plan does not know is a manifest naming a
      // zone it did not declare. `zone_ifindexes[dest]` would default-
      // construct an empty vector and fill the devmap with nothing —
      // the same `operator[]` mechanism that made the attach loop run
      // zero times, and with the same silence: every redirected frame
      // is dropped and the load still says ok.
      auto dest_it = zone_ifindexes.find(dest_zone);
      if (dest_it == zone_ifindexes.end()) {
        return bail(BpfError::kLoadFailed,
            std::format("zone '{}' redirects to '{}', which the "
                        "manifest never declares — every frame "
                        "redirected there would be dropped",
                        zone, dest_zone));
      }
      std::string map_name = "fwl_devmap_" + dest_zone;
      int map_fd = FindMap(obj, map_name.c_str());
      if (map_fd < 0) {
        // The compiler said this zone redirects there; the object it
        // compiled has no devmap for it. Contract disagreement, and a
        // bare `continue` made it a silent drop.
        spdlog::warn("zone '{}' redirects to '{}' but its object has "
                     "no '{}'; redirected frames will be DROPPED",
                     zone, dest_zone, map_name);
        continue;
      }
      const auto& targets = dest_it->second;
      for (uint32_t i = 0; i < targets.size(); ++i) {
        uint32_t key = i;
        uint32_t val = static_cast<uint32_t>(targets[i]);
        bpf_map_update_elem(map_fd, &key, &val, BPF_ANY);
      }
      if (targets.empty()) {
        // Same shape as the attach count: the map exists, so the load
        // proceeds, but `redirect to <dest>` looks up slot 0 of an
        // empty devmap and the frame is dropped. "0 ifaces" at info,
        // next to a successful load, is not something anybody reads.
        spdlog::warn(
            "zone '{}' redirects to '{}' but that zone has no "
            "interface on this host ([{}]); every redirected frame "
            "will be DROPPED",
            zone, dest_zone, Join(zone_ifnames.at(dest_zone)));
      } else {
        spdlog::info("zone '{}' devmap -> '{}' ({} ifaces)", zone,
                     dest_zone, targets.size());
      }
    }

    // Attach the program to every interface in its own zone. On a
    // hot reload the interface already runs the previous bundle's
    // program: swap atomically (no detach, no NIC reset, no
    // policy-off window).
    for (int ifindex : zone_ifindexes[zone]) {
      auto old_it = old_prog_by_ifindex.find(ifindex);
      if (old_it != old_prog_by_ifindex.end()) {
        // Recorded BEFORE the swap is attempted, not after it
        // succeeds: the fallback below detaches this interface, so a
        // failure between the detach and the re-attach leaves it bare.
        // Rolling back an interface that was never touched re-attaches
        // the program already on it, which the kernel rejects and the
        // rollback ignores; leaving one bare is a hole in the firewall.
        flipped.emplace_back(ifindex, old_it->second);
        auto r = ReplaceXdp(ifindex, zh.prog_fd, old_it->second);
        if (!r) {
          // No atomic replace on this interface. Rather than fail the
          // reload, detach and re-attach this one interface: a gap of
          // microseconds on it alone, against a policy that does not
          // land at all.
          bool generic = false;
          bpf_xdp_detach(ifindex, 0, nullptr);
          int aerr = AttachXdpFallback(ifindex, zh.prog_fd, &generic);
          if (aerr) {
            return bail(BpfError::kAttachFailed,
                std::format("swap zone '{}' on ifindex {} failed: {}",
                            zone, ifindex, r.error().message));
          }
          spdlog::warn(
              "zone '{}' ifindex {}: atomic XDP replace unavailable, "
              "re-attached ({} mode)",
              zone, ifindex, generic ? "generic" : "native");
        }
      } else {
        // Native (driver) XDP where the NIC has it, generic (SKB)
        // where it does not — the RTL8125 (`r8169`) has no native XDP
        // at all and rejects the attach outright, so without the
        // fallback fd cannot run on that hardware.
        bool generic = false;
        int aerr = AttachXdpFallback(ifindex, zh.prog_fd, &generic);
        if (aerr) {
          return bail(BpfError::kAttachFailed,
              std::format("attach zone '{}' to ifindex {} "
                          "failed: {}",
                          zone, ifindex, std::strerror(-aerr)));
        }
        if (generic) {
          spdlog::warn("zone '{}' ifindex {}: native XDP unavailable, "
                       "attached in generic (SKB) mode", zone, ifindex);
        }
        fresh_attached.push_back(ifindex);
      }
      zh.ifindexes.push_back(ifindex);
    }
    if (zh.ifindexes.empty()) {
      // Every interface this zone names is absent from the host. The
      // zone's policy is not enforced, and saying so at info level
      // beside a line that reads "loaded" is how the whole bundle
      // being off went unnoticed. Not fatal on its own — a zone whose
      // NIC has not appeared receives no packets either — but the
      // bundle-level check below refuses the load when this is true
      // of every zone.
      spdlog::warn("zone '{}' ({}) attached to NO interface: none of "
                   "[{}] is present on this host; this zone's policy "
                   "is NOT enforced",
                   zone, obj_name, Join(zh.interfaces));
    } else {
      spdlog::info("loaded zone '{}' ({}) on {} interface(s)", zone,
                   obj_name, zh.ifindexes.size());
    }
    handles.programs.push_back(std::move(zh));
  }

  // A manifest that lists programs but yields none loadable is not a
  // successful load — it is an unusable bundle, and treating it as
  // success is catastrophic. On reload, ApplyBundle detaches every
  // interface the previous bundle held that the new one does not
  // cover; an empty program set covers nothing, so the entire
  // firewall silently disappears while the journal logs "ok" and
  // systemd still reports the unit healthy. The `current` symlink is
  // then advanced to the broken bundle, so the next boot comes up
  // with no policy either. Verified on hardware before this check
  // existed (tests/system/hw/l8_01_objectless_bundle.sh: XDP
  // attachment went 1 -> 0 with fd active).
  //
  // Failing here keeps the old bundle attached on the reload path
  // (ApplyBundle propagates the error before touching anything) and
  // makes the cold-boot path exit loudly instead of coming up naked.
  // The common cause is compiling a bundle on a host without clang,
  // which emits `"object": null` for every zone.
  if (handles.programs.empty()) {
    return bail(BpfError::kLoadFailed,
        std::format("bundle {} has no loadable zone programs "
                    "(every manifest entry lacks a compiled "
                    "object) — refusing to apply it",
                    bundle_dir));
  }

  // Loading is not attaching, and the count of the first is not
  // evidence about the second. A bundle can produce a full set of
  // ZoneProgramHandles — each with a verified object, a resolved
  // entry program and a real prog_fd — and still be attached to
  // nothing, in which case not one packet on this box is inspected.
  // That state used to be reported as success, at info level, under a
  // line reading "1 zone program(s)": a true sentence about the
  // program list that said nothing about attachment, which is the
  // only thing that decides whether the firewall is up.
  //
  // The rule is therefore about the outcome and not about any of the
  // reasons: whatever the manifest said, whatever the host is missing,
  // a bundle attached to zero interfaces is a failed load. Stating it
  // that way closes every way of arriving there at once, including
  // ones no manifest has produced yet.
  //
  // On reload this keeps the running policy attached (ApplyBundle
  // propagates the error before it touches anything); on cold boot fd
  // exits loudly instead of coming up naked and green.
  size_t attached = 0;
  std::vector<std::string> bare;
  for (const auto& p : handles.programs) {
    attached += p.ifindexes.size();
    bare.push_back(std::format("{} [{}]", p.zone, Join(p.interfaces)));
  }
  if (attached == 0) {
    return bail(BpfError::kAttachFailed,
        std::format("bundle {} loaded {} zone program(s) but attached "
                    "to ZERO interfaces — the firewall would be "
                    "completely off while reporting success. Wanted: "
                    "{}. Check that the interfaces the policy names "
                    "exist on this host (`ip link`).",
                    bundle_dir, handles.programs.size(), Join(bare)));
  }

  // The second attach point (v0.4 § 6.9), through the same machinery
  // and the same rollback as the first — deliberately, because a second
  // lifecycle of its own is where this project's silent defects have
  // come from. It goes on exactly the interfaces the datapath just
  // attached to: those are the ports on which a reply to a flow this
  // box originated would be judged, so those are the ports whose egress
  // has to be tracked.
  //
  // Failing the whole load when it cannot attach is the deliberate
  // trade. A box that filters correctly and cannot resolve a name is
  // not a working appliance, and the alternative — carry on and log —
  // is precisely "report success having attached to nothing".
  if (BundleDeclaresEgressTracker(bundle_dir)) {
    std::vector<EgressTarget> targets;
    // Deduplicated: there is one egress chain per interface whatever
    // the zone list says, so an interface named by two zone programs
    // must not be attached to twice — that would put the same ifindex
    // in `created_qdisc` twice and report a port count nobody can
    // reconcile with `ip link`.
    std::set<int> seen_ifindex;
    for (const auto& p : handles.programs) {
      for (int idx : p.ifindexes) {
        if (!seen_ifindex.insert(idx).second) {
          continue;
        }
        char nm[IF_NAMESIZE] = {};
        if_indextoname(static_cast<unsigned int>(idx), nm);
        targets.push_back(EgressTarget{idx, nm});
      }
    }
    auto tracker = AttachEgressTracker(
        bundle_dir, pin_root, targets,
        replace != nullptr ? &replace->egress : nullptr);
    if (!tracker) {
      return bail(tracker.error().code, tracker.error().message);
    }
    handles.egress = *tracker;
  } else {
    // This bundle wants NO tracker — either its policy asks no
    // conntrack question, or it predates the hook. Either way an egress
    // filter left on these interfaces by the bundle being replaced (or
    // by a previous incarnation of this daemon that was killed) is now
    // a tracker with no bundle behind it: still attached, still writing
    // conntrack entries, and nothing left that will ever detach it —
    // CloseZoneBundle deliberately detaches nothing, and ApplyBundle
    // only touches interfaces the new bundle stops covering. That is
    // the l8_05 shape, one hook over, so it is closed here rather than
    // described.
    for (const auto& p : handles.programs) {
      for (int idx : p.ifindexes) {
        if (EgressFilterPresent(idx)) {
          spdlog::info(
              "removing the egress conntrack tracker from ifindex {}: "
              "this bundle declares none", idx);
          DetachEgressOn(idx);
        }
      }
    }
    // The upgrade case is a THIRD state and has to be said out loud
    // once: an `fd` running a bundle staged by an older `fwl` looks
    // identical to a correctly-tracking box from every counter and
    // every status line. What cannot be said from an old manifest is
    // whether that policy reads conntrack STATE — a masquerade-only
    // policy carries the map without ever asking — so the warning says
    // what is actually known and no more.
    if (!ManifestHasEgressField(bundle_dir)) {
      spdlog::warn(
          "bundle {} was compiled before egress conntrack tracking "
          "existed. If its policy reads conntrack(pkt).state, then "
          "flows this box ORIGINATES (DNS forwarding, NTP, updates) "
          "create no entry, their replies read NEW, and a default-drop "
          "policy will drop them. Recompiling the policy answers it "
          "either way.",
          bundle_dir);
    }
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
  // Both attach points, in one call. `EngineStop` walks the bundle and
  // not the boot-time interface list precisely because a stale list
  // left XDP programs running with no daemon behind them (l8_05); an
  // egress filter left behind the same way would keep writing conntrack
  // entries that nothing ages.
  DetachEgressTracker(handles.egress);
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
