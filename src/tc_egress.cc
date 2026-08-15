/// @file tc_egress.cc
/// @brief Loading and attaching the egress conntrack tracker.

#include "f/tc_egress.h"

#include <cerrno>
#include <set>
#include <cstring>
#include <filesystem>
#include <format>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

namespace f {

namespace {

// One fixed slot on the clsact egress chain, so a re-attach REPLACES
// the previous filter instead of stacking a second one behind it. A
// stacked pair would run the tracker twice per packet and, worse, leave
// the old bundle's program in the path after a reload with nothing
// naming it.
constexpr uint32_t kEgressHandle = 1;
constexpr uint32_t kEgressPriority = 1;

/// The parsed `egress_tracker` object of a bundle manifest, or a null
/// json when the manifest is missing, unparseable, or carries no such
/// key. Every reader here has to distinguish "the field is absent"
/// (a bundle compiled before the tracker existed) from "the field says
/// there is no tracker", so the raw value is what is returned.
auto ReadEgressEntry(std::string_view bundle_dir) -> nlohmann::json {
  using nlohmann::json;
  std::filesystem::path dir(bundle_dir);
  std::ifstream mf(dir / "manifest.json");
  if (!mf) {
    return json();
  }
  std::stringstream ss;
  ss << mf.rdbuf();
  try {
    auto manifest = json::parse(ss.str());
    if (!manifest.contains("egress_tracker")) {
      return json();
    }
    return manifest["egress_tracker"];
  } catch (const std::exception&) {
    return json();
  }
}

auto MakeHook(int ifindex) -> struct bpf_tc_hook {
  struct bpf_tc_hook hook = {};
  hook.sz = sizeof(hook);
  hook.ifindex = ifindex;
  hook.attach_point = BPF_TC_EGRESS;
  return hook;
}

}  // namespace

auto BundleDeclaresEgressTracker(std::string_view bundle_dir) -> bool {
  auto entry = ReadEgressEntry(bundle_dir);
  return !entry.is_null();
}

auto ManifestHasEgressField(std::string_view bundle_dir) -> bool {
  using nlohmann::json;
  std::filesystem::path dir(bundle_dir);
  std::ifstream mf(dir / "manifest.json");
  if (!mf) {
    return false;
  }
  std::stringstream ss;
  ss << mf.rdbuf();
  try {
    return json::parse(ss.str()).contains("egress_tracker");
  } catch (const std::exception&) {
    return false;
  }
}

auto BundleEgressObject(std::string_view bundle_dir) -> std::string {
  auto entry = ReadEgressEntry(bundle_dir);
  if (!entry.is_object()) {
    return {};
  }
  auto obj = entry.value("object", nlohmann::json());
  if (!obj.is_string() || obj.get<std::string>().empty()) {
    // Declared but not compiled: the caller must refuse, not fall back
    // to "no tracker". Returning "" here and letting it read as absent
    // is exactly how `"object": null` used to pass for a working
    // bundle on the zone path.
    return {};
  }
  return (std::filesystem::path(bundle_dir) / obj.get<std::string>())
      .string();
}

auto BundleEgressProgram(std::string_view bundle_dir) -> std::string {
  auto entry = ReadEgressEntry(bundle_dir);
  if (entry.is_object()) {
    auto p = entry.value("program", std::string{});
    if (!p.empty()) return p;
  }
  return "fwl_egress_ct";
}

auto EgressFilterPresent(int ifindex, uint32_t prog_id) -> bool {
  auto hook = MakeHook(ifindex);
  struct bpf_tc_opts opts = {};
  opts.sz = sizeof(opts);
  opts.handle = kEgressHandle;
  opts.priority = kEgressPriority;
  if (bpf_tc_query(&hook, &opts) != 0 || opts.prog_id == 0) {
    return false;
  }
  // `prog_id == 0` asks only whether the slot is occupied, and a filter
  // left by a killed predecessor occupies the same handle and priority.
  // Reading that as "attached" makes the status line a claim about
  // somebody else's program.
  return prog_id == 0 || opts.prog_id == prog_id;
}

auto DetachEgressOn(int ifindex) -> void {
  auto hook = MakeHook(ifindex);
  struct bpf_tc_opts opts = {};
  opts.sz = sizeof(opts);
  opts.handle = kEgressHandle;
  opts.priority = kEgressPriority;
  bpf_tc_detach(&hook, &opts);
}

auto RemoveEgressFrom(int ifindex, const EgressTracker& owner) -> void {
  DetachEgressOn(ifindex);
  for (int idx : owner.created_qdisc) {
    if (idx != ifindex) {
      continue;
    }
    auto hook = MakeHook(ifindex);
    hook.attach_point =
        static_cast<enum bpf_tc_attach_point>(BPF_TC_INGRESS |
                                              BPF_TC_EGRESS);
    bpf_tc_hook_destroy(&hook);
    return;
  }
}

auto DetachEgressTracker(const EgressTracker& t) -> void {
  for (int idx : t.ifindexes) {
    DetachEgressOn(idx);
  }
  for (int idx : t.created_qdisc) {
    // Only the qdiscs this daemon created. clsact is one qdisc for both
    // directions, so destroying one we found already there would take
    // whatever the operator had on ingress with it.
    auto hook = MakeHook(idx);
    hook.attach_point =
        static_cast<enum bpf_tc_attach_point>(BPF_TC_INGRESS |
                                              BPF_TC_EGRESS);
    bpf_tc_hook_destroy(&hook);
  }
}

auto CloseEgressTracker(EgressTracker& t) -> void {
  if (t.obj != nullptr) {
    bpf_object__close(t.obj);
    t.obj = nullptr;
  }
  t.prog_fd = -1;
  t.stats_fd = -1;
}

namespace {

/// Undo a partial attach.
///
/// For each interface already flipped: put the PREVIOUS tracker's
/// program back where there was one, and detach where there was not.
/// Destroy only the qdiscs this attempt created. Removing the filters
/// outright — the obvious rollback — would disarm the tracker of a
/// bundle that is still running and still enforcing, while the caller
/// reports that nothing was disturbed.
auto RollbackAttach(const EgressTracker& t, const EgressTracker* previous,
                    const std::set<int>& made_here) -> void {
  std::set<int> prev_covered;
  if (previous != nullptr) {
    prev_covered.insert(previous->ifindexes.begin(),
                        previous->ifindexes.end());
  }
  for (int idx : t.ifindexes) {
    if (prev_covered.contains(idx) && previous->prog_fd >= 0) {
      auto hook = MakeHook(idx);
      struct bpf_tc_opts opts = {};
      opts.sz = sizeof(opts);
      opts.handle = kEgressHandle;
      opts.priority = kEgressPriority;
      opts.prog_fd = previous->prog_fd;
      opts.flags = BPF_TC_F_REPLACE;
      if (bpf_tc_attach(&hook, &opts) == 0) {
        continue;
      }
      spdlog::warn(
          "egress rollback: could not restore the previous tracker on "
          "ifindex {}; it is now untracked", idx);
    }
    DetachEgressOn(idx);
  }
  for (int idx : t.created_qdisc) {
    if (!made_here.contains(idx)) {
      continue;
    }
    auto hook = MakeHook(idx);
    hook.attach_point =
        static_cast<enum bpf_tc_attach_point>(BPF_TC_INGRESS |
                                              BPF_TC_EGRESS);
    bpf_tc_hook_destroy(&hook);
  }
}

}  // namespace

auto AttachEgressTracker(std::string_view bundle_dir,
                         std::string_view pin_root,
                         const std::vector<EgressTarget>& targets,
                         const EgressTracker* previous)
    -> std::expected<EgressTracker, Error<BpfError>> {
  EgressTracker t;
  // Qdiscs the daemon already owns, carried across the swap. See the
  // header: without this, ownership is lost on the first reload and
  // `systemctl stop` leaves an orphan clsact behind.
  std::set<int> owned;
  if (previous != nullptr) {
    owned.insert(previous->created_qdisc.begin(),
                 previous->created_qdisc.end());
  }
  // Qdiscs THIS call created, as opposed to ones it inherited. Only
  // these may be destroyed by a rollback: an inherited one still has
  // the previous tracker's filter on it.
  std::set<int> made_here;
  std::string obj_path = BundleEgressObject(bundle_dir);
  if (obj_path.empty()) {
    // The manifest declares a tracker (the caller checked) and it has
    // no compiled object. Same shape and same cause as a zone entry
    // with `"object": null` — a compile on a host without clang — and
    // the same answer: refuse, rather than run a firewall whose own DNS
    // will be dropped by its own policy with nothing saying so.
    return MakeError(BpfError::kLoadFailed,
        std::format("bundle {}: the manifest declares an egress "
                    "conntrack tracker with no compiled object. Every "
                    "flow this box originates would go untracked and "
                    "its replies would be dropped by this policy — "
                    "recompile the bundle on a host with clang.",
                    bundle_dir));
  }
  if (targets.empty()) {
    return MakeError(BpfError::kAttachFailed,
        std::format("bundle {}: nothing to attach the egress tracker "
                    "to. The datapath is attached to no interface, so "
                    "there is no port on which a reply to a flow this "
                    "box originated could be judged.",
                    bundle_dir));
  }

  std::string pin_root_str(pin_root);
  LIBBPF_OPTS(bpf_object_open_opts, open_opts);
  open_opts.pin_root_path = pin_root_str.c_str();
  t.obj = bpf_object__open_file(obj_path.c_str(), &open_opts);
  if (t.obj == nullptr) {
    return MakeError(BpfError::kLoadFailed,
        std::format("open egress tracker {} failed", obj_path));
  }
  int err = bpf_object__load(t.obj);
  if (err) {
    // The overwhelmingly likely -EINVAL here is a `conntrack` pin whose
    // definition this object disagrees with, which would mean the
    // emitter's one _CONNTRACK_DECL had been copied instead of shared.
    std::string msg = std::format(
        "load egress tracker {} failed: {}. The tracker shares the "
        "bundle's pinned `conntrack` map, so a definition mismatch "
        "here means the object was built against a different "
        "compiler.",
        obj_path, std::strerror(-err));
    bpf_object__close(t.obj);
    t.obj = nullptr;
    return MakeError(BpfError::kLoadFailed, std::move(msg));
  }

  std::string prog_name(BundleEgressProgram(bundle_dir));
  struct bpf_program* prog =
      bpf_object__find_program_by_name(t.obj, prog_name.c_str());
  if (prog == nullptr) {
    CloseEgressTracker(t);
    return MakeError(BpfError::kLoadFailed,
        std::format("egress tracker {} has no program '{}'",
                    obj_path, prog_name));
  }
  t.prog_fd = bpf_program__fd(prog);
  // The kernel id, so `EgressFilterPresent` can ask whether OUR filter
  // is on an interface rather than whether SOMETHING occupies the slot.
  // A filter left by a killed predecessor sits at the same handle and
  // priority, and reading it as "attached" is the daemon's own status
  // line reporting a hook it has no relationship with.
  struct bpf_prog_info pinfo = {};
  uint32_t plen = sizeof(pinfo);
  if (bpf_prog_get_info_by_fd(t.prog_fd, &pinfo, &plen) == 0) {
    t.prog_id = pinfo.id;
  }
  struct bpf_map* stats =
      bpf_object__find_map_by_name(t.obj, "fwl_egress_stats");
  if (stats == nullptr) {
    // Not a degraded mode. Without the tally every counter reads 0 and
    // `EgressMgr::Report` can never fire, so the one failure this
    // feature can have — a refused insert because conntrack is full,
    // which restores the original symptom exactly — would be silent for
    // the life of the bundle. The emitter always emits this map, so its
    // absence means the object is not the one this daemon expects.
    CloseEgressTracker(t);
    return MakeError(BpfError::kLoadFailed,
        std::format("egress tracker {} has no 'fwl_egress_stats' map, "
                    "so a refused insert could never be reported — and "
                    "a refusal is a flow of this box's own whose reply "
                    "this policy will drop.",
                    obj_path));
  }
  t.stats_fd = bpf_map__fd(stats);

  for (const auto& target : targets) {
    auto hook = MakeHook(target.ifindex);
    int herr = bpf_tc_hook_create(&hook);
    // The error test comes FIRST. Written the other way round, a real
    // -EPERM or -ENODEV on an interface this daemon happened to own the
    // qdisc of was read as success, recorded as created, and then
    // destroyed by the rollback — a qdisc whose creation was never
    // confirmed.
    if (herr != 0 && herr != -EEXIST) {
      RollbackAttach(t, previous, made_here);
      CloseEgressTracker(t);
      return MakeError(BpfError::kAttachFailed,
          std::format("clsact qdisc on {} (ifindex {}): {}",
                      target.name, target.ifindex,
                      std::strerror(-herr)));
    }
    if (herr == 0) {
      t.created_qdisc.push_back(target.ifindex);
      made_here.insert(target.ifindex);
    } else if (owned.contains(target.ifindex)) {
      // -EEXIST because the tracker being replaced made it. Ownership
      // carries forward; see the header.
      t.created_qdisc.push_back(target.ifindex);
    }
    struct bpf_tc_opts opts = {};
    opts.sz = sizeof(opts);
    opts.handle = kEgressHandle;
    opts.priority = kEgressPriority;
    opts.prog_fd = t.prog_fd;
    opts.flags = BPF_TC_F_REPLACE;
    int aerr = bpf_tc_attach(&hook, &opts);
    if (aerr) {
      // Roll back everything attached so far. A strict subset is not a
      // degraded mode here: it is a box whose own DNS works through one
      // port and is dropped on another, which is harder to diagnose
      // than either extreme.
      //
      // On a reload the interfaces already done carry the NEW program,
      // put there by an atomic REPLACE over the OLD one. Detaching them
      // — which is what a plain DetachEgressTracker does — would leave
      // the still-running previous bundle with no tracker on part of
      // its ports while the caller reported "the old bundle is still
      // attached and intact". Restore, do not remove.
      RollbackAttach(t, previous, made_here);
      CloseEgressTracker(t);
      return MakeError(BpfError::kAttachFailed,
          std::format("attach egress tracker to {} (ifindex {}) "
                      "failed: {}. Every interface here is one the "
                      "datapath just attached to, so this is not a "
                      "missing NIC.",
                      target.name, target.ifindex,
                      std::strerror(-aerr)));
    }
    t.ifindexes.push_back(target.ifindex);
    t.interfaces.push_back(target.name);
  }

  // The outcome, asked as an outcome. Loading is not attaching and a
  // count of the first says nothing about the second; the loop above
  // cannot reach here with an empty list, and this is the check that
  // makes that a guarantee rather than an observation about the loop.
  if (t.ifindexes.empty()) {
    CloseEgressTracker(t);
    return MakeError(BpfError::kAttachFailed,
        std::format("bundle {}: the egress conntrack tracker loaded "
                    "and attached to ZERO interfaces. Flows this box "
                    "originates would be untracked while the load "
                    "reported success — DNS, NTP and every update path "
                    "would fail against this policy with nothing "
                    "logged.",
                    bundle_dir));
  }
  spdlog::info(
      "egress conntrack tracker attached to {} interface(s): {}",
      t.ifindexes.size(),
      [&t] {
        std::string s;
        for (const auto& n : t.interfaces) {
          if (!s.empty()) s += ", ";
          s += n;
        }
        return s;
      }());
  return t;
}

}  // namespace f
