/// @file engine.cc
/// @brief BPF engine: load, attach, pin, ZMQ control loop.

#include "f/engine.h"
#include "f/reload.h"

#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <format>
#include <fstream>
#include <set>
#include <string>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

namespace f {

auto WritePidFile(const char* path) -> bool {
  std::ofstream f(path);
  if (!f) return false;
  f << getpid();
  return f.good();
}

auto ReadPidFile(const char* path) -> int {
  std::ifstream f(path);
  int pid = -1;
  f >> pid;
  return pid;
}

auto RemovePidFile(const char* path) -> void {
  std::filesystem::remove(path);
}

auto IsProcessRunning(int pid) -> bool {
  return pid > 0 && kill(pid, 0) == 0;
}

namespace {

using json = nlohmann::json;

auto CurrentTimeS() -> uint64_t {
  return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::seconds>(
          std::chrono::steady_clock::now().time_since_epoch())
          .count());
}

auto ProtoName(uint8_t proto) -> std::string {
  switch (proto) {
    case 1: return "icmp";
    case 6: return "tcp";
    case 17: return "udp";
    case 0: return "any";
    default: return std::to_string(proto);
  }
}

auto CtStateName(uint8_t state) -> std::string {
  switch (state) {
    case 0: return "new";
    case 1: return "established";
    case 2: return "related";
    case 3: return "invalid";
    default: return std::to_string(state);
  }
}

auto Ipv4Str(uint32_t netorder) -> std::string {
  char buf[INET_ADDRSTRLEN] = {};
  inet_ntop(AF_INET, &netorder, buf, sizeof(buf));
  return buf;
}

// Report the masquerade source address of every masquerading zone into
// `out`, read back off the very maps the XDP programs read.
//
// PER ZONE, because there is one per zone: `masquerade` translates to
// the address of the zone THIS one redirects to, and two masquerading
// zones need not name the same uplink — `deploy/firstboot` gives every
// non-uplink zone its own `masquerade` + `redirect to <uplink>`. A
// single `masq_source` cannot express a box with two uplinks, and a
// report that cannot state the truth is part of how the one-slot
// version of this map stayed invisible: everything said healthy while
// half the traffic was translated to the other zone's address.
//
// `masq_source` is kept when every masquerading zone resolved the SAME
// address — the ordinary one-uplink gateway, and what the field always
// meant. A box with two uplinks has no single answer and gets none;
// `masq_sources` is where it is.
auto AddMasqSources(const ZoneBundleHandles& bundle,
                    nlohmann::json* out) -> void {
  json sources = json::array();
  std::set<std::string> distinct;
  for (const auto& zp : bundle.programs) {
    // Zones this loader actually seeded — a zone that does not
    // masquerade has nothing to report. Asked of the MAP instead, a
    // pre-split bundle would list every zone in it, because they all
    // resolve one slot; the whole point of the row is which zone
    // translates to what.
    if (zp.nat_cfg_fd < 0 || zp.masq_addr == 0) continue;
    // The value comes off the map the program reads, not off what the
    // loader remembers writing. On a pre-split bundle those two differ
    // for every zone but the last, and that difference IS the defect —
    // so the report shows what the datapath holds.
    uint32_t k = 0, masq = 0;
    if (bpf_map_lookup_elem(zp.nat_cfg_fd, &k, &masq) != 0 || masq == 0) {
      continue;
    }
    std::string addr = Ipv4Str(masq);
    sources.push_back({{"zone", zp.zone}, {"address", addr}});
    distinct.insert(addr);
  }
  if (!sources.empty()) {
    (*out)["masq_sources"] = sources;
  }
  if (distinct.size() == 1) {
    (*out)["masq_source"] = *distinct.begin();
  }
  // And whether those addresses can be trusted to be per zone at all:
  // on a bundle compiled before the split they are ONE slot read
  // several times, so two zones reading differently is not possible
  // however the policy is written. Recompiling is the fix.
  if (bundle.legacy_nat_cfg) {
    (*out)["masq_source_is_bundle_wide"] = true;
  }
}

// Cap on entries serialized per map dump — an unbounded map (up to 64k
// conntrack/NAT entries) would block the single-threaded control loop
// while it builds the JSON. Beyond this the reply is marked truncated.
constexpr size_t kMaxDumpEntries = 4096;

// Which XDP mode a program is attached in on `ifindex`: native (driver)
// is line-rate, generic (SKB) is the software fallback for NICs without
// native XDP. Operators need this to know if they are on the slow path.
auto XdpMode(int ifindex) -> std::string {
  LIBBPF_OPTS(bpf_xdp_query_opts, opts);
  if (bpf_xdp_query(ifindex, 0, &opts) != 0) return "unknown";
  switch (opts.attach_mode) {
    case XDP_ATTACHED_DRV:
    case XDP_ATTACHED_HW:
      return "native";
    case XDP_ATTACHED_SKB:
      return "generic";
    case XDP_ATTACHED_NONE:
      return "none";
    default:
      return "multi";
  }
}

auto HandleRequest(Engine& e, const std::string& req_str)
    -> std::string {
  if (req_str.empty()) {
    return R"({"error":"empty request"})";
  }
  auto cmd = static_cast<Cmd>(
      static_cast<uint8_t>(req_str[0]));
  switch (cmd) {
    case Cmd::kGetStatus: {
      return GetFullState(e).dump();
    }
    case Cmd::kStop: {
      spdlog::info("Received stop command.");
      e.state.store(EngineState::kStopping,
                    std::memory_order_release);
      return R"({"ok":true})";
    }
    case Cmd::kReloadProg: {
      // Recompile the configured source and hot-swap it. On any
      // failure (compile error, invalid bundle) ReloadFromSource
      // leaves the running program untouched — the reload path never
      // installs a broken program.
      auto r = ReloadFromSource(e);
      if (!r) {
        return json({{"error", r.error().message}}).dump();
      }
      return json({
          {"status", "reloaded"},
          {"version", r->version},
          {"program_updated", r->program_updated},
      }).dump();
    }
    case Cmd::kGetZones: {
      // v0.4 multi-zone bundle topology. Empty on the single-program
      // path (no zones declared).
      json arr = json::array();
      for (const auto& p : e.zone_bundle.programs) {
        json attached = json::array();
        // Aggregate the XDP attach mode across the zone's interfaces:
        // a single value if they agree, "mixed" otherwise.
        std::string mode;
        for (int idx : p.ifindexes) {
          char nm[IF_NAMESIZE] = {};
          if (if_indextoname(static_cast<unsigned int>(idx), nm)) {
            attached.push_back(std::string(nm));
          }
          auto m = XdpMode(idx);
          if (mode.empty()) {
            mode = m;
          } else if (mode != m) {
            mode = "mixed";
          }
        }
        arr.push_back({
            {"zone", p.zone},
            {"interfaces", p.interfaces},
            {"redirects_to", p.redirects_to},
            {"masquerades", p.masquerades},
            {"attached", attached},
            {"attached_count", p.ifindexes.size()},
            {"xdp_mode", mode.empty() ? "none" : mode},
        });
      }
      return arr.dump();
    }
    case Cmd::kGetNat: {
      json j;
      json arr = json::array();
      // The same clock the datapath stamps with (bpf_ktime_get_ns is
      // CLOCK_MONOTONIC), so the difference is a real age and not two
      // unrelated numbers subtracted.
      auto now_ns = static_cast<uint64_t>(
          std::chrono::duration_cast<std::chrono::nanoseconds>(
              std::chrono::steady_clock::now().time_since_epoch())
              .count());
      int fd = e.zone_bundle.nat_fd;
      if (fd >= 0) {
        FwlNatKey key{}, next{};
        FwlNatValue val{};
        bool has =
            bpf_map_get_next_key(fd, nullptr, &next) == 0;
        while (has) {
          if (bpf_map_lookup_elem(fd, &next, &val) == 0) {
            // fwl_nat holds reply mappings, so nat_type is what the
            // RETURN packet rewrites — the inverse of the original
            // action. Report the original direction operators expect:
            // a reply that restores the destination (DNAT) came from an
            // outbound snat/masquerade; one that restores the source
            // (SNAT) came from an inbound dnat/port-forward.
            const char* dir = val.nat_type == 2 ? "snat" : "dnat";
            // How long since the datapath last touched this mapping.
            // A list of translations with no ages cannot answer the
            // question an operator is actually asking — "is any of
            // this still real" — and the reclamation rule is stated in
            // exactly these terms.
            uint64_t idle_ns = now_ns > val.last_seen_ns
                                   ? now_ns - val.last_seen_ns
                                   : 0;
            arr.push_back({
                {"proto", ProtoName(next.proto)},
                {"orig_src", Ipv4Str(next.src_addr)},
                {"orig_dst", Ipv4Str(next.dst_addr)},
                {"orig_src_port", next.src_port},
                {"orig_dst_port", next.dst_port},
                {"new_addr", Ipv4Str(val.new_addr)},
                {"new_port", val.new_port},
                {"type", dir},
                {"idle_s", idle_ns / 1'000'000'000ULL},
            });
          }
          key = next;
          has = bpf_map_get_next_key(fd, &key, &next) == 0;
          if (arr.size() >= kMaxDumpEntries) {
            j["truncated"] = true;
            break;
          }
        }
      }
      j["translations"] = arr;
      // The masquerade source addresses the datapath is actually
      // holding, read back per zone off the maps the programs read.
      AddMasqSources(e.zone_bundle, &j);
      return j.dump();
    }
    case Cmd::kGetConntrack: {
      json arr = json::array();
      int fd = e.conntrack.map_fd;
      if (fd >= 0) {
        ConnKey key{}, next{};
        ConnValue val{};
        bool has =
            bpf_map_get_next_key(fd, nullptr, &next) == 0;
        while (has) {
          if (bpf_map_lookup_elem(fd, &next, &val) == 0) {
            arr.push_back({
                {"proto", ProtoName(next.proto)},
                {"src", Ipv4Str(next.src_addr)},
                {"dst", Ipv4Str(next.dst_addr)},
                {"src_port", next.src_port},
                {"dst_port", next.dst_port},
                {"state", CtStateName(val.state)},
                {"packets", val.packets},
                {"last_seen_ns", val.last_seen_ns},
            });
          }
          key = next;
          has = bpf_map_get_next_key(fd, &key, &next) == 0;
          // The response is a bare array (the CLI/UI consume it as one),
          // so cap it and log rather than reshape to add a flag — the
          // point is to not block the control loop serializing 64k
          // entries.
          if (arr.size() >= kMaxDumpEntries) {
            spdlog::warn("conntrack dump truncated at {} entries",
                         kMaxDumpEntries);
            break;
          }
        }
      }
      return arr.dump();
    }
    case Cmd::kGetFwlCounters: {
      // The policy's own `count <name>` statements, per zone. Both
      // halves of each answer were captured by the load that put the
      // program in the packet path: the map descriptor from the
      // object, the name->slot table from the generated C beside it.
      // Nothing here re-derives the pairing, and nothing here numbers
      // anything — the name the operator wrote travels with the value.
      std::vector<ZoneCounters> zones;
      zones.reserve(e.zone_bundle.programs.size());
      for (const auto& p : e.zone_bundle.programs) {
        BpfCounterMap map(p.counters_fd);
        zones.push_back(ReadZoneCounters(
            p.zone, p.counters,
            p.counters_fd >= 0 ? &map : nullptr));
      }
      return ZoneCountersToJson(zones).dump();
    }
    case Cmd::kGetFwlRules: {
      // What this box is enforcing, zone by zone, in policy order.
      // Every rule below was captured by the load that put the program
      // in the packet path — from the manifest read in that same call,
      // not from the bundle directory as it stands now. A policy
      // recompiled since the load leaves this answer alone, which is
      // the whole point: it describes the packet path, and the source
      // digest beside it is what tells an operator the two have parted
      // company.
      std::vector<ZoneRules> zones;
      zones.reserve(e.zone_bundle.programs.size());
      for (const auto& p : e.zone_bundle.programs) {
        zones.push_back(p.rules);
      }
      return ZoneRulesToJson(zones, e.zone_bundle.policy_source)
          .dump();
    }
    default:
      return R"({"error":"unknown command"})";
  }
}

}  // namespace

auto HandleControlRequest(Engine& e, const std::string& req)
    -> std::string {
  return HandleRequest(e, req);
}

auto AttachRouteMgr(Engine& e) -> void {
  e.route.stats_fd = e.zone_bundle.route_stats_fd;
  e.route.enabled = e.route.stats_fd >= 0;
  // POLICY-lifetime map: the pin is discarded on a reload and the new
  // bundle counts from zero, so the "already reported" watermarks have
  // to reset with it. Otherwise the first drops after a reload sit
  // below the old mark and are never logged — the daemon goes quiet
  // about exactly the event it exists to shout about.
  e.route.reported_no_route = 0;
  e.route.reported_no_neigh = 0;
}

auto SetForwardingFromDatapath(Engine& e, std::string_view when)
    -> void {
  // One fact, one knob. Not the zone count, not whether any zone
  // redirects — the number of interfaces the KERNEL accepted an XDP
  // program on. A policy analysis can be wrong about whether this box
  // routes; this cannot be wrong about whether it filters.
  if (e.ifaces.count > 0) {
    e.route.SetForwarding(
        true, std::format("{}: datapath armed on {} interface(s)",
                          when, e.ifaces.count));
  } else {
    e.route.SetForwarding(
        false,
        std::format("{}: NO interface is running an f program, so "
                    "nothing is being filtered",
                    when));
  }
}

auto AttachEgressMgr(Engine& e, std::string_view bundle_dir) -> void {
  e.egress.stats_fd = e.zone_bundle.egress.stats_fd;
  // Attachment, not loading. The tracker's object can be perfectly
  // loaded and on no interface at all, and that box's DNS is broken —
  // this is the same distinction the datapath's own "1 zone program(s)"
  // line failed to make.
  e.egress.enabled = e.zone_bundle.egress.Attached();
  e.egress.interfaces = e.zone_bundle.egress.interfaces;
  e.egress.ifindexes = e.zone_bundle.egress.ifindexes;
  e.egress.prog_id = e.zone_bundle.egress.prog_id;
  // From the manifest — the compiler's own answer — not from the map's
  // presence. Every NAT bundle carries `conntrack` whether or not its
  // policy ever reads the state, so `conntrack_fd >= 0` said yes for a
  // masquerade-only policy and produced a red status row and an ERROR
  // per load on a box with nothing wrong with it.
  e.egress.tracker_declared = BundleDeclaresEgressTracker(bundle_dir);
  e.egress.bundle_predates_tracker =
      !ManifestHasEgressField(bundle_dir);
  // POLICY-lifetime map, so the pin is discarded on a reload and the
  // counters restart from zero; the watermark has to restart with them
  // or the first refusals after a reload sit under the old mark and are
  // never logged.
  e.egress.reported_refusals = 0;
  if (e.egress.tracker_declared && !e.egress.enabled) {
    // Should be unreachable — a declared tracker that will not attach
    // fails the load — so this is a belt against a future path that
    // forgets that, not a routine condition. Nothing else about such a
    // box would look wrong: the firewall filters, every counter climbs,
    // and its own DNS resolves nothing.
    spdlog::error(
        "This bundle declares an egress conntrack tracker and none is "
        "attached, so flows this box ORIGINATES (DNS forwarding, NTP, "
        "updates) create no conntrack entry and their replies read "
        "NEW.");
  }
}

auto AttachNatMgr(Engine& e) -> void {
  e.nat.map_fd = e.zone_bundle.nat_fd;
  e.nat.stats_fd = e.zone_bundle.nat_stats_fd;
  // One conntrack fd, held in two places, taken from one source: a
  // mapping is reclaimed on the say-so of the conntrack entry behind
  // it, so the two managers must be looking at the same table.
  e.nat.conntrack_fd = e.conntrack.map_fd;
  e.nat.enabled = e.nat.map_fd >= 0;
  // `fwl_nat_stats` is POLICY-lifetime: its pin is discarded on a
  // reload and the new bundle starts counting from zero. The mirror of
  // "refusals already reported" has to reset with it, or after a
  // reload the first refusals sit below the old high mark and are
  // never logged — the daemon would go quiet about exactly the event
  // it exists to shout about. The table's own numbers (high_water,
  // total_reclaimed) are the daemon's observations of a FLOW-lifetime
  // map that survives the reload, so they carry over.
  e.nat.reported_refusals = 0;
  if (!e.nat.enabled) {
    e.nat.max_entries = 0;
    return;
  }
  // Read the cap from the map rather than assume 65536: occupancy is
  // only meaningful as a fraction of the real limit, and a hard-coded
  // one silently reports the wrong percentage the day the emitter
  // changes it.
  struct bpf_map_info info = {};
  uint32_t len = sizeof(info);
  if (bpf_obj_get_info_by_fd(e.nat.map_fd, &info, &len) == 0) {
    e.nat.max_entries = info.max_entries;
  }
  spdlog::info(
      "NAT mapping GC enabled: {} entries max, reclaimed when the "
      "flow's conntrack entry is gone and the mapping has been idle "
      "{}s; swept every {}s with conntrack.",
      e.nat.max_entries, e.nat.grace_s, e.conntrack.gc_interval_s);
}

auto EngineInit(Engine& e,
                std::string_view sock_addr,
                std::string_view pin_path,
                std::string_view bundle_dir)
    -> std::expected<void, Error<EngineError>> {
  e.socket_addr = std::string(sock_addr);
  e.pin_path = std::string(pin_path);
  e.start_time_s = CurrentTimeS();
  e.state.store(EngineState::kStarting);

  // Close the box before doing anything else, and do not depend on
  // systemd or on the sysctl drop-in to have done it.
  //
  // Every path out of the rest of this function that is not "the
  // datapath is armed" ends with the process exiting, and until the
  // attach succeeds there is no firewall in the packet path. If the
  // previous instance was SIGKILLed it never ran EngineStop, so the
  // knob can be at 1 with the XDP programs from a policy this daemon
  // is about to replace. Lowering here costs a forwarding gap that
  // already exists (EngineStop detaches XDP) and buys the guarantee
  // that fd's own refusal to start is enough, on its own, to stop the
  // box routing.
  e.route.SetForwarding(
      false, "fd is starting: the datapath is not armed yet");

  // v0.4 § 6.2 cold-boot: load every zone program in the bundle staged
  // at <bundle_dir>/current and attach them per-zone from the
  // manifest's interface lists. The per-zone objects carry their policy
  // compiled in and share the bpffs-pinned conntrack map.
  //
  // There is no other branch. A second one used to sit below this,
  // loading the v0.1 `fw.bpf.o` when no bundle was staged, and what it
  // produced was a running daemon enforcing a policy nobody wrote:
  // `default_action = ALLOW`, attached, READY, and green in every view
  // the operator has. Refusing here is the same rule the zero-attach
  // check applies one level down — the daemon does not come up unless
  // the configured policy is in the packet path.
  std::string current_dir;
  if (!bundle_dir.empty()) {
    current_dir =
        (std::filesystem::path(bundle_dir) / "current").string();
  }
  if (current_dir.empty()) {
    return MakeError(EngineError::kInvalidConfig,
        "no bundle directory configured: fd loads its policy from "
        "<bundle-dir>/current and has nothing else to load. Set "
        "--bundle-dir (default /usr/share/f/compiled).");
  }
  if (!IsMultiZoneBundle(current_dir)) {
    return MakeError(EngineError::kBpfLoadFailed,
        std::format(
            "{} is not a compiled bundle: no manifest.json, or one "
            "naming no @xdp programs. Compile the policy with `fwl "
            "compile <src> --bundle <dir>` and point `current` at it. "
            "Refusing to start rather than run a policy nobody wrote.",
            current_dir));
  }
  {
    spdlog::info("Cold-boot: loading multi-zone bundle from {}...",
                 current_dir);
    // A pin outlives the process that made it. bpffs holds a reference,
    // so every map a previous `fd` pinned is still there — with the
    // previous POLICY's shape and the previous policy's numbering. The
    // reload path has always reconciled that; cold boot did not, and
    // the result was a daemon that could not start at all: libbpf
    // refuses to reuse a pin whose definition differs (-EINVAL), the
    // load fails, and systemd's Restart= turns it into a loop with no
    // XDP attached anywhere. A reboot cleared it (bpffs is a fresh
    // mount) and a restart did not, so the fault presented as "works
    // after a reboot, fails after a restart" — measured on the rig,
    // tests/system/hw/l8_09_stale_pins_cold_boot.sh.
    //
    // kColdBoot: there is no running policy to fall back on, so an
    // unusable pin is discarded rather than deferred to the loader.
    // Losing state hurts; not coming up at all is worse.
    auto pins = ReconcilePinnedMaps(current_dir, e.pin_path,
                                    PinPolicy::kColdBoot,
                                    e.conntrack.timeout_s);
    for (const auto& name : pins.discarded) {
      spdlog::info("Cold-boot: discarded stale pin '{}' "
                   "(left by a previous policy).", name);
    }
    for (const auto& name : pins.adopted) {
      spdlog::info("Cold-boot: adopted pinned '{}' (flow-keyed state, "
                   "definition matches this bundle).", name);
    }
    if (pins.conntrack_swept > 0) {
      spdlog::info(
          "Cold-boot: swept {} conntrack entries older than {}s from "
          "the adopted table.",
          pins.conntrack_swept, e.conntrack.timeout_s);
    }
    auto zb = LoadZoneBundle(current_dir, e.pin_path);
    if (!zb) {
      return MakeError(EngineError::kBpfLoadFailed,
          std::format("LoadZoneBundle: {}", zb.error().message));
    }
    e.zone_bundle = *zb;
    e.conntrack.map_fd = e.zone_bundle.conntrack_fd;
    // Garbage collection is gated on `enabled`, which was only ever
    // set by ApplyConfig — the single-program rule path. A bundle
    // deployment (i.e. every v0.4 deployment) therefore never
    // collected: entries accumulated until the map hit its 65536
    // cap, after which new flows stopped being tracked and every
    // established-state rule silently began mismatching, with
    // nothing logged. Measured on hardware —
    // tests/system/hw/l8_02_conntrack_gc.sh saw entries only grow
    // with enabled=false and total_evicted stuck at 0.
    //
    // Enable it whenever the bundle actually carries a conntrack map
    // (a policy that never reads conntrack(pkt).state has none, and
    // there is nothing to collect). The struct defaults — 300 s
    // idle timeout, 30 s sweep — are the documented ones.
    if (e.zone_bundle.conntrack_fd >= 0) {
      e.conntrack.enabled = true;
      spdlog::info(
          "Conntrack GC enabled (timeout {}s, sweep every {}s).",
          e.conntrack.timeout_s, e.conntrack.gc_interval_s);
    }
    AttachNatMgr(e);
    AttachRouteMgr(e);
    AttachEgressMgr(e, current_dir);
    // Record the attached interfaces for status reporting.
    for (const auto& prog : e.zone_bundle.programs) {
      for (int idx : prog.ifindexes) {
        if (e.ifaces.count >=
            sizeof(e.ifaces.interfaces) /
                sizeof(e.ifaces.interfaces[0])) {
          break;
        }
        auto& entry = e.ifaces.interfaces[e.ifaces.count];
        entry.ifindex = idx;
        if_indextoname(static_cast<unsigned int>(idx), entry.name);
        e.ifaces.count++;
      }
    }
    // Both numbers, because the first one alone was the whole
    // problem: "1 zone program(s)" was true of a bundle attached to
    // no interface at all. The program count comes from the manifest;
    // the interface count comes from what the kernel accepted. Only
    // the second says the firewall is in the path.
    spdlog::info("Multi-zone bundle loaded: {} zone program(s), "
                 "attached to {} interface(s).",
                 e.zone_bundle.programs.size(), e.ifaces.count);
    // ...and only now does this box get to route. The count above is
    // the same number the readiness notification is gated on, taken
    // from the same place, so "systemd says ready" and "the kernel
    // forwards" cannot disagree.
    SetForwardingFromDatapath(e, "cold boot");
  }


  // ZMQ control socket.
  try {
    e.zmq_ctx = std::make_unique<zmq::context_t>(1);
    e.ctrl_socket = std::make_unique<zmq::socket_t>(
        *e.zmq_ctx, zmq::socket_type::rep);
    e.ctrl_socket->set(zmq::sockopt::rcvtimeo, 100);
    e.ctrl_socket->set(zmq::sockopt::linger, 0);

    if (e.socket_addr.starts_with("ipc://")) {
      std::string path = e.socket_addr.substr(6);
      if (std::filesystem::exists(path)) {
        std::filesystem::remove(path);
      }
    }
    e.ctrl_socket->bind(e.socket_addr);

    if (e.socket_addr.starts_with("ipc://")) {
      chmod(e.socket_addr.substr(6).c_str(), 0777);
    }
  } catch (const zmq::error_t& ex) {
    return MakeError(EngineError::kSocketError,
        std::format("ZMQ bind failed: {}", ex.what()));
  }
  spdlog::info("Control socket: {}", e.socket_addr);

  return {};
}


namespace {

/// Minimal sd_notify(3): report readiness to the service manager.
///
/// Implemented directly rather than by linking libsystemd — the
/// protocol is one datagram to the socket named in $NOTIFY_SOCKET,
/// and a firewall daemon does not need another shared library on its
/// critical path for it. A leading '@' denotes an abstract socket,
/// encoded as a leading NUL. Silently does nothing when the variable
/// is unset, so running fd by hand is unaffected.
auto NotifySystemd(const std::string& message) -> void {
  const char* path = ::getenv("NOTIFY_SOCKET");
  if (path == nullptr || *path == '\0') {
    return;
  }
  int fd = ::socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    return;
  }
  struct sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  std::string p(path);
  if (p.size() >= sizeof(addr.sun_path)) {
    ::close(fd);
    return;
  }
  std::memcpy(addr.sun_path, p.data(), p.size());
  if (addr.sun_path[0] == '@') {
    addr.sun_path[0] = '\0';  // abstract namespace
  }
  ::sendto(fd, message.data(), message.size(), MSG_NOSIGNAL,
           reinterpret_cast<struct sockaddr*>(&addr),
           static_cast<socklen_t>(offsetof(struct sockaddr_un, sun_path)
                                  + p.size()));
  ::close(fd);
}

}  // namespace

auto EngineRun(Engine& e, std::stop_token stop)
    -> std::expected<void, Error<EngineError>> {
  e.state.store(EngineState::kRunning);
  spdlog::info("Engine running. {} interfaces.",
               e.ifaces.count);

  // Readiness means "the datapath is armed", not "the process
  // started". With Type=simple, systemd considers the unit started
  // the moment exec() succeeds, so `Before=network.target` ordered
  // the spawn and nothing more: on the rig, network.target was
  // reached 17 ms BEFORE fd logged its first line, and the only
  // reason no traffic passed unfiltered is that PHY autonegotiation
  // happens to take ~1.4 s longer than loading a BPF program. That
  // margin is physics, not a guarantee — a larger bundle or a faster
  // link could invert it silently.
  //
  // With Type=notify, systemd holds network.target until this
  // datagram arrives, so the ordering is enforced rather than
  // observed.
  if (e.ifaces.count == 0) {
    // Nothing is attached, so nothing is being filtered. Staying
    // silent here makes systemd fail the unit on TimeoutStartSec
    // instead of reporting a healthy firewall that filters nothing
    // — the failure mode is otherwise invisible: active, green, and
    // forwarding everything.
    spdlog::error(
        "No interfaces attached — the datapath is NOT armed, and this "
        "box is therefore not forwarding either "
        "(net.ipv4.ip_forward=0). Refusing to report readiness; check "
        "the bundle's zone interfaces exist and that XDP attach "
        "succeeded.");
    NotifySystemd(
        "STATUS=datapath NOT armed: 0 interfaces attached, "
        "forwarding off\n");
  } else {
    NotifySystemd(
        std::format("READY=1\nSTATUS=datapath armed on {} "
                    "interface(s)\n",
                    e.ifaces.count));
  }

  // The v0.1 ring-buffer slow path started here, gated on
  // `e.bpf.events_fd`, which only the single-program loader ever set —
  // so on every bundle deployment it never started, and `fctl status`
  // reported `slow_path: {events: 0, allowed: 0, denied: 0}` as if it
  // had. It is gone with the datapath that fed it. The bundle's own
  // ring buffer is `fwl_log_events`, a different mechanism with a
  // different ABI, and nothing consumes it yet — which the
  // observability page says rather than implying otherwise with a
  // counter that is structurally zero.

  while (!stop.stop_requested() &&
         e.state.load(std::memory_order_acquire) !=
             EngineState::kStopping) {
    try {
      zmq::pollitem_t items[] = {
          {static_cast<void*>(*e.ctrl_socket),
           0, ZMQ_POLLIN, 0}};
      zmq::poll(items, 1,
                std::chrono::milliseconds(100));

      if (items[0].revents & ZMQ_POLLIN) {
        zmq::message_t request;
        auto res = e.ctrl_socket->recv(
            request, zmq::recv_flags::none);
        if (res) {
          std::string req_str(
              static_cast<char*>(request.data()),
              request.size());
          auto response = HandleRequest(e, req_str);
          zmq::message_t reply(response.size());
          std::memcpy(reply.data(), response.data(),
                      response.size());
          e.ctrl_socket->send(
              reply, zmq::send_flags::none);
        }
      }
    } catch (const zmq::error_t& ex) {
      if (ex.num() != ETERM && ex.num() != EINTR) {
        spdlog::error("ZMQ error: {}", ex.what());
      }
    }

    // Hot reload: the watcher thread flags a source change; the
    // compile + apply runs here on the main thread so it can touch
    // engine state without locking.
    if (WatcherConsumeReload(e.watcher)) {
      auto reloaded = ReloadFromSource(e);
      if (!reloaded) {
        spdlog::error("reload failed ({}); previous policy stays "
                      "active",
                      reloaded.error().message);
      }
    }

    auto now_ns = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now()
                .time_since_epoch())
            .count());
    auto evicted = e.conntrack.MaybeRunGc(now_ns);
    if (evicted > 0) {
      spdlog::debug("conntrack gc: evicted {} entries",
                    evicted);
    }
    // NAT mappings are reclaimed AFTER conntrack, never before: a
    // mapping is freed when its flow is over, and the conntrack entry
    // behind it is what says so. Sweeping the other way round would
    // read anchors this tick was about to delete and keep every dead
    // mapping for one extra interval.
    e.nat.MaybeRunGc(now_ns, e.conntrack.gc_interval_s);
    // Not a sweep — nothing to collect. Routing failures are
    // counted by the datapath and are invisible everywhere
    // else, so this is where they become a log line.
    e.route.Report();
    // The one knob this daemon owns, checked against what the kernel
    // actually holds. Corrects an unarmed box that somebody opened;
    // reports, and does not fight, an armed box that somebody closed.
    e.route.MaybeReassertForwarding(now_ns);
    // Same reason, one hook over: an insert the egress tracker
    // could not make is a flow of this box's own whose reply
    // this policy will drop, and it has no other symptom.
    e.egress.Report();
  }

  spdlog::info("Engine stopping.");
  e.state.store(EngineState::kStopping);
  return {};
}

auto EngineStop(Engine& e) -> void {
  WatcherStop(e.watcher);
  // Before the detach, not after, and this ordering is the whole
  // point. Between "no XDP program on any port" and "the kernel stops
  // routing" there must be no window in which this box is a plain
  // unfiltered router — and `systemctl stop fd` is the FIRST step in
  // the handbook's own recovery procedure, so that window is a thing
  // an operator is told to open.
  e.route.SetForwarding(
      false, "fd is stopping: XDP is being detached from every port");
  spdlog::info("Detaching XDP.");
  // Detach what is actually attached, not what was attached at
  // startup. `e.ifaces` is populated once in EngineInit; a reload
  // that changes zone membership replaces `e.zone_bundle` without
  // touching it. Walking the stale list left every interface a
  // reload had ADDED still running an XDP program after a clean
  // `systemctl stop` — a firewall with no daemon behind it,
  // surviving until reboot or a manual detach, and liable to
  // collide with the next start. Measured on hardware:
  // tests/system/hw/l8_05_stale_ifaces.sh.
  if (!e.zone_bundle.programs.empty()) {
    DetachZoneBundle(e.zone_bundle);
  }
  e.ctrl_socket.reset();
  e.zmq_ctx.reset();
  if (e.socket_addr.starts_with("ipc://")) {
    std::filesystem::remove(
        e.socket_addr.substr(6));
  }
  e.state.store(EngineState::kNotRunning);
  spdlog::info("Engine stopped.");
}

auto GetFullState(const Engine& e) -> nlohmann::json {
  json j;

  // Engine metadata.
  j["pid"] = static_cast<uint32_t>(getpid());
  j["uptime_s"] = CurrentTimeS() - e.start_time_s;

  // Each component reports its own state.
  //
  // There is no `rules` section. It came from `RuleTable::GetState()`,
  // which walked `rules_a`/`rules_b` and reported the total counter —
  // maps that only the v0.1 single-program datapath ever had. On every
  // bundle box it answered `{"active_table":"A","count":0,"rules":[]}`
  // and the CLI rendered `active_table A` / `rule_count 0` beside a
  // policy with dozens of rules in it. A section that is structurally
  // empty is not a smaller truth than the real one; it is a different
  // claim, and it is false. `show zones` and `show policy` are where
  // the loaded policy is reported.
  j["interfaces"] = e.ifaces.GetState();
  j["conntrack"] = e.conntrack.GetState();
  // The NAT table had no section here at all, which is why a map with
  // no collector behind it was also the one an operator could not
  // watch. l11_02 measured the consequence: 65536 mappings, "new
  // connections hang, old ones are fine", and nothing in the CLI to
  // see it in.
  j["nat"] = e.nat.GetState();
  // ...plus what each masquerading zone actually translates to. It
  // belongs here and not only in `show nat` because this is the live
  // view an operator watches, and because the one thing a two-uplink
  // box could not do until the map became per zone was tell you that
  // its two inside zones had ended up on one address.
  AddMasqSources(e.zone_bundle, &j["nat"]);
  // Whether a redirect re-addressed the frame to a next hop or handed
  // it on with the MAC it arrived carrying. Not visible in any capture
  // — a frame addressed to the wrong MAC is still on the cable — so
  // this section is the only place the difference is written down.
  j["route"] = e.route.GetState();
  // Whether flows the BOX ITSELF starts are tracked. Without the hook
  // this section reports, `conntrack(pkt).state` answers NEW for the
  // reply to the appliance's own DNS query and `default drop` eats it
  // — a box that filters perfectly and cannot resolve a name, with
  // every counter climbing and nothing anywhere saying why (l12_01).
  j["egress"] = e.egress.GetState();

  return j;
}

}  // namespace f
