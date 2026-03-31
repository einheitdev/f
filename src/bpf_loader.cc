/// @file bpf_loader.cc
/// @brief BPF program loading, attaching, and map management.
///
/// Uses libbpf's generic object API so the build doesn't depend
/// on a generated skeleton header.  The skeleton path is preferred
/// when available, but this file compiles without bpftool.

#include "f/bpf_loader.h"

#include <cerrno>
#include <cstring>
#include <filesystem>
#include <format>

#include "f/types.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <net/if.h>

namespace f {

namespace {

struct bpf_object* g_obj = nullptr;

auto FindMap(struct bpf_object* obj, const char* name)
    -> int {
  struct bpf_map* map = bpf_object__find_map_by_name(
      obj, name);
  return map ? bpf_map__fd(map) : -1;
}

}  // namespace

auto LoadProgram()
    -> std::expected<BpfHandles, Error<BpfError>> {
  // Look for the compiled BPF object next to the binary
  // or in the build directory.
  const char* paths[] = {
      "fw.bpf.o",
      "build/fw.bpf.o",
      "../bpf/fw.bpf.o",
      "/usr/lib/f/fw.bpf.o",
  };

  for (const auto* path : paths) {
    if (std::filesystem::exists(path)) {
      g_obj = bpf_object__open(path);
      if (g_obj) {
        break;
      }
    }
  }

  if (!g_obj) {
    return MakeError(BpfError::kLoadFailed,
        "fw.bpf.o not found — compile the BPF program "
        "first (clang -target bpf)");
  }

  int err = bpf_object__load(g_obj);
  if (err) {
    bpf_object__close(g_obj);
    g_obj = nullptr;
    return MakeError(BpfError::kLoadFailed,
        std::format("bpf_object__load failed: {}",
                    std::strerror(-err)));
  }

  struct bpf_program* prog =
      bpf_object__find_program_by_name(g_obj, "fw_prog");
  if (!prog) {
    bpf_object__close(g_obj);
    g_obj = nullptr;
    return MakeError(BpfError::kLoadFailed,
        "fw_prog not found in BPF object");
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

auto PinMaps(const BpfHandles& h,
             std::string_view pin_path)
    -> std::expected<void, Error<BpfError>> {
  std::filesystem::create_directories(pin_path);
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

}  // namespace f
