/// @file bundle_verify.cc
/// @brief Implementation of the pre-flight bundle check. See
///        bundle_verify.h for why a zero exit status is not an answer.

#include "f/bundle_verify.h"

#include <unistd.h>

#include <chrono>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <format>
#include <fstream>
#include <sstream>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

namespace f {
namespace {

namespace fs = std::filesystem;
using json = nlohmann::json;

/// Load one object, describe what the kernel ended up holding, and
/// close it.
///
/// The verifier log is requested at a level that names the offending
/// instruction. It is the only text that turns "load failed: Argument
/// list too long" into something an operator can act on, and it is
/// thrown away by every default.
auto VerifyObject(const fs::path& obj_path, const std::string& pin_root,
                  VerifiedProgram* out) -> void {
  static thread_local std::string log_buf;
  log_buf.assign(256 * 1024, '\0');

  LIBBPF_OPTS(bpf_object_open_opts, open_opts);
  open_opts.pin_root_path = pin_root.c_str();
  open_opts.kernel_log_buf = log_buf.data();
  open_opts.kernel_log_size = log_buf.size();
  open_opts.kernel_log_level = 1;

  struct bpf_object* obj =
      bpf_object__open_file(obj_path.string().c_str(), &open_opts);
  if (!obj) {
    out->why = std::format("open {}: {}", obj_path.string(),
                           std::strerror(errno));
    return;
  }
  int err = bpf_object__load(obj);
  if (err) {
    // Trim to the tail: the interesting part of a verifier log is the
    // last few lines, and the head is thousands of lines of state.
    std::string log(log_buf.c_str());
    std::string tail;
    if (!log.empty()) {
      std::size_t cut = log.size() > 1200 ? log.size() - 1200 : 0;
      tail = log.substr(cut);
    }
    out->why = std::format("load failed: {}{}", std::strerror(-err),
                           tail.empty() ? "" : "\n" + tail);
    bpf_object__close(obj);
    return;
  }

  // A load that "succeeded" and left nothing behind is a failure. The
  // rig harness learned this the expensive way; the same rule applies
  // here for the same reason.
  struct bpf_program* prog = nullptr;
  bpf_object__for_each_program(prog, obj) {
    int fd = bpf_program__fd(prog);
    if (fd < 0) continue;
    struct bpf_prog_info info = {};
    std::uint32_t len = sizeof(info);
    if (bpf_obj_get_info_by_fd(fd, &info, &len) != 0) continue;
    if (info.xlated_prog_len > out->xlated_bytes) {
      out->program = bpf_program__name(prog);
      out->xlated_bytes = info.xlated_prog_len;
      out->jited_bytes = info.jited_prog_len;
    }
  }
  if (out->xlated_bytes == 0) {
    out->why =
        "the kernel accepted the object but describes no program with "
        "a translated size. A load that leaves nothing behind is not a "
        "pass.";
    bpf_object__close(obj);
    return;
  }
  out->loaded = true;
  bpf_object__close(obj);
}

}  // namespace

auto VerifyBundle(const std::string& bundle_dir,
                  const std::string& scratch_pin_root)
    -> std::expected<VerifyReport, std::string> {
  VerifyReport report;
  report.bundle_dir = bundle_dir;

  fs::path dir(bundle_dir);
  std::ifstream in(dir / "manifest.json");
  if (!in) {
    return std::unexpected(std::format(
        "{}/manifest.json: cannot be read. `fwl compile --bundle` "
        "writes one for every bundle; a directory without it was not "
        "written by the compiler.",
        bundle_dir));
  }
  std::ostringstream ss;
  ss << in.rdbuf();
  json manifest;
  try {
    manifest = json::parse(ss.str());
  } catch (const std::exception& ex) {
    return std::unexpected(
        std::format("{}/manifest.json: {}", bundle_dir, ex.what()));
  }

  std::error_code ec;
  fs::create_directories(scratch_pin_root, ec);
  if (ec) {
    return std::unexpected(std::format(
        "{}: {}. The check needs a bpffs directory of its own so it "
        "cannot disturb the pins the running policy is using.",
        scratch_pin_root, ec.message()));
  }

  auto start = std::chrono::steady_clock::now();
  bool all_ok = true;
  int examined = 0;
  for (const auto& p : manifest.value("programs", json::array())) {
    VerifiedProgram v;
    v.zone = p.value("zone", std::string{});
    if (p.value("object", json()).is_null()) {
      v.why =
          "the bundle carries no compiled object for this zone (clang "
          "was unavailable when it was compiled). It cannot be loaded.";
      all_ok = false;
      report.programs.push_back(std::move(v));
      continue;
    }
    v.object = p.value("object", std::string{});
    VerifyObject(dir / v.object, scratch_pin_root, &v);
    if (!v.loaded) all_ok = false;
    ++examined;
    report.programs.push_back(std::move(v));
  }
  report.seconds =
      std::chrono::duration<double>(std::chrono::steady_clock::now() -
                                    start)
          .count();

  // Leave nothing pinned. Anything the check created under its scratch
  // root would otherwise be adopted by the next load of a bundle with
  // maps of the same names.
  fs::remove_all(scratch_pin_root, ec);

  if (report.programs.empty()) {
    report.ok = false;
    report.summary = std::format(
        "{} names no @xdp programs. Nothing to verify, and nothing fd "
        "could attach.",
        bundle_dir);
    return report;
  }
  report.ok = all_ok;
  if (all_ok) {
    std::uint32_t total = 0;
    for (const auto& v : report.programs) total += v.xlated_bytes;
    report.summary = std::format(
        "{}: {} program(s) accepted by the kernel in {:.2f}s, {} "
        "translated bytes. Nothing was attached and `current` was not "
        "moved.",
        bundle_dir, examined, report.seconds, total);
  } else {
    report.summary = std::format(
        "{}: the kernel will not take this bundle. fd would fail to "
        "start on it.",
        bundle_dir);
  }
  return report;
}

}  // namespace f
