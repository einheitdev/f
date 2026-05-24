/// @file config.h
/// @brief fd.yaml configuration parser.

#ifndef INCLUDE_F_CONFIG_H_
#define INCLUDE_F_CONFIG_H_

#include <chrono>
#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <vector>

#include "f/error.h"

namespace f {

enum class ConfigError : uint8_t {
  kFileNotFound,
  kParseFailed,
  kInvalidValue,
};

/// Parsed fd.yaml — populated from disk by ParseConfigFile.
/// Each field has a sensible default; missing keys leave them.
struct DaemonConfig {
  // ---- Engine settings ----
  std::vector<std::string> interfaces;
  std::string socket_addr = "ipc:///tmp/fd-control.sock";
  std::string pin_path = "/sys/fs/bpf/f";
  std::string log_level = "info";

  // ---- Watcher settings ----
  bool watch_enabled = false;
  std::chrono::seconds watch_interval{5};
  std::string watch_source;
  std::string watch_compiled_dir = "/usr/share/f/compiled";
  std::string watch_fwl = "fwl";
};

/// Parse a YAML config file. Missing optional keys leave the
/// corresponding DaemonConfig field at its default.
auto ParseConfigFile(std::string_view path)
    -> std::expected<DaemonConfig, Error<ConfigError>>;

/// Parse a YAML config from an in-memory string. Public for
/// testability — ParseConfigFile is a thin wrapper over this.
auto ParseConfigString(std::string_view yaml)
    -> std::expected<DaemonConfig, Error<ConfigError>>;

}  // namespace f

#endif  // INCLUDE_F_CONFIG_H_
