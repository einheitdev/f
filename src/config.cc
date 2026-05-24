/// @file config.cc
/// @brief fd.yaml parser implementation.

#include "f/config.h"

#include <cctype>
#include <filesystem>
#include <format>
#include <fstream>
#include <sstream>
#include <stdexcept>

#include <yaml-cpp/yaml.h>

namespace f {
namespace {

/// Parse strings like "5", "5s", "30s", "2m", "1h" into seconds.
/// Returns nullopt for unrecognized formats.
auto ParseDuration(const std::string& s)
    -> std::optional<std::chrono::seconds> {
  if (s.empty()) return std::nullopt;
  size_t i = 0;
  while (i < s.size() && std::isdigit(
             static_cast<unsigned char>(s[i]))) {
    i++;
  }
  if (i == 0) return std::nullopt;
  long n = 0;
  try {
    n = std::stol(s.substr(0, i));
  } catch (...) {
    return std::nullopt;
  }
  std::string unit = s.substr(i);
  if (unit.empty() || unit == "s") {
    return std::chrono::seconds(n);
  }
  if (unit == "m") return std::chrono::seconds(n * 60);
  if (unit == "h") return std::chrono::seconds(n * 3600);
  return std::nullopt;
}

}  // namespace

auto ParseConfigString(std::string_view yaml)
    -> std::expected<DaemonConfig, Error<ConfigError>> {
  YAML::Node doc;
  try {
    doc = YAML::Load(std::string(yaml));
  } catch (const YAML::Exception& ex) {
    return MakeError(ConfigError::kParseFailed,
                     std::format("yaml parse: {}",
                                 ex.what()));
  }

  DaemonConfig cfg;

  // Top-level scalars.
  if (auto n = doc["interfaces"]; n && n.IsSequence()) {
    for (const auto& item : n) {
      try {
        cfg.interfaces.push_back(item.as<std::string>());
      } catch (const YAML::Exception&) {
        return MakeError(
            ConfigError::kInvalidValue,
            "interfaces: items must be strings");
      }
    }
  }
  if (auto n = doc["socket"]; n) {
    cfg.socket_addr = n.as<std::string>();
  }
  if (auto n = doc["pin_path"]; n) {
    cfg.pin_path = n.as<std::string>();
  }
  if (auto n = doc["log_level"]; n) {
    cfg.log_level = n.as<std::string>();
  }

  // Watch section.
  if (auto w = doc["watch"]; w && w.IsMap()) {
    if (auto n = w["enabled"]; n) {
      cfg.watch_enabled = n.as<bool>();
    }
    if (auto n = w["interval"]; n) {
      auto raw = n.as<std::string>();
      auto d = ParseDuration(raw);
      if (!d) {
        return MakeError(
            ConfigError::kInvalidValue,
            std::format(
                "watch.interval: bad duration '{}'", raw));
      }
      cfg.watch_interval = *d;
    }
    if (auto n = w["source"]; n) {
      cfg.watch_source = n.as<std::string>();
    }
    if (auto n = w["compiled_dir"]; n) {
      cfg.watch_compiled_dir = n.as<std::string>();
    }
    if (auto n = w["fwl"]; n) {
      cfg.watch_fwl = n.as<std::string>();
    }
  }

  // Validate: if watch is enabled, source must be set.
  if (cfg.watch_enabled && cfg.watch_source.empty()) {
    return MakeError(
        ConfigError::kInvalidValue,
        "watch.enabled is true but watch.source is empty");
  }

  return cfg;
}

auto ParseConfigFile(std::string_view path)
    -> std::expected<DaemonConfig, Error<ConfigError>> {
  std::string p(path);
  if (!std::filesystem::exists(p)) {
    return MakeError(ConfigError::kFileNotFound,
                     std::format("config not found: {}", p));
  }
  std::ifstream in(p);
  if (!in) {
    return MakeError(ConfigError::kFileNotFound,
                     std::format("open {}: failed", p));
  }
  std::ostringstream ss;
  ss << in.rdbuf();
  return ParseConfigString(ss.str());
}

}  // namespace f
