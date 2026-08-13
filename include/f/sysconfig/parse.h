/// @file parse.h
/// @brief Parse the appliance system config (YAML) into the model.
///
/// Parsing is strict about unknown keys. That is not pedantry: the
/// containment argument for services rests on there being nowhere to
/// write an interface name under a service, and a parser that silently
/// ignores `interface: wan0` would let an operator believe they had
/// written something the model does not honour. An unknown key is a
/// refused config, located at the key.

#ifndef INCLUDE_F_SYSCONFIG_PARSE_H_
#define INCLUDE_F_SYSCONFIG_PARSE_H_

#include <expected>
#include <string>
#include <string_view>
#include <vector>

#include "f/sysconfig/model.h"

namespace f::sysconfig {

/// A parse that failed carries the same Diagnostic shape as a
/// validation failure, so the CLI has one rendering path.
struct ParseFailure {
  std::vector<Diagnostic> diagnostics;
};

auto ParseSystemConfigString(std::string_view yaml)
    -> std::expected<SystemConfig, ParseFailure>;

auto ParseSystemConfigFile(std::string_view path)
    -> std::expected<SystemConfig, ParseFailure>;

}  // namespace f::sysconfig

#endif  // INCLUDE_F_SYSCONFIG_PARSE_H_
