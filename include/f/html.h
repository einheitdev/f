/// @file html.h
/// @brief Lightweight HTML fragment builder and render functions.

#ifndef INCLUDE_F_HTML_H_
#define INCLUDE_F_HTML_H_

#include <format>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "f/log_sink.h"
#include "f/protocol.h"
#include "f/types.h"

namespace f {

// Forward declared — defined in engine.h.
// For html.h we only need the layout for rendering.
struct IfAttach;

/// Inline HTML builder — appends to an internal buffer.
struct Html {
  std::string buf;

  /// Append an element: <tag attrs>body</tag>.
  auto Tag(std::string_view tag, std::string_view attrs,
           std::string_view body) -> Html&;

  /// Append raw HTML.
  auto Raw(std::string_view s) -> Html&;

  /// Move the buffer out.
  auto Build() -> std::string;
};

/// Render the rules table as an HTML fragment.
auto RenderRulesTable(
    std::span<const std::pair<RuleKey, RuleValue>> rules)
    -> std::string;

/// Render per-rule counters as an HTML fragment.
auto RenderCountersTable(
    std::span<const RuleCounter> counters)
    -> std::string;

/// Render daemon status as an HTML card.
auto RenderStatusCard(const StatusResponse& status)
    -> std::string;

/// Render the connection tracking table.
auto RenderConntrackTable(
    std::span<const std::pair<ConnKey, ConnValue>> conns)
    -> std::string;

/// Render the interface list.
auto RenderInterfaceList(
    std::span<const IfAttach> ifaces)
    -> std::string;

/// Render recent log entries.
auto RenderLogEntries(
    std::span<const LogEntry> entries)
    -> std::string;

}  // namespace f

#endif  // INCLUDE_F_HTML_H_
