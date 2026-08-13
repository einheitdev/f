/// @file edit.cc
/// @brief Targeted, comment-preserving edits to the system config.

#include "f/sysconfig/edit.h"

#include <algorithm>
#include <format>
#include <sstream>
#include <string>
#include <vector>

#include "f/sysconfig/net.h"
#include "f/sysconfig/parse.h"

namespace f::sysconfig {
namespace {

using Lines = std::vector<std::string>;

auto SplitLines(std::string_view text) -> Lines {
  Lines out;
  std::string cur;
  for (char c : text) {
    if (c == '\n') {
      out.push_back(cur);
      cur.clear();
    } else {
      cur.push_back(c);
    }
  }
  // A trailing newline means the last line is empty; keep the
  // distinction so the rebuilt document ends the same way.
  out.push_back(cur);
  return out;
}

auto Join(const Lines& lines) -> std::string {
  std::string out;
  for (std::size_t i = 0; i < lines.size(); ++i) {
    out += lines[i];
    if (i + 1 < lines.size()) out += '\n';
  }
  return out;
}

auto Indent(const std::string& line) -> std::size_t {
  std::size_t n = 0;
  while (n < line.size() && line[n] == ' ') ++n;
  return n;
}

auto IsBlankOrComment(const std::string& line) -> bool {
  auto n = Indent(line);
  return n >= line.size() || line[n] == '#';
}

/// Index of the line declaring top-level key `key`, or npos.
auto FindTopLevelKey(const Lines& lines, const std::string& key)
    -> std::size_t {
  for (std::size_t i = 0; i < lines.size(); ++i) {
    if (IsBlankOrComment(lines[i])) continue;
    if (Indent(lines[i]) != 0) continue;
    auto colon = lines[i].find(':');
    if (colon == std::string::npos) continue;
    if (lines[i].substr(0, colon) == key) return i;
  }
  return std::string::npos;
}

/// The half-open line range of the block nested under `header`.
auto BlockRange(const Lines& lines, std::size_t header)
    -> std::pair<std::size_t, std::size_t> {
  const auto base = Indent(lines[header]);
  std::size_t end = header + 1;
  for (std::size_t i = header + 1; i < lines.size(); ++i) {
    if (IsBlankOrComment(lines[i])) continue;
    if (Indent(lines[i]) <= base) break;
    end = i + 1;
  }
  return {header + 1, end};
}

/// Index of the line declaring `name` inside [from, to), or npos.
auto FindChildKey(const Lines& lines, std::size_t from,
                  std::size_t to, const std::string& name)
    -> std::size_t {
  std::size_t child_indent = 0;
  for (std::size_t i = from; i < to; ++i) {
    if (IsBlankOrComment(lines[i])) continue;
    if (child_indent == 0) child_indent = Indent(lines[i]);
    if (Indent(lines[i]) != child_indent) continue;
    auto colon = lines[i].find(':');
    if (colon == std::string::npos) continue;
    auto key = lines[i].substr(child_indent,
                               colon - child_indent);
    if (key == name) return i;
  }
  return std::string::npos;
}

/// Re-parse the edited document. An edit that does not parse, or that
/// did not take, is refused rather than returned.
auto Verify(const std::string& text, const std::string& iface,
            const std::string& address)
    -> std::expected<std::string, std::string> {
  auto parsed = ParseSystemConfigString(text);
  if (!parsed) {
    std::string why;
    for (const auto& d : parsed.error().diagnostics) {
      if (!why.empty()) why += "; ";
      why += d.Format();
    }
    return std::unexpected(std::format(
        "the edit would not parse ({}) — nothing was changed", why));
  }
  for (const auto& i : parsed->interfaces) {
    if (i.name != iface) continue;
    const bool ok =
        address == "dhcp"
            ? i.mode == AddressMode::kDhcpClient
        : address.empty() || address == "none"
            ? i.mode == AddressMode::kUnconfigured
            : i.address == address;
    if (!ok) {
      return std::unexpected(
          "the edit did not take — nothing was changed");
    }
    return text;
  }
  return std::unexpected(std::format(
      "interface '{}' is not in the edited document", iface));
}

}  // namespace

auto SetInterfaceAddress(std::string_view document,
                         const std::string& iface,
                         const std::string& address,
                         const InterfaceSeed& seed)
    -> std::expected<std::string, std::string> {
  if (iface.empty()) {
    return std::unexpected("no interface named");
  }
  auto lines = SplitLines(document);

  auto ifaces = FindTopLevelKey(lines, "interfaces");
  if (ifaces == std::string::npos) {
    if (seed.mac.empty()) {
      return std::unexpected(std::format(
          "the system configuration declares no interfaces and "
          "'{}' has no hardware address to pin a name to",
          iface));
    }
    // Append the section; a name with no hardware identity behind it
    // is exactly what the model refuses, so it is seeded with one.
    if (!lines.empty() && !lines.back().empty()) lines.push_back("");
    lines.push_back("interfaces:");
    lines.push_back(std::format("  {}:", iface));
    lines.push_back(std::format("    mac: \"{}\"", seed.mac));
    lines.push_back(std::format("    address: {}", address));
    lines.push_back("");
    return Verify(Join(lines), iface, address);
  }

  auto [begin, end] = BlockRange(lines, ifaces);
  auto entry = FindChildKey(lines, begin, end, iface);
  if (entry == std::string::npos) {
    if (seed.mac.empty()) {
      return std::unexpected(std::format(
          "interface '{}' is not declared and has no hardware "
          "address to pin a name to — declare it in the system "
          "configuration first",
          iface));
    }
    std::size_t child_indent = 2;
    for (std::size_t i = begin; i < end; ++i) {
      if (IsBlankOrComment(lines[i])) continue;
      child_indent = Indent(lines[i]);
      break;
    }
    const std::string pad(child_indent, ' ');
    const std::string pad2(child_indent * 2, ' ');
    Lines block = {
        std::format("{}{}:", pad, iface),
        std::format("{}mac: \"{}\"", pad2, seed.mac),
        std::format("{}address: {}", pad2, address),
    };
    lines.insert(lines.begin() + static_cast<long>(end),
                 block.begin(), block.end());
    return Verify(Join(lines), iface, address);
  }

  auto [body_begin, body_end] = BlockRange(lines, entry);
  auto addr_line =
      FindChildKey(lines, body_begin, body_end, "address");
  if (addr_line != std::string::npos) {
    const std::string pad(Indent(lines[addr_line]), ' ');
    lines[addr_line] = std::format("{}address: {}", pad, address);
  } else {
    std::size_t pad_n = Indent(lines[entry]) + 2;
    for (std::size_t i = body_begin; i < body_end; ++i) {
      if (IsBlankOrComment(lines[i])) continue;
      pad_n = Indent(lines[i]);
      break;
    }
    const std::string pad(pad_n, ' ');
    lines.insert(lines.begin() + static_cast<long>(body_end),
                 std::format("{}address: {}", pad, address));
  }
  return Verify(Join(lines), iface, address);
}

auto ClearInterfaceAddress(std::string_view document,
                           const std::string& iface)
    -> std::expected<std::string, std::string> {
  auto lines = SplitLines(document);
  auto ifaces = FindTopLevelKey(lines, "interfaces");
  if (ifaces == std::string::npos) {
    return std::unexpected(
        "the system configuration declares no interfaces");
  }
  auto [begin, end] = BlockRange(lines, ifaces);
  auto entry = FindChildKey(lines, begin, end, iface);
  if (entry == std::string::npos) {
    return std::unexpected(std::format(
        "interface '{}' is not declared in the system "
        "configuration",
        iface));
  }
  auto [body_begin, body_end] = BlockRange(lines, entry);
  auto addr_line =
      FindChildKey(lines, body_begin, body_end, "address");
  if (addr_line != std::string::npos) {
    lines.erase(lines.begin() + static_cast<long>(addr_line));
  }
  return Verify(Join(lines), iface, "none");
}

}  // namespace f::sysconfig
