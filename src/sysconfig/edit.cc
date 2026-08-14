/// @file edit.cc
/// @brief Targeted, comment-preserving edits to the system config.

#include "f/sysconfig/edit.h"

#include <algorithm>
#include <cstddef>
#include <format>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
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

/// Where a YAML sequence item begins and ends, half-open.
struct ItemRange {
  std::size_t begin = 0;
  std::size_t end = 0;
  /// Column of the `-`.
  std::size_t dash_indent = 0;
};

/// The sequence items nested in [from, to). An item starts at a line
/// whose first non-space character is `-` and runs to the next such
/// line at the same indent.
auto SequenceItems(const Lines& lines, std::size_t from,
                   std::size_t to) -> std::vector<ItemRange> {
  std::vector<ItemRange> items;
  std::size_t dash_indent = std::string::npos;
  for (std::size_t i = from; i < to; ++i) {
    if (IsBlankOrComment(lines[i])) continue;
    auto n = Indent(lines[i]);
    if (n >= lines[i].size() || lines[i][n] != '-') continue;
    if (dash_indent == std::string::npos) dash_indent = n;
    if (n != dash_indent) continue;
    if (!items.empty()) items.back().end = i;
    items.push_back({i, to, n});
  }
  if (!items.empty()) items.back().end = to;
  return items;
}

/// The value of `key` inside a sequence item, or nullopt.
///
/// The first key of an item shares the `- ` line, so the item's key
/// indent is the dash column plus two — not the indent of the first
/// line, which would be the dash itself.
auto ItemKeyLine(const Lines& lines, const ItemRange& item,
                 const std::string& key) -> std::size_t {
  const auto key_indent = item.dash_indent + 2;
  for (std::size_t i = item.begin; i < item.end; ++i) {
    if (IsBlankOrComment(lines[i])) continue;
    std::string body = lines[i];
    std::size_t start = Indent(body);
    if (i == item.begin) {
      // "  - zone: lan" -> the key starts after the dash and a space.
      if (start < body.size() && body[start] == '-') {
        start = start + 1;
        while (start < body.size() && body[start] == ' ') ++start;
      }
    } else if (start != key_indent) {
      continue;
    }
    auto colon = body.find(':', start);
    if (colon == std::string::npos) continue;
    if (body.substr(start, colon - start) == key) return i;
  }
  return std::string::npos;
}

auto ValueAfterColon(const std::string& line) -> std::string {
  auto colon = line.find(':');
  if (colon == std::string::npos) return "";
  auto v = line.substr(colon + 1);
  auto b = v.find_first_not_of(" \t");
  if (b == std::string::npos) return "";
  auto e = v.find_last_not_of(" \t\r");
  auto out = v.substr(b, e - b + 1);
  if (out.size() >= 2 && (out.front() == '"' || out.front() == '\'') &&
      out.back() == out.front()) {
    out = out.substr(1, out.size() - 2);
  }
  return out;
}

/// The line range of the block nested under a key line inside an item.
/// `base` is the key's own column, passed in rather than measured: a
/// key that shares the `- ` line is indented to the dash, and measuring
/// would swallow every sibling key of the item.
auto KeyBlockRange(const Lines& lines, std::size_t key_line,
                   std::size_t base, std::size_t limit)
    -> std::pair<std::size_t, std::size_t> {
  std::size_t end = key_line + 1;
  for (std::size_t i = key_line + 1; i < limit; ++i) {
    if (IsBlankOrComment(lines[i])) continue;
    if (Indent(lines[i]) <= base) break;
    end = i + 1;
  }
  return {key_line + 1, end};
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

namespace {

/// Re-parse, and hand back the model's view of the reservation for
/// `mac`. Same rule as the interface edits: nothing goes back to a
/// caller who is about to install it until it has been read again.
auto ReparseReservation(const std::string& text,
                        const std::string& mac,
                        std::optional<std::string>* found)
    -> std::expected<void, std::string> {
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
  for (const auto& d : parsed->dhcp) {
    for (const auto& r : d.reservations) {
      if (r.mac == mac) {
        *found = r.address;
        return {};
      }
    }
  }
  *found = std::nullopt;
  return {};
}

/// The reservation must exist, at exactly this address.
auto VerifyReservationPresent(const std::string& text,
                              const std::string& mac,
                              const std::string& address)
    -> std::expected<std::string, std::string> {
  std::optional<std::string> found;
  if (auto r = ReparseReservation(text, mac, &found); !r) {
    return std::unexpected(r.error());
  }
  if (!found || *found != address) {
    return std::unexpected(
        "the edit did not take — nothing was changed");
  }
  return text;
}

/// The reservation must be gone.
auto VerifyReservationAbsent(const std::string& text,
                             const std::string& mac)
    -> std::expected<std::string, std::string> {
  std::optional<std::string> found;
  if (auto r = ReparseReservation(text, mac, &found); !r) {
    return std::unexpected(r.error());
  }
  if (found) {
    return std::unexpected(
        "the reservation is still there — nothing was changed");
  }
  return text;
}

/// Locate the `services: dhcp:` sequence, or say why it is not there.
struct DhcpSequence {
  std::size_t begin = 0;
  std::size_t end = 0;
};

auto FindDhcpSequence(const Lines& lines)
    -> std::expected<DhcpSequence, std::string> {
  auto services = FindTopLevelKey(lines, "services");
  if (services == std::string::npos) {
    return std::unexpected(
        "the system configuration declares no services");
  }
  auto [sbegin, send] = BlockRange(lines, services);
  auto dhcp = FindChildKey(lines, sbegin, send, "dhcp");
  if (dhcp == std::string::npos) {
    return std::unexpected(
        "no DHCP server is declared in the system configuration");
  }
  auto [dbegin, dend] = KeyBlockRange(lines, dhcp, Indent(lines[dhcp]),
                                      send);
  return DhcpSequence{dbegin, dend};
}

}  // namespace

auto SetDhcpReservation(std::string_view document,
                        const std::string& zone,
                        const std::string& mac,
                        const std::string& address,
                        const std::string& hostname)
    -> std::expected<std::string, std::string> {
  if (!IsMacAddress(mac)) {
    return std::unexpected(std::format(
        "'{}' is not a MAC address — a reservation is keyed by the "
        "client's hardware address",
        mac));
  }
  const auto norm = NormalizeMac(mac);
  if (!ParseIpv4(address)) {
    return std::unexpected(std::format(
        "'{}' is not an IPv4 address", address));
  }

  auto lines = SplitLines(document);
  auto seq = FindDhcpSequence(lines);
  if (!seq) return std::unexpected(seq.error());

  auto items = SequenceItems(lines, seq->begin, seq->end);
  const ItemRange* target = nullptr;
  std::vector<std::string> zones_seen;
  for (const auto& it : items) {
    auto zl = ItemKeyLine(lines, it, "zone");
    if (zl == std::string::npos) continue;
    auto name = ValueAfterColon(lines[zl]);
    zones_seen.push_back(name);
    if (name == zone) target = &it;
  }
  if (target == nullptr) {
    std::string list;
    for (const auto& z : zones_seen) {
      if (!list.empty()) list += ", ";
      list += z;
    }
    return std::unexpected(std::format(
        "no DHCP server is bound to zone '{}'{}", zone,
        list.empty() ? "" : std::format(" (declared: {})", list)));
  }

  const auto key_indent = target->dash_indent + 2;
  const std::string key_pad(key_indent, ' ');
  auto res_line = ItemKeyLine(lines, *target, "reservations");

  if (res_line == std::string::npos) {
    // No reservations block yet: open one at the end of this server's
    // body, leaving every other key where it was.
    Lines block = {
        std::format("{}reservations:", key_pad),
        std::format("{}  - mac: \"{}\"", key_pad, norm),
        std::format("{}    address: {}", key_pad, address),
    };
    if (!hostname.empty()) {
      block.push_back(
          std::format("{}    hostname: {}", key_pad, hostname));
    }
    // Skip trailing blank lines so the block lands inside the item and
    // not after the blank line that separates it from the next.
    auto at = target->end;
    while (at > target->begin && IsBlankOrComment(lines[at - 1]) &&
           Indent(lines[at - 1]) >= lines[at - 1].size()) {
      --at;
    }
    lines.insert(lines.begin() + static_cast<long>(at), block.begin(),
                 block.end());
    return VerifyReservationPresent(Join(lines), norm, address);
  }

  auto [rbegin, rend] =
      KeyBlockRange(lines, res_line, key_indent, target->end);
  auto entries = SequenceItems(lines, rbegin, rend);
  for (const auto& e : entries) {
    auto ml = ItemKeyLine(lines, e, "mac");
    if (ml == std::string::npos) continue;
    if (NormalizeMac(ValueAfterColon(lines[ml])) != norm) continue;
    // Editing in place keeps whatever the operator wrote beside it.
    // Every line index is resolved before anything moves, and the
    // edits are then applied from the bottom up so the earlier indices
    // stay valid.
    const std::string epad(e.dash_indent + 2, ' ');
    auto al = ItemKeyLine(lines, e, "address");
    auto hl = hostname.empty() ? std::string::npos
                               : ItemKeyLine(lines, e, "hostname");
    struct Insert {
      std::size_t at;
      std::string text;
    };
    std::vector<Insert> inserts;
    if (al != std::string::npos) {
      lines[al] = std::format("{}address: {}", epad, address);
    } else {
      inserts.push_back({e.end, std::format("{}address: {}", epad,
                                            address)});
    }
    if (!hostname.empty()) {
      if (hl != std::string::npos) {
        lines[hl] = std::format("{}hostname: {}", epad, hostname);
      } else {
        inserts.push_back({e.end, std::format("{}hostname: {}", epad,
                                              hostname)});
      }
    }
    for (auto it = inserts.rbegin(); it != inserts.rend(); ++it) {
      lines.insert(lines.begin() + static_cast<long>(it->at),
                   it->text);
    }
    return VerifyReservationPresent(Join(lines), norm, address);
  }

  // A reservations block that does not mention this MAC: append.
  std::size_t entry_indent = key_indent + 2;
  if (!entries.empty()) entry_indent = entries.front().dash_indent;
  const std::string epad(entry_indent, ' ');
  Lines block = {
      std::format("{}- mac: \"{}\"", epad, norm),
      std::format("{}  address: {}", epad, address),
  };
  if (!hostname.empty()) {
    block.push_back(std::format("{}  hostname: {}", epad, hostname));
  }
  lines.insert(lines.begin() + static_cast<long>(rend), block.begin(),
               block.end());
  return VerifyReservationPresent(Join(lines), norm, address);
}

auto ClearDhcpReservation(std::string_view document,
                          const std::string& mac)
    -> std::expected<std::string, std::string> {
  if (!IsMacAddress(mac)) {
    return std::unexpected(
        std::format("'{}' is not a MAC address", mac));
  }
  const auto norm = NormalizeMac(mac);
  auto lines = SplitLines(document);
  auto seq = FindDhcpSequence(lines);
  if (!seq) return std::unexpected(seq.error());

  for (const auto& item : SequenceItems(lines, seq->begin, seq->end)) {
    auto res_line = ItemKeyLine(lines, item, "reservations");
    if (res_line == std::string::npos) continue;
    auto [rbegin, rend] = KeyBlockRange(
        lines, res_line, item.dash_indent + 2, item.end);
    auto entries = SequenceItems(lines, rbegin, rend);
    for (const auto& e : entries) {
      auto ml = ItemKeyLine(lines, e, "mac");
      if (ml == std::string::npos) continue;
      if (NormalizeMac(ValueAfterColon(lines[ml])) != norm) continue;
      lines.erase(lines.begin() + static_cast<long>(e.begin),
                  lines.begin() + static_cast<long>(e.end));
      // An empty `reservations:` key parses as null, which the model
      // reads as no reservations — but it reads as an unfinished edit
      // to a human, so take the key with the last entry.
      if (entries.size() == 1) {
        lines.erase(lines.begin() + static_cast<long>(res_line));
      }
      return VerifyReservationAbsent(Join(lines), norm);
    }
  }
  return std::unexpected(std::format(
      "no reservation for {} in the system configuration", norm));
}

}  // namespace f::sysconfig
