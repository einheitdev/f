/// @file net.cc
/// @brief IPv4 helpers for system config validation.

#include "f/sysconfig/net.h"

#include <cctype>
#include <cstdlib>
#include <format>
#include <string>
#include <vector>

namespace f::sysconfig {
namespace {

auto Split(const std::string& s, char sep)
    -> std::vector<std::string> {
  std::vector<std::string> out;
  std::string cur;
  for (char c : s) {
    if (c == sep) {
      out.push_back(cur);
      cur.clear();
    } else {
      cur.push_back(c);
    }
  }
  out.push_back(cur);
  return out;
}

/// Parse a bare unsigned decimal. Rejects empty, signs, whitespace and
/// leading zeros beyond a single "0" so "010" is never octal-adjacent.
auto ParseDecimal(const std::string& s, long max)
    -> std::optional<long> {
  if (s.empty() || s.size() > 10) return std::nullopt;
  for (char c : s) {
    if (!std::isdigit(static_cast<unsigned char>(c))) {
      return std::nullopt;
    }
  }
  if (s.size() > 1 && s[0] == '0') return std::nullopt;
  long v = std::strtol(s.c_str(), nullptr, 10);
  if (v < 0 || v > max) return std::nullopt;
  return v;
}

}  // namespace

auto Prefix4::Network() const -> std::uint32_t {
  if (bits <= 0) return 0;
  if (bits >= 32) return addr;
  return addr & (0xFFFFFFFFu << (32 - bits));
}

auto Prefix4::Broadcast() const -> std::uint32_t {
  if (bits <= 0) return 0xFFFFFFFFu;
  if (bits >= 32) return addr;
  return Network() | (0xFFFFFFFFu >> bits);
}

auto Prefix4::Netmask() const -> std::string {
  std::uint32_t m =
      bits <= 0 ? 0u
                : (bits >= 32 ? 0xFFFFFFFFu
                              : (0xFFFFFFFFu << (32 - bits)));
  return FormatIpv4(m);
}

auto Prefix4::Contains(std::uint32_t a) const -> bool {
  return a >= Network() && a <= Broadcast();
}

auto ParseIpv4(const std::string& s) -> std::optional<std::uint32_t> {
  auto parts = Split(s, '.');
  if (parts.size() != 4) return std::nullopt;
  std::uint32_t v = 0;
  for (const auto& p : parts) {
    auto octet = ParseDecimal(p, 255);
    if (!octet) return std::nullopt;
    v = (v << 8) | static_cast<std::uint32_t>(*octet);
  }
  return v;
}

auto ParseCidr4(const std::string& s) -> std::optional<Prefix4> {
  auto slash = s.find('/');
  if (slash == std::string::npos) return std::nullopt;
  auto addr = ParseIpv4(s.substr(0, slash));
  if (!addr) return std::nullopt;
  auto bits = ParseDecimal(s.substr(slash + 1), 32);
  if (!bits) return std::nullopt;
  return Prefix4{*addr, static_cast<int>(*bits)};
}

auto FormatIpv4(std::uint32_t a) -> std::string {
  return std::format("{}.{}.{}.{}", (a >> 24) & 0xFF,
                     (a >> 16) & 0xFF, (a >> 8) & 0xFF, a & 0xFF);
}

auto PrefixesOverlap(const Prefix4& a, const Prefix4& b) -> bool {
  return a.Network() <= b.Broadcast() &&
         b.Network() <= a.Broadcast();
}

auto ParseSeconds(const std::string& s)
    -> std::optional<std::uint32_t> {
  if (s.empty()) return std::nullopt;
  std::size_t i = 0;
  while (i < s.size() &&
         std::isdigit(static_cast<unsigned char>(s[i]))) {
    i++;
  }
  if (i == 0) return std::nullopt;
  auto n = ParseDecimal(s.substr(0, i), 4'000'000'000L);
  if (!n) return std::nullopt;
  auto unit = s.substr(i);
  long mult = 1;
  if (unit.empty() || unit == "s") {
    mult = 1;
  } else if (unit == "m") {
    mult = 60;
  } else if (unit == "h") {
    mult = 3600;
  } else if (unit == "d") {
    mult = 86400;
  } else {
    return std::nullopt;
  }
  long total = *n * mult;
  if (total <= 0 || total > 4'000'000'000L) return std::nullopt;
  return static_cast<std::uint32_t>(total);
}

auto IsMacAddress(const std::string& s) -> bool {
  auto parts = Split(s, ':');
  if (parts.size() != 6) return false;
  for (const auto& p : parts) {
    if (p.size() != 2) return false;
    for (char c : p) {
      if (!std::isxdigit(static_cast<unsigned char>(c))) {
        return false;
      }
    }
  }
  return true;
}

auto NormalizeMac(const std::string& s) -> std::string {
  std::string out;
  out.reserve(s.size());
  for (char c : s) {
    out.push_back(static_cast<char>(
        std::tolower(static_cast<unsigned char>(c))));
  }
  return out;
}

}  // namespace f::sysconfig
