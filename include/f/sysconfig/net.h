/// @file net.h
/// @brief Small IPv4 helpers used by system config validation.
///
/// Deliberately narrow: parsing an address, parsing a CIDR, and asking
/// whether two prefixes overlap. Nothing here knows about zones.

#ifndef INCLUDE_F_SYSCONFIG_NET_H_
#define INCLUDE_F_SYSCONFIG_NET_H_

#include <cstdint>
#include <optional>
#include <string>

namespace f::sysconfig {

/// An IPv4 prefix in host byte order.
struct Prefix4 {
  std::uint32_t addr = 0;
  /// Prefix length, 0..32.
  int bits = 0;

  /// The network address (host bits cleared).
  auto Network() const -> std::uint32_t;
  /// The broadcast address (host bits set).
  auto Broadcast() const -> std::uint32_t;
  /// Dotted-quad netmask, e.g. "255.255.255.0".
  auto Netmask() const -> std::string;
  /// True when `a` falls inside this prefix.
  auto Contains(std::uint32_t a) const -> bool;
};

/// Parse a dotted-quad IPv4 address. Rejects anything that is not
/// exactly four decimal octets — `inet_aton`'s octal and short forms
/// are a config-file footgun, not a feature.
auto ParseIpv4(const std::string& s) -> std::optional<std::uint32_t>;

/// Parse "a.b.c.d/len".
auto ParseCidr4(const std::string& s) -> std::optional<Prefix4>;

/// Render an address as dotted quad.
auto FormatIpv4(std::uint32_t a) -> std::string;

/// True when the two prefixes share any address.
auto PrefixesOverlap(const Prefix4& a, const Prefix4& b) -> bool;

/// Parse a duration like "12h", "30m", "600s", "600" into seconds.
auto ParseSeconds(const std::string& s) -> std::optional<std::uint32_t>;

/// True when `s` looks like a MAC address (six colon-separated hex
/// octets). Case-insensitive.
auto IsMacAddress(const std::string& s) -> bool;

/// Lowercase a MAC address so two spellings of the same hardware
/// identity compare equal.
auto NormalizeMac(const std::string& s) -> std::string;

}  // namespace f::sysconfig

#endif  // INCLUDE_F_SYSCONFIG_NET_H_
