/// @file lease.cc
/// @brief Parse the dnsmasq lease file.

#include "f/lease/lease.h"

#include <cctype>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <format>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "f/sysconfig/net.h"

namespace f::lease {
namespace {

auto SplitFields(const std::string& line)
    -> std::vector<std::string> {
  std::vector<std::string> out;
  std::istringstream ss(line);
  std::string tok;
  while (ss >> tok) out.push_back(tok);
  return out;
}

auto AllDigits(const std::string& s) -> bool {
  if (s.empty()) return false;
  for (char c : s) {
    if (std::isdigit(static_cast<unsigned char>(c)) == 0) {
      return false;
    }
  }
  return true;
}

/// dnsmasq writes a bare `*` where the client supplied nothing.
auto Optional(const std::string& s) -> std::string {
  return s == "*" ? std::string() : s;
}

}  // namespace

auto ParseLeases(std::string_view text) -> LeaseFileRead {
  LeaseFileRead out;
  std::istringstream ss{std::string(text)};
  std::string line;
  while (std::getline(ss, line)) {
    // Tolerate CRLF; a lease file copied off a box through Windows is
    // still a lease file.
    if (!line.empty() && line.back() == '\r') line.pop_back();
    auto f = SplitFields(line);
    if (f.empty()) continue;
    // The DHCPv6 server identifier, not a lease.
    if (f[0] == "duid") continue;
    if (f.size() < 3 || !AllDigits(f[0])) {
      out.unparsable.push_back(line);
      continue;
    }
    // A DHCPv6 lease: the second field is an IAID, not a MAC, and the
    // third is a v6 address. We do not serve DHCPv6, so this is not
    // corruption — but it is also not something to render as a device.
    if (f[2].find(':') != std::string::npos) {
      ++out.ipv6_skipped;
      continue;
    }
    if (!sysconfig::IsMacAddress(f[1]) ||
        !sysconfig::ParseIpv4(f[2]).has_value()) {
      out.unparsable.push_back(line);
      continue;
    }
    Lease l;
    l.expiry = std::stoll(f[0]);
    l.mac = sysconfig::NormalizeMac(f[1]);
    l.address = f[2];
    if (f.size() > 3) l.hostname = Optional(f[3]);
    if (f.size() > 4) l.client_id = Optional(f[4]);
    out.leases.push_back(std::move(l));
  }
  return out;
}

auto ReadLeases(const std::string& path)
    -> std::expected<LeaseFileRead, Error<LeaseError>> {
  std::error_code ec;
  auto st = std::filesystem::status(path, ec);
  if (ec || st.type() == std::filesystem::file_type::not_found) {
    return MakeError(LeaseError::kAbsent,
                     std::format("no lease file at {}", path));
  }
  // A directory (or a device, or a socket) opens without complaint and
  // then reads as nothing, which would render as "no client holds a
  // lease" — the exact confusion this whole type exists to prevent.
  if (!std::filesystem::is_regular_file(st)) {
    return MakeError(
        LeaseError::kUnreadable,
        std::format("{} is not a regular file", path));
  }
  std::ifstream in(path);
  if (!in) {
    return MakeError(
        LeaseError::kUnreadable,
        std::format("cannot read {}: {}", path,
                    std::strerror(errno)));
  }
  std::ostringstream body;
  body << in.rdbuf();
  if (in.bad()) {
    return MakeError(
        LeaseError::kUnreadable,
        std::format("error reading {}: {}", path,
                    std::strerror(errno)));
  }
  return ParseLeases(body.str());
}

}  // namespace f::lease
