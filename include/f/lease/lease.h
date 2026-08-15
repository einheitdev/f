/// @file lease.h
/// @brief The DHCP lease database, read as evidence.
///
/// dnsmasq owns the leases; we only read the file it writes. That makes
/// the read the weakest link in the whole visibility story, so the
/// failures are named rather than collapsed into an empty list:
///
///   - the file is absent because nothing serves DHCP,
///   - the file is absent because dnsmasq has not written one yet,
///   - the file is there and unreadable,
///   - the file is there and one line inside it makes no sense.
///
/// Only the last of those is survivable by ignoring it, and even then
/// the bad line is carried out to the caller instead of dropped: a
/// lease view that quietly hides a client is worse than one that says
/// it could not read a line.
///
/// The path is a constant here and the dnsmasq artifact generator uses
/// the same constant, so the writer and the reader cannot disagree
/// about where the file is.

#ifndef INCLUDE_F_LEASE_LEASE_H_
#define INCLUDE_F_LEASE_LEASE_H_

#include <cstddef>
#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <vector>

#include "f/error.h"

namespace f::lease {

/// Where dnsmasq is told to keep its lease database. Referenced by the
/// dnsmasq config generator, so there is one spelling of this path.
inline constexpr const char* kLeaseFilePath =
    "/var/lib/f/dnsmasq.leases";

/// One IPv4 lease, as dnsmasq wrote it.
struct Lease {
  /// Unix seconds at which the lease expires. dnsmasq writes 0 for an
  /// infinite lease.
  std::int64_t expiry = 0;
  /// Client hardware address, lowercased.
  std::string mac;
  std::string address;
  /// Empty when the client sent no hostname (dnsmasq writes "*").
  std::string hostname;
  /// Empty when the client sent no identifier.
  std::string client_id;
};

/// Why a lease-file read produced nothing at all.
enum class LeaseError {
  /// No file at the path.
  kAbsent,
  /// The file is there and could not be opened or read.
  kUnreadable,
};

/// The outcome of parsing a lease file, including what did not parse.
struct LeaseFileRead {
  std::vector<Lease> leases;
  /// Lines the parser could not make sense of, verbatim, so the
  /// operator can look at the actual text rather than a count.
  std::vector<std::string> unparsable;
  /// DHCPv6 leases, which this appliance does not hand out. Counted so
  /// that a file full of them does not read as an empty file.
  std::size_t ipv6_skipped = 0;
};

/// Parse the contents of a dnsmasq lease file.
///
/// Format, one lease per line:
///     <expiry-epoch> <mac> <ipv4> <hostname|*> <client-id|*>
/// A leading `duid <hex>` line is dnsmasq's DHCPv6 server identifier
/// and is not a lease.
/// @param text Whole file contents.
auto ParseLeases(std::string_view text) -> LeaseFileRead;

/// Read and parse the lease file at `path`.
/// @param path Lease-file path.
/// @returns the parse, or why the file could not be read at all.
auto ReadLeases(const std::string& path)
    -> std::expected<LeaseFileRead, Error<LeaseError>>;

}  // namespace f::lease

#endif  // INCLUDE_F_LEASE_LEASE_H_
