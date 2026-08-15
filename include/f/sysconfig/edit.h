/// @file edit.h
/// @brief Targeted edits to the system configuration document.
///
/// `set address wan0 10.0.0.5/24` at a console is the same statement
/// as an `address:` line in the system configuration — so it has to
/// *be* that line, not a second file saying the same thing somewhere
/// else. Two writers for one interface's addressing is how a box ends
/// up with a policy that points at the wrong port.
///
/// Rewriting the document from the parsed model would work and would
/// also delete every comment the operator wrote, which is why these
/// functions edit the text in place: they change the one line they are
/// about and leave the rest of the file — comments, ordering,
/// formatting — exactly as it was. Every edit is verified by
/// re-parsing the result before it is handed back, so a malformed edit
/// is never returned to a caller who is about to install it.

#ifndef INCLUDE_F_SYSCONFIG_EDIT_H_
#define INCLUDE_F_SYSCONFIG_EDIT_H_

#include <expected>
#include <string>
#include <string_view>
#include <vector>

namespace f::sysconfig {

/// How to declare an interface the document does not mention yet.
struct InterfaceSeed {
  /// Hardware identity to pin the name to, e.g. the port's MAC. An
  /// interface with no identity is a name that survives nothing, so
  /// the edit refuses rather than declaring one without it.
  std::string mac;
};

/// Set (or replace) `interfaces.<name>.address`. `address` is a CIDR,
/// `dhcp`, or `none`. When the interface is not declared, it is added
/// with `seed`'s hardware identity.
/// @returns the edited document, or why the edit was refused.
auto SetInterfaceAddress(std::string_view document,
                         const std::string& iface,
                         const std::string& address,
                         const InterfaceSeed& seed = {})
    -> std::expected<std::string, std::string>;

/// Remove `interfaces.<name>.address`, leaving the interface declared
/// but unaddressed. Removing an address the interface does not have is
/// not an error.
auto ClearInterfaceAddress(std::string_view document,
                           const std::string& iface)
    -> std::expected<std::string, std::string>;

/// Declare `zone`, or change the IPv6 stance of one already declared.
///
/// A zone is a name that interfaces join and services bind to, so
/// creating one is the first statement anybody makes about a new
/// segment — before there is an interface in it and long before there
/// is a policy. It therefore has to be legal to create an empty zone;
/// what is refused is a *service* bound to a zone with nothing in it
/// (SC021), which is a different sentence.
///
/// @param document The system configuration text.
/// @param zone The zone name.
/// @param ipv6 `off`, `ra` or `full`; empty leaves an existing
///     stance alone and omits the key on a new zone, which the model
///     reads as `off`.
/// @returns the edited document, or why the edit was refused.
auto SetZone(std::string_view document, const std::string& zone,
             const std::string& ipv6 = "")
    -> std::expected<std::string, std::string>;

/// Remove `zones.<name>`.
///
/// Refused while anything still points at it — an interface in it or a
/// service bound to it. Removing the zone first would leave a document
/// that names a zone it does not declare, and the operator would find
/// that out from a validation error about the *service* rather than
/// about the deletion they just made.
auto ClearZone(std::string_view document, const std::string& zone)
    -> std::expected<std::string, std::string>;

/// Put `iface` in `zone`, declaring the interface if the document does
/// not mention it yet.
///
/// Refuses when `zone` is not declared. A zone name is not created by
/// being referenced: the whole point of the zone list is that a typo
/// fails here rather than producing a second, empty segment that
/// carries no service and no policy.
auto SetInterfaceZone(std::string_view document,
                      const std::string& iface,
                      const std::string& zone,
                      const InterfaceSeed& seed = {})
    -> std::expected<std::string, std::string>;

/// Remove `interfaces.<name>.zone`, leaving the port declared and in
/// no zone. Taking an interface out of a zone it is not in is not an
/// error; taking out an interface that is not declared is.
auto ClearInterfaceZone(std::string_view document,
                        const std::string& iface)
    -> std::expected<std::string, std::string>;

/// Declare (or re-range) the DHCP server on `zone`.
///
/// A service names a zone and nothing else that decides placement,
/// which is why there is no interface argument here and why there
/// cannot be one: the set of ports the server answers on is derived
/// from zone membership every time the config is generated.
///
/// The zone must be declared. Whether it has a statically addressed
/// interface and whether the range falls inside that subnet are
/// questions `Validate` answers (SC024, SC026) — this edit does not
/// duplicate them, so the operator gets the located diagnostic rather
/// than a second, shorter version of it.
///
/// @param zone The zone to serve.
/// @param range_start First address of the pool.
/// @param range_end Last address of the pool.
/// @param lease Lease duration as written in the document
///     (`12h`, `30m`, `600s`); empty leaves an existing one alone and
///     omits the key on a new entry.
auto SetDhcpServer(std::string_view document, const std::string& zone,
                   const std::string& range_start,
                   const std::string& range_end,
                   const std::string& lease = "")
    -> std::expected<std::string, std::string>;

/// Remove the DHCP server bound to `zone`, reservations included.
auto ClearDhcpServer(std::string_view document,
                     const std::string& zone)
    -> std::expected<std::string, std::string>;

/// Declare (or re-point) the DNS forwarder on `zone`.
/// @param upstreams Resolvers to forward to. Empty means inherit the
///     system resolver, which on a DHCP uplink is whatever the
///     upstream handed us.
auto SetDnsForwarder(std::string_view document,
                     const std::string& zone,
                     const std::vector<std::string>& upstreams)
    -> std::expected<std::string, std::string>;

/// Remove the DNS forwarder bound to `zone`.
auto ClearDnsForwarder(std::string_view document,
                       const std::string& zone)
    -> std::expected<std::string, std::string>;

/// Add or update the DHCP reservation for `mac` on the server bound to
/// `zone`.
///
/// A reservation is the operator saying "this board keeps this
/// address", so it belongs in the same document as the range it comes
/// out of — not in a dnsmasq file that the next `apply system` would
/// overwrite. An existing reservation for the same MAC is edited in
/// place so any comment beside it survives.
///
/// Refuses when the document declares no DHCP server on `zone`:
/// inventing a server (and a range for it) from a reservation command
/// would be guessing at the shape of the network.
/// @param document The system configuration text.
/// @param zone The zone whose DHCP server holds the reservation.
/// @param mac Client hardware address.
/// @param address The address to pin it to.
/// @param hostname Optional name; empty leaves it unset.
/// @returns the edited document, or why the edit was refused.
auto SetDhcpReservation(std::string_view document,
                        const std::string& zone,
                        const std::string& mac,
                        const std::string& address,
                        const std::string& hostname = "")
    -> std::expected<std::string, std::string>;

/// Remove the reservation for `mac` wherever it is declared. Removing
/// one that is not there is an error, not a no-op: an operator typing
/// a MAC by hand wants to know the deletion did not match.
auto ClearDhcpReservation(std::string_view document,
                          const std::string& mac)
    -> std::expected<std::string, std::string>;

}  // namespace f::sysconfig

#endif  // INCLUDE_F_SYSCONFIG_EDIT_H_
