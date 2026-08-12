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

}  // namespace f::sysconfig

#endif  // INCLUDE_F_SYSCONFIG_EDIT_H_
