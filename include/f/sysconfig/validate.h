/// @file validate.h
/// @brief Structural validation of the system config model.
///
/// The rules here are the compile-time-shaped errors from the design:
/// a DHCP server on an interface that is also a DHCP client,
/// overlapping subnets across zones, a service bound to a nonexistent
/// zone, a zone with services but no interfaces. Each one is named,
/// located and refused.
///
/// Diagnostic codes are stable — they are what an operator greps for
/// and what tests assert on.
///
/// | code  | meaning                                              |
/// |-------|------------------------------------------------------|
/// | SC001 | duplicate zone name                                  |
/// | SC002 | duplicate interface name                             |
/// | SC003 | two interfaces claim the same hardware identity       |
/// | SC004 | interface has no hardware identity to pin its name to |
/// | SC005 | interface references an undeclared zone               |
/// | SC010 | malformed static address                             |
/// | SC011 | gateway outside the interface's own subnet            |
/// | SC012 | overlapping subnets across zones                      |
/// | SC020 | service bound to a zone that does not exist           |
/// | SC021 | zone has services bound but no interfaces             |
/// | SC022 | DHCP server in a zone that also holds a DHCP client   |
/// | SC023 | more than one DHCP server bound to one zone           |
/// | SC024 | DHCP zone has no statically addressed interface       |
/// | SC025 | malformed DHCP range                                  |
/// | SC026 | DHCP range outside the zone's subnet                  |
/// | SC027 | bad or out-of-subnet reservation                      |
/// | SC028 | more than one DNS forwarder bound to one zone         |
/// | SC029 | zone asks for IPv6 RAs but nothing can send them      |
/// | SC030 | zone asks for full IPv6, which this build refuses     |
/// | SC031 | zone asks for IPv6 RAs but has no prefix to advertise |
/// | SC032 | IPv6 address on a port whose zone says v6 is off      |
/// | SC040 | malformed NTP upstream                                |
/// | SC041 | more than one NTP server bound to one zone            |
/// | SC042 | NTP server in a zone that also holds a DHCP client    |
/// | SC043 | NTP zone has no statically addressed interface        |
/// | SC044 | (warning) nothing is configured to set the clock      |
/// | SC045 | (warning) DNS rebind protection exempts no domain     |
/// | SC046 | (warning) `rebind_ok` listed while protection is off  |

#ifndef INCLUDE_F_SYSCONFIG_VALIDATE_H_
#define INCLUDE_F_SYSCONFIG_VALIDATE_H_

#include "f/sysconfig/model.h"

namespace f::sysconfig {

/// Validate a parsed config. Never throws; collects every finding so
/// the operator fixes them in one pass.
auto Validate(const SystemConfig& cfg) -> ValidationResult;

}  // namespace f::sysconfig

#endif  // INCLUDE_F_SYSCONFIG_VALIDATE_H_
