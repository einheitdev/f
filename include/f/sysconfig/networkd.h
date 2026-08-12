/// @file networkd.h
/// @brief systemd-networkd backend: durable names and addressing.
///
/// Two derived artifacts per interface:
///
///  - a `.link` unit that pins the durable name to a hardware
///    identity, so the name survives a reboot, a driver change and a
///    port being added. Probe order never gets a vote.
///  - a `.network` unit carrying the address mode.
///
/// The `.link` file is the one that matters most. A firewall whose
/// policy names `wan0` while udev has moved `wan0` to a different
/// socket is not a broken firewall, it is an open one.

#ifndef INCLUDE_F_SYSCONFIG_NETWORKD_H_
#define INCLUDE_F_SYSCONFIG_NETWORKD_H_

#include <expected>
#include <string>
#include <vector>

#include "f/sysconfig/artifact.h"
#include "f/sysconfig/model.h"

namespace f::sysconfig {

/// One generated unit file.
struct NetworkdUnit {
  std::string path;
  std::string content;
  /// The interface it belongs to, for reporting.
  std::string interface;
};

/// Where the units go.
struct NetworkdOptions {
  std::string dir = "/etc/systemd/network";
  bool refuse_on_drift = true;
};

/// Render every unit the model implies. Pure: no I/O.
auto PlanNetworkd(const SystemConfig& cfg,
                  const NetworkdOptions& opts)
    -> std::vector<NetworkdUnit>;

/// Per-unit drift, in the same order as PlanNetworkd.
auto CheckNetworkdDrift(const std::vector<NetworkdUnit>& units)
    -> std::vector<DriftKind>;

struct NetworkdReport {
  std::vector<NetworkdUnit> units;
  std::vector<std::string> changed;
};

/// Install every unit atomically. Refuses the whole apply if any unit
/// was hand-edited, so a partial write cannot leave half the ports
/// pinned to the new model and half to the old one.
auto ApplyNetworkd(const SystemConfig& cfg,
                   const NetworkdOptions& opts)
    -> std::expected<NetworkdReport, std::string>;

}  // namespace f::sysconfig

#endif  // INCLUDE_F_SYSCONFIG_NETWORKD_H_
