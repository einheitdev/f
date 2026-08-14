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

/// What one `.link` file on disk claims, whoever wrote it.
struct LinkClaim {
  std::string path;
  /// Lowercase MAC from `[Match] MACAddress=`, empty when it matches on
  /// something else.
  std::string mac;
  /// The name from `[Link] Name=`.
  std::string name;
  /// True when the file carries our digest header — i.e. we wrote it.
  bool generated = false;
};

/// Every `.link` unit in `dir`, parsed for the claim it makes. Reading
/// other people's units is deliberate: the question "does anything else
/// on this box pin this MAC to a different name" cannot be answered
/// from our own output.
auto ScanLinkUnits(const std::string& dir) -> std::vector<LinkClaim>;

struct NetworkdReport {
  std::vector<NetworkdUnit> units;
  std::vector<std::string> changed;
  /// Units we generated for an interface that has since left the
  /// model, deleted by this apply.
  ///
  /// This is not tidiness. Two `.link` units pinning the same MAC to
  /// different names are resolved by udev in lexical filename order,
  /// and the one that wins is whichever name sorts first — which is
  /// how `10-f-enp1s0f1.link`, left behind by a single exploratory
  /// `set address`, beat `10-f-lan0.link` and left the port unrenamed
  /// with no error anywhere.
  std::vector<std::string> removed;
  /// `.link` files we did **not** write that pin a MAC this model also
  /// pins, to a different name. Reported, never deleted.
  std::vector<std::string> conflicts;
};

/// Install every unit atomically, and remove the ones we generated for
/// interfaces that are no longer in the model. Refuses the whole apply
/// if any unit was hand-edited, or if a foreign `.link` file claims one
/// of our MACs under another name — a firewall pointing at the wrong
/// port is a bypass, not an outage, so that is a refusal rather than a
/// warning.
auto ApplyNetworkd(const SystemConfig& cfg,
                   const NetworkdOptions& opts)
    -> std::expected<NetworkdReport, std::string>;

}  // namespace f::sysconfig

#endif  // INCLUDE_F_SYSCONFIG_NETWORKD_H_
