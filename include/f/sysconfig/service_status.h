/// @file service_status.h
/// @brief What the operator sees when a service is not running.
///
/// "Silently absent" is the wrong answer everywhere, so every service
/// the model can express has a state that can be asked for and a
/// reason attached to it. The two questions that must always have an
/// answer are *should this be running* (from the model) and *is it*
/// (from systemd) — a mismatch between them is the fault, and it is
/// reported rather than inferred.

#ifndef INCLUDE_F_SYSCONFIG_SERVICE_STATUS_H_
#define INCLUDE_F_SYSCONFIG_SERVICE_STATUS_H_

#include <string>
#include <vector>

#include "f/sysconfig/model.h"
#include "f/sysconfig/observe.h"

namespace f::sysconfig {

/// The health of one backing service.
enum class ServiceState {
  /// The model binds nothing here, and nothing is running. Correct.
  kNotConfigured,
  /// Should be running, and is.
  kRunning,
  /// Should be running, is coming up for the first time.
  kActivating,
  /// Should be running, is between restarts after a failure. systemd
  /// reports this as `activating` for the whole restart burst, which
  /// reads as "starting" and hides a unit that is failing repeatedly —
  /// so it gets its own state rather than being rendered as progress.
  kRestarting,
  /// Should be running, is not, and systemd says why.
  kFailed,
  /// The model binds a service here, but the unit is not installed on
  /// this box at all. systemd reports a missing unit as `failed`
  /// (and remembers a stale ActiveState even after the file is
  /// deleted), which would send an operator hunting for a crash that
  /// never happened. This is the "silently absent" case, named.
  kNotInstalled,
  /// Should be running, is not running and has not failed — nobody
  /// ever started it. This is the case a status display must never
  /// render as blank.
  kStopped,
  /// Running, but the model says it should not be.
  kUnexpected,
  /// systemd could not be reached; state is genuinely unknown, which
  /// is not the same as "fine".
  kUnknown,
};

auto ServiceStateName(ServiceState s) -> std::string;

struct ServiceStatus {
  /// Display name, e.g. "dhcp+dns (dnsmasq)".
  std::string name;
  std::string unit;
  ServiceState state = ServiceState::kUnknown;
  /// True when the model binds this service to at least one zone.
  bool expected = false;
  /// Zones the service is bound to.
  std::vector<std::string> zones;
  /// Interfaces it *should* answer on, derived from those zones. This
  /// is intent. It is re-derived from the same model that generated
  /// the config, so it can never disagree with the config and is
  /// therefore not evidence that the config worked.
  std::vector<std::string> interfaces;
  /// Where the daemon is *actually* listening, read from the kernel.
  /// This is the column an operator is entitled to trust, and the one
  /// that told the truth when a config named a port that did not
  /// exist.
  BindingReport observed;
  /// The last thing the service said, when it said something bad.
  std::string detail;

  /// Interfaces the model expects but the kernel does not show a
  /// socket for. Empty when the observation is unavailable — an
  /// unanswerable question is not a mismatch.
  auto MissingInterfaces() const -> std::vector<std::string>;

  /// True when the service is running, the model binds it somewhere,
  /// and it is demonstrably not answering there. The whole reason this
  /// struct carries two lists instead of one.
  auto Mismatched() const -> bool;

  /// One sentence naming the mismatch, or empty when there is none.
  auto MismatchDetail() const -> std::string;
};

/// How to reach systemd. Injected so the query is testable without a
/// running init.
struct ServiceProbe {
  /// Command that prints a unit's ActiveState, given the unit name.
  std::string is_active_cmd = "systemctl is-active";
  /// Command that prints how many times the unit has been restarted.
  /// A non-zero count turns `activating` from progress into flapping.
  std::string restarts_cmd =
      "systemctl show {} -p NRestarts --value";
  /// Command that prints the unit's last Result. systemd sets this to
  /// `exit-code` on the first failed start, before NRestarts has
  /// incremented, so it catches a flap one restart earlier.
  std::string result_cmd = "systemctl show {} -p Result --value";
  /// Command that prints whether the unit file exists at all.
  /// `not-found` here outranks every other signal: systemd keeps
  /// reporting a deleted unit's last ActiveState, so ActiveState alone
  /// says "failed" for a unit that was never installed.
  std::string load_state_cmd =
      "systemctl show {} -p LoadState --value";
  /// Command that prints recent log lines for a unit.
  std::string log_cmd =
      "journalctl -u {} -n 5 --no-pager -o cat";
  /// Command that prints the unit's main PID. Everything about where
  /// the daemon is actually listening hangs off this one number.
  std::string main_pid_cmd = "systemctl show {} -p MainPID --value";
  /// Where the socket observation reads from. Injected together with
  /// the port table so the whole "green while broken" case can be
  /// reproduced from a fixture.
  ListenerSource listeners;
  /// The port table, used to turn a listening address into the port it
  /// answers on. Injected for the same reason.
  PortSource ports;
};

/// Ask systemd about every service the model can express, and then ask
/// the kernel where each one is actually bound. Two different
/// questions, deliberately not answered from one source.
auto QueryServices(const SystemConfig& cfg,
                   const ServiceProbe& probe = {})
    -> std::vector<ServiceStatus>;

/// Classify a raw `systemctl is-active` answer against whether the
/// model expects the unit to be running, and how many times systemd
/// has already restarted it. Pure, so the whole state table is
/// unit-testable.
/// @param active_state systemd's ActiveState string.
/// @param expected Whether the model binds this service anywhere.
/// @param restarts How many restarts systemd has performed.
/// @param result systemd's Result string; anything but "success" (or
///     empty, meaning not asked) means the unit has already failed at
///     least once.
/// @param load_state systemd's LoadState; "not-found" means the unit
///     file is absent and outranks everything else.
auto ClassifyState(const std::string& active_state, bool expected,
                   int restarts = 0, const std::string& result = "",
                   const std::string& load_state = "") -> ServiceState;

}  // namespace f::sysconfig

#endif  // INCLUDE_F_SYSCONFIG_SERVICE_STATUS_H_
