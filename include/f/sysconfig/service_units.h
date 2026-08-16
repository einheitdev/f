/// @file service_units.h
/// @brief Who owns the lifecycle of the units the model implies.
///
/// **The apply path owns it.** A service bound with `set dhcp` or
/// `set dns` is enabled and started by the apply that makes the
/// binding live, and one that is no longer bound anywhere is stopped
/// and disabled by the same apply. Before this file existed,
/// `systemctl enable --now` occurred in `deploy/firstboot/firstboot.py`
/// and nowhere else in the tree: the unit set was a snapshot of
/// whatever the model bound at provisioning time, and a service bound
/// afterwards was started by nobody while the CLI answered
/// `applied: yes`.
///
/// Two things follow from that decision, and both are the point:
///
///  1. **An apply can now fail in a new way.** A configuration that
///     was written but whose service will not start is not a success
///     with a footnote. It is reported as a failure, with the unit
///     named and systemd's own reason attached.
///
///  2. **The report is an observation, never the exit code.**
///     `systemctl enable --now` exits 0 for a unit that started,
///     crashed and entered auto-restart — the defect that made the
///     first provisioned box restart its dashboard sixty-seven times
///     while every line of output said it had started. Every state in
///     a `ReconcileReport` is read back out of systemd *after* the
///     action, through the same `ClassifyState` that `show services`
///     uses, so the two screens cannot disagree.
///
/// The model-to-unit derivation lives here too, in `PlanServiceUnits`,
/// and it is the only one. `QueryServices` builds `show services` from
/// it, the reconciler acts on it, and `f-sysconf render units` prints
/// it so `firstboot.py` can enable the same set without keeping a
/// second copy of the table in Python. A reconciler that derived its
/// unit list separately from the screen an operator checks afterwards
/// could act on one answer and report the other.

#ifndef INCLUDE_F_SYSCONFIG_SERVICE_UNITS_H_
#define INCLUDE_F_SYSCONFIG_SERVICE_UNITS_H_

#include <functional>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include "f/sysconfig/model.h"
#include "f/sysconfig/service_status.h"

namespace f::sysconfig {

// -- what the model implies --------------------------------------------

/// One backing service unit, and whether the model wants it running.
struct ServiceUnit {
  /// systemd unit name, e.g. "f-dnsmasq.service".
  std::string unit;
  /// Display name, e.g. "dhcp+dns (dnsmasq)".
  std::string name;
  /// True when the model binds this service somewhere it can serve.
  ///
  /// Note "where it can serve": a DHCP server bound to a zone with no
  /// interface in it is not wanted, because dnsmasq started for it
  /// would bind loopback and answer nobody. That is `PlanDnsmasq`'s
  /// judgement and it is deliberately not second-guessed here.
  bool wanted = false;
  /// Zones the service is bound to.
  std::vector<std::string> zones;
  /// Interfaces it should answer on, derived from those zones. This is
  /// intent, and is not evidence about anything.
  std::vector<std::string> interfaces;
};

/// The units the model implies, in a stable order.
///
/// The single derivation. Every consumer goes through it: the status
/// screen, the reconciler, and — via `f-sysconf render units` — the
/// first-boot provisioner.
auto PlanServiceUnits(const SystemConfig& cfg)
    -> std::vector<ServiceUnit>;

// -- what systemd says -------------------------------------------------

/// The raw properties one unit's state is decided from. Kept as
/// systemd's own strings rather than a verdict, so the classification
/// happens in exactly one place (`ClassifyState`).
struct UnitObservation {
  /// ActiveState: active / activating / inactive / failed / ...
  std::string active_state;
  /// SubState. `auto-restart` is what distinguishes a first start from
  /// a crash loop, and both report `activating`.
  std::string sub_state;
  /// Result: `success`, or the way it last died.
  std::string result;
  /// LoadState. `not-found` outranks everything: systemd goes on
  /// reporting a deleted unit's last ActiveState.
  std::string load_state;
  /// UnitFileState: `enabled`, `disabled`, `static`, ... Empty when it
  /// could not be asked. A unit that is running but not enabled does
  /// not survive the next reboot, which is not what "the model says
  /// this should run" means.
  std::string enabled_state;
  /// How many times systemd has restarted it.
  int restarts = 0;
  /// True when systemd could not be asked at all. Not the same as any
  /// answer it might have given.
  bool unreachable = false;

  /// True when the unit file is installed on this box.
  auto Installed() const -> bool;
  /// True when the unit is enabled for the next boot.
  auto Enabled() const -> bool;
};

/// Everything the reconciler needs from systemd, in one seam.
///
/// Injected in full rather than as command strings so a test can hold
/// a mutable unit table and prove a real transition: a test whose fake
/// reports "active" before and after the action has proved nothing
/// about the action.
struct SystemdOps {
  /// Read one unit's properties.
  std::function<UnitObservation(const std::string& unit)> observe;
  /// Run a systemctl verb on a unit. `verb` is already split, e.g.
  /// {"enable", "--now"}. Returns (exit code, combined output).
  ///
  /// Null means this caller may not change unit state: the reconcile
  /// then names the command each unit needs and marks the row refused,
  /// rather than reporting an action it did not take.
  std::function<std::pair<int, std::string>(
      const std::vector<std::string>& verb, const std::string& unit)>
      act;
  /// The unit's last few log lines, asked for only when something is
  /// wrong. Null means no log is available, which is reported as no
  /// log rather than as no fault.
  std::function<std::string(const std::string& unit)> log;
};

/// The real thing: `systemctl show` and `systemctl <verb>`.
/// @param systemctl Path to the binary; overridable for a test bench.
auto RealSystemdOps(const std::string& systemctl = "systemctl")
    -> SystemdOps;

/// Ops that refuse to act and say so, for a caller with no privilege
/// to change unit state. Observation still works.
auto ReadOnlySystemdOps(const std::string& systemctl = "systemctl")
    -> SystemdOps;

// -- what the reconciler did -------------------------------------------

/// What was ATTEMPTED on a unit — never what came of it, which is
/// `UnitOutcome::after`. Deliberately distinguishes "started" from
/// "was already running": a test that cannot tell them apart passes on
/// a box where the unit happened to be up already, which proves
/// nothing about the code that was supposed to start it.
enum class UnitAction {
  /// The model and systemd already agreed; nothing was run.
  kNone,
  /// It was not running, and it was enabled and started.
  kStarted,
  /// It was already running and its configuration had changed under
  /// it, so it was restarted.
  kRestarted,
  /// It was running, and it was enabled for the next boot as well.
  kEnabledOnly,
  /// The model no longer binds it; it was stopped and disabled.
  kStopped,
  /// Nothing was attempted, and the reason is in `detail` — the unit
  /// is not installed, or these ops cannot act.
  kRefused,
};

auto UnitActionName(UnitAction a) -> std::string;

/// One unit, before and after.
struct UnitOutcome {
  std::string unit;
  std::string name;
  bool wanted = false;
  /// The state systemd reported before anything was run.
  ServiceState before = ServiceState::kUnknown;
  UnitAction action = UnitAction::kNone;
  /// The command line that was run, or — when `action` is `kRefused`
  /// because these ops may not act — the one that would have been
  /// needed. Either way the operator gets to see the thing that acts
  /// on their box, named.
  std::string command;
  /// The state systemd reported afterwards. This — not the exit code
  /// of `command` — is what the report is built from.
  ServiceState after = ServiceState::kUnknown;
  /// systemd's own words when something is wrong.
  std::string detail;

  /// True when systemd and the model agree now.
  auto Ok() const -> bool;
  /// True when this row has nothing to tell anybody: nothing was run,
  /// nothing binds the unit, it is not running, and it was not running
  /// before either. Every other combination gets a row — a state that
  /// is left out is a state nobody can act on. It is a method rather
  /// than a rule each renderer applies, because two renderers with
  /// their own copy of "when to stay quiet" is two ways to lose a
  /// finding.
  auto Silent() const -> bool;
  /// One sentence an operator can act on. Never empty.
  auto Summary() const -> std::string;
};

/// The whole reconcile.
struct ReconcileReport {
  std::vector<UnitOutcome> units;
  /// True when every unit ended in the state the model asks for.
  auto Ok() const -> bool;
  /// One line per unit that did something or is wrong; empty when
  /// there is nothing to say.
  auto Format() const -> std::string;
  /// Why `Ok()` is false, naming every unit that is wrong. Empty when
  /// it is true.
  auto FailureDetail() const -> std::string;
};

/// How to reconcile.
struct ReconcileOptions {
  SystemdOps ops;
  /// Units whose backing configuration was just rewritten. One that is
  /// already running is restarted so it reads the new file; one that
  /// is not running is started regardless, because the model wants it.
  std::vector<std::string> config_changed;
  /// States observed BEFORE the apply, unit by unit.
  ///
  /// For the caller that also acts this is empty and the states are
  /// read here. It matters for the caller that only observes, because
  /// something else — `f-confd` — did the applying: by the time that
  /// caller looks, the `before` it would read is already the `after`,
  /// and the report would describe the observer's own inaction ("this
  /// was already running") instead of the change the operator asked
  /// for. `ObserveServiceStates` takes the snapshot.
  std::map<std::string, ServiceState> before;
};

/// The state of every unit the model implies, right now.
///
/// Taken before an apply by a caller that will not be the one acting,
/// so the report afterwards can name the transition rather than the
/// state it happens to find.
auto ObserveServiceStates(const SystemConfig& cfg,
                          const SystemdOps& ops)
    -> std::map<std::string, ServiceState>;

/// Bring the units the model implies into the state it implies, then
/// report what systemd says about each.
///
/// Never throws and never leaves a unit unreported: a unit that could
/// not be asked about is `kUnknown`, which is a fault state, not a
/// blank row.
auto ReconcileServices(const SystemConfig& cfg,
                       const ReconcileOptions& opts)
    -> ReconcileReport;

}  // namespace f::sysconfig

#endif  // INCLUDE_F_SYSCONFIG_SERVICE_UNITS_H_
