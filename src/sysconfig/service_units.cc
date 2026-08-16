/// @file service_units.cc
/// @brief The model-to-unit derivation, and the reconcile that acts on
///     it.

#include "f/sysconfig/service_units.h"

#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <format>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "f/sysconfig/chrony.h"
#include "f/sysconfig/dnsmasq.h"

namespace f::sysconfig {
namespace {

auto Trim(std::string s) -> std::string {
  while (!s.empty() && (s.back() == '\n' || s.back() == '\r' ||
                        s.back() == ' ' || s.back() == '\t')) {
    s.pop_back();
  }
  std::size_t i = 0;
  while (i < s.size() && (s[i] == ' ' || s[i] == '\t')) ++i;
  return s.substr(i);
}

auto Join(const std::vector<std::string>& v, const char* sep)
    -> std::string {
  std::string out;
  for (const auto& s : v) {
    if (!out.empty()) out += sep;
    out += s;
  }
  return out;
}

/// Run an argv and capture stdout+stderr. Used only by the real ops.
auto RunCapture(const std::vector<std::string>& argv)
    -> std::pair<int, std::string> {
  int fds[2];
  if (pipe(fds) != 0) return {-1, "pipe failed"};
  pid_t pid = fork();
  if (pid < 0) {
    close(fds[0]);
    close(fds[1]);
    return {-1, "fork failed"};
  }
  if (pid == 0) {
    close(fds[0]);
    dup2(fds[1], STDOUT_FILENO);
    dup2(fds[1], STDERR_FILENO);
    close(fds[1]);
    std::vector<char*> args;
    args.reserve(argv.size() + 1);
    for (const auto& a : argv) {
      args.push_back(const_cast<char*>(a.c_str()));
    }
    args.push_back(nullptr);
    execvp(args[0], args.data());
    _exit(127);
  }
  close(fds[1]);
  std::string out;
  std::array<char, 4096> buf{};
  ssize_t n = 0;
  while ((n = read(fds[0], buf.data(), buf.size())) > 0) {
    out.append(buf.data(), static_cast<std::size_t>(n));
  }
  close(fds[0]);
  int status = 0;
  waitpid(pid, &status, 0);
  return {WIFEXITED(status) ? WEXITSTATUS(status) : -1, out};
}

/// One `systemctl show` for every property, so a unit's state is one
/// atomic read rather than five that can disagree with each other
/// across a restart.
auto ShowUnit(const std::string& systemctl, const std::string& unit)
    -> UnitObservation {
  UnitObservation obs;
  auto [rc, out] = RunCapture(
      {systemctl, "show", unit, "--property=ActiveState",
       "--property=SubState", "--property=Result",
       "--property=LoadState", "--property=UnitFileState",
       "--property=NRestarts"});
  if (rc != 0 && out.empty()) {
    obs.unreachable = true;
    return obs;
  }
  bool saw_any = false;
  std::size_t pos = 0;
  while (pos <= out.size()) {
    auto nl = out.find('\n', pos);
    auto line =
        out.substr(pos, nl == std::string::npos ? std::string::npos
                                                : nl - pos);
    pos = nl == std::string::npos ? out.size() + 1 : nl + 1;
    auto eq = line.find('=');
    if (eq == std::string::npos) continue;
    auto key = line.substr(0, eq);
    auto value = Trim(line.substr(eq + 1));
    saw_any = true;
    if (key == "ActiveState") obs.active_state = value;
    if (key == "SubState") obs.sub_state = value;
    if (key == "Result") obs.result = value;
    if (key == "LoadState") obs.load_state = value;
    if (key == "UnitFileState") obs.enabled_state = value;
    if (key == "NRestarts") {
      try {
        if (!value.empty()) obs.restarts = std::stoi(value);
      } catch (...) {
        obs.restarts = 0;
      }
    }
  }
  // No properties at all is systemd not answering, which is not the
  // same as a unit that is inactive.
  if (!saw_any) obs.unreachable = true;
  return obs;
}

/// The unit's last few log lines, for the cases that need a reason.
auto UnitLog(const std::string& unit) -> std::string {
  auto [rc, out] = RunCapture(
      {"journalctl", "-u", unit, "-n", "5", "--no-pager", "-o",
       "cat"});
  (void)rc;
  return Trim(out);
}

/// Turn one observation into the state `show services` would name.
/// Routed through `ClassifyState` deliberately: the reconciler must
/// not be able to call a unit healthy that the status screen calls
/// broken.
auto Classify(const UnitObservation& obs, bool wanted) -> ServiceState {
  if (obs.unreachable) return ServiceState::kUnknown;
  // `activating (auto-restart)` is a crash loop that systemd reports
  // with the same ActiveState as a first start. ClassifyState reads
  // that off NRestarts and Result; SubState says it one step earlier,
  // before the first restart has been counted.
  int restarts = obs.restarts;
  std::string result = obs.result;
  if (obs.sub_state == "auto-restart" && restarts == 0 &&
      (result.empty() || result == "success")) {
    result = "auto-restart";
  }
  return ClassifyState(obs.active_state, wanted, restarts, result,
                       obs.load_state);
}

}  // namespace

auto UnitObservation::Installed() const -> bool {
  if (unreachable) return false;
  return load_state != "not-found" && !load_state.empty();
}

auto UnitObservation::Enabled() const -> bool {
  // `static` and `indirect` units have no enablement to change and are
  // treated as already correct; anything else must say `enabled`.
  return enabled_state == "enabled" ||
         enabled_state == "enabled-runtime" ||
         enabled_state == "static" || enabled_state == "indirect";
}

auto PlanServiceUnits(const SystemConfig& cfg)
    -> std::vector<ServiceUnit> {
  std::vector<ServiceUnit> out;

  ServiceUnit dnsmasq;
  dnsmasq.unit = "f-dnsmasq.service";
  {
    std::set<std::string> zones;
    for (const auto& d : cfg.dhcp) zones.insert(d.bind.zone);
    for (const auto& d : cfg.dns) zones.insert(d.bind.zone);
    dnsmasq.zones.assign(zones.begin(), zones.end());
  }
  auto dm = PlanDnsmasq(cfg);
  dnsmasq.interfaces = dm.allowed_interfaces;
  dnsmasq.wanted = dm.needed;
  {
    std::string kinds;
    if (!cfg.dhcp.empty()) kinds = "dhcp";
    if (!cfg.dns.empty()) {
      if (!kinds.empty()) kinds += "+";
      kinds += "dns";
    }
    if (kinds.empty()) kinds = "dhcp/dns";
    dnsmasq.name = std::format("{} (dnsmasq)", kinds);
  }
  out.push_back(std::move(dnsmasq));

  ServiceUnit chrony;
  chrony.unit = "f-chrony.service";
  auto ch = PlanChrony(cfg);
  chrony.wanted = ch.needed;
  chrony.zones = ch.served_zones;
  {
    // Interface names, not bind addresses: this list is compared
    // against observed sockets resolved to ports, and comparing two
    // different kinds of string manufactures a mismatch on every box.
    std::set<std::string> names;
    for (const auto& z : ch.served_zones) {
      for (const auto& n : cfg.InterfaceNamesInZone(z)) {
        names.insert(n);
      }
    }
    chrony.interfaces.assign(names.begin(), names.end());
  }
  chrony.name = ch.serves ? "ntp client+server (chrony)"
                          : "ntp client (chrony)";
  out.push_back(std::move(chrony));

  return out;
}

auto RealSystemdOps(const std::string& systemctl) -> SystemdOps {
  SystemdOps ops;
  ops.observe = [systemctl](const std::string& unit) {
    return ShowUnit(systemctl, unit);
  };
  ops.act = [systemctl](const std::vector<std::string>& verb,
                        const std::string& unit) {
    std::vector<std::string> argv{systemctl};
    argv.insert(argv.end(), verb.begin(), verb.end());
    argv.push_back(unit);
    return RunCapture(argv);
  };
  ops.log = [](const std::string& unit) { return UnitLog(unit); };
  return ops;
}

auto ReadOnlySystemdOps(const std::string& systemctl) -> SystemdOps {
  SystemdOps ops = RealSystemdOps(systemctl);
  // Deliberately null rather than a stub that fails: a caller which
  // may not act must not produce a report that reads as though it
  // tried. `ReconcileServices` records the command that WOULD have
  // been needed and marks the row refused.
  ops.act = nullptr;
  return ops;
}

auto UnitActionName(UnitAction a) -> std::string {
  switch (a) {
    case UnitAction::kNone:
      return "nothing to do";
    case UnitAction::kStarted:
      return "enabled and started";
    case UnitAction::kRestarted:
      return "restarted";
    case UnitAction::kEnabledOnly:
      return "enabled for next boot";
    case UnitAction::kStopped:
      return "stopped and disabled";
    case UnitAction::kRefused:
      break;
  }
  return "not attempted";
}

auto UnitOutcome::Ok() const -> bool {
  if (wanted) return after == ServiceState::kRunning;
  // Not wanted: the only thing that is wrong is still running.
  // `kUnexpected` is exactly that. A unit nobody wants that is
  // `failed`, or that systemd would not talk about, is reported —
  // `Format()` prints every row that is not silent — but it does not
  // fail an apply that was never about it.
  return after != ServiceState::kUnexpected;
}

auto UnitOutcome::Silent() const -> bool {
  return command.empty() && !wanted &&
         after == ServiceState::kNotConfigured &&
         (before == after || before == ServiceState::kUnknown);
}

auto UnitOutcome::Summary() const -> std::string {
  const auto state = ServiceStateName(after);
  if (!wanted) {
    if (after == ServiceState::kNotConfigured) {
      if (action == UnitAction::kStopped) {
        return std::format("{}: stopped and disabled — the model no "
                           "longer binds it anywhere",
                           unit);
      }
      // Nothing was run here. If it was running before this apply,
      // something else stopped it and the operator is entitled to see
      // that their `no dhcp` took effect rather than a row that reads
      // as though the service was never up.
      if (before == ServiceState::kUnexpected ||
          before == ServiceState::kRunning) {
        return std::format(
            "{}: no longer running — nothing in the model binds it "
            "any more",
            unit);
      }
      return std::format("{}: not running, and nothing binds it",
                         unit);
    }
    return std::format(
        "{}: nothing in the model binds it and systemd says {}{}{}",
        unit, state, detail.empty() ? "" : " — ", detail);
  }
  switch (after) {
    case ServiceState::kRunning:
      switch (action) {
        case UnitAction::kStarted:
          return std::format("{}: STARTED — it was not running, and "
                             "systemd now reports it active",
                             unit);
        case UnitAction::kRestarted:
          return std::format("{}: restarted onto the new "
                             "configuration, active",
                             unit);
        case UnitAction::kEnabledOnly:
          return std::format("{}: already running, now enabled for "
                             "the next boot too",
                             unit);
        default:
          // Nothing was run HERE. Whether that is because there was
          // nothing to do, or because something else — f-confd — did
          // it before this observer looked, is exactly what `before`
          // answers. Saying "already running" for the second would
          // describe this process's inaction and hide the change the
          // operator asked for.
          if (before != ServiceState::kRunning &&
              before != ServiceState::kUnknown) {
            return std::format(
                "{}: now RUNNING — it was {} before this apply", unit,
                ServiceStateName(before));
          }
          return std::format("{}: already running, nothing to do",
                             unit);
      }
    case ServiceState::kNotInstalled:
      return std::format(
          "{}: NOT INSTALLED on this box, so the {} this "
          "configuration binds cannot be served at all{}",
          unit, name, detail.empty() ? "" : std::format(" ({})",
                                                        detail));
    case ServiceState::kUnknown:
      return std::format(
          "{}: systemd did not answer, so whether the {} this "
          "configuration binds is being served is UNKNOWN{}",
          unit, name,
          detail.empty() ? "" : std::format(" ({})", detail));
    default:
      break;
  }
  if (action == UnitAction::kRefused && !command.empty()) {
    // Nothing was run, so the sentence must not read as though
    // something was. Name the command the box still needs.
    return std::format(
        "{}: the model binds {} here and systemd says {} — nothing "
        "was run ({}); `{}` is what it needs",
        unit, name, state,
        detail.empty() ? "this process may not change unit state"
                       : detail,
        command);
  }
  return std::format(
      "{}: the model binds {} here and systemd says {} after `{}`{}",
      unit, name, state,
      command.empty() ? "no command" : command,
      detail.empty() ? "" : std::format(" — {}", detail));
}

auto ReconcileReport::Ok() const -> bool {
  for (const auto& u : units) {
    if (!u.Ok()) return false;
  }
  return true;
}

auto ReconcileReport::Format() const -> std::string {
  std::vector<std::string> lines;
  for (const auto& u : units) {
    if (u.Silent()) continue;
    lines.push_back(u.Summary());
  }
  return Join(lines, "; ");
}

auto ReconcileReport::FailureDetail() const -> std::string {
  std::vector<std::string> lines;
  for (const auto& u : units) {
    if (!u.Ok()) lines.push_back(u.Summary());
  }
  return Join(lines, "; ");
}

auto ObserveServiceStates(const SystemConfig& cfg,
                          const SystemdOps& ops)
    -> std::map<std::string, ServiceState> {
  std::map<std::string, ServiceState> out;
  if (!ops.observe) return out;
  for (const auto& want : PlanServiceUnits(cfg)) {
    out[want.unit] = Classify(ops.observe(want.unit), want.wanted);
  }
  return out;
}

auto ReconcileServices(const SystemConfig& cfg,
                       const ReconcileOptions& opts)
    -> ReconcileReport {
  ReconcileReport report;
  const auto plan = PlanServiceUnits(cfg);
  for (const auto& want : plan) {
    UnitOutcome o;
    o.unit = want.unit;
    o.name = want.name;
    o.wanted = want.wanted;

    if (!opts.ops.observe) {
      o.action = UnitAction::kRefused;
      o.after = ServiceState::kUnknown;
      o.detail = "no way to ask systemd was configured";
      report.units.push_back(std::move(o));
      continue;
    }

    const auto before = opts.ops.observe(want.unit);
    // A snapshot from before the apply wins: this observer may be
    // looking after somebody else has already acted, and reading
    // `before` here would then read the `after`.
    if (auto it = opts.before.find(want.unit);
        it != opts.before.end()) {
      o.before = it->second;
    } else {
      o.before = Classify(before, want.wanted);
    }
    o.after = o.before;

    // A unit that is not installed is not a unit that failed. Nothing
    // is run, and the state stands as the report. It is only a refusal
    // when the model wanted it: an appliance is not obliged to carry
    // every unit, and a box with no chrony installed and no NTP bound
    // is not a box with a problem.
    if (!before.Installed()) {
      o.action = want.wanted ? UnitAction::kRefused : UnitAction::kNone;
      if (!before.unreachable) {
        o.detail = std::format("systemd reports LoadState={}",
                               before.load_state.empty()
                                   ? "(nothing)"
                                   : before.load_state);
      } else {
        o.detail = "systemctl could not be asked";
      }
      report.units.push_back(std::move(o));
      continue;
    }

    // From the LIVE observation, never the snapshot: what to run is a
    // decision about the box as it is now, while `o.before` may be a
    // record of how it was before somebody else acted.
    const auto now = Classify(before, want.wanted);
    const bool running = now == ServiceState::kRunning ||
                         now == ServiceState::kUnexpected ||
                         now == ServiceState::kActivating;
    const bool changed =
        std::find(opts.config_changed.begin(),
                  opts.config_changed.end(),
                  want.unit) != opts.config_changed.end();

    std::vector<std::string> verb;
    if (want.wanted) {
      if (!running || now == ServiceState::kRestarting) {
        // Not running — or running only in the sense that systemd is
        // still trying. Enable it so it survives a reboot and start it
        // in the same command, which is exactly what firstboot does.
        verb = {"enable", "--now"};
        o.action = UnitAction::kStarted;
      } else if (changed) {
        verb = {"restart"};
        o.action = UnitAction::kRestarted;
      } else if (!before.Enabled()) {
        // Running but not enabled: it does not survive the next
        // reboot, and "the model says this runs" has to mean both.
        verb = {"enable"};
        o.action = UnitAction::kEnabledOnly;
      }
    } else if (running || before.Enabled()) {
      // `no dhcp` on the last binding has to stop the server. A box
      // that goes on answering DHCP after being told not to is the
      // same defect as one that never starts, pointed the other way.
      verb = {"disable", "--now"};
      o.action = UnitAction::kStopped;
    }

    if (!verb.empty()) {
      o.command = std::format("systemctl {} {}", Join(verb, " "),
                              want.unit);
      if (!opts.ops.act) {
        o.action = UnitAction::kRefused;
        o.detail = "this process cannot change unit state";
      } else {
        auto [rc, out] = opts.ops.act(verb, want.unit);
        // The exit code is not the answer and is not reported as one.
        // It is kept only to explain a unit that did not move.
        if (rc != 0) o.detail = Trim(out);
      }
    }

    // Ask again. Everything above this line is intent.
    const auto after =
        verb.empty() ? before : opts.ops.observe(want.unit);
    o.after = Classify(after, want.wanted);
    if (o.after == ServiceState::kUnknown && after.unreachable) {
      if (o.detail.empty()) o.detail = "systemctl could not be asked";
    }
    if (!o.Ok() && o.detail.empty()) {
      o.detail = opts.ops.log ? opts.ops.log(want.unit) : "";
      if (o.detail.empty()) {
        o.detail = "no log output — the unit was never started";
      }
    }
    report.units.push_back(std::move(o));
  }
  return report;
}

}  // namespace f::sysconfig
