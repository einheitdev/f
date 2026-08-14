/// @file service_status.cc
/// @brief Query the backing services' health.

#include "f/sysconfig/service_status.h"

#include <sys/wait.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <format>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "f/sysconfig/chrony.h"
#include "f/sysconfig/dnsmasq.h"
#include "f/sysconfig/observe.h"

namespace f::sysconfig {
namespace {

auto RunCapture(const std::string& cmd)
    -> std::pair<int, std::string> {
  std::string out;
  FILE* p = popen((cmd + " 2>/dev/null").c_str(), "r");
  if (p == nullptr) return {-1, ""};
  std::array<char, 512> buf{};
  while (std::fgets(buf.data(), buf.size(), p) != nullptr) {
    out += buf.data();
  }
  int rc = pclose(p);
  return {rc == -1 ? -1 : (WIFEXITED(rc) ? WEXITSTATUS(rc) : -1),
          out};
}

auto Trim(std::string s) -> std::string {
  while (!s.empty() &&
         (s.back() == '\n' || s.back() == '\r' || s.back() == ' ')) {
    s.pop_back();
  }
  return s;
}

/// Substitute the unit name into a probe command template.
auto Format(const std::string& tmpl, const std::string& unit)
    -> std::string {
  auto brace = tmpl.find("{}");
  if (brace == std::string::npos) return tmpl + " " + unit;
  return tmpl.substr(0, brace) + unit + tmpl.substr(brace + 2);
}

}  // namespace

auto ServiceStatus::MissingInterfaces() const
    -> std::vector<std::string> {
  std::vector<std::string> missing;
  if (observed.availability != BindingAvailability::kObserved) {
    return missing;
  }
  for (const auto& want : interfaces) {
    if (std::find(observed.interfaces.begin(),
                  observed.interfaces.end(),
                  want) == observed.interfaces.end()) {
      missing.push_back(want);
    }
  }
  return missing;
}

auto ServiceStatus::Mismatched() const -> bool {
  if (!expected) return false;
  if (state != ServiceState::kRunning) return false;
  return !MissingInterfaces().empty();
}

auto ServiceStatus::MismatchDetail() const -> std::string {
  if (!Mismatched()) return "";
  std::string want;
  for (const auto& n : MissingInterfaces()) {
    want += (want.empty() ? "" : ", ") + n;
  }
  std::string have;
  for (const auto& l : observed.listeners) {
    have += (have.empty() ? "" : ", ") + l.Format();
  }
  if (have.empty()) have = "nothing at all";
  return std::format(
      "systemd says this unit is running, and it is — but the model "
      "binds it to {} and the kernel shows it listening on {}. It is "
      "running and answering nobody on {}. The usual cause is a "
      "generated file naming an interface that does not exist yet: "
      "check `show system` for a pending rename.",
      want, have, want);
}

auto ServiceStateName(ServiceState s) -> std::string {
  switch (s) {
    case ServiceState::kNotConfigured:
      return "not configured";
    case ServiceState::kRunning:
      return "running";
    case ServiceState::kActivating:
      return "starting";
    case ServiceState::kRestarting:
      return "RESTARTING (failing)";
    case ServiceState::kFailed:
      return "FAILED";
    case ServiceState::kNotInstalled:
      return "NOT INSTALLED";
    case ServiceState::kStopped:
      return "STOPPED";
    case ServiceState::kUnexpected:
      return "running (not in the config)";
    case ServiceState::kUnknown:
      break;
  }
  return "unknown";
}

auto ClassifyState(const std::string& active_state, bool expected,
                   int restarts, const std::string& result,
                   const std::string& load_state) -> ServiceState {
  // A missing unit file outranks ActiveState, which systemd keeps
  // reporting from the last time the unit existed.
  if (Trim(load_state) == "not-found") {
    return expected ? ServiceState::kNotInstalled
                    : ServiceState::kNotConfigured;
  }
  const auto s = Trim(active_state);
  if (s.empty()) return ServiceState::kUnknown;
  if (s == "active" || s == "reloading") {
    return expected ? ServiceState::kRunning
                    : ServiceState::kUnexpected;
  }
  if (s == "activating") {
    if (!expected) return ServiceState::kUnexpected;
    // systemd reports `activating` both for a first start and for
    // every gap in a Restart=on-failure burst. Rendering the second
    // as "starting" is how a unit that has never once served a packet
    // passes for healthy until somebody watches it for a minute.
    const auto r = Trim(result);
    bool already_failed = restarts > 0 ||
                          (!r.empty() && r != "success");
    return already_failed ? ServiceState::kRestarting
                          : ServiceState::kActivating;
  }
  if (s == "failed") {
    // A unit that failed is a fault whether or not the model wants it
    // — the operator needs to see it either way.
    return ServiceState::kFailed;
  }
  if (s == "inactive" || s == "deactivating") {
    // The load-bearing distinction: not running *and expected to be*
    // is a fault with a name, not an empty row.
    return expected ? ServiceState::kStopped
                    : ServiceState::kNotConfigured;
  }
  return ServiceState::kUnknown;
}

namespace {

/// Ask systemd about one unit and classify what it says. Shared so
/// that a second service cannot accidentally get a laxer reading of
/// "healthy" than the first.
auto Probe(const ServiceProbe& probe, ServiceStatus* out) -> void {
  auto [rc, active] = RunCapture(Format(probe.is_active_cmd,
                                        out->unit));
  (void)rc;
  int restarts = 0;
  auto [rrc, restart_text] =
      RunCapture(Format(probe.restarts_cmd, out->unit));
  (void)rrc;
  try {
    auto trimmed = Trim(restart_text);
    if (!trimmed.empty()) restarts = std::stoi(trimmed);
  } catch (...) {
    restarts = 0;
  }
  auto [src, result] = RunCapture(Format(probe.result_cmd,
                                         out->unit));
  (void)src;
  auto [lsrc, load_state] =
      RunCapture(Format(probe.load_state_cmd, out->unit));
  (void)lsrc;
  out->state = ClassifyState(active, out->expected, restarts, result,
                             load_state);

  if (out->state == ServiceState::kNotInstalled) {
    out->detail = std::format(
        "the model binds a service to {}, but {} is not installed "
        "on this box",
        out->zones.empty() ? "a zone" : out->zones.front(),
        out->unit);
    return;
  }
  if (out->state != ServiceState::kFailed &&
      out->state != ServiceState::kRestarting &&
      out->state != ServiceState::kStopped &&
      out->state != ServiceState::kUnknown) {
    return;
  }
  auto [lrc, log] = RunCapture(Format(probe.log_cmd, out->unit));
  (void)lrc;
  out->detail = Trim(log);
  if (out->state == ServiceState::kRestarting) {
    auto how = restarts > 0
                   ? std::format("failed and restarted {} time(s)",
                                 restarts)
                   : std::string("failed on start and is retrying");
    out->detail = std::format("{}{}{}", how,
                              out->detail.empty() ? "" : ": ",
                              out->detail);
  }
  if (out->detail.empty()) {
    out->detail =
        out->state == ServiceState::kUnknown
            ? "systemd did not answer; state is unknown, which is "
              "not the same as healthy"
            : "no log output — the unit was never started";
  }
}

/// Ask the kernel where this unit is actually listening.
///
/// Deliberately a second question, asked of a second source. Deriving
/// it from the model would make the answer agree with the config by
/// construction, which is the defect this exists to close: a status
/// column that cannot disagree with the thing it is reporting on is
/// not a report.
auto ObserveBinding(const ServiceProbe& probe, const PortTable& ports,
                    ServiceStatus* out) -> void {
  if (out->state == ServiceState::kNotInstalled ||
      out->state == ServiceState::kNotConfigured) {
    out->observed.availability = BindingAvailability::kNoProcess;
    out->observed.detail =
        "the unit is not running, so it holds no sockets";
    return;
  }
  auto [rc, pid_text] =
      RunCapture(Format(probe.main_pid_cmd, out->unit));
  (void)rc;
  int pid = 0;
  try {
    auto trimmed = Trim(pid_text);
    if (!trimmed.empty()) pid = std::stoi(trimmed);
  } catch (...) {
    pid = 0;
  }
  out->observed = ObserveListeners(pid, probe.listeners);
  ResolveListenerInterfaces(ports, &out->observed);
}

/// The time service, which is a service like any other and must not
/// be allowed to be silently absent — every timestamp on the box is
/// stated in what it does or fails to do.
auto ChronyStatus(const SystemConfig& cfg, const ServiceProbe& probe,
                  const PortTable& ports) -> ServiceStatus {
  ServiceStatus s;
  s.unit = "f-chrony.service";
  auto plan = PlanChrony(cfg);
  s.expected = plan.needed;
  s.zones = plan.served_zones;
  // Interface names, not bind addresses: the column this feeds is
  // compared against observed sockets resolved to ports, and comparing
  // two different kinds of string would manufacture a mismatch on
  // every box. A client-only chrony serves no zone and expects
  // nothing, which is the containment stated as an empty list.
  {
    std::set<std::string> names;
    for (const auto& z : plan.served_zones) {
      for (const auto& n : cfg.InterfaceNamesInZone(z)) {
        names.insert(n);
      }
    }
    s.interfaces.assign(names.begin(), names.end());
  }
  s.name = plan.serves ? "ntp client+server (chrony)"
                       : "ntp client (chrony)";
  // Probed even when the model does not expect it. A chronyd running
  // that nothing asked for is `running (not in the config)` — a box
  // quietly taking its time from a source the model never named — and
  // skipping the probe would render that as `unknown`, which is a
  // fault state and would hide a real one behind it.
  Probe(probe, &s);
  ObserveBinding(probe, ports, &s);
  return s;
}

}  // namespace

auto QueryServices(const SystemConfig& cfg,
                   const ServiceProbe& probe)
    -> std::vector<ServiceStatus> {
  ServiceStatus dnsmasq;
  dnsmasq.unit = "f-dnsmasq.service";

  std::set<std::string> zones;
  for (const auto& d : cfg.dhcp) zones.insert(d.bind.zone);
  for (const auto& d : cfg.dns) zones.insert(d.bind.zone);
  dnsmasq.zones.assign(zones.begin(), zones.end());

  auto plan = PlanDnsmasq(cfg);
  dnsmasq.interfaces = plan.allowed_interfaces;
  dnsmasq.expected = plan.needed;

  std::string kinds;
  if (!cfg.dhcp.empty()) kinds = "dhcp";
  if (!cfg.dns.empty()) {
    if (!kinds.empty()) kinds += "+";
    kinds += "dns";
  }
  if (kinds.empty()) kinds = "dhcp/dns";
  dnsmasq.name = std::format("{} (dnsmasq)", kinds);

  Probe(probe, &dnsmasq);

  // The port table is read once and shared: both services resolve
  // their listening addresses through the same view of the hardware,
  // so they cannot disagree about which port an address is on.
  auto ports = ObservePorts(probe.ports);
  ObserveBinding(probe, ports, &dnsmasq);

  return {dnsmasq, ChronyStatus(cfg, probe, ports)};
}

}  // namespace f::sysconfig
