/// @file service_status.cc
/// @brief Query the backing services' health.

#include "f/sysconfig/service_status.h"

#include <sys/wait.h>

#include <array>
#include <cstdio>
#include <format>
#include <set>
#include <string>
#include <utility>

#include "f/sysconfig/dnsmasq.h"

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

  auto [rc, active] =
      RunCapture(Format(probe.is_active_cmd, dnsmasq.unit));
  // `systemctl is-active` exits non-zero for anything but active, so
  // the exit code carries no information the output does not.
  (void)rc;
  int restarts = 0;
  auto [rrc, restart_text] =
      RunCapture(Format(probe.restarts_cmd, dnsmasq.unit));
  (void)rrc;
  try {
    auto trimmed = Trim(restart_text);
    if (!trimmed.empty()) restarts = std::stoi(trimmed);
  } catch (...) {
    restarts = 0;
  }
  auto [src, result] =
      RunCapture(Format(probe.result_cmd, dnsmasq.unit));
  (void)src;
  auto [lsrc, load_state] =
      RunCapture(Format(probe.load_state_cmd, dnsmasq.unit));
  (void)lsrc;
  dnsmasq.state = ClassifyState(active, dnsmasq.expected, restarts,
                                result, load_state);

  if (dnsmasq.state == ServiceState::kNotInstalled) {
    dnsmasq.detail = std::format(
        "the model binds a service to {}, but {} is not installed "
        "on this box",
        dnsmasq.zones.empty() ? "a zone" : dnsmasq.zones.front(),
        dnsmasq.unit);
  } else if (dnsmasq.state == ServiceState::kFailed ||
             dnsmasq.state == ServiceState::kRestarting ||
             dnsmasq.state == ServiceState::kStopped ||
             dnsmasq.state == ServiceState::kUnknown) {
    auto [lrc, log] = RunCapture(Format(probe.log_cmd, dnsmasq.unit));
    (void)lrc;
    dnsmasq.detail = Trim(log);
    if (dnsmasq.state == ServiceState::kRestarting) {
      // systemd flags Result before it increments NRestarts, so the
      // count is legitimately zero on the first failed start.
      auto how = restarts > 0
                     ? std::format("failed and restarted {} time(s)",
                                   restarts)
                     : std::string("failed on start and is "
                                   "retrying");
      dnsmasq.detail =
          std::format("{}{}{}", how,
                      dnsmasq.detail.empty() ? "" : ": ",
                      dnsmasq.detail);
    }
    if (dnsmasq.detail.empty()) {
      dnsmasq.detail =
          dnsmasq.state == ServiceState::kUnknown
              ? "systemd did not answer; state is unknown, which is "
                "not the same as healthy"
              : "no log output — the unit was never started";
    }
  }

  return {dnsmasq};
}

}  // namespace f::sysconfig
