/// @file chrony.cc
/// @brief Render and install the chrony artifact; report the clock.

#include "f/sysconfig/chrony.h"

#include <sys/timex.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <format>
#include <fstream>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "f/sysconfig/artifact.h"
#include "f/sysconfig/net.h"
#include "f/sysconfig/validate.h"

namespace f::sysconfig {
namespace {

auto RunCapture(const std::string& cmd)
    -> std::pair<int, std::string> {
  std::string out;
  FILE* p = popen((cmd + " 2>&1").c_str(), "r");
  if (p == nullptr) return {-1, "popen failed"};
  std::array<char, 512> buf{};
  while (std::fgets(buf.data(), buf.size(), p) != nullptr) {
    out += buf.data();
  }
  int rc = pclose(p);
  if (rc == -1) return {-1, out};
  return {WIFEXITED(rc) ? WEXITSTATUS(rc) : -1, out};
}

auto ReadFile(const std::string& path)
    -> std::optional<std::string> {
  std::ifstream in(path);
  if (!in) return std::nullopt;
  std::ostringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

auto Trim(std::string s) -> std::string {
  while (!s.empty() && (s.back() == '\n' || s.back() == '\r' ||
                        s.back() == ' ')) {
    s.pop_back();
  }
  return s;
}

/// A cut-off before which a wall clock is not a time, it is a boot
/// that has not been told what year it is. 2020-01-01. Chosen well
/// after the last plausible build date and well before any deployment.
constexpr std::int64_t kImplausibleBefore = 1577836800;

}  // namespace

auto PlanChrony(const SystemConfig& cfg) -> ChronyPlan {
  ChronyPlan plan;

  for (const auto& n : cfg.ntp) {
    if (!n.upstreams.empty()) {
      for (const auto& u : n.upstreams) plan.upstreams.push_back(u);
    }
    if (n.bind.zone.empty()) continue;
    if (cfg.FindZone(n.bind.zone) == nullptr) continue;
    if (!n.serve) continue;
    plan.served_zones.push_back(n.bind.zone);
    // Placement is derived from zone membership here and nowhere
    // else, exactly as the dnsmasq interface list is. There is no key
    // in the model that names an address for the NTP server.
    for (const auto* i : cfg.InterfacesInZone(n.bind.zone)) {
      if (i->mode != AddressMode::kStatic) continue;
      auto p = ParseCidr4(i->address);
      if (!p) continue;
      auto slash = i->address.find('/');
      plan.bind_addresses.push_back(i->address.substr(0, slash));
      plan.allowed_subnets.push_back(std::format(
          "{}/{}", FormatIpv4(p->Network()), p->bits));
    }
  }
  plan.serves = !plan.bind_addresses.empty();
  plan.needed = !cfg.ntp.empty();

  std::ostringstream o;
  o << "# chrony configuration for the f appliance.\n"
    << "#\n"
    << "# GENERATED FROM THE SYSTEM CONFIGURATION MODEL.\n"
    << "# Do not edit. Edits are reported as drift, not merged.\n"
    << "#\n"
    << "# Every address below was derived from zone membership. No "
       "key\n"
    << "# in the system config names an address for a service.\n"
    << "\n";

  o << "# --- the client half "
       "----------------------------------------\n";
  if (plan.upstreams.empty()) {
    o << "# no upstream is configured: this box will not learn the "
         "time\n";
    o << "# from anywhere, and `show time` reports that as a named "
         "state\n";
    o << "# rather than as a clock that happens to be wrong.\n";
  } else {
    for (const auto& u : plan.upstreams) {
      // `iburst` so the first correction happens in seconds rather
      // than minutes. The window between boot and first sync is
      // exactly when log timestamps are worthless, so it is the
      // window worth shortening.
      o << "server " << u << " iburst\n";
    }
  }
  // A board with no battery-backed RTC boots at the epoch, which is
  // an offset chrony would otherwise refuse to slew and would take
  // days to walk in. Step it, without limit, for the first three
  // corrections: the alternative is a box that runs for a week
  // stamping logs 1970 while chrony politely converges.
  o << "makestep 1.0 3\n";
  // Write the disciplined time back to the RTC when there is one, so
  // the next boot starts from something sane even before the network
  // is up.
  o << "rtcsync\n";
  // Inside chronyd's own state directory, not f's: the stock
  // AppArmor profile permits /var/lib/chrony/{,*} and nothing else,
  // and a drift file it cannot write is a daemon that relearns the
  // oscillator's error from scratch on every boot.
  o << "driftfile /var/lib/chrony/f.drift\n";
  o << "\n";

  o << "# --- the server half "
       "----------------------------------------\n";
  if (!plan.serves) {
    // The containment, one directive wide: with no zone asking for a
    // server there is no listening socket, so there is nothing to
    // answer the office with even by mistake.
    o << "# no zone asks for an NTP server, so the server port is "
         "not\n";
    o << "# opened at all.\n";
    o << "port 0\n";
  } else {
    o << "port 123\n";
    for (const auto& a : plan.bind_addresses) {
      o << "bindaddress " << a << "\n";
    }
    for (std::size_t i = 0; i < plan.served_zones.size(); ++i) {
      o << "# zone " << plan.served_zones[i] << "\n";
    }
    for (const auto& s : plan.allowed_subnets) {
      o << "allow " << s << "\n";
    }
    // Serve time even before we are synchronised ourselves, at a
    // stratum that says so. A testnet whose boards agree with each
    // other and are an hour out is far more useful than a testnet
    // whose boards each guess separately — and stratum 10 is the
    // standing convention for "this is local, do not trust it far".
    o << "local stratum 10\n";
  }
  // The command socket is how `show time` asks what the reference is.
  o << "\ncmdport 0\n";
  o << "bindcmdaddress /run/chrony/chronyd.sock\n";

  plan.content = WrapWithDigest(o.str());
  return plan;
}

auto CheckWithChrony(const std::string& content,
                     const std::string& chronyd_path,
                     const std::string& near_path)
    -> std::expected<std::string, Error<BackendError>> {
  std::error_code ec;
  if (!std::filesystem::exists(chronyd_path, ec)) {
    return MakeError(
        BackendError::kToolMissing,
        std::format("chronyd not found at {}", chronyd_path));
  }
  // The scratch file goes beside the real one, not in /tmp. chronyd
  // is AppArmor-confined on Debian, so a check run somewhere the
  // daemon may read proves nothing about the path it will actually
  // be given — the check has to be subject to the same confinement
  // as the thing it is checking.
  auto dir = std::filesystem::path(near_path).parent_path();
  if (dir.empty() || !std::filesystem::exists(dir, ec)) {
    dir = std::filesystem::temp_directory_path();
  }
  auto tmp =
      dir / std::format(".f-chrony-check-{}.conf", ::getpid());
  {
    std::ofstream out(tmp);
    if (!out) {
      return MakeError(BackendError::kWriteFailed,
                       std::format("cannot write {}", tmp.string()));
    }
    out << content;
  }
  // `chronyd -p` parses the configuration, prints it and exits
  // without touching the clock or binding anything.
  auto [rc, output] = RunCapture(
      std::format("{} -p -f {}", chronyd_path, tmp.string()));
  std::filesystem::remove(tmp, ec);
  if (rc != 0) {
    // A permission error on a file that plainly exists and is
    // readable is almost always AppArmor, and the raw message sends
    // an operator hunting file modes for an hour. Name the real
    // cause and the two ways out.
    if (output.find("Permission denied") != std::string::npos) {
      return MakeError(
          BackendError::kToolRejected,
          std::format(
              "chronyd could not read the generated config at {}. "
              "The file exists and is readable — this is AppArmor: "
              "the stock profile confines chronyd to "
              "/etc/chrony/{{,**}}. Put the artifact inside "
              "/etc/chrony/, or add a local include permitting this "
              "path. chronyd said: {}",
              tmp.string(), output));
    }
    return MakeError(
        BackendError::kToolRejected,
        std::format("chronyd rejected the generated config: {}",
                    output));
  }
  return output;
}

auto CheckChronyDrift(const SystemConfig& cfg,
                      const std::string& path) -> DriftKind {
  return CheckArtifactDrift(path, PlanChrony(cfg).content);
}

auto ApplyChrony(const SystemConfig& cfg, const ChronyOptions& opts)
    -> std::expected<ApplyReport, Error<BackendError>> {
  auto vr = Validate(cfg);
  if (vr.HasErrors()) {
    std::string msg = "system config does not validate:";
    for (const auto& e : vr.Errors()) msg += "\n  " + e.Format();
    return MakeError(BackendError::kModelInvalid, msg);
  }

  auto plan = PlanChrony(cfg);
  auto drift = CheckArtifactDrift(opts.conf_path, plan.content);
  if (opts.refuse_on_drift && drift == DriftKind::kHandEdited) {
    return MakeError(
        BackendError::kDrift,
        std::format(
            "{} was edited by hand. It is a generated artifact, so "
            "the edit would be lost: fold the change into the "
            "system config, or re-apply with force to discard it.",
            opts.conf_path));
  }

  auto check = CheckWithChrony(plan.content, opts.chronyd_path,
                               opts.conf_path);
  if (!check) return std::unexpected(check.error());

  ApplyReport report;
  report.conf_path = opts.conf_path;
  report.check_output = *check;

  auto installed = InstallArtifact(opts.conf_path, plan.content);
  if (!installed) {
    return MakeError(BackendError::kWriteFailed, installed.error());
  }
  report.changed = *installed;
  return report;
}

// -- the clock --------------------------------------------------------

auto TimeTrustName(TimeTrust t) -> std::string {
  switch (t) {
    case TimeTrust::kSynchronised:
      return "synchronised";
    case TimeTrust::kNotYetSynchronised:
      return "NOT YET SYNCHRONISED";
    case TimeTrust::kNoTimeSource:
      return "NO TIME SOURCE";
    case TimeTrust::kUnknown:
      break;
  }
  return "unknown";
}

auto RtcPresenceName(RtcPresence p) -> std::string {
  switch (p) {
    case RtcPresence::kPresent:
      return "present";
    case RtcPresence::kAbsent:
      return "absent";
    case RtcPresence::kUnknown:
      break;
  }
  return "unknown";
}

auto QueryTime(const SystemConfig& cfg, const TimeSource& src)
    -> TimeStatus {
  TimeStatus status;

  status.wall_seconds = src.fake_wall_seconds != 0
                            ? src.fake_wall_seconds
                            : static_cast<std::int64_t>(::time(
                                  nullptr));
  status.implausible = status.wall_seconds < kImplausibleBefore;

  if (auto up = ReadFile(src.uptime_path); up) {
    status.uptime_seconds =
        static_cast<std::int64_t>(std::strtod(up->c_str(), nullptr));
  }

  // The RTC. Its presence is a hardware fact the board answers for
  // itself, which is better than a claim in a document: the same
  // binary runs on the rig, on a VM and on whatever the product
  // module turns out to be.
  std::error_code ec;
  status.rtc = RtcPresence::kUnknown;
  if (std::filesystem::exists(src.rtc_dir, ec)) {
    status.rtc = RtcPresence::kAbsent;
    for (const auto& e :
         std::filesystem::directory_iterator(src.rtc_dir, ec)) {
      status.rtc = RtcPresence::kPresent;
      auto name = e.path().filename().string();
      auto driver = ReadFile((e.path() / "name").string());
      status.rtc_name =
          driver ? std::format("{} ({})", name, Trim(*driver))
                 : name;
      break;
    }
  }

  bool has_source = false;
  for (const auto& n : cfg.ntp) {
    if (!n.upstreams.empty()) has_source = true;
  }

  if (src.fake_trust != 0) {
    switch (src.fake_trust) {
      case 1:
        status.trust = TimeTrust::kSynchronised;
        break;
      case 2:
        status.trust = TimeTrust::kNotYetSynchronised;
        break;
      case 3:
        status.trust = TimeTrust::kNoTimeSource;
        break;
      default:
        status.trust = TimeTrust::kUnknown;
        break;
    }
    if (src.fake_max_error_us >= 0) {
      status.max_error_us = src.fake_max_error_us;
    }
  } else {
    // The kernel's own answer, and the reason this needs no daemon
    // and no parsing: STA_UNSYNC is the bit a time daemon clears when
    // it has disciplined the clock, and adjtimex reports TIME_ERROR
    // while it is set.
    struct timex tx{};
    int state = ::adjtimex(&tx);
    if (state < 0) {
      status.trust = TimeTrust::kUnknown;
      status.detail =
          "adjtimex() failed; the clock's state is unknown, which is "
          "not the same as correct";
    } else {
      status.max_error_us = static_cast<std::int64_t>(tx.maxerror);
      bool unsynced = (tx.status & STA_UNSYNC) != 0;
      if (!unsynced) {
        status.trust = TimeTrust::kSynchronised;
      } else {
        status.trust = has_source ? TimeTrust::kNotYetSynchronised
                                  : TimeTrust::kNoTimeSource;
      }
    }
  }

  if (status.trust == TimeTrust::kNotYetSynchronised &&
      !has_source) {
    status.trust = TimeTrust::kNoTimeSource;
  }

  if (!src.chronyc_cmd.empty() &&
      status.trust != TimeTrust::kNoTimeSource) {
    auto [rc, out] = RunCapture(src.chronyc_cmd);
    if (rc == 0) {
      std::istringstream lines(out);
      std::string line;
      while (std::getline(lines, line)) {
        if (line.rfind("Reference ID", 0) == 0 ||
            line.rfind("Stratum", 0) == 0 ||
            line.rfind("System time", 0) == 0) {
          if (!status.reference.empty()) status.reference += "; ";
          status.reference += Trim(line);
        }
      }
    }
  }

  if (status.detail.empty()) {
    switch (status.trust) {
      case TimeTrust::kSynchronised:
        status.detail =
            "the kernel reports the clock is disciplined by a time "
            "source";
        break;
      case TimeTrust::kNotYetSynchronised:
        status.detail = std::format(
            "an upstream is configured but has not corrected the "
            "clock yet ({}s since boot)",
            status.uptime_seconds);
        break;
      case TimeTrust::kNoTimeSource:
        status.detail =
            "no NTP upstream is configured, so nothing will ever "
            "set this clock";
        break;
      case TimeTrust::kUnknown:
        break;
    }
  }
  return status;
}

auto TimeWarningBanner(const TimeStatus& status) -> std::string {
  // A warning that is always there is a warning nobody reads, so a
  // trustworthy clock produces nothing at all.
  if (status.Trustworthy()) return "";

  std::string head;
  if (status.implausible) {
    head =
        "THE CLOCK IS AT THE EPOCH. Every timestamp below is wrong, "
        "and logs written now are stamped 1970";
  } else {
    head = std::format("THE CLOCK IS {}. Timestamps below may be "
                       "wrong",
                       TimeTrustName(status.trust));
  }
  std::string tail;
  switch (status.trust) {
    case TimeTrust::kNoTimeSource:
      tail =
          "nothing is configured to set it: add an `ntp:` service "
          "with an upstream, then `apply system`";
      break;
    case TimeTrust::kNotYetSynchronised:
      tail =
          "an upstream is configured and has not converged; if this "
          "persists, check that the uplink can reach it";
      break;
    case TimeTrust::kUnknown:
      tail =
          "the state could not be read, which is not the same as "
          "correct";
      break;
    case TimeTrust::kSynchronised:
      tail = "the wall clock is implausibly early despite a "
             "synchronised kernel flag — check the RTC";
      break;
  }
  auto rtc = status.rtc == RtcPresence::kAbsent
                 ? ". This board has no RTC, so it starts from the "
                   "epoch on every boot"
                 : "";
  return std::format("{} — {}{}.\n", head, tail, rtc);
}

}  // namespace f::sysconfig
