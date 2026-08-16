/// @file test_sysconfig_service_units.cc
/// @brief The apply path owns service lifecycle, and says what systemd
///     says.
///
/// Every test here starts from a unit state and asserts a TRANSITION.
/// That is not a style preference: the defect this closes is a box on
/// which `set dhcp` reported success while nothing served, and a test
/// that asserts "the unit is running" against a fixture where it was
/// already running is green on that box too. So the fake systemd here
/// is a mutable table — a verb moves it, and the assertions name the
/// state before as well as the state after.
///
/// The second thing under test is that the report is an OBSERVATION.
/// `systemctl enable --now` exits 0 for a unit that started, crashed
/// and entered auto-restart. A reconciler that believed the exit code
/// would call that box healthy, so the fake can be told to fail a
/// start, or to crash-loop, while still exiting 0.

#include <gtest/gtest.h>

#include <map>
#include <string>
#include <vector>

#include "f/sysconfig/parse.h"
#include "f/sysconfig/service_units.h"

namespace {

namespace sc = f::sysconfig;

/// A model with DHCP and DNS bound to a zone that has a port in it.
/// Both halves matter: a service bound to a zone with no interface is
/// deliberately NOT wanted, and that is its own test below.
constexpr const char* kServing = R"(
zones:
  lan:
interfaces:
  lan0:
    mac: "52:54:00:aa:bb:01"
    address: 10.10.0.1/24
    zone: lan
services:
  dhcp:
    - zone: lan
      range: 10.10.0.100-10.10.0.200
)";

/// The same box with nothing bound. This is what `no dhcp` leaves
/// behind, and the unit must not go on serving.
constexpr const char* kQuiet = R"(
zones:
  lan:
interfaces:
  lan0:
    mac: "52:54:00:aa:bb:01"
    address: 10.10.0.1/24
    zone: lan
)";

auto Parse(const char* text) -> sc::SystemConfig {
  auto parsed = sc::ParseSystemConfigString(text);
  EXPECT_TRUE(parsed.has_value())
      << (parsed ? "" : parsed.error().diagnostics.front().Format());
  return parsed ? *parsed : sc::SystemConfig{};
}

/// A systemd whose unit table actually moves.
class FakeSystemd {
 public:
  struct Unit {
    std::string active = "inactive";
    std::string sub = "dead";
    std::string result = "success";
    std::string load = "loaded";
    std::string enabled = "disabled";
    int restarts = 0;
    /// What starting this unit does on this imaginary box.
    enum class OnStart { kOk, kFail, kCrashLoop } on_start =
        OnStart::kOk;
  };

  auto Install(const std::string& unit, Unit u) -> void {
    units_[unit] = std::move(u);
  }

  /// A unit nobody installed. `show` answers not-found, the way
  /// systemd does, rather than the caller having to know.
  auto Absent(const std::string& unit) -> void {
    units_.erase(unit);
  }

  auto Get(const std::string& unit) const -> Unit {
    auto it = units_.find(unit);
    if (it == units_.end()) {
      Unit u;
      u.load = "not-found";
      u.enabled = "";
      return u;
    }
    return it->second;
  }

  /// Every command that was run, in order. A test that wants to prove
  /// nothing was run reads this.
  auto Commands() const -> const std::vector<std::string>& {
    return commands_;
  }

  auto Ops() -> sc::SystemdOps {
    sc::SystemdOps ops;
    ops.observe = [this](const std::string& unit) {
      const auto u = Get(unit);
      sc::UnitObservation obs;
      obs.active_state = u.active;
      obs.sub_state = u.sub;
      obs.result = u.result;
      obs.load_state = u.load;
      obs.enabled_state = u.enabled;
      obs.restarts = u.restarts;
      return obs;
    };
    ops.act = [this](const std::vector<std::string>& verb,
                     const std::string& unit) {
      std::string line;
      for (const auto& v : verb) line += v + " ";
      commands_.push_back(line + unit);
      auto it = units_.find(unit);
      if (it == units_.end()) {
        return std::pair<int, std::string>{5, "Unit not found."};
      }
      auto& u = it->second;
      const auto& v0 = verb.front();
      const bool now =
          std::find(verb.begin(), verb.end(), "--now") != verb.end();
      if (v0 == "enable") {
        u.enabled = "enabled";
        return now ? Start(&u) : std::pair<int, std::string>{0, ""};
      }
      if (v0 == "restart") return Start(&u);
      if (v0 == "disable") {
        u.enabled = "disabled";
        if (now) {
          u.active = "inactive";
          u.sub = "dead";
        }
        return std::pair<int, std::string>{0, ""};
      }
      return std::pair<int, std::string>{1, "unknown verb"};
    };
    ops.log = [](const std::string&) {
      return std::string("dnsmasq: failed to bind listening socket");
    };
    return ops;
  }

 private:
  static auto Start(Unit* u) -> std::pair<int, std::string> {
    switch (u->on_start) {
      case Unit::OnStart::kFail:
        u->active = "failed";
        u->sub = "failed";
        u->result = "exit-code";
        return {1, "Job failed. See journalctl."};
      case Unit::OnStart::kCrashLoop:
        // The one that matters: systemctl exits 0 and the unit is
        // already on its way back down.
        u->active = "activating";
        u->sub = "auto-restart";
        u->result = "exit-code";
        u->restarts += 1;
        return {0, ""};
      case Unit::OnStart::kOk:
        break;
    }
    u->active = "active";
    u->sub = "running";
    u->result = "success";
    return {0, ""};
  }

  std::map<std::string, Unit> units_;
  std::vector<std::string> commands_;
};

auto FindUnit(const sc::ReconcileReport& r, const std::string& unit)
    -> const sc::UnitOutcome* {
  for (const auto& u : r.units) {
    if (u.unit == unit) return &u;
  }
  return nullptr;
}

// -- the derivation ----------------------------------------------------

TEST(PlanServiceUnits, ABoundServiceWantsItsUnit) {
  auto plan = sc::PlanServiceUnits(Parse(kServing));
  const auto* dm = &plan[0];
  ASSERT_EQ(dm->unit, "f-dnsmasq.service");
  EXPECT_TRUE(dm->wanted);
  EXPECT_EQ(dm->zones, std::vector<std::string>{"lan"});
  EXPECT_EQ(dm->interfaces, std::vector<std::string>{"lan0"});
}

TEST(PlanServiceUnits, NothingBoundWantsNoUnit) {
  auto plan = sc::PlanServiceUnits(Parse(kQuiet));
  for (const auto& u : plan) EXPECT_FALSE(u.wanted) << u.unit;
}

// A DHCP server bound to a zone with no port in it has nowhere to
// answer. dnsmasq started for it binds loopback and serves nobody,
// which is the "running and answering nobody" state `show services`
// exists to name — so it is not wanted, and the reconcile must not
// start it. The judgement is PlanDnsmasq's and is deliberately shared
// rather than re-made here.
TEST(PlanServiceUnits, AServiceBoundToAZoneWithNoPortIsNotWanted) {
  auto plan = sc::PlanServiceUnits(Parse(R"(
zones:
  lan:
services:
  dhcp:
    - zone: lan
      range: 10.10.0.100-10.10.0.200
)"));
  EXPECT_FALSE(plan[0].wanted);
}

// The screen an operator checks afterwards and the thing that acted
// must not be able to disagree about whether a unit should be running.
// They share this derivation; if that ever stops being true, this
// fails.
TEST(PlanServiceUnits, ShowServicesAgreesAboutWhatIsExpected) {
  for (const char* doc : {kServing, kQuiet}) {
    const auto cfg = Parse(doc);
    const auto plan = sc::PlanServiceUnits(cfg);
    // A probe that answers nothing: only the `expected` flag is under
    // test here, and it comes from the model, not from systemd.
    sc::ServiceProbe probe;
    probe.is_active_cmd = "true";
    probe.restarts_cmd = "true";
    probe.result_cmd = "true";
    probe.load_state_cmd = "true";
    probe.log_cmd = "true";
    probe.main_pid_cmd = "true";
    const auto shown = sc::QueryServices(cfg, probe);
    ASSERT_EQ(shown.size(), plan.size());
    for (std::size_t i = 0; i < plan.size(); ++i) {
      EXPECT_EQ(shown[i].unit, plan[i].unit);
      EXPECT_EQ(shown[i].expected, plan[i].wanted) << plan[i].unit;
    }
  }
}

// -- the transition ----------------------------------------------------

// The whole finding: a service bound through the CLI was started by
// nobody. It is started here, and the evidence is that it was STOPPED
// first — a test that could not tell those apart would pass on the
// broken box too.
TEST(ReconcileServices, ABoundServiceIsStartedFromStopped) {
  FakeSystemd box;
  box.Install("f-dnsmasq.service", {});
  ASSERT_EQ(box.Get("f-dnsmasq.service").active, "inactive");

  sc::ReconcileOptions opts;
  opts.ops = box.Ops();
  auto report = sc::ReconcileServices(Parse(kServing), opts);

  const auto* dm = FindUnit(report, "f-dnsmasq.service");
  ASSERT_NE(dm, nullptr);
  EXPECT_EQ(dm->before, sc::ServiceState::kStopped);
  EXPECT_EQ(dm->action, sc::UnitAction::kStarted);
  EXPECT_EQ(dm->after, sc::ServiceState::kRunning);
  EXPECT_TRUE(dm->Ok());
  EXPECT_TRUE(report.Ok());
  // Enabled as well as started: a unit that is running and not enabled
  // does not survive the reboot, and "the model says this runs" has to
  // mean both.
  EXPECT_EQ(box.Get("f-dnsmasq.service").enabled, "enabled");
  EXPECT_EQ(box.Get("f-dnsmasq.service").active, "active");
  EXPECT_NE(dm->Summary().find("STARTED"), std::string::npos)
      << dm->Summary();
}

// The vacuity guard, stated as a test: a unit that was already running
// must NOT be reported as started, and no command is run for it.
TEST(ReconcileServices, AlreadyRunningIsNotReportedAsStarted) {
  FakeSystemd box;
  FakeSystemd::Unit up;
  up.active = "active";
  up.sub = "running";
  up.enabled = "enabled";
  box.Install("f-dnsmasq.service", up);

  sc::ReconcileOptions opts;
  opts.ops = box.Ops();
  auto report = sc::ReconcileServices(Parse(kServing), opts);

  const auto* dm = FindUnit(report, "f-dnsmasq.service");
  ASSERT_NE(dm, nullptr);
  EXPECT_EQ(dm->before, sc::ServiceState::kRunning);
  EXPECT_EQ(dm->action, sc::UnitAction::kNone);
  EXPECT_EQ(dm->after, sc::ServiceState::kRunning);
  EXPECT_TRUE(dm->Ok());
  EXPECT_TRUE(box.Commands().empty());
  EXPECT_EQ(dm->Summary().find("STARTED"), std::string::npos)
      << dm->Summary();
  EXPECT_NE(dm->Summary().find("already running"), std::string::npos)
      << dm->Summary();
}

TEST(ReconcileServices, ARunningButNotEnabledUnitIsEnabled) {
  FakeSystemd box;
  FakeSystemd::Unit up;
  up.active = "active";
  up.sub = "running";
  up.enabled = "disabled";
  box.Install("f-dnsmasq.service", up);

  sc::ReconcileOptions opts;
  opts.ops = box.Ops();
  auto report = sc::ReconcileServices(Parse(kServing), opts);

  const auto* dm = FindUnit(report, "f-dnsmasq.service");
  ASSERT_NE(dm, nullptr);
  EXPECT_EQ(dm->action, sc::UnitAction::kEnabledOnly);
  EXPECT_EQ(box.Get("f-dnsmasq.service").enabled, "enabled");
  // It was not restarted: the configuration did not change under it.
  EXPECT_EQ(box.Commands().size(), 1u);
  EXPECT_EQ(box.Commands()[0], "enable f-dnsmasq.service");
}

TEST(ReconcileServices, ARunningUnitIsRestartedWhenItsConfigChanged) {
  FakeSystemd box;
  FakeSystemd::Unit up;
  up.active = "active";
  up.sub = "running";
  up.enabled = "enabled";
  box.Install("f-dnsmasq.service", up);

  sc::ReconcileOptions opts;
  opts.ops = box.Ops();
  opts.config_changed = {"f-dnsmasq.service"};
  auto report = sc::ReconcileServices(Parse(kServing), opts);

  const auto* dm = FindUnit(report, "f-dnsmasq.service");
  ASSERT_NE(dm, nullptr);
  EXPECT_EQ(dm->action, sc::UnitAction::kRestarted);
  EXPECT_EQ(dm->after, sc::ServiceState::kRunning);
  ASSERT_EQ(box.Commands().size(), 1u);
  EXPECT_EQ(box.Commands()[0], "restart f-dnsmasq.service");
}

// `no dhcp` on the last binding. A box that goes on answering DHCP
// after being told to stop is the same defect as one that never
// starts, pointed the other way — so the unit is stopped AND disabled.
TEST(ReconcileServices, AnUnboundServiceIsStoppedAndDisabled) {
  FakeSystemd box;
  FakeSystemd::Unit up;
  up.active = "active";
  up.sub = "running";
  up.enabled = "enabled";
  box.Install("f-dnsmasq.service", up);

  sc::ReconcileOptions opts;
  opts.ops = box.Ops();
  auto report = sc::ReconcileServices(Parse(kQuiet), opts);

  const auto* dm = FindUnit(report, "f-dnsmasq.service");
  ASSERT_NE(dm, nullptr);
  EXPECT_EQ(dm->before, sc::ServiceState::kUnexpected);
  EXPECT_EQ(dm->action, sc::UnitAction::kStopped);
  EXPECT_EQ(dm->after, sc::ServiceState::kNotConfigured);
  EXPECT_TRUE(dm->Ok());
  EXPECT_EQ(box.Get("f-dnsmasq.service").active, "inactive");
  EXPECT_EQ(box.Get("f-dnsmasq.service").enabled, "disabled");
}

// -- the failures, which must be visible -------------------------------

TEST(ReconcileServices, AUnitThatWillNotStartFailsTheReconcile) {
  FakeSystemd box;
  FakeSystemd::Unit u;
  u.on_start = FakeSystemd::Unit::OnStart::kFail;
  box.Install("f-dnsmasq.service", u);

  sc::ReconcileOptions opts;
  opts.ops = box.Ops();
  auto report = sc::ReconcileServices(Parse(kServing), opts);

  const auto* dm = FindUnit(report, "f-dnsmasq.service");
  ASSERT_NE(dm, nullptr);
  EXPECT_EQ(dm->before, sc::ServiceState::kStopped);
  EXPECT_EQ(dm->after, sc::ServiceState::kFailed);
  EXPECT_FALSE(dm->Ok());
  EXPECT_FALSE(report.Ok());
  // systemd's own reason travels with it, not a generic sentence.
  EXPECT_NE(report.FailureDetail().find("f-dnsmasq.service"),
            std::string::npos);
  EXPECT_NE(report.FailureDetail().find("FAILED"), std::string::npos)
      << report.FailureDetail();
}

// The one the exit code cannot see. `systemctl enable --now` returns 0
// and the unit is already in auto-restart. A reconciler that trusted
// the return value reports this box as serving DHCP.
TEST(ReconcileServices, ACrashLoopIsNotASuccessfulStart) {
  FakeSystemd box;
  FakeSystemd::Unit u;
  u.on_start = FakeSystemd::Unit::OnStart::kCrashLoop;
  box.Install("f-dnsmasq.service", u);

  sc::ReconcileOptions opts;
  opts.ops = box.Ops();
  auto report = sc::ReconcileServices(Parse(kServing), opts);

  const auto* dm = FindUnit(report, "f-dnsmasq.service");
  ASSERT_NE(dm, nullptr);
  EXPECT_EQ(dm->after, sc::ServiceState::kRestarting);
  EXPECT_FALSE(dm->Ok());
  EXPECT_FALSE(report.Ok());
  // And it is not rendered as progress: "starting" would send the
  // operator away to wait for something that is never coming.
  EXPECT_EQ(dm->Summary().find("starting"), std::string::npos)
      << dm->Summary();
}

// A missing unit file is not a unit that failed, and nothing is run
// for it: systemd answers `not-found` and an operator sent hunting for
// a crash that never happened has been told the wrong thing.
TEST(ReconcileServices, AnUninstalledUnitIsNamedAndNothingIsRun) {
  FakeSystemd box;
  box.Absent("f-dnsmasq.service");

  sc::ReconcileOptions opts;
  opts.ops = box.Ops();
  auto report = sc::ReconcileServices(Parse(kServing), opts);

  const auto* dm = FindUnit(report, "f-dnsmasq.service");
  ASSERT_NE(dm, nullptr);
  EXPECT_EQ(dm->action, sc::UnitAction::kRefused);
  EXPECT_EQ(dm->after, sc::ServiceState::kNotInstalled);
  EXPECT_FALSE(dm->Ok());
  EXPECT_TRUE(box.Commands().empty());
  EXPECT_NE(dm->Summary().find("NOT INSTALLED"), std::string::npos)
      << dm->Summary();
  // The four bad endings differ. A screen that renders "not installed"
  // and "failed to start" identically is the blank-row defect again.
  FakeSystemd broken;
  FakeSystemd::Unit u;
  u.on_start = FakeSystemd::Unit::OnStart::kFail;
  broken.Install("f-dnsmasq.service", u);
  sc::ReconcileOptions bopts;
  bopts.ops = broken.Ops();
  auto other = sc::ReconcileServices(Parse(kServing), bopts);
  EXPECT_NE(FindUnit(other, "f-dnsmasq.service")->Summary(),
            dm->Summary());
}

TEST(ReconcileServices, ASystemdThatCannotBeAskedIsNotHealthy) {
  sc::ReconcileOptions opts;
  opts.ops.observe = [](const std::string&) {
    sc::UnitObservation obs;
    obs.unreachable = true;
    return obs;
  };
  auto report = sc::ReconcileServices(Parse(kServing), opts);

  const auto* dm = FindUnit(report, "f-dnsmasq.service");
  ASSERT_NE(dm, nullptr);
  EXPECT_EQ(dm->after, sc::ServiceState::kUnknown);
  EXPECT_FALSE(dm->Ok());
  EXPECT_NE(dm->Summary().find("UNKNOWN"), std::string::npos)
      << dm->Summary();
}

// A caller that may not act must not produce a report that reads as
// though it tried. It names the command the box still needs.
TEST(ReconcileServices, AReadOnlyCallerNamesTheCommandItDidNotRun) {
  FakeSystemd box;
  box.Install("f-dnsmasq.service", {});

  sc::ReconcileOptions opts;
  opts.ops = box.Ops();
  opts.ops.act = nullptr;
  auto report = sc::ReconcileServices(Parse(kServing), opts);

  const auto* dm = FindUnit(report, "f-dnsmasq.service");
  ASSERT_NE(dm, nullptr);
  EXPECT_EQ(dm->action, sc::UnitAction::kRefused);
  EXPECT_EQ(dm->after, sc::ServiceState::kStopped);
  EXPECT_FALSE(dm->Ok());
  EXPECT_EQ(dm->command, "systemctl enable --now f-dnsmasq.service");
  EXPECT_NE(dm->Summary().find("nothing was run"), std::string::npos)
      << dm->Summary();
  EXPECT_TRUE(box.Commands().empty());
}

// -- what the report keeps quiet about ---------------------------------

TEST(ReconcileServices, AUnitNobodyWantsAndNobodyRunsIsSilent) {
  FakeSystemd box;
  box.Install("f-dnsmasq.service", {});
  box.Install("f-chrony.service", {});

  sc::ReconcileOptions opts;
  opts.ops = box.Ops();
  auto report = sc::ReconcileServices(Parse(kQuiet), opts);

  EXPECT_TRUE(report.Ok());
  EXPECT_EQ(report.Format(), "");
  EXPECT_TRUE(box.Commands().empty());
}

// f-chrony is a service like any other and is reconciled by the same
// pass. Binding NTP starts it; nothing else on the box does.
TEST(ReconcileServices, NtpGetsTheSameTreatmentAsDhcp) {
  FakeSystemd box;
  box.Install("f-chrony.service", {});
  box.Install("f-dnsmasq.service", {});

  sc::ReconcileOptions opts;
  opts.ops = box.Ops();
  auto report = sc::ReconcileServices(Parse(R"(
zones:
  lan:
interfaces:
  lan0:
    mac: "52:54:00:aa:bb:01"
    address: 10.10.0.1/24
    zone: lan
services:
  ntp:
    - zone: lan
      upstream: [pool.ntp.org]
)"), opts);

  const auto* ch = FindUnit(report, "f-chrony.service");
  ASSERT_NE(ch, nullptr);
  EXPECT_EQ(ch->before, sc::ServiceState::kStopped);
  EXPECT_EQ(ch->action, sc::UnitAction::kStarted);
  EXPECT_EQ(ch->after, sc::ServiceState::kRunning);
  // And dnsmasq, which nothing binds, was left alone.
  const auto* dm = FindUnit(report, "f-dnsmasq.service");
  ASSERT_NE(dm, nullptr);
  EXPECT_EQ(dm->action, sc::UnitAction::kNone);
  EXPECT_EQ(box.Get("f-dnsmasq.service").active, "inactive");
}

// -- observing a transition somebody else performed --------------------
//
// On an appliance with `f-confd` running it is f-confd that acts, and
// the CLI only observes. If the CLI read `before` at the moment it
// looks, `before` would already be the `after`, and a unit f-confd had
// just started would be reported "already running" — a description of
// the observer's inaction rather than of the operator's change.

TEST(ObserveServiceStates, SnapshotsEveryUnitTheModelImplies) {
  FakeSystemd box;
  box.Install("f-dnsmasq.service", {});
  const auto states =
      sc::ObserveServiceStates(Parse(kServing), box.Ops());
  ASSERT_TRUE(states.count("f-dnsmasq.service"));
  EXPECT_EQ(states.at("f-dnsmasq.service"), sc::ServiceState::kStopped);
  // Not installed on this fake, and that is a state, not an omission.
  ASSERT_TRUE(states.count("f-chrony.service"));
}

TEST(ReconcileServices, AnObserverNamesTheTransitionItDidNotPerform) {
  FakeSystemd box;
  box.Install("f-dnsmasq.service", {});
  const auto cfg = Parse(kServing);
  const auto before = sc::ObserveServiceStates(cfg, box.Ops());

  // Somebody else — f-confd, on a real box — applies and starts it.
  box.Ops().act({"enable", "--now"}, "f-dnsmasq.service");
  ASSERT_EQ(box.Get("f-dnsmasq.service").active, "active");

  sc::ReconcileOptions opts;
  opts.ops = box.Ops();
  opts.ops.act = nullptr;
  opts.before = before;
  auto report = sc::ReconcileServices(cfg, opts);

  const auto* dm = FindUnit(report, "f-dnsmasq.service");
  ASSERT_NE(dm, nullptr);
  EXPECT_EQ(dm->before, sc::ServiceState::kStopped);
  EXPECT_EQ(dm->after, sc::ServiceState::kRunning);
  EXPECT_EQ(dm->action, sc::UnitAction::kNone);
  EXPECT_TRUE(dm->Ok());
  EXPECT_NE(dm->Summary().find("now RUNNING"), std::string::npos)
      << dm->Summary();
  EXPECT_EQ(dm->Summary().find("already running"), std::string::npos)
      << dm->Summary();
  // And it does not claim to have started it either — it did not.
  EXPECT_EQ(dm->Summary().find("STARTED"), std::string::npos)
      << dm->Summary();
}

// The other half: no snapshot, so the observer says only what it can
// see, and does not invent a transition.
TEST(ReconcileServices, WithNoSnapshotItClaimsNoTransition) {
  FakeSystemd box;
  FakeSystemd::Unit up;
  up.active = "active";
  up.sub = "running";
  up.enabled = "enabled";
  box.Install("f-dnsmasq.service", up);

  sc::ReconcileOptions opts;
  opts.ops = box.Ops();
  auto report = sc::ReconcileServices(Parse(kServing), opts);
  const auto* dm = FindUnit(report, "f-dnsmasq.service");
  ASSERT_NE(dm, nullptr);
  EXPECT_NE(dm->Summary().find("already running"), std::string::npos)
      << dm->Summary();
  EXPECT_EQ(dm->Summary().find("now RUNNING"), std::string::npos)
      << dm->Summary();
}

}  // namespace
