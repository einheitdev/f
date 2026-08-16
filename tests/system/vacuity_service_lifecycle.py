#!/usr/bin/env python3
"""Mutation testing pointed at test_service_lifecycle.py.

A scenario that cannot fail is worse than no scenario: it occupies the
line in the report where the evidence should be. So for each defect
this reconcile could plausibly have — starting with the one it was
written to close — the sweep plants it in the product, rebuilds,
deploys the planted binary to the target, and requires the scenario
that exists to catch it to go RED.

The verdicts are three-valued, and the third one matters:

  discriminating  red with the defect planted, green without it.
  vacuous         green with the defect planted. Either the scenario
                  is measuring nothing, or the plant did not do what
                  it says — a substitution can compile and still have
                  no effect. Reported, not deleted, and investigated
                  before it is believed.
  unrunnable      the question could not be put — the plant did not
                  apply, the build failed, the deploy failed, or the
                  scenario is red with no plant at all. This is a
                  defect in the SWEEP. Folding it into pass or fail is
                  how a sweep comes to report on scenarios it never
                  ran.

The plants are the defect classes this surface has actually shipped or
could plausibly grow. The first one IS the finding: a reconcile that
works out what to run and never runs it, which is exactly what the box
did before this change, with the CLI answering `applied: yes`.

Unlike the other sweeps in this directory, this one runs on the
WORKSTATION and drives the target over ssh: the plants are in C++ and
the scenario needs a real systemd, so the build happens where the
toolchain is and the binary is shipped to where the daemons are.

  ./vacuity_service_lifecycle.py run --target 10.101.0.101
  ./vacuity_service_lifecycle.py run --target ... --only never_starts
  ./vacuity_service_lifecycle.py restore --target ...
"""
import argparse
import glob
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
# Whole-file copies of everything a plant touches, taken before the
# edit. The sweep restores BYTES, not patterns: undoing a plant by
# substituting the replacement text back out edits every line that
# happens to match, including ones no plant wrote.
BACKUPS = os.path.join(HERE, ".vacuity_lifecycle_backup")
# What the target runs. Every plant is in code linked into this one
# binary, so the deploy is a copy rather than an install.
BINARY = "einheit-f"
REMOTE_BINARY = "/usr/local/bin/einheit-f"
REMOTE_TEST = "/home/worker/f/tests/system/test_service_lifecycle.py"


class Plant:
  """One defect, planted deliberately, that a scenario must notice.

  `defect` says what is broken in the PRODUCT's terms — a plant
  described only by its diff is a plant nobody can check the relevance
  of. `scenario` names the one scenario that exists to catch it.
  """

  def __init__(self, ident, defect, path, find, replace, scenario):
    self.id = ident
    self.defect = defect
    self.path = path
    self.find = find
    self.replace = replace
    self.scenario = scenario

  def file(self):
    return os.path.join(ROOT, self.path)

  def backup(self):
    return os.path.join(BACKUPS, self.path.replace(os.sep, "__"))

  def apply(self):
    """Returns '' on success or a sentence saying why not."""
    text = open(self.file(), encoding="utf-8").read()
    n = text.count(self.find)
    if n != 1:
      return (f"the pattern matches {n} times in {self.path}; a plant "
              f"that did not land makes a green run mean nothing")
    os.makedirs(BACKUPS, exist_ok=True)
    shutil.copy2(self.file(), self.backup())
    with open(self.file(), "w", encoding="utf-8") as f:
      f.write(text.replace(self.find, self.replace))
    after = open(self.file(), encoding="utf-8").read()
    if after == text:
      return "the substitution produced identical text"
    return ""

  def undo(self):
    if not os.path.exists(self.backup()):
      return
    shutil.copy2(self.backup(), self.file())
    # copy2 restores the ORIGINAL mtime, which is older than the object
    # built from the planted source — so ninja finds nothing to do and
    # the target keeps running the sabotaged binary after the sweep
    # says it restored.
    os.utime(self.file(), None)
    os.remove(self.backup())


PLANTS = [
    Plant("never_starts",
          "the reconcile works out which command the unit needs and "
          "never runs it — the finding itself: the model is written, "
          "the reply says applied, and nothing serves",
          "src/sysconfig/service_units.cc",
          "        auto [rc, out] = opts.ops.act(verb, want.unit);",
          "        std::pair<int, std::string> rc_out{0, \"\"};\n"
          "        auto [rc, out] = rc_out;",
          "started"),
    Plant("reports_the_intent",
          "the state reported is what the model asked for rather than "
          "what systemd says afterwards — a column that agrees with "
          "the config by construction",
          "src/sysconfig/service_units.cc",
          "    o.after = Classify(after, want.wanted);",
          "    o.after = want.wanted ? ServiceState::kRunning\n"
          "                          : ServiceState::kNotConfigured;",
          "willnot"),
    Plant("trusts_the_exit_code",
          "a unit is called healthy because `systemctl` exited 0 — "
          "which it does for a unit that started, crashed and entered "
          "auto-restart",
          "src/sysconfig/service_units.cc",
          "    const auto after =\n"
          "        verb.empty() ? before : opts.ops.observe(want.unit);",
          "    const auto after = before;",
          "started"),
    Plant("always_says_started",
          "every reconcile reports STARTED, including for a unit that "
          "was already running and that nothing was run against",
          "src/sysconfig/service_units.cc",
          "          return std::format(\"{}: already running, "
          "nothing to do\",\n"
          "                             unit);",
          "          return std::format(\"{}: STARTED\", unit);",
          "already"),
    Plant("never_stops",
          "the model no longer binds the service and the unit is left "
          "running — a box still answering DHCP after `no dhcp`",
          "src/sysconfig/service_units.cc",
          "    } else if (running || before.Enabled()) {",
          "    } else if (false) {",
          "stopped"),
    Plant("stops_but_leaves_enabled",
          "the unit is stopped and left enabled, so the next reboot "
          "brings back a service the model does not bind",
          "src/sysconfig/service_units.cc",
          "      verb = {\"disable\", \"--now\"};",
          "      verb = {\"stop\"};",
          "stopped"),
    Plant("enables_without_starting",
          "the unit is enabled for the next boot and not started now, "
          "so the segment is unserved until somebody reboots",
          "src/sysconfig/service_units.cc",
          "        verb = {\"enable\", \"--now\"};",
          "        verb = {\"enable\"};",
          "started"),
    Plant("not_installed_is_failed",
          "a unit that is not installed is reported as one that "
          "failed, which sends the operator hunting for a crash that "
          "never happened",
          "src/sysconfig/service_status.cc",
          "    return expected ? ServiceState::kNotInstalled\n"
          "                    : ServiceState::kNotConfigured;",
          "    return expected ? ServiceState::kFailed\n"
          "                    : ServiceState::kNotConfigured;",
          "notinstalled"),
    Plant("swallows_the_failure",
          "the apply reports success whatever became of the unit — "
          "the configuration is on disk, nothing is serving it, and "
          "the command exits 0",
          "adapters/cli/src/transport.cc",
          "    (*out)[\"services_ok\"] = report.Ok();\n"
          "    (*out)[\"services_note\"] = report.Format();\n"
          "    return report.Ok();",
          "    (*out)[\"services_ok\"] = report.Ok();\n"
          "    (*out)[\"services_note\"] = report.Format();\n"
          "    return true;",
          "willnot"),
    Plant("never_restarts",
          "a running daemon whose configuration was just rewritten is "
          "left reading the old one",
          "src/sysconfig/service_units.cc",
          "      } else if (changed) {\n"
          "        verb = {\"restart\"};",
          "      } else if (false) {\n"
          "        verb = {\"restart\"};",
          "dns"),
    Plant("everything_is_silent",
          "every service row is marked as having nothing to say, so "
          "the observation is computed and then thrown away one layer "
          "above where the renderer would drop it",
          "src/sysconfig/service_units.cc",
          "auto UnitOutcome::Silent() const -> bool {\n"
          "  return command.empty()",
          "auto UnitOutcome::Silent() const -> bool {\n"
          "  if (true) return true;\n"
          "  return command.empty()",
          "started"),
    Plant("renderer_drops_the_row",
          "the reply carries the observation and the screen does not "
          "print it — the last place a finding can become a blank row "
          "is the renderer",
          "adapters/cli/src/adapter.cc",
          "    AddRow(*t, {Cell{\"service\", Semantic::Info},\n"
          "                Cell{s.value(\"summary\", \"\"), sem}});",
          "    (void)sem;",
          "started"),
]


def run(argv, **kw):
  return subprocess.run(argv, capture_output=True, text=True, **kw)


def build():
  r = run(["cmake", "--build", "--preset", "default"], cwd=ROOT)
  return r.returncode == 0, (r.stdout + r.stderr)[-1500:]


class Target:
  """The box the scenarios run on."""

  def __init__(self, host, user, key):
    self.host = host
    self.user = user
    self.key = os.path.expanduser(key)

  def ssh(self, command, timeout=900):
    return run(["ssh", "-i", self.key, "-o",
                "StrictHostKeyChecking=no",
                f"{self.user}@{self.host}", command], timeout=timeout)

  def deploy(self):
    """Put the freshly built binary where the scenarios call it.

    Returns '' on success or a sentence saying why not. A deploy that
    silently did nothing would make every planted run green for the
    wrong reason, so the digest is compared afterwards.
    """
    local = os.path.join(ROOT, "build", BINARY)
    r = run(["scp", "-i", self.key, "-o", "StrictHostKeyChecking=no",
             local, f"{self.user}@{self.host}:/tmp/{BINARY}.new"])
    if r.returncode != 0:
      return "scp failed: " + (r.stdout + r.stderr)[-300:]
    r = self.ssh(f"sudo install -m 0755 /tmp/{BINARY}.new "
                 f"{REMOTE_BINARY} && sha256sum {REMOTE_BINARY}")
    if r.returncode != 0:
      return "install failed: " + (r.stdout + r.stderr)[-300:]
    remote_digest = r.stdout.split()[0] if r.stdout.split() else ""
    local_digest = run(["sha256sum", local]).stdout.split()[0]
    if remote_digest != local_digest:
      return (f"the binary on the target is not the one just built "
              f"({remote_digest[:12]} vs {local_digest[:12]})")
    return ""

  def scenario(self, name):
    """True when the scenario passes. Second value is its tail."""
    r = self.ssh(f"sudo python3 {REMOTE_TEST} --only {name}")
    return r.returncode == 0, (r.stdout + r.stderr)[-1800:]

  def push_test(self):
    """Ship the scenario file itself, so the sweep runs what is here."""
    r = run(["scp", "-i", self.key, "-o", "StrictHostKeyChecking=no",
             os.path.join(HERE, "test_service_lifecycle.py"),
             f"{self.user}@{self.host}:{REMOTE_TEST}"])
    return r.returncode == 0


def restore_all():
  for p in PLANTS:
    p.undo()
  leftovers = glob.glob(os.path.join(BACKUPS, "*"))
  if leftovers:
    print(f"warning: {len(leftovers)} unclaimed backup(s) in "
          f"{BACKUPS}")
    return
  if os.path.isdir(BACKUPS):
    os.rmdir(BACKUPS)


def restore_and_verify(target, scenarios):
  """Put the tree back, rebuild, redeploy, and PROVE it is unplanted.

  Claiming a restore is not performing one. A sweep that leaves a
  sabotaged binary on the target has poisoned every run after it, so
  the restore ends by re-running the scenarios that were green before
  any plant and says so out loud if they are not green again.
  """
  restore_all()
  built, tail = build()
  if not built:
    print("RESTORE FAILED: the tree does not build after restore")
    print(tail)
    return False
  why = target.deploy()
  if why:
    print("RESTORE FAILED: the target still runs a planted binary — "
          + why)
    return False
  ok = True
  for name in scenarios:
    good, tail = target.scenario(name)
    if not good:
      ok = False
      print(f"RESTORE FAILED: scenario {name} is still red after "
            f"restore")
      print(tail)
  print("restore verified" if ok else "restore NOT verified")
  return ok


def cmd_run(args):
  target = Target(args.target, args.user, args.key)
  restore_all()
  ok, tail = build()
  if not ok:
    print("baseline build failed; nothing can be measured")
    print(tail)
    return 2
  if not target.push_test():
    print("could not ship the scenario file to the target")
    return 2
  why = target.deploy()
  if why:
    print("baseline deploy failed: " + why)
    return 2

  wanted = [p for p in PLANTS if not args.only or p.id in args.only]
  baseline = {}
  for name in sorted({p.scenario for p in wanted}):
    good, tail = target.scenario(name)
    baseline[name] = good
    print(f"baseline scenario {name}: "
          f"{'green' if good else 'RED (unrunnable)'}")
    if not good:
      print(tail)

  results = []
  try:
    for p in wanted:
      print(f"\n--- plant {p.id}: {p.defect}")
      if not baseline.get(p.scenario, False):
        results.append((p, "unrunnable", "scenario is red unplanted"))
        continue
      why = p.apply()
      if why:
        results.append((p, "unrunnable", why))
        continue
      built, tail = build()
      if not built:
        p.undo()
        results.append((p, "unrunnable",
                        "build failed with the plant: " + tail[-400:]))
        continue
      why = target.deploy()
      if why:
        p.undo()
        results.append((p, "unrunnable", "deploy failed: " + why))
        continue
      good, tail = target.scenario(p.scenario)
      p.undo()
      if good:
        results.append((p, "vacuous",
                        f"scenario {p.scenario} stayed green with "
                        f"the defect in place"))
      else:
        results.append((p, "discriminating",
                        f"scenario {p.scenario} went red"))
      print(f"    scenario {p.scenario}: "
            f"{'GREEN (vacuous)' if good else 'red (good)'}")
  finally:
    restored = restore_and_verify(target, sorted(baseline))

  print("\n=== vacuity sweep ===")
  worst = 0 if restored else 2
  for p, verdict, detail in results:
    print(f"{verdict:<15} {p.id:<26} {detail}")
    if verdict == "vacuous":
      worst = max(worst, 1)
    if verdict == "unrunnable":
      worst = max(worst, 2)
  counts = {}
  for _, verdict, _ in results:
    counts[verdict] = counts.get(verdict, 0) + 1
  print("  " + ", ".join(f"{v} {k}" for k, v in sorted(counts.items())))
  return worst


def cmd_restore(args):
  target = Target(args.target, args.user, args.key)
  return 0 if restore_and_verify(target, ["started"]) else 2


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument("--target", default="10.101.0.101",
                      help="the box the scenarios run on")
  parser.add_argument("--user", default="worker")
  parser.add_argument("--key", default="~/.ssh/id_ed25519_targets")
  sub = parser.add_subparsers(dest="cmd", required=True)
  runner = sub.add_parser("run")
  runner.add_argument("--only", action="append")
  sub.add_parser("restore")
  args = parser.parse_args()
  if args.cmd == "run":
    return cmd_run(args)
  return cmd_restore(args)


if __name__ == "__main__":
  sys.exit(main())
