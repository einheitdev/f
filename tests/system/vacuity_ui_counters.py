#!/usr/bin/env python3
"""Mutation testing pointed at test_ui_counters.py.

A scenario that cannot fail is worse than no scenario: it occupies the
line in the report where the evidence should be. So for each defect
this surface could plausibly have, the sweep plants it in the product,
rebuilds, and requires the scenario that exists to catch it to go RED.

The verdicts are three-valued, and the third one matters:

  discriminating  red with the defect planted, green without it.
  vacuous         green with the defect planted. Either the scenario
                  is measuring nothing, or the plant did not do what
                  it says.
  unrunnable      the question could not be put — the plant did not
                  apply, the build failed, or the scenario is red with
                  no plant at all. This is a defect in the SWEEP.

The plants are the defect classes this surface has actually shipped,
plus the ones the counters work exists to prevent:

  the page that answers "no counters" to a question it could not ask
  (which is what `/counters` did on every box ever deployed), a zone
  that vanishes from the table when its names cannot be read, an
  unreadable slot printed as 0, "not readable" collapsed into "not
  there", a TEMPLATE that renders every state as the same row while
  the view model keeps them apart, values paired with names by
  position, a dashboard badge that says the same thing whatever it
  measured, and a policy page that blanks the counts column instead of
  saying why it is blank.

Run on the target, from tests/system, as the build user (the system
scenarios invoke sudo themselves):

  ./vacuity_ui_counters.py run
  ./vacuity_ui_counters.py run --only zeros
  ./vacuity_ui_counters.py restore
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
# edit: the sweep restores bytes, not patterns.
BACKUPS = os.path.join(HERE, ".vacuity_ui_backup")


class Plant:
  """One defect, planted deliberately, that a scenario must notice."""

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
    # copy2 restores the ORIGINAL mtime, so ninja would find nothing
    # to do and the box would keep running the sabotaged binary after
    # the sweep says it restored. Stamp it now.
    os.utime(self.file(), None)
    os.remove(self.backup())


VIEWS = "adapters/ui/src/views.cc"
TABLE = "adapters/ui/templates/fw/counters_table.html.inja"

PLANTS = [
    Plant("error_is_empty",
          "a question that could not be asked is rendered as a box "
          "with no counters on it — what the removed /counters page "
          "did on every deployment",
          VIEWS,
          '    out["answered"] = false;\n'
          '    out["unavailable"] =\n'
          '        "cannot read counters from fd: " + answer.error;\n'
          "    return out;",
          '    out["answered"] = true;\n'
          '    out["empty_text"] = "no counters active";\n'
          "    return out;",
          "4"),
    Plant("zone_vanishes",
          "a zone whose names could not be read drops out of the "
          "table, so a firewall with unreadable counters looks like "
          "one with none",
          VIEWS,
          "    zones.push_back({",
          "    if (avail != ::f::CounterAvailability::kRead) continue;\n"
          "    zones.push_back({",
          "2"),
    Plant("unreadable_is_none",
          "a name table that could not be read is reported as 'this "
          "zone declares no counters'",
          VIEWS,
          "             : std::string(::f::CounterStateWord(avail))},",
          '             : std::string("no count statements")},',
          "2"),
    Plant("by_position",
          "values are paired with names by position rather than by "
          "name — the kGetRules defect, which produces plausible "
          "numbers against the wrong rules",
          VIEWS,
          '          {"name", c.value("name", std::string{})},',
          '          {"name", z["counters"][z["counters"].size() - 1 -\n'
          "                                 rows.size()]\n"
          '                       .value("name", std::string{})},',
          "1"),
    Plant("dashboard_is_a_slogan",
          "the dashboard counters row says the same thing whatever it "
          "measured — the unconditional red `maps unavailable` badge, "
          "in its new place",
          VIEWS,
          '    out["text"] = answer.ok\n'
          "                      ? std::string(kSkewText)\n"
          '                      : "cannot read counters from fd: " '
          "+ answer.error;",
          '    out["text"] = "unavailable";',
          "4"),
    Plant("policy_counts_blank",
          "the policy page blanks the counts column for a zone whose "
          "counters could not be named, instead of saying why",
          VIEWS,
          "      z[\"counts_str\"] = "
          "std::string(::f::CounterStateWord(avail));",
          '      z["counts_str"] = "";',
          "6"),
    Plant("template_flattens_states",
          "the TEMPLATE draws every kind of empty as the same row "
          "while the view model keeps them apart — the last place the "
          "four states can be lost, and the only one a view-model "
          "test cannot see",
          TABLE,
          '      <td><span class="badge badge-{{ z.state_semantic }}">'
          "{{ z.state_word }}</span></td>",
          "      <td>-</td>",
          "2"),
    Plant("attached_count_as_list",
          "the egress tracker's attach COUNT is read as a list of "
          "names, so a box with the hook on every interface is told "
          "the hook its policy needs is on none — the defect this "
          "page shipped with until deb-03 was walked",
          VIEWS,
          '  if (eg.contains("attached") && eg["attached"].is_number()'
          ") {\n"
          '    have = eg["attached"].get<std::size_t>();\n'
          "  }",
          '  have = JoinArr(eg.value("attached", json::array())).empty()'
          "\n             ? 0\n             : 1;",
          "7"),
    Plant("unreadable_renders_zero",
          "a slot the daemon could not read is printed as 0",
          VIEWS,
          '          {"value", read ? std::to_string(packets) '
          ': "unreadable"},',
          '          {"value", std::to_string(packets)},',
          "unit"),
]


def run(argv, **kw):
  return subprocess.run(argv, capture_output=True, text=True, **kw)


def build():
  r = run(["cmake", "--build", "--preset", "default"], cwd=ROOT)
  return r.returncode == 0, (r.stdout + r.stderr)[-1500:]


def run_scenario(name):
  """True when the scenario passes. Second value is its tail."""
  if name == "unit":
    ok = True
    tail = ""
    for binary in ("tests/test_ui_views", "tests/test_ui_pages"):
      r = run([os.path.join(ROOT, "build", binary)])
      ok = ok and r.returncode == 0
      tail += r.stdout[-600:]
    return ok, tail
  r = run(["sudo", sys.executable,
           os.path.join(HERE, "test_ui_counters.py"),
           "--only", name], cwd=HERE)
  return r.returncode == 0, (r.stdout + r.stderr)[-1500:]


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


def restore_and_verify(scenarios):
  """Put the tree back, rebuild, and PROVE the box is unplanted.

  Claiming a restore is not performing one, so the restore ends by
  re-running the scenarios that were green before any plant and says
  so out loud if they are not green again.
  """
  restore_all()
  built, tail = build()
  if not built:
    print("RESTORE FAILED: the tree does not build after restore")
    print(tail)
    return False
  ok = True
  for name in scenarios:
    good, tail = run_scenario(name)
    if not good:
      ok = False
      print(f"RESTORE FAILED: scenario {name} is still red after "
            f"restore — this box is running planted code")
      print(tail)
  print("restore verified" if ok else "restore NOT verified")
  return ok


def cmd_run(args):
  restore_all()
  ok, tail = build()
  if not ok:
    print("baseline build failed; nothing can be measured")
    print(tail)
    return 2

  wanted = [p for p in PLANTS
            if not args.only or p.id in args.only]
  baseline = {}
  for name in sorted({p.scenario for p in wanted}):
    good, tail = run_scenario(name)
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
        results.append(
            (p, "unrunnable",
             "build failed with the plant: " + tail[-400:]))
        continue
      good, tail = run_scenario(p.scenario)
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
    restored = restore_and_verify(sorted(baseline))

  print("\n=== vacuity sweep ===")
  worst = 0 if restored else 2
  for p, verdict, detail in results:
    print(f"{verdict:<15} {p.id:<24} {detail}")
    if verdict == "vacuous":
      worst = max(worst, 1)
    if verdict == "unrunnable":
      worst = max(worst, 2)
  counts = {}
  for _, verdict, _ in results:
    counts[verdict] = counts.get(verdict, 0) + 1
  print("  " + ", ".join(f"{v} {k}" for k, v in sorted(counts.items())))
  return worst


def cmd_restore(_args):
  return 0 if restore_and_verify(
      sorted({p.scenario for p in PLANTS})) else 2


def main():
  ap = argparse.ArgumentParser(description=__doc__)
  sub = ap.add_subparsers(dest="cmd", required=True)
  r = sub.add_parser("run")
  r.add_argument("--only", nargs="*", default=None)
  r.set_defaults(func=cmd_run)
  s = sub.add_parser("restore")
  s.set_defaults(func=cmd_restore)
  args = ap.parse_args()
  return args.func(args)


if __name__ == "__main__":
  sys.exit(main())
