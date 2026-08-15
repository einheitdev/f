#!/usr/bin/env python3
"""Mutation testing pointed at test_named_counters.py.

A scenario that cannot fail is worse than no scenario: it occupies the
line in the report where the evidence should be. So for each defect
this reader could plausibly have, the sweep plants it in the product,
rebuilds, and requires the scenario that exists to catch it to go RED.

The verdicts are three-valued, and the third one matters:

  discriminating  red with the defect planted, green without it.
  vacuous         green with the defect planted. Either the scenario
                  is measuring nothing, or the plant did not do what
                  it says — a substitution can compile and still have
                  no effect. Reported, not deleted, and investigated
                  before it is believed: the first vacuous verdict
                  this sweep produced was a plant that captured state
                  a line too late.
  unrunnable      the question could not be put — the plant did not
                  apply, the build failed, or the scenario is red
                  with no plant at all. This is a defect in the SWEEP.
                  Folding it into pass or fail is how a sweep comes to
                  report on scenarios it never ran.

The plants are the defect classes this project has actually shipped:
a reader that answers zero to everything, one that answers nothing,
one that pairs values with names by position, one that collapses "not
readable" into "not there", and a map bound taken from a literal
instead of from the map.

Run on the target, from tests/system, as the build user (the system
scenarios invoke sudo themselves):

  ./vacuity_named_counters.py run
  ./vacuity_named_counters.py run --only zeros
  ./vacuity_named_counters.py restore
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
# edit. The first version of this sweep undid its plants by
# substituting the replacement text back out, and one replacement —
# `z.availability = CounterAvailability::kNoneDeclared;` — occurs in
# the untouched source as well, so the undo edited a line no plant had
# written and left the product broken. Every baseline after that was
# red for a reason that had nothing to do with the product, and a red
# baseline turns every planted run into `unrunnable`. The sweep now
# restores bytes, not patterns.
BACKUPS = os.path.join(HERE, ".vacuity_counters_backup")


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
    # A plant that does not change the file is not a plant.
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
    # the box keeps running the sabotaged binary after the sweep says
    # it restored. The sweep left deb-03 in that state once; the whole
    # point of a restore step is that it is believable without
    # checking. Stamp it now so the rebuild is unavoidable.
    os.utime(self.file(), None)
    os.remove(self.backup())


PLANTS = [
    Plant("zeros",
          "the reader answers 0 for every counter, whatever the "
          "datapath counted",
          "src/counters.cc",
          "      r.packets = *v;",
          "      r.packets = 0;",
          "1"),
    Plant("nothing",
          "the reader answers 'this zone declares no counters' for "
          "every zone — what the removed v0.1 page printed on a box "
          "whose counters were moving",
          "src/counters.cc",
          "  if (table.slots.empty()) {",
          "  if (true) {",
          "1"),
    Plant("by_position",
          "values are paired with names by position rather than by "
          "name — the kGetRules defect, which produces plausible "
          "numbers against the wrong rules",
          "src/counters.cc",
          "    r.name = s.name;",
          "    r.name = table.slots[table.slots.size() - 1 -\n"
          "                         z.counters.size()].name;",
          "1"),
    Plant("unreadable_is_none",
          "a name table that could not be read is reported as 'this "
          "zone declares no counters'",
          "src/counters.cc",
          "    z.availability = CounterAvailability::kTableUnreadable;",
          "    z.availability = CounterAvailability::kNoneDeclared;",
          "3"),
    Plant("literal_bound",
          "the counter map's size is a literal instead of read from "
          "the map — the 256-against-10000 defect",
          "src/bpf_loader.cc",
          "  slots_ = info.max_entries;",
          "  slots_ = 256;",
          "4"),
    Plant("stale_names_across_reload",
          "a reload keeps the previous policy's counter names and "
          "hangs them on the new policy's map — a name from a policy "
          "that is no longer in the packet path, beside numbers from "
          "one that is",
          "src/reload.cc",
          # Anchored on the line BEFORE the assignment, because
          # CloseZoneBundle clears `programs` — a capture taken after
          # it copies an empty vector and plants nothing at all. The
          # first version of this plant did exactly that and the sweep
          # reported the scenario `vacuous`, which is why a vacuous
          # verdict is a thing to investigate rather than a thing to
          # act on: the fault was in the plant.
          "    CloseZoneBundle(e.zone_bundle);\n"
          "    e.zone_bundle = *loaded;",
          "    auto stale_names = e.zone_bundle.programs;\n"
          "    CloseZoneBundle(e.zone_bundle);\n"
          "    e.zone_bundle = *loaded;\n"
          "    for (std::size_t i = 0;\n"
          "         i < e.zone_bundle.programs.size() &&\n"
          "         i < stale_names.size(); i++) {\n"
          "      e.zone_bundle.programs[i].counters =\n"
          "          stale_names[i].counters;\n"
          "    }",
          "6"),
    Plant("unreadable_renders_zero",
          "the CLI prints a slot it could not read as 0",
          "adapters/cli/src/adapter.cc",
          "          read ? Cell{std::to_string(packets),\n"
          "                      packets > 0 ? Semantic::Good "
          ": Semantic::Dim}\n"
          "               : Cell{\"unreadable\", Semantic::Bad},",
          "          Cell{std::to_string(packets),\n"
          "               read && packets > 0 ? Semantic::Good\n"
          "                                   : Semantic::Dim},",
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
    for binary in ("tests/test_counters", "tests/test_fw_counters"):
      r = run([os.path.join(ROOT, "build", binary)])
      ok = ok and r.returncode == 0
      tail += r.stdout[-600:]
    return ok, tail
  r = run(["sudo", sys.executable,
           os.path.join(HERE, "test_named_counters.py"),
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

  Claiming a restore is not performing one. This sweep once said it
  had restored while the box still ran a sabotaged `fd`, because the
  files were back and the binaries were not — so the restore ends by
  re-running the same scenarios that were green before any plant, and
  says so out loud if they are not green again.
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
  # Baseline once per scenario the plants use. A scenario that is red
  # with nothing planted makes every planted red meaningless.
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
