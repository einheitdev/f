#!/usr/bin/env python3
"""Mutation testing pointed at test_loaded_rules.py.

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

The plants are this surface's own defect classes, and the first one is
the whole reason the work was done the way it was:

  a reader that re-derives the rules from the bundle directory instead
  of using what was captured at load (green on any box where the file
  and the packet path agree, wrong on every box where they do not),
  a drift check that answers "match" when it could not compare, a
  drift check that never fires, a bundle with no rule metadata rendered
  as a policy with no rules, "written as a function" collapsed into
  "no rules", an unguarded rule and an unrenderable guard drawn the
  same way, a compiler that emits the action and drops its target, a
  fall-through default reported as nothing at all, a daemon that
  answers the rule query with an empty list instead of an error, and a
  TEMPLATE that renders every zone state as the same block while the
  view model keeps them apart.

Run on the target, from tests/system, as the build user (the system
scenarios invoke sudo themselves):

  ./vacuity_loaded_rules.py run
  ./vacuity_loaded_rules.py run --only from_disk
  ./vacuity_loaded_rules.py restore
"""
import argparse
import glob
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
BACKUPS = os.path.join(HERE, ".vacuity_rules_backup")


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
    if open(self.file(), encoding="utf-8").read() == text:
      return "the substitution produced identical text"
    return ""

  def undo(self):
    if not os.path.exists(self.backup()):
      return
    shutil.copy2(self.backup(), self.file())
    # copy2 restores the ORIGINAL mtime, so ninja would find nothing
    # to do and the box would keep running the sabotaged binary after
    # the sweep says it restored (BUGLOG #64). Stamp it now.
    os.utime(self.file(), None)
    os.remove(self.backup())


LOADER = "src/bpf_loader.cc"
RULES = "src/rules.cc"
VIEWS = "adapters/ui/src/views.cc"
TRANSPORT = "adapters/cli/src/transport.cc"
ADAPTER = "adapters/cli/src/adapter.cc"
EMITTER = "fwl/fwl/rulemeta.py"
TEMPLATE = "adapters/ui/templates/fw/policy_rules.html.inja"

PLANTS = [
    # --- the one the whole design exists to prevent ------------------
    Plant("from_disk",
          "the rules are re-read from the bundle directory at answer "
          "time instead of being used as captured at load — green on "
          "any box where the file and the packet path agree, and "
          "wrong on every box where they do not",
          "src/engine.cc",
          "      for (const auto& p : e.zone_bundle.programs) {\n"
          "        zones.push_back(p.rules);\n"
          "      }",
          "      for (const auto& p : e.zone_bundle.programs) {\n"
          "        nlohmann::json mf;\n"
          "        std::ifstream in(\n"
          "            std::filesystem::path(e.watcher.compiled_dir)\n"
          "                .parent_path() / \"fdroot\" / \"current\" /\n"
          "            \"manifest.json\");\n"
          "        if (in) { try { in >> mf; } catch (...) {} }\n"
          "        ZoneRules zr = p.rules;\n"
          "        for (const auto& e2 :\n"
          "             mf.value(\"programs\", nlohmann::json::array())) {\n"
          "          if (e2.value(\"zone\", std::string{}) == p.zone) {\n"
          "            zr = ParseRuleTable(e2, p.zone);\n"
          "          }\n"
          "        }\n"
          "        zones.push_back(zr);\n"
          "      }",
          "8"),
    # --- the drift verdict -------------------------------------------
    Plant("cannot_tell_is_match",
          "a comparison that could not be made is reported as a "
          "match, so a box nobody could check reads as a box that "
          "checks out",
          RULES,
          "  if (!loaded.known) {\n"
          "    out.verdict = SourceDrift::kCannotTell;",
          "  if (!loaded.known) {\n"
          "    out.verdict = SourceDrift::kMatch;",
          "5"),
    Plant("drift_never_fires",
          "the drift check always reports a match, so an edited and "
          "never-applied policy is indistinguishable from a live one",
          RULES,
          "  if (*disk_sha256 == loaded.sha256) {",
          "  if (true) {",
          "2"),
    Plant("unreadable_is_match",
          "a source file that could not be read is reported as "
          "matching rather than as a comparison nobody made",
          RULES,
          "  if (!disk_sha256.has_value()) {\n"
          "    out.verdict = SourceDrift::kCannotTell;",
          "  if (!disk_sha256.has_value()) {\n"
          "    out.verdict = SourceDrift::kMatch;",
          "2"),
    # --- the availability states -------------------------------------
    Plant("old_bundle_is_empty",
          "a bundle compiled before rule metadata existed is reported "
          "as a policy with no rules — which shows a working firewall "
          "as an empty one on every box upgraded across this change",
          RULES,
          "    out.availability = RuleAvailability::kNotEmitted;\n"
          "    out.detail =",
          "    out.availability = RuleAvailability::kNoneDeclared;\n"
          "    out.detail =",
          "5"),
    Plant("function_is_empty",
          "a Tier 2 zone, whose policy is a statement tree with no "
          "rule list, is reported as a zone with no rules",
          RULES,
          "  if (form == \"function\") {\n"
          "    out.availability = RuleAvailability::kFunctionForm;",
          "  if (form == \"function\") {\n"
          "    out.availability = RuleAvailability::kNoneDeclared;",
          "5"),
    Plant("one_state_word",
          "every rule state gets the same sentence, so five findings "
          "about a firewall render as one",
          RULES,
          "    case RuleAvailability::kNoneDeclared:\n"
          "      return \"no rules — only a default action\";",
          "    case RuleAvailability::kNoneDeclared:\n"
          "      return \"rules unknown — this bundle carries none\";",
          "5"),
    # --- the compiler ------------------------------------------------
    Plant("action_loses_target",
          "the compiler emits the verb and drops its target, so a "
          "`redirect to wan` and a `redirect to dmz` are the same row "
          "and a dnat's destination is invisible",
          EMITTER,
          "  action = rule.action\n"
          "  if action is ast.Action.COUNT and rule.counter_name:",
          "  action = rule.action\n"
          "  return action.value\n"
          "  if action is ast.Action.COUNT and rule.counter_name:",
          "1"),
    Plant("no_fall_through",
          "a zone with no `default` line is reported as having no "
          "default, when what it actually does is ALLOW everything "
          "that reaches the end of the block",
          EMITTER,
          "    default = {\n"
          "      \"action\": \"allow\",\n"
          "      \"line\": 0,\n"
          "      \"explicit\": False,\n"
          "    }",
          "    default = None",
          "1"),
    Plant("digest_of_nothing",
          "the compiler records a constant digest, so every file on "
          "disk compares equal to every policy ever compiled",
          EMITTER,
          "  digest = hashlib.sha256(text.encode(\"utf-8\")).hexdigest()",
          "  digest = hashlib.sha256(b\"\").hexdigest()",
          "2"),
    # --- the daemon --------------------------------------------------
    Plant("error_is_empty",
          "a daemon that cannot be asked answers with an empty rule "
          "list instead of an error — what the removed /counters page "
          "did on every deployment",
          VIEWS,
          "  if (!answer.ok) {\n"
          "    out[\"answered\"] = false;\n"
          "    out[\"unavailable\"] =\n"
          "        \"cannot read the loaded policy's rules from fd: \" +\n"
          "        answer.error;\n"
          "    return out;\n"
          "  }",
          "  if (!answer.ok) {\n"
          "    out[\"answered\"] = true;\n"
          "    out[\"empty_text\"] = \"no rules loaded\";\n"
          "    return out;\n"
          "  }",
          "6"),
    Plant("cli_error_is_empty",
          "the CLI reports a daemon it could not reach as a policy "
          "with no rules, and its drift verdict stops being three-"
          "valued",
          TRANSPORT,
          "    if (!out[\"answered\"].get<bool>()) {\n"
          "      // fd could not be asked at all, so there is nothing to "
          "compare",
          "    if (false) {\n"
          "      // fd could not be asked at all, so there is nothing to "
          "compare",
          "6"),
    # --- the renderers -----------------------------------------------
    Plant("unguarded_is_blank",
          "a rule that matches every packet is drawn with an empty "
          "match cell, which is also how a guard nobody could render "
          "would look",
          VIEWS,
          "        match = ::f::UnguardedMatchWord(r.terminal);",
          "        match = \"\";",
          "4"),
    Plant("cli_pairs_by_position",
          "the CLI numbers the loaded rules with the SOURCE positions "
          "`no rule` takes, so deleting rule 2 deletes a statement "
          "nobody was looking at",
          ADAPTER,
          "          row(\"loaded\", zone, \"\", r.value(\"text\", \"\"),",
          "          row(\"loaded\", zone,\n"
          "              std::to_string(r.value(\"log_rule_index\", 0)),\n"
          "              r.value(\"text\", \"\"),",
          "1"),
    Plant("live_fragment_dropped",
          "the rules live fragment is published in a shape the "
          "template cannot render, so the page loads correctly once "
          "and never updates again — this one was real, and the "
          "sweep is what it cost to find",
          "adapters/ui/src/ui_adapter.cc",
          "        Push(events, \"fw.rules\", json{{\"rules\",\n"
          "                                       PolicyRulesView(rules)}});",
          "        Push(events, \"fw.rules\", PolicyRulesView(rules));",
          "4"),
    Plant("template_flattens_states",
          "the TEMPLATE draws every zone state as the same block while "
          "the view model keeps them apart — the last place five "
          "findings can become one blank screen",
          TEMPLATE,
          "{{ z.state_word }}",
          "loaded",
          "5"),
]


def run(argv, **kw):
  return subprocess.run(argv, capture_output=True, text=True, **kw)


def build():
  r = run(["cmake", "--build", "build", "-j4"], cwd=ROOT)
  return r.returncode == 0, (r.stdout + r.stderr)[-1500:]


def run_scenario(name):
  """True when the scenario passes. Second value is its tail."""
  if name == "unit":
    ok = True
    tail = ""
    for binary in ("tests/test_rules", "tests/test_ui_views",
                   "tests/test_ui_pages"):
      r = run([os.path.join(ROOT, "build", binary)])
      ok = ok and r.returncode == 0
      tail += r.stdout[-600:]
    return ok, tail
  r = run(["sudo", sys.executable,
           os.path.join(HERE, "test_loaded_rules.py"),
           "--only", name], cwd=HERE)
  return r.returncode == 0, (r.stdout + r.stderr)[-2000:]


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

  wanted = [p for p in PLANTS if not args.only or p.id in args.only]
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
