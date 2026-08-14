"""Machinery for the vacuity sweep: plants, witnesses, verdict history.

The sweep asks one question of every hardware scenario: if the defect
it exists to catch were present, would it go red? A scenario that stays
green while its subject is broken measures nothing, and this project has
found that shape eight times in three days — a promiscuous witness for a
delivery claim, a deploy that cleared the pin root it was supposed to
dirty, a regression gate that was red on every cycle it ever ran.

Three capabilities live here and they are deliberately separate:

  * `Plant` and the `rewrite_argv` / `deploy_hook` entry points break a
    scenario's subject at run time. `hwlib.sh` calls them; nothing is
    touched unless HW_SABOTAGE names a plant.

  * `classify_witness` records what KIND of evidence a scenario rests
    on. A counter, a promiscuous sniffer and a real far-side socket are
    three different claims, and the routing defect was invisible for
    months because nothing named the difference.

  * `History` remembers per-scenario and per-CHECK verdicts across runs,
    so a check that has never been red — or never been green — can be
    reported as carrying no information.

A plant that could not be applied is never silently treated as a pass or
a failure: `applied` is recorded per step and the driver turns an
unapplied plant into `unrunnable`.
"""
import argparse
import dataclasses
import fnmatch
import json
import os
import re
import subprocess
import sys
import time
import typing

STATE_DIR = os.environ.get('HW_SWEEP_STATE', '/var/lib/f-hw-sweep')
BUNDLE_TAG_RE = re.compile(r'^v-hw-(.+)-\d+$')
# Flags that consume the following argument; everything else that does
# not start with '-' is a positional.
VALUE_FLAGS = frozenset(['--bundle', '--geoip', '-o', '--out', '--output'])

@dataclasses.dataclass(frozen=True)
class PolicySub:
  """Rewrite the FWL text (or a data file) handed to the compiler.

  `tag` is a glob over the bundle tag, which hw::deploy derives from its
  first argument: `hw::deploy l1-01 policy.fw` compiles into
  `v-hw-l1-01-<pid>`, so a plant can target one deploy of a scenario
  that deploys several. `flag` selects a file named by a flag instead of
  the policy positional — `--geoip` reaches the trie data, which is the
  only way to plant a defect in the geoip load path.
  """
  find: str
  repl: str
  tag: str = '*'
  regex: bool = False
  flag: typing.Optional[str] = None
  kind: str = 'policy_sub'

@dataclasses.dataclass(frozen=True)
class FileSub:
  """Edit a file on the rig for the duration of one scenario run.

  The driver backs the file up and restores it, so a plant in
  /etc/f/fd.yaml cannot outlive the run that used it.
  """
  path: str
  find: str
  repl: str
  regex: bool = False
  kind: str = 'file_sub'

@dataclasses.dataclass(frozen=True)
class UnitDropIn:
  """Install a systemd drop-in, daemon-reload, remove it afterwards.

  This is how a defect in the UNIT is planted — the l3_08 defect was
  exactly a missing RuntimeDirectoryPreserve, so the plant that proves
  l3_08 can see it is the same line taken back out.
  """
  unit: str
  body: str
  kind: str = 'unit_dropin'

@dataclasses.dataclass(frozen=True)
class DeployCmd:
  """Run a command around a matching hw::deploy.

  `phase` is 'pre' (before fd is restarted onto the new bundle) or
  'post' (after XDP is attached and the wire is proven). `undo` runs
  when the scenario finishes, whatever its verdict.
  """
  tag: str
  cmd: str
  phase: str = 'post'
  undo: str = ''
  kind: str = 'deploy_cmd'

@dataclasses.dataclass(frozen=True)
class Plant:
  """One defect, planted deliberately, that a scenario must notice.

  `defect` says what is broken in the product's terms, not the plant's.
  `residual` is the honest half: the part of the scenario's subject this
  plant does NOT reach, usually because reaching it needs a mutated
  daemon binary rather than a mutated policy or environment.
  """
  ident: str
  defect: str
  steps: typing.Tuple[typing.Any, ...]
  residual: str = ''
  # A shell command that must succeed once the steps are in place.
  #
  # "The edit was made" and "the defect is present" are different
  # claims, and the sweep's first run proved it: a drop-in setting
  # RuntimeDirectoryPreserve=no on f-confd installed cleanly and changed
  # nothing, because the directory is deleted by the unit that STOPS —
  # fd — and the scenario was reported vacuous for the plant's mistake.
  # A plant that cannot verify itself is exactly the instrument this
  # sweep exists to catch, so where the defect has a readable state,
  # read it.
  verify: str = ''

@dataclasses.dataclass(frozen=True)
class Scenario:
  """A hardware scenario and what the sweep knows about it."""
  name: str
  subject: str
  plants: typing.Tuple[Plant, ...] = ()
  # Set when the subject genuinely cannot be broken on this bench. Such
  # a scenario is COUNTED and REPORTED, never silently skipped.
  declared: str = ''
  # Why a weak witness is the right one here, when it is.
  witness_note: str = ''
  # Wall-clock budget for one run of this scenario, in seconds.
  timeout_s: int = 600

def _load_registry():
  sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
  import sweep_registry
  return sweep_registry.SCENARIOS

def plant_for(name, ident=None):
  """The named plant of a scenario, or its first one."""
  scen = _load_registry().get(name)
  if scen is None or not scen.plants:
    return None, None
  if ident is None:
    return scen, scen.plants[0]
  for plant in scen.plants:
    if plant.ident == ident:
      return scen, plant
  return scen, None

def _receipt(path, record):
  if not path:
    return
  os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
  with open(path, 'a') as fh:
    fh.write(json.dumps(record) + '\n')

def read_receipts(path):
  if not path or not os.path.exists(path):
    return []
  out = []
  with open(path) as fh:
    for line in fh:
      line = line.strip()
      if line:
        out.append(json.loads(line))
  return out

def _substitute(text, step):
  if step.regex:
    new, n = re.subn(step.find, step.repl, text, flags=re.M)
  else:
    n = text.count(step.find)
    new = text.replace(step.find, step.repl)
  return new, n

def _bundle_tag(argv):
  for i, arg in enumerate(argv):
    if arg == '--bundle' and i + 1 < len(argv):
      match = BUNDLE_TAG_RE.match(os.path.basename(argv[i + 1].rstrip('/')))
      return match.group(1) if match else None
  return None

def _positional_index(argv):
  """Index of the policy file argument, or None."""
  idx = None
  skip = False
  for i, arg in enumerate(argv):
    if skip:
      skip = False
      continue
    if arg in VALUE_FLAGS:
      skip = True
      continue
    if arg.startswith('-'):
      continue
    idx = i
  return idx

def _flag_index(argv, flag):
  for i, arg in enumerate(argv):
    if arg == flag and i + 1 < len(argv):
      return i + 1
  return None

def rewrite_argv(scenario, ident, argv, receipt, plant_dir):
  """Rewrite a `fwl` command line so it compiles the planted policy.

  Only a compile into a `v-hw-<tag>-<pid>` bundle is ever touched. That
  exclusion is not cosmetic: hw::restore_smoke compiles the operator's
  own /etc/f/rules.fw into `v-smoke` from the EXIT trap of every
  scenario, and a plant that reached it would leave the rig running a
  deliberately broken policy for whoever walks up next.
  """
  argv = list(argv)
  if len(argv) < 2 or argv[0] != 'compile':
    return argv
  tag = _bundle_tag(argv)
  if tag is None:
    return argv
  scen, plant = plant_for(scenario, ident)
  if plant is None:
    return argv
  for step_no, step in enumerate(plant.steps):
    if step.kind != 'policy_sub':
      continue
    if not fnmatch.fnmatch(tag, step.tag):
      continue
    if step.flag:
      idx = _flag_index(argv, step.flag)
    else:
      idx = _positional_index(argv)
    if idx is None or not os.path.exists(argv[idx]):
      _receipt(receipt, {'plant': plant.ident, 'step': step_no,
                         'kind': step.kind, 'tag': tag, 'applied': False,
                         'detail': 'no such argument'})
      continue
    with open(argv[idx]) as fh:
      text = fh.read()
    new, n = _substitute(text, step)
    if n == 0:
      _receipt(receipt, {'plant': plant.ident, 'step': step_no,
                         'kind': step.kind, 'tag': tag, 'applied': False,
                         'detail': 'pattern did not match'})
      continue
    os.makedirs(plant_dir, exist_ok=True)
    out = os.path.join(plant_dir, '%s-%s-%d.fw' % (tag, plant.ident, step_no))
    with open(out, 'w') as fh:
      fh.write(new)
    argv[idx] = out
    _receipt(receipt, {'plant': plant.ident, 'step': step_no,
                       'kind': step.kind, 'tag': tag, 'applied': True,
                       'detail': '%d replacement(s) -> %s' % (n, out)})
  return argv

def deploy_hook(scenario, ident, tag, phase, receipt, env):
  """Run the plant's deploy-phase commands for one hw::deploy."""
  scen, plant = plant_for(scenario, ident)
  if plant is None:
    return 0
  rc = 0
  for step_no, step in enumerate(plant.steps):
    if step.kind != 'deploy_cmd' or step.phase != phase:
      continue
    if not fnmatch.fnmatch(tag, step.tag):
      continue
    proc = subprocess.run(['bash', '-c', step.cmd], env=env,
                          capture_output=True, text=True)
    _receipt(receipt, {'plant': plant.ident, 'step': step_no,
                       'kind': step.kind, 'tag': tag, 'phase': phase,
                       'applied': proc.returncode == 0,
                       'detail': (proc.stderr or proc.stdout).strip()[:400]})
    rc |= proc.returncode
  return rc

# --- witness classification -----------------------------------------
#
# Ranked weakest to strongest. The rank is the whole point: "a frame was
# on the cable" and "a host accepted it" are different claims, and a
# scenario that asserts the second while measuring the first is the
# defect this file exists to surface.
WITNESS_KINDS = (
    ('daemon_selfreport', 1,
     r'fctl status|systemctl is-active|systemctl show|journalctl',
     "the daemon's own report of itself — it can agree with the model "
     "that produced it and disagree with the kernel"),
    ('counter', 1,
     r'hw::counter|hw::map_sum|hw::nat |hw::ct |hw::route ',
     'a datapath counter: the program ran a rule, which says nothing '
     'about what reached the wire'),
    ('sniffer_promisc', 2,
     r'hw::sniff_get|hw::sniff_start',
     'a PROMISCUOUS AF_PACKET tap: the frame was on this cable and '
     'survived XDP. It counts frames a real stack reports '
     'PACKET_OTHERHOST and discards'),
    ('kernel_state', 3,
     r'ip -d link show|bpftool |hw::map_id|hw::map_entries|/proc/sys',
     'the kernel itself, queried independently of the daemon'),
    ('nic_counter', 3,
     r'ethtool -S|tx_packets|rx_packets',
     'the NIC hardware counter: the frame left on copper'),
    ('switch_witness', 4,
     r'hw::mirror_on|ssh -o BatchMode=yes ex01|ssh ex01',
     'the EX2300: a copy made by the switch, which the DUT cannot '
     'influence'),
    ('real_socket', 5,
     r'hw::server_get|hw::client |realsock\.py|hw::host_up',
     'a real non-promiscuous Linux stack ACCEPTED the bytes, and its '
     'own kernel reports the peer address it saw'),
)

def classify_witness(path):
  """Which witnesses a scenario actually uses, and the strongest one."""
  with open(path) as fh:
    text = fh.read()
  # Comment lines describe witnesses they do not use; only code counts.
  code = '\n'.join(l for l in text.splitlines()
                   if not l.lstrip().startswith('#'))
  found = []
  for name, rank, pattern, _ in WITNESS_KINDS:
    if re.search(pattern, code):
      found.append((name, rank))
  if not found:
    return {'witnesses': [], 'rank': 0, 'strongest': 'none'}
  best = max(found, key=lambda w: w[1])
  return {'witnesses': [n for n, _ in found], 'rank': best[1],
          'strongest': best[0]}

# --- static vacuity lint ---------------------------------------------

def lint_unfalsifiable(path):
  """Find checks that cannot fail, without running anything.

  `if ...; then pass ...; else pass ...; fi` is a verdict with one
  outcome. It reads like a measurement and is a print statement. Cheap
  to find, and this suite has some.
  """
  with open(path) as fh:
    lines = fh.readlines()
  findings = []
  stack = []
  for lineno, raw in enumerate(lines, 1):
    line = raw.strip()
    if line.startswith('#'):
      continue
    if re.match(r'^if\b', line):
      stack.append({'line': lineno, 'pass': 0, 'fail': 0, 'branches': 1})
      continue
    if not stack:
      continue
    # `elif` opens a BRANCH of the enclosing conditional, not a new one.
    # Counting it as a new block splits an if/elif/else whose first
    # branch fails into a fail-free elif/else and reports a false
    # positive — which is what it did on l8_01 and l8_06.
    if re.match(r'^(else|elif)\b', line):
      stack[-1]['branches'] += 1
    elif re.match(r'^fi\b', line):
      block = stack.pop()
      # No branch of this conditional can fail, yet at least one of them
      # renders a PASS. Whatever the measurement says, the scenario gets
      # a green line out of it — which is a recording, not a verdict.
      if block['fail'] == 0 and block['pass'] >= 1 \
         and block['branches'] >= 2:
        findings.append({
            'line': block['line'],
            'why': 'no branch of this conditional can fail, yet it emits '
                   'a PASS: the check has one possible colour',
        })
    # An argument is required: a bare `pass` is Python, and these
    # scripts embed Python heredocs.
    elif re.match(r'''^pass\s+["'$]''', line):
      stack[-1]['pass'] += 1
    elif re.match(r'''^(fail|hw::abort|assert_\w+)\s+["'$]''', line) \
        or re.match(r'^exit [1-9]', line):
      # hw::abort calls fail() and leaves; a branch that aborts is a
      # branch that can be red.
      stack[-1]['fail'] += 1
  return findings

# --- verdict parsing and history -------------------------------------

VERDICT_RE = re.compile(r'^\[[^\]]+\]\s+(PASS|FAIL):\s+(.*)$')

def normalise_check(text):
  """A stable key for one check across runs.

  hwlib's pass/fail messages embed the measured value ("counter hit_80 =
  100"), so the raw text changes every run. Strip the value; keep the
  label, which is what the author wrote.
  """
  text = text.strip()
  if ' = ' in text:
    text = text.rsplit(' = ', 1)[0]
  text = re.sub(r'\s+', ' ', text)
  return text[:160]

def parse_checks(output):
  """{normalised label: PASS|FAIL} plus the raw ordered list."""
  checks = {}
  order = []
  for line in output.splitlines():
    match = VERDICT_RE.match(line.strip())
    if not match:
      continue
    verdict, text = match.group(1), match.group(2)
    key = normalise_check(text)
    order.append((key, verdict))
    # A label asserted twice in one run (l1_07 rounds, l5_02 variants)
    # is FAIL for the run if either instance failed.
    if checks.get(key) == 'FAIL':
      continue
    checks[key] = verdict
  return checks, order

class History:
  """Append-only verdict history, and the invariance it makes visible.

  `regress` was red on every cycle it ever ran and nobody noticed,
  because red was its normal colour. A verdict that never changes is not
  evidence; it is a constant with a colour.
  """

  def __init__(self, path=None):
    self.path = path or os.path.join(STATE_DIR, 'history.jsonl')

  def record(self, scenario, mode, rc, verdict, checks, extra=None):
    os.makedirs(os.path.dirname(self.path) or '.', exist_ok=True)
    row = {'ts': time.time(), 'scenario': scenario, 'mode': mode,
           'rc': rc, 'verdict': verdict, 'checks': checks}
    if extra:
      row.update(extra)
    with open(self.path, 'a') as fh:
      fh.write(json.dumps(row) + '\n')

  def rows(self):
    if not os.path.exists(self.path):
      return []
    out = []
    with open(self.path) as fh:
      for line in fh:
        line = line.strip()
        if line:
          out.append(json.loads(line))
    return out

  def invariant_checks(self, min_runs=3):
    """Checks whose verdict has never changed across >= min_runs runs.

    Both directions are reported. never-red is a check that may be
    guarding nothing; never-green is the `regress` shape, a check that
    is red as its normal colour and can therefore hide the first real
    regression behind the declared ones.
    """
    seen = {}
    for row in self.rows():
      for key, verdict in (row.get('checks') or {}).items():
        rec = seen.setdefault((row['scenario'], key),
                              {'PASS': 0, 'FAIL': 0})
        rec[verdict] = rec.get(verdict, 0) + 1
    never_red, never_green = [], []
    for (scenario, key), rec in sorted(seen.items()):
      runs = rec['PASS'] + rec['FAIL']
      if runs < min_runs:
        continue
      if rec['FAIL'] == 0:
        never_red.append({'scenario': scenario, 'check': key, 'runs': runs})
      elif rec['PASS'] == 0:
        never_green.append({'scenario': scenario, 'check': key,
                            'runs': runs})
    return {'never_red': never_red, 'never_green': never_green}

  def invariant_scenarios(self, min_runs=3):
    seen = {}
    for row in self.rows():
      seen.setdefault(row['scenario'], []).append(row['verdict'])
    out = []
    for scenario, verdicts in sorted(seen.items()):
      if len(verdicts) >= min_runs and len(set(verdicts)) == 1:
        out.append({'scenario': scenario, 'verdict': verdicts[0],
                    'runs': len(verdicts)})
    return out

def main(argv=None):
  parser = argparse.ArgumentParser(description=__doc__)
  sub = parser.add_subparsers(dest='cmd', required=True)

  rw = sub.add_parser('rewrite-argv')
  rw.add_argument('--scenario', required=True)
  rw.add_argument('--plant', default=None)
  rw.add_argument('--receipt', default='')
  rw.add_argument('--plant-dir', default=os.path.join(STATE_DIR, 'plants'))
  rw.add_argument('rest', nargs=argparse.REMAINDER)

  dh = sub.add_parser('deploy-hook')
  dh.add_argument('--scenario', required=True)
  dh.add_argument('--plant', default=None)
  dh.add_argument('--tag', required=True)
  dh.add_argument('--phase', required=True, choices=['pre', 'post'])
  dh.add_argument('--receipt', default='')

  args = parser.parse_args(argv)
  if args.cmd == 'rewrite-argv':
    rest = args.rest
    if rest and rest[0] == '--':
      rest = rest[1:]
    out = rewrite_argv(args.scenario, args.plant, rest, args.receipt,
                       args.plant_dir)
    sys.stdout.write('\0'.join(out) + '\0')
    return 0
  if args.cmd == 'deploy-hook':
    return deploy_hook(args.scenario, args.plant, args.tag, args.phase,
                       args.receipt, dict(os.environ))
  return 2

if __name__ == '__main__':
  sys.exit(main())
