#!/usr/bin/env python3
"""The vacuity sweep: run every hardware scenario against its own defect.

Mutation testing pointed at the SCENARIOS rather than at the corpus. For
each scenario the registry names the defect it exists to catch; the sweep
plants that defect and requires the scenario to go red. A scenario that
stays green while its subject is broken is measuring nothing, and is
reported as a finding rather than quietly deleted.

The verdict vocabulary is three-valued on purpose:

  discriminating  the scenario went red with the defect in place, and
                  green without it. It measures what it claims to.
  vacuous         the scenario stayed green with the defect in place.
  unrunnable      the sweep could not put the question — the plant did
                  not apply, or the scenario is red without any plant.
                  This is a defect in the SWEEP, not a pass and not a
                  failure, and folding it into either has already cost
                  this project a whole section of soak reporting.

plus `declared`, for a scenario whose subject genuinely cannot be broken
on this bench. Declared scenarios are named and counted; nothing is ever
silently skipped.

Run order per scenario is sabotage-first. A run that is GREEN under the
plant already proves vacuity — a green run is green whatever a baseline
would have said — so the baseline is only paid for when the plant went
red and the question becomes "was it red anyway?".

Usage on the rig (root):
  vacuity_sweep.py run                     # everything, in cost order
  vacuity_sweep.py run --only l2_03_masquerade l11_05_icmp_pmtu
  vacuity_sweep.py run --resume            # skip what already has a row
  vacuity_sweep.py preflight               # static: do the plants match?
  vacuity_sweep.py report                  # render from the results file
  vacuity_sweep.py restore                 # put the rig back, verify
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import sweep_lib  # noqa: E402
from sweep_lib import History  # noqa: E402

STATE = sweep_lib.STATE_DIR
RESULTS = os.path.join(STATE, 'results.jsonl')
LOGS = os.path.join(STATE, 'logs')
DROPIN_ROOT = '/etc/systemd/system'

def _run(cmd, timeout=None, env=None):
  return subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True,
                        text=True, timeout=timeout, env=env)

def _log(msg):
  sys.stdout.write('%s %s\n' % (time.strftime('%H:%M:%S'), msg))
  sys.stdout.flush()

# --- planting and un-planting the environment ------------------------

class PlantedEnv:
  """Environment-level plants, applied around one scenario run.

  Every step records whether it really took effect. A FileSub whose
  pattern did not match, or a drop-in systemd refused, must surface as
  `unrunnable` — a plant that did not happen makes a green run mean
  nothing at all.
  """

  def __init__(self, plant):
    self.plant = plant
    self.undo = []
    self.applied = []

  def __enter__(self):
    for step_no, step in enumerate(self.plant.steps if self.plant else ()):
      if step.kind == 'file_sub':
        self._file_sub(step_no, step)
      elif step.kind == 'unit_dropin':
        self._dropin(step_no, step)
    if self.plant is not None and self.plant.verify:
      proc = _run(['bash', '-c', self.plant.verify])
      self.applied.append({'step': 'verify', 'kind': 'verify',
                           'applied': proc.returncode == 0,
                           'detail': self.plant.verify})
    return self

  def __exit__(self, *exc):
    # A deploy-phase plant can leave a file behind (a stand-in compiler,
    # a scratch policy). Its undo runs whether or not the command itself
    # ran, because the rig has to come back clean either way.
    for step in (self.plant.steps if self.plant else ()):
      if step.kind == 'deploy_cmd' and step.undo:
        _run(['bash', '-c', step.undo])
    for fn in reversed(self.undo):
      try:
        fn()
      except Exception as err:  # never let cleanup mask a result
        _log('  cleanup error: %s' % err)
    self.undo = []
    return False

  def _file_sub(self, step_no, step):
    if not os.path.exists(step.path):
      self.applied.append({'step': step_no, 'kind': step.kind,
                           'applied': False, 'detail': 'no such file'})
      return
    # One backup PER STEP, not per file. Two FileSubs on one file used
    # to share `<path>.sweepbak`: the second overwrote the first's copy
    # with the already-patched text, and the LIFO restore then put THAT
    # back and left the file half-planted for every scenario after it.
    # Found by running the sweep — l2_08's plant is two edits to
    # emitter.py, and its baseline run failed to compile at all, which
    # the sweep correctly reported as `unrunnable` and could not
    # explain. A plant that outlives its own run is the same class as a
    # test that cannot fail.
    backup = '%s.sweepbak.%s' % (step.path, step_no)
    shutil.copy2(step.path, backup)
    with open(step.path) as fh:
      text = fh.read()
    if step.regex:
      new, n = re.subn(step.find, step.repl, text, flags=re.M)
    else:
      n = text.count(step.find)
      new = text.replace(step.find, step.repl)
    if n:
      with open(step.path, 'w') as fh:
        fh.write(new)
    self.applied.append({'step': step_no, 'kind': step.kind,
                         'applied': bool(n),
                         'detail': '%d replacement(s) in %s' % (n, step.path)})

    def restore(path=step.path, bak=backup):
      shutil.copy2(bak, path)
      os.unlink(bak)
    self.undo.append(restore)

  def _dropin(self, step_no, step):
    directory = os.path.join(DROPIN_ROOT, '%s.service.d' % step.unit)
    path = os.path.join(directory, 'zz-vacuity-sweep.conf')
    os.makedirs(directory, exist_ok=True)
    with open(path, 'w') as fh:
      fh.write(step.body)
    proc = _run(['systemctl', 'daemon-reload'])
    shown = _run(['systemctl', 'cat', step.unit]).stdout
    took = 'zz-vacuity-sweep.conf' in shown and proc.returncode == 0
    self.applied.append({'step': step_no, 'kind': step.kind,
                         'applied': took,
                         'detail': 'drop-in on %s' % step.unit})

    def restore(p=path, d=directory):
      if os.path.exists(p):
        os.unlink(p)
      if os.path.isdir(d) and not os.listdir(d):
        os.rmdir(d)
      _run(['systemctl', 'daemon-reload'])
    self.undo.append(restore)

# --- rig restoration --------------------------------------------------

RESTORE_SH = r'''
set -u
cd %(here)s
# Stray far hosts and their interfaces: a scenario that died mid-run can
# leave a netns holding one of the data ports, and the smoke policy then
# cannot attach to a port that is not in the root namespace.
for ns in $(ip netns list 2>/dev/null | awk '{print $1}'); do
  case "$ns" in fguest|fserver|f*) ip netns del "$ns" 2>/dev/null || true;; esac
done
for dev in $(ip -o link show | awk -F': ' '{print $2}' | cut -d@ -f1); do
  # mv*/vl* are hw::host_up's macvlan and 802.1Q far hosts; fz3b is
  # l2_08's veth zone, whose root-side end stays behind if that
  # scenario dies before its own cleanup.
  case "$dev" in mv*|vl*|fz3b*) ip link del "$dev" 2>/dev/null || true;; esac
done
for f in %(ifaces)s; do
  ip addr flush dev "$f" 2>/dev/null || true
  tc qdisc del dev "$f" clsact 2>/dev/null || true
  ethtool -K "$f" rxvlan off 2>/dev/null || true
done
source ./hwlib.sh
hw::restore_smoke
'''

DATA_IFACES = ['enp1s0f0', 'enp1s0f1', 'enp1s0f2']

def restore_rig(ip_forward=None):
  """Put the rig back on the smoke policy and say whether it worked.

  `ip_forward` is now CHECKED, not written, and the reason is a state
  this used to create. It wrote the knob after `hw::restore_smoke` had
  already restarted fd, so on an armed box the sequence was: fd raises
  ip_forward to 1 and records why, then this wrote 0 behind it. Since
  the fail-closed change that is not a tidy resting state, it is a
  disagreement — and `show status` reports it exactly as designed,
  `[FAIL] OFF, and fd did not do it`. The rig was found in that state
  on 2026-08-16, left by the previous run's restore, and it renders as
  a failure to whoever walks up next.

  On a box whose datapath is armed the knob belongs to fd. So restore
  leaves it alone and reports what the kernel actually holds together
  with fd's own interface count, which is what an operator needs to
  tell "closed on purpose" from "closed by accident".
  """
  script = RESTORE_SH % {'here': HERE, 'ifaces': ' '.join(DATA_IFACES)}
  proc = _run(['bash', '-c', script], timeout=300)
  ok = False
  for _ in range(20):
    status = _run(['fctl', 'status'])
    if '"xdp_attached":true' in status.stdout:
      ok = True
      break
    time.sleep(0.5)
  with open('/proc/sys/net/ipv4/ip_forward') as fh:
    knob = fh.read().strip()
  out = {'ok': ok, 'stderr': proc.stderr[-400:], 'ip_forward': knob}
  if ip_forward is not None and knob != str(ip_forward):
    # Not an error: fd owns this on an armed box. Recorded so a run
    # that expected otherwise says so instead of being surprised.
    out['ip_forward_expected'] = str(ip_forward)
  if ok and knob == '0':
    out['disagreement'] = (
        'the datapath is armed but net.ipv4.ip_forward is 0 — '
        '`einheit-f show status` will report this as a FAIL')
  return out

# --- one scenario -----------------------------------------------------

def _script_path(name):
  return os.path.join(HERE, name + '.sh')

def run_once(name, timeout, plant_ident=None, receipt=None):
  """Run one hardware scenario, with or without a plant."""
  env = dict(os.environ)
  env['HW_SWEEP_STATE'] = STATE
  if plant_ident is not None:
    env['HW_SABOTAGE'] = name
    env['HW_SABOTAGE_PLANT'] = plant_ident
    env['HW_SABOTAGE_RECEIPT'] = receipt
  else:
    env.pop('HW_SABOTAGE', None)
    env.pop('HW_SABOTAGE_PLANT', None)
    env.pop('HW_SABOTAGE_RECEIPT', None)
  start = time.time()
  try:
    proc = subprocess.run(['bash', _script_path(name)], capture_output=True,
                          text=True, timeout=timeout, env=env)
    rc, out = proc.returncode, proc.stdout + proc.stderr
  except subprocess.TimeoutExpired as err:
    rc = 124
    out = (err.stdout or '') + (err.stderr or '')
    out = (out.decode() if isinstance(out, bytes) else out)
    out += '\n[sweep] TIMEOUT after %ss\n' % timeout
  return {'rc': rc, 'output': out, 'seconds': round(time.time() - start, 1)}

def red_via(output):
  """How a red run went red: an assertion, or a setup abort."""
  if 'FAIL: ABORT:' in output:
    return 'abort'
  if re.search(r'^\[[^\]]+\]\s+FAIL:', output, re.M):
    return 'assertion'
  return 'crash'

def sweep_scenario(scen, history, keep_logs=True):
  """The verdict for one scenario, and the evidence behind it."""
  name = scen.name
  if scen.declared:
    _log('%-42s DECLARED' % name)
    row = {'scenario': name, 'verdict': 'declared', 'reason': scen.declared,
           'subject': scen.subject}
    history.record(name, 'declared', 0, 'declared', {})
    return row

  plant = scen.plants[0]
  receipt = os.path.join(STATE, 'receipts', '%s.jsonl' % name)
  if os.path.exists(receipt):
    os.unlink(receipt)
  os.makedirs(os.path.dirname(receipt), exist_ok=True)

  _log('%-42s plant=%s' % (name, plant.ident))
  restore_rig()
  with PlantedEnv(plant) as env_plant:
    sab = run_once(name, scen.timeout_s, plant.ident, receipt)
  restore_rig()

  receipts = sweep_lib.read_receipts(receipt) + env_plant.applied
  wanted = [i for i, s in enumerate(plant.steps)]
  applied_steps = {r.get('step') for r in receipts if r.get('applied')}
  not_applied = [i for i in wanted if i not in applied_steps]

  sab_checks, _ = sweep_lib.parse_checks(sab['output'])
  row = {'scenario': name, 'subject': scen.subject, 'plant': plant.ident,
         'defect': plant.defect, 'residual': plant.residual,
         'sabotage_rc': sab['rc'], 'sabotage_seconds': sab['seconds'],
         'receipts': receipts, 'ts': time.time()}

  verify_failed = any(r.get('step') == 'verify' and not r.get('applied')
                      for r in receipts)
  # A text plant compiled into v-hw-<tag> is live only while fd is
  # running that bundle. Several scenarios hand the same policy to
  # /etc/f/rules.fw, and fd's watcher recompiles the PRISTINE file within
  # seconds — the product reverts the plant, the scenario passes, and the
  # sweep would call it vacuous. The bundle fd was running when the
  # scenario ended is the evidence that the plant was still in force.
  #
  # It can only explain a false GREEN. A scenario that went red with the
  # plant was asked the question and answered it, and several scenarios
  # legitimately END on a watcher bundle because driving the watcher is
  # their subject (l8_01) — reading supersession there would throw away
  # a good result.
  text_only = all(s.kind == 'policy_sub' for s in plant.steps)
  loaded = [r.get('value') for r in receipts if r.get('note') ==
            'current_bundle']
  superseded = (sab['rc'] == 0 and text_only and loaded and
                not os.path.basename(loaded[-1] or '').startswith('v-hw-'))
  if not_applied or verify_failed or superseded:
    row['verdict'] = 'unrunnable'
    if verify_failed:
      row['reason'] = ('the plant was installed but its own verification '
                       'says the defect is NOT present, so the scenario '
                       'was never asked the question')
    elif superseded:
      row['reason'] = ('the plant was superseded: fd was running %s when '
                       'the scenario ended, which is not the planted '
                       'bundle. A text plant cannot survive a scenario '
                       'that hands the same policy to the watcher.'
                       % os.path.basename(loaded[-1] or '?'))
    else:
      row['reason'] = ('the plant did not apply (step(s) %s); the scenario '
                       'was never asked the question' %
                       ','.join(str(i) for i in not_applied))
    history.record(name, 'sabotage:%s' % plant.ident, sab['rc'],
                   'unrunnable', sab_checks)
  elif sab['rc'] == 0:
    # Green with the defect in place. Confirm once — a vacuity finding
    # is a claim about the scenario, not about one run of it.
    restore_rig()
    with PlantedEnv(plant):
      again = run_once(name, scen.timeout_s, plant.ident, receipt)
    restore_rig()
    row['confirm_rc'] = again['rc']
    if again['rc'] == 0:
      row['verdict'] = 'vacuous'
      row['reason'] = ('stayed green twice with its subject broken: %s'
                       % plant.defect)
    else:
      row['verdict'] = 'flaky'
      row['reason'] = ('green then red under the identical plant — the '
                       'scenario is not deterministic, which is its own '
                       'finding')
    history.record(name, 'sabotage:%s' % plant.ident, sab['rc'],
                   row['verdict'], sab_checks)
  else:
    base = run_once(name, scen.timeout_s)
    restore_rig()
    base_checks, _ = sweep_lib.parse_checks(base['output'])
    row['baseline_rc'] = base['rc']
    row['baseline_seconds'] = base['seconds']
    if base['rc'] == 0:
      row['verdict'] = 'discriminating'
      row['red_via'] = red_via(sab['output'])
      moved = sorted(k for k, v in sab_checks.items()
                     if v == 'FAIL' and base_checks.get(k) == 'PASS')
      still = sorted(k for k, v in sab_checks.items()
                     if v == 'PASS' and base_checks.get(k) == 'PASS')
      row['checks_that_moved'] = moved
      row['checks_that_did_not_move'] = still
    else:
      row['verdict'] = 'unrunnable'
      row['reason'] = ('red without any plant (rc=%d): a scenario that '
                       'cannot pass cannot be asked whether it '
                       'discriminates' % base['rc'])
    history.record(name, 'sabotage:%s' % plant.ident, sab['rc'],
                   row['verdict'], sab_checks)
    history.record(name, 'baseline', base['rc'],
                   'pass' if base['rc'] == 0 else 'fail', base_checks)
    if keep_logs:
      _write_log(name, 'baseline', base['output'])

  if keep_logs:
    _write_log(name, 'sabotage', sab['output'])
  _log('%-42s -> %s' % (name, row['verdict'].upper()))
  return row

def _write_log(name, mode, text):
  os.makedirs(LOGS, exist_ok=True)
  with open(os.path.join(LOGS, '%s.%s.log' % (name, mode)), 'w') as fh:
    fh.write(text)

# --- preflight: do the plants even match? -----------------------------

POLICY_BLOCK_RE = re.compile(
    r"<<'?\"?(\w+)'?\"?\n(.*?)\n\1\n", re.S)

def _policy_text(path):
  """Every FWL-looking string a scenario can compile, for static checks.

  Includes the shipped examples a scenario deploys — l2_06 deploys
  examples/storm_shield.fw rather than a heredoc, and a plant aimed at
  the example is invisible from the script alone.
  """
  with open(path) as fh:
    text = fh.read()
  blocks = [b for _, b in POLICY_BLOCK_RE.findall(text)]
  blocks += re.findall(r"='((?:[^']*\n)+[^']*)'", text)
  examples = os.path.abspath(os.path.join(HERE, '..', '..', '..', 'examples'))
  for name in set(re.findall(r'examples/([\w.-]+\.fw)', text)):
    candidate = os.path.join(examples, name)
    if os.path.exists(candidate):
      with open(candidate) as fh:
        blocks.append(fh.read())
  return '\n'.join(blocks) + '\n' + text

def preflight(names):
  """Check each plant against the scenario source without running it.

  A plant whose pattern never appears is a sweep defect, and finding it
  here costs seconds instead of a full hardware run.
  """
  out = []
  for name in names:
    scen = sweep_lib._load_registry()[name]
    if scen.declared:
      out.append({'scenario': name, 'ok': True, 'note': 'declared'})
      continue
    text = _policy_text(_script_path(name))
    for plant in scen.plants:
      for step_no, step in enumerate(plant.steps):
        note, ok = '', True
        if step.kind == 'policy_sub':
          if step.regex:
            hits = len(re.findall(step.find, text, re.M))
          else:
            hits = text.count(step.find)
          ok = hits > 0
          note = '%d static hit(s) for %r' % (hits, step.find[:60])
        elif step.kind == 'file_sub':
          ok = os.path.exists(step.path)
          note = '%s %s' % (step.path, 'exists' if ok else 'MISSING')
        elif step.kind == 'unit_dropin':
          ok = _run(['systemctl', 'cat', step.unit]).returncode == 0
          note = 'unit %s %s' % (step.unit, 'known' if ok else 'UNKNOWN')
        elif step.kind == 'deploy_cmd':
          note = 'runtime command, not statically checkable'
        out.append({'scenario': name, 'plant': plant.ident, 'step': step_no,
                    'kind': step.kind, 'ok': ok, 'note': note})
  return out

# --- reporting --------------------------------------------------------

ORDER = ['vacuous', 'unrunnable', 'flaky', 'discriminating', 'declared']

def load_results(path=RESULTS):
  rows = {}
  if not os.path.exists(path):
    return rows
  with open(path) as fh:
    for line in fh:
      line = line.strip()
      if line:
        row = json.loads(line)
        rows[row['scenario']] = row
  return rows

def report(rows, history):
  reg = sweep_lib._load_registry()
  counts = {}
  for row in rows.values():
    counts[row['verdict']] = counts.get(row['verdict'], 0) + 1
  lines = []
  add = lines.append
  add('=' * 72)
  add('VACUITY SWEEP — does each scenario notice its own defect?')
  add('=' * 72)
  add('scenarios in registry : %d' % len(reg))
  add('scenarios swept       : %d' % len(rows))
  for key in ORDER:
    if counts.get(key):
      add('  %-16s %3d' % (key, counts[key]))
  add('')

  for key, title, blurb in [
      ('vacuous', 'VACUOUS — stayed GREEN with its subject broken',
       'each of these passes while the thing it exists to catch is '
       'present. They are findings, not tests to delete.'),
      ('flaky', 'NON-DETERMINISTIC under an identical plant', ''),
      ('unrunnable', 'UNRUNNABLE — the question could not be put',
       'a defect in the sweep or a scenario that is red anyway; '
       'neither a pass nor a failure.'),
  ]:
    hits = [r for r in rows.values() if r['verdict'] == key]
    if not hits:
      continue
    add(title)
    if blurb:
      add('  ' + blurb)
    for row in sorted(hits, key=lambda r: r['scenario']):
      add('  %s' % row['scenario'])
      add('      subject : %s' % row.get('subject', ''))
      if row.get('defect'):
        add('      planted : %s' % row['defect'])
      add('      why     : %s' % row.get('reason', ''))
    add('')

  disc = [r for r in rows.values() if r['verdict'] == 'discriminating']
  if disc:
    add('DISCRIMINATING (%d) — went red with the defect, green without'
        % len(disc))
    for row in sorted(disc, key=lambda r: r['scenario']):
      add('  %-42s red via %s' % (row['scenario'], row.get('red_via', '?')))
    add('')

  decl = [r for r in rows.values() if r['verdict'] == 'declared']
  if decl:
    add('DECLARED UNBREAKABLE ON THIS BENCH (%d)' % len(decl))
    for row in sorted(decl, key=lambda r: r['scenario']):
      add('  %s' % row['scenario'])
      add('      %s' % row.get('reason', ''))
    add('')

  residual = [(r['scenario'], r['residual']) for r in rows.values()
              if r.get('residual')]
  if residual:
    add('RESIDUAL — what the plant did NOT reach (%d)' % len(residual))
    for name, text in sorted(residual):
      add('  %-42s %s' % (name, text))
    add('')

  add(movement_report(rows))
  add(witness_report())
  add(invariance_report(history))
  add(lint_report())
  return '\n'.join(lines)

def check_movement(name):
  """Per-CHECK discrimination, read back from the two stored runs.

  A scenario can be discriminating while most of its checks are not: the
  plant moves one assertion and the other eleven read the same either
  way. Those eleven are not necessarily wrong — many measure something
  the plant does not touch — but they are the population the next plant
  should be aimed at, and nothing else in the sweep names them.

  Free-form pass/fail pairs do not share a label (the pass text and the
  fail text are different sentences), so a check that is FAIL under the
  plant and absent from the baseline is counted as red too.
  """
  paths = {mode: os.path.join(LOGS, '%s.%s.log' % (name, mode))
           for mode in ('baseline', 'sabotage')}
  if not all(os.path.exists(p) for p in paths.values()):
    return None
  parsed = {}
  for mode, path in paths.items():
    with open(path) as fh:
      parsed[mode], _ = sweep_lib.parse_checks(fh.read())
  base, sab = parsed['baseline'], parsed['sabotage']
  return {
      'moved': sorted(k for k, v in sab.items()
                      if v == 'FAIL' and base.get(k) == 'PASS'),
      'new_red': sorted(k for k, v in sab.items()
                        if v == 'FAIL' and k not in base),
      'unmoved': sorted(k for k, v in sab.items()
                        if v == 'PASS' and base.get(k) == 'PASS'),
  }

def movement_report(rows):
  lines = ['CHECK-LEVEL DISCRIMINATION — which assertions the plant moved']
  lines.append('  A scenario can be discriminating on one assertion while')
  lines.append('  the rest read the same either way. The unmoved ones are')
  lines.append('  where the next plant should be aimed.')
  total_moved = total_unmoved = 0
  detail = []
  for name in sorted(rows):
    if rows[name]['verdict'] != 'discriminating':
      continue
    move = check_movement(name)
    if move is None:
      continue
    red = move['moved'] + move['new_red']
    total_moved += len(red)
    total_unmoved += len(move['unmoved'])
    detail.append('    %-42s %d red / %d unmoved'
                  % (name, len(red), len(move['unmoved'])))
  lines.append('  %d check(s) went red under a plant; %d stayed green'
               % (total_moved, total_unmoved))
  lines.extend(detail)
  return '\n'.join(lines) + '\n'

def witness_report():
  reg = sweep_lib._load_registry()
  lines = ['WITNESS CLASSIFICATION — what the evidence actually is']
  buckets = {}
  weak = []
  for name, scen in sorted(reg.items()):
    path = _script_path(name)
    if not os.path.exists(path):
      continue
    info = sweep_lib.classify_witness(path)
    buckets.setdefault(info['strongest'], []).append(name)
    if info['rank'] <= 2:
      weak.append((name, info, scen.witness_note))
  for kind, rank, _, blurb in reversed(sweep_lib.WITNESS_KINDS):
    names = buckets.get(kind)
    if not names:
      continue
    lines.append('  [%d] %-18s %d scenario(s)' % (rank, kind, len(names)))
    lines.append('      %s' % blurb)
    lines.append('      %s' % ', '.join(sorted(names)))
  lines.append('')
  lines.append('  WEAK WITNESS (rank <= 2: a counter or a promiscuous tap).')
  lines.append('  A promiscuous AF_PACKET socket counts frames a real stack')
  lines.append('  reports PACKET_OTHERHOST and discards. That is the right')
  lines.append('  witness for a subject no socket can see, and the wrong one')
  lines.append('  for any claim of the form "the packet got there".')
  for name, info, note in weak:
    lines.append('    %-42s %s' % (name, info['strongest']))
    if note:
      lines.append('        justified: %s' % note)
    else:
      lines.append('        UNJUSTIFIED: no witness_note in the registry — '
                   'either write one or add a real-socket leg')
  return '\n'.join(lines) + '\n'

def invariance_report(history, min_runs=3):
  lines = ['INVARIANT VERDICTS — checks that have never changed']
  lines.append('  A check that is always green, or always red, carries no')
  lines.append('  information. The soak\'s `regress` step was red on every')
  lines.append('  cycle it ever ran, which is why nobody read it.')
  inv = history.invariant_checks(min_runs=min_runs)
  if not inv['never_green'] and not inv['never_red']:
    lines.append('  (not enough history yet: need %d runs of a check)'
                 % min_runs)
    return '\n'.join(lines) + '\n'
  for key, title in [('never_green', 'NEVER GREEN (the `regress` shape)'),
                     ('never_red', 'NEVER RED across every run, plant '
                                   'included')]:
    if inv[key]:
      lines.append('  %s: %d' % (title, len(inv[key])))
      for row in inv[key][:60]:
        lines.append('    %-38s %s (%d runs)'
                     % (row['scenario'], row['check'], row['runs']))
  return '\n'.join(lines) + '\n'

def lint_report():
  lines = ['STATIC LINT — checks that cannot fail']
  lines.append('  Found by reading, not by running: a conditional whose')
  lines.append('  every branch calls pass() is a print statement wearing a')
  lines.append('  verdict\'s clothes.')
  total = 0
  for name in sorted(sweep_lib._load_registry()):
    path = _script_path(name)
    if not os.path.exists(path):
      continue
    for finding in sweep_lib.lint_unfalsifiable(path):
      total += 1
      lines.append('    %s:%d  %s' % (os.path.basename(path),
                                      finding['line'], finding['why']))
  if not total:
    lines.append('    (none)')
  return '\n'.join(lines) + '\n'

# --- entry point ------------------------------------------------------

def select(args, reg):
  names = sorted(reg)
  if args.only:
    names = [n for n in names if n in set(args.only)]
  if args.exclude:
    names = [n for n in names if n not in set(args.exclude)]
  if args.resume:
    done = set(load_results())
    names = [n for n in names if n not in done]
  # Cheapest first, so a sweep that runs out of time has still answered
  # the most scenarios it could.
  return sorted(names, key=lambda n: (reg[n].timeout_s, n))

def main(argv=None):
  parser = argparse.ArgumentParser(description=__doc__)
  sub = parser.add_subparsers(dest='cmd', required=True)
  for cmd in ('run', 'preflight'):
    p = sub.add_parser(cmd)
    p.add_argument('--only', nargs='*', default=None)
    p.add_argument('--exclude', nargs='*', default=None)
    p.add_argument('--resume', action='store_true')
  sub.add_parser('report')
  sub.add_parser('restore')
  args = parser.parse_args(argv)

  os.makedirs(STATE, exist_ok=True)
  history = History()
  reg = sweep_lib._load_registry()

  if args.cmd == 'preflight':
    rows = preflight(select(args, reg))
    bad = [r for r in rows if not r['ok']]
    for row in rows:
      print('%-6s %-42s %s' % ('ok' if row['ok'] else 'BAD',
                               row['scenario'], row.get('note', '')))
    print('\n%d plant step(s) checked, %d cannot apply' % (len(rows), len(bad)))
    return 1 if bad else 0

  if args.cmd == 'report':
    print(report(load_results(), history))
    return 0

  if args.cmd == 'restore':
    result = restore_rig()
    print(json.dumps(result))
    return 0 if result['ok'] else 1

  if os.geteuid() != 0:
    print('the sweep runs on the rig, as root', file=sys.stderr)
    return 2
  names = select(args, reg)
  _log('sweeping %d scenario(s)' % len(names))
  for name in names:
    try:
      row = sweep_scenario(reg[name], history)
    except Exception as err:  # a sweep bug is unrunnable, never a pass
      row = {'scenario': name, 'verdict': 'unrunnable',
             'reason': 'the sweep itself raised: %r' % err,
             'subject': reg[name].subject}
      restore_rig()
    with open(RESULTS, 'a') as fh:
      fh.write(json.dumps(row) + '\n')
  final = restore_rig()
  _log('rig restored: %s' % json.dumps(final))
  print(report(load_results(), history))
  return 0

if __name__ == '__main__':
  sys.exit(main())
