"""Unit tests for the vacuity sweep's machinery.

The sweep exists because instruments lie about what they measure, so its
own instrument is held to the same bar. Four properties carry the whole
capability and each is asserted with a case that fails when it breaks:

  a plant that did not apply is recorded as NOT applied, never silently
    as applied — that distinction is the whole of the `unrunnable`
    verdict;

  a compile into the operator's smoke bundle is never rewritten, because
    hw::restore_smoke runs from the EXIT trap of every scenario and a
    plant that reached it would leave the rig broken;

  a check's history key is stable across runs even though hwlib embeds
    the measured value in the message;

  a conditional that cannot fail is found statically, and one that CAN
    fail is not.
"""
import json
import os
import sys
import pytest

HW = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'system', 'hw')
sys.path.insert(0, HW)
sweep_lib = pytest.importorskip('sweep_lib')

POLICY = '''zone t = [enp1s0f1]

@xdp(t)

count hit_80 if pkt.proto == tcp and pkt.dst_port == 80
allow if pkt.proto == tcp and pkt.dst_port == 80
default drop
'''

def _plant(tmp_path, step, ident='p1'):
  """A registry stub, so the tests do not depend on the real registry."""
  scen = sweep_lib.Scenario(
      name='fake', subject='s',
      plants=(sweep_lib.Plant(ident=ident, defect='d', steps=(step,)),))
  return scen

def _patch_registry(monkeypatch, scen):
  monkeypatch.setattr(sweep_lib, '_load_registry', lambda: {scen.name: scen})

def test_rewrite_argv_plants_the_policy(tmp_path, monkeypatch):
  fw = tmp_path / 'p.fw'
  fw.write_text(POLICY)
  step = sweep_lib.PolicySub(tag='l1-01',
                             find='allow if pkt.proto == tcp and '
                                  'pkt.dst_port == 80',
                             repl='allow if pkt.proto == tcp and '
                                  'pkt.dst_port == 81')
  _patch_registry(monkeypatch, _plant(tmp_path, step))
  receipt = str(tmp_path / 'r.jsonl')
  argv = sweep_lib.rewrite_argv(
      'fake', 'p1',
      ['compile', '--bundle', '/x/v-hw-l1-01-99', str(fw)],
      receipt, str(tmp_path / 'plants'))
  assert argv[-1] != str(fw)
  planted = open(argv[-1]).read()
  assert 'pkt.dst_port == 81' in planted
  # The counter is deliberately left alone: the plant changes the
  # DISPOSITION, so the wire witness has to do the work.
  assert 'count hit_80 if pkt.proto == tcp and pkt.dst_port == 80' in planted
  rows = sweep_lib.read_receipts(receipt)
  assert rows and rows[0]['applied'] is True

def test_a_pattern_that_does_not_match_is_recorded_as_not_applied(
    tmp_path, monkeypatch):
  """The `unrunnable` verdict rests entirely on this.

  A plant that silently failed to apply, counted as applied, turns every
  green run into a false vacuity finding and every red run into a false
  discrimination.
  """
  fw = tmp_path / 'p.fw'
  fw.write_text(POLICY)
  step = sweep_lib.PolicySub(tag='l1-01', find='no such text',
                             repl='irrelevant')
  _patch_registry(monkeypatch, _plant(tmp_path, step))
  receipt = str(tmp_path / 'r.jsonl')
  argv = sweep_lib.rewrite_argv(
      'fake', 'p1',
      ['compile', '--bundle', '/x/v-hw-l1-01-99', str(fw)],
      receipt, str(tmp_path / 'plants'))
  assert argv[-1] == str(fw)
  rows = sweep_lib.read_receipts(receipt)
  assert rows and rows[0]['applied'] is False
  assert 'did not match' in rows[0]['detail']

def test_the_smoke_bundle_is_never_planted(tmp_path, monkeypatch):
  """hw::restore_smoke must always compile the operator's real policy."""
  fw = tmp_path / 'rules.fw'
  fw.write_text(POLICY)
  step = sweep_lib.PolicySub(tag='*', find='default drop',
                             repl='default allow')
  _patch_registry(monkeypatch, _plant(tmp_path, step))
  receipt = str(tmp_path / 'r.jsonl')
  for bundle in ['/usr/share/f/compiled/v-smoke',
                 '/usr/share/f/compiled/v-office']:
    argv = sweep_lib.rewrite_argv(
        'fake', 'p1', ['compile', '--bundle', bundle, str(fw)],
        receipt, str(tmp_path / 'plants'))
    assert argv[-1] == str(fw), bundle
  assert sweep_lib.read_receipts(receipt) == []

def test_a_flag_named_file_can_be_planted(tmp_path, monkeypatch):
  """The geoip trie data is reachable only through its own flag."""
  data = tmp_path / 'geo.json'
  data.write_text('{"DE": ["10.99.77.0/24"]}')
  fw = tmp_path / 'p.fw'
  fw.write_text(POLICY)
  step = sweep_lib.PolicySub(tag='l1-09', flag='--geoip',
                             find='10.99.77.0/24', repl='10.99.78.0/24')
  _patch_registry(monkeypatch, _plant(tmp_path, step))
  argv = sweep_lib.rewrite_argv(
      'fake', 'p1',
      ['compile', '--bundle', '/x/v-hw-l1-09-1', '--geoip', str(data),
       str(fw)],
      str(tmp_path / 'r.jsonl'), str(tmp_path / 'plants'))
  assert argv[-1] == str(fw)
  assert '10.99.78.0/24' in open(argv[argv.index('--geoip') + 1]).read()

def test_a_plant_only_touches_the_deploy_it_names(tmp_path, monkeypatch):
  fw = tmp_path / 'p.fw'
  fw.write_text(POLICY)
  step = sweep_lib.PolicySub(tag='l1-02a', find='default drop',
                             repl='default allow')
  _patch_registry(monkeypatch, _plant(tmp_path, step))
  argv = sweep_lib.rewrite_argv(
      'fake', 'p1', ['compile', '--bundle', '/x/v-hw-l1-02b-7', str(fw)],
      str(tmp_path / 'r.jsonl'), str(tmp_path / 'plants'))
  assert argv[-1] == str(fw)

# --- check keys and history ------------------------------------------

def test_a_check_key_survives_a_changed_measurement():
  """hwlib embeds the value: "counter hit_80 = 100". The key must not."""
  a = sweep_lib.normalise_check('counter hit_80 = 100')
  b = sweep_lib.normalise_check('counter hit_80 = 0')
  assert a == b == 'counter hit_80'

def test_parse_checks_reads_both_colours():
  out = ('[l1_01] PASS: counter hit_80 = 100\n'
         '[l1_01] FAIL: wire tcp:80 passed = 0, expected 100\n'
         '[l1_01] NOTE: something observed\n')
  checks, order = sweep_lib.parse_checks(out)
  assert checks['counter hit_80'] == 'PASS'
  assert checks['wire tcp:80 passed'] == 'FAIL'
  # A NOTE is a recording, not a verdict, and must not enter the history
  # as a permanently-green check.
  assert not any('something observed' in k for k in checks)
  assert len(order) == 2

def test_a_label_asserted_twice_is_red_if_either_instance_failed():
  out = ('[l1_07] PASS: round_frames = 70\n'
         '[l1_07] FAIL: round_frames = 90, expected 100\n')
  checks, _ = sweep_lib.parse_checks(out)
  assert checks['round_frames'] == 'FAIL'

def test_history_names_the_check_that_is_never_red(tmp_path):
  hist = sweep_lib.History(str(tmp_path / 'h.jsonl'))
  for _ in range(3):
    hist.record('s', 'baseline', 0, 'pass',
                {'always green': 'PASS', 'moves': 'PASS'})
  hist.record('s', 'sabotage:p', 1, 'discriminating',
              {'always green': 'PASS', 'moves': 'FAIL'})
  inv = hist.invariant_checks(min_runs=3)
  names = [row['check'] for row in inv['never_red']]
  assert 'always green' in names
  assert 'moves' not in names

def test_history_names_the_regress_shape(tmp_path):
  """A check that is red as its normal colour hides the next regression."""
  hist = sweep_lib.History(str(tmp_path / 'h.jsonl'))
  for _ in range(4):
    hist.record('soak', 'baseline', 1, 'fail', {'regress': 'FAIL'})
  inv = hist.invariant_checks(min_runs=3)
  assert [row['check'] for row in inv['never_green']] == ['regress']

# --- witness classification ------------------------------------------

def test_a_real_socket_outranks_a_promiscuous_tap(tmp_path):
  weak = tmp_path / 'weak.sh'
  weak.write_text('hw::sniff_get udp:1.2.3.4:53\nhw::counter seen\n')
  strong = tmp_path / 'strong.sh'
  strong.write_text('hw::sniff_get udp:1.2.3.4:53\nhw::server_get accepted\n')
  assert sweep_lib.classify_witness(str(weak))['strongest'] == \
      'sniffer_promisc'
  assert sweep_lib.classify_witness(str(strong))['strongest'] == \
      'real_socket'
  assert sweep_lib.classify_witness(str(strong))['rank'] > \
      sweep_lib.classify_witness(str(weak))['rank']

def test_a_witness_named_only_in_a_comment_does_not_count(tmp_path):
  """A file that explains why it does NOT use a real socket still has a
  weak witness, and must be classified by its code."""
  path = tmp_path / 's.sh'
  path.write_text('# a real socket (hw::server_get) cannot see this\n'
                  'hw::sniff_get udp:1.2.3.4:53\n')
  assert sweep_lib.classify_witness(str(path))['strongest'] == \
      'sniffer_promisc'

# --- static lint ------------------------------------------------------

UNFALSIFIABLE = '''if [ "$X" -gt 0 ]; then
  pass "one thing happened"
else
  pass "the other thing happened"
fi
'''

FALSIFIABLE = '''if [ "$X" -gt 0 ]; then
  pass "it held"
else
  fail "it did not"
fi
'''

ELIF_WITH_A_FAIL = '''if [ "$X" = a ]; then
  fail "the bad case"
elif [ "$X" = b ]; then
  pass "one good case"
else
  pass "the other good case"
fi
'''

EMBEDDED_PYTHON = '''if [ "$X" -gt 0 ]; then
  $PY -c "
try:
  go()
except Exception:
  pass
"
  fail "it went wrong"
else
  pass "fine"
fi
'''

@pytest.mark.parametrize('source,expected', [
    (UNFALSIFIABLE, 1),
    (FALSIFIABLE, 0),
    # An elif branch belongs to the enclosing conditional; counting it as
    # a new one splits an if/elif/else whose FIRST branch fails into a
    # fail-free tail and reports a false positive.
    (ELIF_WITH_A_FAIL, 0),
    # A bare `pass` inside an embedded Python heredoc is not a verdict.
    (EMBEDDED_PYTHON, 0),
])
def test_lint_finds_only_the_checks_that_cannot_fail(tmp_path, source,
                                                     expected):
  path = tmp_path / 's.sh'
  path.write_text(source)
  assert len(sweep_lib.lint_unfalsifiable(str(path))) == expected

# --- the registry itself ---------------------------------------------

def test_every_hardware_scenario_is_declared_in_the_registry():
  """A scenario nobody planted a defect in is a scenario nobody asked."""
  import glob
  scripts = {os.path.basename(p)[:-3]
             for p in glob.glob(os.path.join(HW, 'l*.sh'))}
  registry = set(sweep_lib._load_registry())
  assert scripts - registry == set(), 'scenarios with no sweep entry'
  assert registry - scripts == set(), 'sweep entries with no scenario'

def test_every_entry_has_a_plant_or_a_declared_reason():
  for name, scen in sweep_lib._load_registry().items():
    assert scen.plants or scen.declared, name
    assert scen.subject, name

def test_every_weak_witness_scenario_justifies_itself():
  """The classification is only worth having if the weak ones say why.

  Six of the nine NAT scenarios kept the promiscuous sniffer for a good
  reason and three did not, and nothing in the files said which was
  which.
  """
  unjustified = []
  for name, scen in sweep_lib._load_registry().items():
    path = os.path.join(HW, name + '.sh')
    if not os.path.exists(path):
      continue
    if sweep_lib.classify_witness(path)['rank'] <= 2 and not \
       scen.witness_note:
      unjustified.append(name)
  assert unjustified == []
