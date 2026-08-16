"""Unit tests for the gateway soak's own instruments.

A soak runs unattended for days and nobody reads it while it runs, so
the two ways it can be worthless are both silent: a generator that
manufactures the symptom the soak watches for, and a report that cannot
go red. Both are asserted here.

  The generator's frames must be VALID on the wire. The NAT rewrite
    updates the L4 checksum incrementally, so a wrong value going in
    stays wrong going out and every translated frame would be recorded
    as corrupt — a bench artefact indistinguishable from the defect.

  The churn must stay inside the black-holed /22 and inside its own
    zone's /24. Outside the first, the box solicits addresses that
    never answer and `no_neigh` climbs forever, which is exactly the
    reading a long run exists to take. Outside the second, the
    masquerade predicate stops matching and the churn silently stops
    being NAT load at all. Byte offsets were wrong on the first
    writing, and reading them did not find it.

  `verify_probe` must go red for each delivery failure separately, and
    must go red on an ABSENT report rather than treating a missing
    field as a zero that happens to satisfy nothing.

  The report must exit non-zero on drift. That is the property the
    whole soak's evidential value rests on.
"""
import ipaddress
import json
import os
import socket
import struct
import subprocess
import sys
import pytest

HW = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                  "system", "hw")
sys.path.insert(0, HW)
gwsoak = pytest.importorskip("gwsoak")
traffic = pytest.importorskip("gwsoak_traffic")
report = pytest.importorskip("gwsoak_report")
sniff = pytest.importorskip("sniff")

CHURN_NET = ipaddress.ip_network(gwsoak.CHURN_NET)


def test_the_generator_emits_frames_a_real_stack_accepts():
  """Every builder the generator sends must carry valid checksums."""
  builders = [
    f'tcp(src_ip="{gwsoak.GUEST_A}", dst_ip="{gwsoak.SERVER}", '
    f'src_port=41000, dst_port=443, syn=true)',
    'udp(src_ip="10.99.31.201", dst_port=9999)',
    'udp(src_ip="10.99.31.202", dst_port=137)',
    'udp(src_ip="10.99.31.203", dst_ip="239.255.255.250", '
    'dst_port=1900)',
    'udp(src_ip="10.99.60.5", dst_port=7000)',
    f'tcp(src_ip="{gwsoak.SERVER}", dst_ip="{gwsoak.MASQ_ADDR}", '
    f'src_port=443, dst_port=41000, ack=true)',
  ]
  for builder in builders:
    frame = traffic._frame(builder)
    before = bytes(frame)
    traffic.fix_csums(frame)
    assert bytes(frame) == before, f"fix_csums changed {builder}"
    assert sniff.checksums_ok(bytes(frame), 14), builder


def _walk_churn(zone_key, churned):
  """Exercise the SHIPPED arithmetic, never a copy of it."""
  zone = traffic.ZONES[zone_key]
  frame = traffic._frame(
    f'tcp(src_ip="{zone["net"]}.100", dst_ip="10.99.240.1", '
    f'src_port=1024, dst_port=443, syn=true)')
  traffic.patch_churn(frame, zone, churned)
  return (ipaddress.ip_address(socket.inet_ntoa(bytes(frame[26:30]))),
          ipaddress.ip_address(socket.inet_ntoa(bytes(frame[30:34]))),
          struct.unpack_from(">H", frame, 34)[0],
          sniff.checksums_ok(bytes(frame), 14))


@pytest.mark.parametrize("zone_key", sorted(traffic.ZONES))
def test_churn_stays_in_the_black_hole_and_in_its_own_zone(zone_key):
  own = ipaddress.ip_network(traffic.ZONES[zone_key]["net"] + ".0/24")
  for churned in list(range(0, 2048)) + [27999, 28000, 1 << 20]:
    src, dst, _sport, ok = _walk_churn(zone_key, churned)
    assert src in own, f"churn {churned} left {own} with {src}"
    assert dst in CHURN_NET, f"churn {churned} left {CHURN_NET}: {dst}"
    assert ok, f"churn {churned} carries a bad checksum"


def test_the_two_zones_churn_on_disjoint_translated_ports():
  """Both zones masquerade to ONE address, so a shared source-port
  sequence to a shared destination sequence collides on every churn
  flow — measured at 462 reallocations in 90 s before the ranges were
  separated. Half the churn was then spent proving the collision path
  instead of filling the table at the rate on the label."""
  seen = {}
  for zone_key in traffic.ZONES:
    for churned in range(0, 3000):
      _src, dst, sport, _ok = _walk_churn(zone_key, churned)
      key = (str(dst), sport)
      assert key not in seen or seen[key] == zone_key, (
        f"{zone_key} churn {churned} collides with {seen.get(key)} "
        f"on {key}")
      seen[key] = zone_key


def test_the_two_zones_cannot_collide_on_a_translated_port():
  """Disjoint source-port ranges, by construction.

  Two guests behind one masquerade address wanting the same port is
  legal and handled, but it would move the port the reply injector
  addresses — so the generator must not create the case it would then
  be unable to follow.
  """
  ranges = []
  for zone in traffic.ZONES.values():
    base = zone["sport"]
    ranges.append(set(range(base, base + traffic.STEADY_FLOWS)))
  for i, first in enumerate(ranges):
    for second in ranges[i + 1:]:
      assert not first & second


def _good_probe():
  want = gwsoak.CONNS_PER_ZONE
  return {
    "want_per_zone": want,
    "masq_addr": gwsoak.MASQ_ADDR,
    "a": {"completed": want, "connected": want},
    "b": {"completed": want, "connected": want},
    "srv": {"accepted": want * 2, "echoed": want * 2,
            "peer_addrs": [gwsoak.MASQ_ADDR]},
    "box": {"completed": 1},
    "boxsrv": {"accepted": 1, "echoed": 1,
               "peer_addrs": [gwsoak.MASQ_ADDR]},
  }


def test_a_working_gateway_produces_no_wire_problem():
  assert gwsoak.verify_probe(_good_probe()) == []


def test_an_absent_report_is_never_a_pass():
  """The vacuity guard: a probe that did not run must go red.

  A missing field read as zero, against a check written as "no errors",
  is how a phase once recorded a refusal proven by a box that had not
  spoken.
  """
  assert gwsoak.verify_probe({})
  assert gwsoak.verify_probe({"a": {}, "b": {}, "srv": {}, "box": {}})


@pytest.mark.parametrize("break_it,expect", [
  (lambda p: p["a"].update(completed=0), "zone a"),
  (lambda p: p["b"].update(completed=1), "zone b"),
  (lambda p: p["srv"].update(accepted=3), "accepted"),
  (lambda p: p["srv"].update(echoed=0), "echoed"),
  (lambda p: p["srv"].update(peer_addrs=["10.99.31.5"]), "peers"),
  (lambda p: p["srv"].update(
    peer_addrs=["10.99.210.2", "10.99.31.5"]), "peers"),
  (lambda p: p["box"].update(completed=0), "egress tracker"),
  (lambda p: p["boxsrv"].update(accepted=0), "box's own flow"),
])
def test_each_delivery_failure_is_named_on_its_own(break_it, expect):
  probe = _good_probe()
  break_it(probe)
  problems = gwsoak.verify_probe(probe)
  assert problems, f"{expect}: nothing went red"
  assert any(expect in p for p in problems), problems


def test_an_untranslated_source_on_the_far_side_is_a_failure():
  """The masquerade's whole point, asserted from the far side.

  The far side's own kernel must name the uplink address and no other.
  A second address in that list is a guest whose source was never
  translated — which is precisely what a promiscuous sniffer cannot
  tell you and a real socket can.
  """
  probe = _good_probe()
  probe["srv"]["peer_addrs"] = ["10.99.31.5", "10.99.32.5"]
  assert gwsoak.verify_probe(probe)


class _FakeProc:
  """Stands in for a realsock.py child, reporting a healthy exchange."""

  def __init__(self, payload):
    self.stdout = json.dumps(payload) + "\n"
    self.returncode = 0

  def communicate(self, timeout=None):
    return (self.stdout, "")


def test_probe_plumbing_holds_together_without_hardware(monkeypatch):
  """The wiring, asserted where a bench is not needed.

  `probe()` spawns five processes across three namespaces and reads
  five reports back. Two shipped defects in that plumbing — a
  keyword-only argument nobody passed, and children spawned without the
  PYTHONPATH the rig has no other way to supply — both reached the rig
  before anything noticed, because the only thing that ran this code
  was the rig. This runs it here.
  """
  spawned = []

  def fake_popen(cmd, **kw):
    spawned.append((cmd, kw))
    port = int(cmd[cmd.index("server") + 2])
    want = gwsoak.CONNS_PER_ZONE * 2 if port == gwsoak.PORT_GUEST else 1
    return _FakeProc({"accepted": want, "echoed": want,
                      "peers": [], "peer_addrs": [gwsoak.MASQ_ADDR]})

  def fake_run(args, check=False, ns=None, timeout=120):
    spawned.append((args, {"ns": ns}))
    want = gwsoak.CONNS_PER_ZONE if ns else 1
    return _FakeProc({"attempted": want, "connected": want,
                      "completed": want, "errors": []})

  monkeypatch.setattr(gwsoak.subprocess, "Popen", fake_popen)
  monkeypatch.setattr(gwsoak, "run", fake_run)
  monkeypatch.setattr(gwsoak.time, "sleep", lambda _s: None)
  result = gwsoak.probe()
  assert gwsoak.verify_probe(result) == []
  # Every child must be able to import fwl: on the rig there is no pip
  # and no venv, and PYTHONPATH is the only route to the package.
  for _cmd, kw in spawned:
    if "env" in kw:
      assert "/opt/fwl" in kw["env"]["PYTHONPATH"]
  assert "/opt/fwl-deps" in gwsoak.child_env()["PYTHONPATH"]


def test_both_bpftool_spellings_of_a_number_are_read():
  """`map dump` gives integers; `-j map dump` gives hex byte lists.

  Reading one spelling turned every counter in the first run into -1.
  The report DID fail on it, which is the instrument being honest —
  but it named an absent counter rather than a parser, so both
  spellings are handled and both are asserted.
  """
  assert gwsoak._as_int(6989) == 6989
  assert gwsoak._as_int(["0xad", "0x1b", "0x00", "0x00"]) == 0x1BAD
  assert gwsoak._as_int(
    ["0x00"] * 4) == 0
  assert gwsoak._as_int(
    ["0xd6", "0x34", "0x00", "0x00", "0x00", "0x00", "0x00",
     "0x00"]) == 0x34D6


def test_a_bridged_share_of_the_forwards_fails_but_a_stray_does_not(
    tmp_path):
  """A routed forward that silently became an L2 hand-off."""
  samples = [_sample(i) for i in range(20)]
  for i, sample in enumerate(samples):
    sample["route"]["bridged"] = 3 * i
  path = _write_log(tmp_path, samples)
  proc = _run_report(path)
  assert proc.returncode == 0, proc.stdout
  for i, sample in enumerate(samples):
    sample["route"]["bridged"] = 900 * i
  path = _write_log(tmp_path, samples)
  proc = _run_report(path)
  assert proc.returncode == 1
  assert "L2-adjacent fallback" in proc.stdout


def test_creep_detection_tells_a_plateau_from_a_climb():
  flat = [1500 + (i % 40) for i in range(60)]
  crept, _, _ = report.creeping(flat)
  assert not crept
  climbing = [100 * i for i in range(60)]
  crept, mid, end = report.creeping(climbing)
  assert crept and end > mid
  # Too short to judge is neither: a run nobody has watched yet must
  # not be reported as plateaued.
  assert report.creeping([1, 2, 3])[0] is False


def _sample(index, **over):
  """One structurally complete sample of a healthy run."""
  minute = f"2026-08-16T12:{index:02d}:00Z"
  sample = {
    "ts": minute,
    "boot_id": "b0",
    "uptime_s": 1000 + index * 60,
    "counters": {"a_masq": 100 * (index + 1),
                 "b_masq": 90 * (index + 1),
                 "w_est": 50 * (index + 1),
                 "a_total": 500 * (index + 1)},
    "nat": {"entries": 1500, "total_reclaimed": 10 * index,
            "refused": 0, "table_full": 0, "occupancy_pct": 2},
    "conntrack": {"entries": 3000, "total_evicted": 20 * index},
    "egress": {"attached": 3, "tracked": index + 1, "refused": 0},
    "route": {"routed": 1000 * (index + 1), "bridged": 0,
              "no_neigh": 2, "forwarding_overridden": False},
    "xdp_ifaces": 3,
    "fd": {"active": "active", "rss_kb": 8400, "nrestarts": 0,
           "err_5min": 0},
    "traffic_active": ["active", "active", "active"],
    "linkup_total": 6,
    "sys": {"soc_temp_mC": 52000, "i350_die_mC": 68000},
    "probe": _good_probe(),
  }
  sample.update(over)
  return sample


def _write_log(tmp_path, samples):
  path = tmp_path / "gwsoak.jsonl"
  with open(path, "w") as fh:
    for sample in samples:
      fh.write(json.dumps(sample) + "\n")
  return str(path)


def _run_report(path):
  return subprocess.run(
    [sys.executable, os.path.join(HW, "gwsoak_report.py"), path],
    capture_output=True, text=True)


def test_the_report_passes_a_clean_run(tmp_path):
  path = _write_log(tmp_path, [_sample(i) for i in range(20)])
  proc = _run_report(path)
  assert proc.returncode == 0, proc.stdout + proc.stderr
  assert "VERDICT: PASS" in proc.stdout


def test_the_report_cannot_reach_a_verdict_without_samples(tmp_path):
  path = _write_log(tmp_path, [_sample(0)])
  assert _run_report(path).returncode == 2
  assert _run_report(str(tmp_path / "nothing.jsonl")).returncode == 2


@pytest.mark.parametrize("index,mutate,expect", [
  (10, lambda s: s["probe"]["a"].update(completed=0), "wire claim"),
  (10, lambda s: s["counters"].update(a_masq=1), "backwards"),
  (10, lambda s: s["counters"].pop("w_est"), "ABSENT"),
  (10, lambda s: s["fd"].update(nrestarts=1), "restarted"),
  (10, lambda s: s["fd"].update(active="failed"), "not active"),
  (10, lambda s: s["fd"].update(err_5min=3), "at the error level"),
  (10, lambda s: s.update(boot_id="b1"), "rebooted"),
  (10, lambda s: s["egress"].update(attached=2), "every interface"),
  (10, lambda s: s["egress"].update(refused=5), "refused"),
  (10, lambda s: s.update(linkup_total=9), "link-up"),
  (10, lambda s: s["route"].update(forwarding_overridden=True),
   "behind fd's back"),
  (10, lambda s: s["traffic_active"].__setitem__(1, "inactive"),
   "traffic generator"),
  (10, lambda s: s["nat"].update(refused=7), "nat.refused"),
  (10, lambda s: s["sys"].update(i350_die_mC=95000), "i350 die"),
])
def test_every_drift_makes_the_report_exit_non_zero(
    tmp_path, index, mutate, expect):
  samples = [_sample(i) for i in range(20)]
  for later in samples[index:]:
    mutate(later)
  path = _write_log(tmp_path, samples)
  proc = _run_report(path)
  assert proc.returncode == 1, f"{expect}: {proc.stdout}"
  assert expect in proc.stdout, proc.stdout


def test_a_table_that_never_plateaus_fails(tmp_path):
  samples = [_sample(i) for i in range(60)]
  for i, sample in enumerate(samples):
    sample["nat"]["entries"] = 500 + 300 * i
  path = _write_log(tmp_path, samples)
  proc = _run_report(path)
  assert proc.returncode == 1
  assert "still climbing" in proc.stdout


def test_a_next_hop_lost_again_after_the_box_is_warm_fails(tmp_path):
  """The reading a long run can take and a short one cannot."""
  samples = [_sample(i) for i in range(40)]
  for sample in samples[30:]:
    sample["route"]["no_neigh"] = 9
  path = _write_log(tmp_path, samples)
  proc = _run_report(path)
  assert proc.returncode == 1
  assert "re-lost a next hop" in proc.stdout


def test_a_stalled_egress_tracker_fails(tmp_path):
  """Every sample opens exactly one new box-originated flow, so a
  tracker that stopped counting them is a tracker that stopped."""
  samples = [_sample(i) for i in range(20)]
  for sample in samples[10:]:
    sample["egress"]["tracked"] = 11
  path = _write_log(tmp_path, samples)
  proc = _run_report(path)
  assert proc.returncode == 1
  assert "no NEW box-originated flow" in proc.stdout


def test_one_reused_ephemeral_port_is_not_a_stalled_tracker(tmp_path):
  """A stall is a RUN. One non-increase is a refresh, not a defect,
  and failing a 96 h run on it would make the check about luck."""
  samples = [_sample(i) for i in range(20)]
  for sample in samples[10:]:
    sample["egress"]["tracked"] -= 1
  path = _write_log(tmp_path, samples)
  proc = _run_report(path)
  assert proc.returncode == 0, proc.stdout
  assert "isolated sample" in proc.stdout


def test_the_body_s_view_of_a_denated_frame_is_recorded(tmp_path):
  """The finding is a NOTE with two numbers, never a green check.

  One counter at zero proves nothing; the pair — the pre-de-NAT
  address on nearly every frame, an inside address on none — is what
  says which address the BODY saw.
  """
  samples = [_sample(i) for i in range(20)]
  for i, sample in enumerate(samples):
    sample["counters"].update(w_total=500 * (i + 1),
                              w_pre_denat=498 * (i + 1),
                              w_to_a=0, w_to_b=0)
  path = _write_log(tmp_path, samples)
  proc = _run_report(path)
  assert proc.returncode == 0, proc.stdout
  assert "PRE-de-NAT destination" in proc.stdout
  assert "an inside address on 0" in proc.stdout


def test_a_sampling_gap_fails(tmp_path):
  samples = [_sample(i) for i in range(20)]
  samples[10]["ts"] = "2026-08-16T13:30:00Z"
  for i, sample in enumerate(samples[11:], start=31):
    sample["ts"] = f"2026-08-16T13:{i:02d}:00Z"
  path = _write_log(tmp_path, samples)
  proc = _run_report(path)
  assert proc.returncode == 1
  assert "sampling gap" in proc.stdout


def test_the_policy_declares_every_counter_the_report_names():
  """The report reads counters BY NAME; the names have to exist."""
  with open(os.path.join(HW, "gwsoak_policy.fw")) as fh:
    policy = fh.read()
  for name in ("a_masq", "b_masq", "w_est", "w_pre_denat", "w_to_a",
               "w_to_b"):
    assert f"count {name} " in policy, name
  # Both inside zones must redirect to the ONE uplink: that is the
  # bundle that could not load, and the masquerade address that was a
  # single bundle-global slot.
  assert policy.count("redirect to wanz if") == 2
  assert "conntrack(pkt).state in [established, related]" in policy
  # And the uplink must NOT carry a return-path redirect: the prelude
  # caches dst_ip before the de-NAT pass rewrites it, so such a rule
  # can never match and a soak policy is the most-copied policy there
  # is. Asked of the RULES, not of the file — the comment explaining
  # why the rule is absent quotes the rule.
  rules = [ln for ln in policy.splitlines()
           if ln.strip() and not ln.lstrip().startswith("#")]
  assert not [ln for ln in rules if "redirect to ina" in ln]
  assert not [ln for ln in rules if "redirect to inb" in ln]
