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
import datetime
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
_BASE_TS = datetime.datetime(2026, 8, 16, 12, 0, 0)


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
  minute = (_BASE_TS + datetime.timedelta(minutes=index)).strftime(
    "%Y-%m-%dT%H:%M:%SZ")
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


def test_the_warm_up_window_does_not_grow_with_the_run(tmp_path):
  """A tenth of a 96 h run is nine hours.

  Scaling the warm-up with the sample count would swallow a next hop
  re-lost at hour five, which is precisely the event a long run exists
  to catch. `start` pings every next hop it routes to before the first
  sample, so the box is warm in minutes and the window is capped.
  """
  samples = [_sample(i) for i in range(600)]
  for sample in samples[40:]:
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


# --- epoch 2: the Tier 2 half -----------------------------------------
#
# `gwsoak.py append` widens a RUNNING soak onto the Tier 2 emission
# path by a deliberate hot reload. Two things have to hold for that to
# be safe, and both are checked here rather than argued: the Tier 1
# half of the policy does not change at all, and the report can tell
# the two halves apart and still go red on drift inside either.

def _policy(name):
  with open(os.path.join(HW, name)) as fh:
    return fh.read()


def test_the_epoch_2_policy_contains_the_epoch_1_zones_verbatim():
  """The append must not change what is already being measured.

  Not "looks the same": the three `@xdp` blocks of the running policy
  have to appear as one unbroken run of bytes inside the epoch-2 file.
  `tier2_gateway_netns.py` takes this the rest of the way and compares
  the EMITTED objects on a VM; this is the cheap half that runs in CI.
  """
  one, two = _policy("gwsoak_policy.fw"), _policy("gwsoak_policy_t2.fw")
  body = one[one.index("# --- inside zone A"):]
  assert body in two, "the epoch-1 zones are not verbatim in epoch 2"
  # And the Tier 2 half is genuinely additive: everything after the
  # epoch-1 body is new, and nothing before it was deleted.
  assert two.index(body) < two.index("@xdp(inc)")
  for zone in ("ina", "inb", "wanz"):
    assert two.count(f"@xdp({zone})") == 1


def test_the_epoch_2_policy_avoids_what_tier_2_cannot_do():
  """Constructs the language forbids, or emits as a stub, stay out."""
  two = _policy("gwsoak_policy_t2.fw")
  rules = [ln for ln in two.splitlines()
           if ln.strip() and not ln.lstrip().startswith("#")]
  tier2 = rules[rules.index("@xdp(inc)"):]
  body = "\n".join(tier2)
  # Tier 2 rate_limit emits `(0)`; `chain` is refused in a def body;
  # `log(sample=N)` has no Tier 2 form. None may appear in the Tier 2
  # zones, and the shared helper may carry none of rate_limit, geoip
  # or pkt.zone at all.
  for forbidden in ("rate_limit", "chain ", "log(", "geoip(",
                    "pkt.zone"):
    assert forbidden not in body, forbidden
  helper = two[two.index("def t2_noise(pkt):"):two.index("@xdp(ina)")]
  for forbidden in ("rate_limit", "geoip(", "pkt.zone"):
    assert forbidden not in helper, forbidden
  # The helper must be declared BEFORE the first @xdp block: a `def`
  # written after one is absorbed as that zone's own function, with no
  # diagnostic, and the call would silently vanish.
  assert two.index("def t2_noise(pkt):") < two.index("@xdp(ina)")


def test_the_shared_helper_is_reached_from_more_than_one_zone():
  """§ 6.5 is only exercised when two zones call the same helper."""
  two = _policy("gwsoak_policy_t2.fw")
  rules = [ln.strip() for ln in two.splitlines()
           if ln.strip() and not ln.lstrip().startswith("#")]
  assert rules.count("t2_noise(pkt)") == 2


def test_the_tier_2_identity_covers_every_leaf_the_policy_counts():
  """Every counter the Tier 2 zones declare is in the identity.

  The identity is what the report checks every sample, so a leaf left
  out of it is a branch nothing watches. `c_syn` is deliberately not a
  leaf — it is a SUBSET of `c_workload`, and adding it would make the
  sum wrong on purpose — so it is named here rather than excluded by
  an accident that reads the same.
  """
  two = _policy("gwsoak_policy_t2.fw")
  tier2 = two[two.index("@xdp(inc)"):]
  declared = {ln.split()[1] for ln in tier2.splitlines()
              if ln.strip().startswith("count ")}
  helper = two[two.index("def t2_noise(pkt):"):two.index("@xdp(ina)")]
  declared |= {ln.split()[1] for ln in helper.splitlines()
               if ln.strip().startswith("count ")}
  in_identity = set()
  for total, leaves in gwsoak.EPOCHS[2]["identities"]:
    in_identity.add(total)
    in_identity |= {leaf.split(".")[-1] for leaf in leaves}
  assert declared - in_identity == {"c_syn", "d_syn"}
  assert not in_identity - declared


def test_the_tier_2_generator_sends_exactly_what_the_identity_expects():
  """The shipped frame mix, walked against the policy's branches."""
  frames = traffic.t2_frames(traffic.T2_ZONES["c"], "", "")
  assert len(frames) == 10
  for frame in frames:
    assert sniff.checksums_ok(frame, 14), frame.hex()
  # One frame per cycle must be OFF-NET, so the source guard is
  # witnessed rejecting as well as admitting. A guard that stopped
  # discriminating reads as c_offnet flat at zero.
  offnet = [f for f in frames
            if socket.inet_ntoa(f[26:30]) == traffic.OFFNET_SRC]
  assert len(offnet) == 1
  guests = [f for f in frames
            if socket.inet_ntoa(f[26:30]).startswith("10.99.33.")]
  assert len(guests) == 9


def test_a_duplicated_counter_name_is_read_once_per_zone(monkeypatch):
  """A shared helper's counter lands in EVERY calling zone's map.

  The older reader wrote both zones to one dictionary key and kept
  whichever it read last, which is exactly the reading that would hide
  a helper that had stopped working in one object.
  """
  slots = {"inc": {"c_total": 0, "t2_mcast": 1},
           "ind": {"d_total": 0, "t2_mcast": 1}}
  dumps = {"inc": [{"key": 0, "values": [{"value": 7}]},
                   {"key": 1, "values": [{"value": 11}]}],
           "ind": [{"key": 0, "values": [{"value": 9}]},
                   {"key": 1, "values": [{"value": 13}]}]}
  monkeypatch.setattr(gwsoak, "counter_slots", lambda current="": slots)
  monkeypatch.setattr(
    gwsoak, "out",
    lambda args, ns=None, timeout=120: json.dumps(
      dumps[args[-1].rsplit("_", 1)[-1]]))
  values = gwsoak.read_counters()
  assert values == {"c_total": 7, "inc.t2_mcast": 11,
                    "d_total": 9, "ind.t2_mcast": 13}
  # And the epoch-1 spelling is byte-for-byte the old behaviour, so a
  # counter can only change name AT a declared boundary.
  assert gwsoak.read_counters(qualify=False)["t2_mcast"] == 13


def test_the_wire_bar_is_a_property_of_the_epoch_not_of_the_probe():
  """An epoch-1 probe cannot satisfy the epoch-2 bar by omission."""
  probe = _good_probe()
  assert gwsoak.verify_probe(probe, 1) == []
  problems = gwsoak.verify_probe(probe, 2)
  assert any("zone c" in p for p in problems)
  assert any("zone d" in p for p in problems)


# --- the report across a policy boundary -------------------------------

def _good_probe4():
  """The epoch-2 probe: four inside zones, one masquerade address."""
  want = gwsoak.CONNS_PER_ZONE
  probe = _good_probe()
  probe.update({
    "epoch": 2,
    "c": {"completed": want, "connected": want},
    "d": {"completed": want, "connected": want},
    "srv": {"accepted": want * 4, "echoed": want * 4,
            "peer_addrs": [gwsoak.MASQ_ADDR]},
  })
  return probe


def _t2_counters(step):
  """Epoch-2 counters that satisfy the identity by construction."""
  values = {"a_masq": 100 * step, "b_masq": 90 * step,
            "w_est": 50 * step, "a_total": 500 * step}
  for zone, prefix in (("inc", "c"), ("ind", "d")):
    values.update({
      f"{prefix}_total": 10 * step, f"{prefix}_workload": 6 * step,
      f"{prefix}_syn": 6 * step, f"{prefix}_web": 0,
      f"{prefix}_other_tcp": 0, f"{prefix}_udp": step,
      f"{prefix}_other_proto": 0, f"{prefix}_offnet": step,
      f"{zone}.t2_mcast": step, f"{zone}.t2_nbns": step,
    })
  return values


def _sample2(index, **over):
  """One epoch-2 sample. Every POLICY-lifetime tally restarts at the
  boundary, exactly as a hot reload leaves them; everything that is
  one fact about fd carries straight on."""
  sample = _sample(index)
  step = index - 19
  sample.update({
    "epoch": 2,
    "policy_sha": "deadbeef" * 8,
    "counters": _t2_counters(step),
    "probe": _good_probe4(),
    "xdp_ifaces": 5,
    "traffic_active": ["active"] * 5,
  })
  sample["egress"] = {"attached": 5, "tracked": step, "refused": 0}
  sample["route"] = {"routed": 1000 * step, "bridged": 0,
                     "no_neigh": 1, "forwarding_overridden": False}
  sample["nat"] = {"entries": 1500, "total_reclaimed": 10 * step,
                   "refused": 0, "table_full": 0, "occupancy_pct": 2}
  sample["conntrack"] = {"entries": 3000, "total_evicted": 20 * step}
  sample.update(over)
  return sample


def _two_epoch_log(tmp_path, mutate=None, epoch2=20):
  samples = ([_sample(i) for i in range(epoch2)]
             + [_sample2(i) for i in range(epoch2, epoch2 + 20)])
  if mutate:
    mutate(samples)
  return _write_log(tmp_path, samples)


def test_a_declared_policy_change_is_readable_and_still_a_pass(
    tmp_path):
  """The whole point: a hot reload zeroes every POLICY-lifetime map,
  and a run that says where it happened is still judgeable."""
  proc = _run_report(_two_epoch_log(tmp_path))
  assert proc.returncode == 0, proc.stdout + proc.stderr
  assert "2 epoch(s), CHANGED MID-RUN" in proc.stdout
  assert "epoch 1:" in proc.stdout and "epoch 2:" in proc.stdout
  # Both halves are named, and the reader is told which numbers are
  # per-epoch and which are not.
  assert "judged INSIDE each epoch" in proc.stdout
  assert "in each of the 2 policy epochs" in proc.stdout


def test_an_undeclared_reload_is_not_forgiven(tmp_path):
  """Counters reset without the epoch moving is still every counter
  going backwards at once, and still a FAIL. The boundary is a
  declaration, not an amnesty."""
  def strip_epoch(samples):
    for sample in samples[20:]:
      sample.pop("epoch")
      sample["counters"] = {k: v for k, v in sample["counters"].items()
                            if k in ("a_masq", "b_masq", "w_est",
                                     "a_total")}
  proc = _run_report(_two_epoch_log(tmp_path, strip_epoch))
  assert proc.returncode == 1
  assert "went backwards" in proc.stdout


@pytest.mark.parametrize("mutate,expect", [
  # A daemon fact is judged across the WHOLE run: a policy change must
  # never become a way to hide one.
  (lambda s: s["fd"].update(nrestarts=1), "restarted"),
  (lambda s: s.update(boot_id="b1"), "rebooted"),
  (lambda s: s["fd"].update(err_5min=4), "at the error level"),
  (lambda s: s.update(linkup_total=9), "link-up"),
  # The Tier 2 claims themselves.
  (lambda s: s["probe"]["c"].update(completed=0), "wire claim"),
  (lambda s: s["counters"].pop("inc.t2_mcast"), "ABSENT"),
  (lambda s: s["counters"].update(c_offnet=0), "backwards"),
  (lambda s: s["counters"].update(
    c_total=s["counters"]["c_total"] + 999), "ran AHEAD"),
  (lambda s: s["egress"].update(attached=4), "every interface"),
], ids=["fd-restart", "reboot", "journal-error", "link-flap",
        "zone-c-wire", "helper-counter-gone", "counter-backwards",
        "identity-broken", "egress-short"])
def test_drift_in_the_second_half_still_fails(tmp_path, mutate,
                                              expect):
  """Every plant is applied from sample 25 onward — which is inside
  epoch 2 — and every one of them must still be named."""
  def apply(samples):
    for sample in samples[25:]:
      mutate(sample)
  proc = _run_report(_two_epoch_log(tmp_path, apply))
  assert proc.returncode == 1, f"{expect}: {proc.stdout}"
  assert expect in proc.stdout, proc.stdout


def test_a_counter_that_never_moves_in_the_new_epoch_fails(tmp_path):
  """A Tier 2 zone that stopped counting is the failure this half of
  the soak exists to catch. The identity is held intact so that what
  fails is the stall and not the arithmetic."""
  def freeze(samples):
    for sample in samples[20:]:
      counters = sample["counters"]
      counters["c_workload"] = 6
      counters["c_syn"] = 6
      counters["c_total"] = (counters["inc.t2_mcast"]
                             + counters["inc.t2_nbns"] + 6
                             + counters["c_udp"]
                             + counters["c_offnet"])
  proc = _run_report(_two_epoch_log(tmp_path, freeze))
  assert proc.returncode == 1
  assert "did not move across the epoch" in proc.stdout


def test_an_epoch_that_goes_backwards_cannot_support_a_verdict(
    tmp_path):
  def scramble(samples):
    samples[30]["epoch"] = 1
  proc = _run_report(_two_epoch_log(tmp_path, scramble))
  assert proc.returncode == 2
  assert "went backwards or repeated" in proc.stdout


def test_the_first_epoch_needs_no_epoch_field(tmp_path):
  """Samples written before the field existed are epoch 1, and the
  absence is the marker rather than a default worth arguing about."""
  assert report.epoch_of({"ts": "x"}) == gwsoak.FIRST_EPOCH
  assert report.epoch_of({"epoch": 2}) == 2
  blocks = report.segment([{"a": 1}, {"epoch": 1}, {"epoch": 2}])
  assert [e for e, _ in blocks] == [1, 2]
  assert [len(b) for _, b in blocks] == [2, 1]


# --- the Tier 2 identity, and the read that cannot see it atomically --
#
# `bpftool map dump` walks a map's slots in key order and is not a
# snapshot, so a frame arriving mid-dump increments a leaf whose zone
# total has already been read past. Measured on the rig under this
# soak's own load: 800 live dumps, 794 exact, 6 with the leaves ahead
# by at most 7, longest run of consecutive non-zero readings ONE. The
# first spelling of this check demanded exact equality and went red on
# one sample in 130 — honest, but it named the Tier 2 conjunction when
# the cause was the reader.

def test_a_transient_skew_is_the_reader_and_is_not_a_failure(tmp_path):
  """The leaves briefly ahead, back to zero next sample, is a read."""
  def tear(samples):
    for i in (24, 31, 38):
      samples[i]["counters"]["c_workload"] += 5
  proc = _run_report(_two_epoch_log(tmp_path, tear))
  assert proc.returncode == 0, proc.stdout
  assert "closed exactly in" in proc.stdout
  assert "is not atomic across slots" in proc.stdout


def test_a_skew_that_never_comes_back_is_the_datapath(tmp_path):
  """These counters only ever rise, so a frame counted in two leaves
  is a PERMANENT offset. A skew still there ten samples later was in
  the datapath and not in the read."""
  def double_count(samples):
    for sample in samples[25:]:
      sample["counters"]["c_workload"] += 5
  proc = _run_report(_two_epoch_log(tmp_path, double_count))
  assert proc.returncode == 1
  assert "did not close once in 10 consecutive samples" in proc.stdout


def test_a_total_ahead_of_its_leaves_fails_on_one_sample(tmp_path):
  """The direction a non-atomic read CANNOT produce: it can only put
  the leaves ahead. A total ahead of its leaves is a frame that
  reached the def and landed in no leaf, and one is enough."""
  def collapse(samples):
    samples[30]["counters"]["c_total"] += 40
  proc = _run_report(_two_epoch_log(tmp_path, collapse))
  assert proc.returncode == 1
  assert "ran AHEAD of the sum of its leaves" in proc.stdout
  flat = " ".join(proc.stdout.split())
  assert "This is the Tier 2 conjunction, not the instrument" in flat


def test_the_identity_window_is_shorter_than_the_epoch_it_judges():
  """A window longer than the run would silently check nothing."""
  assert report.IDENTITY_WINDOW >= 2
  assert report.IDENTITY_WINDOW <= 20
