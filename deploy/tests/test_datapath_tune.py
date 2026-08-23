"""Behavioural tests for the datapath tuning applied before fd starts.

The thing worth protecting here is not that a sysfs write happens. It
is that the tool **refuses to act on a map it had to guess**. An RSS
weight vector applied to the wrong queues is worse than no vector at
all: it silently steers most traffic at the slowest cores, it looks
exactly like a correctly tuned box from every command an operator
would run, and the only symptom is a throughput number nobody has a
baseline for. So most of what follows is about the skip paths.
"""

import subprocess
import pytest
import f_datapath_tune as tune

def _cpu_tree(root, cpus, states, max_khz, governor="ondemand"):
  """Build a fake /sys/devices/system/cpu.

  Args:
    root: Directory to build under.
    cpus: CPU numbers to create.
    states: [(name, latency_us)] idle states, given to every CPU.
    max_khz: {cpu: cpuinfo_max_freq} for the per-CPU cpufreq links.
    governor: Starting governor for every policy.

  Returns:
    The root path, for convenience.
  """
  for cpu in cpus:
    for index, (name, latency) in enumerate(states):
      state = root / f"cpu{cpu}" / "cpuidle" / f"state{index}"
      state.mkdir(parents=True)
      (state / "name").write_text(name + "\n")
      (state / "latency").write_text(f"{latency}\n")
      (state / "disable").write_text("0\n")
    freq = root / f"cpu{cpu}" / "cpufreq"
    freq.mkdir(parents=True, exist_ok=True)
    (freq / "cpuinfo_max_freq").write_text(f"{max_khz[cpu]}\n")
  for policy, cpu in enumerate(sorted(set(max_khz))):
    pol = root / "cpufreq" / f"policy{policy}"
    pol.mkdir(parents=True)
    (pol / "scaling_governor").write_text(governor + "\n")
    (pol / "scaling_available_governors").write_text(
      "ondemand performance powersave\n")
  return root

# RK3588 as the rig actually reports it: four A55 at 1.8 GHz, four A76
# at 2.4 GHz, and mlx5 completion queue n landing on cpu n.
RK3588_MAX_KHZ = {0: 1800000, 1: 1800000, 2: 1800000, 3: 1800000,
                  4: 2400000, 5: 2400000, 6: 2400000, 7: 2400000}
RK3588_QUEUES = {q: q for q in range(8)}

@pytest.fixture
def rk3588(tmp_path, monkeypatch):
  """A fake RK3588 sysfs tree, with CPU_ROOT pointed at it."""
  root = _cpu_tree(tmp_path / "cpu", range(8),
                   [("WFI", 1), ("cpu-sleep", 220)], RK3588_MAX_KHZ)
  monkeypatch.setattr(tune, "CPU_ROOT", root)
  return root

def _rss_fixture(monkeypatch, rings=8, queues=None, max_khz=None,
                 table=None, ethtool_rc=0, after=None):
  """Point every RSS input at a value, so nothing touches hardware."""
  monkeypatch.setattr(tune, "rx_ring_count", lambda iface: rings)
  monkeypatch.setattr(tune, "queue_cpu_map",
                      lambda iface: dict(queues or RK3588_QUEUES))
  monkeypatch.setattr(tune, "cpu_max_khz",
                      lambda: dict(max_khz or RK3588_MAX_KHZ))
  tables = [table if table is not None else list(range(rings)) * 16]
  if after is not None:
    tables.append(after)
  calls = {"n": 0, "argv": None}

  def fake_table(iface):
    index = min(calls["n"], len(tables) - 1)
    return tables[index]

  def fake_run(argv, **kwargs):
    calls["n"] += 1
    calls["argv"] = argv
    return subprocess.CompletedProcess(argv, ethtool_rc, "", "no")

  monkeypatch.setattr(tune, "indirection_table", fake_table)
  monkeypatch.setattr(tune.subprocess, "run", fake_run)
  return calls

def test_weights_follow_the_measured_queue_to_cpu_map(monkeypatch):
  """The A76-served queues get the heavy weight, and only those."""
  calls = _rss_fixture(monkeypatch, after=[4, 5, 6, 7] * 32)
  report = tune.Report()
  tune.tune_rss(report, "enp1s0f0np0", 3, 1)
  assert not report.failed and not report.skipped
  assert calls["argv"][:4] == ["ethtool", "-X", "enp1s0f0np0", "weight"]
  assert calls["argv"][4:] == ["1", "1", "1", "1", "3", "3", "3", "3"]

def test_refuses_when_a_queue_cannot_be_traced_to_a_cpu(monkeypatch):
  """A guessed map is the failure mode this tool exists to avoid."""
  partial = {q: q for q in range(6)}
  _rss_fixture(monkeypatch, queues=partial)
  report = tune.Report()
  tune.tune_rss(report, "eth0", 3, 1)
  assert not report.changed
  assert any("cannot tell which CPU serves queue" in line
             for line in report.skipped)

def test_skips_a_machine_whose_cores_are_all_the_same_speed(monkeypatch):
  """There is nothing to weight toward on a uniform CPU."""
  flat = {cpu: 3000000 for cpu in range(8)}
  _rss_fixture(monkeypatch, max_khz=flat)
  report = tune.Report()
  tune.tune_rss(report, "eth0", 3, 1)
  assert not report.changed
  assert any("same maximum frequency" in line
             for line in report.skipped)

def test_skips_when_every_queue_lands_on_one_cluster(monkeypatch):
  """A NIC pinned to the big cores has nothing to rebalance."""
  _rss_fixture(monkeypatch, rings=4,
               queues={0: 4, 1: 5, 2: 6, 3: 7})
  report = tune.Report()
  tune.tune_rss(report, "eth0", 3, 1)
  assert not report.changed
  assert any("same class of core" in line for line in report.skipped)

def test_a_single_queue_nic_is_left_alone(monkeypatch):
  _rss_fixture(monkeypatch, rings=1)
  report = tune.Report()
  tune.tune_rss(report, "eth0", 3, 1)
  assert any("nothing to spread" in line for line in report.skipped)

def test_an_already_weighted_table_is_not_rewritten(monkeypatch):
  """Idempotent, so the unit can be restarted without churning RSS."""
  weighted = ([0, 1, 2, 3] + [4, 5, 6, 7] * 3) * 8
  calls = _rss_fixture(monkeypatch, table=weighted)
  report = tune.Report()
  tune.tune_rss(report, "eth0", 3, 1)
  assert calls["argv"] is None
  assert any("RSS weighted" in line for line in report.already)

def test_ethtool_succeeding_while_the_table_stays_flat_is_a_failure(
    monkeypatch):
  """`ethtool -X` can return 0 having done nothing the driver liked.

  Trusting the exit code alone would report a tuned box that is not
  one, which is the same class of mistake as trusting a counter that
  says more packets left than arrived.
  """
  _rss_fixture(monkeypatch, after=list(range(8)) * 16)
  report = tune.Report()
  tune.tune_rss(report, "eth0", 3, 1)
  assert not report.changed
  assert any("came back flat" in line for line in report.failed)

def test_ethtool_refusing_is_reported_not_swallowed(monkeypatch):
  _rss_fixture(monkeypatch, ethtool_rc=1)
  report = tune.Report()
  tune.tune_rss(report, "eth0", 3, 1)
  assert report.failed and not report.changed

def test_deep_idle_is_disabled_and_the_shallow_state_is_not(rk3588):
  """220 us is 300 frames at 1.4 Mpps; 1 us is not worth the power."""
  report = tune.Report()
  tune.tune_cpuidle(report, 50)
  for cpu in range(8):
    base = rk3588 / f"cpu{cpu}" / "cpuidle"
    assert (base / "state0" / "disable").read_text().strip() == "0"
    assert (base / "state1" / "disable").read_text().strip() == "1"
  assert any("cpu-sleep" in line and "disabled" in line
             for line in report.changed)
  assert any("WFI" in line and "left enabled" in line
             for line in report.already)

def test_cpuidle_is_idempotent(rk3588):
  report = tune.Report()
  tune.tune_cpuidle(report, 50)
  second = tune.Report()
  tune.tune_cpuidle(second, 50)
  assert not second.changed
  assert any("cpu-sleep" in line for line in second.already)

def test_raising_the_threshold_leaves_deep_idle_alone(rk3588):
  """The threshold is a knob, and it has to actually be one."""
  report = tune.Report()
  tune.tune_cpuidle(report, 500)
  assert (rk3588 / "cpu0" / "cpuidle" / "state1"
          / "disable").read_text().strip() == "0"

def test_the_governor_is_pinned_and_the_change_is_named(rk3588):
  report = tune.Report()
  tune.tune_governor(report, "performance")
  for policy in sorted((rk3588 / "cpufreq").glob("policy*")):
    assert (policy / "scaling_governor").read_text().strip() == \
        "performance"
  assert any("ondemand -> performance" in line
             for line in report.changed)

def test_an_unavailable_governor_fails_loudly(rk3588):
  """Silently leaving ondemand in place would be a 40% regression."""
  report = tune.Report()
  tune.tune_governor(report, "schedutil")
  assert report.failed and not report.changed

def test_a_failed_setting_makes_the_run_exit_nonzero(capsys):
  report = tune.Report()
  report.failed.append("something")
  assert report.emit() == 1
  assert "NOT in the state" in capsys.readouterr().out

def test_a_clean_run_exits_zero(capsys):
  report = tune.Report()
  report.already.append("something")
  assert report.emit() == 0

def test_queue_map_reads_mlx5_and_igb_interrupt_names(tmp_path,
                                                      monkeypatch):
  """Two drivers name their queues differently; both have to parse."""
  names = {40: "mlx5_async0@pci:0000:01:00.0",
           41: "mlx5_comp0@pci:0000:01:00.0",
           42: "mlx5_comp1@pci:0000:01:00.0",
           50: "enp1s0f3-TxRx-0",
           51: "enp1s0f3-TxRx-1"}
  affinity = {41: "4", 42: "5", 50: "0", 51: "1", 40: "0"}
  monkeypatch.setattr(tune, "irq_names", lambda: names)
  monkeypatch.setattr(
    tune, "read",
    lambda path, default=None: affinity.get(
      int(str(path).split("/")[3]), default)
    if str(path).startswith("/proc/irq/") else default)

  for iface, irqs in (("mlx", [40, 41, 42]), ("igb", [50, 51])):
    msi = tmp_path / iface / "device" / "msi_irqs"
    msi.mkdir(parents=True)
    for irq in irqs:
      (msi / str(irq)).write_text("")
  monkeypatch.setattr(tune, "NET_ROOT", tmp_path)

  # The async queue carries no packets and must not shift the indices.
  assert tune.queue_cpu_map("mlx") == {0: 4, 1: 5}
  assert tune.queue_cpu_map("igb") == {0: 0, 1: 1}

def test_a_queue_pinned_to_several_cpus_is_not_mapped(tmp_path,
                                                      monkeypatch):
  """One queue, one core is the premise; a range breaks it."""
  monkeypatch.setattr(tune, "irq_names",
                      lambda: {41: "mlx5_comp0@pci:0000:01:00.0"})
  monkeypatch.setattr(
    tune, "read",
    lambda path, default=None: "0-7"
    if str(path).startswith("/proc/irq/") else default)
  msi = tmp_path / "mlx" / "device" / "msi_irqs"
  msi.mkdir(parents=True)
  (msi / "41").write_text("")
  monkeypatch.setattr(tune, "NET_ROOT", tmp_path)
  assert tune.queue_cpu_map("mlx") == {}
