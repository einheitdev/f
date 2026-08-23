"""Behavioural tests for the datapath tuning applied before fd starts.

The thing worth protecting here is not that a sysfs write happens. It
is that the tool **refuses to act on a map it had to guess**. An RSS
weight vector applied to the wrong queues is worse than no vector at
all: it silently steers most traffic at the slowest cores, it looks
exactly like a correctly tuned box from every command an operator
would run, and the only symptom is a throughput number nobody has a
baseline for. So most of what follows is about the skip paths.
"""

import pathlib
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
  """A guessed map is the failure mode this tool exists to avoid.

  And it is a FAILURE, not a skip. A multi-queue NIC is one the
  weighting was meant for; leaving it flat costs 25-32% on
  big.LITTLE. The rig ran a day at three quarters of its capability
  because this was a skip line in a report that ended "datapath
  tuning applied".
  """
  partial = {q: q for q in range(6)}
  _rss_fixture(monkeypatch, queues=partial)
  report = tune.Report()
  tune.tune_rss(report, "eth0", 3, 1)
  assert not report.changed
  assert any("cannot tell which CPU serves queue" in line
             for line in report.failed)
  assert not report.skipped

def test_an_unweighted_multiqueue_nic_makes_the_run_exit_nonzero(
    monkeypatch, capsys):
  """The property that matters: the operator is told, and told loudly."""
  _rss_fixture(monkeypatch, queues={q: q for q in range(4)})
  report = tune.Report()
  tune.tune_rss(report, "eth0", 3, 1)
  assert report.emit() == 1
  assert "NOT in the state" in capsys.readouterr().out

def test_it_waits_for_a_queue_map_that_arrives_late(monkeypatch):
  """The boot race: udev has not renamed the NIC and the driver's
  completion-queue interrupts do not exist yet. Waiting is what makes
  running before network.target survivable."""
  calls = {"n": 0}

  def late(iface):
    calls["n"] += 1
    return RK3588_QUEUES if calls["n"] > 2 else {}

  monkeypatch.setattr(tune, "queue_cpu_map", late)
  monkeypatch.setattr(tune.time, "sleep", lambda _s: None)
  got = tune.wait_for_queue_map("eth0", 8, seconds=5)
  assert got == RK3588_QUEUES
  assert calls["n"] > 2

def test_waiting_gives_up_rather_than_hanging(monkeypatch):
  monkeypatch.setattr(tune, "queue_cpu_map", lambda iface: {})
  monkeypatch.setattr(tune.time, "sleep", lambda _s: None)
  assert tune.wait_for_queue_map("eth0", 8, seconds=0) == {}

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

def _fake_net(tmp_path, monkeypatch, ifaces):
  """A fake /sys/class/net.

  Args:
    tmp_path: pytest temporary directory.
    monkeypatch: pytest monkeypatch fixture.
    ifaces: {name: (has_device, operstate, iommu_type or None)}.

  Returns:
    The fake NET_ROOT path.
  """
  root = tmp_path / "net"
  groups = tmp_path / "iommu_groups"
  for index, (name, (device, state, iommu)) in enumerate(
      sorted(ifaces.items())):
    entry = root / name
    entry.mkdir(parents=True)
    (entry / "operstate").write_text(state + "\n")
    if device:
      (entry / "device").mkdir()
    if iommu:
      group = groups / str(index)
      group.mkdir(parents=True)
      (group / "type").write_text(iommu + "\n")
      (entry / "device" / "iommu_group").symlink_to(group)
  monkeypatch.setattr(tune, "NET_ROOT", root)
  return root

def test_a_down_interface_is_still_a_candidate(tmp_path, monkeypatch):
  """The regression that made every reboot come up untuned.

  This unit runs before fd, which runs before network.target, so on a
  cold boot the interfaces it must weight are administratively down.
  Filtering on operstate meant it weighted nothing, every time, and
  said "tuning applied" while doing it.
  """
  _fake_net(tmp_path, monkeypatch,
            {"enp1s0f0np0": (True, "down", None),
             "enp1s0f1np1": (True, "down", None),
             "lo": (False, "unknown", None)})
  assert tune.candidate_ifaces() == ["enp1s0f0np0", "enp1s0f1np1"]

def test_finding_no_interface_at_all_is_a_failure(tmp_path,
                                                  monkeypatch, capsys):
  """Silence is the failure mode; it has to be loud instead."""
  _fake_net(tmp_path, monkeypatch, {"lo": (False, "unknown", None)})
  monkeypatch.setattr(tune, "cpu_ids", lambda: [])
  monkeypatch.setattr(tune, "CPU_ROOT", tmp_path / "nothing")
  monkeypatch.setattr(tune.sys, "argv", ["f-datapath-tune"])
  assert tune.main() == 1
  assert "no physical interface found" in capsys.readouterr().out


# --- the isolation posture is a choice, so test it as one ------------

@pytest.mark.parametrize("mode,group", [("strict", "DMA"),
                                        ("lazy", "DMA-FQ"),
                                        ("passthrough", "identity")])
def test_the_configured_posture_is_the_one_that_passes(
    tmp_path, monkeypatch, mode, group):
  """Each mode is satisfied by its own group type and no other."""
  _fake_net(tmp_path, monkeypatch, {"eth0": (True, "up", group)})
  report = tune.Report()
  tune.check_iommu(report, ["eth0"], mode)
  assert not report.failed
  assert any(mode in line for line in report.already)

def test_a_box_not_in_the_configured_posture_says_which_and_how(
    tmp_path, monkeypatch):
  """The mismatch has to name the parameter, not just complain.

  A box in strict mode forwards at half its datasheet and nothing
  else on it reports that, so this message is the only place an
  operator finds out.
  """
  _fake_net(tmp_path, monkeypatch, {"eth0": (True, "up", "DMA")})
  report = tune.Report()
  tune.check_iommu(report, ["eth0"], "passthrough")
  assert report.failed
  assert "iommu.passthrough=1" in report.failed[0]
  assert "--apply-boot" in report.failed[0]

def test_choosing_strict_is_satisfied_by_the_kernel_default(
    tmp_path, monkeypatch):
  """An operator who wants full isolation should not be nagged."""
  _fake_net(tmp_path, monkeypatch, {"eth0": (True, "up", "DMA")})
  report = tune.Report()
  tune.check_iommu(report, ["eth0"], "strict")
  assert not report.failed

def test_no_iommu_in_the_path_is_not_a_failure(tmp_path, monkeypatch):
  """An x86 box with the IOMMU off has nothing to choose."""
  _fake_net(tmp_path, monkeypatch, {"eth0": (True, "up", None)})
  report = tune.Report()
  tune.check_iommu(report, ["eth0"], "lazy")
  assert not report.failed
  assert any("nothing to choose" in line for line in report.skipped)

# --- config ----------------------------------------------------------

def test_a_missing_config_is_not_an_error(tmp_path):
  settings, note = tune.load_config(tmp_path / "absent.yaml")
  assert settings == tune.DEFAULTS
  assert "absent" in note

def test_the_shipped_default_keeps_dma_isolation():
  """Inheriting `passthrough` unchosen is the failure to avoid.

  The default has to be a posture that still isolates. Anything
  faster is a decision, and a decision has to be made rather than
  arrive.
  """
  assert tune.DEFAULTS["iommu"] == "lazy"
  assert tune.IOMMU_MODES["lazy"]["cmdline"] == "iommu.strict=0"

def test_config_overrides_defaults_and_reports_where_it_came_from(
    tmp_path):
  path = tmp_path / "datapath.yaml"
  path.write_text("iommu: passthrough\nrss_big_weight: 5\n")
  settings, note = tune.load_config(path)
  assert settings["iommu"] == "passthrough"
  assert settings["rss_big_weight"] == 5
  assert settings["governor"] == tune.DEFAULTS["governor"]
  assert str(path) in note

def test_an_unknown_key_is_named_rather_than_silently_dropped(tmp_path):
  path = tmp_path / "datapath.yaml"
  path.write_text("iommu: lazy\nring_size: 8192\n")
  settings, note = tune.load_config(path)
  assert "ring_size" not in settings
  assert "ring_size" in note

def test_broken_yaml_falls_back_loudly(tmp_path):
  path = tmp_path / "datapath.yaml"
  path.write_text("iommu: [unclosed\n")
  settings, note = tune.load_config(path)
  assert settings == tune.DEFAULTS
  assert "not valid YAML" in note

# --- writing the kernel command line ---------------------------------

def _boot(monkeypatch, tmp_path, flavour, content):
  name = "armbianEnv.txt" if flavour == "armbian" else "grub"
  var = ("extraargs" if flavour == "armbian"
         else "GRUB_CMDLINE_LINUX_DEFAULT")
  path = tmp_path / name
  path.write_text(content)
  monkeypatch.setattr(tune, "BOOT_CONFIGS",
                      ((str(path), var, flavour),))
  monkeypatch.setattr(tune.subprocess, "run",
                      lambda *a, **k: subprocess.CompletedProcess(
                        a[0], 0, "", ""))
  return path

def _value(path, var):
  for line in path.read_text().splitlines():
    if line.startswith(var + "="):
      return line.split("=", 1)[1]
  return None

def test_switching_posture_replaces_the_other_parameter(tmp_path,
                                                        monkeypatch):
  """Both iommu parameters present at once is a box nobody can reason
  about, so the one being replaced is removed rather than left."""
  path = _boot(monkeypatch, tmp_path, "armbian",
               "verbosity=1\nextraargs=cma=256M iommu.passthrough=1\n")
  assert tune.apply_boot("lazy") == 0
  assert _value(path, "extraargs") == "cma=256M iommu.strict=0"
  assert "passthrough" not in path.read_text()

def test_choosing_strict_removes_both_parameters(tmp_path, monkeypatch):
  path = _boot(monkeypatch, tmp_path, "armbian",
               "extraargs=cma=256M iommu.strict=0\n")
  assert tune.apply_boot("strict") == 0
  assert _value(path, "extraargs") == "cma=256M"

def test_unrelated_kernel_parameters_survive(tmp_path, monkeypatch):
  """Editing somebody else's boot line is how a box stops booting."""
  path = _boot(monkeypatch, tmp_path, "grub",
               'GRUB_TIMEOUT=5\n'
               'GRUB_CMDLINE_LINUX_DEFAULT="quiet splash"\n')
  assert tune.apply_boot("passthrough") == 0
  want = '"quiet splash iommu.passthrough=1"'
  assert _value(path, "GRUB_CMDLINE_LINUX_DEFAULT") == want
  assert "GRUB_TIMEOUT=5" in path.read_text()

def test_a_backup_is_left_behind(tmp_path, monkeypatch):
  path = _boot(monkeypatch, tmp_path, "armbian", "extraargs=cma=256M\n")
  tune.apply_boot("lazy")
  backup = pathlib.Path(str(path) + ".bak-f-datapath")
  assert backup.exists()
  assert backup.read_text() == "extraargs=cma=256M\n"

def test_applying_twice_changes_nothing_the_second_time(tmp_path,
                                                        monkeypatch):
  path = _boot(monkeypatch, tmp_path, "armbian", "extraargs=cma=256M\n")
  tune.apply_boot("lazy")
  first = path.read_text()
  tune.apply_boot("lazy")
  assert path.read_text() == first

def test_dry_run_writes_nothing(tmp_path, monkeypatch, capsys):
  path = _boot(monkeypatch, tmp_path, "armbian", "extraargs=cma=256M\n")
  before = path.read_text()
  assert tune.apply_boot("passthrough", dry_run=True) == 0
  assert path.read_text() == before
  assert "iommu.passthrough=1" in capsys.readouterr().out

def test_an_unrecognised_bootloader_refuses_and_says_what_to_add(
    monkeypatch, capsys):
  """Guessing at a bootloader does not produce an error message, it
  produces a box that does not boot."""
  monkeypatch.setattr(tune, "BOOT_CONFIGS",
                      (("/nonexistent/boot.conf", "x", "armbian"),))
  assert tune.apply_boot("lazy") == 1
  assert "iommu.strict=0" in capsys.readouterr().out
