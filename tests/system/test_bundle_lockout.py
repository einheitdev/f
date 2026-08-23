#!/usr/bin/env python3
"""A bundle that will not load must not produce a box that will not boot.

`fd.service` carries `Restart=on-failure`, loads whatever
`<bundle-dir>/current` points at, and is ordered `Before=network.target`
— which puts it before sshd. So until 2026-08-23 a bundle that failed on
load was retried forever, and a bundle that took the board down while
loading took it down on every boot, before anyone could reach the box to
change the symlink. The only reason it never cost a rig is that the
crash that produced it happened during compilation, before the symlink
moved.

This is the test for the fix. It is deliberately not an argument that
the mechanism is sound: it stages bundles the kernel really refuses,
starts the real `fd` against a real netns with real XDP, and requires
the box to come back attached on the last-known-good.

## What is simulated, and what is not

Two failure shapes, and the second is the one that matters.

  * **The kernel refuses the object.** `fd` exits with an error and
    says why. This is the easy case and the loader always handled it;
    what is new is that the refusal is COUNTED, and that the count
    survives the process.

  * **The daemon never gets to say anything.** On the rig the load
    pinned every core, scheduled nothing in userspace, and ended in a
    watchdog reset. No handler ran, no log line was flushed. That is
    reproduced here by SIGKILLing `fd` mid-start — the same observable
    aftermath, which is: an attempt was begun and nothing recorded its
    outcome. If the guard's bookkeeping happened after the load instead
    of before it, this scenario would leave no trace and the next boot
    would walk into the same trap. Scenario 3 is the assertion that it
    does not.

Nothing here can reproduce an actual board wedge, and nothing should
try: that is what cost three power cycles. What can be tested is the
evidence such a wedge leaves behind, and that is what is tested.

## Isolation

Everything lives inside one network namespace entered with `nsenter
--net=`, not `ip netns exec`. The difference matters: `ip netns exec`
also unshares the mount namespace and remounts /sys, which takes the
bpffs mount at /sys/fs/bpf with it and makes every load fail for a
reason that has nothing to do with the bundle. The pin root, the bundle
root, the control socket and the interfaces are all scratch, and
`net.ipv4.ip_forward` is per-namespace so the host's is never touched.

Requires root, because it loads BPF programs and attaches XDP. `fwl` is
usually a `pip install --user` script that root cannot see, so pass it
as a command:

    sudo env PYTHONPATH=fwl python3 tests/system/test_bundle_lockout.py \
      --fd build/fd --fwl "python3 -c 'from fwl.cli import main; main()'"
"""

import argparse
import json
import os
import pathlib
import shlex
import shutil
import signal
import subprocess
import sys
import time

NS = "f-lockout"
NS_PATH = f"/var/run/netns/{NS}"
ROOT = pathlib.Path("/tmp/f-lockout")
BUNDLES = ROOT / "compiled"
PIN = "/sys/fs/bpf/f-lockout"
SOCK = ROOT / "control.sock"
WAN_IF = "flo0"
LAN_IF = "flo1"

POLICY = f"""zone wan = [{WAN_IF}]
zone lan = [{LAN_IF}]

@xdp(wan)
drop if pkt.proto == icmp
redirect to lan

@xdp(lan)
default drop
"""

FD_YAML = f"""socket: ipc://{SOCK}
pin_path: {PIN}
log_level: info
watch:
  enabled: false
bundle:
  on_load_failure: fallback
  max_load_attempts: 2
"""


class Failure(Exception):
  """A checked expectation that did not hold."""


def run(cmd, **kw):
  """Run a command, capturing both streams."""
  return subprocess.run(cmd, capture_output=True, text=True, **kw)


def sh(cmd):
  """Run a shell command and return its CompletedProcess."""
  return run(["/bin/sh", "-c", cmd])


def check(condition, message):
  if not condition:
    raise Failure(message)


class Topology:
  """One namespace, two veths, and nothing of the host's touched."""

  def up(self):
    self.down()
    run(["ip", "netns", "add", NS], check=True)
    for name in (WAN_IF, LAN_IF):
      run(["ip", "-n", NS, "link", "add", name, "type", "veth",
           "peer", "name", name + "p"], check=True)
      for end in (name, name + "p"):
        run(["ip", "-n", NS, "link", "set", end, "up"], check=True)
    run(["ip", "-n", NS, "link", "set", "lo", "up"], check=True)

  def down(self):
    run(["ip", "netns", "del", NS])
    shutil.rmtree(PIN, ignore_errors=True)


class Daemon:
  """One `fd` start, and whatever it left behind.

  A start is a context manager because the interesting scenarios end
  with the process being killed rather than stopping, and a leaked `fd`
  holding an XDP program on a scratch veth would make every later
  scenario in the run report the wrong thing.
  """

  def __init__(self, fd_path, log_path):
    self.fd_path = str(pathlib.Path(fd_path).resolve())
    self.log_path = pathlib.Path(log_path)
    self.proc = None

  def start(self):
    log = open(self.log_path, "w", encoding="utf-8")
    self.proc = subprocess.Popen(
      ["nsenter", f"--net={NS_PATH}", self.fd_path,
       "-c", str(ROOT / "fd.yaml"),
       "--bundle-dir", str(BUNDLES), "run"],
      stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    return self

  def wait_attached(self, timeout_s=15.0):
    """True once the log says XDP is on at least one interface.

    The log rather than the exit status, and the interface count rather
    than the program count: "1 zone program(s)" was true of a bundle
    attached to nothing at all, which is the failure the loader's own
    message was rewritten to make impossible to misread.
    """
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
      text = self.log()
      if "Engine running." in text:
        return True
      if "Init failed" in text or self.proc.poll() is not None:
        return False
      time.sleep(0.2)
    return False

  def wait_exit(self, timeout_s=20.0):
    try:
      self.proc.wait(timeout=timeout_s)
      return True
    except subprocess.TimeoutExpired:
      return False

  def kill_now(self):
    """SIGKILL, i.e. what a board that stops being scheduled looks like.

    No signal handler, no ExecStopPost, no final log line — the daemon
    simply stops existing between one instruction and the next.
    """
    if self.proc and self.proc.poll() is None:
      os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
      self.proc.wait(timeout=10)

  def stop(self):
    if self.proc and self.proc.poll() is None:
      self.proc.terminate()
      try:
        self.proc.wait(timeout=10)
      except subprocess.TimeoutExpired:
        self.kill_now()

  def log(self):
    try:
      return self.log_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
      return ""

  def __enter__(self):
    return self.start()

  def __exit__(self, *exc):
    self.stop()
    return False


def compile_bundle(fwl, version):
  """Build one bundle with `fwl`, exactly as an operator would."""
  src = ROOT / "policy.fw"
  src.write_text(POLICY, encoding="utf-8")
  out = BUNDLES / version
  shutil.rmtree(out, ignore_errors=True)
  proc = run(shlex.split(fwl) +
             ["compile", str(src), "--bundle", str(out)])
  check(proc.returncode == 0,
        f"fwl compile failed: {proc.stderr or proc.stdout}")
  check((out / "manifest.json").exists(), f"{out} has no manifest")
  return out


def break_bundle(version):
  """Make a bundle the kernel will refuse, without breaking the manifest.

  Truncating the object leaves everything `fd` reads before the load —
  the manifest, the zone list, the interface names — intact and correct,
  so the refusal comes from the kernel rather than from a validity check
  fd could have made on its own. That is the shape of the real failure:
  a bundle the compiler was happy with and the verifier is not.
  """
  obj = BUNDLES / version / "wan.bpf.o"
  data = obj.read_bytes()
  obj.write_bytes(data[: len(data) // 2])


def point(link, version):
  """Repoint one of the bundle-root symlinks."""
  path = BUNDLES / link
  tmp = BUNDLES / (link + ".new")
  if tmp.is_symlink() or tmp.exists():
    tmp.unlink()
  tmp.symlink_to(version)
  tmp.replace(path)


def read_link(link):
  path = BUNDLES / link
  return os.readlink(path) if path.is_symlink() else ""


def read_record():
  path = BUNDLES / ".load-attempt.json"
  if not path.exists():
    return None
  return json.loads(path.read_text(encoding="utf-8"))


def status():
  """The daemon's own view, over the control socket."""
  here = pathlib.Path(__file__).resolve().parent
  proc = run(["python3", str(here / "lib" / "fdctl.py"), "3",
              f"ipc://{SOCK}"])
  if proc.returncode != 0:
    return {}
  try:
    return json.loads(proc.stdout)
  except json.JSONDecodeError:
    return {}


# -- scenarios ---------------------------------------------------------

def scenario_good_bundle_becomes_last_known_good(fd):
  """A bundle that attaches is recorded as having attached.

  Not "loaded" and not "started": the marker is written after the
  interface count, from the same number the readiness notification is
  gated on, because every silent failure in this daemon's history has
  been something that was running without being in the packet path.
  """
  point("current", "v-good")
  with Daemon(fd, ROOT / "fd-good.log") as d:
    check(d.wait_attached(), f"fd never attached:\n{d.log()}")
    check(read_link("last-known-good") == "v-good",
          f"last-known-good is {read_link('last-known-good')!r}")
    check(read_record() is None,
          f"an attached bundle left an attempt behind: {read_record()}")
    st = status()
    check(st.get("bundle", {}).get("degraded") is False,
          f"a healthy box reported degraded: {st.get('bundle')}")
    check(st.get("bundle", {}).get("running") == "v-good",
          f"status says running={st.get('bundle', {}).get('running')!r}")
  print("  ok: an attached bundle becomes the last-known-good")


def scenario_refused_bundle_is_counted(fd):
  """A bundle the kernel refuses is counted, and the reason is kept."""
  point("current", "v-bad")
  with Daemon(fd, ROOT / "fd-bad1.log") as d:
    check(not d.wait_attached(), "a truncated object attached anyway")
    check(d.wait_exit(), "fd did not exit after refusing the bundle")
  record = read_record()
  check(record is not None, "a refused bundle left no attempt record")
  check(record["version"] == "v-bad",
        f"record names {record['version']!r}")
  check(record["attempts"] == 1, f"attempts={record['attempts']}")
  check(record["last_error"],
        "the loader exited cleanly and recorded no reason")
  print("  ok: a refused bundle is counted and the reason is kept")


def scenario_a_silent_death_still_leaves_evidence(fd):
  """The one that matters: the daemon never gets to report anything.

  This is the rig's failure reproduced as far as it safely can be. If
  the attempt were recorded after the load rather than before it, this
  start would leave nothing behind and the next boot would walk into the
  same bundle with a clean slate — forever.
  """
  before = read_record()
  check(before is not None and before["attempts"] == 1,
        "this scenario expects one prior attempt")
  point("current", "v-bad")
  d = Daemon(fd, ROOT / "fd-bad2.log").start()
  # Let it get as far as opening the bundle, then take the board away.
  deadline = time.monotonic() + 10
  while time.monotonic() < deadline:
    if "Cold-boot: loading" in d.log():
      break
    time.sleep(0.1)
  d.kill_now()
  check("Cold-boot: loading" in d.log(),
        f"fd never reached the load:\n{d.log()}")
  after = read_record()
  check(after is not None,
        "a SIGKILLed start left no evidence that it happened")
  check(after["attempts"] == 2,
        f"the killed start was not counted: attempts={after['attempts']}")
  print("  ok: a start that never returns is still on the record")


def scenario_the_box_comes_back_on_the_last_known_good(fd):
  """The acceptance criterion. Third start, and the box comes up.

  `current` still points at the bundle that failed twice. Nothing has
  been repaired by hand. `fd` must not open it again, must load the
  last-known-good instead, must attach, and must say all of that
  somewhere an operator will see it.
  """
  check(read_link("current") == "v-bad",
        "the test repaired `current` by accident")
  with Daemon(fd, ROOT / "fd-fallback.log") as d:
    check(d.wait_attached(),
          f"the box did not come back on the fallback:\n{d.log()}")
    log = d.log()
    check("bundle guard" in log, "the fallback was silent in the log")
    check("v-bad" in log and "v-good" in log,
          "the log does not name both bundles")
    check("NOT RUNNING THE POLICY IT WAS LAST GIVEN" in log,
          "the fallback did not say the policy is not the one asked for")
    # ...and the trap is disarmed on disk too, so losing the attempt
    # record does not re-arm it.
    check(read_link("current") == "v-good",
          f"`current` still points at {read_link('current')!r}")
    st = status().get("bundle", {})
    check(st.get("degraded") is True,
          f"a box on its fallback reported healthy: {st}")
    check(st.get("running") == "v-good", f"status: {st}")
    check("v-bad" in st.get("reason", ""),
          f"the status reason does not name the quarantined bundle: {st}")
  print("  ok: the box comes back attached, on the last-known-good, "
        "and says so")


def scenario_fail_closed_refuses_instead(fd):
  """The other half of the operator's choice, exercised as configured.

  `fail-closed` does not run a policy nobody asked for. It also does not
  leave the box forwarding: fd lowers ip_forward on the way in and never
  raises it, so the refusal is a refusal rather than an outage with a
  router still in it.
  """
  (ROOT / "fd.yaml").write_text(
    FD_YAML.replace("fallback", "fail-closed"), encoding="utf-8")
  point("current", "v-bad")
  (BUNDLES / ".load-attempt.json").unlink(missing_ok=True)
  try:
    for _ in range(2):
      with Daemon(fd, ROOT / "fd-closed-try.log") as d:
        d.wait_attached()
        d.wait_exit()
    with Daemon(fd, ROOT / "fd-closed.log") as d:
      check(not d.wait_attached(), "fail-closed attached something")
      check(d.wait_exit(), "fd hung instead of refusing")
      log = d.log()
      check("will not be tried again" in log,
            f"the refusal does not say it is final:\n{log}")
      check(read_link("current") == "v-bad",
            "fail-closed rewrote `current` behind the operator's back")
    forward = sh(f"nsenter --net={NS_PATH} "
                 "cat /proc/sys/net/ipv4/ip_forward").stdout.strip()
    check(forward == "0",
          f"a refused box is still forwarding (ip_forward={forward!r})")
  finally:
    (ROOT / "fd.yaml").write_text(FD_YAML, encoding="utf-8")
  print("  ok: fail-closed refuses, keeps `current`, and stops routing")


def scenario_verify_bundle_answers_without_touching_current(fd):
  """`fd verify-bundle` is the safe order of operations.

  The order that lost the rig was compile, point `current` at it,
  restart, find out. This asks the kernel first, and a refusal costs a
  log line rather than a box.
  """
  before = read_link("current")
  good = run(["nsenter", f"--net={NS_PATH}", str(pathlib.Path(fd).resolve()),
              "--bundle-dir", str(BUNDLES), "verify-bundle",
              str(BUNDLES / "v-good")])
  check(good.returncode == 0,
        f"a loadable bundle was refused: {good.stdout}{good.stderr}")
  check("xlated" in good.stdout,
        "the check reported a pass with no translated size, which is "
        f"exactly the thing it exists not to do: {good.stdout}")
  bad = run(["nsenter", f"--net={NS_PATH}", str(pathlib.Path(fd).resolve()),
             "--bundle-dir", str(BUNDLES), "verify-bundle",
             str(BUNDLES / "v-bad")])
  check(bad.returncode != 0, f"a broken bundle passed: {bad.stdout}")
  check(read_link("current") == before,
        "verify-bundle moved `current`")
  print("  ok: verify-bundle answers the question without arming a trap")


SCENARIOS = [
  scenario_good_bundle_becomes_last_known_good,
  scenario_refused_bundle_is_counted,
  scenario_a_silent_death_still_leaves_evidence,
  scenario_the_box_comes_back_on_the_last_known_good,
  scenario_verify_bundle_answers_without_touching_current,
  scenario_fail_closed_refuses_instead,
]


def main():
  ap = argparse.ArgumentParser(description=__doc__)
  ap.add_argument("--fd", default="build/fd", help="path to the fd binary")
  ap.add_argument(
    "--fwl", default=shutil.which("fwl") or "fwl",
    help="the compiler, as a command. Split like a shell word list, so "
         "an uninstalled tree can be used directly: --fwl 'python3 -m "
         "fwl.cli'. Worth having because this test runs as root and a "
         "`pip install --user` fwl is not on root's path.")
  ap.add_argument("--keep", action="store_true",
                  help="leave the namespace and bundles for inspection")
  args = ap.parse_args()

  if os.geteuid() != 0:
    print("this test loads real BPF programs and needs root", file=sys.stderr)
    return 2
  if not pathlib.Path(args.fd).exists():
    print(f"no fd binary at {args.fd}", file=sys.stderr)
    return 2

  topo = Topology()
  shutil.rmtree(ROOT, ignore_errors=True)
  BUNDLES.mkdir(parents=True)
  (ROOT / "fd.yaml").write_text(FD_YAML, encoding="utf-8")
  topo.up()

  failures = []
  try:
    compile_bundle(args.fwl, "v-good")
    compile_bundle(args.fwl, "v-bad")
    break_bundle("v-bad")
    for scenario in SCENARIOS:
      print(f"- {scenario.__name__}")
      try:
        scenario(args.fd)
      except Failure as exc:
        failures.append(f"{scenario.__name__}: {exc}")
        print(f"  FAIL: {exc}")
  finally:
    if not args.keep:
      topo.down()

  if failures:
    print(f"\n{len(failures)} scenario(s) failed:")
    for f in failures:
      print(f"  - {f}")
    return 1
  print(f"\nall {len(SCENARIOS)} scenarios passed")
  return 0


if __name__ == "__main__":
  sys.exit(main())
