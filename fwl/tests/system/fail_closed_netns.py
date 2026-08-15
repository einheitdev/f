#!/usr/bin/env python3
"""The box forwards only while it filters — measured on a real kernel.

The finding this exists for was measured on a booted image, not
reasoned about. A provisioned appliance with its compiled bundle
removed refused to start `fd` exactly as designed — `activating/
auto-restart`, zero XDP programs anywhere, the refusal in the journal
— and went on routing, because `f-sysconf apply` had written
`net.ipv4.ip_forward = 1` once at provisioning time and
`systemd-sysctl` reapplied it every boot. An unsolicited inbound TCP
connection the healthy box refused with zero frames on the inside wire
completed with four, and outbound flows left un-masqueraded with
inside addresses on them, because the NAT lived in the XDP program
that was not there.

The daemon was fail-closed; the appliance was not. `fd` owns the knob
now, and this asks the running kernel whether it does — the unit tests
can only ask a temp directory, and the thing being claimed is about
`/proc/sys`.

Five states, and the fourth and fifth are the ones worth the trouble:

  1. `fd` lowers the knob on the way IN, before it has loaded
     anything. Started against a kernel already at 1, it must go to 0
     and only come back up once something is attached.
  2. A successful attach raises it. This is the fail-NEVER half: a box
     that filters must route without anybody typing.
  3. A clean stop lowers it, BEFORE the XDP detach rather than after,
     because `systemctl stop fd` is step one of the handbook's own
     recovery procedure and the window between "no program" and "no
     routing" is the whole defect.
  4. A REFUSED bundle leaves it at 0. This is the measured finding.
  5. A SIGKILLed `fd` leaves it at 1 and the XDP programs attached —
     and that is recorded as a fact rather than fixed here, because
     the thing that closes it is `ExecStopPost` in `fd.service` and
     there is no systemd in this bench. A test that quietly passed
     this case would be claiming cover this file does not have.

Two controls, so a pass is attributable:

  * the knob is set to the WRONG value before each phase, so a phase
    that measured nothing reads red rather than green
  * the attach itself is asserted from `ip link`, because "forwarding
    is on" proves nothing about a daemon that never armed anything

Usage:
  sudo python3 fail_closed_netns.py --fd build/fd [--fwl fwl]
"""

import argparse
import os
import pathlib
import shutil
import signal
import subprocess
import sys
import tempfile
import time

FWD = pathlib.Path("/proc/sys/net/ipv4/ip_forward")
PIN_ROOT = "/sys/fs/bpf/f-failclosed"
LEG = "fcl0"
PEER = "fcl0p"
POLICY = f"""zone edge = [{LEG}]

@xdp(edge)
allow if pkt.proto == icmp
default drop
"""


class Result:
  """Verdicts, printed as they are reached."""

  def __init__(self):
    """Start with nothing decided."""
    self.failed = 0
    self.passed = 0

  def check(self, ok, what):
    """Record one verdict and return it."""
    print(f"[fc] {'PASS' if ok else 'FAIL'}: {what}", flush=True)
    if ok:
      self.passed += 1
    else:
      self.failed += 1
    return ok

  def note(self, what):
    """Record something observed that is not a verdict."""
    print(f"[fc] NOTE: {what}", flush=True)


def run(argv, check=False):
  """Run a command and capture it."""
  return subprocess.run(argv, capture_output=True, text=True,
                        check=check)


def forwarding():
  """The live knob, as a string."""
  return FWD.read_text().strip()


def set_forwarding(value):
  """Put the knob somewhere, so a phase that does nothing shows."""
  FWD.write_text(f"{value}\n")


def attached():
  """Whether the zone leg carries an XDP program."""
  return "xdp" in run(["ip", "link", "show", LEG]).stdout


def build_topology():
  """One veth pair, up, with no addresses. Nothing routes here.

  The datapath only has to ARM for these measurements; what it does
  to a packet is `three_zone_gateway_netns.py`'s question. Keeping
  this bench addressless keeps the two from sharing a failure.
  """
  run(["ip", "link", "del", LEG])
  run(["ip", "link", "add", LEG, "type", "veth", "peer", "name",
       PEER], check=True)
  run(["ip", "link", "set", LEG, "up"], check=True)
  run(["ip", "link", "set", PEER, "up"], check=True)


def tear_down():
  """Leave the machine as it was found."""
  run(["ip", "link", "del", LEG])
  shutil.rmtree(PIN_ROOT, ignore_errors=True)


def start_fd(fd_bin, bundle, work, name):
  """Cold-boot `fd` against a bundle directory."""
  log = open(work / f"fd-{name}.log", "w")
  return subprocess.Popen(
    [fd_bin, "--bundle-dir", str(bundle), "--pin-path", PIN_ROOT,
     "--socket", f"ipc://{work}/{name}.sock", "-l", "debug", "run"],
    stdout=log, stderr=subprocess.STDOUT)


def wait_for(predicate, timeout_s=25.0):
  """Poll until a predicate holds, and report whether it did."""
  deadline = time.monotonic() + timeout_s
  while time.monotonic() < deadline:
    if predicate():
      return True
    time.sleep(0.25)
  return False


def journal(work, name):
  """What fd said, for the record."""
  return (work / f"fd-{name}.log").read_text()


def phase_armed(res, fd_bin, bundle, work):
  """Lowered on the way in, raised by the attach, lowered on stop."""
  # The control for phases 1 and 2 at once: start from the value a
  # passing run must MOVE. If fd did nothing at all, phase 1 reads
  # red rather than green.
  set_forwarding(1)
  proc = start_fd(fd_bin, bundle, work, "armed")
  try:
    res.check(wait_for(attached),
              f"fd attached an XDP program to {LEG}")
    res.check(wait_for(lambda: forwarding() == "1"),
              f"an armed datapath forwards: ip_forward = "
              f"{forwarding()} with a program on {LEG}")
    log = journal(work, "armed")
    # Both transitions, in order, in fd's own words. The knob ending
    # at 1 is also what a daemon that never touched it produces, and
    # this is the only thing that tells the two apart.
    lowered = "net.ipv4.ip_forward 1 -> 0" in log
    raised = "net.ipv4.ip_forward 0 -> 1" in log
    res.check(lowered,
              "fd lowered the knob on the way IN, before it had "
              "loaded anything")
    res.check(raised and log.find("1 -> 0") < log.find("0 -> 1"),
              "...and raised it again only after the attach, in that "
              "order")
    res.check("datapath armed on 1 interface(s)" in log,
              "the reason it gives is the interface count, not a "
              "property of the policy")
  finally:
    proc.send_signal(signal.SIGTERM)
    proc.wait(timeout=30)
  # Lowered on the way out, and the ordering matters: a clean stop
  # detaches XDP from every port, so a box that stopped routing only
  # AFTER that is a plain unfiltered router for the length of the
  # gap.
  res.check(forwarding() == "0",
            f"a clean stop closes the box: ip_forward = "
            f"{forwarding()} after SIGTERM")
  res.check(not attached(), f"...and {LEG} carries no program")
  log = journal(work, "armed")
  res.check(log.find("fd is stopping") < log.find("Detaching XDP"),
            "the knob went down BEFORE the detach, not after")


def phase_refused(res, fd_bin, work):
  """The measured finding: a refused bundle must not leave it open."""
  empty = pathlib.Path(tempfile.mkdtemp(prefix="fc-nobundle-"))
  (empty / "current").mkdir()
  # The control. A box that WAS forwarding, whose bundle has gone —
  # which is exactly the image that was measured, since the sysctl
  # had been applied at provisioning time and reapplied every boot.
  set_forwarding(1)
  proc = start_fd(fd_bin, empty, work, "refused")
  rc = proc.wait(timeout=60)
  res.check(rc != 0, f"fd refused to start (exit {rc})")
  res.check(not attached(),
            f"no XDP program is attached to {LEG}")
  res.check(forwarding() == "0",
            f"and the box is NOT routing: ip_forward = "
            f"{forwarding()} after the refusal")
  log = journal(work, "refused")
  res.check("Init failed" in log, "fd said why it refused")
  res.check("forwarding:" in log,
            "fd said why the box stopped forwarding, separately — a "
            "box that has stopped routing must be a visible fault")
  shutil.rmtree(empty, ignore_errors=True)


def phase_override(res, fd_bin, bundle, work):
  """An armed box someone closes by hand is reported, not fought.

  The asymmetry is deliberate and this is where it is pinned. Putting
  a lowered knob back would make the daemon un-overridable by the
  operator whose box it is, and would break the controls in the
  hardware scenarios — several prove "these frames were on the wire
  and no socket took one" by holding forwarding down under a running
  `fd`. `three_zone_gateway_netns.py` is one of them.
  """
  set_forwarding(0)
  proc = start_fd(fd_bin, bundle, work, "override")
  try:
    res.check(wait_for(lambda: attached() and forwarding() == "1"),
              "the box is armed and forwarding before the override")
    set_forwarding(0)
    # Longer than RouteMgr::forwarding_recheck_s, so a daemon that
    # DID fight would have had its chance to.
    time.sleep(12)
    res.check(forwarding() == "0",
              f"fd left the operator's 0 alone: ip_forward = "
              f"{forwarding()} twelve seconds later")
    log = journal(work, "override")
    res.check("something has since set it to 0" in log,
              "...and said so, once, rather than silently obeying")
  finally:
    proc.send_signal(signal.SIGTERM)
    proc.wait(timeout=30)


def phase_killed(res, fd_bin, bundle, work):
  """SIGKILL: recorded as a fact, because systemd is what covers it.

  `EngineStop` never runs, so the XDP programs stay attached and the
  knob stays where the last attach put it. `fd.service` carries
  `ExecStopPost=-/usr/local/bin/fd close-forwarding` for exactly this,
  and systemd runs it whichever way the main process died. There is no
  systemd here, so this phase measures the gap rather than the cover,
  and says which it is.
  """
  set_forwarding(0)
  proc = start_fd(fd_bin, bundle, work, "killed")
  res.check(wait_for(lambda: attached() and forwarding() == "1"),
            "the box is armed and forwarding before the kill")
  proc.send_signal(signal.SIGKILL)
  proc.wait(timeout=30)
  time.sleep(2)
  res.note(f"after SIGKILL, with no service manager: ip_forward = "
           f"{forwarding()}, {LEG} "
           f"{'still carries' if attached() else 'carries no'} a "
           f"program. fd.service's ExecStopPost is what closes this "
           f"on a real box; this bench has no systemd and does not "
           f"claim to have tested it.")
  # What CAN be tested here is the thing ExecStopPost runs.
  set_forwarding(1)
  closed = run([fd_bin, "close-forwarding"])
  res.check(closed.returncode == 0 and forwarding() == "0",
            f"`fd close-forwarding` — the command ExecStopPost runs — "
            f"leaves ip_forward = {forwarding()}")
  run(["ip", "link", "set", "dev", LEG, "xdp", "off"])


def build_parser():
  """Construct the argument parser."""
  parser = argparse.ArgumentParser(
    prog="fail_closed_netns.py",
    description="Does this box forward only while it filters?")
  parser.add_argument("--fd", default="build/fd")
  parser.add_argument("--fwl", default="fwl")
  return parser


def main(argv=None):
  """Entry point. Returns a process exit code."""
  args = build_parser().parse_args(argv)
  if os.geteuid() != 0:
    print("[fc] BLOCKED: needs root (it loads BPF and writes "
          "/proc/sys/net/ipv4/ip_forward)", file=sys.stderr)
    return 2
  res = Result()
  saved = forwarding()
  work = pathlib.Path(tempfile.mkdtemp(prefix="fc-work-"))
  bundle = work / "compiled"
  try:
    source = work / "edge.fw"
    source.write_text(POLICY)
    (bundle / "current").mkdir(parents=True)
    compiled = run([args.fwl, "compile", str(source), "--bundle",
                    str(bundle / "current")])
    if not res.check(compiled.returncode == 0,
                     f"fwl compiled the bundle ("
                     f"{compiled.stdout.strip() or compiled.stderr.strip()})"):
      return 1
    build_topology()
    phase_armed(res, args.fd, bundle, work)
    phase_refused(res, args.fd, work)
    phase_override(res, args.fd, bundle, work)
    phase_killed(res, args.fd, bundle, work)
  finally:
    tear_down()
    FWD.write_text(f"{saved}\n")
    shutil.rmtree(work, ignore_errors=True)
  total = res.passed + res.failed
  print(f"[fc] {'PASS' if not res.failed else 'FAIL'}: "
        f"{res.passed}/{total} checks", flush=True)
  return 0 if not res.failed else 1


if __name__ == "__main__":
  raise SystemExit(main())
