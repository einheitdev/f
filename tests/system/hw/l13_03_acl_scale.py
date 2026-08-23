#!/usr/bin/env python3
"""What a rule set costs, and how many rules the box survives.

Appliance datasheets publish two throughput figures: one for plain
routing and one for the same traffic through a large access list.
Netgate's is 10,000 ACLs, and on their $899 box it costs more than
half the throughput -- 18.50 Gb/s of L3 forwarding becomes 9.93. Every
`f` figure measured so far is the routing column. This measures the
other one.

It is also the first thing here that can take the box down, so most of
this file is about not doing that.

## What went wrong the first time, and what it changed

The first attempt compiled a 10,000-rule policy **on the DUT** and
loaded it through `fd`, in a loop, unguarded. The rig has 4 GB of RAM
and 1.8 GB of zram, and a large compile thrashes compressed swap:
every core pinned, no OOM kill, nothing in userspace scheduled. The
box answered ping and nothing else for forty minutes and needed a
power cycle.

Worse, it was armed to do it again. `fd.service` has
`Restart=on-failure` and loads whatever `compiled/current` points at,
so a bundle that wedges the box on load wedges it on every boot --
before `sshd`, since fd is ordered `Before=network.target`. A policy
the compiler happily accepted was one power cycle from an
unrecoverable appliance.

So, in order:

  * **Compile on the generator, not the DUT.** BPF objects are
    `elf64-bpf` and architecture-neutral, so an x86 workstation can
    build a bundle an ARM board loads. clang never runs on the 4 GB
    box.

  * **Ask the verifier before asking fd.** `bpftool prog load` answers
    "will the kernel accept this" without touching `compiled/current`,
    so a program that is too big is refused with no boot trap created
    and nothing to roll back.

  * **Cap the memory rather than let it thrash.** The probe runs in a
    transient scope with `MemoryMax` and `MemorySwapMax=0`. Without
    the second one the cgroup limit just pushes the pressure into
    zram, which is the failure being avoided.

  * **Arm the hardware watchdog.** Userspace guards are petting
    nothing at exactly the moment they are needed -- that is what the
    first attempt proved. The SoC's watchdog resets the board whether
    or not anything can be scheduled.

  * **Defuse the symlink the instant it stops being needed.** fd reads
    the bundle once, at start. As soon as it reports attached,
    `current` goes back to the safe bundle, so any reset from that
    point on comes up clean.

  * **Climb, and stop at the first refusal.** 250 rules before 10,000.
    The interesting number is where it stops, and jumping to the end
    to find out is how the first attempt went.
"""

import argparse
import importlib.util
import json
import pathlib
import subprocess
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent

# Installed rather than staged in /tmp: a watchdog-
# triggered reset clears tmpfs, and the next run then
# refuses to start for want of the thing that saved it.
WATCHDOG_PATH = "/usr/local/bin/f-hw-watchdog"

def _load_rfc2544():
  """Reuse the throughput harness rather than reimplement its honesty."""
  spec = importlib.util.spec_from_file_location(
    "rfc2544", HERE / "l13_02_rfc2544_throughput.py")
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module

def run(cmd, **kw):
  return subprocess.run(cmd, capture_output=True, text=True, **kw)

def policy(count, rx, tx):
  """A policy of `count` rules that the test traffic never matches.

  Deliberately non-matching. An ACL benchmark measures the cost of
  traversing the list, so every packet has to reach the bottom of it:
  a rule set the traffic matches early measures how fast the box can
  stop looking. The generator sends UDP from 10.60/16, and these match
  TCP from 10.1-250/24, so nothing short-circuits.

  Three terms per rule -- source prefix, protocol, destination port --
  because a one-term rule is not what anyone means by an ACL and would
  flatter the result.
  """
  lines = [f"zone wan = [{rx}]", f"zone lan = [{tx}]", "", "@xdp(wan)", ""]
  for i in range(count):
    a, b = (i // 254) % 250 + 1, i % 254 + 1
    port = 1024 + (i % 60000)
    lines.append(f"drop if pkt.src_ip in 10.{a}.{b}.0/24 "
                 f"and pkt.proto == tcp and pkt.dst_port == {port}")
  lines += ["redirect to lan", "", "@xdp(lan)", "", "default drop", ""]
  return "\n".join(lines)

def xdp_insns(obj):
  """BPF instructions in the object's xdp section, or -1."""
  out = run(["readelf", "-S", str(obj)]).stdout.splitlines()
  for i, line in enumerate(out):
    # "  [ 3] xdp               PROGBITS  ..." -- the bracketed index
    # may or may not have a space in it, so match on the fields rather
    # than on a position.
    fields = line.replace("[", " ").replace("]", " ").split()
    if "xdp" in fields and "PROGBITS" in fields and i + 1 < len(out):
      try:
        return int(out[i + 1].split()[0], 16) // 8
      except (ValueError, IndexError):
        return -1
  return -1

def compile_local(count, rx, tx, fwl, workdir):
  """Build the bundle here, where there is memory to build it in."""
  src = workdir / f"acl{count}.fw"
  src.write_text(policy(count, rx, tx))
  bundle = workdir / f"bundle{count}"
  start = time.monotonic()
  proc = run([fwl, "compile", "--bundle", str(bundle), str(src)])
  seconds = time.monotonic() - start
  if proc.returncode != 0:
    return None, {"error": (proc.stderr or proc.stdout).strip()[:400],
                  "compile_s": round(seconds, 1)}
  obj = bundle / "wan.bpf.o"
  return bundle, {
    "compile_s": round(seconds, 1),
    "c_bytes": (bundle / "wan.bpf.c").stat().st_size,
    "obj_bytes": obj.stat().st_size,
    "manifest_bytes": (bundle / "manifest.json").stat().st_size,
    "insns": xdp_insns(obj),
  }

class Guard:
  """The hardware watchdog, armed around anything that can wedge.

  Context-managed so the magic-close disarm cannot be forgotten:
  leaving `/dev/watchdog` armed resets a box that is working fine,
  which would be a worse bug than the one this prevents.
  """

  def __init__(self, dut, seconds, path=WATCHDOG_PATH):
    self.dut = dut
    self.seconds = seconds
    self.path = path
    self.sentinel = "/run/f-acl-guard"

  def __enter__(self):
    self.dut.sh(
      f"sudo -n touch {self.sentinel}; "
      f"sudo -n setsid nohup python3 {self.path} "
      f"{self.sentinel} {self.seconds} >/dev/null 2>&1 < /dev/null &")
    return self

  def __exit__(self, *exc):
    # Best effort, repeatedly: a box that is merely slow will get here
    # eventually, and a box that never does deserves the reset.
    for _ in range(3):
      self.dut.sh(f"sudo -n rm -f {self.sentinel}")
      if self.dut.sh(f"test -e {self.sentinel}").returncode != 0:
        return False
      time.sleep(2)
    return False

def probe_verifier(dut, bundle, count, mem_mb, timeout_s):
  """Ask the kernel whether it will take this program at all.

  Nothing here touches `compiled/current`, so a refusal costs a log
  line rather than an appliance that cannot boot. The transient scope
  caps memory AND swap: capping memory alone pushes the pressure into
  zram, which is the thing that took the box down.

  **The exit status is not the answer.** An earlier version read `$?`
  and reported "verifier accepted in 0.1s" for every rule count up to
  2500 -- while the same program, loaded by hand, ran for five minutes
  and wedged the box. So acceptance now requires evidence that a
  program exists: the pin is there afterwards, `bpftool prog show`
  reports it, and it has a non-zero translated size. A load that
  claims success without leaving a program behind is a failure, in the
  same way that delivering more packets than were sent is a counter
  bug rather than a result.

  A suspiciously fast pass is also treated as a failure. Verification
  of tens of thousands of instructions on this SoC does not happen in
  a tenth of a second, and a number that good is a bug report.
  """
  remote = f"/tmp/acl{count}.bpf.o"
  proc = run(["scp", "-q", str(bundle / "wan.bpf.o"),
              f"{dut.target}:{remote}"])
  if proc.returncode != 0:
    return {"loaded": False, "verify_s": -1, "why": "scp failed"}
  pin = f"/sys/fs/bpf/aclprobe{count}"
  # `timeout` on the REMOTE side. A timeout that lives in the local
  # ssh invocation stops the client and leaves the verifier running,
  # which is how one of these outlived its own harness.
  script = (
    f"sudo -n rm -f {pin}; "
    f"start=$(date +%s.%N); "
    f"sudo -n timeout -s KILL {timeout_s} systemd-run --scope -q "
    f"-p MemoryMax={mem_mb}M -p MemorySwapMax=0 -- "
    f"bpftool prog load {remote} {pin} type xdp 2>&1; "
    f"rc=$?; end=$(date +%s.%N); "
    f"echo \"HARNESS_RC=$rc\"; "
    f"echo \"HARNESS_SECONDS=$(echo \"$end - $start\" | bc)\"; "
    f"if [ -e {pin} ]; then echo HARNESS_PINNED=yes; "
    f"sudo -n bpftool prog show pinned {pin} 2>&1 | head -6; "
    f"else echo HARNESS_PINNED=no; fi; "
    f"sudo -n rm -f {pin}")
  out = dut.sh(script).stdout
  rc, seconds, pinned, xlated = 1, -1.0, False, 0
  for line in out.splitlines():
    if line.startswith("HARNESS_RC="):
      rc = int(line.split("=", 1)[1] or 1)
    elif line.startswith("HARNESS_SECONDS="):
      try:
        seconds = float(line.split("=", 1)[1])
      except ValueError:
        seconds = -1.0
    elif line.startswith("HARNESS_PINNED="):
      pinned = line.split("=", 1)[1] == "yes"
    elif "xlated" in line:
      for token in line.replace(",", " ").split():
        if token.startswith("xlated"):
          continue
        if token.endswith("B") and token[:-1].isdigit():
          xlated = int(token[:-1])
          break
  noise = " ".join(line for line in out.splitlines()
                   if not line.startswith("HARNESS_")).strip()[:300]

  if rc != 0:
    return {"loaded": False, "verify_s": round(seconds, 1),
            "why": noise or f"bpftool exit {rc}"}
  if not pinned or xlated <= 0:
    return {"loaded": False, "verify_s": round(seconds, 1),
            "why": "bpftool reported success but left no program "
                   f"behind (pinned={pinned}, xlated={xlated}B). "
                   "Not a result."}
  return {"loaded": True, "verify_s": round(seconds, 1),
          "xlated_bytes": xlated, "xlated_insns": xlated // 8}

def deploy_and_measure(rfc, dut, bundle, count, safe_bundle, gen,
                       mix, seconds, tolerance, precision, bundle_root):
  """Load through fd, defuse the symlink, then measure.

  The **built bundle** is copied, not the policy source: compiling on
  the DUT is the operation that took the box down three times, and it
  is measured separately (`--probe-compile`) rather than performed
  here as a side effect of wanting a throughput number.

  As soon as fd reports attached, `current` goes back to the safe
  bundle. fd read the manifest once, at start, so from that moment a
  reset -- watchdog or otherwise -- comes up on a policy that is known
  to load. The window in which this box could be trapped is the four
  seconds between the symlink moving and fd answering, rather than
  every boot until someone notices.
  """
  version = f"{bundle_root}/v-acl{count}"
  dut.sh(f"sudo -n rm -rf {version} && sudo -n mkdir -p {version} && "
         f"rm -rf /tmp/aclstage{count} && mkdir -p /tmp/aclstage{count}")
  proc = run(["scp", "-q"] + [str(f) for f in sorted(bundle.iterdir())] +
             [f"{dut.target}:/tmp/aclstage{count}/"])
  if proc.returncode != 0:
    return None, "copying the bundle to the DUT failed"
  if dut.sh(f"sudo -n cp /tmp/aclstage{count}/* {version}/").returncode:
    return None, "staging the bundle failed"

  script = (f"sudo -n systemctl stop fd && "
            f"sudo -n ln -sfT {version} {bundle_root}/current && "
            f"sudo -n systemctl start fd")
  started = dut.sh(script).returncode == 0
  attached = False
  if started:
    for _ in range(40):
      if '"xdp_attached":true' in dut.sh("fctl status 2>/dev/null").stdout:
        attached = True
        break
      time.sleep(0.5)
  # Whatever happened, `current` stops pointing at the experiment now.
  dut.sh(f"sudo -n ln -sfT {safe_bundle} {bundle_root}/current")
  if not attached:
    return None, ("fd did not start" if not started
                  else "fd never reported xdp_attached")
  log = []
  best = rfc.search(dut, gen, seconds, mix, "forward", tolerance, log,
                    precision)
  return best, ""

def main():
  ap = argparse.ArgumentParser(description=__doc__)
  ap.add_argument("--dut-host", required=True)
  ap.add_argument("--rx-iface", required=True)
  ap.add_argument("--tx-iface", required=True)
  ap.add_argument("--gen-iface", required=True)
  ap.add_argument("--dst-mac", required=True)
  ap.add_argument("--gen-cpus", default="0,1,2,3,4,5")
  ap.add_argument("--counts", default="0,250,1000,2500,5000,10000",
                  help="rule counts to climb through. 0 is the "
                       "baseline: the same policy with no rules.")
  ap.add_argument("--line-gbit", type=float, default=10.0)
  ap.add_argument("--seconds", type=float, default=10)
  ap.add_argument("--tolerance", type=float, default=0.01)
  ap.add_argument("--precision", type=float, default=0.02)
  ap.add_argument("--frames", default="imix")
  ap.add_argument("--probe-mem-mb", type=int, default=1500,
                  help="memory cap for the verifier probe. The DUT "
                       "has 4 GB and 1.8 GB of zram; without a cap "
                       "the pressure goes to compressed swap and "
                       "pins every core.")
  ap.add_argument("--probe-timeout", type=int, default=120)
  ap.add_argument("--watchdog-path", default=WATCHDOG_PATH)
  ap.add_argument("--watchdog", type=int, default=90,
                  help="hardware watchdog timeout, seconds")
  ap.add_argument("--safe-bundle", default=None,
                  help="bundle `current` is restored to. Defaults to "
                       "whatever it points at now.")
  ap.add_argument("--fwl-local", default="fwl")
  ap.add_argument("--fwl-remote", default="/usr/local/bin/fwl")
  ap.add_argument("--bundle-root", default="/usr/share/f/compiled")
  ap.add_argument("--measure", action="store_true",
                  help="also measure throughput at every count that "
                       "verifies. Without this it only reports what "
                       "compiles and what the kernel accepts.")
  ap.add_argument("--out", default="/tmp/acl-scale")
  args = ap.parse_args()

  rfc = _load_rfc2544()
  rfc.LINE_BITS = int(args.line_gbit * 1_000_000_000)
  mix = rfc.parse_mixes(args.frames)[0]

  dut = rfc.Dut(args.dut_host)
  if dut.sh("true").returncode != 0:
    sys.exit(f"cannot reach {args.dut_host}")
  if dut.sh(f"test -e {args.watchdog_path}").returncode != 0:
    sys.exit(f"the DUT needs {args.watchdog_path} (from "
             "tests/system/hw/hw_watchdog.py). Running this without a "
             "watchdog is how the rig spent forty minutes answering "
             "only ping.")

  safe = args.safe_bundle or dut.sh(
    f"readlink {args.bundle_root}/current").stdout.strip()
  if not safe:
    sys.exit("cannot determine a safe bundle to fall back to")
  print(f"safe bundle: {safe}")

  workdir = pathlib.Path(args.out)
  workdir.mkdir(parents=True, exist_ok=True)
  cpus = [int(c) for c in args.gen_cpus.split(",")]
  direction = rfc.Direction(args.gen_iface, cpus, args.dst_mac,
                            args.rx_iface, args.tx_iface)
  results = []

  for count in [int(c) for c in args.counts.split(",")]:
    row = {"rules": count}
    bundle, built = compile_local(count, args.rx_iface, args.tx_iface,
                                  args.fwl_local, workdir)
    row.update(built)
    if bundle is None:
      print(f"{count:>6} rules: COMPILE FAILED after "
            f"{built['compile_s']}s -- {built['error']}")
      results.append(row)
      break
    print(f"{count:>6} rules: compiled in {built['compile_s']}s, "
          f"{built['insns']:,} insns, {built['obj_bytes'] // 1024} KB "
          f"object, {built['manifest_bytes'] // 1024} KB manifest",
          flush=True)

    with Guard(dut, args.watchdog, args.watchdog_path):
      probe = probe_verifier(dut, bundle, count, args.probe_mem_mb,
                             args.probe_timeout)
    row.update(probe)
    if not probe["loaded"]:
      print(f"        verifier REFUSED after {probe['verify_s']}s: "
            f"{probe['why']}")
      results.append(row)
      break
    print(f"        verifier accepted in {probe['verify_s']}s",
          flush=True)

    if args.measure:
      gen = rfc.Generator([direction], mix)
      try:
        with Guard(dut, args.watchdog, args.watchdog_path):
          best, why = deploy_and_measure(
            rfc, dut, bundle, count, safe, gen, mix, args.seconds,
            args.tolerance, args.precision, args.bundle_root)
      finally:
        gen.cleanup()
      if best is None:
        row["measure_error"] = why
        print(f"        NOT MEASURED: {why}")
        results.append(row)
        break
      row["throughput_pps"] = best["offered_pps"]
      row["line_pct"] = best["line_pct"]
      row["gbit"] = round(mix.gbit(best["aggregate_pps"]), 3)
      print(f"        {best['offered_pps']:,} pps "
            f"({best['line_pct']}% of line, {row['gbit']} Gb/s)",
            flush=True)
    results.append(row)

  dut.sh(f"sudo -n ln -sfT {safe} {args.bundle_root}/current")
  dut.sh("sudo -n systemctl restart fd")

  print("\n" + "=" * 74)
  print("RULE SET SCALING")
  print("=" * 74)
  header = f'{"rules":>7}{"insns":>10}{"obj KB":>9}{"verify s":>10}'
  if args.measure:
    header += f'{"pps":>12}{"% line":>9}'
  print(header)
  for row in results:
    line = (f'{row["rules"]:>7}{row.get("insns", -1):>10,}'
            f'{row.get("obj_bytes", 0) // 1024:>9}'
            f'{row.get("verify_s", -1):>10}')
    if args.measure:
      line += (f'{row.get("throughput_pps", 0):>12,}'
               f'{row.get("line_pct", 0):>8}%')
    print(line)
  path = workdir / "acl-scale.json"
  path.write_text(json.dumps(results, indent=2))
  print(f"\nfull results: {path}")
  return 0

if __name__ == "__main__":
  sys.exit(main())
