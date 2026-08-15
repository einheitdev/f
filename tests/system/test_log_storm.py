#!/usr/bin/env python3
"""Storm-level log volume, and bundles that stop accumulating.

Two unbounded things, both of which grow fastest exactly when the box
is working hardest, and both of which fail at the office rather than
on the bench.

**Logs.** Sampled logging on a segment carrying office broadcast
storms is a high event rate. journald's answer to a high event rate
is to *silently discard* — `RateLimitBurst` messages per interval,
then "Suppressed N messages" and nothing else. An appliance that
quietly stops recording during the minute worth recording is worse
than one that stops working, because it looks fine.

**Compiled bundles.** Every reload writes a new timestamped directory
and repoints `current`. Nothing removed the old ones; the rig carries
~500.

This test **generates real volume** rather than asserting a rate. It
writes tens of thousands of log lines as fast as the machine will
take them, then asks the box what it lost — first with the
distribution's limiter in place (which must drop, and must be seen to
drop), then with the generated policy (which must not).

  1. CONTROL — with a tight rate limit, a storm IS dropped, and
     `show storage` reports it. If a limiter cannot be caught losing
     messages, the clean result afterwards means nothing.
  2. THE POLICY — with the generated drop-in, the same storm is
     recorded in full and nothing is suppressed.
  3. RETENTION — a directory of bundles is bounded, the running one
     survives, and an unreadable directory is not reported as a tidy
     one.

Run on the target, as root:
  sudo ./test_log_storm.py --f-sysconf /path/to/f-sysconf
"""
import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import time

PASS = 0
FAIL = 0

# Big enough to blow through any plausible burst limit in well under
# the rate-limit interval, small enough to finish in seconds.
STORM_LINES = 20000
DROPIN_DIR = "/etc/systemd/journald.conf.d"
TEST_DROPIN = os.path.join(DROPIN_DIR, "99-f-storm-test.conf")


def check(desc, cond, detail=""):
  """Record one assertion: PASS/FAIL with truncated detail."""
  global PASS, FAIL
  if cond:
    PASS += 1
    print("PASS  %s" % desc)
  else:
    FAIL += 1
    print("FAIL  %s" % desc)
    if detail:
      text = detail if len(detail) < 600 else detail[:600] + "..."
      for line in text.splitlines():
        print("        %s" % line)


def run(cmd, check_rc=False):
  p = subprocess.run(cmd, shell=isinstance(cmd, str),
                     capture_output=True, text=True)
  out = p.stdout + p.stderr
  if check_rc and p.returncode != 0:
    raise RuntimeError("command failed: %s\n%s" % (cmd, out))
  return p.returncode, out


def quiet(cmd):
  subprocess.run(cmd, shell=True, capture_output=True)


def write_dropin(body):
  os.makedirs(DROPIN_DIR, exist_ok=True)
  with open(TEST_DROPIN, "w") as fh:
    fh.write(body)
  run("systemctl restart systemd-journald")
  time.sleep(1.5)


def storm(tag, lines=STORM_LINES):
  """Emit `lines` log records as fast as the machine will take them.

  systemd-cat rather than logger(1): one process, one socket, no
  per-line fork, which is what makes this a storm rather than a
  trickle.
  """
  body = "".join("f-storm %s line %d payload "
                 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n" % (tag, i)
                 for i in range(lines))
  start = time.time()
  p = subprocess.Popen(["systemd-cat", "-t", tag],
                       stdin=subprocess.PIPE, text=True)
  p.communicate(body)
  elapsed = time.time() - start

  # Long enough for journald to drain and for the rate-limit interval
  # to close.
  time.sleep(8.0)

  # Then a trickle, from the same unit, on a different tag.
  #
  # This is not padding. journald evaluates the rate limit lazily: the
  # "Suppressed N messages" record is written when the NEXT message
  # from that group arrives after the interval expires, not when
  # discarding starts. A box that goes quiet after a storm therefore
  # never records that it dropped anything — measured here on systemd
  # 257, and one more reason the shipped policy sets
  # RateLimitBurst=0 rather than trusting the report.
  p = subprocess.Popen(["systemd-cat", "-t", tag + "flush"],
                       stdin=subprocess.PIPE, text=True)
  p.communicate("flush\n" * 5)
  time.sleep(3.0)
  return elapsed


def recorded(tag):
  """How many of that tag's lines journald actually kept.

  The tag is unique per run. An earlier run's lines sitting in the
  same time window would otherwise be counted here, and a test that
  reports 40001 of 20000 recorded has been measuring its own history.
  """
  rc, out = run("journalctl -t %s --no-pager --output=cat" % tag)
  if rc != 0:
    return -1
  return len([ln for ln in out.splitlines() if "f-storm" in ln])


def cursor():
  """A place in the journal, so 'since' means since *this* point.

  A wall-clock window is not good enough: journald's suppression
  records are sparse, and a previous run's record inside the same
  ten minutes reads as this run's.
  """
  rc, out = run("journalctl -n0 --no-pager --show-cursor")
  for line in out.splitlines():
    if line.startswith("-- cursor:"):
      return line.split("cursor:", 1)[1].strip()
  return ""


def suppressed_after(cur):
  """Messages journald discarded since `cur`, summed from its own
  records rather than counted as episodes."""
  if not cur:
    return -1
  rc, out = run("journalctl --after-cursor '%s' --no-pager --quiet "
                "--grep='Suppressed [0-9]+ messages'" % cur)
  if rc not in (0, 1):
    return -1
  total = 0
  for line in out.splitlines():
    at = line.find("Suppressed ")
    if at < 0:
      continue
    try:
      total += int(line[at + 11:].split()[0])
    except (ValueError, IndexError):
      pass
  return total


def make_bundles(root, count, current_index=None):
  """A compiled-bundle directory, as fd's own versioning leaves it."""
  shutil.rmtree(root, ignore_errors=True)
  os.makedirs(root)
  names = []
  for i in range(1, count + 1):
    name = "20260814%06d" % i
    os.makedirs(os.path.join(root, name))
    with open(os.path.join(root, name, "manifest.json"), "wb") as fh:
      fh.write(os.urandom(8192))
    names.append(name)
  if current_index is not None:
    os.symlink(names[current_index], os.path.join(root, "current"))
  return names


def main():
  ap = argparse.ArgumentParser(description=__doc__)
  ap.add_argument("--f-sysconf", default="f-sysconf")
  ap.add_argument("--lines", type=int, default=STORM_LINES)
  args = ap.parse_args()

  if os.geteuid() != 0:
    print("this test needs root", file=sys.stderr)
    return 2

  work = tempfile.mkdtemp(prefix="f-storm-")
  bundles = os.path.join(work, "compiled")
  # The directory has to exist before the first `storage` call, or
  # the report is legitimately about an unreadable path rather than
  # about the journal.
  os.makedirs(bundles)
  model_path = os.path.join(work, "system.yaml")
  with open(model_path, "w") as fh:
    fh.write("zones:\n  testnet:\ninterfaces:\n  lan0:\n"
             "    mac: \"52:54:00:f8:00:01\"\n"
             "    address: 10.30.0.1/24\n    zone: testnet\n")

  def sysconf(*extra):
    return run([args.f_sysconf, "-c", model_path,
                "--compiled-dir", bundles] + list(extra))

  had_dropin = os.path.exists(TEST_DROPIN)
  try:
    # ---- 1. CONTROL: a limiter can be caught losing messages ------
    # The distribution ships a limiter. Tightened here so a storm
    # that finishes in seconds is guaranteed to hit it — the point is
    # to prove the *detector* works, not to discover journald's
    # defaults.
    # A 5-second interval, not the 30 the distribution ships. The
    # suppression record is written when the interval ENDS, not when
    # discarding starts (measured on systemd 257) — so a long
    # interval means a test that waits a long time to see the loss it
    # already caused, and an operator polling during a storm who sees
    # a reassuring zero.
    write_dropin("[Journal]\n"
                 "Storage=persistent\n"
                 "RateLimitIntervalSec=5s\n"
                 "RateLimitBurst=100\n")
    ctl_tag = "fstormctl%d" % os.getpid()
    mark = cursor()
    elapsed = storm(ctl_tag, args.lines)
    kept = recorded(ctl_tag)
    dropped = suppressed_after(mark)
    print("  control: %d lines in %.1fs, %d recorded, %d reported "
          "dropped" % (args.lines, elapsed, kept, dropped))
    check("CONTROL: the storm was generated (not a rate we assumed)",
          elapsed >= 0 and args.lines >= 10000,
          "%d lines in %.2fs" % (args.lines, elapsed))
    check("CONTROL: a tight limiter DROPS a storm",
          kept >= 0 and kept < args.lines,
          "%d of %d recorded" % (kept, args.lines))
    check("CONTROL: and the drop is REPORTED, not merely suffered",
          dropped > 0,
          "journald reported %d dropped" % dropped)
    check("CONTROL: ...and the number reported matches what went "
          "missing",
          dropped > 0 and abs((args.lines - kept) - dropped) <
          args.lines // 10,
          "%d missing, %d reported" % (args.lines - kept, dropped))

    rc, out = sysconf("storage")
    check("CONTROL: `storage` reports the loss rather than a clean "
          "bill",
          "dropped logs" in out and "0 message(s)" not in out, out)
    check("CONTROL: ...and exits non-zero so a script notices",
          rc == 6, "rc=%d\n%s" % (rc, out))

    # ---- 2. THE POLICY --------------------------------------------
    rc, out = run([args.f_sysconf, "-c", model_path,
                   "--journald-dropin", TEST_DROPIN, "--compiled-dir",
                   bundles, "--dnsmasq-conf",
                   os.path.join(work, "dnsmasq.conf"),
                   "--networkd-dir", os.path.join(work, "networkd"),
                   "--ipv6-sysctl", os.path.join(work, "ipv6.conf"),
                   "--chrony-conf",
                   "/etc/chrony/f-storm-test.conf",
                   "--proc-sys", "", "apply"])
    check("apply installs the journal limits", rc == 0, out)
    with open(TEST_DROPIN) as fh:
      dropin = fh.read()
    check("...and the limiter is disabled by decision",
          "RateLimitBurst=0" in dropin, dropin)
    check("...and the journal is capped so it cannot fill the disk",
          "SystemMaxUse=" in dropin and "SystemKeepFree=" in dropin,
          dropin)
    run("systemctl restart systemd-journald")
    time.sleep(1.5)

    pol_tag = "fstormpol%d" % os.getpid()
    mark = cursor()
    elapsed = storm(pol_tag, args.lines)
    kept = recorded(pol_tag)
    dropped = suppressed_after(mark)
    print("  policy:  %d lines in %.1fs, %d recorded, %d reported "
          "dropped" % (args.lines, elapsed, kept, dropped))
    check("POLICY: THE SAME STORM IS RECORDED IN FULL",
          kept == args.lines,
          "%d of %d recorded" % (kept, args.lines))
    check("POLICY: nothing was suppressed",
          dropped == 0, "journald reported %d dropped" % dropped)

    # ---- 3. RETENTION ---------------------------------------------
    make_bundles(bundles, 40, current_index=0)
    rc, out = sysconf("prune", "--dry-run")
    check("a dry run reports what it would remove without removing",
          rc == 0 and "would remove" in out, out)
    # 40 bundles, keep 10, and `current` points at the OLDEST — so 29
    # go, not 30. The running policy is kept whatever its age.
    check("...and 40 bundles are 29 over a limit of 10 plus the "
          "running one",
          "29 of 40" in out, out)
    check("...and nothing was actually removed",
          len(os.listdir(bundles)) == 41, os.listdir(bundles)[:5])

    rc, out = sysconf("prune")
    check("prune removes the excess", rc == 0, out)
    left = sorted(n for n in os.listdir(bundles) if n != "current")
    check("...leaving the limit plus the running one",
          len(left) == 11, str(left))
    check("...and the RUNNING bundle survives even though it is the "
          "oldest",
          "20260814000001" in left, str(left))
    check("...and `current` still resolves",
          os.path.exists(os.path.join(bundles, "current",
                                      "manifest.json")))

    rc, out = sysconf("prune")
    check("a second prune is a no-op", rc == 0 and "0 bundle(s) "
          "removed" in out, out)

    # An unreadable directory must not read as a tidy one.
    rc, out = run([args.f_sysconf, "-c", model_path,
                   "--compiled-dir", "/nonexistent/f/compiled",
                   "storage"])
    check("an unreadable bundle directory is reported, not counted "
          "as zero",
          "could not be read" in out or "does not exist" in out, out)

  finally:
    if not had_dropin:
      quiet("rm -f %s" % TEST_DROPIN)
    quiet("rm -f /etc/chrony/f-storm-test.conf")
    quiet("systemctl restart systemd-journald")
    shutil.rmtree(work, ignore_errors=True)

  print("\n%d passed, %d failed" % (PASS, FAIL))
  return 1 if FAIL else 0


if __name__ == "__main__":
  sys.exit(main())
