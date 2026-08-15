#!/usr/bin/env python3
"""Build a flashable rootfs for the f firewall appliance.

This does two things and delegates the third. It debootstraps a Debian
rootfs, installs the packages the appliance depends on, and then hands
the whole question of *what f consists of* to `f_install.py`, which
reads `deploy/manifest.yaml`.

That delegation is the point. The shell script this replaces carried
its own list of files to copy, and that list was wrong: it installed
`fd`, `einheit-f`, `einheit-f-ui` and `fctl` and had never heard of
`f-confd` or `f-sysconf`, so every image it produced was a box with no
anti-lockout timer and no way to apply a configuration. It also
installed the v0.1 networkd examples into /etc/systemd/network, where
`10-eth0.network` sorts ahead of the model's own `10-f-eth0.network`
and quietly wins.

Usage:
  sudo deploy/image/build_image.py --build-dir build-aarch64 [--out DIR]

It has to be root, and that is checked rather than assumed. Every path
this writes lives in a root-owned rootfs; run as a user, `stage` gets
EPERM on every one of them, and `stage` is written to report a file it
could not write and carry on rather than stop at the first awkward
one. The first time this script was ever run end to end, that is
exactly what happened: all 27 components skipped with `Permission
denied`, the rootfs got nothing, and the run continued to
`systemctl enable` before anything noticed.

Prerequisites: debootstrap, qemu-user-static, and a cross build in
--build-dir. `deploy/image/vm.py check` names any that are missing,
and boots the result.
"""

import argparse
import datetime
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO / "deploy"))
import f_install  # noqa: E402

# Packages the appliance needs and does not ship. `f-install verify`
# knows about the ones it can see as files; this is the list that puts
# them there.
#
# Two things were wrong with it, and the first one meant this script
# had never produced a rootfs at all.
#
# `dbus` is here because `systemd-resolved` depends on
# `default-dbus-system-bus | dbus-system-bus`, and debootstrap does
# not choose between the alternatives of an --include'd package: it
# unpacks systemd-resolved, finds neither provider, and fails
# `--second-stage` with "Failure while configuring base packages",
# five times, and stops. Naming a provider outright is the fix.
#
# `libzmq5` and `libyaml-cpp0.8` are here because every binary this
# project ships needs one or both, and only `libbpf1` was listed. The
# rootfs verified `complete` without them — every file the manifest
# names was in place — and not one of the six could have exec'd.
# Nothing in the build could have said so, because a cross-built
# binary's `ldd` on the build host answers for the build host's
# architecture, which is why `check_binaries_load` below asks the
# rootfs itself rather than trusting this list to stay right.
#
# The third line is the compiler's dependencies, from Debian rather
# than from pypi. `pip install` in the chroot used to resolve
# lark, click and the setuptools build backend over the network, and
# an image build that reaches the internet from inside an emulated
# aarch64 chroot fails the way this one did: pypi.org answers with
# AAAA records only, wget's problem one layer up, and pip sat in
# `Installing build dependencies: started` for twenty minutes. The
# compiler is installed `--no-build-isolation --no-deps` now, so the
# only thing the chroot needs is the archive it was bootstrapped
# from. lark 1.2.2 >= 1.1 and click 8.1.8 >= 8.0 satisfy
# fwl/pyproject.toml; a version skew there is a build failure, which
# is the right place for it.
PACKAGES = [
  "systemd", "systemd-resolved", "dbus", "openssh-server",
  "python3", "python3-pip", "python3-yaml",
  "python3-lark", "python3-click",
  "python3-setuptools", "python3-setuptools-scm", "python3-wheel",
  "clang", "llvm", "libbpf1", "libbpf-dev", "libzmq5", "libyaml-cpp0.8",
  "bpftool",
  "dnsmasq", "chrony",
  "sudo", "curl", "ca-certificates", "iproute2", "ethtool",
]
def run(argv, **kwargs):
  """Run a command, failing the build if it fails."""
  print("+ " + " ".join(str(a) for a in argv), flush=True)
  return subprocess.run([str(a) for a in argv], check=True, **kwargs)
DEFAULT_MIRROR = "http://deb.debian.org/debian"
def mirror_preflight(mirror, suite, workdir):
  """Prove the mirror is fetchable the way debootstrap will fetch it.

  This exists because the failure it catches has no symptom. debootstrap
  fetches with `wget`, which has no happy-eyeballs fallback: it resolves
  deb.debian.org to a Fastly anycast address, picks the AAAA, and if
  that POP is unreachable over IPv6 it sits in `Connecting to ...:80`
  until its timeout — per file, for hundreds of files. The build prints
  one line, `I: Retrieving InRelease`, and then nothing at all, for as
  long as you are willing to wait. Measured on this workstation:
  `wget <mirror>/dists/trixie/InRelease` never returns, `wget -4` on the
  same URL returns in 0.3 s, and `curl` returns because curl DOES have
  the fallback — so every hand-check an operator is likely to run says
  the network is fine.

  It was known and it was not handled: the note above this function said
  the only way past it was "a mirror this build had no way to name",
  which is a workaround performed by hand, once, by whoever hit it.

  Args:
    mirror: The Debian mirror URL.
    suite: The suite whose InRelease is fetched as the probe.
    workdir: Where a generated wgetrc may be written.

  Returns:
    A dict of environment overrides for the debootstrap call — empty
    when plain wget works.

  Raises:
    FileNotFoundError: If the mirror cannot be fetched either way. The
      message names the mirror and the --mirror flag, because at that
      point the build genuinely cannot proceed and a hang is the one
      answer that helps nobody.
  """
  url = f"{mirror}/dists/{suite}/InRelease"

  def probe(family):
    """Fetch the probe URL over one address family only."""
    return subprocess.run(
      ["wget", family, "--timeout=15", "--tries=1", "-q", "-O",
       os.devnull, url], check=False).returncode == 0

  # The question is "does IPv6 work to this mirror", and it has to be
  # asked THAT way. Probing the default path asks something weaker —
  # "did wget happen to pick a working address this time" — and on an
  # anycast mirror it picks per connection, so a probe that passes is
  # no promise about the next four hundred fetches. Measured on this
  # workstation: the InRelease probe over the default path succeeded,
  # and the very next fetch in the same run, of Packages.xz, hung.
  if probe("-6"):
    return {}
  print(f"note: wget cannot fetch {url} over IPv6.")
  if not probe("-4"):
    raise FileNotFoundError(
      f"cannot fetch {url} with wget over IPv4 or IPv6. debootstrap "
      f"uses wget and would hang here rather than fail, so the build "
      f"stops instead. Check the network, or name a reachable mirror "
      f"with --mirror.")
  # IPv4 works and IPv6 does not. Forced for the WHOLE bootstrap and
  # not merely for the fetch that failed, because the failure is per
  # connection: debootstrap makes hundreds, and any one of them
  # picking an unreachable POP hangs the build with no output.
  # debootstrap takes no flag for this and wget reads WGETRC, so that
  # is the seam. Written into the build's own working directory rather
  # than the user's ~/.wgetrc: this is a property of one build, not of
  # the machine.
  wgetrc = Path(workdir) / "wgetrc-inet4"
  wgetrc.parent.mkdir(parents=True, exist_ok=True)
  wgetrc.write_text("inet4_only = on\n")
  print(f"note: it works over IPv4 only, so this build forces IPv4 "
        f"for debootstrap via {wgetrc}. Without this the bootstrap "
        f"hangs with no output rather than failing.")
  return {"WGETRC": str(wgetrc)}


def debootstrap(rootfs, suite, arch, mirror=DEFAULT_MIRROR,
                workdir=None):
  """Create the base rootfs, unless one is already there.

  `mirror` is an argument because the default is not always reachable;
  see `mirror_preflight` for the failure that makes it necessary and
  for what this does about it before spending half an hour.
  """
  if (rootfs / "usr/bin").is_dir():
    print(f"rootfs already at {rootfs}, reusing")
    return
  env = mirror_preflight(mirror, suite, workdir or rootfs.parent)
  # `sudo env K=V` rather than `--preserve-env`: sudo scrubs the
  # environment by default, and a variable that silently did not
  # arrive would put the hang back with the fix apparently applied.
  prefix = ["sudo"]
  if env:
    prefix += ["env"] + [f"{k}={v}" for k, v in env.items()]
  run(prefix + ["debootstrap", f"--arch={arch}", "--foreign",
                "--include=" + ",".join(PACKAGES), suite, rootfs,
                mirror])
  qemu = Path("/usr/bin/qemu-aarch64-static")
  if arch == "arm64" and qemu.exists():
    run(["sudo", "cp", qemu, rootfs / "usr/bin/"])
  run(["sudo", "chroot", rootfs,
       "/debootstrap/debootstrap", "--second-stage"])
def enable_units(rootfs, units):
  """Enable the units that must be on before the first boot."""
  run(["sudo", "chroot", rootfs, "systemctl", "enable", *units])
# The distributions' own units for the two daemons f supervises. Both
# are enabled by their packages' postinst, and neither belongs on this
# box: `f-dnsmasq.service` and `f-chrony.service` run these binaries
# against configs generated from /etc/f/system.yaml, and the packaged
# units run them against /etc/dnsmasq.conf and /etc/chrony/chrony.conf
# on every interface the box has.
#
# On the first image ever booted, `dnsmasq.service` was enabled and
# failed, and `chrony.service` was enabled and ACTIVE — an NTP client
# nothing in the model asked for. The dnsmasq one is the worse of the
# two by a distance: firstboot's own default system.yaml says that an
# appliance which starts a DHCP server on an office network it was
# plugged into by mistake is the worst first impression available, and
# the packaged unit is exactly that, arriving by a route the model
# cannot see. Masked rather than disabled, so that a later
# `apt-get install --reinstall` cannot quietly enable them again.
SUPERSEDED_UNITS = ["dnsmasq.service", "chrony.service"]
def mask_units(rootfs, units):
  """Mask the packaged units f replaces with its own."""
  run(["sudo", "chroot", rootfs, "systemctl", "mask", *units])
def check_binaries_load(rootfs, manifest):
  """Ask the rootfs whether the binaries in it can actually start.

  `f_install.verify` runs `ldd` on a live box and deliberately does
  not on a staged root: on the build host it would answer for the
  build host, and for a cross build it would answer for the wrong
  architecture entirely. Inside the chroot it answers for neither —
  binfmt runs the target's own dynamic loader against the target's own
  libraries, which is the question.

  This exists because the alternative was found the expensive way. The
  package list above was missing libzmq5 and libyaml-cpp0.8; the
  staged rootfs verified `complete`, the archive was written, and the
  box it produced could not exec a single one of its binaries. The
  build must not be able to say `complete` about that again.

  Returns:
    A dict of destination path -> list of unresolved sonames, empty
    when every binary resolves.
  """
  unresolved = {}
  for item in manifest.components:
    if item.kind != "binary":
      continue
    proc = subprocess.run(
      ["sudo", "chroot", str(rootfs), "ldd", item.dest],
      capture_output=True, text=True, check=False)
    missing = [line.strip().split()[0]
               for line in proc.stdout.splitlines()
               if "not found" in line]
    if missing:
      unresolved[item.dest] = missing
  return unresolved
def create_operator(rootfs, shell):
  """Give the box its operator account, with the CLI as its shell."""
  script = (
    f"useradd -m -s {shell} operator 2>/dev/null || true\n"
    "echo 'operator:operator' | chpasswd\n"
    "echo 'operator ALL=(ALL) NOPASSWD: ALL' "
    "> /etc/sudoers.d/operator\n")
  run(["sudo", "chroot", rootfs, "bash", "-c", script])
def build(build_dir, out_dir, suite, arch, skip_bootstrap=False,
          mirror=DEFAULT_MIRROR):
  """Assemble an image and return the path to the archive.

  Raises:
    FileNotFoundError: If the manifest's sources are not all there.
      The message names every missing one.
  """
  manifest = f_install.load_manifest(REPO / "deploy" / "manifest.yaml")
  rootfs = out_dir / "rootfs"
  out_dir.mkdir(parents=True, exist_ok=True)

  # Pre-flight before debootstrap, not after: half an hour of
  # bootstrapping followed by "f-confd is missing" is the same defect
  # this file exists to remove, only slower.
  missing_req, missing_opt = f_install.preflight(
    manifest, build_dir, REPO)
  if missing_req:
    raise FileNotFoundError(
      "the build is incomplete; these are required and are not "
      "there:\n" + "\n".join(
        f"  {i.id}: {f_install.source_path(i, build_dir, REPO)}"
        for i in missing_req))
  for item in missing_opt:
    print(f"note: optional {item.id} was not built; the image will "
          f"not have it")

  if not skip_bootstrap:
    debootstrap(rootfs, suite, arch, mirror, workdir=out_dir)

  actions = f_install.stage(manifest, build_dir, REPO, rootfs,
                            remove_stale=True, with_pip=False)
  for action in actions:
    print(f"{'ok  ' if action.done else 'SKIP'} {action.item.id:<22} "
          f"{action.detail}")

  # `stage` reports what it could not do and carries on, deliberately:
  # an installer that stops at the first awkward file leaves a box in
  # a state nothing describes. The judgement is the caller's, and it
  # was not being made. The python-package is excluded because this
  # script installs the compiler into the chroot itself, a few lines
  # below, and `stage` is told not to.
  refused = [a for a in actions
             if not a.done and a.item.required
             and a.item.kind != "python-package"]
  if refused:
    raise FileNotFoundError(
      f"{len(refused)} required item(s) were not staged; the image "
      f"would be missing them:\n" + "\n".join(
        f"  {a.item.id:<20} {a.detail}" for a in refused))

  # The compiler is pure Python and its dependencies are too, so it
  # can be installed into the chroot rather than cross-built.
  fwl_src = rootfs / "usr/local/lib/fwl"
  run(["sudo", "mkdir", "-p", fwl_src])
  run(["sudo", "cp", "-r", REPO / "fwl/fwl", fwl_src])
  run(["sudo", "cp", REPO / "fwl/pyproject.toml", fwl_src])
  run(["sudo", "chroot", rootfs, "pip3", "install",
       "--break-system-packages", "--no-build-isolation", "--no-deps",
       "/usr/local/lib/fwl/"])

  enable_units(rootfs, ["systemd-networkd", "f-firstboot", "ssh"])
  mask_units(rootfs, SUPERSEDED_UNITS)
  create_operator(rootfs, manifest.prefix + "/bin/einheit-f")

  # Verify what was built, in the rootfs, before it is sealed. An
  # image that is missing something must not become a board that is.
  report = f_install.verify(manifest, root=rootfs)
  f_install.render_report(report)
  if report.verdict is f_install.Verdict.INCOMPLETE:
    raise FileNotFoundError(
      "the staged rootfs is incomplete; no archive was written")

  unresolved = check_binaries_load(rootfs, manifest)
  if unresolved:
    raise FileNotFoundError(
      "every file is in place and the binaries cannot load; no "
      "archive was written. Add the package that provides each "
      "library to PACKAGES:\n" + "\n".join(
        f"  {dest}: {', '.join(libs)}"
        for dest, libs in sorted(unresolved.items())))

  stamp = datetime.datetime.now().strftime("%Y%m%d")
  archive = out_dir / f"f-appliance-{arch}-{stamp}.tar.gz"
  run(["sudo", "tar", "czf", archive, "-C", rootfs, "."])
  return archive
def build_parser():
  """Construct the argument parser."""
  parser = argparse.ArgumentParser(
    description="Build an f appliance rootfs image.")
  parser.add_argument("--build-dir", default=str(REPO / "build-aarch64"),
                      help="Directory holding the built binaries")
  parser.add_argument("--out", default=None,
                      help="Where to assemble the image")
  parser.add_argument("--suite", default="trixie")
  parser.add_argument("--arch", default="arm64")
  parser.add_argument("--mirror", default=DEFAULT_MIRROR,
                      help="Debian mirror to bootstrap from")
  parser.add_argument("--skip-bootstrap", action="store_true",
                      help="Assume the rootfs is already there")
  return parser
def main(argv=None):
  """Entry point. Returns a process exit code."""
  args = build_parser().parse_args(argv)
  if os.geteuid() != 0:
    print("build-image: this writes a root-owned rootfs and must be "
          "run as root. Re-run it with sudo.", file=sys.stderr)
    return 1
  build_dir = Path(args.build_dir)
  out_dir = Path(args.out or (build_dir / "image"))
  try:
    archive = build(build_dir, out_dir, args.suite, args.arch,
                    args.skip_bootstrap, args.mirror)
  except FileNotFoundError as exc:
    print(f"build-image: {exc}", file=sys.stderr)
    return 1
  except subprocess.CalledProcessError as exc:
    print(f"build-image: {exc.cmd[0]} failed ({exc.returncode})",
          file=sys.stderr)
    return 1
  print(f"\n=== image built: {archive} ===")
  return 0
if __name__ == "__main__":
  sys.exit(main())
