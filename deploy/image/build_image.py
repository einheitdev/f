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
  deploy/image/build_image.py --build-dir build-aarch64 [--out DIR]

Prerequisites: debootstrap, qemu-user-static, and a cross build in
--build-dir.
"""

import argparse
import datetime
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO / "deploy"))
import f_install  # noqa: E402

# Packages the appliance needs and does not ship. `f-install verify`
# knows about the ones it can see as files; this is the list that puts
# them there.
PACKAGES = [
  "systemd", "systemd-resolved", "openssh-server",
  "python3", "python3-pip", "python3-yaml",
  "clang", "llvm", "libbpf1", "bpftool",
  "dnsmasq", "chrony",
  "sudo", "curl", "ca-certificates", "iproute2", "ethtool",
]
def run(argv, **kwargs):
  """Run a command, failing the build if it fails."""
  print("+ " + " ".join(str(a) for a in argv), flush=True)
  return subprocess.run([str(a) for a in argv], check=True, **kwargs)
def debootstrap(rootfs, suite, arch):
  """Create the base rootfs, unless one is already there."""
  if (rootfs / "usr/bin").is_dir():
    print(f"rootfs already at {rootfs}, reusing")
    return
  run(["sudo", "debootstrap", f"--arch={arch}", "--foreign",
       "--include=" + ",".join(PACKAGES), suite, rootfs,
       "http://deb.debian.org/debian"])
  qemu = Path("/usr/bin/qemu-aarch64-static")
  if arch == "arm64" and qemu.exists():
    run(["sudo", "cp", qemu, rootfs / "usr/bin/"])
  run(["sudo", "chroot", rootfs,
       "/debootstrap/debootstrap", "--second-stage"])
def enable_units(rootfs, units):
  """Enable the units that must be on before the first boot."""
  run(["sudo", "chroot", rootfs, "systemctl", "enable", *units])
def create_operator(rootfs, shell):
  """Give the box its operator account, with the CLI as its shell."""
  script = (
    f"useradd -m -s {shell} operator 2>/dev/null || true\n"
    "echo 'operator:operator' | chpasswd\n"
    "echo 'operator ALL=(ALL) NOPASSWD: ALL' "
    "> /etc/sudoers.d/operator\n")
  run(["sudo", "chroot", rootfs, "bash", "-c", script])
def build(build_dir, out_dir, suite, arch, skip_bootstrap=False):
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
    debootstrap(rootfs, suite, arch)

  actions = f_install.stage(manifest, build_dir, REPO, rootfs,
                            remove_stale=True, with_pip=False)
  for action in actions:
    print(f"{'ok  ' if action.done else 'SKIP'} {action.item.id:<22} "
          f"{action.detail}")

  # The compiler is pure Python and its dependencies are too, so it
  # can be installed into the chroot rather than cross-built.
  fwl_src = rootfs / "usr/local/lib/fwl"
  run(["sudo", "mkdir", "-p", fwl_src])
  run(["sudo", "cp", "-r", REPO / "fwl/fwl", fwl_src])
  run(["sudo", "cp", REPO / "fwl/pyproject.toml", fwl_src])
  run(["sudo", "chroot", rootfs, "pip3", "install",
       "--break-system-packages", "/usr/local/lib/fwl/"])

  enable_units(rootfs, ["systemd-networkd", "f-firstboot", "ssh"])
  create_operator(rootfs, manifest.prefix + "/bin/einheit-f")

  # Verify what was built, in the rootfs, before it is sealed. An
  # image that is missing something must not become a board that is.
  report = f_install.verify(manifest, root=rootfs)
  f_install.render_report(report)
  if report.verdict is f_install.Verdict.INCOMPLETE:
    raise FileNotFoundError(
      "the staged rootfs is incomplete; no archive was written")

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
  parser.add_argument("--skip-bootstrap", action="store_true",
                      help="Assume the rootfs is already there")
  return parser
def main(argv=None):
  """Entry point. Returns a process exit code."""
  args = build_parser().parse_args(argv)
  build_dir = Path(args.build_dir)
  out_dir = Path(args.out or (build_dir / "image"))
  try:
    archive = build(build_dir, out_dir, args.suite, args.arch,
                    args.skip_bootstrap)
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
