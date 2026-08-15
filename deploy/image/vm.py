#!/usr/bin/env python3
"""Boot an f appliance image on a workstation, with wire on both sides.

`build_image.py` produces a rootfs. Until this file existed, nothing
could say whether that rootfs boots: the step was recorded as unwalked
because there was no aarch64 board free, and a board is not what the
step needs. `qemu-system-aarch64` boots the image, `qemu-user-static`
runs the chroot that builds it, and both are packages.

What it gives you is a bench, not just a boot:

  * three virtio NICs — one on user-mode networking for the control
    path, and two on host taps
  * each tap on its own bridge, and each bridge reaching a network
    namespace with a real Linux host in it. The bridges carry no
    address on the host, so the ONLY path from `left` to `right` is
    through the appliance. That is what makes "nothing was forwarded"
    a measurement rather than a hope.
  * the appliance's own console captured to a file, because the
    interesting failures happen before sshd

The fabric mirrors the physical rig's netns scenarios deliberately: a
promiscuous sniffer on the interface a frame arrived on is not a
witness that anything accepted it, and this bench has real stacks on
both sides for the same reason `l2_03` does.

Usage:
  deploy/image/vm.py prepare --rootfs DIR --out DIR
  deploy/image/vm.py net-up
  deploy/image/vm.py run --out DIR
  deploy/image/vm.py net-down

Emulation is TCG: there is no aarch64 host CPU under this. Expect a
boot to take minutes and do not measure throughput on it.
"""

import argparse
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

# The fabric. Names are prefixed so that a half-cleaned run is
# recognisable on a workstation that has other bridges on it.
LAN_BRIDGE = "fvm-brlan"
WAN_BRIDGE = "fvm-brwan"
LAN_TAP = "fvm-taplan"
WAN_TAP = "fvm-tapwan"
LEFT_NS = "fvm-left"
RIGHT_NS = "fvm-right"
LEFT_VETH = "fvm-vl"
RIGHT_VETH = "fvm-vr"

# Addresses. The appliance holds .1 on each side; the hosts hold .2.
LAN_NET = "10.10.1"
WAN_NET = "10.10.2"
LAN_BOX = f"{LAN_NET}.1"
WAN_BOX = f"{WAN_NET}.1"
LEFT_HOST = f"{LAN_NET}.2"
RIGHT_HOST = f"{WAN_NET}.2"

# MACs. firstboot pins interface names to these, so they are part of
# the thing under test and must not drift between boots.
MGMT_MAC = "52:54:00:f0:00:01"
LAN_MAC = "52:54:00:f0:00:02"
WAN_MAC = "52:54:00:f0:00:03"

SSH_PORT = 2222
def run(argv, check=True, **kwargs):
  """Run a command, echoing it first."""
  print("+ " + " ".join(str(a) for a in argv), flush=True)
  return subprocess.run([str(a) for a in argv], check=check, **kwargs)
def _quiet(argv):
  """Run a command and swallow its result. Teardown only."""
  subprocess.run([str(a) for a in argv], check=False,
                 capture_output=True)
def kernel_and_initrd(rootfs):
  """Find the kernel and initramfs inside a rootfs.

  The appliance image carries no kernel of its own — on the product
  board it comes from the vendor BSP — so `prepare` installs Debian's
  generic arm64 kernel into the rootfs before calling this. That is a
  harness addition and it is deliberately visible here rather than
  buried: nothing else about the image is changed to make it boot.

  Returns:
    A (vmlinuz, initrd) pair of Paths.

  Raises:
    FileNotFoundError: When the rootfs has no kernel in it.
  """
  boot = Path(rootfs) / "boot"
  kernels = sorted(boot.glob("vmlinuz-*"))
  initrds = sorted(boot.glob("initrd.img-*"))
  if not kernels or not initrds:
    raise FileNotFoundError(
      f"no kernel in {boot}; run `prepare` first, which installs "
      f"linux-image-arm64 into the rootfs")
  return kernels[-1], initrds[-1]
def install_kernel(rootfs):
  """Put a kernel and an initramfs into the rootfs, in the chroot.

  This is the second half of the chroot step `build_image.py` walks —
  the same binfmt path, the same `sudo chroot`, doing the one thing a
  rootfs needs before it can be booted at all.
  """
  # Force IPv4, for the reason `build_image.mirror_preflight`
  # documents at length: deb.debian.org is anycast, and on a host
  # whose IPv6 path to the chosen POP is black-holed every fetch sits
  # in `Connecting to ...` until its timeout. apt's timeout is 120 s
  # per attempt rather than wget's infinity, so this does not hang
  # forever — it merely turns a two-minute step into an hour, which is
  # worse in one way: it looks like emulation being slow.
  #
  # Written unconditionally rather than probed. The build's preflight
  # probes because it can act on the answer; here the setting costs
  # nothing on a host where IPv6 works, and this is a throwaway rootfs
  # for a bench.
  script = (
    "export DEBIAN_FRONTEND=noninteractive\n"
    "echo 'Acquire::ForceIPv4 \"true\";' "
    "> /etc/apt/apt.conf.d/99-f-bench-ipv4\n"
    "apt-get update\n"
    "apt-get install -y --no-install-recommends "
    "linux-image-arm64 initramfs-tools\n")
  run(["sudo", "chroot", rootfs, "bash", "-c", script])
def enable_serial_console(rootfs):
  """Let the console log carry the boot, including what fails early."""
  run(["sudo", "chroot", rootfs, "systemctl", "enable",
       "serial-getty@ttyAMA0.service"])
def authorize(rootfs, pubkey):
  """Install a throwaway key for root, so the run can be scripted.

  The appliance's own operator account keeps its CLI login shell; this
  is a second door for the harness, and it is the only change made to
  the image's access control.
  """
  script = (
    "mkdir -p /root/.ssh\n"
    "chmod 700 /root/.ssh\n"
    f"echo '{pubkey.strip()}' > /root/.ssh/authorized_keys\n"
    "chmod 600 /root/.ssh/authorized_keys\n"
    "sed -i 's/^#*PermitRootLogin.*/PermitRootLogin prohibit-password/' "
    "/etc/ssh/sshd_config\n")
  run(["sudo", "chroot", rootfs, "bash", "-c", script])
def write_fstab(rootfs):
  """Give the box a root entry and the bpffs mount fd insists on.

  `fd.service` carries `ConditionPathIsMountPoint=/sys/fs/bpf`, and a
  unit whose condition fails is *skipped*, not failed — which would
  make the missing-bundle case indistinguishable from a box that never
  tried. systemd mounts bpffs itself on a modern system; the fstab
  line makes it explicit so the distinction cannot go quiet.
  """
  fstab = ("/dev/vda  /  ext4  errors=remount-ro  0 1\n"
           "bpf  /sys/fs/bpf  bpf  nosuid,nodev  0 0\n")
  run(["sudo", "tee", str(Path(rootfs) / "etc/fstab")],
      input=fstab.encode(), stdout=subprocess.DEVNULL)
def make_disk(rootfs, disk, size_mb):
  """Turn the rootfs directory into a raw ext4 disk image."""
  if disk.exists():
    disk.unlink()
  run(["truncate", "-s", f"{size_mb}M", disk])
  # -d populates from a directory; as root it keeps ownership, which
  # matters for /etc/shadow and for the ssh host keys.
  run(["sudo", "mkfs.ext4", "-q", "-F", "-L", "f-root", "-d",
       str(rootfs), str(disk)])
def prepare(rootfs, out, size_mb, pubkey):
  """Make a bootable disk out of a staged rootfs.

  Returns:
    A (disk, vmlinuz, initrd) triple of Paths.
  """
  out.mkdir(parents=True, exist_ok=True)
  install_kernel(rootfs)
  enable_serial_console(rootfs)
  write_fstab(rootfs)
  if pubkey:
    authorize(rootfs, pubkey)
  vmlinuz, initrd = kernel_and_initrd(rootfs)
  host_kernel = out / "vmlinuz"
  host_initrd = out / "initrd.img"
  run(["sudo", "cp", str(vmlinuz), str(host_kernel)])
  run(["sudo", "cp", str(initrd), str(host_initrd)])
  run(["sudo", "chown", f"{os.getuid()}:{os.getgid()}",
       str(host_kernel), str(host_initrd)])
  disk = out / "disk.img"
  make_disk(rootfs, disk, size_mb)
  run(["sudo", "chown", f"{os.getuid()}:{os.getgid()}", str(disk)])
  return disk, host_kernel, host_initrd
def net_up(user=None):
  """Build the two-sided fabric: bridge, tap, veth, namespace.

  The host end of each bridge deliberately has no address. A host that
  can route between the two sides is a host that can answer a test the
  appliance failed, and this bench exists to make that impossible.
  """
  user = user or os.environ.get("SUDO_USER") or os.environ.get("USER")
  unmanage = []
  for bridge, tap, ns, veth, net in (
      (LAN_BRIDGE, LAN_TAP, LEFT_NS, LEFT_VETH, LAN_NET),
      (WAN_BRIDGE, WAN_TAP, RIGHT_NS, RIGHT_VETH, WAN_NET)):
    run(["sudo", "ip", "link", "add", bridge, "type", "bridge"])
    run(["sudo", "ip", "link", "set", bridge, "up"])
    run(["sudo", "ip", "tuntap", "add", "dev", tap, "mode", "tap",
         "user", user])
    run(["sudo", "ip", "link", "set", tap, "master", bridge])
    run(["sudo", "ip", "link", "set", tap, "up"])
    run(["sudo", "ip", "netns", "add", ns])
    run(["sudo", "ip", "link", "add", f"{veth}h", "type", "veth",
         "peer", "name", f"{veth}n"])
    run(["sudo", "ip", "link", "set", f"{veth}h", "master", bridge])
    run(["sudo", "ip", "link", "set", f"{veth}h", "up"])
    run(["sudo", "ip", "link", "set", f"{veth}n", "netns", ns])
    run(["sudo", "ip", "-n", ns, "link", "set", "lo", "up"])
    run(["sudo", "ip", "-n", ns, "addr", "add", f"{net}.2/24",
         "dev", f"{veth}n"])
    run(["sudo", "ip", "-n", ns, "link", "set", f"{veth}n", "up"])
    unmanage += [bridge, tap, f"{veth}h"]
  # A workstation running NetworkManager will otherwise adopt these,
  # give them addresses, and become a second router on a bench whose
  # whole argument is that only the appliance can carry a packet
  # across.
  for link in unmanage:
    _quiet(["sudo", "nmcli", "device", "set", link, "managed", "no"])
  # The left host routes everything through the appliance. The right
  # host is given only the return route it would have on a real
  # segment — without it a reply cannot come back and every negative
  # result would be explained by routing rather than by policy.
  run(["sudo", "ip", "-n", LEFT_NS, "route", "add", "default",
       "via", LAN_BOX])
  run(["sudo", "ip", "-n", RIGHT_NS, "route", "add", f"{LAN_NET}.0/24",
       "via", WAN_BOX])
def net_down():
  """Tear the fabric down. Safe to run against a half-built one."""
  for ns in (LEFT_NS, RIGHT_NS):
    _quiet(["sudo", "ip", "netns", "del", ns])
  for link in (LAN_TAP, WAN_TAP, f"{LEFT_VETH}h", f"{RIGHT_VETH}h",
               LAN_BRIDGE, WAN_BRIDGE):
    _quiet(["sudo", "ip", "link", "del", link])
def qemu_argv(disk, kernel, initrd, console, memory=2048, cpus=4,
              ssh_port=SSH_PORT):
  """The command line that boots the appliance."""
  return [
    "qemu-system-aarch64",
    "-machine", "virt", "-cpu", "cortex-a72",
    "-smp", str(cpus), "-m", str(memory),
    "-kernel", str(kernel), "-initrd", str(initrd),
    "-append", "root=/dev/vda rw console=ttyAMA0 panic=10",
    "-drive", f"file={disk},format=raw,if=none,id=hd0",
    "-device", "virtio-blk-pci,drive=hd0",
    "-netdev",
    f"user,id=n0,hostfwd=tcp:127.0.0.1:{ssh_port}-:22",
    "-device", f"virtio-net-pci,netdev=n0,mac={MGMT_MAC}",
    "-netdev",
    f"tap,id=n1,ifname={LAN_TAP},script=no,downscript=no",
    "-device", f"virtio-net-pci,netdev=n1,mac={LAN_MAC}",
    "-netdev",
    f"tap,id=n2,ifname={WAN_TAP},script=no,downscript=no",
    "-device", f"virtio-net-pci,netdev=n2,mac={WAN_MAC}",
    "-display", "none",
    "-serial", f"file:{console}",
    "-monitor", "none",
  ]
def boot(disk, kernel, initrd, console, **kwargs):
  """Start the VM in the background and return the Popen."""
  argv = qemu_argv(disk, kernel, initrd, console, **kwargs)
  print("+ " + " ".join(argv), flush=True)
  return subprocess.Popen(argv, stdout=subprocess.DEVNULL,
                          stderr=subprocess.PIPE)
def wait_for_ssh(port=SSH_PORT, timeout=900, proc=None, key=None):
  """Block until the box RUNS A COMMAND over ssh.

  Not until the port accepts. Under qemu's user-mode networking the
  host-forwarded port is served by qemu itself, so a TCP connect to it
  succeeds the moment the emulator is up and says nothing whatever
  about the guest — sshd need not exist yet, or at all.

  That is not a hypothetical distinction. The first full run of the
  walk passed `boot` in every phase and then read empty output from
  every command in the two phases that do not begin by waiting for a
  unit: `systemctl show fd.service` returned nothing, and the check
  reading it recorded `fd.service is None` as a PASS, because None is
  not "active". A connect test measured qemu; this runs `true` on the
  box.

  Args:
    port: Host port forwarded to the guest's 22.
    timeout: Seconds to wait.
    proc: The qemu Popen, so a dead emulator is reported as itself
      rather than as a timeout.
    key: The private key to log in with. Without one this falls back
      to the connect test and says so by returning "port-only".

  Returns:
    "ready" when a command ran, "port-only" when only the port could
    be tested, or False on timeout.
  """
  deadline = time.monotonic() + timeout
  while time.monotonic() < deadline:
    if proc is not None and proc.poll() is not None:
      err = (proc.stderr.read().decode() if proc.stderr else "")
      raise RuntimeError(f"qemu exited early: {err.strip()}")
    with socket.socket() as sock:
      sock.settimeout(2)
      try:
        sock.connect(("127.0.0.1", port))
      except OSError:
        time.sleep(2)
        continue
    if key is None:
      return "port-only"
    try:
      proof = ssh(key, "echo ready", port=port, timeout=30)
    except subprocess.TimeoutExpired:
      time.sleep(2)
      continue
    if proof.returncode == 0 and "ready" in proof.stdout:
      return "ready"
    time.sleep(2)
  return False
def ssh_argv(key, port=SSH_PORT):
  """The ssh prefix used for every command sent to the box."""
  return [
    "ssh", "-i", str(key), "-p", str(port),
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "LogLevel=ERROR",
    "-o", "ConnectTimeout=10",
    "root@127.0.0.1",
  ]
def ssh(key, command, port=SSH_PORT, check=False, timeout=120):
  """Run one command on the box and return the CompletedProcess."""
  return subprocess.run(ssh_argv(key, port) + [command],
                        capture_output=True, text=True, check=check,
                        timeout=timeout)
def ns_run(ns, command, timeout=60, check=False):
  """Run a command inside one of the bench's namespaces."""
  return subprocess.run(
    ["sudo", "ip", "netns", "exec", ns, "bash", "-c", command],
    capture_output=True, text=True, check=check, timeout=timeout)
def shutdown(proc, key, port=SSH_PORT, timeout=180):
  """Ask the box to power off, and make sure qemu is gone."""
  ssh(key, "systemctl poweroff", port=port, timeout=30)
  try:
    proc.wait(timeout=timeout)
  except subprocess.TimeoutExpired:
    proc.kill()
    proc.wait(timeout=30)
def keypair(out):
  """Make (once) the throwaway keypair the harness logs in with."""
  key = Path(out) / "id_ed25519"
  if not key.exists():
    key.parent.mkdir(parents=True, exist_ok=True)
    run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(key),
         "-C", "f-vm-harness"], stdout=subprocess.DEVNULL)
  return key, (key.with_suffix(".pub")).read_text(encoding="utf-8")
def require_tools():
  """Name every missing prerequisite at once.

  Raises:
    FileNotFoundError: With all of them in the message.
  """
  needed = {
    "qemu-system-aarch64": "qemu-system-arm",
    "mkfs.ext4": "e2fsprogs",
    "ip": "iproute2",
    "ssh": "openssh-client",
    "debootstrap": "debootstrap",
  }
  # Everything here except ssh is run through sudo, and half of it
  # lives in /usr/sbin — which is not on a desktop user's PATH. Asking
  # `which` alone reports e2fsprogs as missing on a box that has it.
  sbin = ("/usr/sbin", "/sbin", "/usr/local/sbin")
  missing = [
    f"{tool} ({pkg})" for tool, pkg in needed.items()
    if shutil.which(tool) is None
    and not any((Path(d) / tool).exists() for d in sbin)]
  if missing:
    raise FileNotFoundError("missing: " + ", ".join(missing))
def build_parser():
  """Construct the argument parser."""
  parser = argparse.ArgumentParser(
    prog="vm.py", description="Boot an f appliance image under qemu.")
  sub = parser.add_subparsers(dest="command", required=True)
  prep = sub.add_parser("prepare", help="Make a bootable disk")
  prep.add_argument("--rootfs", required=True)
  prep.add_argument("--out", required=True)
  prep.add_argument("--size-mb", type=int, default=6144)
  runner = sub.add_parser("run", help="Boot it and wait for ssh")
  runner.add_argument("--out", required=True)
  sub.add_parser("net-up", help="Build the two-sided fabric")
  sub.add_parser("net-down", help="Tear the fabric down")
  sub.add_parser("check", help="Report missing prerequisites")
  return parser
def main(argv=None):
  """Entry point. Returns a process exit code."""
  args = build_parser().parse_args(argv)
  if args.command == "check":
    try:
      require_tools()
    except FileNotFoundError as exc:
      print(f"vm: {exc}", file=sys.stderr)
      return 1
    print("all prerequisites present")
    return 0
  if args.command == "net-up":
    net_up()
    return 0
  if args.command == "net-down":
    net_down()
    return 0
  out = Path(args.out)
  if args.command == "prepare":
    key, pub = keypair(out)
    disk, kernel, initrd = prepare(Path(args.rootfs), out,
                                   args.size_mb, pub)
    print(f"disk={disk}\nkernel={kernel}\ninitrd={initrd}\nkey={key}")
    return 0
  key, _ = keypair(out)
  proc = boot(out / "disk.img", out / "vmlinuz", out / "initrd.img",
              out / "console.log")
  if not wait_for_ssh(proc=proc, key=key):
    proc.kill()
    print("vm: the box never answered on ssh", file=sys.stderr)
    return 1
  print(f"up: ssh -i {key} -p {SSH_PORT} root@127.0.0.1")
  return 0
if __name__ == "__main__":
  sys.exit(main())
