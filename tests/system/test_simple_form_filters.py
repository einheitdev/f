#!/usr/bin/env python3
"""A policy in the simple `@xdp(<iface>)` form actually filters.

The defect this pins: a unit written in the simple form — `@xdp(eth0)`
with no `zone` declaration, the form the docs teach and the first one
anybody writes — compiled to a manifest whose `zones` array was empty.
`fd` derived every interface it attaches to from that array, so it
attached to NONE, logged `1 zone program(s)`, and reported a successful
load. Every packet on the box flowed unfiltered while every indicator
said the firewall was up.

Which is why a log line cannot be the evidence here. The measurement is
on the wire, and it is a DROP: an allow-policy test cannot tell
"attached and permitting" apart from "attached to nothing and therefore
permitting", and those are the two states this bug is about. So the
policy drops one UDP port and allows another, and the test requires
BOTH answers — the allowed port proves the path works at all, the
dropped port proves the program is in it.

Four scenarios, on a real `fd` with real XDP over a veth into a netns:

  1. the simple form, compiled by the in-tree `fwl`: filters.
  2. the same bundle with its manifest rewritten back to `"zones": []`
     — what an `fwl` older than this fix emitted, and what is already
     staged under `<bundle_dir>/current` on a deployed box that a
     package upgrade does not recompile. Must still attach and filter.
  3. a bundle naming an interface that does not exist: `fd` must refuse
     it, loudly, and must not come up reporting success.
  4. the same, on the hot-reload path rather than cold boot: a refused
     bundle must leave the running policy attached and filtering.

Run on the target, as root:
  sudo ./test_simple_form_filters.py --fd /path/to/fd
"""
import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

PASS = 0
FAIL = 0

IFACE = "fwlsimp0"
PEER = "fwlsimp0p"
NETNS = "fwlsimpns"
HOST_ADDR = "10.77.0.1"
PEER_ADDR = "10.77.0.2"
DROPPED_PORT = 9999
ALLOWED_PORT = 9998

# The simple form: no `zone` line anywhere. The @xdp argument is a bare
# interface name (FWL_V04_SPEC.md § 6.2, "one implicit zone whose name
# is the @xdp argument"; the v0.1 spec spells the hook
# `@xdp(<interface>)`).
POLICY = f"""@xdp({IFACE})
drop if pkt.proto == udp and pkt.dst_port == {DROPPED_PORT}
allow
"""

# The same shape, aimed at an interface that is not on this host.
ABSENT_POLICY = """@xdp(fwlnosuch9)
drop if pkt.proto == udp and pkt.dst_port == 9999
allow
"""


def check(name, ok, detail=""):
  global PASS, FAIL
  if ok:
    PASS += 1
    print(f"  ok   {name}")
  else:
    FAIL += 1
    print(f"  FAIL {name}{(': ' + detail) if detail else ''}")


def run(argv, **kw):
  return subprocess.run(argv, capture_output=True, text=True, **kw)


def sh(cmd):
  return subprocess.run(cmd, shell=True, capture_output=True, text=True)


def topo_up():
  topo_down()
  sh(f"ip netns add {NETNS}")
  sh(f"ip link add {IFACE} type veth peer name {PEER}")
  sh(f"ip link set {PEER} netns {NETNS}")
  sh(f"ip addr add {HOST_ADDR}/24 dev {IFACE}")
  sh(f"ip link set {IFACE} up")
  sh(f"ip -n {NETNS} addr add {PEER_ADDR}/24 dev {PEER}")
  sh(f"ip -n {NETNS} link set {PEER} up")
  sh(f"ip -n {NETNS} link set lo up")
  # Seed the neighbour entries both ways so the measurement is never
  # confused by an unanswered ARP.
  peer_mac = sh(f"cat /sys/class/net/{IFACE}/address").stdout.strip()
  host_mac = sh(
      f"ip netns exec {NETNS} cat /sys/class/net/{PEER}/address"
  ).stdout.strip()
  sh(f"ip neigh replace {PEER_ADDR} lladdr {host_mac} dev {IFACE}")
  sh(f"ip -n {NETNS} neigh replace {HOST_ADDR} lladdr {peer_mac} "
     f"dev {PEER}")


def topo_down():
  sh(f"ip netns del {NETNS}")
  sh(f"ip link del {IFACE}")


def xdp_attached(iface):
  """True when the kernel says an XDP program is on `iface`.

  Asked of the kernel, not of a log line — the whole defect was a log
  line that agreed with a kernel that had nothing attached.
  """
  out = sh(f"ip -details -json link show dev {iface}").stdout
  try:
    info = json.loads(out)
  except (ValueError, TypeError):
    return False
  for entry in info:
    if entry.get("xdp", {}).get("prog", {}).get("id"):
      return True
  return False


def python_path(fwl_root):
  """PYTHONPATH for the in-tree compiler, run under sudo.

  sudo drops PYTHONPATH and root does not share the invoking user's
  site-packages, so `click` is missing from an otherwise working
  checkout. Put the caller's site directory back rather than requiring
  a system-wide install of the compiler's dependencies.
  """
  parts = [fwl_root]
  user = os.environ.get("SUDO_USER")
  if user:
    import glob
    home = os.path.expanduser("~" + user)
    parts += sorted(glob.glob(
        os.path.join(home, ".local/lib/python3*/site-packages")))
  if os.environ.get("PYTHONPATH"):
    parts.append(os.environ["PYTHONPATH"])
  return os.pathsep.join(parts)


def compile_bundle(fwl_root, source_text, bundle_dir, work):
  """Compile `source_text` with the IN-TREE compiler.

  Deliberately not the `fwl` on PATH: an installed compiler is a
  different program from the one in this checkout, and a test that
  cannot say which one it ran is not evidence about either.
  """
  src = os.path.join(work, "policy.fw")
  with open(src, "w", encoding="utf-8") as f:
    f.write(source_text)
  shutil.rmtree(bundle_dir, ignore_errors=True)
  env = dict(os.environ, PYTHONPATH=python_path(fwl_root))
  r = run([sys.executable, "-c", "from fwl.cli import main; main()",
           "compile", src, "--bundle", bundle_dir], env=env)
  return src, r


class Daemon:
  """A real `fd`, cold-booting a real bundle, on its own pin root."""

  def __init__(self, fd_bin, work):
    self.fd_bin = fd_bin
    self.work = work
    self.root = os.path.join(work, "fdroot")
    self.pin = "/sys/fs/bpf/ftsimple"
    self.sock = f"ipc://{work}/fd.sock"
    self.log = os.path.join(work, "fd.log")
    self.proc = None

  def start(self, bundle_dir, source=None, fwl_root=None):
    os.makedirs(self.root, exist_ok=True)
    link = os.path.join(self.root, "current")
    if os.path.islink(link) or os.path.exists(link):
      os.remove(link)
    os.symlink(bundle_dir, link)
    cfg = os.path.join(self.root, "fd.yaml")
    lines = [f"pin_path: {self.pin}\n", f"socket: {self.sock}\n",
             "log_level: debug\n", "watch:\n  enabled: false\n"]
    if source is not None:
      shim = os.path.join(self.work, "fwl-shim")
      with open(shim, "w", encoding="utf-8") as f:
        f.write("#!/bin/sh\n"
                f"exec env PYTHONPATH='{python_path(fwl_root)}' "
                f"{sys.executable} "
                f"-c 'from fwl.cli import main; main()' \"$@\"\n")
      os.chmod(shim, 0o755)
      lines.append(f"  source: {source}\n")
      lines.append(f"  compiled_dir: {self.root}\n")
      lines.append(f"  fwl: {shim}\n")
    with open(cfg, "w", encoding="utf-8") as f:
      f.writelines(lines)
    logf = open(self.log, "w", encoding="utf-8")
    self.proc = subprocess.Popen(
        [self.fd_bin, "-c", cfg, "--bundle-dir", self.root, "run"],
        stdout=logf, stderr=subprocess.STDOUT)
    for _ in range(60):
      if self.proc.poll() is not None:
        break
      if "zone program(s)" in self.text() or "efus" in self.text():
        break
      time.sleep(0.25)
    time.sleep(0.5)
    return self

  def text(self):
    try:
      with open(self.log, encoding="utf-8", errors="replace") as f:
        return f.read()
    except OSError:
      return ""

  def alive(self):
    return self.proc is not None and self.proc.poll() is None

  def stop(self):
    if self.proc is not None and self.proc.poll() is None:
      self.proc.terminate()
      try:
        self.proc.wait(timeout=10)
      except subprocess.TimeoutExpired:
        self.proc.kill()
    sh(f"ip link set dev {IFACE} xdp off")
    shutil.rmtree(self.pin, ignore_errors=True)


def send_udp(port, payload):
  """Send one UDP datagram from inside the netns."""
  code = (
      "import socket,sys;"
      "s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);"
      f"s.sendto({payload!r}.encode(),('{HOST_ADDR}',{port}))"
  )
  return run(["ip", "netns", "exec", NETNS, sys.executable, "-c", code])


def arrives(port, payload, timeout=2.0):
  """True when a datagram sent to `port` reaches the host stack.

  Bound before the send, and the socket is what answers — not a
  counter, not a log. XDP_DROP frees the frame before any tap or
  socket sees it, so this is a direct read of whether the program in
  the path let it through.
  """
  srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  srv.bind(("0.0.0.0", port))
  srv.settimeout(timeout)
  try:
    send_udp(port, payload)
    try:
      data, _ = srv.recvfrom(2048)
    except socket.timeout:
      return False
    return data == payload.encode()
  finally:
    srv.close()


def assert_filters(label):
  """The wire measurement, both halves, in the order that matters.

  The allowed port FIRST: if it does not arrive the topology is broken
  and the dropped port proves nothing, so the test says which of the
  two it is instead of reporting a green drop over a dead link.
  """
  allowed = arrives(ALLOWED_PORT, "allowed-" + label)
  check(f"{label}: allowed port {ALLOWED_PORT} arrives", allowed,
        "the link itself is not carrying traffic — a DROP result "
        "below would be vacuous")
  dropped = arrives(DROPPED_PORT, "dropped-" + label)
  check(f"{label}: dropped port {DROPPED_PORT} does NOT arrive",
        not dropped,
        "the policy is not filtering — either nothing is attached or "
        "the attached program is not this policy")
  return allowed and not dropped


def scenario_simple_form(fd_bin, fwl_root, work):
  print("\n1. the simple @xdp(<iface>) form, as the compiler emits it")
  bundle = os.path.join(work, "bundle-simple")
  _, r = compile_bundle(fwl_root, POLICY, bundle, work)
  check("compiles", r.returncode == 0, r.stderr.strip())
  if r.returncode != 0:
    return
  manifest = json.load(open(os.path.join(bundle, "manifest.json")))
  check("manifest names the interface in its zones array",
        manifest["zones"] == [{"name": IFACE, "interfaces": [IFACE]}],
        json.dumps(manifest["zones"]))
  d = Daemon(fd_bin, work).start(bundle)
  try:
    check("fd is running", d.alive(), d.text()[-500:])
    check("the kernel has an XDP program on " + IFACE,
          xdp_attached(IFACE),
          "fd reported a load and attached nothing")
    assert_filters("simple form")
    check("fd's own log states the interface count",
          "attached to 1 interface(s)" in d.text(),
          "a program count alone was the whole defect")
  finally:
    d.stop()


def scenario_legacy_manifest(fd_bin, fwl_root, work):
  print("\n2. a bundle from an older fwl (manifest zones: [])")
  bundle = os.path.join(work, "bundle-legacy")
  _, r = compile_bundle(fwl_root, POLICY, bundle, work)
  if r.returncode != 0:
    check("compiles", False, r.stderr.strip())
    return
  # Rewrite the manifest to exactly what an `fwl` older than this fix
  # emitted. This is not hypothetical: it is what is already staged
  # under <bundle_dir>/current on every box deployed before the fix,
  # and a package upgrade replaces `fd` without recompiling it.
  path = os.path.join(bundle, "manifest.json")
  manifest = json.load(open(path))
  manifest["zones"] = []
  with open(path, "w", encoding="utf-8") as f:
    json.dump(manifest, f, indent=2)
  check("manifest is the pre-fix shape",
        manifest["zones"] == [] and
        manifest["programs"][0]["zone"] == IFACE)
  d = Daemon(fd_bin, work).start(bundle)
  try:
    check("fd is running", d.alive(), d.text()[-500:])
    check("the kernel has an XDP program on " + IFACE,
          xdp_attached(IFACE),
          "an already-deployed bundle stopped being enforced")
    assert_filters("legacy manifest")
  finally:
    d.stop()


def scenario_absent_interface(fd_bin, fwl_root, work):
  print("\n3. a bundle whose interface does not exist is refused")
  bundle = os.path.join(work, "bundle-absent")
  _, r = compile_bundle(fwl_root, ABSENT_POLICY, bundle, work)
  check("compiles", r.returncode == 0, r.stderr.strip())
  if r.returncode != 0:
    return
  d = Daemon(fd_bin, work).start(bundle)
  try:
    log = d.text()
    check("fd did not come up clean", not d.alive(),
          "fd is running with nothing attached — the state this "
          "whole test exists to make impossible")
    check("it says it attached to zero interfaces",
          "ZERO interfaces" in log or "attach to ZERO" in log,
          log[-800:])
    check("it names the interface it wanted",
          "fwlnosuch9" in log, log[-800:])
    check("it did not report a successful load",
          "Multi-zone bundle loaded" not in log, log[-800:])
  finally:
    d.stop()


def scenario_refused_reload_keeps_running(fd_bin, fwl_root, work):
  print("\n4. a refused reload leaves the running policy filtering")
  bundle = os.path.join(work, "bundle-reload")
  src, r = compile_bundle(fwl_root, POLICY, bundle, work)
  if r.returncode != 0:
    check("compiles", False, r.stderr.strip())
    return
  d = Daemon(fd_bin, work).start(bundle, source=src, fwl_root=fwl_root)
  try:
    if not assert_filters("before reload"):
      return
    with open(src, "w", encoding="utf-8") as f:
      f.write(ABSENT_POLICY)
    here = os.path.dirname(os.path.abspath(__file__))
    reply = run([sys.executable, os.path.join(here, "lib", "fdctl.py"),
                 "4", d.sock])
    out = reply.stdout.strip()
    check("fd rejected the unattachable bundle", '"error"' in out, out)
    check("fd is still running", d.alive(), d.text()[-500:])
    check("the kernel still has an XDP program on " + IFACE,
          xdp_attached(IFACE), "the refused reload took the "
          "firewall down with it")
    assert_filters("after refused reload")
  finally:
    d.stop()


def main():
  ap = argparse.ArgumentParser()
  ap.add_argument("--fd", default=os.path.expanduser(
      "~/f-appliance/f/build/fd"))
  ap.add_argument("--fwl-root", default=os.path.expanduser(
      "~/f-appliance/f/fwl"))
  args = ap.parse_args()

  if os.geteuid() != 0:
    print("must run as root (real XDP)")
    return 2
  for path in (args.fd, args.fwl_root):
    if not os.path.exists(path):
      print(f"missing: {path}")
      return 2

  work = tempfile.mkdtemp(prefix="ftsimple-")
  topo_up()
  try:
    scenario_simple_form(args.fd, args.fwl_root, work)
    scenario_legacy_manifest(args.fd, args.fwl_root, work)
    scenario_absent_interface(args.fd, args.fwl_root, work)
    scenario_refused_reload_keeps_running(args.fd, args.fwl_root, work)
  finally:
    topo_down()
    shutil.rmtree(work, ignore_errors=True)

  print(f"\n{PASS} passed, {FAIL} failed")
  return 1 if FAIL else 0


if __name__ == "__main__":
  sys.exit(main())
