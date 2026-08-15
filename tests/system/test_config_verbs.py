#!/usr/bin/env python3
"""Configuring a box through the CLI, on a box.

The rehearsal's step 3 — configure interfaces and zones through the
CLI — could not be done at all: no verb created a zone, no verb moved
an interface into one, and no verb put content into a policy file. The
handbook agreed, and told the operator to open an editor.

This walks the verbs that close that, on a real box:

  1. a whole `system.yaml` built from an empty file with nothing but
     `einheit-f` — zones, a port pinned to its MAC, an address, DHCP,
     DNS, a reservation — and `check system` accepting the result.
  2. `set rule` composing a policy statement, compiling it, and `fd`
     hot-reloading it.
  3. the measurement, on the wire and as a DROP.

Point 3 is the one that matters. An allow rule cannot tell "the
program is in the path" from "the program is attached to nothing and
therefore permitting", which is precisely the failure this codebase
has already shipped once (BUGLOG #43). So the rule this test composes
is a `drop`, and the evidence is a datagram that stops arriving at a
socket bound before it was sent — and a second port that keeps
arriving, which is what proves the path itself still works.

Run on the target, as root:
  sudo ./test_config_verbs.py
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

IFACE = "fcfgv0"
PEER = "fcfgv0p"
NETNS = "fcfgvns"
# A second, unused veth so there is a real port for the outside zone.
# A zone with no interface is refused by the compiler, and rightly:
# a program attached to nothing inspects nothing.
IFACE2 = "fcfgv1"
PEER2 = "fcfgv1p"
HOST_ADDR = "10.79.0.1"
PEER_ADDR = "10.79.0.2"
OUT_ADDR = "10.78.0.1"
ZONE = "bench"
OUTSIDE = "outside"
DROPPED_PORT = 9999
ALLOWED_PORT = 9998


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
  return subprocess.run(cmd, shell=True, capture_output=True,
                        text=True)


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
  peer_mac = sh(f"cat /sys/class/net/{IFACE}/address").stdout.strip()
  host_mac = sh(
      f"ip netns exec {NETNS} cat /sys/class/net/{PEER}/address"
  ).stdout.strip()
  sh(f"ip neigh replace {PEER_ADDR} lladdr {host_mac} dev {IFACE}")
  sh(f"ip -n {NETNS} neigh replace {HOST_ADDR} lladdr {peer_mac} "
     f"dev {PEER}")
  sh(f"ip link add {IFACE2} type veth peer name {PEER2}")
  sh(f"ip addr add {OUT_ADDR}/24 dev {IFACE2}")
  sh(f"ip link set {IFACE2} up")
  sh(f"ip link set {PEER2} up")


def topo_down():
  sh(f"ip netns del {NETNS}")
  sh(f"ip link del {IFACE}")
  sh(f"ip link del {IFACE2}")


def xdp_attached(iface):
  """True when the KERNEL says an XDP program is on `iface`."""
  out = sh(f"ip -details -json link show dev {iface}").stdout
  try:
    info = json.loads(out)
  except (ValueError, TypeError):
    return False
  for entry in info:
    if entry.get("xdp", {}).get("prog", {}).get("id"):
      return True
  return False


def send_udp(port, payload):
  code = (
      "import socket;"
      "s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);"
      f"s.sendto({payload!r}.encode(),('{HOST_ADDR}',{port}))"
  )
  return run(["ip", "netns", "exec", NETNS, sys.executable, "-c",
              code])


def arrives(port, payload, timeout=2.0):
  """True when a datagram sent to `port` reaches the host stack.

  The socket is what answers, not a counter and not a log line. An
  XDP_DROP frees the frame before any socket sees it, so this reads
  whether the program in the path let it through.
  """
  srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  srv.bind(("0.0.0.0", port))
  srv.settimeout(timeout)
  try:
    send_udp(port, payload)
    try:
      data, _ = srv.recvfrom(2048)
      return data.decode(errors="replace") == payload
    except socket.timeout:
      return False
  finally:
    srv.close()


class Cli:
  """`einheit-f`, pointed at a scratch tree instead of /etc/f."""

  def __init__(self, binary, work, fd_sock, confd_sock):
    self.binary = binary
    self.work = work
    self.system = os.path.join(work, "system.yaml")
    self.policy = os.path.join(work, "rules.fw")
    self.fd_sock = fd_sock
    self.confd_sock = confd_sock

  def __call__(self, *args, fmt="json"):
    argv = [
        self.binary, "--color", "never", "--format", fmt,
        "--system-config", self.system,
        "--source", self.policy,
        "--networkd-dir", os.path.join(self.work, "net"),
        "--dnsmasq-conf", os.path.join(self.work, "dnsmasq.conf"),
        "--sysctl-dir", os.path.join(self.work, "sysctl"),
        "--socket", self.fd_sock,
        "--confd-socket", self.confd_sock,
    ] + list(args)
    return run(argv)

  def json(self, *args):
    r = self(*args)
    try:
      return r.returncode, json.loads(r.stdout)
    except ValueError:
      return r.returncode, {"_stdout": r.stdout, "_stderr": r.stderr}


class Daemon:
  """A real `fd` on its own pin root, recompiling from source."""

  def __init__(self, fd_bin, fwl_bin, work, source):
    self.fd_bin = fd_bin
    self.fwl_bin = fwl_bin
    self.work = work
    self.root = os.path.join(work, "fdroot")
    self.pin = "/sys/fs/bpf/ftcfgverbs"
    self.sock = f"ipc://{work}/fd.sock"
    self.log = os.path.join(work, "fd.log")
    self.source = source
    self.proc = None

  def compile(self, bundle_dir):
    shutil.rmtree(bundle_dir, ignore_errors=True)
    return run([self.fwl_bin, "compile", self.source, "--bundle",
                bundle_dir])

  def start(self, bundle_dir):
    os.makedirs(self.root, exist_ok=True)
    link = os.path.join(self.root, "current")
    if os.path.islink(link) or os.path.exists(link):
      os.remove(link)
    os.symlink(bundle_dir, link)
    cfg = os.path.join(self.root, "fd.yaml")
    with open(cfg, "w", encoding="utf-8") as f:
      f.writelines([
          f"pin_path: {self.pin}\n",
          f"socket: {self.sock}\n",
          "log_level: debug\n",
          "watch:\n  enabled: false\n",
          f"  source: {self.source}\n",
          f"  compiled_dir: {self.root}\n",
          f"  fwl: {self.fwl_bin}\n",
      ])
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


def scenario_build_the_document(cli, mac):
  """A whole system.yaml, from an empty file, with only verbs."""
  print("\n[1] the system configuration, built from nothing")
  with open(cli.system, "w", encoding="utf-8") as f:
    f.write("")

  steps = [
      ("set zone", ("set", "zone", ZONE)),
      ("set interface zone", ("set", "interface", "zone", IFACE,
                              ZONE)),
      ("set address", ("set", "address", IFACE,
                       f"{HOST_ADDR}/24")),
      ("set dhcp", ("set", "dhcp", ZONE, "10.79.0.100-10.79.0.200",
                    "12h")),
      ("set dns", ("set", "dns", ZONE, "9.9.9.9")),
      ("set reservation", ("set", "reservation",
                           "aa:bb:cc:dd:ee:01", "10.79.0.50",
                           "bench1")),
  ]
  for name, argv in steps:
    r = cli(*argv)
    check(f"{name} accepted", r.returncode == 0,
          (r.stderr or r.stdout).strip()[:200])

  text = open(cli.system, encoding="utf-8").read()
  check("the document names the zone", f"{ZONE}:" in text)
  check("the port is pinned to its hardware address",
        mac in text, text)
  check("the address is on the port", f"{HOST_ADDR}/24" in text)
  check("dhcp is bound to the zone",
        "10.79.0.100-10.79.0.200" in text)
  check("dns is bound to the zone", "9.9.9.9" in text)
  check("the reservation is in the same document",
        "10.79.0.50" in text)
  # No key anywhere in a service block names an interface, here as in
  # the model: that is what makes the rogue-DHCP case inexpressible.
  services = (
    text.split("services:", 1)[-1] if "services:" in text else "")
  check("no service names an interface", IFACE not in services,
        services)

  r = cli("check", "system", fmt="table")
  check("check system accepts what the verbs wrote",
        r.returncode == 0 and "ok" in r.stdout.lower(),
        (r.stdout + r.stderr).strip()[:300])

  rc, body = cli.json("show", "system")
  check("show system reports the port as present",
        json.dumps(body).find(IFACE) >= 0, json.dumps(body)[:300])


def scenario_refusals(cli):
  """The refusals, which are half of what makes a verb usable."""
  print("\n[2] what the verbs refuse")
  before = open(cli.system, encoding="utf-8").read()

  r = cli("set", "interface", "zone", IFACE, "nosuchzone")
  check("an undeclared zone is refused by name",
        r.returncode != 0 and "not declared" in (r.stdout + r.stderr),
        (r.stdout + r.stderr)[:200])

  r = cli("no", "zone", ZONE)
  check("a zone still holding a port is not deleted",
        r.returncode != 0 and IFACE in (r.stdout + r.stderr),
        (r.stdout + r.stderr)[:200])

  r = cli("set", "dhcp", "nosuchzone", "10.1.0.1-10.1.0.9")
  check("a service on an undeclared zone is refused",
        r.returncode != 0, (r.stdout + r.stderr)[:200])

  check("nothing was written by any of them",
        open(cli.system, encoding="utf-8").read() == before)


def scenario_policy(cli, daemon, work):
  """`set rule` composes a rule, and the wire says it is in the path."""
  print("\n[3] the policy, composed and measured")
  # A starting policy that allows everything, so the measurement below
  # starts from "both ports arrive" and the DROP is the change.
  with open(cli.policy, "w", encoding="utf-8") as f:
    f.write(f"zone {ZONE} = [{IFACE}]\n\n"
            f"@xdp({ZONE})\n\n"
            f"count {ZONE}_total\n\n"
            f"allow if pkt.proto == icmp\n\n"
            "default allow\n")

  bundle = os.path.join(work, "bundle0")
  r = daemon.compile(bundle)
  check("the starting policy compiles", r.returncode == 0,
        (r.stdout + r.stderr)[-300:])
  daemon.start(bundle)
  check("fd is running", daemon.alive(), daemon.text()[-400:])
  check("the kernel has an XDP program on the port",
        xdp_attached(IFACE), daemon.text()[-400:])

  check("before the rule, the port arrives",
        arrives(DROPPED_PORT, "before"))

  rc, rows = cli.json("show", "policy", ZONE)
  stmts = (
    [r for r in rows if r.get("ZONE") == ZONE]
    if isinstance(rows, list) else [])
  check("show policy numbers the statements", len(stmts) == 3,
        json.dumps(rows)[:300])
  check("show policy marks the unconditional statement",
        any(r.get("STATEMENT") == "default allow"
            and "stops here" in r.get("MATCHES", "")
            for r in stmts), json.dumps(stmts)[:300])
  check("show policy is a parseable document under --format json",
        isinstance(rows, list), json.dumps(rows)[:200])

  r = cli("set", "rule", ZONE, "drop", "udp", str(DROPPED_PORT))
  out = r.stdout + r.stderr
  check("set rule reported the reload", r.returncode == 0, out[:400])
  check("set rule reported where it put the statement",
        "position" in out or "before" in out, out[:400])

  text = open(cli.policy, encoding="utf-8").read()
  check("the rule is in the source file",
        f"pkt.dst_port == {DROPPED_PORT}" in text, text)
  check("the rule is above the unconditional default",
        text.index(f"dst_port == {DROPPED_PORT}")
        < text.index("default allow"), text)

  # The measurement. A DROP, because an allow rule cannot tell an
  # attached program from an absent one.
  check("the composed rule DROPS its port on the wire",
        not arrives(DROPPED_PORT, "after"), daemon.text()[-500:])
  check("the port it does not name still arrives",
        arrives(ALLOWED_PORT, "control"),
        "the path itself is broken, so the drop above proves nothing")
  check("the kernel still has a program on the port",
        xdp_attached(IFACE))

  # ...and taking it away puts the traffic back.
  rc, rows = cli.json("show", "policy", ZONE)
  index = None
  if isinstance(rows, list):
    for r in rows:
      if f"dst_port == {DROPPED_PORT}" in r.get("STATEMENT", ""):
        index = r.get("#")
  check("show policy gives the rule a position", index is not None,
        json.dumps(rows)[:300])
  if index is not None:
    r = cli("no", "rule", ZONE, str(index))
    check("no rule reported the reload", r.returncode == 0,
          (r.stdout + r.stderr)[:300])
    check("the port arrives again once the rule is gone",
          arrives(DROPPED_PORT, "removed"), daemon.text()[-500:])


def scenario_bad_policy(cli, daemon):
  """A rule that will not compile never reaches the file."""
  print("\n[4] the compiler has the last word before the write")
  before = open(cli.policy, encoding="utf-8").read()
  r = cli("set", "rule", "nosuchzone", "drop", "udp", "1234")
  check("a zone the policy does not have is refused",
        r.returncode != 0, (r.stdout + r.stderr)[:200])
  r = cli("set", "rule", ZONE, "drop", "4444")
  check("a port with no protocol guard is refused",
        r.returncode != 0 and "protocol" in (r.stdout + r.stderr),
        (r.stdout + r.stderr)[:300])
  check("the policy file is untouched",
        open(cli.policy, encoding="utf-8").read() == before)
  check("fd is still running and still attached",
        daemon.alive() and xdp_attached(IFACE))
  check("the traffic is unaffected", arrives(ALLOWED_PORT, "still"))


def scenario_forward(cli, work, daemon):
  """A port forward is written as a pair with one guard."""
  print("\n[5] a port forward, as one edit")
  # Two zones, so there is somewhere to forward to. The inside zone is
  # derived from the system configuration, never asked for.
  # The outside zone gets a real port, because a zone with no
  # interface is refused by the compiler — a program attached to
  # nothing inspects nothing.
  r = cli("set", "zone", OUTSIDE)
  check("the outside zone is declared", r.returncode == 0,
        (r.stdout + r.stderr)[:200])
  r = cli("set", "interface", "zone", IFACE2, OUTSIDE)
  check("the outside port is in it", r.returncode == 0,
        (r.stdout + r.stderr)[:200])
  r = cli("set", "address", IFACE2, f"{OUT_ADDR}/24")
  check("the outside port is addressed", r.returncode == 0,
        (r.stdout + r.stderr)[:200])

  with open(cli.policy, "w", encoding="utf-8") as f:
    f.write(f"zone {ZONE} = [{IFACE}]\n"
            f"zone {OUTSIDE} = [{IFACE2}]\n\n"
            f"@xdp({ZONE})\n\n"
            "allow if conntrack(pkt).state in [established, related]\n"
            "\ndefault drop\n\n"
            f"@xdp({OUTSIDE})\n\n"
            "default drop\n")
  r = cli("set", "forward", OUTSIDE, "tcp", "8080",
          f"{HOST_ADDR}:80")
  out = r.stdout + r.stderr
  text = open(cli.policy, encoding="utf-8").read()
  check("the forward names the inside zone from the model",
        f"redirect to {ZONE}" in text, out[:400] + "\n" + text)
  check("both halves carry the same guard",
        text.count("pkt.proto == tcp and pkt.dst_port == 8080") == 2,
        text)
  check("the dnat is written", f"dnat to {HOST_ADDR}:80" in text,
        text)
  r = cli("no", "forward", OUTSIDE, "tcp", "8080")
  text = open(cli.policy, encoding="utf-8").read()
  check("no forward removes both halves",
        "dst_port == 8080" not in text, text)
  check("fd survived all of it", daemon.alive())


def main():
  ap = argparse.ArgumentParser(description=__doc__)
  ap.add_argument("--fd", default="/usr/local/bin/fd")
  ap.add_argument("--fwl", default="/usr/local/bin/fwl")
  ap.add_argument("--cli", default="/usr/local/bin/einheit-f")
  args = ap.parse_args()

  if os.geteuid() != 0:
    print("must run as root (XDP attach, netns, veth)")
    return 2
  for path in (args.fd, args.fwl, args.cli):
    if not os.path.exists(path):
      print(f"missing: {path}")
      return 2

  work = tempfile.mkdtemp(prefix="fcfgverbs-")
  os.makedirs(os.path.join(work, "net"), exist_ok=True)
  os.makedirs(os.path.join(work, "sysctl"), exist_ok=True)
  daemon = None
  try:
    topo_up()
    mac = sh(f"cat /sys/class/net/{IFACE}/address").stdout.strip()
    # No f-confd in this scenario: the direct path is the one that has
    # to degrade honestly, and it is the one a box without the daemon
    # running actually takes.
    cli = Cli(args.cli, work, f"ipc://{work}/fd.sock",
              f"ipc://{work}/no-confd.sock")
    daemon = Daemon(args.fd, args.fwl, work, cli.policy)
    cli.fd_sock = daemon.sock

    scenario_build_the_document(cli, mac)
    scenario_refusals(cli)
    scenario_policy(cli, daemon, work)
    scenario_bad_policy(cli, daemon)
    scenario_forward(cli, work, daemon)
  finally:
    if daemon is not None:
      daemon.stop()
    topo_down()
    shutil.rmtree(work, ignore_errors=True)

  print(f"\n{PASS} passed, {FAIL} failed")
  return 1 if FAIL else 0


if __name__ == "__main__":
  sys.exit(main())
