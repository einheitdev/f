#!/usr/bin/env python3
"""`count <name>` is readable from the CLI, against the rule that named it.

The gap this closes was stated rather than papered over: a policy's
`count` statements write into that zone's `fwl_counters_<zone>` map and
nothing on the box read it. `bpftool map dump` gave slot numbers and no
names; five documentation pages said so.

The measurement here is on the wire, and it needs a control. A reader
that always answers zero and a reader that always answers nothing both
look plausible against a single counter, so every scenario carries a
SECOND counted rule in the SAME policy that must stay at zero, and
traffic that matches neither. And because "zero" and "could not be
read" are the two findings the removed v0.1 surface spelled the same
way, scenario 3 deliberately makes a zone unnameable while its counter
is still moving, and requires the screen to differ from the readable
one — character for character.

Six scenarios, on a real `fd` with real XDP over two veths into a
netns:

  1. counts land against the names that declared them, and the control
     counter stays at zero while traffic that matches neither moves
     neither.
  2. zero, absent and found are three different answers to
     `show counters <name>`.
  3. a zone whose names cannot be read reports that, does NOT report
     zeros, and does NOT report "no such counter" for a counter it
     cannot see.
  4. generated C that is not the source of the loaded object is
     refused as a naming, not used as one.
  5. with fd stopped, the verb says so rather than showing an empty
     table.
  6. a reload that renames a counter moves the name and the map
     together — no name from the retired policy beside the live one's
     numbers.

Run on the target, as root:
  sudo ./test_named_counters.py --fd ../../build/fd --cli ../../build/einheit-f
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

PASS = 0
FAIL = 0

EDGE_IF = "fwlcnt0"
EDGE_PEER = "fwlcnt0p"
QUIET_IF = "fwlcnt1"
QUIET_PEER = "fwlcnt1p"
NETNS = "fwlcntns"
EDGE_HOST = "10.78.0.1"
EDGE_PEER_ADDR = "10.78.0.2"
QUIET_HOST = "10.78.1.1"
QUIET_PEER_ADDR = "10.78.1.2"

COUNTED_PORT = 9101
CONTROL_PORT = 9102
UNCOUNTED_PORT = 9103

# Two counted rules in one policy, and a zone that counts nothing at
# all. The control counter is what makes a green result mean something:
# a reader that pairs values with names by position rather than by name
# would report the same two numbers with the labels swapped.
POLICY = f"""zone edge = [{EDGE_IF}]
zone quiet = [{QUIET_IF}]

@xdp(edge)

count edge_probe if pkt.proto == udp and pkt.dst_port == {COUNTED_PORT}
count edge_never if pkt.proto == udp and pkt.dst_port == {CONTROL_PORT}
allow

@xdp(quiet)

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
  for host_if, peer_if, host_addr, peer_addr in (
      (EDGE_IF, EDGE_PEER, EDGE_HOST, EDGE_PEER_ADDR),
      (QUIET_IF, QUIET_PEER, QUIET_HOST, QUIET_PEER_ADDR)):
    sh(f"ip link add {host_if} type veth peer name {peer_if}")
    sh(f"ip link set {peer_if} netns {NETNS}")
    sh(f"ip addr add {host_addr}/24 dev {host_if}")
    sh(f"ip link set {host_if} up")
    sh(f"ip -n {NETNS} addr add {peer_addr}/24 dev {peer_if}")
    sh(f"ip -n {NETNS} link set {peer_if} up")
    host_mac = sh(f"cat /sys/class/net/{host_if}/address").stdout.strip()
    peer_mac = sh(
        f"ip netns exec {NETNS} cat /sys/class/net/{peer_if}/address"
    ).stdout.strip()
    sh(f"ip neigh replace {peer_addr} lladdr {peer_mac} dev {host_if}")
    sh(f"ip -n {NETNS} neigh replace {host_addr} lladdr {host_mac} "
       f"dev {peer_if}")
  sh(f"ip -n {NETNS} link set lo up")


def topo_down():
  sh(f"ip netns del {NETNS}")
  sh(f"ip link del {EDGE_IF}")
  sh(f"ip link del {QUIET_IF}")


def python_path(fwl_root):
  """PYTHONPATH for the in-tree compiler, run under sudo."""
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
  """Compile with the IN-TREE compiler, never the one on PATH."""
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
    self.pin = "/sys/fs/bpf/ftcounters"
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
      # `reload firewall` recompiles from source; point fd at the
      # in-tree compiler rather than whatever `fwl` is on PATH.
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
    for iface in (EDGE_IF, QUIET_IF):
      sh(f"ip link set dev {iface} xdp off")
    shutil.rmtree(self.pin, ignore_errors=True)


class Cli:
  """`einheit-f`, pointed at a scratch tree and at this fd."""

  def __init__(self, binary, work, fd_sock):
    self.binary = binary
    self.work = work
    self.fd_sock = fd_sock

  def __call__(self, *args, fmt="table"):
    argv = [
        self.binary, "--color", "never", "--format", fmt,
        "--system-config", os.path.join(self.work, "system.yaml"),
        "--source", os.path.join(self.work, "rules.fw"),
        "--networkd-dir", os.path.join(self.work, "net"),
        "--dnsmasq-conf", os.path.join(self.work, "dnsmasq.conf"),
        "--sysctl-dir", os.path.join(self.work, "sysctl"),
        "--socket", self.fd_sock,
    ] + list(args)
    return run(argv)

  def rows(self, *args):
    """`--format json` output as a list of table rows.

    This is the operator-facing surface, not the wire: what the CLI
    puts on stdout is what a script and a person both act on.
    """
    r = self(*args, fmt="json")
    try:
      return json.loads(r.stdout)
    except ValueError:
      return []


def send_udp(port, count, dst=EDGE_HOST):
  """Send `count` UDP datagrams from inside the netns."""
  code = (
      "import socket;"
      "s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);"
      f"[s.sendto(b'x',('{dst}',{port})) for _ in range({count})]"
  )
  r = run(["ip", "netns", "exec", NETNS, sys.executable, "-c", code])
  # The datapath counts on ingress; give the frames time to land.
  time.sleep(0.5)
  return r


def counter_rows(cli, *args):
  """{(zone, counter): packets-as-written} from `show counters`."""
  out = {}
  for row in cli.rows("show", "counters", *args):
    out[(row.get("ZONE", ""), row.get("COUNTER", ""))] = row.get(
        "PACKETS", "")
  return out


def value_of(rows, zone, name):
  return rows.get((zone, name))


def xdp_attached(iface):
  out = sh(f"ip -details -json link show dev {iface}").stdout
  try:
    info = json.loads(out)
  except (ValueError, TypeError):
    return False
  return any(e.get("xdp", {}).get("prog", {}).get("id") for e in info)


SCREENS = {}


def scenario_counts_against_names(fd_bin, cli_bin, fwl_root, work):
  print("\n1. counts land against the names that declared them")
  bundle = os.path.join(work, "bundle-1")
  _, r = compile_bundle(fwl_root, POLICY, bundle, work)
  check("compiles", r.returncode == 0, r.stderr.strip())
  if r.returncode != 0:
    return
  # The name->slot table the reader resolves against is in the bundle,
  # written by the compiler. Assert it is there before trusting a
  # number that claims to come from it.
  edge_c = open(os.path.join(bundle, "edge.bpf.c"),
                encoding="utf-8").read()
  check("the bundle carries a counter table for edge",
        "// fwl_counter_table:" in edge_c and
        re.search(r"//\s+\d+\tedge_probe", edge_c) is not None,
        "nothing can name a slot without it")

  d = Daemon(fd_bin, work).start(bundle)
  cli = Cli(cli_bin, work, d.sock)
  try:
    check("fd is running", d.alive(), d.text()[-500:])
    check("XDP is on both interfaces",
          xdp_attached(EDGE_IF) and xdp_attached(QUIET_IF))

    base = counter_rows(cli)
    check("both counters are listed by name before any traffic",
          value_of(base, "edge", "edge_probe") == "0" and
          value_of(base, "edge", "edge_never") == "0",
          json.dumps({str(k): v for k, v in base.items()}))
    # A zone that declares no counters is its own answer, not a blank.
    check("the zone with no `count` says so rather than showing zero",
          value_of(base, "quiet", "(no count statements)") is not None,
          json.dumps({str(k): v for k, v in base.items()}))

    send_udp(COUNTED_PORT, 7)
    after = counter_rows(cli)
    check("the counted rule reports exactly the traffic that hit it",
          value_of(after, "edge", "edge_probe") == "7",
          f"got {value_of(after, 'edge', 'edge_probe')!r}")
    check("the control counter in the same policy stays at zero",
          value_of(after, "edge", "edge_never") == "0",
          "a reader that reports one number for every counter, or "
          "pairs values with names by position, passes without this")

    send_udp(UNCOUNTED_PORT, 4)
    neither = counter_rows(cli)
    check("traffic matching neither rule moves neither counter",
          value_of(neither, "edge", "edge_probe") == "7" and
          value_of(neither, "edge", "edge_never") == "0",
          json.dumps({str(k): v for k, v in neither.items()}))

    send_udp(COUNTED_PORT, 5)
    more = counter_rows(cli)
    check("the count is cumulative and still against its own name",
          value_of(more, "edge", "edge_probe") == "12" and
          value_of(more, "edge", "edge_never") == "0",
          json.dumps({str(k): v for k, v in more.items()}))

    screen = cli("show", "counters").stdout
    check("the rendered table names the counter and its value",
          "edge_probe" in screen and "12" in screen, screen)
    SCREENS["readable"] = screen

    # Asked for one name.
    found = cli.rows("show", "counters", "edge_probe")
    check("`show counters <name>` answers for that name alone",
          len(found) == 1 and found[0].get("COUNTER") == "edge_probe"
          and found[0].get("PACKETS") == "12",
          json.dumps(found))
  finally:
    d.stop()


def scenario_zero_absent_found(fd_bin, cli_bin, fwl_root, work):
  print("\n2. zero, absent and found are three different answers")
  bundle = os.path.join(work, "bundle-2")
  _, r = compile_bundle(fwl_root, POLICY, bundle, work)
  if r.returncode != 0:
    check("compiles", False, r.stderr.strip())
    return
  d = Daemon(fd_bin, work).start(bundle)
  cli = Cli(cli_bin, work, d.sock)
  try:
    send_udp(COUNTED_PORT, 3)
    hit = cli("show", "counters", "edge_probe").stdout
    zero = cli("show", "counters", "edge_never").stdout
    absent = cli("show", "counters", "no_such_counter")
    check("a counter that was hit reports its number",
          "edge_probe" in hit and "3" in hit, hit)
    check("a counter that was not hit reports zero, by name",
          "edge_never" in zero and "0" in zero, zero)
    check("a name no policy declares is refused, not zeroed",
          "no counter named 'no_such_counter'" in
          (absent.stdout + absent.stderr),
          absent.stdout + absent.stderr)
    check("the zero screen and the absent screen are different",
          zero.strip() != (absent.stdout + absent.stderr).strip())
    check("the refusal does not print a zero for the name",
          "no_such_counter" not in
          "".join(line for line in absent.stdout.splitlines()
                  if line.strip().endswith("0")),
          absent.stdout)
  finally:
    d.stop()


def scenario_unnameable_zone(fd_bin, cli_bin, fwl_root, work):
  print("\n3. a zone whose names cannot be read says so, not zero")
  bundle = os.path.join(work, "bundle-3")
  _, r = compile_bundle(fwl_root, POLICY, bundle, work)
  if r.returncode != 0:
    check("compiles", False, r.stderr.strip())
    return
  # Remove the generated C, keeping the compiled object. The datapath
  # is untouched and still counting; what is gone is the only thing
  # that can put a NAME on a slot. This is the state the removed v0.1
  # surface rendered as "no counters active" while counters moved.
  os.remove(os.path.join(bundle, "edge.bpf.c"))
  d = Daemon(fd_bin, work).start(bundle)
  cli = Cli(cli_bin, work, d.sock)
  try:
    check("fd still comes up and attaches", d.alive() and
          xdp_attached(EDGE_IF), d.text()[-400:])
    send_udp(COUNTED_PORT, 6)
    rows = counter_rows(cli)
    screen = cli("show", "counters").stdout
    check("the zone is still on the screen",
          any(z == "edge" for z, _ in rows), json.dumps(
              {str(k): v for k, v in rows.items()}))
    check("it reports that the names are unknown",
          value_of(rows, "edge", "(names unknown)") is not None,
          json.dumps({str(k): v for k, v in rows.items()}))
    check("it does NOT report the counter as zero",
          value_of(rows, "edge", "edge_probe") is None,
          "a slot with no name rendered as a named zero is the exact "
          "defect this reader exists to avoid")
    check("the reason names the file it could not read",
          "edge.bpf.c" in screen, screen)
    # The discriminator the brief asks for, stated as an assertion:
    # a reader that returns zeros and a reader that returns nothing
    # must not produce the same screen.
    check("this screen differs from the readable one",
          SCREENS.get("readable") is not None and
          screen.strip() != SCREENS["readable"].strip(),
          "zeros and unreadable rendered identically")

    asked = cli("show", "counters", "edge_probe")
    text = asked.stdout + asked.stderr
    check("asking for a counter it cannot see is 'cannot tell'",
          "cannot say whether" in text, text)
    check("...and NOT 'no such counter'",
          "no counter named" not in text,
          "absence was asserted from a table that was never read")
    check("...and it names the zone it could not search",
          "edge" in text, text)
  finally:
    d.stop()


def scenario_stale_table(fd_bin, cli_bin, fwl_root, work):
  print("\n4. generated C that is not the loaded object's source")
  bundle = os.path.join(work, "bundle-4")
  _, r = compile_bundle(fwl_root, POLICY, bundle, work)
  if r.returncode != 0:
    check("compiles", False, r.stderr.strip())
    return
  # Rewrite the table to name a slot the compiled map does not have —
  # what a bundle directory looks like when the .bpf.c has moved on
  # from the .bpf.o beside it. Every name it offers would be wrong.
  path = os.path.join(bundle, "edge.bpf.c")
  src = open(path, encoding="utf-8").read()
  src = src.replace("//   0\tedge_probe", "//   99\tedge_probe")
  with open(path, "w", encoding="utf-8") as f:
    f.write(src)
  d = Daemon(fd_bin, work).start(bundle)
  cli = Cli(cli_bin, work, d.sock)
  try:
    send_udp(COUNTED_PORT, 2)
    rows = counter_rows(cli)
    screen = cli("show", "counters").stdout
    check("the mismatch is reported as its own state",
          value_of(rows, "edge", "(stale table)") is not None,
          json.dumps({str(k): v for k, v in rows.items()}))
    check("no name is offered from the stale table",
          value_of(rows, "edge", "edge_probe") is None,
          "a plausible name against the wrong slot is the worst of "
          "the available answers")
    check("the reason names the counter and the slot",
          "edge_probe" in screen and "99" in screen, screen)
  finally:
    d.stop()


def scenario_fd_down(fd_bin, cli_bin, fwl_root, work):
  print("\n5. with fd stopped, the verb says so")
  bundle = os.path.join(work, "bundle-5")
  _, r = compile_bundle(fwl_root, POLICY, bundle, work)
  if r.returncode != 0:
    check("compiles", False, r.stderr.strip())
    return
  d = Daemon(fd_bin, work).start(bundle)
  cli = Cli(cli_bin, work, d.sock)
  d.stop()
  out = cli("show", "counters")
  text = out.stdout + out.stderr
  check("it reports that fd is not running",
        "fd is not running" in text or "no_daemon" in text or
        "not connected" in text, text)
  check("it does not print a counter table of zeros",
        "edge_probe" not in text, text)


def scenario_reload_renames(fd_bin, cli_bin, fwl_root, work):
  print("\n6. a reload moves the names and the map together")
  bundle = os.path.join(work, "bundle-6")
  src, r = compile_bundle(fwl_root, POLICY, bundle, work)
  if r.returncode != 0:
    check("compiles", False, r.stderr.strip())
    return
  d = Daemon(fd_bin, work).start(bundle, source=src, fwl_root=fwl_root)
  cli = Cli(cli_bin, work, d.sock)
  try:
    send_udp(COUNTED_PORT, 3)
    before = counter_rows(cli)
    check("the first policy's counter is reported",
          value_of(before, "edge", "edge_probe") == "3",
          json.dumps({str(k): v for k, v in before.items()}))

    # Same rule, new name. The counter map is POLICY-lifetime: the new
    # bundle gets a fresh one. A reader that kept the old table would
    # print the OLD name against the NEW map — a name from a policy
    # that is no longer in the packet path, beside a value from one
    # that is.
    with open(src, "w", encoding="utf-8") as f:
      f.write(POLICY.replace("edge_probe", "edge_renamed"))
    reload_out = cli("reload", "firewall")
    check("the reload was accepted",
          "error" not in (reload_out.stdout + reload_out.stderr).lower(),
          reload_out.stdout + reload_out.stderr)

    after = counter_rows(cli)
    check("the new name is reported",
          value_of(after, "edge", "edge_renamed") is not None,
          json.dumps({str(k): v for k, v in after.items()}))
    check("the old name is gone",
          value_of(after, "edge", "edge_probe") is None,
          "a name from the previous policy beside this policy's map")
    check("the new policy's counter starts from zero",
          value_of(after, "edge", "edge_renamed") == "0",
          "the counter map is discarded on a policy change")

    send_udp(COUNTED_PORT, 2)
    moved = counter_rows(cli)
    check("and counts the traffic that hits it now",
          value_of(moved, "edge", "edge_renamed") == "2" and
          value_of(moved, "edge", "edge_never") == "0",
          json.dumps({str(k): v for k, v in moved.items()}))
  finally:
    d.stop()


def main():
  ap = argparse.ArgumentParser()
  here = os.path.dirname(os.path.abspath(__file__))
  ap.add_argument("--fd", default=os.path.join(here, "../../build/fd"))
  ap.add_argument("--cli",
                  default=os.path.join(here, "../../build/einheit-f"))
  ap.add_argument("--fwl-root", default=os.path.join(here, "../../fwl"))
  ap.add_argument("--only", nargs="*", default=None)
  args = ap.parse_args()

  if os.geteuid() != 0:
    print("must run as root (real XDP)")
    return 2
  for path in (args.fd, args.cli, args.fwl_root):
    if not os.path.exists(path):
      print(f"missing: {path}")
      return 2

  scenarios = {
      "1": scenario_counts_against_names,
      "2": scenario_zero_absent_found,
      "3": scenario_unnameable_zone,
      "4": scenario_stale_table,
      "5": scenario_fd_down,
      "6": scenario_reload_renames,
  }
  # Scenario 3 compares its screen with scenario 1's, so 1 always runs.
  wanted = list(scenarios) if not args.only else sorted(
      set(args.only) | ({"1"} if "3" in args.only else set()))

  work = tempfile.mkdtemp(prefix="ftcounters-")
  topo_up()
  try:
    for key in wanted:
      scenarios[key](os.path.abspath(args.fd), os.path.abspath(args.cli),
                     os.path.abspath(args.fwl_root), work)
  finally:
    topo_down()
    shutil.rmtree(work, ignore_errors=True)

  print(f"\n{PASS} passed, {FAIL} failed")
  return 1 if FAIL else 0


if __name__ == "__main__":
  sys.exit(main())
