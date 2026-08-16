"""The gateway soak's epoch-2 policy, proved on real fd and real XDP.

Why this bench exists
---------------------
The 96 h gateway soak running on the rig is Tier 1 only: three `@xdp`
blocks of rules, no `def` anywhere. Tier 2 bodies compile down a
DIFFERENT emitter path — `_emit_tier2_if` lowers an `if` straight into
a C conditional where Tier 1's `_emit_rule` threads the rule's guard
and its `limited by` gate into the conjunction — so days of green say
nothing about it. `gwsoak.py append` widens that run onto the Tier 2
path by a hot reload, and this is where the policy it hands over is
proved before it is handed to a run that is already hours deep.

It runs on a VM, not on the rig. The rig is soaking and a bench that
deployed a five-zone bundle to it would be ending the run it is meant
to widen.

What it proves, and what each check is worth
--------------------------------------------
The policy it deploys is `hw/gwsoak_policy_t2.fw` VERBATIM — the same
bytes `append` copies to /etc/f/rules.fw — on veth pairs named after
the rig's interfaces, because a bundle manifest names interfaces
literally. So this is not a policy that resembles the one that ships.

  1. The three Tier 1 zones are BYTE-IDENTICAL between the epoch-1 and
     epoch-2 policies, generated C and emitted instruction stream
     both. That is the whole safety argument for appending to a
     running measurement, and it is checked rather than asserted.
  2. Five objects load, five programs attach, four zones masquerade
     and every one of them resolves the single uplink address.
  3. The shared helper is a REAL BPF-to-BPF function in inc.bpf.o AND
     in ind.bpf.o, with the caller checking its sentinel — which is
     what "reached from more than one zone" means at the object level.
  4. Real non-promiscuous sockets in four guest namespaces complete
     real TCP exchanges through the box, and the far side's own kernel
     names ONE peer address for all four.
  5. Every counter the soak intends to read back is read back BY NAME
     through `gwsoak.read_counters` itself — not a copy of it — and
     moves under the same frames `gwsoak_traffic.t2_frames` will send
     on the rig. The zone-qualified names (`inc.t2_mcast` vs
     `ind.t2_mcast`) are the case that reader was rewritten for.
  6. The Tier 2 identity holds exactly: every frame a Tier 2 `def`
     sees lands in exactly one leaf, so the leaves sum to the total.
  7. CONTROL. The same bundle with exactly `t2_noise(pkt)` removed
     from `inc_filter` and nothing else, rebuilt by the same compiler:
     `inc.t2_mcast` must stop existing, the multicast frames must land
     in `c_offnet` instead, and `ind`'s helper must go on working. A
     green half with no control is a claim about a bench, not about a
     firewall.

Usage, as root, on a VM:

  sudo python3 tier2_gateway_netns.py --fd build/fd [--fwl fwl]
"""
import argparse
import atexit
import json
import os
import pathlib
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time

HERE = pathlib.Path(__file__).resolve().parent
WS = HERE.parent.parent
sys.path.insert(0, str(HERE / "hw"))
sys.path.insert(0, str(WS))

import gwsoak  # noqa: E402

REALSOCK = HERE / "hw" / "realsock.py"
XDP_PASS_SRC = HERE / "xdp_pass.bpf.c"
PIN_ROOT = "/sys/fs/bpf/ft2"
POLICY_T1 = HERE / "hw" / "gwsoak_policy.fw"
POLICY_T2 = HERE / "hw" / "gwsoak_policy_t2.fw"
# The zones, exactly as the policy names them. `tier` is what this
# bench is here to tell apart.
LEGS = (
  ("ina", "enp1s0f1", "ft2ap", "gwt2a", "10.99.31.1", "10.99.31.5", 1),
  ("inb", "fs3b", "ft2bp", "gwt2b", "10.99.32.1", "10.99.32.5", 1),
  ("wanz", "enp1s0f2", "ft2sp", "gwt2s", "10.99.210.2",
   "10.99.210.9", 1),
  ("inc", "fs4c", "fs4cp", "gwt2c", "10.99.33.1", "10.99.33.5", 2),
  ("ind", "fs4d", "fs4dp", "gwt2d", "10.99.34.1", "10.99.34.5", 2),
)
SERVER = "10.99.210.9"
PORT = 8461
N_CONNS = 3
INSIDE = tuple(leg for leg in LEGS if leg[0] != "wanz")
MASQ_ADDR = "10.99.210.2"
CYCLES = 40
_MAP_DECL_RE = re.compile(
    r"struct\s*\{(?P<body>[^{}]*)\}\s*(?P<name>\w+)\s*SEC\(\"\.maps\"\);")


class Result:
  """The running verdict: every check, and whether any failed."""

  def __init__(self):
    self.failed = 0
    self.checks = 0

  def check(self, ok: bool, what: str) -> bool:
    """Record one assertion and print it."""
    self.checks += 1
    if not ok:
      self.failed += 1
    print(f"[t2] {'PASS' if ok else 'FAIL'}: {what}", flush=True)
    return ok

  def note(self, what: str) -> None:
    """Record a bench observation that is not a verdict."""
    print(f"[t2] NOTE: {what}", flush=True)


def run(cmd, check=False, ns=None, capture=True):
  """Run `cmd`, optionally inside network namespace `ns`."""
  argv = list(cmd)
  if ns is not None:
    argv = ["ip", "netns", "exec", ns] + argv
  return subprocess.run(argv, check=check, text=True,
                        capture_output=capture)


def quiet(cmd, ns=None) -> None:
  """Run `cmd` and ignore its outcome (teardown, best effort)."""
  try:
    run(cmd, ns=ns)
  except OSError:
    pass


def teardown() -> None:
  """Remove everything this bench creates. Safe to call twice."""
  for _, dev, peer, ns, _, _, _ in LEGS:
    quiet(["ip", "link", "set", "dev", dev, "xdp", "off"])
    quiet(["ip", "link", "set", "dev", peer, "xdp", "off"], ns=ns)
    quiet(["ip", "link", "del", dev])
    quiet(["ip", "netns", "del", ns])
  shutil.rmtree(PIN_ROOT, ignore_errors=True)


def build_topology(work: pathlib.Path, res: Result) -> bool:
  """Five veth pairs, five host namespaces, addresses both sides."""
  obj = work / "xdp_pass.bpf.o"
  clang = subprocess.run(
      ["clang", "-O2", "-g", "-target", "bpf",
       "-I/usr/include/x86_64-linux-gnu",
       "-I/usr/include/aarch64-linux-gnu",
       "-c", str(XDP_PASS_SRC), "-o", str(obj)],
      text=True, capture_output=True)
  if clang.returncode != 0:
    res.check(False, f"compile xdp_pass: {clang.stderr.strip()}")
    return False
  for _, dev, peer, ns, gw_addr, host_addr, _ in LEGS:
    run(["ip", "netns", "add", ns], check=True)
    run(["ip", "link", "add", dev, "type", "veth",
         "peer", "name", peer], check=True)
    run(["ip", "link", "set", peer, "netns", ns], check=True)
    run(["ip", "link", "set", dev, "up"], check=True)
    run(["ip", "addr", "add", f"{gw_addr}/24", "dev", dev], check=True)
    run(["ip", "link", "set", "lo", "up"], ns=ns, check=True)
    run(["ip", "link", "set", peer, "up"], ns=ns, check=True)
    run(["ip", "addr", "add", f"{host_addr}/24", "dev", peer],
        ns=ns, check=True)
    run(["ip", "route", "add", "default", "via", gw_addr],
        ns=ns, check=True)
    # A veth pair keeps CHECKSUM_PARTIAL end to end, so the NAT's
    # incremental update lands on a base that was never valid and the
    # far stack drops the frame with Tcp:InCsumErrors. On copper the
    # sending NIC has computed it already.
    for end, where in ((dev, None), (peer, ns)):
      run(["ethtool", "-K", end, "tx", "off", "rx", "off",
           "tso", "off", "gso", "off", "gro", "off"], ns=where)
      # IPv6 off on both ends of every leg. Router solicitations and
      # MLD reports are frames this bench did not send, and the Tier 2
      # counter arithmetic below is asserted as EXACT numbers — six
      # workload frames a cycle, not "about six". On the rig the same
      # frames land in `c_offnet` and the identity absorbs them, which
      # is why the identity and not a count is what the soak checks.
      run(["sysctl", "-qw", f"net.ipv6.conf.{end}.disable_ipv6=1"],
          ns=where)
    # veth's ndo_xdp_xmit needs an XDP program on the RECEIVING side,
    # or a redirect into this leg is dropped below the peer's stack.
    attached = run(["ip", "link", "set", "dev", peer, "xdpdrv",
                    "obj", str(obj), "sec", "xdp"], ns=ns)
    if attached.returncode != 0:
      attached = run(["ip", "link", "set", "dev", peer, "xdp",
                      "obj", str(obj), "sec", "xdp"], ns=ns)
    if attached.returncode != 0:
      res.check(False, f"xdp_pass on {peer}: {attached.stderr.strip()}")
      return False
    if "PROMISC" in run(["ip", "link", "show", peer], ns=ns).stdout:
      res.check(False, f"{ns}/{peer} is PROMISC; it would accept "
                       f"frames a real host drops")
      return False
  return True


def compile_bundle(fwl: str, source: pathlib.Path,
                   into: pathlib.Path) -> subprocess.CompletedProcess:
  """Compile one policy into one bundle directory."""
  env = dict(os.environ)
  env["PYTHONPATH"] = os.pathsep.join(
      [str(WS)] + ([env["PYTHONPATH"]] if "PYTHONPATH" in env else []))
  shutil.rmtree(into, ignore_errors=True)
  return subprocess.run([fwl, "compile", str(source), "--bundle",
                         str(into)],
                        text=True, capture_output=True, env=env)


def text_of(obj: pathlib.Path) -> str:
  """An object's disassembled instruction stream, without its header.

  Comparing whole .o files answers the wrong question: they differ by
  the path baked into their debug info alone. The instruction stream
  is what runs.
  """
  proc = subprocess.run(["llvm-objdump", "-d", str(obj)],
                        text=True, capture_output=True)
  return "\n".join(proc.stdout.splitlines()[2:])


def start_fd(fd_bin: str, bundle: pathlib.Path, log_path: pathlib.Path,
             sock: str) -> subprocess.Popen:
  """Cold-boot `fd` against a bundle and return the process."""
  log = open(log_path, "w")
  return subprocess.Popen(
      [fd_bin, "--bundle-dir", str(bundle), "--pin-path", PIN_ROOT,
       "--socket", sock, "-l", "debug", "run"],
      stdout=log, stderr=subprocess.STDOUT)


def stop_fd(proc) -> None:
  """SIGTERM and wait; never SIGKILL a daemon holding pins."""
  if proc is None:
    return
  proc.terminate()
  try:
    proc.wait(timeout=15)
  except subprocess.TimeoutExpired:
    proc.kill()


def wait_for_attach(want: int, timeout_s: float = 30.0) -> list:
  """The zone devices carrying an XDP program, once `want` do."""
  deadline = time.monotonic() + timeout_s
  live: list = []
  while time.monotonic() < deadline:
    live = [dev for _, dev, _, _, _, _, _ in LEGS
            if "xdp" in run(["ip", "link", "show", dev]).stdout]
    if len(live) >= want:
      return live
    time.sleep(0.5)
  return live


def fctl_status(fctl: str, sock: str) -> dict:
  """`fctl status`, as the operator would read it."""
  proc = run([fctl, "-s", sock, "status"])
  try:
    return json.loads(proc.stdout)
  except (json.JSONDecodeError, TypeError):
    return {}


def warm_neighbours() -> None:
  """Resolve each host's MAC from the firewall's own stack.

  XDP cannot ARP, and on a masquerading box neither can the traffic it
  forwards: the frame handed to the stack carries one of the box's own
  addresses as its source and the kernel discards it as a martian
  before it would ask for a neighbour. This is a warm-up, not a
  workaround — `l2_03` and the cold-neighbour bench are where the cold
  case is a measurement.
  """
  for _, dev, _, _, _, host_addr, _ in LEGS:
    run(["ping", "-c1", "-W2", "-I", dev, host_addr])


def exchange(res: Result, label: str, want: int, legs) -> dict:
  """One TCP exchange from each inside zone, through the box."""
  total = want * len(legs)
  server = subprocess.Popen(
      ["ip", "netns", "exec", LEGS[2][3], sys.executable,
       str(REALSOCK), "server", SERVER, str(PORT), str(max(total, 1)),
       "16"],
      stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
  time.sleep(1.0)
  clients = []
  for zone, _, _, ns, _, _, _ in legs:
    clients.append((zone, subprocess.Popen(
        ["ip", "netns", "exec", ns, sys.executable, str(REALSOCK),
         "client", SERVER, str(PORT), str(want), "5"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)))
  for zone, proc in clients:
    out, err = proc.communicate(timeout=90)
    try:
      report = json.loads(out)
    except json.JSONDecodeError:
      report = {"completed": -1, "raw": out, "err": err}
    res.check(report.get("completed", -1) == want,
              f"{label}: zone {zone} completed "
              f"{report.get('completed')}/{want} end-to-end exchanges")
  srv_out, _ = server.communicate(timeout=40)
  try:
    return json.loads(srv_out)
  except json.JSONDecodeError:
    return {"accepted": -1, "peer_addrs": [], "raw": srv_out}


def send_t2_load(work: pathlib.Path, cycles: int) -> None:
  """The frames the rig's Tier 2 generators will send, N cycles of.

  Built by `gwsoak_traffic.t2_frames` — the shipped function, not a
  copy — so what this bench measures the counters against is what the
  soak will actually put on the wire.
  """
  script = work / "t2send.py"
  script.write_text(
      "import sys, socket, time\n"
      f"sys.path.insert(0, {str(HERE / 'hw')!r})\n"
      f"sys.path.insert(0, {str(WS)!r})\n"
      "import gwsoak_traffic as g\n"
      "zone = g.T2_ZONES[sys.argv[1]]\n"
      "frames = g.t2_frames(zone, sys.argv[3], sys.argv[4])\n"
      "s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)\n"
      "s.bind((sys.argv[2], 0))\n"
      "for _ in range(int(sys.argv[5])):\n"
      "  for f in frames:\n"
      "    s.send(f)\n"
      "  time.sleep(0.01)\n"
      "print(len(frames))\n")
  for zone, dev, peer, ns, _, _, tier in LEGS:
    if tier != 2:
      continue
    key = "c" if zone == "inc" else "d"
    dst = re.search(r"link/ether (\S+)",
                    run(["ip", "link", "show", dev]).stdout)
    src = re.search(r"link/ether (\S+)",
                    run(["ip", "link", "show", peer], ns=ns).stdout)
    run(["ip", "netns", "exec", ns, sys.executable, str(script), key,
         peer, dst.group(1) if dst else "",
         src.group(1) if src else "", str(cycles)], check=True)


def counters(bundle: pathlib.Path) -> dict:
  """Every counter by name, through the SOAK's own reader."""
  return gwsoak.read_counters(current=str(bundle / "current"),
                              pin=PIN_ROOT)


def check_identity(res: Result, values: dict, label: str) -> None:
  """The Tier 2 arithmetic: the leaves sum to the total, exactly."""
  for total_name, leaves in gwsoak.EPOCHS[2]["identities"]:
    missing = [n for n in (total_name,) + tuple(leaves)
               if n not in values]
    if missing:
      res.check(False, f"{label}: {missing} not read back by name")
      continue
    total = values[total_name]
    summed = sum(values[n] for n in leaves)
    res.check(total == summed,
              f"{label}: {total_name}={total} == the sum of its "
              f"{len(leaves)} leaves ({summed})")


def arm_forwarding_restore(saved: str) -> None:
  """Put net.ipv4.ip_forward back on every exit path, and say so."""
  path = pathlib.Path("/proc/sys/net/ipv4/ip_forward")
  done: list = []

  def restore(*_):
    """Restore once, verify, and report."""
    if done:
      return
    done.append(True)
    try:
      path.write_text(saved)
    except OSError as exc:
      print(f"[t2] RESTORE FAILED: could not write {path} ({exc}); "
            f"set it back with `sysctl -w "
            f"net.ipv4.ip_forward={saved.strip()}`",
            file=sys.stderr, flush=True)
      return
    print(f"[t2] restored net.ipv4.ip_forward = "
          f"{path.read_text().strip()} (it was {saved.strip()} when "
          f"this run started)", flush=True)

  atexit.register(restore)
  for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
    signal.signal(sig, lambda *_: sys.exit(1))


def check_emission(res: Result, cur: pathlib.Path,
                   t1: pathlib.Path) -> None:
  """What the two policies emit, before anything is loaded."""
  # (1) The append's whole safety argument: the three zones under
  # measurement do not change. Generated C first, then the
  # instruction stream, because a comment could hide behind the
  # first and nothing can hide behind the second.
  for zone in ("ina", "inb", "wanz"):
    same_c = ((t1 / f"{zone}.bpf.c").read_bytes()
              == (cur / f"{zone}.bpf.c").read_bytes())
    res.check(same_c, f"{zone}.bpf.c is byte-identical between the "
                      f"epoch-1 and epoch-2 policies")
    res.check(text_of(t1 / f"{zone}.bpf.o")
              == text_of(cur / f"{zone}.bpf.o"),
              f"{zone}.bpf.o's instruction stream is identical too")
  src = {z: (cur / f"{z}.bpf.c").read_text()
         for z, _, _, _, _, _, _ in LEGS}
  # (2) The helper is a real BPF-to-BPF function in BOTH Tier 2
  # objects, and the caller checks its sentinel. That pair IS
  # "reached from more than one zone".
  for zone in ("inc", "ind"):
    res.check("static __noinline int fwl_helper_t2_noise("
              "struct xdp_md *ctx)" in src[zone],
              f"{zone} declares the shared helper as a real "
              f"__noinline BPF function")
    res.check("int _r = fwl_helper_t2_noise(ctx);" in src[zone]
              and "if (_r != FWL_CONTINUE) return _r;" in src[zone],
              f"{zone}'s call site propagates the helper's verdict")
    res.check("t2_mcast" in src[zone] and "t2_nbns" in src[zone],
              f"{zone}'s counter table carries the helper's counters")
  # (3) Four masquerading zones behind one uplink is four objects
  # naming one devmap, and none of them may pin it — the shape that
  # could not load until the devmap was unpinned (l2_08).
  namers = [z for z in src if 'fwl_devmap_wanz SEC(".maps")' in src[z]]
  res.check(sorted(namers) == ["ina", "inb", "inc", "ind"],
            f"four objects declare fwl_devmap_wanz (got {namers})")
  pinned = [f"{z}:{m.group('name')}" for z in src
            for m in _MAP_DECL_RE.finditer(src[z])
            if m.group("name").startswith("fwl_devmap_")
            and "LIBBPF_PIN_BY_NAME" in m.group("body")]
  res.check(not pinned, f"no devmap is pinned by name (got {pinned})")
  res.check(all(f'}} fwl_nat_cfg_{z} SEC(".maps");' in src[z]
                for z in src),
            "every zone declares its OWN masquerade source map")
  manifest = json.loads((cur / "manifest.json").read_text())
  res.check([z["name"] for z in manifest["zones"]]
            == [z for z, _, _, _, _, _, _ in LEGS],
            "the manifest carries all five zones in order")


def plant_policy(work: pathlib.Path) -> pathlib.Path:
  """The epoch-2 policy with exactly the helper call removed from inc.

  One line, in one zone, and nothing else. `ind` keeps its call, so
  the control also says the two objects are independent rather than
  one thing observed twice.
  """
  text = POLICY_T2.read_text()
  head, sep, tail = text.partition("def inc_filter(pkt):\n")
  planted = head + sep + tail.replace("  t2_noise(pkt)\n", "", 1)
  if planted == text:
    raise SystemExit("the plant did not change the policy")
  path = work / "planted.fw"
  path.write_text(planted)
  return path


def main() -> int:
  """Build the bench, deploy both bundles, and report."""
  ap = argparse.ArgumentParser(description=__doc__)
  ap.add_argument("--fd", required=True, help="path to the fd binary")
  ap.add_argument("--fwl", default="fwl", help="the fwl compiler")
  ap.add_argument("--fctl", default=None,
                  help="path to fctl (default: beside fd)")
  args = ap.parse_args()
  res = Result()
  if os.geteuid() != 0:
    print("[t2] needs root (bpffs, netns, XDP)", file=sys.stderr)
    return 2
  if not os.access(args.fd, os.X_OK):
    print(f"[t2] not executable: {args.fd}", file=sys.stderr)
    return 2
  if not os.path.ismount("/sys/fs/bpf"):
    run(["mount", "-t", "bpf", "bpf", "/sys/fs/bpf"], check=True)
  sbin = ["/usr/local/sbin", "/usr/sbin", "/sbin"]
  path = os.pathsep.join([os.environ.get("PATH", "")] + sbin)
  missing = [t for t in ("ip", "ethtool", "clang", "bpftool",
                         "llvm-objdump")
             if shutil.which(t, path=path) is None]
  if missing:
    print(f"[t2] BLOCKED: not installed: {', '.join(missing)}",
          file=sys.stderr)
    return 2
  os.environ["PATH"] = path
  fctl = args.fctl or str(pathlib.Path(args.fd).resolve().parent
                          / "fctl")
  if not os.access(fctl, os.X_OK):
    print(f"[t2] not executable: {fctl}", file=sys.stderr)
    return 2

  work = pathlib.Path(tempfile.mkdtemp(prefix="ft2-"))
  sock = f"ipc://{work}/fd.sock"
  bundle = work / "bundle"
  t1_bundle = work / "t1"
  fd_proc = None
  saved = pathlib.Path("/proc/sys/net/ipv4/ip_forward").read_text()
  arm_forwarding_restore(saved)
  teardown()
  os.makedirs(PIN_ROOT, exist_ok=True)
  try:
    built_t1 = compile_bundle(args.fwl, POLICY_T1, t1_bundle)
    if not res.check(built_t1.returncode == 0,
                     f"the epoch-1 policy compiles "
                     f"({built_t1.stderr.strip() or 'ok'})"):
      return 1
    built = compile_bundle(args.fwl, POLICY_T2, bundle / "current")
    if not res.check(built.returncode == 0,
                     f"the epoch-2 policy compiles "
                     f"({built.stderr.strip() or 'ok'})"):
      return 1
    check_emission(res, bundle / "current", t1_bundle)

    if not build_topology(work, res):
      return 1
    pathlib.Path("/proc/sys/net/ipv4/ip_forward").write_text("1\n")
    fd_proc = start_fd(args.fd, bundle, work / "fd.log", sock)
    live = wait_for_attach(len(LEGS))
    if not res.check(len(live) == len(LEGS),
                     f"fd attached all five zones (got {live})"):
      print((work / "fd.log").read_text()[-4000:])
      return 1
    res.check(not any(pathlib.Path(PIN_ROOT).glob("fwl_devmap_*")),
              "no devmap reached bpffs")
    status = fctl_status(fctl, sock)
    sources = sorted(f"{e['zone']}={e['address']}"
                     for e in status.get("nat", {})
                     .get("masq_sources", []))
    res.check(len(sources) == 4 and all(s.endswith(MASQ_ADDR)
                                        for s in sources),
              f"four masquerading zones, all resolving {MASQ_ADDR} "
              f"({sources})")
    res.check(status.get("egress", {}).get("attached", 0) == len(LEGS),
              f"the egress tracker is on all {len(LEGS)} interfaces "
              f"(got {status.get('egress', {}).get('attached')})")
    warm_neighbours()

    # The wire. Four inside zones, real sockets, one peer address.
    srv = exchange(res, "epoch 2", N_CONNS, INSIDE)
    want = N_CONNS * len(INSIDE)
    res.check(srv.get("accepted") == want,
              f"the far side accepted {srv.get('accepted')} of {want} "
              f"connections from four zones")
    res.check(srv.get("echoed") == want,
              f"the far side echoed {srv.get('echoed')} of {want}")
    res.check(srv.get("peer_addrs") == [MASQ_ADDR],
              f"the far side's own kernel saw exactly [{MASQ_ADDR}] "
              f"as the peer from all four zones (saw "
              f"{srv.get('peer_addrs')})")

    # The counters, by name, under the frames the rig will send.
    before = counters(bundle)
    send_t2_load(work, CYCLES)
    time.sleep(1)
    after = counters(bundle)
    for name in gwsoak.EPOCHS[2]["must_move"]:
      if name.startswith(("a_", "b_", "w_")):
        continue
      res.check(after.get(name, -1) > before.get(name, -2),
                f"counter {name} moved under the Tier 2 load "
                f"({before.get(name)} -> {after.get(name)})")
    res.check(after.get("inc.t2_mcast", -1) >= 0
              and after.get("ind.t2_mcast", -1) >= 0
              and "t2_mcast" not in after,
              "the shared helper's counters are read back per zone "
              "(inc.t2_mcast, ind.t2_mcast) and never collapsed into "
              "one name")
    # Exact, not approximate. `t2_frames` sends a fixed mix per cycle
    # and IPv6 is off on both ends of every leg, so every one of these
    # is the number the policy's branch structure predicts. A count
    # that came out "about right" would be describing the generator.
    for name, per_cycle in (("c_total", 10), ("c_workload", 6),
                            ("c_syn", 6), ("c_udp", 1),
                            ("c_offnet", 1), ("inc.t2_mcast", 1),
                            ("inc.t2_nbns", 1), ("c_web", 0),
                            ("c_other_tcp", 0), ("c_other_proto", 0),
                            ("d_total", 10), ("d_workload", 6),
                            ("d_syn", 6), ("d_udp", 1),
                            ("d_offnet", 1), ("ind.t2_mcast", 1),
                            ("ind.t2_nbns", 1)):
      moved = after.get(name, -1) - before.get(name, -1)
      res.check(moved == per_cycle * CYCLES,
                f"{name} moved by exactly {per_cycle} per cycle "
                f"({moved} over {CYCLES} cycles, wanted "
                f"{per_cycle * CYCLES})")
    check_identity(res, after, "epoch 2")
    res.note(f"epoch 2 counters: "
             f"{json.dumps({k: after[k] for k in sorted(after) if not k.startswith(('a_', 'b_', 'w_'))})}")  # noqa: E501

    # --- CONTROL: the helper call removed from inc, and only inc ----
    stop_fd(fd_proc)
    fd_proc = None
    shutil.rmtree(PIN_ROOT, ignore_errors=True)
    os.makedirs(PIN_ROOT, exist_ok=True)
    planted = compile_bundle(args.fwl, plant_policy(work),
                             bundle / "current")
    if not res.check(planted.returncode == 0,
                     f"the planted policy compiles "
                     f"({planted.stderr.strip() or 'ok'})"):
      return 1
    fd_proc = start_fd(args.fd, bundle, work / "fd-plant.log", sock)
    if not res.check(len(wait_for_attach(len(LEGS))) == len(LEGS),
                     "fd attached all five zones of the planted "
                     "bundle"):
      print((work / "fd-plant.log").read_text()[-4000:])
      return 1
    warm_neighbours()
    p_before = counters(bundle)
    send_t2_load(work, CYCLES)
    time.sleep(1)
    p_after = counters(bundle)
    res.check("t2_mcast" in p_after and "inc.t2_mcast" not in p_after,
              "control: with inc's call removed the helper is emitted "
              "into ind alone, so its counters are no longer a "
              "two-zone name")
    res.check(p_after.get("t2_mcast", -1)
              - p_before.get("t2_mcast", -1) == CYCLES,
              "control: ind's helper goes on counting exactly as "
              "before — the plant removed one call site, not the "
              "helper, and the two objects are independent")
    # The two frames inc's helper used to swallow now survive it. Both
    # are UDP from inc's own guest subnet, so they fall through to the
    # zone's `elif pkt.proto == udp:` leaf: c_udp goes from 1 a cycle
    # to 3. Nothing else about the zone moves — which is the point.
    for name, per_cycle in (("c_total", 10), ("c_udp", 3),
                            ("c_workload", 6), ("c_offnet", 1)):
      moved = p_after.get(name, -1) - p_before.get(name, -1)
      res.check(moved == per_cycle * CYCLES,
                f"control: {name} moved by {per_cycle} per cycle "
                f"({moved} over {CYCLES}, wanted "
                f"{per_cycle * CYCLES})")
    # And the arithmetic still closes, on the leaves this bundle has.
    leaves = ("c_workload", "c_web", "c_other_tcp", "c_udp",
              "c_other_proto", "c_offnet")
    res.check(p_after.get("c_total", -1)
              == sum(p_after.get(n, 0) for n in leaves),
              "control: c_total still equals the sum of its leaves, "
              "which now has no helper term in it")
  finally:
    stop_fd(fd_proc)
    teardown()
  verdict = "PASS" if res.failed == 0 else "FAIL"
  print(f"[t2] {verdict}: {res.checks - res.failed}/{res.checks} "
        f"checks")
  return 0 if res.failed == 0 else 1


if __name__ == "__main__":
  sys.exit(main())
