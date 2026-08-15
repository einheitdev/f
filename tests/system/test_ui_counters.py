#!/usr/bin/env python3
"""The web UI's counters and policy pages, against a real fd.

The page this replaces was blank on every box ever deployed. `/counters`
opened the pinned maps in process, on the v0.1 names `rules_a`,
`counters` and `config` that no v0.4 bundle pins, so `OpenPinnedMaps`
failed on its first name and the page rendered "no counters active"
while `fwl_counters_<zone>` on the same box counted every frame on the
wire. Nothing caught it for months, because an empty table is what a
working page looks like on a quiet firewall.

So the measurement here is on the wire and it carries a control, and
the pages are compared with each other rather than merely inspected:

  1. a counted rule shows its count UNDER ITS OWN NAME on the page,
     while a second counted rule in the same policy stays at zero and
     traffic matching neither moves neither.
  2. the four kinds of empty render as four different pages. A page
     that could not tell "zero" from "could not ask" is the defect,
     so this asserts the pages DIFFER, not just that each looks
     plausible on its own.
  3. with fd stopped, the page says so — it does not draw an empty
     table, and it does not say the policy declares no counters.
  4. `/policy` reports what fd has LOADED, rules included — the same
     answer `einheit-f show policy` renders, over the same opcode.
  5. the dashboard's counters row is a measurement. The badge it
     replaced was an unconditional red `unavailable` that nothing on
     the box ever set.
  6. the UI holds no BPF map open and runs as an unprivileged user
     while showing real numbers. That is the whole architectural
     claim: everything goes through the daemon socket.

Run on the target, as root:
  sudo ./test_ui_counters.py --fd ../../build/fd \\
      --ui ../../build/einheit-f-ui
"""
import argparse
import html as html_mod
import json
import os
import pwd
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

PASS = 0
FAIL = 0

EDGE_IF = "fwlui0"
EDGE_PEER = "fwlui0p"
QUIET_IF = "fwlui1"
QUIET_PEER = "fwlui1p"
NETNS = "fwluins"
EDGE_HOST = "10.79.0.1"
EDGE_PEER_ADDR = "10.79.0.2"
QUIET_HOST = "10.79.1.1"
QUIET_PEER_ADDR = "10.79.1.2"

COUNTED_PORT = 9201
CONTROL_PORT = 9202
UNCOUNTED_PORT = 9203
UI_PORT = 17542

# Two counted rules in one policy and a zone that counts nothing. The
# control counter is what makes a green result mean something: a page
# that prints one number for every counter, or pairs values with names
# by position, passes without it.
POLICY = f"""zone edge = [{EDGE_IF}]
zone quiet = [{QUIET_IF}]

@xdp(edge)

count edge_probe if pkt.proto == udp and pkt.dst_port == {COUNTED_PORT}
count edge_never if pkt.proto == udp and pkt.dst_port == {CONTROL_PORT}
allow

@xdp(quiet)

allow
"""

# The same policy with a conntrack question in it, which is what makes
# the bundle carry a TC egress tracker. The policy page reports whether
# that hook is on the wire, and the daemon reports it as a COUNT beside
# the interface list — read as a list it comes back empty and a healthy
# box is told its tracker is missing.
CONNTRACK_POLICY = POLICY.replace(
    "count edge_probe",
    "allow if conntrack(pkt).state in [established, related]\n"
    "count edge_probe")

PAGES = {}


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
    self.pin = "/sys/fs/bpf/fuicounters"
    self.sock_path = os.path.join(work, "fd.sock")
    self.sock = f"ipc://{self.sock_path}"
    self.log = os.path.join(work, "fd.log")
    self.proc = None

  def start(self, bundle_dir):
    os.makedirs(self.root, exist_ok=True)
    link = os.path.join(self.root, "current")
    if os.path.islink(link) or os.path.exists(link):
      os.remove(link)
    os.symlink(bundle_dir, link)
    cfg = os.path.join(self.root, "fd.yaml")
    with open(cfg, "w", encoding="utf-8") as f:
      f.writelines([f"pin_path: {self.pin}\n",
                    f"socket: {self.sock}\n",
                    "log_level: debug\n",
                    "watch:\n  enabled: false\n"])
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
    # The UI runs unprivileged (that is half of what this test is
    # for), so it has to be able to connect to the socket fd made.
    if os.path.exists(self.sock_path):
      os.chmod(self.sock_path, 0o777)
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


def unprivileged_uid():
  """The uid to run the web UI as, or None to stay root.

  A page that needs root to show a number is a page that is reading
  something it should not be. The invoking user is preferred over
  `nobody` so the binary and its template tree are readable.
  """
  name = os.environ.get("SUDO_USER")
  for candidate in (name, "nobody"):
    if not candidate:
      continue
    try:
      ent = pwd.getpwnam(candidate)
    except KeyError:
      continue
    if ent.pw_uid != 0:
      return ent.pw_uid, ent.pw_gid, candidate
  return None


class Ui:
  """`einheit-f-ui`, pointed at this fd, over real HTTP."""

  def __init__(self, ui_bin, work, fd_sock, port=UI_PORT):
    self.ui_bin = ui_bin
    self.work = work
    self.fd_sock = fd_sock
    self.port = port
    self.log = os.path.join(work, f"ui-{port}.log")
    self.proc = None
    self.user = None

  def start(self):
    logf = open(self.log, "w", encoding="utf-8")
    ident = unprivileged_uid()
    uid, gid = (None, None)
    if ident is not None:
      uid, gid, self.user = ident

    def demote():
      if uid is None:
        return
      os.setgid(gid)
      os.setuid(uid)

    self.proc = subprocess.Popen(
        [self.ui_bin, "--bind", "127.0.0.1", "--port", str(self.port),
         "--socket", self.fd_sock, "--sample-ms", "500"],
        stdout=logf, stderr=subprocess.STDOUT, preexec_fn=demote)
    for _ in range(80):
      if self.proc.poll() is not None:
        break
      try:
        urllib.request.urlopen(
            f"http://127.0.0.1:{self.port}/interfaces", timeout=2)
        return self
      except (urllib.error.URLError, OSError):
        time.sleep(0.25)
    return self

  def alive(self):
    return self.proc is not None and self.proc.poll() is None

  def get(self, path):
    try:
      with urllib.request.urlopen(
          f"http://127.0.0.1:{self.port}{path}", timeout=20) as r:
        return r.read().decode("utf-8", "replace")
    except (urllib.error.URLError, OSError) as e:
      return f"<<request failed: {e}>>"

  def json(self, path):
    body = self.get(path + "?format=json")
    try:
      return json.loads(body)
    except ValueError:
      return {}

  def open_bpf_maps(self):
    """Every BPF object this process holds a descriptor to.

    The architectural claim, measured rather than asserted: the UI
    goes through the daemon socket and opens nothing itself.
    """
    out = []
    if self.proc is None:
      return out
    fddir = f"/proc/{self.proc.pid}/fd"
    try:
      names = os.listdir(fddir)
    except OSError:
      return out
    for name in names:
      try:
        target = os.readlink(os.path.join(fddir, name))
      except OSError:
        continue
      if "bpf" in target:
        out.append(target)
    return out

  def stop(self):
    if self.proc is not None and self.proc.poll() is None:
      self.proc.terminate()
      try:
        self.proc.wait(timeout=10)
      except subprocess.TimeoutExpired:
        self.proc.kill()


TAG = re.compile(r"<[^>]+>")


def cells(row_html):
  out = []
  for cell in re.findall(r"<td[^>]*>(.*?)</td>", row_html,
                         re.S):
    text = html_mod.unescape(TAG.sub("", cell)).strip()
    out.append(" ".join(text.split()))
  return out


def table_rows(page):
  """Every table row on a page, as a list of cell texts."""
  return [cells(r) for r in re.findall(r"<tr[^>]*>(.*?)</tr>", page,
                                       re.S)
          if "<td" in r]


def counter_rows(page):
  """{(zone, counter): packets-as-printed} from the counters page."""
  out = {}
  for row in table_rows(page):
    if len(row) == 3:
      out[(row[0], row[1])] = row[2]
  return out


def value_of(rows, zone, name):
  return rows.get((zone, name))


def send_udp(port, count, dst=EDGE_HOST):
  code = (
      "import socket;"
      "s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);"
      f"[s.sendto(b'x',('{dst}',{port})) for _ in range({count})]"
  )
  r = run(["ip", "netns", "exec", NETNS, sys.executable, "-c", code])
  time.sleep(0.5)
  return r


def xdp_attached(iface):
  out = sh(f"ip -details -json link show dev {iface}").stdout
  try:
    info = json.loads(out)
  except (ValueError, TypeError):
    return False
  return any(e.get("xdp", {}).get("prog", {}).get("id") for e in info)


def scenario_counts_on_the_page(fd_bin, ui_bin, fwl_root, work):
  print("\n1. counts land on the page under the names that declared "
        "them")
  bundle = os.path.join(work, "bundle-1")
  _, r = compile_bundle(fwl_root, POLICY, bundle, work)
  check("compiles", r.returncode == 0, r.stderr.strip())
  if r.returncode != 0:
    return
  d = Daemon(fd_bin, work).start(bundle)
  ui = Ui(ui_bin, work, d.sock).start()
  try:
    check("fd is running", d.alive(), d.text()[-400:])
    check("XDP is on both interfaces",
          xdp_attached(EDGE_IF) and xdp_attached(QUIET_IF))
    check("the UI answered", ui.alive(),
          open(ui.log, encoding="utf-8", errors="replace").read()[-400:])

    base = counter_rows(ui.get("/counters"))
    check("both counters are on the page by name before any traffic",
          value_of(base, "edge", "edge_probe") == "0" and
          value_of(base, "edge", "edge_never") == "0",
          json.dumps({str(k): v for k, v in base.items()}))
    check("the zone with no `count` says so rather than showing zero",
          value_of(base, "quiet", "no count statements") is not None,
          json.dumps({str(k): v for k, v in base.items()}))

    send_udp(COUNTED_PORT, 7)
    after = counter_rows(ui.get("/counters"))
    check("the counted rule reports exactly the traffic that hit it",
          value_of(after, "edge", "edge_probe") == "7",
          f"got {value_of(after, 'edge', 'edge_probe')!r}")
    check("the control counter in the same policy stays at zero",
          value_of(after, "edge", "edge_never") == "0",
          "a page that prints one number for every counter, or pairs "
          "values with names by position, passes without this")

    send_udp(UNCOUNTED_PORT, 4)
    neither = counter_rows(ui.get("/counters"))
    check("traffic matching neither rule moves neither counter",
          value_of(neither, "edge", "edge_probe") == "7" and
          value_of(neither, "edge", "edge_never") == "0",
          json.dumps({str(k): v for k, v in neither.items()}))

    send_udp(COUNTED_PORT, 5)
    more = ui.get("/counters")
    rows = counter_rows(more)
    check("the count is cumulative and still against its own name",
          value_of(rows, "edge", "edge_probe") == "12" and
          value_of(rows, "edge", "edge_never") == "0",
          json.dumps({str(k): v for k, v in rows.items()}))
    PAGES["read"] = more

    # The architectural claim, measured. This process shows real
    # numbers off a real datapath and holds no BPF object at all.
    maps = ui.open_bpf_maps()
    check("the UI holds no BPF map open", not maps, ", ".join(maps))
    check("...and it is not running as root",
          ui.user is not None and ui.user != "root",
          f"ran as {ui.user}")

    # The live fragments go out on the same sampler tick as the rest.
    # A page whose updates stop arriving looks exactly like a box
    # where nothing is changing, so a Publish that fails now says so
    # in the log — and this asserts none did across several ticks.
    time.sleep(1.5)
    uilog = open(ui.log, encoding="utf-8", errors="replace").read()
    check("every live fragment rendered and was sent",
          "live update" not in uilog,
          # A list here crashed the reporter on the one path that
          # matters — the failing one — so the detail is text.
          "; ".join(ln for ln in uilog.splitlines()
                    if "live update" in ln))

    dash = ui.get("/")
    check("the dashboard counters row is a measurement, not a badge",
          "1 named in 1 zone(s)" in dash or "2 named in 1 zone(s)"
          in dash, re.sub(r"\s+", " ", dash)[:400])
    check("the dashboard says nothing is unreadable",
          "unreadable" not in dash)
  finally:
    ui.stop()
    d.stop()


def scenario_unreadable_names(fd_bin, ui_bin, fwl_root, work):
  print("\n2. a zone whose names cannot be read says so, not zero")
  bundle = os.path.join(work, "bundle-2")
  _, r = compile_bundle(fwl_root, POLICY, bundle, work)
  if r.returncode != 0:
    check("compiles", False, r.stderr.strip())
    return
  # Remove the generated C, keep the object. The datapath is untouched
  # and still counting; what is gone is the only thing that can put a
  # NAME on a slot — the exact state the removed page rendered as "no
  # counters active" while the counters moved.
  os.remove(os.path.join(bundle, "edge.bpf.c"))
  d = Daemon(fd_bin, work).start(bundle)
  ui = Ui(ui_bin, work, d.sock).start()
  try:
    check("fd still comes up and attaches",
          d.alive() and xdp_attached(EDGE_IF), d.text()[-400:])
    send_udp(COUNTED_PORT, 6)
    page = ui.get("/counters")
    rows = counter_rows(page)
    PAGES["table_unreadable"] = page
    check("the zone is still on the page",
          any(z == "edge" for z, _ in rows),
          json.dumps({str(k): v for k, v in rows.items()}))
    check("it reports that the names are unknown",
          value_of(rows, "edge", "names unknown") is not None,
          json.dumps({str(k): v for k, v in rows.items()}))
    check("it does NOT report the counter as zero",
          value_of(rows, "edge", "edge_probe") is None,
          "a slot with no name rendered as a named zero is the defect "
          "this page exists to avoid")
    check("the reason names the file it could not read",
          "edge.bpf.c" in page, re.sub(r"\s+", " ", page)[:600])
    check("the dashboard names the unreadable zone",
          "edge" in ui.get("/") and "unreadable" in ui.get("/"))
  finally:
    ui.stop()
    d.stop()


def scenario_stale_table(fd_bin, ui_bin, fwl_root, work):
  print("\n3. generated C that is not the loaded object's source")
  bundle = os.path.join(work, "bundle-3")
  _, r = compile_bundle(fwl_root, POLICY, bundle, work)
  if r.returncode != 0:
    check("compiles", False, r.stderr.strip())
    return
  path = os.path.join(bundle, "edge.bpf.c")
  src = open(path, encoding="utf-8").read()
  src = src.replace("//   0\tedge_probe", "//   99\tedge_probe")
  with open(path, "w", encoding="utf-8") as f:
    f.write(src)
  d = Daemon(fd_bin, work).start(bundle)
  ui = Ui(ui_bin, work, d.sock).start()
  try:
    send_udp(COUNTED_PORT, 2)
    page = ui.get("/counters")
    rows = counter_rows(page)
    PAGES["table_map_mismatch"] = page
    check("the mismatch is reported as its own state",
          value_of(rows, "edge", "stale table") is not None,
          json.dumps({str(k): v for k, v in rows.items()}))
    check("no name is offered from the stale table",
          value_of(rows, "edge", "edge_probe") is None,
          "a plausible name against the wrong slot is the worst of "
          "the available answers")
    check("the reason names the counter and the slot",
          "edge_probe" in page and "99" in page,
          re.sub(r"\s+", " ", page)[:600])
  finally:
    ui.stop()
    d.stop()


def scenario_fd_down(fd_bin, ui_bin, fwl_root, work):
  print("\n4. with fd stopped, the pages say so")
  bundle = os.path.join(work, "bundle-4")
  _, r = compile_bundle(fwl_root, POLICY, bundle, work)
  if r.returncode != 0:
    check("compiles", False, r.stderr.strip())
    return
  d = Daemon(fd_bin, work).start(bundle)
  ui = Ui(ui_bin, work, d.sock).start()
  try:
    ui.get("/counters")
    d.stop()
    page = ui.get("/counters")
    PAGES["fd_down"] = page
    check("the counters page says it could not read from fd",
          "cannot read counters from fd" in page,
          re.sub(r"\s+", " ", page)[:600])
    check("it draws no table of zeros",
          "edge_probe" not in page and "<td" not in page,
          re.sub(r"\s+", " ", page)[:600])
    check("it does not claim the policy declares no counters",
          "no count statements" not in page)
    policy = ui.get("/policy")
    check("the policy page says it could not read the loaded policy",
          "cannot read the loaded policy from fd" in policy,
          re.sub(r"\s+", " ", policy)[:600])
    dash = ui.get("/")
    check("the dashboard counters row reports the failure",
          "cannot read counters from fd" in dash,
          re.sub(r"\s+", " ", dash)[:600])
  finally:
    ui.stop()
    d.stop()


def scenario_pages_differ(fd_bin, ui_bin, fwl_root, work):
  print("\n5. the four kinds of empty are four different pages")
  wanted = ["read", "table_unreadable", "table_map_mismatch",
            "fd_down"]
  missing = [k for k in wanted if k not in PAGES]
  if missing:
    check("every state was captured", False, f"missing {missing}")
    return
  for i, a in enumerate(wanted):
    for b in wanted[i + 1:]:
      check(f"'{a}' and '{b}' do not render the same page",
            PAGES[a].strip() != PAGES[b].strip(),
            "two different findings about a firewall, one screen")
  # And the discriminator that matters most, stated directly: none of
  # the three failures prints a number for the counter that is moving.
  for state in wanted[1:]:
    check(f"'{state}' prints no count for edge_probe",
          "edge_probe" not in PAGES[state] or
          "stale table" in PAGES[state],
          "a page that answers zero to a question it could not ask")


def scenario_policy_page(fd_bin, ui_bin, fwl_root, work):
  print("\n6. the policy page reports what fd has loaded")
  bundle = os.path.join(work, "bundle-6")
  _, r = compile_bundle(fwl_root, POLICY, bundle, work)
  if r.returncode != 0:
    check("compiles", False, r.stderr.strip())
    return
  d = Daemon(fd_bin, work).start(bundle)
  ui = Ui(ui_bin, work, d.sock).start()
  try:
    page = ui.get("/policy")
    rows = table_rows(page)
    zones = {row[0]: row for row in rows if len(row) == 7}
    check("both loaded zones are listed", "edge" in zones and
          "quiet" in zones, json.dumps(rows))
    check("each zone shows the interface fd attached it to",
          EDGE_IF in zones.get("edge", [""] * 7)[2],
          json.dumps(zones.get("edge")))
    check("the XDP mode fd measured is shown",
          zones.get("edge", [""] * 7)[3] in
          ("native", "generic", "mixed"),
          json.dumps(zones.get("edge")))
    check("the counters the loaded policy declares are named",
          "edge_probe" in zones.get("edge", [""] * 7)[6] and
          "edge_never" in zones.get("edge", [""] * 7)[6],
          json.dumps(zones.get("edge")))
    check("a zone declaring no counters says so on the policy page",
          "no count statements" in zones.get("quiet", [""] * 7)[6],
          json.dumps(zones.get("quiet")))
    # The page used to state that fd could not be asked for the
    # rules, which was true while the bundle carried none. It carries
    # them now, so the sentence is gone and the rules are here — and
    # the assertion moved with it, because a page still explaining a
    # closed gap is a page describing a different box.
    check("the gap sentence is gone now that the rules are served",
          "does not list the rules" not in page)
    check("the rules of the loaded policy are on the page",
          "pkt.dst_port" in page, page[-800:])
    rows = {r[0]: r[1] for r in table_rows(page) if len(r) == 2}
    check("connection tracking is reported for this policy",
          "connection tracking" in rows, json.dumps(rows))
    check("a policy with no conntrack question needs no tracker",
          "needs no tracker" in rows.get("host-originated flows", ""),
          json.dumps(rows))
  finally:
    ui.stop()
    d.stop()


def scenario_egress_tracker(fd_bin, ui_bin, fwl_root, work):
  print("\n7. an attached egress tracker is not reported as missing")
  bundle = os.path.join(work, "bundle-7")
  _, r = compile_bundle(fwl_root, CONNTRACK_POLICY, bundle, work)
  if r.returncode != 0:
    check("compiles", False, r.stderr.strip())
    return
  d = Daemon(fd_bin, work).start(bundle)
  ui = Ui(ui_bin, work, d.sock).start()
  try:
    check("fd loaded the conntrack policy", d.alive(),
          d.text()[-400:])
    page = ui.get("/policy")
    rows = {r[0]: r[1] for r in table_rows(page) if len(r) == 2}
    flows = rows.get("host-originated flows", "")
    # The defect this scenario exists for was found by walking a real
    # box: `egress.attached` is a count and the page read it as a list,
    # so a box with the tracker on both interfaces was told the hook
    # its policy needs was on none of them.
    check("the tracker the bundle declares is reported as attached",
          flows.startswith("tracked on"), f"got {flows!r}")
    check("...and names the interfaces it is on",
          EDGE_IF in flows, f"got {flows!r}")
    check("...and does not report it as missing",
          "NOT ATTACHED" not in flows, f"got {flows!r}")
    check("connection tracking is reported as on",
          rows.get("connection tracking", "").startswith("on"),
          json.dumps(rows))
  finally:
    ui.stop()
    d.stop()


def main():
  ap = argparse.ArgumentParser()
  here = os.path.dirname(os.path.abspath(__file__))
  ap.add_argument("--fd", default=os.path.join(here, "../../build/fd"))
  ap.add_argument("--ui", default=os.path.join(
      here, "../../build/einheit-f-ui"))
  ap.add_argument("--fwl-root", default=os.path.join(here, "../../fwl"))
  ap.add_argument("--only", nargs="*", default=None)
  args = ap.parse_args()

  if os.geteuid() != 0:
    print("must run as root (real XDP)")
    return 2
  for path in (args.fd, args.ui, args.fwl_root):
    if not os.path.exists(path):
      print(f"missing: {path}")
      return 2

  scenarios = {
      "1": scenario_counts_on_the_page,
      "2": scenario_unreadable_names,
      "3": scenario_stale_table,
      "4": scenario_fd_down,
      "5": scenario_pages_differ,
      "6": scenario_policy_page,
      "7": scenario_egress_tracker,
  }
  # Scenario 5 compares the pages the others captured, so asking for
  # it alone would compare nothing and report green.
  wanted = list(scenarios)
  if args.only:
    wanted = sorted(set(args.only))
    if "5" in wanted:
      wanted = sorted(set(wanted) | {"1", "2", "3", "4"})

  work = tempfile.mkdtemp(prefix="fuicounters-")
  os.chmod(work, 0o755)
  topo_up()
  try:
    for key in wanted:
      scenarios[key](os.path.abspath(args.fd), os.path.abspath(args.ui),
                     os.path.abspath(args.fwl_root), work)
  finally:
    topo_down()
    shutil.rmtree(work, ignore_errors=True)

  print(f"\n{PASS} passed, {FAIL} failed")
  return 1 if FAIL else 0


if __name__ == "__main__":
  sys.exit(main())
