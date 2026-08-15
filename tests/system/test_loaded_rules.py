#!/usr/bin/env python3
"""The box reports the rules it is actually running.

The gap this closes was stated for two sessions rather than papered
over: `fd` holds compiled BPF objects, the bundle manifest carried
per-zone topology and no rule metadata, and the daemon has never seen
the policy text. `show policy` read the SOURCE FILE — which is not
necessarily what is loaded — and `/policy` said in place that the rules
could not be shown. At the office the question is "what is this box
enforcing right now", and the honest answer was "read the file and hope
it matches".

The measurement that makes a green result here mean something is a
DIVERGENCE. Every scenario below that claims the box reports the loaded
policy first edits the source WITHOUT applying it, so the file and the
packet path say different things. A reader that quietly re-derived the
rules from disk — which is what any implementation short of load-time
capture does — reports the edit and passes every test that only ever
looks at a box where the two agree.

Seven scenarios, on a real `fd` with real XDP over two veths into a
netns, with the web UI beside it:

  1. the rules of the loaded policy are served, in policy order, with
     their actions and matches, over opcode 13.
  2. the source is edited and NOT applied: the CLI still reports the
     loaded rules, reports the edit as DRIFT, and the drifted rule
     does not appear. Then the source is removed, and the verdict
     becomes "cannot tell" rather than either of the two answers the
     box has no evidence for.
  3. a reload makes the new rules the reported ones, and the drift
     verdict goes back to a match.
  4. the CLI and the UI agree — the same rules, from the same daemon,
     rendered by two different surfaces.
  5. the availability states stay apart: "no rules", "written as a
     function", and a bundle compiled before this metadata existed
     ("cannot ask") are three different screens.
  6. with fd stopped, both surfaces say so rather than showing a
     policy with no rules in it.
  7. the datapath is what the reported rules say it is: the rule the
     box reports as a drop drops, and the port it does not name
     arrives.
  8. the bundle directory is RECOMPILED behind the daemon's back and
     the box goes on reporting the policy it loaded. This is the
     scenario that separates metadata captured at load from metadata
     re-read when somebody asks; nothing else here can tell them
     apart.

Run on the target, as root:
  sudo ./test_loaded_rules.py --fd ../../build/fd \\
      --cli ../../build/einheit-f --ui ../../build/einheit-f-ui
"""
import argparse
import hashlib
import html as html_mod
import json
import os
import pwd
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

PASS = 0
FAIL = 0

EDGE_IF = "fwlrul0"
EDGE_PEER = "fwlrul0p"
QUIET_IF = "fwlrul1"
QUIET_PEER = "fwlrul1p"
NETNS = "fwlrulns"
EDGE_HOST = "10.81.0.1"
EDGE_PEER_ADDR = "10.81.0.2"
QUIET_HOST = "10.81.1.1"
QUIET_PEER_ADDR = "10.81.1.2"

DROPPED_PORT = 9301
OPEN_PORT = 9302
LATER_PORT = 9303
# A port whose rule carries a TARGET — `redirect to quiet`. An action
# rendered without its target reads the same for every destination,
# which is a redirect to the wrong zone that nobody can see.
SENT_PORT = 9304
UI_PORT = 17544

# How both surfaces spell "this rule has no guard". Written once here
# so a test cannot pass by comparing one surface's blank cell with the
# other's.
UNGUARDED = "every packet — stops here"

# Two zones with different shapes, so one policy exercises several of
# the states at once: `edge` has rules and an explicit default, `quiet`
# has no rules at all and falls through.
POLICY = f"""zone edge = [{EDGE_IF}]
zone quiet = [{QUIET_IF}]

@xdp(edge)

count edge_seen
drop if pkt.proto == udp and pkt.dst_port == {DROPPED_PORT}
redirect to quiet if pkt.proto == udp and pkt.dst_port == {SENT_PORT}
allow

@xdp(quiet)

allow
"""

# The edit scenario 2 makes and does NOT apply. A second dropped port
# that must not appear in what the box reports until it is compiled in.
EDITED = POLICY.replace(
    f"drop if pkt.proto == udp and pkt.dst_port == {DROPPED_PORT}",
    f"drop if pkt.proto == udp and pkt.dst_port == {DROPPED_PORT}\n"
    f"drop if pkt.proto == udp and pkt.dst_port == {LATER_PORT}")

# A zone whose policy is a Tier 2 function: there is no rule list to
# give, which is a different finding from a zone with no rules.
FUNCTION_POLICY = f"""zone edge = [{EDGE_IF}]
zone quiet = [{QUIET_IF}]

@xdp(edge)

def policy(pkt):
  if pkt.proto == udp and pkt.dst_port == {DROPPED_PORT}:
    drop
  allow

@xdp(quiet)

allow
"""

# A zone with no rules at all, only a default. `edge` keeps its rules
# so the two states appear on one screen.
BARE_POLICY = f"""zone edge = [{EDGE_IF}]
zone quiet = [{QUIET_IF}]

@xdp(edge)

drop if pkt.proto == udp and pkt.dst_port == {DROPPED_PORT}
allow

@xdp(quiet)

default drop
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


def compile_bundle(fwl_root, src, bundle_dir):
  """Compile with the IN-TREE compiler, never the one on PATH."""
  shutil.rmtree(bundle_dir, ignore_errors=True)
  env = dict(os.environ, PYTHONPATH=python_path(fwl_root))
  return run([sys.executable, "-c", "from fwl.cli import main; main()",
              "compile", src, "--bundle", bundle_dir], env=env)


def write_source(path, text):
  with open(path, "w", encoding="utf-8") as f:
    f.write(text)
  return path


class Daemon:
  """A real `fd`, cold-booting a real bundle, on its own pin root."""

  def __init__(self, fd_bin, work, source=None, fwl_root=None):
    self.fd_bin = fd_bin
    self.work = work
    self.source = source
    self.fwl_root = fwl_root
    self.root = os.path.join(work, "fdroot")
    self.pin = "/sys/fs/bpf/fruleset"
    self.sock_path = os.path.join(work, "fd.sock")
    self.sock = f"ipc://{self.sock_path}"
    self.log = os.path.join(work, "fd.log")
    self.proc = None

  def fwl_shim(self):
    """A `fwl` that is the IN-TREE compiler.

    The `fwl` on PATH is stale on more than one machine here and
    accepts a different language from the one in the tree; a reload
    driven by it would be testing a compiler nobody is changing.
    """
    path = os.path.join(self.work, "fwl-shim")
    with open(path, "w", encoding="utf-8") as f:
      f.write("#!/bin/sh\n"
              f"PYTHONPATH={python_path(self.fwl_root)} "
              f"exec {sys.executable} -c "
              "'from fwl.cli import main; main()' \"$@\"\n")
    os.chmod(path, 0o755)
    return path

  def start(self, bundle_dir):
    os.makedirs(self.root, exist_ok=True)
    link = os.path.join(self.root, "current")
    if os.path.islink(link) or os.path.exists(link):
      os.remove(link)
    os.symlink(bundle_dir, link)
    cfg = os.path.join(self.root, "fd.yaml")
    lines = [f"pin_path: {self.pin}\n",
             f"socket: {self.sock}\n",
             "log_level: debug\n",
             # The watcher THREAD stays off — nothing here should
             # reload behind a scenario's back — but the daemon still
             # needs to be told where the source is, because that is
             # what `reload firewall` recompiles.
             "watch:\n  enabled: false\n"]
    if self.source and self.fwl_root:
      lines += [f"  source: {self.source}\n",
                f"  compiled_dir: {os.path.join(self.work, 'built')}\n",
                f"  fwl: {self.fwl_shim()}\n"]
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

  def start(self):
    logf = open(self.log, "w", encoding="utf-8")
    ident = unprivileged_uid()
    uid, gid = (None, None)
    if ident is not None:
      uid, gid, _ = ident

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

  def stop(self):
    if self.proc is not None and self.proc.poll() is None:
      self.proc.terminate()
      try:
        self.proc.wait(timeout=10)
      except subprocess.TimeoutExpired:
        self.proc.kill()


class Cli:
  """`einheit-f`, pointed at this fd and this policy file."""

  def __init__(self, cli_bin, work, fd_sock, fw_source):
    self.cli_bin = cli_bin
    self.work = work
    self.fd_sock = fd_sock
    self.fw_source = fw_source

  def run(self, *args, fmt="table"):
    argv = [
        self.cli_bin, "--color", "never", "--format", fmt,
        "--system-config", os.path.join(self.work, "system.yaml"),
        "--source", self.fw_source,
        "--networkd-dir", os.path.join(self.work, "net"),
        "--dnsmasq-conf", os.path.join(self.work, "dnsmasq.conf"),
        "--sysctl-dir", os.path.join(self.work, "sysctl"),
        "--socket", self.fd_sock,
    ] + list(args)
    return run(argv)

  def policy_json(self, *args):
    r = self.run("show", "policy", *args, fmt="json")
    try:
      doc = json.loads(r.stdout)
    except ValueError:
      return []
    # Always a list of rows. A helper that had to cope with two shapes
    # would swallow the case where the CLI produced neither.
    return doc if isinstance(doc, list) else []


TAG = re.compile(r"<[^>]+>")


def strip_tags(page):
  return html_mod.unescape(TAG.sub(" ", page))


def send_udp(port, count, dst=EDGE_HOST):
  code = (
      "import socket;"
      "s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);"
      f"[s.sendto(b'x',('{dst}',{port})) for _ in range({count})]"
  )
  r = run(["ip", "netns", "exec", NETNS, sys.executable, "-c", code])
  time.sleep(0.5)
  return r


def receives(port, count=3):
  """True when datagrams to `port` reach a socket on the host.

  A DROP is the only evidence that separates an attached program from
  an absent one: an allow rule cannot tell "attached and permitting"
  from "not attached at all" (BUGLOG #43).
  """
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  s.settimeout(2.0)
  try:
    s.bind((EDGE_HOST, port))
    send_udp(port, count)
    try:
      s.recvfrom(64)
      return True
    except socket.timeout:
      return False
  finally:
    s.close()


# The operator surface, not the wire. `show policy --format json`
# renders ONE document whose every row says which claim it belongs to:
# `loaded` is the packet path as fd reports it, `source` is a statement
# in a file, `drift` is the verdict comparing the two. Testing the wire
# instead would leave the renderer — where the last session's bugs
# lived — unexercised.

def rows_of(doc, kind):
  return [r for r in doc
          if isinstance(r, dict) and r.get("KIND") == kind]


def loaded_for(doc, zone):
  return [r for r in rows_of(doc, "loaded") if r.get("ZONE") == zone]


def statements_of(doc, zone):
  return [r["STATEMENT"] for r in loaded_for(doc, zone)]


def source_statements(doc):
  return [r["STATEMENT"] for r in rows_of(doc, "source")]


def drift_row(doc):
  rows = rows_of(doc, "drift")
  return rows[0] if rows else {}


def drift_verdict(doc):
  return drift_row(doc).get("STATEMENT", "")


def drift_text(doc):
  return drift_row(doc).get("MATCHES", "")


def cli_rules(doc, zone):
  """[(action, match)] as the CLI rendered them, for one zone.

  An unguarded rule takes the WORDS THE CLI PRINTED for it, not an
  empty string. "this rule stops every packet", "this rule runs on
  every packet and falls through" and "we have nothing to put in this
  cell" must not compare equal, or a surface that lost the distinction
  would agree with one that kept it.
  """
  out = []
  for row in loaded_for(doc, zone):
    st = row["STATEMENT"]
    if st.startswith("default ") or st.startswith("("):
      continue
    action, sep, match = st.partition(" if ")
    limit, has_limit, _ = action.partition(" limited by ")
    if has_limit:
      action = limit
    out.append((action.strip(),
                match.strip() if sep else row["MATCHES"].strip()))
  return out


def page_rules(page_html, zone):
  """[(action, match)] as the web page rendered them, for one zone."""
  block = re.search(
      rf'<h3 class="mono">\s*{re.escape(zone)}\b.*?</table>',
      page_html, re.S)
  if not block:
    return []
  out = []
  for row in re.findall(r"<tr[^>]*>(.*?)</tr>", block.group(0), re.S):
    cells = [" ".join(html_mod.unescape(TAG.sub("", c)).split())
             for c in re.findall(r"<td[^>]*>(.*?)</td>", row, re.S)]
    if len(cells) < 2:
      continue
    out.append((cells[0], cells[1]))
  return out


def loaded_answered(doc):
  """False when the daemon could not be asked at all."""
  for r in rows_of(doc, "loaded"):
    if not r.get("ZONE") and "cannot read the loaded policy" in (
        r.get("MATCHES") or ""):
      return False
  return True


# --- scenarios -------------------------------------------------------

def scenario_rules_are_served(fd, cli_bin, ui_bin, fwl_root, work):
  print("\n1. the loaded policy's rules are served, in policy order")
  src = write_source(os.path.join(work, "policy.fw"), POLICY)
  bundle = os.path.join(work, "bundle-1")
  r = compile_bundle(fwl_root, src, bundle)
  check("compiles", r.returncode == 0, r.stderr.strip())
  if r.returncode != 0:
    return
  d = Daemon(fd, work).start(bundle)
  cli = Cli(cli_bin, work, d.sock, src)
  try:
    check("fd is running", d.alive(), d.text()[-400:])
    doc = cli.policy_json()
    check("the daemon answered the rule query", loaded_answered(doc),
          json.dumps(doc)[:400])
    zones = {r["ZONE"] for r in rows_of(doc, "loaded") if r["ZONE"]}
    check("both loaded zones are reported",
          zones == {"edge", "quiet"}, json.dumps(sorted(zones)))

    edge = statements_of(doc, "edge")
    if len(edge) < 4:
      check("the edge zone reported its rules", False,
            json.dumps(edge))
      return
    check("the rules are in policy order",
          edge[:4] == [
              "count edge_seen",
              f"drop if pkt.proto == udp and "
              f"pkt.dst_port == {DROPPED_PORT}",
              f"redirect to quiet if pkt.proto == udp and "
              f"pkt.dst_port == {SENT_PORT}",
              "allow"],
          json.dumps(edge))
    check("the match names the port the policy names",
          str(DROPPED_PORT) in edge[1], json.dumps(edge))
    # An action reported without its target is the same row for every
    # destination: a `redirect to quiet` and a `redirect to dmz` read
    # identically, and a counter's name disappears.
    check("a redirect reports the zone it sends to",
          any(st.startswith("redirect to quiet") for st in edge),
          json.dumps(edge))
    check("a count reports the name it bumps",
          "count edge_seen" in edge, json.dumps(edge))
    check("no loaded row carries a `no rule` position",
          all(not r["#"] for r in rows_of(doc, "loaded")),
          json.dumps(rows_of(doc, "loaded")))
    # A block with no `default` line falls through to XDP_PASS — it
    # ALLOWS. Reported as nothing at all, the most consequential line
    # of a policy would be a blank.
    check("the fall-through default is named rather than left blank",
          any("default allow" in st for st in edge), json.dumps(edge))
    check("...and is marked as not written by the author",
          any("falls through" in (r["MATCHES"] or "")
              for r in loaded_for(doc, "edge")),
          json.dumps(loaded_for(doc, "edge")))
    quiet = statements_of(doc, "quiet")
    check("the second zone is reported too",
          any("allow" in st for st in quiet), json.dumps(quiet))

    # The two ends of the drift answer agreeing: the digest the
    # compiler recorded is the digest of the bytes it compiled.
    want = hashlib.sha256(POLICY.encode("utf-8")).hexdigest()
    manifest = os.path.join(bundle, "manifest.json")
    with open(manifest, encoding="utf-8") as f:
      m = json.load(f)
    check("the bundle records the digest of its source",
          (m.get("policy_source") or {}).get("sha256") == want,
          json.dumps(m.get("policy_source")))
    check("the source on disk is reported as the loaded policy",
          drift_verdict(doc) == "match", drift_text(doc))
  finally:
    d.stop()


def scenario_drift_is_detected(fd, cli_bin, ui_bin, fwl_root, work):
  print("\n2. the source is edited and NOT applied")
  src = write_source(os.path.join(work, "policy.fw"), POLICY)
  bundle = os.path.join(work, "bundle-2")
  r = compile_bundle(fwl_root, src, bundle)
  if r.returncode != 0:
    check("compiles", False, r.stderr.strip())
    return
  d = Daemon(fd, work).start(bundle)
  cli = Cli(cli_bin, work, d.sock, src)
  ui = Ui(ui_bin, work, d.sock).start()
  try:
    before = cli.policy_json()
    check("before the edit the file and the loaded policy agree",
          drift_verdict(before) == "match", drift_text(before))

    # The edit. Nothing is compiled and nothing is reloaded — this is
    # exactly the state an operator gets into by opening the file.
    write_source(src, EDITED)
    after = cli.policy_json()

    check("the box reports DRIFT rather than a match",
          drift_verdict(after) == "differs", drift_text(after))
    check("...and says the box is enforcing the older policy",
          "OLDER" in drift_text(after), drift_text(after))

    texts = statements_of(after, "edge")
    check("the edited-in rule is NOT reported as loaded",
          not any(str(LATER_PORT) in t for t in texts),
          json.dumps(texts))
    check("the rules that ARE loaded are still reported",
          any(str(DROPPED_PORT) in t for t in texts),
          json.dumps(texts))
    # And the source half of the same document does carry the edit, so
    # the operator sees both and the difference between them.
    src_texts = source_statements(after)
    check("the SOURCE rows do show the edit",
          any(str(LATER_PORT) in t for t in src_texts),
          json.dumps(src_texts))

    # The datapath is the arbiter. The rule the operator added is not
    # in the packet path, and the box said so.
    check("the edited-in port still arrives, as the box reported",
          receives(LATER_PORT))
    check("the loaded drop is still dropping",
          not receives(DROPPED_PORT))

    # The human-readable rendering has to carry it too — a verdict
    # that only exists under --format json is a verdict nobody sees.
    plain = cli.run("show", "policy")
    check("the drift verdict is in the operator's own output",
          "DRIFT" in plain.stdout or "DRIFT" in plain.stderr,
          (plain.stdout + plain.stderr)[-500:])

    # And the third value. With fd answering perfectly well and the
    # source gone, the box has not found a match and has not found an
    # edit — it has failed to look, and saying either of the other two
    # would be inventing an answer.
    os.remove(src)
    gone = cli.policy_json()
    check("a source that cannot be read is neither match nor drift",
          drift_verdict(gone) == "cannot_tell", drift_text(gone))
    check("...and the sentence names the file it went looking for",
          "policy.fw" in drift_text(gone), drift_text(gone))
    check("...and the rules that ARE loaded are still reported",
          any(str(DROPPED_PORT) in t
              for t in statements_of(gone, "edge")),
          json.dumps(statements_of(gone, "edge")))
  finally:
    ui.stop()
    d.stop()


def scenario_reload_moves_the_answer(fd, cli_bin, ui_bin, fwl_root,
                                     work):
  print("\n3. a reload makes the new rules the reported ones")
  src = write_source(os.path.join(work, "policy.fw"), POLICY)
  bundle = os.path.join(work, "bundle-3a")
  r = compile_bundle(fwl_root, src, bundle)
  if r.returncode != 0:
    check("compiles", False, r.stderr.strip())
    return
  d = Daemon(fd, work, source=src, fwl_root=fwl_root).start(bundle)
  cli = Cli(cli_bin, work, d.sock, src)
  try:
    write_source(src, EDITED)
    check("drift before the reload",
          drift_verdict(cli.policy_json()) == "differs")

    r = cli.run("reload", "firewall")
    check("reload firewall succeeds",
          r.returncode == 0, (r.stdout + r.stderr)[-400:])
    time.sleep(1.0)

    doc = cli.policy_json()
    texts = statements_of(doc, "edge")
    check("the new rule is now reported as loaded",
          any(str(LATER_PORT) in t for t in texts), json.dumps(texts))
    check("the drift verdict is back to a match",
          drift_verdict(doc) == "match", drift_text(doc))
    check("the new drop is dropping on the wire",
          not receives(LATER_PORT))
  finally:
    d.stop()


def scenario_both_surfaces_agree(fd, cli_bin, ui_bin, fwl_root, work):
  print("\n4. the CLI and the web page report the same rules")
  src = write_source(os.path.join(work, "policy.fw"), POLICY)
  bundle = os.path.join(work, "bundle-4")
  r = compile_bundle(fwl_root, src, bundle)
  if r.returncode != 0:
    check("compiles", False, r.stderr.strip())
    return
  d = Daemon(fd, work).start(bundle)
  cli = Cli(cli_bin, work, d.sock, src)
  ui = Ui(ui_bin, work, d.sock).start()
  try:
    check("the UI answered", ui.alive(),
          open(ui.log, encoding="utf-8", errors="replace").read()[-400:])
    doc = cli.policy_json()
    page_html = ui.get("/policy")
    page = " ".join(strip_tags(page_html).split())

    # The claim is agreement, not resemblance: the same ordered
    # (action, match) sequence per zone out of two renderings of one
    # daemon reply. A page built from a second reader of the disk
    # could agree by accident today and disagree after a reload.
    for zone in ("edge", "quiet"):
      from_cli = cli_rules(doc, zone)
      from_page = page_rules(page_html, zone)
      check(f"the CLI reported rules for {zone}", bool(from_cli),
            json.dumps(doc)[:300])
      check(f"the page and the CLI agree about {zone}",
            from_cli == from_page,
            json.dumps({"cli": from_cli, "page": from_page}))
    check("the page does not claim the rules are unavailable",
          "cannot read the loaded policy" not in page, page[-400:])

    # The live fragment goes out on the sampler tick. A rule table
    # that stops updating shows the previous policy after a reload,
    # which is the same lie as a counter table frozen at yesterday's
    # numbers — and a fragment published in the wrong shape renders
    # nothing while the page beside it looks fine.
    time.sleep(1.5)
    uilog = open(ui.log, encoding="utf-8", errors="replace").read()
    check("the rules live fragment is published, not dropped",
          "live update" not in uilog,
          "; ".join(ln for ln in uilog.splitlines()
                    if "live update" in ln))
    # A rule that runs on every packet gets a word for it. An empty
    # cell there is indistinguishable from a guard nobody could write
    # down, and the two are opposite claims about a firewall.
    check("an unguarded terminal rule says it stops every packet",
          ("allow", UNGUARDED) in page_rules(page_html, "edge"),
          json.dumps(page_rules(page_html, "edge")))
    # ...and an unguarded `count`, which falls through, is not marked
    # the same way. A red flag beside the harmless statement is how an
    # operator learns to ignore the column.
    check("an unguarded count is not marked as stopping packets",
          ("count edge_seen", "every packet, falls through")
          in page_rules(page_html, "edge"),
          json.dumps(page_rules(page_html, "edge")))
  finally:
    ui.stop()
    d.stop()


def scenario_states_stay_apart(fd, cli_bin, ui_bin, fwl_root, work):
  print("\n5. no-rules, function-form and cannot-ask stay three "
        "answers")
  screens = {}

  def capture(tag, text, mangle=None):
    src = write_source(os.path.join(work, f"policy-{tag}.fw"), text)
    bundle = os.path.join(work, f"bundle-5{tag}")
    r = compile_bundle(fwl_root, src, bundle)
    if r.returncode != 0:
      check(f"compiles ({tag})", False, r.stderr.strip())
      return None
    if mangle:
      mangle(bundle)
    d = Daemon(fd, work).start(bundle)
    cli = Cli(cli_bin, work, d.sock, src)
    ui = Ui(ui_bin, work, d.sock).start()
    try:
      doc = cli.policy_json()
      page = ui.get("/policy")
      screens[tag] = (doc, page)
      return doc
    finally:
      ui.stop()
      d.stop()

  def strip_rule_metadata(bundle):
    """Make the bundle look like one an older `fwl` produced.

    This is the upgrade case, and it is the state that matters most:
    rendered as "no rules" it shows a working firewall as an empty
    one on every box upgraded across this change.
    """
    path = os.path.join(bundle, "manifest.json")
    with open(path, encoding="utf-8") as f:
      m = json.load(f)
    for p in m.get("programs", []):
      p.pop("rules", None)
    m.pop("policy_source", None)
    with open(path, "w", encoding="utf-8") as f:
      json.dump(m, f, indent=2)

  bare = capture("bare", BARE_POLICY)
  fn = capture("fn", FUNCTION_POLICY)
  old = capture("old", POLICY, mangle=strip_rule_metadata)

  words = {}
  if bare:
    q = statements_of(bare, "quiet")
    words["bare"] = q
    check("a zone with only a default says it has no rules",
          any("no rules" in st for st in q), json.dumps(q))
  if fn:
    e = statements_of(fn, "edge")
    words["fn"] = e
    check("a Tier 2 zone says it is written as a function",
          any("written as a function" in st for st in e),
          json.dumps(e))
    check("...and says why, naming the tier",
          any("Tier 2" in (r["MATCHES"] or "")
              for r in loaded_for(fn, "edge")),
          json.dumps(loaded_for(fn, "edge")))
  if old:
    e = statements_of(old, "edge")
    words["old"] = e
    check("a bundle with no rule metadata says the rules are unknown",
          any("rules unknown" in st for st in e), json.dumps(e))
    check("...and does NOT say the policy has no rules",
          not any("no rules" in st for st in e), json.dumps(e))
    check("...and the source cannot be compared rather than matching",
          drift_verdict(old) == "cannot_tell", drift_text(old))
  keys = sorted(words)
  for i, a in enumerate(keys):
    for b in keys[i + 1:]:
      check(f"the {a} and {b} zone states read differently",
            words[a] != words[b], json.dumps([words[a], words[b]]))

  pages = {t: strip_tags(p) for t, (_, p) in screens.items()}
  keys = sorted(pages)
  for i, a in enumerate(keys):
    for b in keys[i + 1:]:
      check(f"the {a} and {b} pages differ",
            pages[a] != pages[b])
  if "old" in pages:
    check("the upgrade case does not draw an empty rule table",
          "rules unknown" in pages["old"], pages["old"][-500:])


def scenario_fd_down(fd, cli_bin, ui_bin, fwl_root, work):
  print("\n6. with fd stopped, neither surface invents a policy")
  src = write_source(os.path.join(work, "policy.fw"), POLICY)
  bundle = os.path.join(work, "bundle-6")
  r = compile_bundle(fwl_root, src, bundle)
  if r.returncode != 0:
    check("compiles", False, r.stderr.strip())
    return
  d = Daemon(fd, work).start(bundle)
  ui = Ui(ui_bin, work, d.sock).start()
  cli = Cli(cli_bin, work, d.sock, src)
  try:
    live = strip_tags(ui.get("/policy"))
    d.stop()
    time.sleep(0.5)
    dead_page = strip_tags(ui.get("/policy"))
    doc = cli.policy_json()

    check("the CLI says the loaded policy could not be read",
          not loaded_answered(doc), json.dumps(doc)[:400])
    check("...and names no zone as having rules",
          not any(r["ZONE"] for r in rows_of(doc, "loaded")),
          json.dumps(rows_of(doc, "loaded")))
    check("...and the drift verdict is cannot_tell, never a match",
          drift_verdict(doc) == "cannot_tell", drift_text(doc))
    # ...for fd's own reason. Blaming the bundle for the daemon being
    # down sends an operator to recompile a policy that is fine.
    check("...and the reason given is that fd could not be asked",
          "from fd" in drift_text(doc), drift_text(doc))
    check("the page says it cannot read the rules from fd",
          "cannot read the loaded policy's rules" in dead_page,
          dead_page[-500:])
    check("the dead page differs from the live one",
          dead_page != live)
    # The source is still on disk, and reading it is still possible —
    # so the CLI must not fail outright, it must report both halves.
    check("the source rows survive fd being down",
          bool(source_statements(doc)), json.dumps(doc)[:300])
  finally:
    ui.stop()
    d.stop()


def scenario_the_reported_rule_is_the_enforced_rule(fd, cli_bin,
                                                    ui_bin, fwl_root,
                                                    work):
  print("\n7. the datapath does what the reported rules say")
  src = write_source(os.path.join(work, "policy.fw"), POLICY)
  bundle = os.path.join(work, "bundle-7")
  r = compile_bundle(fwl_root, src, bundle)
  if r.returncode != 0:
    check("compiles", False, r.stderr.strip())
    return
  d = Daemon(fd, work).start(bundle)
  cli = Cli(cli_bin, work, d.sock, src)
  try:
    edge = statements_of(cli.policy_json(), "edge")
    dropped = [st for st in edge if st.startswith("drop")]
    check("the box reports exactly one drop rule",
          len(dropped) == 1, json.dumps(edge))
    if not dropped:
      return
    check("the reported drop names a port",
          str(DROPPED_PORT) in dropped[0], dropped[0])
    # The report is not evidence about the wire; the wire is. A rule
    # table read off a manifest could name any port at all.
    check("the port the box reports as dropped does not arrive",
          not receives(DROPPED_PORT))
    check("a port the reported rules do not name arrives",
          receives(OPEN_PORT))
  finally:
    d.stop()


def scenario_bundle_recompiled_behind_the_daemon(fd, cli_bin, ui_bin,
                                                 fwl_root, work):
  print("\n8. the bundle directory is recompiled behind fd's back")
  # This is the state that separates metadata CAPTURED AT LOAD from
  # metadata re-read when somebody asks. An operator (or a script, or
  # a reload whose compile succeeded and whose load did not) leaves a
  # bundle directory holding a manifest that is NOT the one the
  # running programs were loaded from. A reader that consults the
  # directory then describes a policy that is not in the packet path,
  # and it looks entirely plausible.
  src = write_source(os.path.join(work, "policy.fw"), POLICY)
  bundle = os.path.join(work, "bundle-8")
  r = compile_bundle(fwl_root, src, bundle)
  if r.returncode != 0:
    check("compiles", False, r.stderr.strip())
    return
  d = Daemon(fd, work).start(bundle)
  cli = Cli(cli_bin, work, d.sock, src)
  ui = Ui(ui_bin, work, d.sock).start()
  try:
    check("the loaded policy is reported before the recompile",
          any(str(DROPPED_PORT) in st
              for st in statements_of(cli.policy_json(), "edge")))

    # Recompile the edited source OVER the very directory `current`
    # points at. Nothing tells fd; the attached programs are the old
    # ones.
    write_source(src, EDITED)
    r = compile_bundle(fwl_root, src, bundle)
    check("the bundle directory now holds the NEW manifest",
          r.returncode == 0, r.stderr.strip())
    with open(os.path.join(bundle, "manifest.json"),
              encoding="utf-8") as f:
      on_disk = json.dumps(json.load(f))
    check("...and the manifest on disk really did change",
          str(LATER_PORT) in on_disk)

    doc = cli.policy_json()
    texts = statements_of(doc, "edge")
    check("the box still reports the rules it LOADED",
          not any(str(LATER_PORT) in t for t in texts),
          json.dumps(texts))
    check("...and still reports the ones that are in the packet path",
          any(str(DROPPED_PORT) in t for t in texts),
          json.dumps(texts))
    check("...and the wire agrees: the recompiled rule is not live",
          receives(LATER_PORT))
    check("the drift verdict still says the file is not the policy",
          drift_verdict(doc) == "differs", drift_text(doc))

    page = " ".join(strip_tags(ui.get("/policy")).split())
    check("the web page reports the loaded rules too, not the file",
          str(LATER_PORT) not in page, page[-500:])
    check("...and does show the loaded drop",
          str(DROPPED_PORT) in page, page[-500:])
  finally:
    ui.stop()
    d.stop()


def main():
  ap = argparse.ArgumentParser()
  here = os.path.dirname(os.path.abspath(__file__))
  ap.add_argument("--fd", default=os.path.join(here, "../../build/fd"))
  ap.add_argument("--cli", default=os.path.join(
      here, "../../build/einheit-f"))
  ap.add_argument("--ui", default=os.path.join(
      here, "../../build/einheit-f-ui"))
  ap.add_argument("--fwl-root", default=os.path.join(here, "../../fwl"))
  ap.add_argument("--only", nargs="*", default=None)
  args = ap.parse_args()

  if os.geteuid() != 0:
    print("must run as root (real XDP)")
    return 2
  for path in (args.fd, args.cli, args.ui, args.fwl_root):
    if not os.path.exists(path):
      print(f"missing: {path}")
      return 2

  scenarios = {
      "1": scenario_rules_are_served,
      "2": scenario_drift_is_detected,
      "3": scenario_reload_moves_the_answer,
      "4": scenario_both_surfaces_agree,
      "5": scenario_states_stay_apart,
      "6": scenario_fd_down,
      "7": scenario_the_reported_rule_is_the_enforced_rule,
      "8": scenario_bundle_recompiled_behind_the_daemon,
  }
  wanted = sorted(set(args.only)) if args.only else list(scenarios)

  work = tempfile.mkdtemp(prefix="fruleset-")
  os.chmod(work, 0o755)
  topo_up()
  try:
    for key in wanted:
      scenarios[key](os.path.abspath(args.fd),
                     os.path.abspath(args.cli),
                     os.path.abspath(args.ui),
                     os.path.abspath(args.fwl_root), work)
  finally:
    topo_down()
    shutil.rmtree(work, ignore_errors=True)

  print(f"\n{PASS} passed, {FAIL} failed")
  return 1 if FAIL else 0


if __name__ == "__main__":
  sys.exit(main())
