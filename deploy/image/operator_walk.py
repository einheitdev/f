#!/usr/bin/env python3
"""Walk the deployment the way the operator would, and count friction.

`firstboot_walk.py` asks whether the image is correct. This asks a
different question — whether a person with a terminal, the docs and no
context from this workspace can take a box out of the box and end up
with an office gateway — and it is written to produce a FRICTION LIST
rather than a verdict. A run in which every step succeeds has not done
its job unless it also says what the operator had to know that the
documentation does not.

So every command sent to the box is kept with its exact reply, and
`friction()` is a first-class result beside `check()`. Four kinds are
worth writing down, and all four turned up in the first rehearsal:

  * output that does not answer the question the command asks
  * a step the docs describe with a name, path or verb that is not the
    one the software uses
  * something you had to reach for a file to do, on a box whose claim
    is that the CLI is the interface
  * a command that is missing entirely

The order is the operator's, not the software's:

  1. firstboot  — a fresh image, told nothing
  2. configure  — zones, ports, addresses, DHCP and DNS, through the
                  CLI verbs and nothing else
  3. policy     — the office-shaped gateway, following
                  docs/howto/give-a-zone-internet-access.md literally
  4. traffic    — a client on the inside takes a DHCP lease, resolves
                  a name, and reaches the far side. The far side is an
                  ordinary non-promiscuous Linux stack in its own
                  namespace, so its `accept()` reporting a translated
                  peer is the masquerade evidence; a sniffer counts
                  frames no socket took.
  5. restart    — `systemctl restart fd`, the first step in the
                  handbook's own recovery procedure
  6. reboot     — and the box comes back carrying traffic with nobody
                  typing anything. This is the check that would go red
                  if fail-closed had become fail-never.
  7. commit     — a policy change through `configure` / `commit`
  8. lockout    — the management path severed on purpose, and
                  commit-confirmed bringing it back

Usage:
  deploy/image/operator_walk.py --rootfs DIR --out DIR
  deploy/image/operator_walk.py --out DIR --phases traffic,reboot

Everything observed goes to <out>/operator-walk.json and to stdout.
"""

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import vm  # noqa: E402
import firstboot_walk as fw  # noqa: E402

# The inside client's lease comes out of this range, which must not
# collide with the static address the rest of the bench uses.
DHCP_FIRST = "10.10.1.100"
DHCP_LAST = "10.10.1.150"
# A name that exists nowhere but on the resolver this walk starts, on
# the FAR side of the appliance. A public resolver would also answer,
# and would prove less: it would answer if the workstation were
# carrying the query.
TEST_NAME = "far.test"
UPSTREAM_DNS = vm.RIGHT_HOST
# Where the policy goes. Not the path the howto names — see the
# friction this walk records about that.
POLICY_PATH = "/etc/f/rules.fw"


class OperatorWalk(fw.Walk):
  """A walk that keeps the friction and the whole transcript.

  The transcript is not a debugging aid. The deliverable is a friction
  list, and a friction item nobody else can check is worth about as
  much as a test with no oracle — so every command and its exact reply
  is kept, and each friction entry names the step it came from.
  """

  def __init__(self, out):
    """Start a walk that writes its evidence under `out`."""
    super().__init__(out)
    self.frictions = []
    self.transcript = []

  def friction(self, phase, title, detail):
    """Record a place the deployment was harder than it should be."""
    self.frictions.append({"phase": phase, "title": title,
                           "detail": detail})
    print(f"[FRICTION] {phase}/{title}: {detail}", flush=True)
    return False

  def save(self):
    """Write the evidence out and return the counts."""
    counts = {}
    for entry in self.checks:
      counts[entry["verdict"]] = counts.get(entry["verdict"], 0) + 1
    counts["FRICTION"] = len(self.frictions)
    (self.out / "operator-walk.json").write_text(
      json.dumps({"checks": self.checks, "facts": self.facts,
                  "frictions": self.frictions,
                  "transcript": self.transcript,
                  "counts": counts}, indent=2), encoding="utf-8")
    return counts


def indent(text):
  """Indent a captured reply so the transcript reads as one."""
  lines = (text or "(no output)").splitlines() or ["(no output)"]
  return "\n".join("    " + line for line in lines)


def cli(walk, key, phase, command, timeout=240):
  """Run one `einheit-f` verb on the box and keep the whole reply."""
  return box(walk, key, phase, f"einheit-f {command}", timeout)


def box(walk, key, phase, command, timeout=240):
  """Run a command on the box and keep the whole reply."""
  rc, out, err = fw.sh(key, command, timeout=timeout)
  walk.transcript.append({"phase": phase, "command": command,
                          "rc": rc, "stdout": out, "stderr": err})
  print(f"  $ {command}\n{indent(out or err)}", flush=True)
  return rc, out, err


# --- the bench's outside world ---------------------------------------


def start_upstream_dns():
  """Run a resolver on the far host, for `far.test` and nothing else.

  Returns:
    The Popen, for the caller to terminate.
  """
  return subprocess.Popen(
    ["sudo", "ip", "netns", "exec", vm.RIGHT_NS,
     "dnsmasq", "--keep-in-foreground", "--no-hosts", "--no-resolv",
     f"--listen-address={vm.RIGHT_HOST}", "--bind-interfaces",
     "--port=53", f"--address=/{TEST_NAME}/{vm.RIGHT_HOST}",
     "--log-facility=-", "--pid-file="],
    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def take_a_lease(walk, phase):
  """Drop the inside host's static address and take a DHCP lease.

  The operator's own first test of a new bench segment, and the one
  that fails most informatively. `masquerade` is unconditional, so a
  policy missing its terminal `allow` above the rewrite translates the
  client's DISCOVER to the uplink address and broadcasts it onto the
  office network rather than answering it.

  Returns:
    The address the client ended up with, or "".
  """
  vm.ns_run(vm.LEFT_NS, f"ip addr flush dev {vm.LEFT_VETH}n")
  proc = subprocess.run(
    ["sudo", "ip", "netns", "exec", vm.LEFT_NS,
     "busybox", "udhcpc", "-i", f"{vm.LEFT_VETH}n", "-n", "-q",
     "-t", "8", "-T", "5", "-s", "/bin/true", "-f"],
    capture_output=True, text=True, timeout=180, check=False)
  walk.fact(phase, "udhcpc", (proc.stdout + proc.stderr).strip())
  got = vm.ns_run(vm.LEFT_NS, f"ip -4 -br addr show {vm.LEFT_VETH}n")
  for word in got.stdout.split():
    if word.startswith("10.10.1."):
      return word.split("/")[0]
  return ""


def restore_static_inside():
  """Put the inside host back where every other probe expects it.

  The lease is the measurement; the static address is what the rest of
  this file and all of `firstboot_walk.py` is written against. Leaving
  the bench in whichever the last phase happened to use is how a suite
  starts depending on its own order.
  """
  vm.ns_run(vm.LEFT_NS, f"ip addr flush dev {vm.LEFT_VETH}n")
  vm.ns_run(vm.LEFT_NS,
            f"ip addr add {vm.LEFT_HOST}/24 dev {vm.LEFT_VETH}n")
  vm.ns_run(vm.LEFT_NS, f"ip route add default via {vm.LAN_BOX}")


def resolve_a_name(walk, phase):
  """Ask the box to resolve a name only the far side knows.

  Returns:
    The answer, or "".
  """
  proc = vm.ns_run(
    vm.LEFT_NS,
    f"dig +time=5 +tries=2 +short @{vm.LAN_BOX} {TEST_NAME}",
    timeout=60)
  answer = proc.stdout.strip()
  walk.fact(phase, "dns", {"stdout": answer,
                           "stderr": proc.stderr.strip()})
  return answer


def reach_the_far_side(walk, phase, expect=True, source=None):
  """Open a real TCP flow from the inside to the far side.

  Returns:
    The peer address the far side reported, or "".
  """
  server = fw.listen(vm.RIGHT_NS)
  time.sleep(2)
  client = fw.connect(vm.LEFT_NS, vm.RIGHT_HOST)
  try:
    stdout, _ = server.communicate(timeout=45)
  except subprocess.TimeoutExpired:
    server.kill()
    stdout = ""
  accepted = stdout.startswith("PEER")
  peer = stdout.split()[1] if accepted else ""
  walk.fact(phase, "far_side", {"client": client.stdout.strip(),
                                "server": stdout.strip(),
                                "inside_source": source or ""})
  saw = f"accepted a flow from {peer}" if accepted else "saw nobody"
  walk.check(
    phase, "reaches-the-far-side", accepted == expect,
    f"the far side {saw}; "
    f"expected {'a flow' if expect else 'nothing'}")
  if accepted and expect:
    walk.check(
      phase, "masqueraded", peer == vm.WAN_BOX,
      f"the far side's own kernel reports the peer as {peer}; this "
      f"box's uplink address is {vm.WAN_BOX}")
  return peer


def forwarding_row(walk, key, phase):
  """Read the knob and the status row that should explain it."""
  _, live, _ = box(walk, key, phase,
                   "cat /proc/sys/net/ipv4/ip_forward")
  _, row, _ = box(walk, key, phase,
                  "fctl status 2>/dev/null | grep -i forwarding "
                  "|| true")
  walk.fact(phase, "forwarding", {"ip_forward": live.strip(),
                                  "status_row": row.strip()})
  return live.strip(), row.strip()


# --- the policy the howto tells you to write -------------------------


def gateway_policy():
  """The office shape, from the howto, with this bench's addresses.

  Section 1 is the part that is easy to get wrong and impossible to
  diagnose from the wire: `masquerade` and `redirect` are
  unconditional, so without a terminal `allow` above them a client's
  DHCP DISCOVER is translated to the uplink address and broadcast onto
  the outside network, and this box's own DHCP server never sees it.
  """
  return f"""zone wan = [enp0s4]
zone lan = [enp0s3]

@xdp(lan)
# 1. Traffic addressed to this box is for this box, and must be
#    delivered locally BEFORE the rewrite below. DHCP by port,
#    because a client with no lease cannot address us.
allow if pkt.proto == udp and pkt.dst_port == 67
allow if pkt.dst_ip == {vm.LAN_BOX}

# 2. The bench's own broadcast and multicast stay on the bench.
drop if pkt.dst_ip in 224.0.0.0/4
drop if pkt.dst_ip == 255.255.255.255
drop if pkt.dst_ip == 10.10.1.255

# 3. Everything else goes out hidden behind the uplink address.
masquerade
redirect to wan

@xdp(wan)
# Only answers to conversations the bench started. `related` admits
# the ICMP errors those conversations provoke; without it large
# transfers hang.
allow if conntrack(pkt).state in [established, related]
default drop
"""


# --- the phases ------------------------------------------------------


def phase_firstboot(out, walk):
  """A fresh image, told nothing, booted once."""
  proc, key = fw.start_box(out, walk, "firstboot")
  if proc is None:
    return None, key
  fw.wait_for_firstboot(key, walk, "firstboot")
  fw.collect_firstboot(key, walk, "firstboot")
  cli(walk, key, "firstboot", "show system")
  cli(walk, key, "firstboot", "show zones")
  live, row = forwarding_row(walk, key, "firstboot")
  # A factory box IS filtering — one zone, every port, `default drop`
  # — so fail-closed says it forwards. Checked because the tempting
  # wrong version of fail-closed is "one zone, nothing to route, keep
  # it shut", which is the derivation that was rejected.
  walk.check("firstboot", "forwarding-follows-the-datapath",
             live == "1",
             f"net.ipv4.ip_forward = {live} on a provisioned box "
             f"whose datapath is armed")
  walk.check("firstboot", "forwarding-is-on-the-status-screen",
             bool(row),
             row or "`fctl status` has no forwarding row at all")
  return proc, key


def phase_configure(walk, key):
  """Zones, ports, addresses and services, through the CLI only."""
  steps = [
    ("set zone lan", "declare the inside zone"),
    ("set zone wan", "declare the uplink zone"),
    ("set interface zone enp0s3 lan", "put the inside port in it"),
    ("set interface zone enp0s4 wan", "put the uplink port in it"),
    (f"set address enp0s3 {vm.LAN_BOX}/24", "address the inside"),
    (f"set address enp0s4 {vm.WAN_BOX}/24", "address the uplink"),
    (f"set dhcp lan {DHCP_FIRST}-{DHCP_LAST}", "serve DHCP inside"),
    (f"set dns lan {UPSTREAM_DNS}", "forward DNS for the inside"),
  ]
  for command, what in steps:
    rc, out, err = cli(walk, key, "configure", command)
    first = ((out or err).splitlines() or ["no reply"])[0]
    walk.check("configure", command.replace(" ", "-"), rc == 0,
               f"{what}: {first}")
  cli(walk, key, "configure", "show system")
  cli(walk, key, "configure", "show services")
  _, yaml, _ = box(walk, key, "configure", "cat /etc/f/system.yaml")
  walk.fact("configure", "system_yaml", yaml)
  # The file is the only place that can say whether all eight verbs
  # did what they claim, rather than the ones whose effect shows up
  # somewhere else as well.
  for want in ("lan", "wan", "enp0s3", "enp0s4", vm.LAN_BOX,
               DHCP_FIRST, UPSTREAM_DNS):
    walk.check("configure", f"model-carries-{want}", want in yaml,
               f"{want} {'is' if want in yaml else 'is NOT'} in "
               f"/etc/f/system.yaml after the verb that set it")


def phase_policy(walk, key):
  """The office-shaped gateway policy, per the howto."""
  policy = gateway_policy()
  walk.fact("policy", "source", policy)
  encoded = policy.replace("'", "'\\''")
  box(walk, key, "policy",
      f"cat > {POLICY_PATH} <<'FWLEOF'\n{policy}FWLEOF")
  _, on_box, _ = box(walk, key, "policy", f"cat {POLICY_PATH}")
  walk.check("policy", "policy-written",
             "redirect to wan" in on_box,
             f"{len(on_box.splitlines())} lines at {POLICY_PATH}")
  del encoded
  rc, out, err = cli(walk, key, "policy", "reload firewall",
                     timeout=600)
  walk.check("policy", "reload-accepted", rc == 0,
             ((out or err).splitlines() or ["no reply"])[-1])
  cli(walk, key, "policy", "show zones")
  cli(walk, key, "policy", "show policy")
  live, row = forwarding_row(walk, key, "policy")
  walk.check("policy", "forwarding-open-after-reload", live == "1",
             f"net.ipv4.ip_forward = {live} with a two-zone gateway "
             f"attached")


def start_bound_services(walk, key, phase):
  """Start the units the service verbs bound but nobody enables.

  `set dhcp` and `set dns` edit the model, regenerate
  `/etc/f/generated/dnsmasq.conf` and report success — and the unit
  that would serve it is not enabled, so nothing on the segment is
  answered. `show services` says so exactly ("STOPPED ... the unit was
  never started"), which is the diagnostics working; what is missing
  is any way to act on it. `systemctl enable --now` appears in
  `deploy/firstboot/firstboot.py` and nowhere else in the tree, so the
  units are planned once at provisioning time and a service bound
  afterwards is never started by anything.

  So this is the walk reaching outside the CLI, deliberately and on
  the record, because an operator following the documentation has no
  other move.
  """
  _, services, _ = cli(walk, key, phase, "show services")
  if "STOPPED" not in services:
    return
  walk.friction(
    phase, "a service bound through the CLI is never started",
    "`set dhcp` and `set dns` succeeded, the model and the generated "
    "dnsmasq.conf carry them, and `show services` reports "
    "`STOPPED — the unit was never started`. There is no verb that "
    "starts it: `systemctl enable --now` occurs only in firstboot.py, "
    "so units are planned once at provisioning time and a service "
    "bound after that is served by nobody. The operator has to know "
    "to run systemctl by hand, which is the reach-for-a-file this "
    "surface exists to remove.")
  box(walk, key, phase, "systemctl enable --now f-dnsmasq")
  state = wait_for_unit(walk, key, phase, "f-dnsmasq.service")
  walk.check(phase, "the-bound-service-can-at-least-be-started",
             state == "active",
             f"f-dnsmasq.service is {state} after enabling it by hand")
  cli(walk, key, phase, "show services")


def phase_traffic(walk, key, phase="traffic"):
  """A client on the inside: a lease, a name, and the far side."""
  start_bound_services(walk, key, phase)
  lease = take_a_lease(walk, phase)
  walk.check(phase, "client-gets-an-address",
             lease.startswith("10.10.1."),
             f"the inside client's own DHCP client ended up with "
             f"{lease or 'no address'} (pool {DHCP_FIRST}-{DHCP_LAST})")
  _, leases, _ = cli(walk, key, phase, "show leases")
  named = bool(lease) and lease in leases
  walk.check(phase, "the-box-can-see-the-client", named,
             f"`show leases` {'names' if named else 'does NOT name'} "
             f"{lease or 'the client'}")
  answer = resolve_a_name(walk, phase)
  walk.check(phase, "client-resolves-a-name",
             answer.strip() == vm.RIGHT_HOST,
             f"{TEST_NAME} resolved to {answer or 'nothing'} through "
             f"{vm.LAN_BOX}; only the far side knows that name")
  reach_the_far_side(walk, phase, expect=True, source=lease)
  cli(walk, key, phase, "show nat")
  cli(walk, key, phase, "show conntrack")
  cli(walk, key, phase, "show counters")
  restore_static_inside()


def wait_for_unit(walk, key, phase, unit, want="active",
                  timeout=180):
  """Block until a unit reaches a state, and say what it reached.

  Returns:
    The state it ended on.
  """
  deadline = time.monotonic() + timeout
  state = "(never answered)"
  while time.monotonic() < deadline:
    _, state, _ = fw.sh(key, f"systemctl is-active {unit} || true")
    state = state.strip()
    if state == want:
      return state
    time.sleep(2)
  return state


def phase_restart(walk, key):
  """`systemctl restart fd` — step one of the recovery procedure."""
  before_live, _ = forwarding_row(walk, key, "restart")
  box(walk, key, "restart", "systemctl restart fd")
  state = wait_for_unit(walk, key, "restart", "fd.service")
  walk.check("restart", "fd-comes-back", state == "active",
             f"fd.service is {state} after a restart")
  after_live, after_row = forwarding_row(walk, key, "restart")
  # The fail-never half at its sharpest. `fd` lowers this knob on the
  # way in and on the way out, so a restart that failed to raise it
  # again would leave a healthy filtering box carrying nothing — and
  # would look exactly like a cable problem.
  walk.check("restart", "forwarding-comes-back-by-itself",
             before_live == "1" and after_live == "1",
             f"net.ipv4.ip_forward was {before_live} before the "
             f"restart and is {after_live} after it, with nobody "
             f"typing anything")
  walk.fact("restart", "status_row_after", after_row)
  reach_the_far_side(walk, "restart", expect=True)


def phase_reboot(out, walk, proc, key):
  """The box comes back carrying traffic with nobody typing.

  Returns:
    The (proc, key) pair to carry on with, or (None, key).
  """
  box(walk, key, "reboot", "systemctl reboot", timeout=30)
  try:
    up = vm.wait_for_ssh(timeout=fw.BOOT_TIMEOUT, proc=proc, key=key)
  except RuntimeError as exc:
    walk.error("reboot", "comes-back", str(exc))
    return None, key
  if up != "ready":
    walk.error("reboot", "comes-back",
               f"the box never ran a command over ssh ({up})")
    return None, key
  walk.check("reboot", "comes-back", True, "the box answers again")
  state = wait_for_unit(walk, key, "reboot", "fd.service")
  walk.check("reboot", "fd-armed-after-cold-boot", state == "active",
             f"fd.service is {state}")
  live, row = forwarding_row(walk, key, "reboot")
  # THE check that fail-closed has not become fail-never. Nothing
  # between the power and this line was typed by anybody: the
  # boot-time drop-in sets the knob to 0, and only a successful attach
  # raises it.
  walk.check("reboot", "forwarding-open-after-cold-boot",
             live == "1",
             f"net.ipv4.ip_forward = {live} after a cold boot with no "
             f"manual intervention; the drop-in on disk says 0")
  walk.fact("reboot", "status_row", row)
  _, dropin, _ = box(walk, key, "reboot",
                     "grep -v '^#' /etc/sysctl.d/10-f-forwarding.conf "
                     "| grep ip_forward")
  walk.check("reboot", "the-floor-on-disk-is-closed",
             "= 0" in dropin,
             f"the boot-time drop-in reads: {dropin.strip()}")
  reach_the_far_side(walk, "reboot", expect=True)
  return proc, key


def phase_commit(walk, key):
  """A policy change, through the candidate and `commit`."""
  # An established flow has to survive it, so open one first and hold
  # it across the reload.
  server = fw.listen(vm.RIGHT_NS)
  time.sleep(2)
  rc, out, err = cli(walk, key, "commit",
                     "set rule lan drop tcp 4444", timeout=600)
  walk.check("commit", "set-rule-accepted", rc == 0,
             ((out or err).splitlines() or ["no reply"])[-1])
  cli(walk, key, "commit", "show policy lan")
  live, row = forwarding_row(walk, key, "commit")
  walk.check("commit", "forwarding-survives-a-reload", live == "1",
             f"net.ipv4.ip_forward = {live} after a hot reload")
  # The reload defect this session found: RouteMgr was attached at
  # cold boot only, so after any reload every routed/bridged number
  # read 0 for the rest of the process's life. The counters have to
  # move again on the far side of a commit.
  server.kill()
  reach_the_far_side(walk, "commit", expect=True)
  _, status, _ = cli(walk, key, "commit", "show status")
  walk.fact("commit", "status_after_reload", status)
  forwards = [ln for ln in status.splitlines()
              if "forwards" in ln.lower()]
  walk.check("commit", "route-counters-live-after-a-reload",
             bool(forwards) and " 0 routed" not in " ".join(forwards),
             " / ".join(forwards) or
             "`show status` has no forwards row after a reload")
  cli(walk, key, "commit", "show counters")


def ssh_answers(key, timeout=20):
  """Whether the box runs a command over ssh right now."""
  proc = vm.ssh(key, "true", timeout=timeout)
  return proc.returncode == 0


def phase_lockout(walk, key):
  """Cut the management path on purpose, and be rescued by the timer.

  The documented safe path for a change that can sever your own
  session is to edit `/etc/f/system.yaml` and run `apply system
  confirmed <minutes>` — the `set` verbs apply on the spot and have no
  window. So that is what this does, off an address the management
  path cannot survive, and the only thing that brings the box back is
  `f-confd` putting the previous revision in place when nobody
  confirms.
  """
  _, before, _ = box(walk, key, "lockout", "cat /etc/f/system.yaml")
  walk.fact("lockout", "system_yaml_before", before)
  cli(walk, key, "lockout", "show commits")
  # Off the management subnet entirely: qemu forwards the ssh port to
  # whatever the guest took by DHCP, so an address outside it is a
  # severed session and not a slow one.
  box(walk, key, "lockout",
      "python3 - <<'PY'\n"
      "import pathlib, re\n"
      "p = pathlib.Path('/etc/f/system.yaml')\n"
      "s = p.read_text()\n"
      "s = s.replace('address: dhcp', 'address: 192.0.2.9/24', 1)\n"
      "p.write_text(s)\n"
      "PY")
  _, after, _ = box(walk, key, "lockout",
                    "grep -n '192.0.2.9' /etc/f/system.yaml || true")
  walk.check("lockout", "the-severing-edit-is-in-the-model",
             "192.0.2.9" in after,
             after.strip() or "the edit did not reach system.yaml")
  # Detached, because the reply to this command travels over the path
  # it is about to cut. A command whose own answer cannot come back is
  # exactly the situation `apply system confirmed` exists for.
  box(walk, key, "lockout",
      "setsid nohup einheit-f apply system confirmed 2 "
      "> /var/tmp/confirmed.log 2>&1 < /dev/null &", timeout=60)
  cut = False
  deadline = time.monotonic() + 180
  while time.monotonic() < deadline:
    if not ssh_answers(key):
      cut = True
      break
    time.sleep(5)
  # A rescue from a session that was never cut proves nothing, so this
  # is a check and not a wait: it is the control for the one below.
  walk.check("lockout", "the-management-path-was-really-cut", cut,
             "ssh stopped answering after the confirmed apply"
             if cut else
             "ssh kept answering; the apply did not sever anything "
             "and the rescue below would be vacuous")
  back = False
  deadline = time.monotonic() + 600
  while time.monotonic() < deadline:
    if ssh_answers(key):
      back = True
      break
    time.sleep(10)
  walk.check("lockout", "commit-confirmed-rescued-it", back,
             "the box answers ssh again without anyone touching it"
             if back else
             "the box never came back within 10 minutes; the revert "
             "did not happen or did not restore the address")
  if not back:
    return
  _, log, _ = box(walk, key, "lockout", "cat /var/tmp/confirmed.log")
  walk.fact("lockout", "confirmed_log", log)
  _, restored, _ = box(walk, key, "lockout",
                       "grep -c '192.0.2.9' /etc/f/system.yaml "
                       "|| true")
  walk.check("lockout", "the-model-went-back-too",
             restored.strip() == "0",
             f"/etc/f/system.yaml mentions 192.0.2.9 "
             f"{restored.strip()} time(s) after the revert; the "
             f"document itself must come back, not just the wire")
  cli(walk, key, "lockout", "show commits")
  live, row = forwarding_row(walk, key, "lockout")
  walk.check("lockout", "forwarding-survived-the-round-trip",
             live == "1",
             f"net.ipv4.ip_forward = {live} after a confirmed apply "
             f"and its revert")
  walk.fact("lockout", "status_row", row)


def build_parser():
  """Construct the argument parser."""
  parser = argparse.ArgumentParser(
    prog="operator_walk.py",
    description="Walk the deployment as an operator would, and count "
                "the friction.")
  parser.add_argument("--rootfs", help="Staged rootfs to prepare from")
  parser.add_argument("--out", required=True, help="Working directory")
  parser.add_argument("--phases", default="all")
  return parser


def main(argv=None):
  """Entry point. Returns a process exit code."""
  args = build_parser().parse_args(argv)
  out = Path(args.out)
  out.mkdir(parents=True, exist_ok=True)
  walk = OperatorWalk(out)
  wanted = (None if args.phases == "all"
            else set(args.phases.split(",")))

  def want(name):
    """Whether this phase was asked for."""
    return wanted is None or name in wanted

  vm.require_tools()
  if args.rootfs:
    key, pub = vm.keypair(out)
    # Same size as firstboot_walk, deliberately: a walk that differs
    # from the other one in a way nobody chose is a difference that
    # will one day explain a result.
    vm.prepare(Path(args.rootfs), out, 6144, pub)
  vm.net_down()
  vm.net_up()
  dns = start_upstream_dns()
  proc = None
  try:
    proc, key = phase_firstboot(out, walk)
    if proc is None:
      return 1
    if want("configure"):
      phase_configure(walk, key)
    if want("policy"):
      phase_policy(walk, key)
    if want("traffic"):
      phase_traffic(walk, key)
    if want("restart"):
      phase_restart(walk, key)
    if want("reboot"):
      proc, key = phase_reboot(out, walk, proc, key)
      if proc is None:
        return 1
    if want("commit"):
      phase_commit(walk, key)
    if want("lockout"):
      phase_lockout(walk, key)
  finally:
    dns.terminate()
    if proc is not None:
      vm.shutdown(proc, key)
    counts = walk.save()
    print(f"\n=== operator walk: {counts} ===")
    for entry in walk.frictions:
      print(f"  FRICTION {entry['phase']}/{entry['title']}")
  return 0 if not counts.get("ERROR") else 1


if __name__ == "__main__":
  raise SystemExit(main())
