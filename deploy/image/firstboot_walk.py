#!/usr/bin/env python3
"""Walk an f appliance image from debootstrap to a box that filters.

`build_image.py` says what an image should contain and `firstboot.py`
says what a new box should become. Neither had ever been run on an
image that booted: the step was recorded as unwalked for want of an
aarch64 board, and `vm.py` removes that reason. This file is the walk
itself, and its shape follows from one finding.

The v0.1 fallback made a box that had lost its bundle come up
attached, READY, green in every operator view, and passing every
packet. `EngineInit` refuses now — and a refusal that is only ever
seen as a log line is the same class of evidence that hid the
original defect for months. So this walk boots the image twice: once
whole, and once with its bundle taken away, and it puts the same
traffic through both.

Four boots, because the questions are different:

  1. factory — no /boot/f-provision.yaml. The shape a board off the
     line comes up in, and where firstboot's own products are checked:
     names pinned to MACs, zones, `default drop`, a compiled bundle
     with `current` on it, and the marker written last.
  2. gateway — a provisioning file with an uplink, so that there is
     traffic to forward and traffic to refuse. Both are measured on
     the wire, from real Linux hosts in namespaces the appliance is
     the only path between.
  3. corrupt — one object in the bundle torn in half. The whole bundle
     must be refused; loading the survivors would be half a firewall.
  4. broken — the same disk with the bundle removed. `fd` must refuse,
     and the traffic the healthy box carried must stop.

The last two boots are the reason for the second. "Nothing was
forwarded" is also what a box that failed to boot produces, so every
check there is paired with a control that must still pass: the box
answers ssh, holds its addresses, and replies on the very wire that
carries nothing across.

WHAT THIS CURRENTLY FINDS, so that a red run is not read as a broken
harness. As of 2026-08-15 boots 3 and 4 end with two red checks each,
and both are real: `fd` refuses exactly as designed and attaches
nothing, and the box forwards anyway. `f-sysconf apply` writes
`net.ipv4.ip_forward = 1` at provisioning time, `systemd-sysctl`
reapplies it every boot, and with connected routes on both zones the
Linux stack carries what XDP is no longer there to stop — including
the unsolicited inbound connection the healthy box refuses with zero
frames on the inside wire. The daemon is fail-closed; the appliance is
not. Recorded in context/image-boot-2026-08-15.md rather than asserted
away here: a check that expected the current behaviour would make the
defect the specification.

Usage:
  deploy/image/firstboot_walk.py --rootfs DIR --out DIR
  deploy/image/firstboot_walk.py --out DIR --phases gateway,broken

Everything it observes goes to <out>/walk.json and to stdout.
"""

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import vm  # noqa: E402

PROBE_PORT = 9000
# Long enough for a first boot that compiles a policy under TCG, where
# clang runs perhaps twenty times slower than on the board.
BOOT_TIMEOUT = 1800
class Walk:
  """The evidence log. Every check is a line, and every line is kept.

  A check that could not be run is `error`, not `fail`: this walk
  exists because a box that could not answer had been read as a box
  that answered fine.
  """

  def __init__(self, out):
    """Start a walk that writes its evidence under `out`."""
    self.out = Path(out)
    self.checks = []
    self.facts = {}

  def check(self, phase, name, ok, detail=""):
    """Record one verdict and print it as it is reached."""
    verdict = "PASS" if ok else "FAIL"
    self.checks.append({"phase": phase, "name": name,
                        "verdict": verdict, "detail": detail})
    print(f"[{verdict}] {phase}/{name}"
          f"{': ' + detail if detail else ''}", flush=True)
    return ok

  def error(self, phase, name, detail):
    """Record a check that could not be put at all."""
    self.checks.append({"phase": phase, "name": name,
                        "verdict": "ERROR", "detail": detail})
    print(f"[ERROR] {phase}/{name}: {detail}", flush=True)
    return False

  def fact(self, phase, name, value):
    """Record something observed that is not itself a verdict."""
    self.facts.setdefault(phase, {})[name] = value
    return value

  def save(self):
    """Write the evidence out and return the counts."""
    counts = {}
    for entry in self.checks:
      counts[entry["verdict"]] = counts.get(entry["verdict"], 0) + 1
    (self.out / "walk.json").write_text(
      json.dumps({"checks": self.checks, "facts": self.facts,
                  "counts": counts}, indent=2), encoding="utf-8")
    return counts
def sh(key, command, timeout=180):
  """Run a command on the box, returning (rc, stdout, stderr)."""
  proc = vm.ssh(key, command, timeout=timeout)
  return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
def mount_rootfs(disk, mountpoint):
  """Mount the disk image so it can be edited between boots."""
  mountpoint.mkdir(parents=True, exist_ok=True)
  vm.run(["sudo", "mount", "-o", "loop", str(disk), str(mountpoint)])
def umount_rootfs(mountpoint):
  """Unmount it again, and make sure the write reached the image."""
  vm.run(["sync"])
  vm.run(["sudo", "umount", str(mountpoint)])
def edit_offline(disk, out, action):
  """Run `action(rootfs_path)` against the powered-off disk image."""
  mountpoint = Path(out) / "mnt"
  mount_rootfs(disk, mountpoint)
  try:
    action(mountpoint)
  finally:
    umount_rootfs(mountpoint)
def start_box(out, walk, phase):
  """Boot the prepared disk and wait for it to answer.

  Returns:
    A (proc, key) pair, or (None, key) when it never came up.
  """
  out = Path(out)
  key, _ = vm.keypair(out)
  console = out / f"console-{phase}.log"
  proc = vm.boot(out / "disk.img", out / "vmlinuz", out / "initrd.img",
                 console)
  try:
    up = vm.wait_for_ssh(timeout=BOOT_TIMEOUT, proc=proc, key=key)
  except RuntimeError as exc:
    walk.error(phase, "boot", str(exc))
    return None, key
  if up != "ready":
    walk.error(phase, "boot",
               f"the box never ran a command over ssh ({up}) in "
               f"{BOOT_TIMEOUT}s; console at {console}")
    proc.kill()
    return None, key
  walk.check(phase, "boot", True,
             f"the box ran a command over ssh; console at {console}")
  return proc, key
def read_properties(key, unit):
  """Read systemd properties, distinguishing "no" from "no answer".

  Returns:
    A dict, or None when the box said nothing at all. A check that
    treats an empty answer as a value is how `fd.service is None`
    came to be recorded as a passing refusal.
  """
  rc, out, _ = sh(key, f"systemctl show {unit} "
                       f"--property=ActiveState --property=SubState "
                       f"--property=Result --property=NRestarts")
  if rc != 0 or not out.strip():
    return None
  fields = dict(line.split("=", 1) for line in out.splitlines()
                if "=" in line)
  return fields or None
def wait_for_firstboot(key, walk, phase, timeout=1800):
  """Block until the provisioner has written its report.

  firstboot runs from a unit, so the box answers ssh while it is still
  working. Reading its products before it has written them is the way
  to get a green run out of a box that was never provisioned.
  """
  deadline = time.monotonic() + timeout
  while time.monotonic() < deadline:
    rc, out, _ = sh(key, "systemctl show f-firstboot.service "
                         "--property=ActiveState --property=Result "
                         "--property=SubState")
    fields = dict(line.split("=", 1) for line in out.splitlines()
                  if "=" in line)
    state = fields.get("ActiveState", "?")
    if rc == 0 and state in ("active", "failed"):
      return walk.fact(phase, "firstboot_unit",
                       f"{state}/{fields.get('SubState')} "
                       f"result={fields.get('Result')}")
    time.sleep(10)
  return walk.error(phase, "firstboot-finished",
                    f"f-firstboot.service was still running after "
                    f"{timeout}s")
def collect_firstboot(key, walk, phase):
  """Read what the provisioner produced, and judge it."""
  rc, report, _ = sh(key, "cat /var/lib/f/firstboot.json")
  if rc != 0:
    return walk.error(phase, "firstboot-report",
                      "no /var/lib/f/firstboot.json")
  doc = json.loads(report)
  walk.fact(phase, "firstboot_steps",
            [(s["name"], s["outcome"], s["detail"]) for s in
             doc["steps"]])
  walk.check(phase, "firstboot-provisioned", doc["provisioned"],
             "steps: " + ", ".join(
               f"{s['name']}={s['outcome']}" for s in doc["steps"]))

  # system.yaml, and the MAC pin that makes a name mean a port.
  rc, model_text, _ = sh(key, "cat /etc/f/system.yaml")
  if rc != 0:
    walk.error(phase, "system-yaml", "not written")
  else:
    walk.fact(phase, "system_yaml", model_text)
    macs = re.findall(r'^\s+mac:\s*"?([0-9a-fA-F:]{17})"?',
                      model_text, re.M)
    walk.check(phase, "interfaces-pinned-to-mac",
               len(macs) >= 1 and all(m for m in macs),
               f"{len(macs)} interface(s) carry a MAC: "
               f"{', '.join(macs)}")

  rc, links, _ = sh(key, "ls /etc/systemd/network/")
  walk.fact(phase, "networkd_units", links)
  walk.check(phase, "networkd-link-units", ".link" in links,
             f"/etc/systemd/network: {links.split() or 'empty'}")

  # The starting policy. `default drop`, and nothing that says allow.
  rc, rules, _ = sh(key, "cat /etc/f/rules.fw")
  if rc != 0:
    walk.error(phase, "policy", "no /etc/f/rules.fw")
  else:
    walk.fact(phase, "rules_fw", rules)
    blocks = rules.count("@xdp(")
    drops = len(re.findall(r"^default drop\s*$", rules, re.M))
    allows = len(re.findall(r"^default allow\s*$", rules, re.M))
    walk.check(phase, "policy-default-drop",
               blocks > 0 and drops == blocks and allows == 0,
               f"{blocks} @xdp block(s), {drops} `default drop`, "
               f"{allows} `default allow`")

  # The bundle, and `current` on it.
  rc, link, _ = sh(key, "readlink /usr/share/f/compiled/current")
  walk.check(phase, "bundle-current-linked",
             rc == 0 and link.startswith("v-"),
             f"current -> {link or '(nothing)'}")
  rc, objs, _ = sh(key, "ls /usr/share/f/compiled/current/")
  walk.fact(phase, "bundle_contents", objs)
  walk.check(phase, "bundle-has-objects",
             "manifest.json" in objs and ".bpf.o" in objs,
             f"bundle holds: {' '.join(objs.split())}")
  return doc
def check_marker_last(key, walk, phase):
  """The marker must be newer than everything the run produced.

  It means "this box is what firstboot makes". Written before the last
  step, it would make a half-provisioned box skip the repair on every
  later boot — so the ordering is the property, not the file.
  """
  paths = ["/etc/f/system.yaml", "/etc/f/rules.fw",
           "/usr/share/f/compiled/current",
           "/var/lib/f/firstboot.json", "/etc/f/.provisioned"]
  rc, out, err = sh(key, "stat -c '%n %.9Y' " + " ".join(paths))
  if rc != 0:
    return walk.error(phase, "marker-written-last", err or "stat failed")
  times = {}
  for line in out.splitlines():
    name, _, stamp = line.rpartition(" ")
    times[name] = float(stamp)
  marker = times.get("/etc/f/.provisioned")
  if marker is None:
    return walk.error(phase, "marker-written-last", "no marker")
  others = {k: v for k, v in times.items() if k != "/etc/f/.provisioned"}
  latest = max(others, key=others.get)
  return walk.check(
    phase, "marker-written-last", all(marker >= v for v in
                                      others.values()),
    f"marker {marker:.3f}; newest artifact before it {latest} "
    f"{others[latest]:.3f}")
def check_services(key, walk, phase, model_binds_services=False):
  """Every unit firstboot planned is running, and no others are on."""
  always = ["fd.service", "f-confd.service", "einheit-f-ui.service"]
  bound = ["f-dnsmasq.service", "f-chrony.service"]
  states = {}
  for unit in always + bound:
    _, out, _ = sh(key, f"systemctl show {unit} "
                        f"--property=ActiveState --property=SubState "
                        f"--property=UnitFileState "
                        f"--property=NRestarts")
    states[unit] = dict(line.split("=", 1) for line in out.splitlines()
                        if "=" in line)
  walk.fact(phase, "units", states)
  for unit in always:
    walk.check(phase, f"unit-{unit}",
               states[unit].get("ActiveState") == "active"
               and states[unit].get("SubState") != "auto-restart",
               f"{states[unit].get('ActiveState')}/"
               f"{states[unit].get('SubState')}, "
               f"{states[unit].get('NRestarts')} restart(s)")
  if not model_binds_services:
    for unit in bound:
      walk.check(phase, f"unit-{unit}-not-enabled",
                 states[unit].get("UnitFileState") != "enabled",
                 f"UnitFileState={states[unit].get('UnitFileState')} "
                 f"(no zone binds dhcp, dns or ntp)")
  return states
def check_install_verify(key, walk, phase):
  """`f-install verify` on the booted box, exit code and all."""
  proc = vm.ssh(key, "f-install verify --format json", timeout=180)
  try:
    report = json.loads(proc.stdout)
  except ValueError:
    return walk.error(phase, "f-install-verify",
                      f"no report; rc={proc.returncode} "
                      f"{proc.stderr.strip()[:200]}")
  walk.fact(phase, "verify_verdict", report["verdict"])
  bad = [i for i in report["items"]
         if i["state"] not in ("present", "not-checked")]
  walk.fact(phase, "verify_not_present",
            [(i["id"], i["state"], i["detail"]) for i in bad])
  return walk.check(
    phase, "f-install-verify",
    report["verdict"] == "complete" and proc.returncode == 0,
    f"verdict={report['verdict']} rc={proc.returncode}, "
    f"{len(report['items'])} items, "
    f"{len(bad)} not present"
    + ("" if not bad else ": " + ", ".join(
      f"{i['id']}={i['state']}" for i in bad)))
def listen(ns, port=PROBE_PORT):
  """Start a one-shot TCP listener in a namespace.

  It prints the peer address it was reached from, which is the only
  thing that can tell a masqueraded arrival from a plain one — and it
  is a real socket on a real stack, not a sniffer that would count a
  frame no host accepted.
  """
  program = (
    "import socket,sys\n"
    "s=socket.socket()\n"
    "s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n"
    f"s.bind(('0.0.0.0',{port}))\n"
    "s.listen(1)\n"
    "s.settimeout(30)\n"
    "try:\n"
    "  c,a=s.accept()\n"
    "except OSError:\n"
    "  print('NOBODY'); sys.exit(0)\n"
    "print('PEER',a[0])\n"
    "c.sendall(b'f-appliance\\n')\n"
    "c.close()\n")
  return subprocess.Popen(
    ["sudo", "ip", "netns", "exec", ns, "python3", "-c", program],
    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
def connect(ns, host, port=PROBE_PORT, timeout=8):
  """Try to complete a TCP exchange from a namespace."""
  program = (
    "import socket,sys\n"
    "try:\n"
    f"  s=socket.create_connection(('{host}',{port}),{timeout})\n"
    "except OSError as e:\n"
    "  print('REFUSED',e); sys.exit(1)\n"
    "print('OPEN',s.recv(32).decode().strip())\n")
  return subprocess.run(
    ["sudo", "ip", "netns", "exec", ns, "python3", "-c", program],
    capture_output=True, text=True, timeout=timeout + 20)
def sniff(ns, iface, expr, seconds=12):
  """Count frames matching an expression on a namespace's own wire.

  A sniffer cannot prove delivery — that is what the listener is for —
  but it is exactly the right instrument for the opposite claim. When
  the far side reports nothing, this says whether nothing arrived or
  whether something arrived and was refused.
  """
  proc = subprocess.Popen(
    ["sudo", "ip", "netns", "exec", ns, "tcpdump", "-l", "-n",
     "-i", iface, "-c", "50", expr],
    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
  return proc
def warm_neighbours(key, walk, phase):
  """Resolve both next hops from the box before measuring anything.

  A redirect whose next hop has no neighbour entry is handed to the
  stack so it can ARP, and a source-translated packet does not survive
  that trip: its source is one of our own addresses and
  `fib_validate_source` rejects it as a martian. On a box one minute
  old that is every first flow — the first run of these probes failed
  with `route.no_neigh` going 0 -> 7 for exactly that reason.

  It runs identically in every phase, so it cannot be the difference
  between them.
  """
  rc, out, _ = sh(key, f"ping -c 2 -W 3 {vm.LEFT_HOST} >/dev/null; "
                       f"ping -c 2 -W 3 {vm.RIGHT_HOST} >/dev/null; "
                       f"ip neigh | grep -c REACHABLE")
  return walk.fact(phase, "neighbours_resolved",
                   out if rc == 0 else "none")
def wire_probe(walk, phase, expect_forward):
  """Put the same traffic through the box and report what happened.

  Args:
    expect_forward: Whether a flow the inside starts should reach the
      far side. True while a bundle is loaded, False when `fd` has
      refused one — an appliance whose datapath is down should not be
      carrying traffic. The unsolicited inbound probe expects the same
      answer in every phase, because there is no state of this box in
      which it should be delivered.
  """
  # Control first. If this fails, nothing below means anything: the
  # wire is dead and every negative result has a second explanation.
  ping = vm.ns_run(vm.LEFT_NS, f"ping -c 3 -W 3 {vm.LAN_BOX}")
  alive = walk.check(
    phase, "control-box-answers-on-lan", ping.returncode == 0,
    (ping.stdout.strip().splitlines() or ["no output"])[-1])

  # Outbound: a flow the inside starts. The listener's own report of
  # the peer address is the masquerade evidence.
  server = listen(vm.RIGHT_NS)
  time.sleep(2)
  client = connect(vm.LEFT_NS, vm.RIGHT_HOST)
  try:
    stdout, _ = server.communicate(timeout=45)
  except subprocess.TimeoutExpired:
    server.kill()
    stdout = ""
  accepted = stdout.startswith("PEER")
  peer = stdout.split()[1] if accepted else "(nobody)"
  walk.fact(phase, "outbound", {"client": client.stdout.strip(),
                                "server": stdout.strip()})
  walk.check(
    phase, "outbound-forwarded",
    accepted == expect_forward,
    f"far side saw {peer}; client said "
    f"{client.stdout.strip() or client.stderr.strip()[:80]} "
    f"(expected {'a completed flow' if expect_forward else 'nothing'})")
  if accepted and expect_forward:
    walk.check(phase, "outbound-masqueraded", peer == vm.WAN_BOX,
               f"the far side's own kernel reports the peer as {peer}; "
               f"the appliance's uplink address is {vm.WAN_BOX}")

  # Inbound: unsolicited, from the uplink side towards a host behind
  # the box. This is the packet a permissive box passes.
  inside = listen(vm.LEFT_NS)
  watcher = sniff(vm.LEFT_NS, f"{vm.LEFT_VETH}n",
                  f"tcp and dst port {PROBE_PORT}")
  time.sleep(2)
  intruder = connect(vm.RIGHT_NS, vm.LEFT_HOST)
  try:
    stdout, _ = inside.communicate(timeout=45)
  except subprocess.TimeoutExpired:
    inside.kill()
    stdout = ""
  time.sleep(2)
  watcher.terminate()
  frames = watcher.stdout.read()
  arrived = len([ln for ln in frames.splitlines() if "IP" in ln])
  delivered = stdout.startswith("PEER")
  walk.fact(phase, "inbound", {"client": intruder.stdout.strip(),
                               "server": stdout.strip(),
                               "frames_on_inside_wire": arrived})
  walk.check(
    phase, "inbound-unsolicited-refused", not delivered,
    f"the inside host {'ACCEPTED' if delivered else 'saw no'} "
    f"connection; {arrived} matching frame(s) reached the inside wire")
  return alive
def phase_factory(out, walk):
  """Boot 1: the shape a board comes up in with nothing told to it."""
  proc, key = start_box(out, walk, "factory")
  if proc is None:
    return None, key, None
  wait_for_firstboot(key, walk, "factory")
  collect_firstboot(key, walk, "factory")
  check_marker_last(key, walk, "factory")
  check_services(key, walk, "factory")
  check_install_verify(key, walk, "factory")
  _, ports, _ = sh(key, "for d in /sys/class/net/*; do "
                        "[ -e $d/device ] || continue; "
                        "echo $(basename $d) $(cat $d/address); done")
  walk.fact("factory", "ports", ports)
  vm.shutdown(proc, key)
  return proc, key, dict(
    line.split() for line in ports.splitlines() if line.split())
def provision_document(ports):
  """The gateway model, keyed by the names this box actually has.

  Written from the MACs the harness gave qemu rather than from a
  guess: an interface block naming a port that is not there is a box
  with no address on the wire the test runs over, and the failure
  would look like a policy result.

  TWO zones, and the management port shares the inside one rather than
  holding a third — a property of this bench (three NICs, one of them
  the management path) and no longer of the product. `render_policy`
  gives every non-uplink zone `masquerade` + `redirect to <uplink>`,
  so a third zone means two zones declaring `fwl_devmap_wan`, and
  while devmaps were pinned by name no such bundle loaded: the kernel
  forces BPF_F_RDONLY_PROG in `dev_map_alloc`, so libbpf's pin-reuse
  check compared the declared 0 against the pinned 128 and refused.
  Devmaps are not pinned any more, and a three-zone gateway loads,
  attaches and forwards from both inside zones
  (`fwl/tests/system/three_zone_gateway_netns.py`). Giving this walk a
  fourth NIC and a third zone is the remaining piece, and it is a
  change to `vm.py`, not to the firewall.
  """
  by_mac = {mac: name for name, mac in ports.items()}
  return {
    "hostname": "f-vm",
    "system": {
      "zones": {"lan": {"ipv6": "off"},
                "wan": {"ipv6": "off"}},
      "interfaces": {
        by_mac[vm.MGMT_MAC]: {"mac": vm.MGMT_MAC,
                              "address": "10.0.2.15/24",
                              "zone": "lan"},
        by_mac[vm.LAN_MAC]: {"mac": vm.LAN_MAC,
                             "address": f"{vm.LAN_BOX}/24",
                             "zone": "lan"},
        by_mac[vm.WAN_MAC]: {"mac": vm.WAN_MAC,
                             "address": f"{vm.WAN_BOX}/24",
                             "zone": "wan"},
      },
      "services": {},
    },
    "policy": {"uplink_zone": "wan", "management_ports": [22, 443]},
  }
def reset_for_reprovision(out, ports):
  """Put the box back to unprovisioned, with a model to provision to.

  Everything firstboot writes is removed, including the marker, which
  is what makes the next boot a first boot again.
  """
  import yaml
  document = provision_document(ports)

  def action(rootfs):
    """Write the provisioning file and clear the previous run."""
    text = yaml.safe_dump(document, sort_keys=False)
    vm.run(["sudo", "tee", str(rootfs / "boot/f-provision.yaml")],
           input=text.encode(), stdout=subprocess.DEVNULL)
    for path in ("etc/f/.provisioned", "etc/f/system.yaml",
                 "etc/f/rules.fw", "var/lib/f/firstboot.json"):
      vm.run(["sudo", "rm", "-f", str(rootfs / path)])
    vm.run(["sudo", "bash", "-c",
            f"rm -rf {rootfs}/usr/share/f/compiled/* "
            f"{rootfs}/etc/systemd/network/10-f-*"])
  edit_offline(Path(out) / "disk.img", out, action)
  return document
def phase_gateway(out, walk, ports):
  """Boot 2: a real gateway, and traffic through it both ways."""
  document = reset_for_reprovision(out, ports)
  walk.fact("gateway", "provision_file", document)
  proc, key = start_box(out, walk, "gateway")
  if proc is None:
    return None, key
  wait_for_firstboot(key, walk, "gateway")
  collect_firstboot(key, walk, "gateway")
  check_marker_last(key, walk, "gateway")
  check_services(key, walk, "gateway")
  check_install_verify(key, walk, "gateway")
  _, status, _ = sh(key, "fctl status || true")
  walk.fact("gateway", "fctl_status", status)
  _, addrs, _ = sh(key, "ip -br addr")
  walk.fact("gateway", "addresses", addrs)
  _, fwd, _ = sh(key, "cat /proc/sys/net/ipv4/ip_forward")
  walk.fact("gateway", "ip_forward", fwd)
  warm_neighbours(key, walk, "gateway")
  wire_probe(walk, "gateway", expect_forward=True)
  vm.shutdown(proc, key)
  return proc, key
def truncate_one_object(out):
  """Leave the bundle in place and tear one object in half.

  A different refusal from a missing bundle, and worth its own boot:
  `IsMultiZoneBundle` is satisfied, the manifest parses, and the
  failure happens inside `LoadZoneBundle`. The property being checked
  is that the WHOLE bundle is refused — loading the objects that
  survived would leave one zone protected and one not, which is the
  half-a-firewall failure that reads as a working box.

  Returns:
    The name of the object that was truncated.
  """
  torn = []

  def action(rootfs):
    """Cut the first zone object down to 64 bytes."""
    current = rootfs / "usr/share/f/compiled/current"
    listing = subprocess.run(
      ["sudo", "bash", "-c",
       f"ls {current}/*.bpf.o | grep -v fwl_egress | head -1"],
      capture_output=True, text=True)
    target = listing.stdout.strip()
    if not target:
      return
    vm.run(["sudo", "truncate", "-s", "64", target])
    torn.append(target)
  edit_offline(Path(out) / "disk.img", out, action)
  return torn[0] if torn else ""
def phase_corrupt(out, walk):
  """Boot 3: the bundle is there and one object in it is torn."""
  torn = truncate_one_object(out)
  if not torn:
    return walk.error("corrupt", "truncate", "no object to tear"), None
  walk.fact("corrupt", "truncated", torn)
  proc, key = start_box(out, walk, "corrupt")
  if proc is None:
    return None, key
  rc, running, _ = sh(key, "systemctl is-system-running || true")
  walk.check("corrupt", "control-box-is-up",
             rc == 0 and running.strip() in ("running", "degraded"),
             f"systemctl is-system-running: {running.strip()}")
  fields = read_properties(key, "fd.service")
  if fields is None:
    walk.error("corrupt", "fd-refuses-to-start",
               "the box did not answer; nothing was measured")
  else:
    walk.check("corrupt", "fd-refuses-to-start",
               fields.get("ActiveState") != "active",
               f"fd.service is {fields.get('ActiveState')}, "
               f"result={fields.get('Result')}")
  _, log, _ = sh(key, "journalctl -u fd.service --no-pager "
                      "| grep 'Init failed' | tail -1")
  walk.fact("corrupt", "fd_journal", log)
  rc, attached, _ = sh(key, "ip -d link show | grep -c 'prog/xdp' "
                            "|| true")
  walk.check("corrupt", "whole-bundle-refused",
             rc == 0 and attached.strip() == "0",
             f"{attached.strip()} interface(s) carry an XDP program; "
             f"one intact object loaded would be half a firewall")
  warm_neighbours(key, walk, "corrupt")
  wire_probe(walk, "corrupt", expect_forward=False)
  vm.shutdown(proc, key)
  return proc, key
def break_bundle(out):
  """Take the compiled bundle away from a provisioned box.

  This is the failure an operator meets, reproduced exactly: a box
  that WAS provisioned, whose marker is in place so firstboot will not
  run again, and whose `current` has gone. Deleting the bundle before
  the first boot would only be a box firstboot has not reached yet.

  Returns:
    What was removed, for the record.
  """
  removed = []

  def action(rootfs):
    """Remove `current` and every bundle it could point at."""
    compiled = rootfs / "usr/share/f/compiled"
    listing = subprocess.run(["sudo", "ls", "-la", str(compiled)],
                             capture_output=True, text=True)
    removed.append(listing.stdout)
    vm.run(["sudo", "bash", "-c", f"rm -rf {compiled}/*"])
  edit_offline(Path(out) / "disk.img", out, action)
  return removed
def phase_broken(out, walk):
  """Boot 3: the same box, minus its bundle. It must not come up."""
  before = break_bundle(out)
  walk.fact("broken", "compiled_before_removal", before)
  proc, key = start_box(out, walk, "broken")
  if proc is None:
    return None, key

  # The box is alive. Without this every result below has a second
  # explanation, and "an image that failed to boot" produces the same
  # silence on the wire as an appliance that is refusing correctly.
  rc, uptime, _ = sh(key, "uptime -p; systemctl is-system-running "
                          "|| true")
  walk.check("broken", "control-box-is-up", rc == 0,
             uptime.replace("\n", "; "))
  rc, addrs, _ = sh(key, "ip -br addr")
  walk.fact("broken", "addresses", addrs)
  held = [a for a in (vm.LAN_BOX, vm.WAN_BOX) if a in addrs]
  walk.check("broken", "control-addresses-held", len(held) == 2,
             f"of {vm.LAN_BOX} and {vm.WAN_BOX} the box holds: "
             f"{', '.join(held) or 'neither'}")

  fields = read_properties(key, "fd.service")
  walk.fact("broken", "fd_unit", fields)
  if fields is None:
    walk.error("broken", "fd-refuses-to-start",
               "the box did not answer; nothing was measured")
  else:
    walk.check(
      "broken", "fd-refuses-to-start",
      fields.get("ActiveState") != "active",
      f"fd.service is {fields.get('ActiveState')}/"
      f"{fields.get('SubState')}, result={fields.get('Result')}, "
      f"{fields.get('NRestarts')} restart(s)")

  # The daemon's own line, not systemd's. `journalctl | tail -1` is
  # "Failed to start fd.service", which every failure produces and
  # which names nothing an operator can act on.
  _, log, _ = sh(key, "journalctl -u fd.service --no-pager "
                      "| grep 'Init failed' | tail -1")
  walk.fact("broken", "fd_journal", log)
  walk.check("broken", "fd-says-why",
             "Init failed" in log and "/usr/share/f/compiled" in log,
             log[:200] or "(fd never said why)")

  # `prog/xdp`, not `xdp`: the flag word appears on the link line of
  # every interface that has ever carried a program, and counting that
  # would report a datapath on a box with none.
  rc, attached, _ = sh(key, "ip -d link show | grep -c 'prog/xdp' "
                            "|| true")
  walk.check("broken", "no-xdp-attached",
             rc == 0 and attached.strip() == "0",
             f"{attached.strip()} interface(s) carry an XDP program")

  warm_neighbours(key, walk, "broken")
  wire_probe(walk, "broken", expect_forward=False)
  vm.shutdown(proc, key)
  return proc, key
def build_parser():
  """Construct the argument parser."""
  parser = argparse.ArgumentParser(
    prog="firstboot_walk.py",
    description="Boot an f image and check what firstboot made.")
  parser.add_argument("--rootfs", help="Staged rootfs to prepare from")
  parser.add_argument("--out", required=True, help="Working directory")
  parser.add_argument("--phases",
                      default="factory,gateway,corrupt,broken")
  parser.add_argument("--keep-net", action="store_true",
                      help="Do not tear the bench fabric down at the "
                           "end")
  return parser
def main(argv=None):
  """Entry point. Returns a process exit code."""
  args = build_parser().parse_args(argv)
  out = Path(args.out)
  out.mkdir(parents=True, exist_ok=True)
  phases = [p.strip() for p in args.phases.split(",") if p.strip()]
  walk = Walk(out)
  vm.require_tools()
  if args.rootfs:
    key, pub = vm.keypair(out)
    vm.prepare(Path(args.rootfs), out, 6144, pub)
  vm.net_down()
  vm.net_up()
  ports = None
  try:
    if "factory" in phases:
      _, _, ports = phase_factory(out, walk)
    if "gateway" in phases:
      if ports is None:
        ports = json.loads((out / "ports.json").read_text())
      else:
        (out / "ports.json").write_text(json.dumps(ports))
      phase_gateway(out, walk, ports)
    # Corrupt before broken, because tearing an object needs one to be
    # there and removing the bundle takes them all.
    if "corrupt" in phases:
      phase_corrupt(out, walk)
    if "broken" in phases:
      phase_broken(out, walk)
  finally:
    counts = walk.save()
    if not args.keep_net:
      vm.net_down()
  print("\n=== " + ", ".join(f"{k}: {v}" for k, v in
                             sorted(counts.items())) + " ===")
  print(f"evidence: {out / 'walk.json'}")
  return 0 if counts.get("FAIL", 0) == 0 and counts.get(
    "ERROR", 0) == 0 else 1
if __name__ == "__main__":
  sys.exit(main())
