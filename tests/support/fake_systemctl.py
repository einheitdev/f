#!/usr/bin/env python3
"""A systemctl that keeps a unit table in a file, so a test can prove a
transition.

The point of this fixture is what it refuses to be: a stub that answers
the same thing before and after the command under test. `show` reads
the table, `enable`/`start`/`restart`/`disable`/`stop` write it, and a
unit can be told in advance to fail on start, to crash-loop, or not to
exist at all. A test that starts from `active` and ends at `active` has
proved nothing about the code that was supposed to start it, so the
table starts wherever the test puts it and every verb moves it.

The table lives at $FAKE_SYSTEMCTL_STATE, a JSON object of

    {"<unit>": {"load": "loaded", "active": "inactive",
                "sub": "dead", "result": "success",
                "enabled": "disabled", "restarts": 0,
                "on_start": "ok"}}

`on_start` is the fixture's only cheat and it is a property of the
imaginary box, not of the code under test:

  ok            start succeeds
  fail          start fails; the unit ends `failed`
  crashloop     start "succeeds" and systemd is already restarting it,
                which reports `activating (auto-restart)` — the shape
                that reads as progress and is not
  missing        the unit file does not exist; `show` says
                LoadState=not-found, the way systemd does

A unit not named in the table is `not-found`, which is the honest
default: an appliance is not obliged to have every unit installed.
"""
import json
import os
import pathlib
import sys

DEFAULTS = {
  "load": "loaded",
  "active": "inactive",
  "sub": "dead",
  "result": "success",
  "enabled": "disabled",
  "restarts": 0,
  "on_start": "ok",
}

def state_path():
  """Where the unit table lives."""
  path = os.environ.get("FAKE_SYSTEMCTL_STATE")
  if not path:
    sys.stderr.write("FAKE_SYSTEMCTL_STATE is not set\n")
    sys.exit(2)
  return pathlib.Path(path)

def load():
  """The whole unit table."""
  path = state_path()
  if not path.exists():
    return {}
  return json.loads(path.read_text(encoding="utf-8"))

def save(table):
  """Write the table back."""
  state_path().write_text(json.dumps(table, indent=2),
                          encoding="utf-8")

def unit_of(table, name):
  """One unit's record, with defaults filled in."""
  rec = dict(DEFAULTS)
  rec.update(table.get(name) or {})
  if name not in table:
    rec["load"] = "not-found"
  if rec.get("on_start") == "missing":
    rec["load"] = "not-found"
  return rec

def do_show(table, name, args):
  """Print the requested properties, systemd's `key=value` per line."""
  rec = unit_of(table, name)
  wanted = [a[len("--property="):] for a in args
            if a.startswith("--property=")]
  values = {
    "ActiveState": rec["active"],
    "SubState": rec["sub"],
    "Result": rec["result"],
    "LoadState": rec["load"],
    "UnitFileState": "" if rec["load"] == "not-found"
                     else rec["enabled"],
    "NRestarts": str(rec["restarts"]),
    "MainPID": "0",
  }
  for key in (wanted or list(values)):
    print(f"{key}={values.get(key, '')}")
  return 0

def start(rec):
  """Move a unit to whatever starting it produces on this box."""
  how = rec.get("on_start", "ok")
  if how == "fail":
    rec.update(active="failed", sub="failed", result="exit-code")
    return 1
  if how == "crashloop":
    # systemd reports the gap between restarts as `activating`, which
    # is the same ActiveState a healthy first start reports. The
    # SubState is the only thing that tells them apart at restart zero.
    rec.update(active="activating", sub="auto-restart",
               result="exit-code", restarts=rec["restarts"] + 1)
    return 0
  rec.update(active="active", sub="running", result="success")
  return 0

def main(argv):
  """Dispatch one systemctl invocation."""
  if not argv:
    return 1
  verb, rest = argv[0], argv[1:]
  flags = [a for a in rest if a.startswith("-")]
  names = [a for a in rest if not a.startswith("-")]
  table = load()

  if verb == "show":
    return do_show(table, names[0] if names else "", flags)

  if verb == "daemon-reload":
    return 0

  if not names:
    return 1
  name = names[0]
  rec = unit_of(table, name)
  if rec["load"] == "not-found":
    sys.stderr.write(f"Unit {name} not found.\n")
    return 5

  rc = 0
  if verb == "enable":
    rec["enabled"] = "enabled"
    if "--now" in flags:
      rc = start(rec)
  elif verb in ("start", "restart", "try-restart"):
    if verb == "try-restart" and rec["active"] != "active":
      rc = 0
    else:
      rc = start(rec)
  elif verb == "disable":
    rec["enabled"] = "disabled"
    if "--now" in flags:
      rec.update(active="inactive", sub="dead")
  elif verb == "stop":
    rec.update(active="inactive", sub="dead")
  elif verb == "is-active":
    print(rec["active"])
    return 0 if rec["active"] == "active" else 3
  else:
    sys.stderr.write(f"fake systemctl: unknown verb {verb}\n")
    return 1

  table[name] = rec
  save(table)
  return rc

if __name__ == "__main__":
  sys.exit(main(sys.argv[1:]))
