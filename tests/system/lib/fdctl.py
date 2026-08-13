#!/usr/bin/env python3
"""Minimal fd control-socket client for system tests.

Sends a single-byte command (the Cmd enum value) over the ZMQ REQ
control socket and prints the daemon's JSON reply. Mirrors the raw wire
protocol the CLI adapter's transport uses.

Usage: fdctl.py <cmd-number> [socket]
  cmd numbers: 2 counters, 3 status, 6 firewall, 7 rules,
               9 zones, 10 nat, 11 conntrack
"""
import sys
import zmq

CMD = int(sys.argv[1])
SOCK = sys.argv[2] if len(sys.argv) > 2 else "ipc:///tmp/fdtest.sock"

ctx = zmq.Context()
s = ctx.socket(zmq.REQ)
s.setsockopt(zmq.RCVTIMEO, 3000)
s.setsockopt(zmq.SNDTIMEO, 3000)
s.setsockopt(zmq.LINGER, 0)
s.connect(SOCK)
s.send(bytes([CMD]))
print(s.recv().decode("utf-8", "replace"))
