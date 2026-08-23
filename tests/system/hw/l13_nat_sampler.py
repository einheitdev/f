#!/usr/bin/env python3
"""Sample fd's NAT table on the DUT, fast enough to see a slope.

Flow establishment rate is a derivative, so it has to be sampled on
the box against a monotonic clock. Reading it over ssh once per tick
puts seconds of network latency inside a measurement whose whole
content is d(entries)/dt -- the same mistake that once had the load
ladder reporting 2.16 Mpps on a 1 GbE port.

`installed` is the cumulative count of translations allocated, so its
slope IS the flows-per-second the datapath established. `entries` is
occupancy, which is the slope minus whatever the collector reclaimed,
and `refused` is what a full table looks like from the outside.
"""

import json
import subprocess
import sys
import time

FIELDS = ("entries", "installed", "refused", "table_full", "high_water",
          "max_entries", "occupancy_pct", "total_reclaimed")

def sample():
  """One reading of fd's NAT counters, or None if fd did not answer."""
  proc = subprocess.run(["fctl", "status"], capture_output=True,
                        text=True)
  if proc.returncode != 0:
    return None
  try:
    nat = json.loads(proc.stdout).get("nat", {})
  except ValueError:
    return None
  return {k: nat.get(k, -1) for k in FIELDS}

def main():
  if len(sys.argv) < 2:
    sys.exit("usage: l13_nat_sampler.py <seconds> [interval]")
  seconds = float(sys.argv[1])
  interval = float(sys.argv[2]) if len(sys.argv) > 2 else 0.2
  deadline = time.monotonic() + seconds
  while True:
    now = time.monotonic()
    nat = sample()
    if nat is not None:
      print(json.dumps({"t": now, **nat}), flush=True)
    if now >= deadline:
      break
    time.sleep(interval)

if __name__ == "__main__":
  main()
