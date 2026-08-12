"""Consume the pinned fwl_log_events ring buffer for N seconds.

The bundle programs pin fwl_log_events under the fd pin root
(LIBBPF_PIN_BY_NAME). This attaches a libbpf ring_buffer consumer to
the pinned map and prints one JSON line per event.

The ring is ONE buffer for the whole bundle and `rule_index` is
numbered per zone, so a record is only meaningful as
(zone, rule_index). Each record carries `zone_id`; this resolves it to
a zone name through the bundle's own `manifest.json["zone_ids"]` —
the table ships with the artifact the events came from, so nothing
here has to know the policy.

Record decoding is `fwl.log_abi`'s, shared with the .pkt oracle rather
than restated: a second copy of the layout is how a reader and a
datapath drift apart without either reporting an error. A record whose
header does not match is counted and reported, and the process exits
3 — never skipped quietly, because a rejected record means every other
record on this ring is suspect too.

Usage: ringlog.py <seconds> [pin_path] [manifest_path]
"""
import ctypes
import ctypes.util
import json
import struct
import sys
import time

from fwl import log_abi

_SAMPLE_FN = ctypes.CFUNCTYPE(
  ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t
)

_DEFAULT_PIN = "/sys/fs/bpf/f/fwl_log_events"
_DEFAULT_MANIFEST = "/usr/share/f/compiled/current/manifest.json"

def _ip(val: int) -> str:
  """Dotted quad for a HOST-byte-order address field.

  The datapath stores src_ip/dst_ip through bpf_ntohl, so the most
  significant octet is the first of the quad. This used to pack "<I"
  and printed every address backwards — 10.99.11.1 came out as
  1.11.99.10, a legal-looking address that is not the one on the wire,
  and nothing reported it. `bpf_runner._u32_to_ip` has always read it
  the right way round; the two consumers of this field now agree.
  """
  packed = struct.pack(">I", val)
  return ".".join(str(b) for b in packed)

def _zone_names(manifest_path: str) -> dict[int, str]:
  """id -> zone name, from the running bundle's manifest.

  Missing or tableless manifests give an empty map rather than an
  error: every event then prints `"zone": null`, which is a visible
  "cannot attribute this" instead of a plausible wrong name.
  """
  try:
    with open(manifest_path, encoding="utf-8") as fh:
      manifest = json.load(fh)
  except (OSError, ValueError) as exc:
    print(f"# no zone table ({manifest_path}): {exc}", file=sys.stderr)
    return {}
  return {
    int(zid): name
    for name, zid in manifest.get("zone_ids", {}).items()
  }

def main() -> int:
  seconds = float(sys.argv[1])
  pin = sys.argv[2] if len(sys.argv) > 2 else _DEFAULT_PIN
  manifest = sys.argv[3] if len(sys.argv) > 3 else _DEFAULT_MANIFEST
  zone_by_id = _zone_names(manifest)
  path = ctypes.util.find_library("bpf")
  if path is None:
    print("libbpf not found", file=sys.stderr)
    return 2
  libbpf = ctypes.CDLL(path, use_errno=True)
  libbpf.bpf_obj_get.argtypes = [ctypes.c_char_p]
  libbpf.bpf_obj_get.restype = ctypes.c_int
  libbpf.ring_buffer__new.argtypes = [
    ctypes.c_int, _SAMPLE_FN, ctypes.c_void_p, ctypes.c_void_p
  ]
  libbpf.ring_buffer__new.restype = ctypes.c_void_p
  libbpf.ring_buffer__poll.argtypes = [
    ctypes.c_void_p, ctypes.c_int
  ]
  libbpf.ring_buffer__poll.restype = ctypes.c_int

  fd = libbpf.bpf_obj_get(pin.encode())
  if fd < 0:
    print(f"bpf_obj_get({pin}) failed", file=sys.stderr)
    return 2

  count = 0
  bad = 0

  @_SAMPLE_FN
  def callback(ctx, data, size):
    nonlocal count, bad
    raw = ctypes.string_at(data, min(size, log_abi.SIZE))
    try:
      ev = log_abi.decode(raw)
    except log_abi.LogAbiError as exc:
      bad += 1
      print(f"# ABI: {exc}", file=sys.stderr)
      return 0
    print(json.dumps({
      "zone": zone_by_id.get(ev["zone_id"]),
      "zone_id": ev["zone_id"],
      "rule_index": ev["rule_index"],
      "src_ip": _ip(ev["src_ip"]), "dst_ip": _ip(ev["dst_ip"]),
      "src_port": ev["src_port"], "dst_port": ev["dst_port"],
      "proto": ev["proto"], "flags": ev["flags"],
    }), flush=True)
    count += 1
    return 0

  rb = libbpf.ring_buffer__new(fd, callback, None, None)
  if not rb:
    print("ring_buffer__new failed", file=sys.stderr)
    return 2
  deadline = time.monotonic() + seconds
  while time.monotonic() < deadline:
    libbpf.ring_buffer__poll(rb, 200)
  print(f"# events={count} rejected={bad}", file=sys.stderr)
  return 3 if bad else 0

if __name__ == "__main__":
  sys.exit(main())
