"""Consume the pinned fwl_log_events ring buffer for N seconds.

The bundle programs pin fwl_log_events under the fd pin root
(LIBBPF_PIN_BY_NAME). This attaches a libbpf ring_buffer consumer to
the pinned map and prints one JSON line per event.

Usage: ringlog.py <seconds> [pin_path]
"""
import ctypes
import ctypes.util
import json
import struct
import sys
import time

_EVENT = struct.Struct("<Q II HH BB xx I")

_SAMPLE_FN = ctypes.CFUNCTYPE(
  ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t
)

def _ip(val: int) -> str:
  packed = struct.pack("<I", val)
  return ".".join(str(b) for b in packed)

def main() -> int:
  seconds = float(sys.argv[1])
  pin = sys.argv[2] if len(sys.argv) > 2 else \
    "/sys/fs/bpf/f/fwl_log_events"
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

  @_SAMPLE_FN
  def callback(ctx, data, size):
    nonlocal count
    if size < _EVENT.size:
      return 0
    raw = ctypes.string_at(data, _EVENT.size)
    (ts, src_ip, dst_ip, src_port, dst_port, proto, flags,
     rule_index) = _EVENT.unpack(raw)
    print(json.dumps({
      "src_ip": _ip(src_ip), "dst_ip": _ip(dst_ip),
      "src_port": src_port, "dst_port": dst_port,
      "proto": proto, "flags": flags, "rule_index": rule_index,
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
  print(f"# events={count}", file=sys.stderr)
  return 0

if __name__ == "__main__":
  sys.exit(main())
