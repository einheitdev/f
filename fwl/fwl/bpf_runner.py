"""BPF_PROG_RUN harness — pure Python via ctypes against libbpf.

Given BPF C source and a packet bytes blob, compiles via
`clang -target bpf`, loads via bpf(BPF_PROG_LOAD), runs via
bpf(BPF_PROG_RUN), and returns the XDP action.

Requires CAP_BPF (or root) on a Linux host with libbpf installed.
When that capability is not available, run() raises BpfUnavailable
with a clear message; the runner uses this to skip the BPF oracle
gracefully rather than failing the whole test suite.
"""
from __future__ import annotations
import ctypes
import os
import platform
import shutil
import struct
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from . import log_abi
from .interpreter import XdpAction


class BpfUnavailable(RuntimeError):
  """Raised when BPF_PROG_RUN is not available in this environment.

  Reasons include: libbpf not installed, kernel
  unprivileged_bpf_disabled=2 with no CAP_BPF, missing clang.
  """


@dataclass(frozen=True)
class LogEvent:
  """A log event read from the BPF ring buffer.

  `zone_id` is the raw tag the datapath wrote (`log_abi.zone_id` of
  the emitting zone's name). It is kept numeric here because this
  module reads a ring, not a compilation: resolving it to a zone name
  needs the id -> name table, which the caller has (the AST it emitted,
  or a bundle's `manifest.json["zone_ids"]`) and this module does not.
  """
  zone_id: int
  rule_index: int
  proto: str
  src_ip: str
  dst_ip: str
  src_port: int
  dst_port: int
  syn: bool
  ack: bool


@dataclass(frozen=True)
class RunResult:
  """Full result of a BPF_PROG_TEST_RUN execution."""
  action: XdpAction
  counter_deltas: dict[int, int]
  log_events: list[LogEvent]
  # The packet as the program left it (rewritten headers for a NAT
  # program). Phase 5 output-packet verification compares this against
  # the .pkt's expected.output_packet.
  output_packet: bytes = b""


@dataclass
class CompileResult:
  """Output of compiling BPF C with clang.

  Also a context manager. `compile_c` makes a temporary directory when
  the caller does not supply one, and leaving the `with` block removes
  it; a caller that passed its own `work_dir` owns that directory and
  it is never touched. Callers that only want to know whether the
  source compiles should use `check_compiles`, which cleans up for
  them.

  Not cleaning up is a real failure mode, not an untidiness: one
  directory per compile filled a 2 GiB tmpfs with 84k of them and
  killed a measurement run with ENOSPC.
  """
  obj_path: Path
  source_path: Path
  # The directory to remove on cleanup, or None when the caller
  # supplied `work_dir` and therefore owns it.
  owned_dir: Path | None = None

  def __enter__(self) -> "CompileResult":
    return self

  def __exit__(self, *exc_info) -> None:
    self.cleanup()

  def cleanup(self) -> None:
    """Remove the temporary directory this compile created, if any."""
    if self.owned_dir is not None:
      shutil.rmtree(self.owned_dir, ignore_errors=True)
      self.owned_dir = None


# BPF ISA v4 added `gotol`, a 32-bit unconditional jump, which is what
# removes LLVM's signed 16-bit branch range. The kernel gained the
# instruction in 6.6, so an object built this way will not load on
# anything older -- the bundle records the floor and `fd` checks it.
BPF_ISA_MIN_KERNEL = {"v4": "6.6"}


def compile_c(c_source: str, work_dir: Path | None = None,
              cpu: str | None = None) -> CompileResult:
  """Compile BPF C to a relocatable object via clang.

  `cpu` is passed straight to `-mcpu=`. None means clang's default,
  which is the widest kernel compatibility and a signed 16-bit branch
  offset; "v4" buys a 32-bit jump at the price of needing kernel 6.6.
  `fwl compile --bundle` asks for it only after clang has refused the
  default with `Branch target out of insn range`, never from an
  estimate: a Tier 2 body of 1,200 branches estimates at 29,000
  instructions and assembles to 161, so an estimate would stamp a
  kernel floor onto bundles that load anywhere.

  This runs in any environment with clang installed (no kernel
  privileges required), so it acts as a partial verification oracle
  even when full BPF_PROG_RUN is unavailable: structurally broken
  emitter output fails here.

  The result owns a temporary directory unless `work_dir` is given, so
  use it as a context manager (or call `cleanup()`) once the object
  file has been consumed. A caller that needs its object to outlive
  the call passes `work_dir` explicitly and owns it, as `fwl compile
  --bundle-dir` does.

  Raises BpfUnavailable if clang is missing.
  Raises subprocess.CalledProcessError if compilation fails — the
  stderr of clang is included in the exception.
  """
  if shutil.which("clang") is None:
    raise BpfUnavailable("clang not found on PATH")

  owned_dir: Path | None = None
  if work_dir is None:
    work_dir = Path(tempfile.mkdtemp(prefix="fwl-bpf-"))
    owned_dir = work_dir
  work_dir.mkdir(parents=True, exist_ok=True)

  src_path = work_dir / "fwl_prog.bpf.c"
  obj_path = work_dir / "fwl_prog.bpf.o"
  src_path.write_text(c_source, encoding="utf-8")

  cmd = [
    "clang",
    "-O2",
    "-g",
    "-target", "bpf",
  ]
  if cpu:
    cmd.append(f"-mcpu={cpu}")
  cmd += [
    "-c", str(src_path),
    "-o", str(obj_path),
  ]
  for path in _ARCH_INCLUDE_PATHS:
    if path.exists():
      cmd.extend(["-I", str(path)])

  try:
    subprocess.run(cmd, check=True, capture_output=True)
  except BaseException:
    # A failed compile has no artifacts worth keeping, and its caller
    # gets an exception rather than a result it could clean up.
    if owned_dir is not None:
      shutil.rmtree(owned_dir, ignore_errors=True)
    raise
  return CompileResult(
    obj_path=obj_path, source_path=src_path, owned_dir=owned_dir
  )


def check_compiles(c_source: str, cpu: str | None = None) -> None:
  """Compile `c_source` and discard the object.

  For callers that use clang purely as an oracle — the object is never
  loaded, only the absence of an exception matters. Raises the same
  exceptions as `compile_c`.
  """
  with compile_c(c_source, cpu=cpu):
    pass


# Debian/Ubuntu multiarch installs put asm/* under a triplet path
# clang -target bpf doesn't search by default. Add anything that
# exists; missing entries are silently skipped on other distros.
_ARCH_INCLUDE_PATHS = [
  Path("/usr/include/x86_64-linux-gnu"),
  Path("/usr/include/aarch64-linux-gnu"),
]


def _can_load_bpf() -> bool:
  """Best-effort check for whether we can load a BPF program.

  Returns False when unprivileged_bpf_disabled=2 and we lack
  CAP_BPF. Used by run() to decide whether to attempt BPF_PROG_LOAD.
  """
  if os.geteuid() == 0:
    return True
  try:
    with open(
      "/proc/sys/kernel/unprivileged_bpf_disabled", encoding="utf-8"
    ) as f:
      value = f.read().strip()
  except OSError:
    return False
  if value == "0":
    return True
  # CAP_BPF or CAP_SYS_ADMIN would let us proceed; checking that
  # without root or capsh is awkward, so we conservatively return
  # False and let bpf(BPF_PROG_LOAD) be the source of truth.
  return False


def run(
  c_source: str,
  packet: bytes,
  map_init: dict[str, dict[bytes, bytes]] | None = None,
) -> XdpAction:
  """Compile, load, and run `c_source` against `packet`.

  Returns the XDP action the kernel verifier-accepted program
  produced. Raises BpfUnavailable when this environment can't load
  BPF programs at all (so the runner can skip the oracle cleanly).
  Raises subprocess.CalledProcessError on clang errors and OSError
  on bpf() syscall errors.

  `map_init`, when provided, is a `{map_name: {key_bytes: value_bytes}}`
  dict applied via bpf_map_update_elem after load and before
  BPF_PROG_TEST_RUN. For per-CPU maps the caller should size
  value_bytes as `nr_possible_cpus * per_cpu_value_size`.
  """
  if not _can_load_bpf():
    raise BpfUnavailable(
      "kernel BPF load unavailable: not root and "
      "unprivileged_bpf_disabled is set"
    )

  return run_full(c_source, packet, map_init).action


def run_full(
  c_source: str,
  packet: bytes,
  map_init: dict[str, dict[bytes, bytes]] | None = None,
  counter_slots: int = 0,
  has_log: bool = False,
) -> RunResult:
  """Compile, load, and run `c_source` against `packet`.

  Returns the XDP action, counter deltas, and log events.
  """
  if not _can_load_bpf():
    raise BpfUnavailable(
      "kernel BPF load unavailable: not root and "
      "unprivileged_bpf_disabled is set"
    )
  # The object is read by the loader inside the block; nothing needs
  # the file afterwards, so the temp dir goes with it.
  with compile_c(c_source) as result:
    return _load_and_run(
      result.obj_path, packet, map_init or {},
      counter_slots, has_log,
    )


def run_sequence(
  c_source: str,
  packets: list[bytes],
  map_init: dict[str, dict[bytes, bytes]] | None = None,
  counter_slots: int = 0,
  has_log: bool = False,
) -> list[RunResult]:
  """Compile + load `c_source` once and run each packet in order.

  The loaded object — and therefore its `conntrack` map — persists
  across packets, so an allowed NEW packet's created entry is visible
  to a later packet in the same list (v0.4 multi-packet sequences).
  """
  if not _can_load_bpf():
    raise BpfUnavailable(
      "kernel BPF load unavailable: not root and "
      "unprivileged_bpf_disabled is set"
    )
  with compile_c(c_source) as result:
    return _load_and_run_seq(
      result.obj_path, packets, map_init or {}, counter_slots, has_log,
    )


def num_possible_cpus() -> int:
  """Return the kernel's nr_cpus_possible (per-CPU map sizing key).

  Reads /sys/devices/system/cpu/possible (e.g. "0-3") rather than
  taking online cpu count — per-CPU BPF maps allocate by *possible*
  not online.
  """
  with open("/sys/devices/system/cpu/possible", encoding="utf-8") as f:
    text = f.read().strip()
  count = 0
  for part in text.split(","):
    if "-" in part:
      lo, hi = part.split("-")
      count += int(hi) - int(lo) + 1
    else:
      count += 1
  return count


def _open_libbpf():
  """Load libbpf and bind the ctypes signatures the runner uses."""
  try:
    libbpf = ctypes.CDLL("libbpf.so.1", use_errno=True)
  except OSError as exc:
    raise BpfUnavailable(f"cannot load libbpf: {exc}") from exc
  _bind_libbpf_signatures(libbpf)
  return libbpf


def _bind_libbpf_signatures(libbpf) -> None:
  """Set restype/argtypes on the libbpf entry points the runner calls."""
  libbpf.bpf_object__open_file.restype = ctypes.c_void_p
  libbpf.bpf_object__open_file.argtypes = [
    ctypes.c_char_p, ctypes.c_void_p
  ]
  libbpf.bpf_object__load.restype = ctypes.c_int
  libbpf.bpf_object__load.argtypes = [ctypes.c_void_p]
  libbpf.bpf_object__close.restype = None
  libbpf.bpf_object__close.argtypes = [ctypes.c_void_p]
  libbpf.bpf_object__find_program_by_name.restype = ctypes.c_void_p
  libbpf.bpf_object__find_program_by_name.argtypes = [
    ctypes.c_void_p, ctypes.c_char_p
  ]
  libbpf.bpf_program__fd.restype = ctypes.c_int
  libbpf.bpf_program__fd.argtypes = [ctypes.c_void_p]
  libbpf.bpf_object__find_map_by_name.restype = ctypes.c_void_p
  libbpf.bpf_object__find_map_by_name.argtypes = [
    ctypes.c_void_p, ctypes.c_char_p
  ]
  libbpf.bpf_map__fd.restype = ctypes.c_int
  libbpf.bpf_map__fd.argtypes = [ctypes.c_void_p]
  libbpf.bpf_map_update_elem.restype = ctypes.c_int
  libbpf.bpf_map_update_elem.argtypes = [
    ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64
  ]
  libbpf.bpf_map_lookup_elem.restype = ctypes.c_int
  libbpf.bpf_map_lookup_elem.argtypes = [
    ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p
  ]
  libbpf.ring_buffer__new.restype = ctypes.c_void_p
  libbpf.ring_buffer__new.argtypes = [
    ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p,
    ctypes.c_void_p,
  ]
  libbpf.ring_buffer__consume.restype = ctypes.c_int
  libbpf.ring_buffer__consume.argtypes = [ctypes.c_void_p]
  libbpf.ring_buffer__free.restype = None
  libbpf.ring_buffer__free.argtypes = [ctypes.c_void_p]


def _load_and_run(
  obj_path: Path,
  packet: bytes,
  map_init: dict[str, dict[bytes, bytes]],
  counter_slots: int = 0,
  has_log: bool = False,
) -> RunResult:
  """Load `obj_path` via libbpf and BPF_PROG_RUN against `packet`."""
  results = _load_and_run_seq(
    obj_path, [packet], map_init, counter_slots, has_log
  )
  return results[0]


def _load_and_run_seq(
  obj_path: Path,
  packets: list[bytes],
  map_init: dict[str, dict[bytes, bytes]],
  counter_slots: int = 0,
  has_log: bool = False,
) -> list[RunResult]:
  """Load `obj_path` once and BPF_PROG_RUN each packet in order.

  Map state (notably the `conntrack` map) persists across runs in the
  same loaded object, so a multi-packet conntrack sequence — first
  packet creates an entry, a later packet matches it — is exercised
  end to end. Counter deltas and log events are read after each run,
  so each step's RunResult reports only that step's side effects.
  """
  libbpf = _open_libbpf()
  obj = libbpf.bpf_object__open_file(
    str(obj_path).encode("utf-8"), None
  )
  if not obj:
    raise OSError(
      ctypes.get_errno(), "bpf_object__open_file failed"
    )
  rb = None
  try:
    if libbpf.bpf_object__load(obj) != 0:
      raise OSError(
        ctypes.get_errno(), "bpf_object__load failed"
      )

    for map_name, entries in map_init.items():
      _populate_map(libbpf, obj, map_name, entries)

    # v0.4 § 6.6: a split object has no `fwl_prog` — it holds N
    # `fwl_stage_i` programs chained through the `fwl_stages` prog_array.
    # Populate that array with the stage fds and enter at stage 0, so
    # BPF_PROG_TEST_RUN drives the whole tail-call pipeline exactly as
    # the daemon would after wiring the prog_array at load.
    prog_fd = _resolve_entry_prog(libbpf, obj)

    results: list[RunResult] = []
    # `fwl_counters` is cumulative across the whole loaded object, so a
    # per-step delta is a difference of two readings. Reporting the raw
    # total made step N of a sequence claim every increment since step
    # 0 — matching the interpreter only on the first step, and only
    # ever compared once a sequence step's `counter_changes` was
    # actually checked (it was accepted and ignored until then).
    prev_totals: dict[int, int] = {}
    for packet in packets:
      log_events: list[LogEvent] = []
      abi_errors: list[str] = []
      rb = _setup_ring_buffer(
        libbpf, obj, log_events, abi_errors
      ) if has_log else None
      action, out_packet = _bpf_prog_test_run_out(prog_fd, packet)
      if rb:
        libbpf.ring_buffer__consume(rb)
        libbpf.ring_buffer__free(rb)
        rb = None
      if abi_errors:
        raise RuntimeError(
          "fwl_log_events record rejected: " + abi_errors[0]
        )

      counter_deltas: dict[int, int] = {}
      if counter_slots > 0:
        totals = _read_counter_totals(libbpf, obj, counter_slots)
        for slot in set(totals) | set(prev_totals):
          delta = totals.get(slot, 0) - prev_totals.get(slot, 0)
          if delta:
            counter_deltas[slot] = delta
        prev_totals = totals
      results.append(RunResult(
        action=action,
        counter_deltas=counter_deltas,
        log_events=log_events,
        output_packet=out_packet,
      ))
    return results
  finally:
    if rb:
      libbpf.ring_buffer__free(rb)
    libbpf.bpf_object__close(obj)


def _resolve_entry_prog(libbpf, obj) -> int:
  """Return the fd of the program to run, wiring a split pipeline.

  For a single-program object, that is `fwl_prog`. For a v0.4 § 6.6
  split object, it is `fwl_stage_0` after every `fwl_stage_i` fd has
  been written into the `fwl_stages` prog_array (index i -> stage i's
  fd), which is what makes the `bpf_tail_call(ctx, &fwl_stages, i)`
  hops resolve.
  """
  stages_map = libbpf.bpf_object__find_map_by_name(obj, b"fwl_stages")
  if not stages_map:
    prog = libbpf.bpf_object__find_program_by_name(obj, b"fwl_prog")
    if not prog:
      raise RuntimeError("BPF program 'fwl_prog' not found in object")
    return libbpf.bpf_program__fd(prog)

  arr_fd = libbpf.bpf_map__fd(stages_map)
  entry_fd = None
  i = 0
  while True:
    prog = libbpf.bpf_object__find_program_by_name(
      obj, f"fwl_stage_{i}".encode("utf-8")
    )
    if not prog:
      break
    fd = libbpf.bpf_program__fd(prog)
    if i == 0:
      entry_fd = fd
    key = struct.pack("<I", i)
    val = struct.pack("<i", fd)
    key_buf = (ctypes.c_ubyte * 4).from_buffer_copy(key)
    val_buf = (ctypes.c_ubyte * 4).from_buffer_copy(val)
    rc = libbpf.bpf_map_update_elem(arr_fd, key_buf, val_buf, 0)
    if rc != 0:
      err = ctypes.get_errno()
      raise OSError(err, f"prog_array update failed at stage {i}")
    i += 1
  if entry_fd is None:
    raise RuntimeError("split object has no 'fwl_stage_0' program")
  return entry_fd


def _populate_map(
  libbpf, obj, map_name: str, entries: dict[bytes, bytes]
) -> None:
  """Write `entries` into the named BPF map via bpf_map_update_elem."""
  bpf_map = libbpf.bpf_object__find_map_by_name(
    obj, map_name.encode("utf-8")
  )
  if not bpf_map:
    raise RuntimeError(
      f"BPF map '{map_name}' not found in object"
    )
  fd = libbpf.bpf_map__fd(bpf_map)
  for key, value in entries.items():
    key_buf = (ctypes.c_ubyte * len(key)).from_buffer_copy(key)
    val_buf = (ctypes.c_ubyte * len(value)).from_buffer_copy(value)
    BPF_ANY = 0
    rc = libbpf.bpf_map_update_elem(fd, key_buf, val_buf, BPF_ANY)
    if rc != 0:
      err = ctypes.get_errno()
      raise OSError(
        err,
        f"bpf_map_update_elem failed on {map_name}: errno={err}",
      )


_PROTO_NUM_TO_STR = {6: "tcp", 17: "udp", 1: "icmp"}


def _u32_to_ip(val: int) -> str:
  """Convert a host-byte-order u32 to dotted-quad string."""
  return (f"{(val >> 24) & 0xFF}.{(val >> 16) & 0xFF}."
          f"{(val >> 8) & 0xFF}.{val & 0xFF}")


_RING_BUFFER_SAMPLE_FN = ctypes.CFUNCTYPE(
  ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p,
  ctypes.c_size_t,
)


def _setup_ring_buffer(libbpf, obj, log_events, abi_errors):
  """Set up a ring buffer consumer for fwl_log_events.

  `abi_errors` collects records the shared `log_abi` decoder rejects.
  A ctypes callback cannot usefully raise — the exception would be
  swallowed inside libbpf's poll loop — so the failure is carried out
  and raised by the caller, which is what turns a layout mismatch into
  a test error instead of a silently short event list.
  """
  bpf_map = libbpf.bpf_object__find_map_by_name(
    obj, b"fwl_log_events"
  )
  if not bpf_map:
    return None
  fd = libbpf.bpf_map__fd(bpf_map)

  @_RING_BUFFER_SAMPLE_FN
  def callback(ctx, data, size):
    raw = ctypes.string_at(data, min(size, log_abi.SIZE))
    try:
      ev = log_abi.decode(raw)
    except log_abi.LogAbiError as exc:
      abi_errors.append(str(exc))
      return 0
    log_events.append(LogEvent(
      zone_id=ev["zone_id"],
      rule_index=ev["rule_index"],
      proto=_PROTO_NUM_TO_STR.get(ev["proto"], str(ev["proto"])),
      src_ip=_u32_to_ip(ev["src_ip"]),
      dst_ip=_u32_to_ip(ev["dst_ip"]),
      src_port=ev["src_port"],
      dst_port=ev["dst_port"],
      syn=bool(ev["flags"] & 0x01),
      ack=bool(ev["flags"] & 0x02),
    ))
    return 0

  _setup_ring_buffer._active_cb = callback  # type: ignore[attr-defined]
  rb = libbpf.ring_buffer__new(fd, callback, None, None)
  if not rb:
    return None
  return rb


def _read_counter_totals(
  libbpf, obj, n_slots: int
) -> dict[int, int]:
  """Read fwl_counters per-CPU array and sum across CPUs.

  ABSOLUTE totals since the object was loaded, not per-run deltas.
  Callers running more than one packet against one loaded object must
  subtract the previous reading themselves — see `_load_and_run_seq`,
  where not doing so made every step of a sequence report the running
  total while the interpreter reported that step alone.
  """
  bpf_map = libbpf.bpf_object__find_map_by_name(
    obj, b"fwl_counters"
  )
  if not bpf_map:
    return {}
  fd = libbpf.bpf_map__fd(bpf_map)
  try:
    nr_cpus = num_possible_cpus()
  except OSError:
    nr_cpus = 1
  val_size = 8 * nr_cpus
  totals: dict[int, int] = {}
  for slot in range(n_slots):
    key = (ctypes.c_uint32)(slot)
    val_buf = (ctypes.c_ubyte * val_size)()
    rc = libbpf.bpf_map_lookup_elem(
      fd, ctypes.byref(key), val_buf
    )
    if rc != 0:
      continue
    total = 0
    for cpu in range(nr_cpus):
      offset = cpu * 8
      cpu_val = struct.unpack_from(
        "<Q", bytes(val_buf), offset
      )
      total += cpu_val[0]
    if total != 0:
      totals[slot] = total
  return totals


# union bpf_attr layout for BPF_PROG_TEST_RUN — minimal fields
# we use. The full union is much larger; padding is added so the
# kernel reads the right offsets regardless of which arm a given
# kernel header version uses.
class _BpfAttrTestRun(ctypes.Structure):
  """The test_run arm of union bpf_attr.

  Field layout taken from include/uapi/linux/bpf.h (kernel 5.x+).
  Padding at the end ensures we hand the kernel a buffer at least as
  large as the largest arm of the union.
  """
  _fields_ = [
    ("prog_fd", ctypes.c_uint32),
    ("retval", ctypes.c_uint32),
    ("data_size_in", ctypes.c_uint32),
    ("data_size_out", ctypes.c_uint32),
    ("data_in", ctypes.c_uint64),
    ("data_out", ctypes.c_uint64),
    ("repeat", ctypes.c_uint32),
    ("duration", ctypes.c_uint32),
    ("ctx_size_in", ctypes.c_uint32),
    ("ctx_size_out", ctypes.c_uint32),
    ("ctx_in", ctypes.c_uint64),
    ("ctx_out", ctypes.c_uint64),
    ("flags", ctypes.c_uint32),
    ("cpu", ctypes.c_uint32),
    ("batch_size", ctypes.c_uint32),
    ("_pad", ctypes.c_uint8 * 64),
  ]


_BPF_PROG_TEST_RUN = 10
# The bpf(2) syscall number is per-architecture. Hardcoding the
# x86_64 value made every BPF_PROG_TEST_RUN fail with ENOSYS on the
# aarch64 rig — the loader (libbpf) worked, so the failure only
# surfaced when the oracle actually executed a program.
_NR_BPF_BY_MACHINE = {
  "x86_64": 321,
  "aarch64": 280,
  "riscv64": 280,
}
_NR_BPF = _NR_BPF_BY_MACHINE.get(platform.machine(), 321)


def _bpf_prog_test_run(prog_fd: int, packet: bytes) -> XdpAction:
  """Invoke BPF_PROG_TEST_RUN, returning only the XDP action."""
  return _bpf_prog_test_run_out(prog_fd, packet)[0]


def _bpf_prog_test_run_out(
  prog_fd: int, packet: bytes
) -> tuple[XdpAction, bytes]:
  """Invoke BPF_PROG_TEST_RUN, returning the action and output packet.

  The output packet is the frame as the program left it — for a NAT
  program, the rewritten headers — so the caller can verify the
  translated fields and recompute checksums (Phase 5)."""
  libc = ctypes.CDLL("libc.so.6", use_errno=True)
  libc.syscall.restype = ctypes.c_long

  # XDP requires at least ETH_HLEN + sizeof(iphdr) = 34 bytes input
  # and may write the packet out — give it generous output room.
  data_in = (ctypes.c_ubyte * len(packet)).from_buffer_copy(packet)
  data_out = (ctypes.c_ubyte * max(len(packet) + 256, 1500))()

  attr = _BpfAttrTestRun(
    prog_fd=prog_fd,
    retval=0,
    data_size_in=len(packet),
    data_size_out=len(data_out),
    data_in=ctypes.addressof(data_in),
    data_out=ctypes.addressof(data_out),
    repeat=1,
    duration=0,
    ctx_size_in=0,
    ctx_size_out=0,
    ctx_in=0,
    ctx_out=0,
    flags=0,
    cpu=0,
    batch_size=0,
  )

  rc = libc.syscall(
    _NR_BPF,
    _BPF_PROG_TEST_RUN,
    ctypes.byref(attr),
    ctypes.sizeof(attr),
  )
  if rc < 0:
    err = ctypes.get_errno()
    raise OSError(err, f"BPF_PROG_TEST_RUN failed: errno={err}")

  retval = attr.retval
  out = bytes(data_out[:attr.data_size_out])
  # XDP_DROP=1, XDP_PASS=2, XDP_TX=3, XDP_REDIRECT=4. v0.4 `redirect to`
  # produces XDP_REDIRECT (§ 6.3); v0.1-v0.3 only ever PASS or DROP.
  if retval == 1:
    return XdpAction.DROP, out
  if retval == 2:
    return XdpAction.PASS, out
  if retval == 4:
    return XdpAction.REDIRECT, out
  raise RuntimeError(f"unexpected XDP retval {retval}")
