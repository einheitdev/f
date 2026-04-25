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
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .interpreter import XdpAction


class BpfUnavailable(RuntimeError):
  """Raised when BPF_PROG_RUN is not available in this environment.

  Reasons include: libbpf not installed, kernel
  unprivileged_bpf_disabled=2 with no CAP_BPF, missing clang.
  """


@dataclass(frozen=True)
class CompileResult:
  """Output of compiling BPF C with clang."""
  obj_path: Path
  source_path: Path


def compile_c(c_source: str, work_dir: Path | None = None) -> CompileResult:
  """Compile BPF C to a relocatable object via clang.

  This runs in any environment with clang installed (no kernel
  privileges required), so it acts as a partial verification oracle
  even when full BPF_PROG_RUN is unavailable: structurally broken
  emitter output fails here.

  Raises BpfUnavailable if clang is missing.
  Raises subprocess.CalledProcessError if compilation fails — the
  stderr of clang is included in the exception.
  """
  if shutil.which("clang") is None:
    raise BpfUnavailable("clang not found on PATH")

  if work_dir is None:
    work_dir = Path(tempfile.mkdtemp(prefix="fwl-bpf-"))
  work_dir.mkdir(parents=True, exist_ok=True)

  src_path = work_dir / "fwl_prog.bpf.c"
  obj_path = work_dir / "fwl_prog.bpf.o"
  src_path.write_text(c_source, encoding="utf-8")

  cmd = [
    "clang",
    "-O2",
    "-g",
    "-target", "bpf",
    "-c", str(src_path),
    "-o", str(obj_path),
  ]
  for path in _ARCH_INCLUDE_PATHS:
    if path.exists():
      cmd.extend(["-I", str(path)])

  subprocess.run(cmd, check=True, capture_output=True)
  return CompileResult(obj_path=obj_path, source_path=src_path)


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


def run(c_source: str, packet: bytes) -> XdpAction:
  """Compile, load, and run `c_source` against `packet`.

  Returns the XDP action the kernel verifier-accepted program
  produced. Raises BpfUnavailable when this environment can't load
  BPF programs at all (so the runner can skip the oracle cleanly).
  Raises subprocess.CalledProcessError on clang errors and OSError
  on bpf() syscall errors.
  """
  if not _can_load_bpf():
    raise BpfUnavailable(
      "kernel BPF load unavailable: not root and "
      "unprivileged_bpf_disabled is set"
    )

  result = compile_c(c_source)
  return _load_and_run(result.obj_path, packet)


def _load_and_run(obj_path: Path, packet: bytes) -> XdpAction:
  """Load `obj_path` via libbpf and BPF_PROG_RUN against `packet`.

  Implementation note: this is the part of the harness that needs
  CAP_BPF. Kept in its own function so the import-time cost of
  loading libbpf is paid only when we're actually going to use it.
  """
  try:
    libbpf = ctypes.CDLL("libbpf.so.1", use_errno=True)
  except OSError as exc:
    raise BpfUnavailable(f"cannot load libbpf: {exc}") from exc

  # bpf_object__open_file(path) -> struct bpf_object *
  libbpf.bpf_object__open_file.restype = ctypes.c_void_p
  libbpf.bpf_object__open_file.argtypes = [
    ctypes.c_char_p, ctypes.c_void_p
  ]
  # bpf_object__load(obj) -> int
  libbpf.bpf_object__load.restype = ctypes.c_int
  libbpf.bpf_object__load.argtypes = [ctypes.c_void_p]
  # bpf_object__close(obj) -> void
  libbpf.bpf_object__close.restype = None
  libbpf.bpf_object__close.argtypes = [ctypes.c_void_p]
  # bpf_object__find_program_by_name(obj, name) -> struct bpf_program *
  libbpf.bpf_object__find_program_by_name.restype = ctypes.c_void_p
  libbpf.bpf_object__find_program_by_name.argtypes = [
    ctypes.c_void_p, ctypes.c_char_p
  ]
  # bpf_program__fd(prog) -> int
  libbpf.bpf_program__fd.restype = ctypes.c_int
  libbpf.bpf_program__fd.argtypes = [ctypes.c_void_p]

  obj = libbpf.bpf_object__open_file(
    str(obj_path).encode("utf-8"), None
  )
  if not obj:
    raise OSError(
      ctypes.get_errno(), "bpf_object__open_file failed"
    )
  try:
    if libbpf.bpf_object__load(obj) != 0:
      raise OSError(ctypes.get_errno(), "bpf_object__load failed")
    prog = libbpf.bpf_object__find_program_by_name(
      obj, b"fwl_prog"
    )
    if not prog:
      raise RuntimeError("BPF program 'fwl_prog' not found in object")
    prog_fd = libbpf.bpf_program__fd(prog)

    return _bpf_prog_test_run(prog_fd, packet)
  finally:
    libbpf.bpf_object__close(obj)


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
_NR_BPF = 321  # x86_64 syscall number


def _bpf_prog_test_run(prog_fd: int, packet: bytes) -> XdpAction:
  """Invoke BPF_PROG_TEST_RUN via the bpf() syscall."""
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
  # XDP_DROP=1, XDP_PASS=2, XDP_TX=3, XDP_REDIRECT=4. v0.1 only ever
  # produces PASS or DROP.
  if retval == 1:
    return XdpAction.DROP
  if retval == 2:
    return XdpAction.PASS
  raise RuntimeError(f"unexpected XDP retval {retval}")
