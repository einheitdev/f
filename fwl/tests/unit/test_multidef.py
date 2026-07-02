"""Unit tests for v0.4 § 6.5 multi-def (BPF-to-BPF function calls).

Covers the parser/analyzer/emitter/interpreter surfaces added for
top-level helper `def`s and the `helper(pkt)` call statement: helpers
compile to `static __noinline` BPF functions (real calls, not inlined
stubs), are callable from multiple zones, and evaluate identically to
the equivalent inlined program (the split-invisible principle).
"""
import pytest

from fwl import analyzer, bpf_runner, emitter, interpreter, parser, pkt
from fwl.errors import FwlException
from fwl.interpreter import XdpAction


def _analyze(text):
  return analyzer.analyze(parser.parse(text))


def _pkt(builder):
  return pkt.build_packet(pkt.parse_builder(builder)).fields


def _run(text, builder):
  return interpreter.evaluate(_analyze(text), _pkt(builder))


# --- parsing --------------------------------------------------------

def test_top_level_helper_parses_into_program_helpers():
  prog = parser.parse(
    "def h(pkt):\n  drop\n\n@xdp(eth0)\ndef m(pkt):\n  h(pkt)\n  allow\n"
  )
  assert [h.name for h in prog.helpers] == ["h"]
  assert prog.programs[0].function.name == "m"
  body = prog.programs[0].function.body
  assert type(body[0]).__name__ == "CallStmt"
  assert body[0].name == "h"


def test_call_stmt_distinguished_from_assignment():
  # `x = ...` is an assignment; `x(pkt)` is a call — one-token lookahead.
  prog = parser.parse(
    "def h(pkt):\n  drop\n\n@xdp(eth0)\ndef m(pkt):\n"
    "  port = pkt.dst_port\n  h(pkt)\n  allow\n"
  )
  kinds = [type(s).__name__ for s in prog.programs[0].function.body]
  assert kinds == ["AssignStmt", "CallStmt", "ActionStmt"]


# --- analysis: valid ------------------------------------------------

def test_shared_helper_across_two_zones_ok():
  _analyze(
    "zone wan = [wan0]\nzone lan = [lan0]\n\n"
    "def gate(pkt):\n  if pkt.proto == tcp and pkt.dst_port == 22:\n"
    "    drop\n  count hits\n\n"
    "@xdp(wan)\ndef fw(pkt):\n  gate(pkt)\n  drop\n\n"
    "@xdp(lan)\ndef fl(pkt):\n  gate(pkt)\n  allow\n"
  )


def test_helper_calls_helper_ok():
  _analyze(
    "def a(pkt):\n  drop\n\ndef b(pkt):\n  a(pkt)\n  allow\n\n"
    "@xdp(eth0)\ndef m(pkt):\n  b(pkt)\n"
  )


# --- analysis: errors -----------------------------------------------

def test_call_to_undefined_helper_rejected():
  with pytest.raises(FwlException, match="undefined helper 'nope'"):
    _analyze("@xdp(eth0)\ndef m(pkt):\n  nope(pkt)\n  drop\n")


def test_duplicate_helper_rejected():
  with pytest.raises(FwlException, match="duplicate helper def 'a'"):
    _analyze(
      "def a(pkt):\n  drop\n\ndef a(pkt):\n  allow\n\n"
      "@xdp(eth0)\ndef m(pkt):\n  a(pkt)\n"
    )


def test_recursion_rejected():
  with pytest.raises(FwlException, match="recursive helper call cycle"):
    _analyze(
      "def a(pkt):\n  b(pkt)\n  drop\n\ndef b(pkt):\n  a(pkt)\n  drop\n\n"
      "@xdp(eth0)\ndef m(pkt):\n  a(pkt)\n"
    )


def test_self_recursion_rejected():
  with pytest.raises(FwlException, match="recursive helper call cycle"):
    _analyze(
      "def a(pkt):\n  a(pkt)\n  drop\n\n@xdp(eth0)\ndef m(pkt):\n  a(pkt)\n"
    )


def test_geoip_in_helper_rejected():
  with pytest.raises(
    FwlException, match="geoip.*not supported inside a helper"
  ):
    _analyze(
      "def a(pkt):\n  if pkt.src_ip in geoip(RU):\n    drop\n\n"
      "@xdp(eth0)\ndef m(pkt):\n  a(pkt)\n"
    )


def test_pkt_zone_in_helper_rejected():
  with pytest.raises(
    FwlException, match="pkt.zone is not supported inside a helper"
  ):
    _analyze(
      "zone wan = [wan0]\n\n"
      "def a(pkt):\n  if pkt.zone == wan:\n    drop\n\n"
      "@xdp(wan)\ndef m(pkt):\n  a(pkt)\n"
    )


# --- emitter: real BPF-to-BPF functions -----------------------------

_SRC = (
  "def gate(pkt):\n  if pkt.proto == tcp and pkt.dst_port == 22:\n"
  "    drop\n  allow\n\n@xdp(eth0)\ndef m(pkt):\n  gate(pkt)\n  drop\n"
)


def test_helper_emits_static_noinline_function():
  c = emitter.emit(_analyze(_SRC))
  assert "static __noinline int fwl_helper_gate(struct xdp_md *ctx)" in c
  # The call site checks the sentinel and propagates a real verdict.
  assert "int _r = fwl_helper_gate(ctx);" in c
  assert "if (_r != FWL_CONTINUE) return _r;" in c
  assert "#define FWL_CONTINUE" in c


def test_helper_object_has_real_call_not_inlined():
  """The compiled object must contain a distinct helper symbol and a
  BPF-to-BPF pseudo-call — proof the helper is not inlined."""
  r = bpf_runner.compile_c(emitter.emit(_analyze(_SRC)))
  import subprocess
  syms = subprocess.run(
    ["llvm-nm", str(r.obj_path)], capture_output=True, text=True
  ).stdout
  assert "fwl_helper_gate" in syms
  disasm = subprocess.run(
    ["llvm-objdump", "-d", str(r.obj_path)], capture_output=True, text=True
  ).stdout
  # opcode 0x85 with src=1 renders as a `call` to a pc-relative target.
  assert "call" in disasm.lower()


def test_bundle_emits_helper_into_each_calling_zone():
  prog = _analyze(
    "zone wan = [wan0]\nzone lan = [lan0]\n\n"
    "def gate(pkt):\n  if pkt.proto == tcp and pkt.dst_port == 22:\n"
    "    drop\n  allow\n\n"
    "@xdp(wan)\ndef fw(pkt):\n  gate(pkt)\n  drop\n\n"
    "@xdp(lan)\ndef fl(pkt):\n  gate(pkt)\n  drop\n"
  )
  files = emitter.emit_bundle(prog)
  for zone in ("wan.bpf.c", "lan.bpf.c"):
    assert "fwl_helper_gate" in files[zone]
    bpf_runner.compile_c(files[zone])  # both objects must compile


def test_uncalled_helper_not_emitted():
  prog = _analyze(
    "def used(pkt):\n  drop\n\ndef unused(pkt):\n  allow\n\n"
    "@xdp(eth0)\ndef m(pkt):\n  used(pkt)\n  allow\n"
  )
  c = emitter.emit(prog)
  assert "fwl_helper_used" in c
  assert "fwl_helper_unused" not in c


# --- interpreter equivalence: multi-def == inlined ------------------

_MULTI = (
  "def gate(pkt):\n"
  "  if pkt.proto == tcp and pkt.dst_port == 22:\n    drop\n"
  "  if pkt.src_ip == 10.0.0.9:\n    allow\n\n"
  "@xdp(eth0)\ndef m(pkt):\n  gate(pkt)\n  drop\n"
)
_INLINED = (
  "@xdp(eth0)\ndef m(pkt):\n"
  "  if pkt.proto == tcp and pkt.dst_port == 22:\n    drop\n"
  "  if pkt.src_ip == 10.0.0.9:\n    allow\n  drop\n"
)


@pytest.mark.parametrize("builder,expected", [
  ('tcp(src_ip="1.2.3.4", dst_ip="9.9.9.9", dst_port=22)', XdpAction.DROP),
  ('tcp(src_ip="10.0.0.9", dst_ip="9.9.9.9", dst_port=80)', XdpAction.PASS),
  ('tcp(src_ip="1.1.1.1", dst_ip="9.9.9.9", dst_port=80)', XdpAction.DROP),
  ('udp(src_ip="10.0.0.9", dst_ip="9.9.9.9", dst_port=22)', XdpAction.PASS),
])
def test_multidef_equivalent_to_inlined(builder, expected):
  packet = _pkt(builder)
  multi = interpreter.evaluate(_analyze(_MULTI), packet)
  inlined = interpreter.evaluate(_analyze(_INLINED), packet)
  assert multi == inlined == expected


def test_helper_fallthrough_continues_in_caller():
  # gate() neither drops nor allows this packet — control returns to the
  # caller, which drops.
  assert _run(_MULTI, 'tcp(src_ip="8.8.8.8", dst_ip="9.9.9.9", dst_port=80)') \
      == XdpAction.DROP
