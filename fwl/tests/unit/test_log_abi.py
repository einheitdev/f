"""The `fwl_log_events` record ABI (v0.4 § 6.8).

`fwl_log_events` is one ring buffer for a whole bundle, and
`rule_index` is numbered per zone. Before the zone tag, zone `wan`'s
rule 2 and zone `lan`'s rule 2 wrote the same record and no consumer
could separate them — every logged event in a multi-zone bundle was
ambiguous, with no error anywhere.

Two things have to stay true for the fix to mean anything, and both
fail silently if they stop being true:

  the C the datapath writes and the Python that reads it must describe
    the same bytes. `test_c_layout_matches_python_format` compiles the
    generated struct and asserts every offset against the offsets the
    `struct` format implies, so a field added on one side and not the
    other is a compile error rather than a shifted read.

  two zones must never share an id. That is the one failure mode a
    hash has, and it puts the ambiguity straight back, so the emitter
    refuses the compile.
"""
import re
import shutil
import struct
import subprocess
from pathlib import Path

import pytest

from fwl import analyzer, emitter, log_abi, parser
from fwl.errors import FwlException

_TWO_ZONES = (
  "zone lan = [e0]\n"
  "zone wan = [e1]\n"
  "@xdp(lan)\n"
  "count lan_hits\n"
  "log if pkt.proto == udp and pkt.dst_port == 7801\n"
  "default allow\n"
  "@xdp(wan)\n"
  "count wan_hits\n"
  "log if pkt.proto == udp and pkt.dst_port == 7802\n"
  "default allow\n"
)

# `__u32 name;` or `__u8 name[2];` inside the generated struct body.
_C_FIELD_RE = re.compile(
  r"^\s*(__u8|__u16|__u32|__u64)\s+(\w+)(?:\[(\d+)\])?;", re.M
)
_C_WIDTH = {"__u8": 1, "__u16": 2, "__u32": 4, "__u64": 8}


def _c_struct_body() -> str:
  """The `struct fwl_log_event { ... }` body from the emitted C."""
  match = re.search(
    r"struct fwl_log_event \{(.*?)\n\};", log_abi.C_DECL, re.S
  )
  assert match is not None, "C_DECL no longer declares the struct"
  return match.group(1)


def _c_fields() -> list[tuple[str, int]]:
  """(name, total byte width) for each field, in declaration order."""
  out = []
  for ctype, name, count in _C_FIELD_RE.findall(_c_struct_body()):
    out.append((name, _C_WIDTH[ctype] * int(count or 1)))
  return out


def _format_offsets() -> list[int]:
  """Byte offset of each non-pad item in `log_abi.FORMAT`."""
  offsets = []
  cursor = 0
  for char in log_abi.FORMAT.lstrip("<"):
    if char != "x":
      offsets.append(cursor)
    cursor += struct.calcsize(char)
  return offsets


def test_python_format_is_the_declared_size():
  assert struct.calcsize(log_abi.FORMAT) == log_abi.SIZE


def test_c_layout_matches_python_format():
  """Compile the generated struct and check every offset.

  The C side is the authority on layout (it is what the verifier loads
  and what writes the bytes); this asserts the `struct` format the
  Python consumers unpack lands on the same offsets. Nothing here
  restates the layout — the expected offsets are derived from
  `log_abi.FORMAT`, so the two definitions are checked against each
  other rather than against a third copy in a test.
  """
  cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
  if cc is None:
    pytest.skip("no C compiler available")
  fields = _c_fields()
  # `pad` exists only to make the C layout explicit; the format spells
  # it as trailing "x" bytes, which carry no offset of their own.
  named = [(n, w) for n, w in fields if n != "pad"]
  offsets = _format_offsets()
  assert len(named) == len(offsets), (
    f"C declares {len(named)} readable fields, FORMAT unpacks "
    f"{len(offsets)}"
  )
  asserts = "\n".join(
    f'_Static_assert(offsetof(struct fwl_log_event, {name}) == {off},'
    f' "{name} offset");'
    for (name, _w), off in zip(named, offsets)
  )
  source = f"""\
#include <stddef.h>
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
struct fwl_log_event {{{_c_struct_body()}
}};
{asserts}
_Static_assert(sizeof(struct fwl_log_event) == {log_abi.SIZE},
               "record size");
"""
  with __import__("tempfile").TemporaryDirectory() as tmp:
    src = Path(tmp) / "abi.c"
    src.write_text(source, encoding="utf-8")
    result = subprocess.run(
      [cc, "-c", "-o", str(Path(tmp) / "abi.o"), str(src)],
      capture_output=True,
    )
  assert result.returncode == 0, result.stderr.decode("utf-8", "replace")


def test_zone_id_is_stable_and_nonzero():
  # Pinned vectors: the id is written into compiled objects and into
  # every bundle's manifest, so changing the hash silently would make
  # a previously written table wrong.
  assert log_abi.zone_id("lan") == 0x56608010
  assert log_abi.zone_id("wan") == 0x2BE2E301
  for name in ("lan", "wan", "a", "b", "zone-with-dashes", "t"):
    assert log_abi.zone_id(name) != log_abi.ZONE_ID_NONE


def test_zone_id_depends_on_the_name_not_the_position():
  """The reason this is a hash and not an ordinal.

  Adding a zone ahead of `wan` must not change what `wan`'s events are
  tagged with: an id that shifts renumbers history, and a table read
  back against the previous compilation names the wrong zone.
  """
  first = _zone_ids("zone wan = [e1]\n@xdp(wan)\nallow\n")
  second = _zone_ids(
    "zone lan = [e0]\nzone wan = [e1]\n"
    "@xdp(lan)\nallow\n@xdp(wan)\nallow\n"
  )
  assert first["wan"] == second["wan"]


def _zone_ids(source: str) -> dict[str, int]:
  program = analyzer.analyze(parser.parse(source))
  return log_abi.zone_ids(emitter.emitting_zone_names(program))


def test_decode_round_trips():
  raw = struct.pack(
    log_abi.FORMAT, log_abi.MAGIC, log_abi.VERSION, log_abi.SIZE,
    123456789, log_abi.zone_id("wan"), 2,
    0x0A63B001, 0x0A63B002, 4444, 7802, 17, 0x03,
  )
  ev = log_abi.decode(raw)
  assert ev["zone_id"] == log_abi.zone_id("wan")
  assert ev["rule_index"] == 2
  assert ev["dst_port"] == 7802
  assert ev["proto"] == 17


def _record(**over) -> bytes:
  vals = dict(
    magic=log_abi.MAGIC, version=log_abi.VERSION,
    event_size=log_abi.SIZE, ts=1, zone=log_abi.zone_id("lan"),
    rule=0, sip=0, dip=0, sport=0, dport=0, proto=17, flags=0,
  )
  vals.update(over)
  return struct.pack(
    log_abi.FORMAT, vals["magic"], vals["version"], vals["event_size"],
    vals["ts"], vals["zone"], vals["rule"], vals["sip"], vals["dip"],
    vals["sport"], vals["dport"], vals["proto"], vals["flags"],
  )


@pytest.mark.parametrize("over,needle", [
  ({"magic": 0xDEADBEEF}, "magic"),
  ({"version": log_abi.VERSION + 1}, "version"),
  ({"event_size": log_abi.SIZE + 8}, "bytes"),
])
def test_decode_refuses_a_foreign_record(over, needle):
  """A mismatch must be an error, not a plausible reading.

  Every field below still unpacks into a legal-looking value — a real
  rule index, a real port — which is exactly why the header is checked
  before any of them is trusted.
  """
  with pytest.raises(log_abi.LogAbiError) as exc:
    log_abi.decode(_record(**over))
  assert needle in str(exc.value)


def test_decode_refuses_a_short_record():
  with pytest.raises(log_abi.LogAbiError):
    log_abi.decode(_record()[:log_abi.SIZE - 1])


def test_each_zone_stamps_its_own_id():
  """The defect, in emitted form: same rule index, different zones."""
  program = analyzer.analyze(parser.parse(_TWO_ZONES))
  files = emitter.emit_bundle(program)
  lan = files["lan.bpf.c"]
  wan = files["wan.bpf.c"]
  # Both `log` rules are rule 1 of their own zone — the collision the
  # tag exists to break.
  assert "ev->rule_index = 1;" in lan
  assert "ev->rule_index = 1;" in wan
  assert f"ev->zone_id = 0x{log_abi.zone_id('lan'):08X}u;" in lan
  assert f"ev->zone_id = 0x{log_abi.zone_id('wan'):08X}u;" in wan


def test_single_object_emission_still_tags_its_zone():
  """`@xdp(t)` with no zone declarations still identifies itself.

  The BPF oracle compiles one object at a time from exactly this
  shape; a record tagged 0 there would be untraceable.
  """
  src = emitter.emit(analyzer.analyze(parser.parse(
    "@xdp(t)\nlog if pkt.proto == udp\ndefault allow\n"
  )))
  assert f"ev->zone_id = 0x{log_abi.zone_id('t'):08X}u;" in src


def test_colliding_zone_ids_fail_the_compile(monkeypatch):
  """A hash collision must stop the build, not reach a bundle.

  Forced by making the hash constant: the check is the subject here,
  and no two short names actually collide under FNV-1a.
  """
  monkeypatch.setattr(log_abi, "zone_id", lambda name: 0x11111111)
  program = analyzer.analyze(parser.parse(_TWO_ZONES))
  with pytest.raises(FwlException) as exc:
    emitter.emit_bundle(program)
  message = str(exc.value)
  assert "lan" in message and "wan" in message
  assert "zone id" in message


def test_reserved_zero_id_fails_the_compile(monkeypatch):
  monkeypatch.setattr(
    log_abi, "zone_id", lambda name: log_abi.ZONE_ID_NONE
  )
  program = analyzer.analyze(parser.parse(_TWO_ZONES))
  with pytest.raises(FwlException) as exc:
    emitter.emit_bundle(program)
  assert "reserved zone id 0" in str(exc.value)


def test_shared_header_carries_the_lookup_table():
  program = analyzer.analyze(parser.parse(_TWO_ZONES))
  header = emitter.emit_bundle(program)["fwl_shared.h"]
  assert f"0x{log_abi.zone_id('lan'):08X}  lan" in header
  assert f"0x{log_abi.zone_id('wan'):08X}  wan" in header
