"""The `fwl_log_events` record layout, stated once (v0.4 § 6.8).

`fwl_log_events` is a single ring buffer shared by every zone object in
a bundle. That is the right shape — it is fixed size and genuinely
bundle-wide — but it means a record's `rule_index` alone is ambiguous:
rule indices are numbered per zone, so zone `wan`'s rule 2 and zone
`lan`'s rule 2 write the same number into the same ring. Every record
therefore carries its emitting zone, and `(zone_id, rule_index)` is the
identity of a logged rule.

Both halves of the ABI live here — the C the emitter stamps into every
zone object, and the `struct` format its Python consumers unpack — so
the two cannot drift apart in a way that reads as plausible data.
`test_log_abi.py` asserts they agree field for field.
"""
from __future__ import annotations

import struct

# "FLGE". Present in every record so a consumer reading a ring written
# by a different layout fails loudly instead of misparsing it.
MAGIC = 0x464C4745
# Bumped by any change to the field list, their order, or their
# meaning. A consumer that does not know a version must refuse the
# record, not read the prefix it recognises.
VERSION = 1
# The `zone_id` of no zone. `zone_id()` never returns it, and the
# emitter refuses to compile a unit whose zone hashes to it, so a
# record carrying 0 is a consumer-side signal ("unattributed"), never
# something the datapath writes.
ZONE_ID_NONE = 0

# Field order and widths must match `C_DECL` exactly. "<" pins
# little-endian and, as a side effect, disables struct's own alignment
# padding — so every pad byte the C layout has is written out here
# explicitly ("xx" for `__u8 pad[2]`).
FORMAT = "<IHHQIIIIHHBBxx"
_STRUCT = struct.Struct(FORMAT)
SIZE = _STRUCT.size

_FNV1A_OFFSET_BASIS = 0x811C9DC5
_FNV1A_PRIME = 0x01000193
_U32_MASK = 0xFFFFFFFF


class LogAbiError(RuntimeError):
  """A ring-buffer record that is not a log event of this ABI.

  Raised rather than skipped: a record whose header does not match is
  evidence that the reader and the loaded datapath disagree about the
  layout, and every subsequent record is suspect too.
  """


def zone_id(zone_name: str) -> int:
  """The 32-bit identifier a log event carries for `zone_name`.

  FNV-1a over the UTF-8 name. A hash, not an ordinal, on purpose: an
  ordinal is a property of a zone's POSITION in the unit, so inserting
  a zone renumbers every zone after it and a table read back against
  the previous compilation names the wrong zone — silently, which is
  the whole defect class this field exists to close. A hash is a
  property of the name, which is the same thing every other artifact
  already keys on (`fwl_counters_<zone>`, the manifest, `pkt.zone`).

  A hash's one failure mode is a collision, and the emitter turns that
  into a compile error over the unit's zone set, so it cannot happen
  silently either.
  """
  h = _FNV1A_OFFSET_BASIS
  for byte in zone_name.encode("utf-8"):
    h = ((h ^ byte) * _FNV1A_PRIME) & _U32_MASK
  return h


def decode(raw: bytes) -> dict:
  """Unpack one ring-buffer record, or raise `LogAbiError`.

  Validates the header before reading anything else. The check is the
  point of the header: without it a layout change produces a record
  that unpacks into plausible wrong values — a rule index that names a
  real rule, an IP that looks like an address — and nothing anywhere
  reports an error.
  """
  if len(raw) < SIZE:
    raise LogAbiError(
      f"log event is {len(raw)} bytes, ABI v{VERSION} needs {SIZE}"
    )
  (magic, version, event_size, timestamp_ns, zid, rule_index,
   src_ip, dst_ip, src_port, dst_port, proto,
   flags) = _STRUCT.unpack(raw[:SIZE])
  if magic != MAGIC:
    raise LogAbiError(
      f"log event magic 0x{magic:08x}, expected 0x{MAGIC:08x} — the "
      f"loaded datapath does not write this ABI"
    )
  if version != VERSION:
    raise LogAbiError(
      f"log event ABI version {version}, this consumer reads "
      f"v{VERSION}"
    )
  if event_size != SIZE:
    raise LogAbiError(
      f"log event declares {event_size} bytes, ABI v{VERSION} is "
      f"{SIZE}"
    )
  return {
    "timestamp_ns": timestamp_ns,
    "zone_id": zid,
    "rule_index": rule_index,
    "src_ip": src_ip,
    "dst_ip": dst_ip,
    "src_port": src_port,
    "dst_port": dst_port,
    "proto": proto,
    "flags": flags,
  }


def zone_ids(zone_names) -> dict[str, int]:
  """The name -> id table for `zone_names`, in first-seen order.

  This is what a bundle ships as `manifest.json["zone_ids"]`: a numeric
  id with no lookup table is not an improvement over no id at all, so
  the table travels with the artifact the ids were compiled into.
  """
  table: dict[str, int] = {}
  for name in zone_names:
    if name not in table:
      table[name] = zone_id(name)
  return table


# The C the emitter stamps into every zone object that logs. Kept
# adjacent to FORMAT above: the two are one decision, and reviewing
# them side by side is the only cheap way to keep them in step.
C_DECL = f"""\
// FWL log-event ABI v{VERSION} (v0.4 § 6.8). A consumer validates
// `magic` and `version` before reading any other field: a layout
// change that goes unnoticed reads back as plausible wrong data —
// a rule index that names a real rule — rather than as an error.
#define FWL_LOG_EVENT_MAGIC 0x{MAGIC:08X}u
#define FWL_LOG_EVENT_VERSION {VERSION}u

struct fwl_log_event {{
  __u32 magic;
  __u16 version;
  // sizeof(struct fwl_log_event), so a consumer can reject a record
  // whose length it does not recognise instead of misreading it.
  __u16 event_size;
  __u64 timestamp_ns;
  // FNV-1a 32 of the emitting zone's name. `fwl_log_events` is one
  // ring for the whole bundle and `rule_index` is numbered per zone,
  // so (zone_id, rule_index) — never rule_index alone — identifies a
  // logged rule. `manifest.json["zone_ids"]` maps this back to a name.
  __u32 zone_id;
  __u32 rule_index;
  __u32 src_ip;
  __u32 dst_ip;
  __u16 src_port;
  __u16 dst_port;
  __u8  proto;
  __u8  flags;
  // Written explicitly: ring-buffer memory is not zeroed on reserve,
  // so unset padding would hand userspace whatever the previous
  // record left there.
  __u8  pad[2];
}};

struct {{
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 20);
}} fwl_log_events SEC(".maps");
"""
