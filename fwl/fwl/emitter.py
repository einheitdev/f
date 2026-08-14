"""BPF C code generator.

Given an analyzed AST, emits a C source string that clang compiles to
a verifier-accepted XDP program. Bounds checks at every layer; IPv4
IHL handled correctly; TCP/UDP ports in host byte order.

The emitter analyzes the program once to decide which protocol layers
need parsing. Layers not referenced are skipped to keep the BPF
instruction budget low. Each parse step gates its pointer dereference
with an inline bounds check; on failure, the relevant field defaults
to 0 (or the rule's condition naturally evaluates to false).
"""
from __future__ import annotations

import dataclasses
import enum
import re

from . import ast
from . import log_abi
from . import splitter
from .errors import FwlError, FwlException


class MapScope(enum.Enum):
  """Whether a generated BPF map's contents are bundle-wide or per-zone.

  SHARED — the map keeps one bundle-global name, so every zone object
    in a bundle resolves it (through the common bpffs pin root) to the
    SAME kernel map. Legitimate only when the contents are meaningful
    bundle-wide by construction: keyed by a flow tuple, holding one
    unit-wide setting, or sized from a constant.

  PRIVATE — the map's size, or the meaning of its indices, comes from
    ONE zone's analysis. Two zones must never land on one kernel map,
    so the name carries the zone (or the map is never pinned at all
    and the object boundary isolates it).

  There is no third value and no default. A map that reaches the
  generated source without a scope is a hard compile error, because
  the failure mode of forgetting is silent: two zones' objects load
  cleanly, share one kernel map, and report each other's numbers.
  """
  SHARED = "shared"
  PRIVATE = "private"


class MapLifetime(enum.Enum):
  """Whether a map's CONTENTS still mean anything under the next policy.

  A second, independent axis from `MapScope`. Scope answers "may two
  zones of ONE bundle land on one kernel map?"; lifetime answers "may
  the contents of this map, left pinned in bpffs by a PREVIOUS
  compilation, be carried into the next one?" The two do not coincide:
  `fwl_rl_g<slot>` is SHARED — bundle-wide by declaration — and still
  POLICY, because slot 0 of the next policy is a different rule.

  POLICY — the size, or the meaning of an index, or the contents come
    from ONE compilation's analysis. A pin left by a previous policy is
    worthless and actively misleading: adopting it reports a dead
    policy's numbers against live rules, or fails the load outright when
    the shape moved. `fd` discards these before every load.

  FLOW — keyed by something a policy does not define (today: the flow
    5-tuple), so an entry means the same thing under any policy. These
    are what `fd` may adopt across a policy change or a process
    restart, and dropping them drops established connections.

  There is no default, for the same reason MapScope has none: a map
  whose lifetime nobody declared would be adopted by whatever the
  daemon's fallback happens to be, and being wrong that way is silent.
  Discarding is the safe direction — at worst it costs state that could
  have been kept — so a new map that nobody thought about must land in
  POLICY, which is what `_MapKind` requiring the field guarantees.
  """
  POLICY = "policy"
  FLOW = "flow"


@dataclasses.dataclass(frozen=True)
class _MapKind:
  """One map the emitter can declare, with its sharing scope declared.

  `base` is a regex fullmatched against the map name as written at the
  declaration site (before any zone qualification). `private_name` is
  the zone-qualified name template for a PRIVATE map — `{zone}` plus
  `\\1`..`\\9` backreferences into `base`'s groups — or None when the
  map is never pinned, so no name change is needed for two zones to
  keep separate kernel maps.

  `lifetime` says whether the contents survive a recompilation, and
  `lifetime_why` says on what grounds. Both are required: the daemon
  reads the FLOW names out of the bundle manifest and discards every
  other pin under its root, so a row that skipped the question would
  have its map silently discarded (or, under the old prefix-list
  loader, silently adopted).
  """
  base: str
  scope: MapScope
  why: str
  lifetime: MapLifetime
  lifetime_why: str
  private_name: str | None = None


# EVERY map the emitter can declare appears here, with its sharing
# stated. This table is where a map's sharing is decided — not the
# declaration site, and not a rewrite pass over the generated text.
#
# A map that reaches the output without a row here fails the compile
# (`_check_map_scopes`). That is deliberate: an allowlist of the maps
# that are private makes *sharing* the default, and the same defect
# has been found three times under that default (fwl_counters,
# fwl_log_sample, and again past a docstring explaining it). Two of the
# three were omissions rather than misjudgements, so the protection
# has to be against omission.
_MAP_KINDS: tuple[_MapKind, ...] = (
  _MapKind(
    r"conntrack", MapScope.SHARED,
    "keyed by the flow 5-tuple: a flow established on one zone is "
    "ESTABLISHED for every other zone (v0.4 § 6.2)",
    lifetime=MapLifetime.FLOW,
    lifetime_why=(
      "an established connection is a fact about the wire, not about "
      "the policy that admitted it. Discarding this map on a reload "
      "or a restart drops every established connection, which is the "
      "outage the state exists to prevent. The daemon adopts it only "
      "when the incoming bundle declares the same definition, and "
      "sweeps it against the GC's own age rule before arming the "
      "datapath"
    ),
  ),
  _MapKind(
    r"fwl_nat", MapScope.SHARED,
    "keyed by the flow 5-tuple; the egress zone installs the reply "
    "mapping that the ingress zone consumes",
    lifetime=MapLifetime.FLOW,
    lifetime_why=(
      "same key, same argument, and the consequence of losing it is "
      "worse than losing conntrack: a reply whose mapping is gone is "
      "not merely re-evaluated, it is forwarded un-translated to a "
      "host that never sent the request"
    ),
  ),
  _MapKind(
    r"fwl_nat_stats", MapScope.SHARED,
    "counts events of the one bundle-wide fwl_nat table, so it has to "
    "be the one bundle-wide tally: a per-zone copy would report the "
    "refusals of whichever zone happened to translate, not of the "
    "table. Slots are numbered by the emitter's own header, not by a "
    "policy, so the same slot means the same event in every zone",
    lifetime=MapLifetime.POLICY,
    lifetime_why=(
      "a counter, and counters restart from zero across a reload for "
      "the same reason every other one does — a number carried over "
      "from a policy that is no longer running is attributed to rules "
      "that never produced it. The mappings themselves are FLOW and "
      "are inherited; the tally of what happened to them is not"
    ),
  ),
  _MapKind(
    r"fwl_route_stats", MapScope.SHARED,
    "counts what the ONE routing table under this box did to forwarded "
    "frames. Routing is a property of the host, not of a zone, so a "
    "per-zone copy would report whichever zone happened to forward "
    "rather than what the box does; slots are numbered by the "
    "emitter's own header, so a slot means the same event everywhere",
    lifetime=MapLifetime.POLICY,
    lifetime_why=(
      "a counter, and every other counter restarts from zero across a "
      "reload for the same reason: a number carried over from a policy "
      "that is no longer running is attributed to a redirect that "
      "never produced it"
    ),
  ),
  _MapKind(
    r"fwl_nat_cfg", MapScope.SHARED,
    "one unit-wide masquerade address, written once by the daemon",
    lifetime=MapLifetime.POLICY,
    lifetime_why=(
      "derived by the daemon at every load from THIS bundle's "
      "redirect topology and the live interface addresses, so nothing "
      "is lost by dropping it — while a stale value would translate "
      "to an address the new policy never named"
    ),
  ),
  _MapKind(
    r"fwl_log_events", MapScope.SHARED,
    "one ring buffer per bundle; every record carries the zone id of "
    "the object that wrote it, so the per-zone rule_index they share "
    "is disambiguated in the record rather than by the map name",
    lifetime=MapLifetime.POLICY,
    lifetime_why=(
      "an unconsumed event carries the rule_index of the compilation "
      "that emitted it; read back against the next policy it names "
      "the wrong rule"
    ),
  ),
  _MapKind(
    r"fwl_devmap_\w+", MapScope.SHARED,
    "named for its DESTINATION zone, so every zone redirecting there "
    "must resolve to the same devmap (v0.4 § 6.3)",
    lifetime=MapLifetime.POLICY,
    lifetime_why=(
      "holds ifindexes the daemon resolves from THIS bundle's "
      "manifest at every load. A zone interface that is not up yet is "
      "skipped rather than written (interfaces may appear after "
      "boot), so an adopted entry would survive un-overwritten and "
      "redirect packets out of an interface the new policy never "
      "named — the one stale-state failure here that misdirects "
      "traffic instead of miscounting it"
    ),
  ),
  _MapKind(
    r"fwl_rl_g\d+", MapScope.SHARED,
    "v0.4 § 6.7 scope=global bucket: a bundle-wide budget BY "
    "DECLARATION, slot numbered unit-wide, sized from the "
    "_RL_MAX_ENTRIES constant and never from a zone's rule count",
    lifetime=MapLifetime.POLICY,
    lifetime_why=(
      "the case where the two axes visibly disagree: bundle-wide by "
      "declaration, yet slot g0 of the next policy is a different "
      "rule with a different budget, and inheriting its accumulated "
      "token state throttles a rule that never spent them"
    ),
  ),
  _MapKind(
    r"fwl_counters", MapScope.PRIVATE,
    "sized by this zone's counter count; slot i means this zone's "
    "i-th counter and nothing else",
    lifetime=MapLifetime.POLICY,
    lifetime_why=(
      "slot i is the i-th counter THIS compilation allocated; the "
      "next one numbers its own"
    ),
    private_name=r"fwl_counters_{zone}",
  ),
  _MapKind(
    r"fwl_log_sample", MapScope.PRIVATE,
    "sized by this zone's rule count; index i is this zone's i-th "
    "rule, and the value is that rule's sampling phase",
    lifetime=MapLifetime.POLICY,
    lifetime_why=(
      "indexed by this compilation's rule numbering, and the value is "
      "a sampling phase that belongs to that rule"
    ),
    private_name=r"fwl_log_sample_{zone}",
  ),
  _MapKind(
    r"fwl_rl_map_(\d+)", MapScope.PRIVATE,
    "addressed by this zone's own rule index (v0.4 § 6.7 scope=zone, "
    "the default)",
    lifetime=MapLifetime.POLICY,
    lifetime_why=(
      "named for a rule index this compilation assigned; the same "
      "name in the next policy is a different rule"
    ),
    private_name=r"fwl_rl_{zone}_\1",
  ),
  _MapKind(
    r"fwl_geoip_(\d+)", MapScope.PRIVATE,
    "one LPM trie per geoip() call site, numbered within the zone",
    lifetime=MapLifetime.POLICY,
    lifetime_why=(
      "numbered per geoip() call site, and repopulated from the "
      "bundle's geoip.json at every load — an adopted trie would "
      "answer for a country the new call site never asked about"
    ),
    private_name=r"fwl_geoip_{zone}_\1",
  ),
  _MapKind(
    r"fwl_scratch", MapScope.PRIVATE,
    "per-packet per-CPU parse metadata for THIS object's tail-call "
    "chain; never pinned, or two split zones would cross-wire their "
    "pipelines (v0.4 § 6.6)",
    lifetime=MapLifetime.POLICY,
    lifetime_why=(
      "never pinned, so nothing of it reaches bpffs to be adopted; "
      "its contents do not outlive a single packet either way"
    ),
  ),
  _MapKind(
    r"fwl_stages", MapScope.PRIVATE,
    "this object's own stage prog_array; never pinned, for the same "
    "reason as fwl_scratch",
    lifetime=MapLifetime.POLICY,
    lifetime_why=(
      "never pinned, and holds program fds belonging to one loaded "
      "object"
    ),
  ),
)


def _map_kind(base_name: str) -> _MapKind | None:
  """The registry row for `base_name`, or None if it has no scope."""
  for kind in _MAP_KINDS:
    if re.fullmatch(kind.base, base_name):
      return kind
  return None


# A `base` pattern that is just a name — no regex metacharacters, so the
# name it matches is the name itself.
_LITERAL_NAME_RE = re.compile(r"\w+")


def persistent_map_names() -> tuple[str, ...]:
  """The pinned map names whose contents survive a policy change.

  Written into every bundle's manifest as `persistent_maps`. `fd`
  reconciles bpffs against this list before each load: a pin named here
  may be adopted (if the incoming bundle declares the same definition),
  and every other pin under its root is removed. The daemon therefore
  never has to re-derive the rule from name prefixes — a second copy of
  this decision, in another language, which is how the same defect got
  in three times before `_MAP_KINDS` existed.

  A FLOW map must be SHARED and must have a literal name: the manifest
  carries names, not patterns, and a per-zone or numbered map cannot be
  keyed by something a policy does not define in the first place. A row
  that breaks either rule is a contradiction in the registry, not a
  compile error in the user's policy, so it raises here.
  """
  names: list[str] = []
  for kind in _MAP_KINDS:
    if kind.lifetime is not MapLifetime.FLOW:
      continue
    if not _LITERAL_NAME_RE.fullmatch(kind.base):
      raise _codegen_error(
        f"_MAP_KINDS row '{kind.base}' is MapLifetime.FLOW but its "
        f"name is a pattern. The bundle manifest carries the "
        f"persistent names literally, so fd can compare them against "
        f"what is pinned in bpffs; give the row a literal name or "
        f"classify it POLICY."
      )
    if kind.scope is not MapScope.SHARED:
      raise _codegen_error(
        f"map '{kind.base}' is MapLifetime.FLOW but MapScope.PRIVATE. "
        f"A map that survives a policy change is keyed by something "
        f"the policy does not define, which is exactly what makes it "
        f"safe to share across zones; a per-zone map cannot qualify."
      )
    names.append(kind.base)
  return tuple(names)


def _codegen_error(message: str) -> FwlException:
  """An emitter-detected error that stops the compile."""
  return FwlException(FwlError(category="codegen", message=message))


def emitting_zone_names(program: ast.Program) -> list[str]:
  """Every zone name a log event of this unit can carry, in order.

  The declared zones plus every @xdp block's zone. They are usually the
  same list, but not always: the degenerate `@xdp(eth0)` unit declares
  no zones at all and still emits events tagged `eth0`, so a table
  built from `program.zones` alone would not resolve its own records.
  """
  names: list[str] = [z.name for z in program.zones]
  for zp in program.programs:
    if zp.zone_name not in names:
      names.append(zp.zone_name)
  return names


def _check_zone_ids(program: ast.Program) -> None:
  """Every zone that can emit a log event needs a distinct `zone_id`.

  Runs on every compile, single-object and bundle alike. A collision is
  the one failure mode `log_abi.zone_id`'s hash has, and it is silent
  in exactly the way the zone tag exists to prevent: two zones' events
  become indistinguishable again, and a consumer reads one zone's rule
  numbering against the other's rules. So it fails the compile, with
  both names in the message, rather than reaching a bundle.
  """
  seen: dict[int, str] = {}
  for name in emitting_zone_names(program):
    tag = log_abi.zone_id(name)
    if tag == log_abi.ZONE_ID_NONE:
      raise _codegen_error(
        f"zone '{name}' hashes to the reserved zone id 0, which a log "
        f"consumer reads as 'unattributed'. Rename the zone."
      )
    other = seen.get(tag)
    if other is not None and other != name:
      raise _codegen_error(
        f"zones '{other}' and '{name}' share log-event zone id "
        f"0x{tag:08X}. Log events identify their zone by a hash of "
        f"its name, so a collision makes the two zones' events "
        f"indistinguishable — the ambiguity the zone tag removes. "
        f"Rename one of them."
      )
    seen[tag] = name


def _unclassified_map_error(name: str) -> FwlException:
  """The error for a map that reached the output with no scope."""
  return _codegen_error(
    f"map '{name}' is emitted with no declared sharing scope. Every "
    f"map the emitter can produce needs a row in emitter._MAP_KINDS "
    f"saying MapScope.SHARED (bundle-wide state: one kernel map for "
    f"every zone) or MapScope.PRIVATE (sized or indexed from one "
    f"zone's analysis, so its name must carry the zone). There is no "
    f"default on purpose: an unclassified map keeps a bundle-global "
    f"pinned name, and zones whose shapes happen to agree then share "
    f"one kernel map with no error and no symptom."
  )


class MapNames:
  """The names one zone object's maps are emitted under.

  Constructed once per object being emitted. `zone` is None for
  single-object emission (`emit()`, the test runner's BPF oracle),
  where nothing is pinned and the base names are unambiguous; in a
  bundle it is the zone being emitted, and every PRIVATE map's name
  carries it.

  Every declaration site takes its name from here, so a map's name and
  its sharing decision are made in one place. Asking for a name the
  registry does not classify raises immediately, before any C is
  generated.
  """

  def __init__(self, zone: str | None = None):
    self.zone = zone
    # Emitted name -> the registry row it came from. `_check_map_scopes`
    # uses this to tell a name that was issued here from one that was
    # hardcoded at a declaration site.
    self.issued: dict[str, _MapKind] = {}

  def qualified(self, base: str) -> str:
    """The emitted name for the map whose base name is `base`."""
    kind = _map_kind(base)
    if kind is None:
      raise _unclassified_map_error(base)
    name = base
    if (
      kind.scope is MapScope.PRIVATE
      and kind.private_name is not None
      and self.zone is not None
    ):
      match = re.fullmatch(kind.base, base)
      assert match is not None
      name = match.expand(kind.private_name.format(zone=self.zone))
    self.issued[name] = kind
    return name

  def counters(self) -> str:
    """The per-zone counter array."""
    return self.qualified("fwl_counters")

  def log_sample(self) -> str:
    """The per-zone log-sampling accumulator."""
    return self.qualified("fwl_log_sample")

  def geoip(self, call_index: int) -> str:
    """The LPM trie backing geoip call site `call_index`."""
    return self.qualified(f"fwl_geoip_{call_index}")

  def rate_limit(self, mod: ast.RateLimit, rule_idx: int) -> str:
    """The bucket map for a rate_limit rule (v0.4 § 6.7)."""
    return self.qualified(_rl_base_name(mod, rule_idx))


_PROTO_TO_IPPROTO = {
  ast.Proto.TCP: "IPPROTO_TCP",
  ast.Proto.UDP: "IPPROTO_UDP",
  ast.Proto.ICMP: "IPPROTO_ICMP",
  ast.Proto.ICMP6: "IPPROTO_ICMPV6",
}


_HEADER = """\
// Generated by fwl. Do not edit.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Minimal ICMP/ICMPv6 header. The kernel's <linux/icmp.h> transitively
// pulls in <linux/if.h> and glibc socket headers that don't compile
// under `clang -target bpf`, so we declare just the two bytes v0.4
// reads (type at offset 0, code at offset 1). The layout is identical
// for ICMPv4 and ICMPv6 (RFC 792 / RFC 4443).
struct fwl_icmphdr {
  __u8 type;
  __u8 code;
};

// ICMPv4 types that carry the datagram that provoked them (RFC 792):
// destination unreachable, source quench, redirect, time exceeded,
// parameter problem. The same five Linux treats as errors when it
// tracks connections. Every other type is a query — its body is its
// own, not a copy of somebody else's packet — so it names no flow.
#define FWL_ICMP_IS_ERROR(t) \\
  ((t) == 3 || (t) == 4 || (t) == 5 || (t) == 11 || (t) == 12)

// The full 8-byte ICMP header, declared alongside the 2-byte one
// because reading a type is not writing a checksum: a struct that
// stops before the checksum field cannot address it, and the ICMP
// checksum covers the embedded datagram an error translation rewrites.
// For type 3 code 4 the second half of `rest` is the next-hop MTU
// (RFC 1191) — read by the host that receives the error, never here.
struct fwl_icmp_err {
  __u8  type;
  __u8  code;
  __u16 check;
  __u32 rest;
};

// The 8 bytes of embedded transport header an ICMP error is required
// to carry ("the first 64 bits of the original datagram's data"). The
// ports sit at the same two offsets in TCP and UDP, which is the only
// reason one struct serves both.
struct fwl_inner_l4 {
  __be16 source;
  __be16 dest;
  __u32 rest;
};

struct fwl_rl_state {
  __u64 ts;
  __u32 count;
};

// 802.1Q VLAN tag (v0.4): the 4 bytes between the Ethernet source MAC
// and the real EtherType. `tci` packs PCP(3) | DEI(1) | VID(12);
// `inner_proto` is the EtherType of the encapsulated L3 frame.
struct fwl_vlanhdr {
  __u16 tci;
  __u16 inner_proto;
};

// v0.4 § 6.5 multi-def: helper `def`s compile to `static __noinline`
// BPF-to-BPF functions returning an XDP action, or this sentinel when
// the helper reached no terminal action (the caller then continues).
// -1 never collides with a real XDP_* code (XDP_ABORTED..XDP_REDIRECT
// are 0..4).
#define FWL_CONTINUE (-1)

// bpf_fib_lookup wants an address family and <linux/bpf.h> does not
// carry one; <sys/socket.h> does not compile under `clang -target bpf`.
#ifndef AF_INET
#define AF_INET 2
#endif
"""


_RL_FIELD_TO_C = {
  "src_ip": "src_ip",
  "dst_ip": "dst_ip",
  "src_port": "src_port",
  "dst_port": "dst_port",
}


# Map the per= field name to the AST field name so _referenced_fields
# can include modifier-keyed fields in its parse-prelude analysis.
_RL_FIELD_TO_AST = {
  "src_ip": ast.FIELD_SRC_IP,
  "dst_ip": ast.FIELD_DST_IP,
  "src_port": ast.FIELD_SRC_PORT,
  "dst_port": ast.FIELD_DST_PORT,
}


_TERMINAL_ACTION_TO_RETURN = {
  ast.Action.ALLOW: "XDP_PASS",
  ast.Action.DROP: "XDP_DROP",
}


# Numeric encoding of conntrack states in the emitted C. NEW is 0 so an
# unparsed (non-IP / IPv6) frame's zero-initialized `ct_state` reads as
# NEW for free. ESTABLISHED/RELATED/INVALID follow. RELATED is produced
# by `fwl_ct_icmp_related`: an ICMP error whose EMBEDDED datagram names
# a tracked flow. Until that existed no packet was ever classified 2,
# so `in [established, related]` was a longer spelling of
# `== established` and path-MTU discovery had no rule that could admit
# it (measured on the rig, l11_05).
_CT_STATE_TO_INT = {
  ast.CtState.NEW: 0,
  ast.CtState.ESTABLISHED: 1,
  ast.CtState.RELATED: 2,
  ast.CtState.INVALID: 3,
}


# The conntrack map's key/value structs and the map declaration. The
# layout MUST byte-match include/f/types.h (struct ConnKey / ConnValue)
# so the emitted program references the daemon's pinned `conntrack` map.
# Addresses are network byte order (raw ip->saddr); ports are host byte
# order (the prelude's bpf_ntohs'd src_port/dst_port). Emitted only when
# the program reads conntrack(pkt).state.
_CONNTRACK_DECL = """\
struct fwl_conn_key {
  __u32 src_addr;
  __u32 dst_addr;
  __u16 src_port;
  __u16 dst_port;
  __u8  proto;
  __u8  pad[3];
};

struct fwl_conn_value {
  __u64 last_seen_ns;
  __u64 packets;
  __u8  state;
  __u8  pad[7];
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 65536);
  __type(key, struct fwl_conn_key);
  __type(value, struct fwl_conn_value);
} conntrack SEC(".maps");
"""


# The RELATED classifier. Emitted with the conntrack map (it is a
# conntrack property, not a NAT one — a policy with no NAT anywhere
# still has to admit the errors its own outbound flows provoke).
_CONNTRACK_HELPERS = """\
// RELATED (FWL_V04_SPEC.md § 4.3): an ICMP error carries no ports of
// its own, so the 5-tuple probe above finds nothing and the packet
// reads NEW — which a `default drop` policy drops, before any NAT gets
// the chance to translate it. That is not a policy mistake to be
// worked around: `conntrack(pkt).state == established` CANNOT match an
// ICMP error, and the only rule that admits one is
// `allow if pkt.proto == icmp`, which admits every ICMP from anywhere.
//
// An error names its flow in the datagram it carries. Probe conntrack
// with that inner tuple, forward and reverse, so an error is RELATED
// whichever end of the flow provoked it. For a translated flow the
// embedded packet is the POST-NAT one, which is the tuple conntrack
// was keyed on — this runs in the prelude, BEFORE de-NAT rewrites it,
// and that ordering is what makes the key match.
//
// Nothing is created and nothing is refreshed: an error is evidence
// ABOUT a flow, not traffic belonging to one, so a flood of them must
// not be able to hold a dead entry open.
static __always_inline int fwl_ct_icmp_related(
    struct iphdr *ip, void *data_end) {
  // A non-first fragment carries no ICMP header, only payload — the
  // same tiny-fragment reasoning the L4 parse is gated on.
  if ((bpf_ntohs(ip->frag_off) & 0x1FFF) != 0) return 0;
  __u32 hlen = ip->ihl * 4;
  if (hlen < sizeof(struct iphdr)) return 0;
  struct fwl_icmp_err *ic = (void *)ip + hlen;
  if ((void *)(ic + 1) > data_end) return 0;
  if (!FWL_ICMP_IS_ERROR(ic->type)) return 0;
  struct iphdr *in_ip = (void *)(ic + 1);
  if ((void *)(in_ip + 1) > data_end) return 0;
  if (in_ip->ihl != 5) return 0;
  struct fwl_inner_l4 *in_l4 = (void *)(in_ip + 1);
  if ((void *)(in_l4 + 1) > data_end) return 0;
  __u16 sp = 0, dp = 0;
  if (in_ip->protocol == IPPROTO_TCP ||
      in_ip->protocol == IPPROTO_UDP) {
    sp = bpf_ntohs(in_l4->source);
    dp = bpf_ntohs(in_l4->dest);
  }
  struct fwl_conn_key _f = {
    .src_addr = in_ip->saddr, .dst_addr = in_ip->daddr,
    .src_port = sp, .dst_port = dp, .proto = in_ip->protocol,
  };
  if (bpf_map_lookup_elem(&conntrack, &_f)) return 1;
  struct fwl_conn_key _r = {
    .src_addr = in_ip->daddr, .dst_addr = in_ip->saddr,
    .src_port = dp, .dst_port = sp, .proto = in_ip->protocol,
  };
  return bpf_map_lookup_elem(&conntrack, &_r) != 0;
}
"""


# Phase 5 NAT mapping table + masquerade config. The key byte-matches
# the conntrack 5-tuple (network-order addresses, host-order ports). The
# value records what a *return* packet must rewrite: FWL_NAT_DNAT
# rewrites the destination back (reply of an egress SNAT/masquerade),
# FWL_NAT_SNAT rewrites the source back (reply of an inbound DNAT).
# Emitted (and bpffs-pinned in a bundle) only when the program uses NAT
# — or, for a bundle, when any zone does, so return traffic de-NATs on
# whichever zone it lands.
#
# `last_seen_ns` is what makes the table collectable. Every datapath
# touch of a mapping stamps it — the egress rewrite that keeps using it
# and the de-NAT of its replies — so the daemon can age it on exactly
# conntrack's rule (idle longer than `timeout_s`, swept every
# `gc_interval_s`) instead of a second policy of its own. Without it
# the map is monotone: 65536 entries is a LIFETIME budget of translated
# flows rather than a concurrency budget, measured on the rig at
# 3613 entries/h from ~1 new flow/s (l11_02).
#
# `fwl_nat_stats` is the visibility half. Every failure this table can
# produce used to be silent — a refused allocation, a full table, a
# reallocated port — which is why a 48 h soak, a NAT soak and 1434
# corpus cases all passed over a defect that breaks a network in a day.
# Slot numbering is fixed HERE, by this header, not by the policy: slot
# i means the same thing under every compilation, which is what lets
# `fctl status` name them.
_NAT_DECL = """\
#define FWL_NAT_SNAT 1
#define FWL_NAT_DNAT 2

#define FWL_NAT_STAT_INSTALLED  0
#define FWL_NAT_STAT_REALLOC    1
#define FWL_NAT_STAT_REFUSED    2
#define FWL_NAT_STAT_TABLE_FULL 3
#define FWL_NAT_STAT_DENAT      4
#define FWL_NAT_STAT_ICMPERR    5
#define FWL_NAT_STAT_SLOTS      6

// The port range the NAT owns. A source port is reallocated out of it
// only when the port the guest chose is already spoken for by a
// DIFFERENT flow toward the same peer; the preference is still to
// preserve. RFC 6335 dynamic range, 16384 ports, masked rather than
// divided so the selection is a single AND.
#define FWL_NAT_PORT_BASE   49152u
#define FWL_NAT_PORT_MASK   0x3fffu
#define FWL_NAT_ALLOC_TRIES 8

struct fwl_nat_key {
  __u32 src_addr;
  __u32 dst_addr;
  __u16 src_port;
  __u16 dst_port;
  __u8  proto;
  __u8  pad[3];
};

struct fwl_nat_value {
  __u64 last_seen_ns;
  __u32 new_addr;
  __u16 new_port;
  __u8  nat_type;
  __u8  pad;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 65536);
  __type(key, struct fwl_nat_key);
  __type(value, struct fwl_nat_value);
} fwl_nat SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, FWL_NAT_STAT_SLOTS);
  __type(key, __u32);
  __type(value, __u64);
} fwl_nat_stats SEC(".maps");

struct fwl_nat_cfg {
  __u32 masq_addr;
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct fwl_nat_cfg);
} fwl_nat_cfg SEC(".maps");
"""


# NAT rewrite + checksum helpers. XDP has no bpf_l3/l4_csum_replace (skb
# only), so checksums are updated with bpf_csum_diff: the IP header is
# recomputed over its fixed 20 bytes; L4 checksums are updated
# incrementally (RFC 1624) for the changed pseudo-header fields. Only
# the no-IP-options common case (ihl == 5) is rewritten.
_NAT_HELPERS = """\
static __always_inline __u16 fwl_csum_fold(__u64 sum) {
  sum = (sum & 0xffffffff) + (sum >> 32);
  sum = (sum & 0xffff) + (sum >> 16);
  sum = (sum & 0xffff) + (sum >> 16);
  return (__u16)sum;
}

static __always_inline struct iphdr *fwl_find_ipv4(
    struct xdp_md *ctx, __u32 *ip_off) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end) return 0;
  __u16 h_proto = eth->h_proto;
  __u32 off = sizeof(*eth);
  if (h_proto == bpf_htons(ETH_P_8021Q)) {
    struct fwl_vlanhdr *vh = (void *)(eth + 1);
    if ((void *)(vh + 1) > data_end) return 0;
    h_proto = vh->inner_proto;
    off += sizeof(*vh);
  }
  if (h_proto != bpf_htons(ETH_P_IP)) return 0;
  struct iphdr *ip = (void *)((__u8 *)data + off);
  if ((void *)(ip + 1) > data_end) return 0;
  if (ip->ihl != 5) return 0;
  *ip_off = off;
  return ip;
}

static __always_inline void fwl_fix_ip_csum(struct iphdr *ip) {
  ip->check = 0;
  __u64 sum = bpf_csum_diff(0, 0, (__be32 *)ip, sizeof(struct iphdr), 0);
  ip->check = ~fwl_csum_fold(sum);
}

// Update a TCP/UDP checksum after an address and/or port rewrite,
// incrementally (RFC 1624). All operands are read in native byte order
// exactly as the checksum field is read/written, so the ones-complement
// update stays self-consistent regardless of host endianness. Unchanged
// fields pass old == new (zero delta).
static __always_inline __u16 fwl_l4_fix(
    __u16 check, __be32 old_a, __be32 new_a,
    __be16 old_p, __be16 new_p) {
  __u16 *ow = (__u16 *)&old_a;
  __u16 *nw = (__u16 *)&new_a;
  __u32 sum = (__u16)~check;
  sum += (__u16)~ow[0];
  sum += (__u16)~ow[1];
  sum += nw[0];
  sum += nw[1];
  if (old_p != new_p) {
    sum += (__u16)~old_p;
    sum += new_p;
  }
  sum = (sum & 0xffff) + (sum >> 16);
  sum = (sum & 0xffff) + (sum >> 16);
  return ~sum;
}

// Incremental ones-complement arithmetic (RFC 1624), split into a
// delta accumulator and a single application. `fwl_l4_fix` folds one
// address+port pair, which is all a TCP/UDP rewrite ever changes; an
// ICMP error's checksum covers FOUR changed words at once — the two
// halves of the embedded address, the embedded port, and the embedded
// IP header's own checksum — so the parts are separated here and
// folded once at the end.
static __always_inline __u32 fwl_csum_delta16(__be16 old_w, __be16 new_w) {
  return (__u32)(__u16)~old_w + (__u32)(__u16)new_w;
}

static __always_inline __u32 fwl_csum_delta32(__be32 old_w, __be32 new_w) {
  __u16 *o = (__u16 *)&old_w;
  __u16 *n = (__u16 *)&new_w;
  return fwl_csum_delta16(o[0], n[0]) + fwl_csum_delta16(o[1], n[1]);
}

// Two folds are enough: the accumulated delta of five 16-bit words
// cannot exceed 6 * 0xffff, so the first fold leaves at most 0x10000.
static __always_inline __u16 fwl_csum_apply(__u16 check, __u32 delta) {
  __u32 sum = (__u32)(__u16)~check + delta;
  sum = (sum & 0xffff) + (sum >> 16);
  sum = (sum & 0xffff) + (sum >> 16);
  return ~sum;
}

static __always_inline void fwl_nat_stat(__u32 slot) {
  __u64 *c = bpf_map_lookup_elem(&fwl_nat_stats, &slot);
  if (c) __sync_fetch_and_add(c, 1);
}

// Spread a flow over the NAT-owned port range. Only ever used to pick a
// REPLACEMENT port, so the requirement is that two flows colliding on
// one guest port diverge immediately, not that the sequence be
// unguessable. FNV-1a-ish mix over the parts of the tuple that differ
// between the colliding flows.
//
// The addresses are bpf_ntohl'd first so the sequence is a function of
// the ADDRESS and not of the machine's byte order: the interpreter
// oracle recomputes this exact sequence from host-order integers, and
// both oracles assert the translated port that reaches the wire.
static __always_inline __u32 fwl_nat_hash(
    __be32 a, __be32 b, __u16 p, __u16 q) {
  __u32 h = 2166136261u;
  h = (h ^ bpf_ntohl(a)) * 16777619u;
  h = (h ^ bpf_ntohl(b)) * 16777619u;
  h = (h ^ (__u32)p) * 16777619u;
  h = (h ^ (__u32)q) * 16777619u;
  h ^= h >> 15;
  return h;
}

// Claim a reply mapping for one translated flow.
//
// `rk` carries the mapping key with the PREFERRED translated port
// already in `dst_port`; `rv` the value a reply must be rewritten to.
// On success the port actually claimed is written to `*got` (host
// order) and 0 is returned; on refusal nothing is installed and -1 is
// returned so the caller can drop the packet instead of translating it
// into someone else's mapping.
//
// v0.4 installed with BPF_ANY and ignored the result, which made a
// collision an OVERWRITE: two guests picking the same ephemeral port
// toward one destination produced one key, and the second guest's
// egress packet silently redirected the first guest's inbound TCP
// payload to itself (l11_01, measured on the wire 20/20 each way).
// BPF_NOEXIST turns that into a detection: the insert either claims
// the key or tells us somebody else holds it.
static __always_inline int fwl_nat_claim(
    struct fwl_nat_key *rk, struct fwl_nat_value *rv,
    int may_realloc, __u16 *got) {
  __u16 want = rk->dst_port;
  long rc = bpf_map_update_elem(&fwl_nat, rk, rv, BPF_NOEXIST);
  if (rc == 0) {
    *got = want;
    fwl_nat_stat(FWL_NAT_STAT_INSTALLED);
    return 0;
  }
  if (rc == -7) {  // -E2BIG: the table is at max_entries
    fwl_nat_stat(FWL_NAT_STAT_TABLE_FULL);
    fwl_nat_stat(FWL_NAT_STAT_REFUSED);
    return -1;
  }
  // Somebody holds the key. If it is this same flow, the mapping is
  // already right — refresh its lifetime stamp and keep the port.
  struct fwl_nat_value *ex = bpf_map_lookup_elem(&fwl_nat, rk);
  if (ex && ex->new_addr == rv->new_addr
      && ex->new_port == rv->new_port
      && ex->nat_type == rv->nat_type) {
    ex->last_seen_ns = rv->last_seen_ns;
    *got = want;
    return 0;
  }
  // A different flow owns it. `dnat to <ip>:<port>` names its port, so
  // moving it would translate to an endpoint the operator never wrote;
  // a source port is ours to choose, so try the NAT-owned range.
  if (may_realloc) {
    __u32 h = fwl_nat_hash(rv->new_addr, rk->src_addr,
                           rv->new_port, rk->src_port);
    #pragma unroll
    for (int i = 0; i < FWL_NAT_ALLOC_TRIES; i++) {
      __u16 cand = (__u16)(FWL_NAT_PORT_BASE
                           + ((h + (__u32)i * 2654435761u)
                              & FWL_NAT_PORT_MASK));
      rk->dst_port = cand;
      rc = bpf_map_update_elem(&fwl_nat, rk, rv, BPF_NOEXIST);
      if (rc == 0) {
        *got = cand;
        fwl_nat_stat(FWL_NAT_STAT_INSTALLED);
        fwl_nat_stat(FWL_NAT_STAT_REALLOC);
        return 0;
      }
      if (rc == -7) {
        fwl_nat_stat(FWL_NAT_STAT_TABLE_FULL);
        fwl_nat_stat(FWL_NAT_STAT_REFUSED);
        return -1;
      }
      // The candidate may be OUR OWN earlier reallocation. Without this
      // check every subsequent packet of a moved flow walks one probe
      // further and claims another port, so a single collision costs a
      // port per packet and the flow is dropped after
      // FWL_NAT_ALLOC_TRIES of them. Measured on the rig: 20 identical
      // SYNs from the colliding host produced 8 mappings and 8
      // reallocations where one of each was correct.
      struct fwl_nat_value *cx = bpf_map_lookup_elem(&fwl_nat, rk);
      if (cx && cx->new_addr == rv->new_addr
          && cx->new_port == rv->new_port
          && cx->nat_type == rv->nat_type) {
        cx->last_seen_ns = rv->last_seen_ns;
        *got = cand;
        return 0;
      }
    }
  }
  rk->dst_port = want;
  fwl_nat_stat(FWL_NAT_STAT_REFUSED);
  return -1;
}

// SNAT/masquerade egress: rewrite source -> new_saddr, fix L3 + L4
// checksums, install the reply mapping so return traffic de-NATs the
// destination back to the original source.
//
// The translated port is the original whenever that is free; when it is
// not, one is taken from the NAT-owned range and the source port is
// rewritten with it. Returns -1 when no mapping could be claimed, and
// then nothing in the frame has been touched: the caller drops. There
// is no third outcome — a translated packet always has a mapping.
static __always_inline int fwl_snat_egress(
    struct xdp_md *ctx, __be32 new_saddr) {
  __u32 ip_off;
  struct iphdr *ip = fwl_find_ipv4(ctx, &ip_off);
  if (!ip) return 0;
  __be32 old_saddr = ip->saddr;
  if (old_saddr == new_saddr) return 0;
  __be32 daddr = ip->daddr;
  __u8 proto = ip->protocol;
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  __u32 l4_off = ip_off + sizeof(struct iphdr);
  __be16 sport = 0, dport = 0;
  int has_ports = 0;
  if (proto == IPPROTO_TCP) {
    struct tcphdr *t = (void *)((__u8 *)data + l4_off);
    if ((void *)(t + 1) > data_end) return 0;
    sport = t->source; dport = t->dest; has_ports = 1;
  } else if (proto == IPPROTO_UDP) {
    struct udphdr *u = (void *)((__u8 *)data + l4_off);
    if ((void *)(u + 1) > data_end) return 0;
    sport = u->source; dport = u->dest; has_ports = 1;
  }
  __u64 now = bpf_ktime_get_ns();
  struct fwl_nat_key rk = {
    .src_addr = daddr, .dst_addr = new_saddr,
    .src_port = bpf_ntohs(dport), .dst_port = bpf_ntohs(sport),
    .proto = proto,
  };
  struct fwl_nat_value rv = {
    .last_seen_ns = now,
    .new_addr = old_saddr, .new_port = bpf_ntohs(sport),
    .nat_type = FWL_NAT_DNAT,
  };
  __u16 got = 0;
  // A frame with no L4 ports (ICMP, anything else) has no port to
  // reallocate: its mapping is keyed on ports 0 and the only honest
  // answer to a collision is to refuse it.
  if (fwl_nat_claim(&rk, &rv, has_ports, &got) != 0) return -1;
  __be16 new_sport = has_ports ? bpf_htons(got) : sport;
  // Track the flow: insert the post-NAT forward 5-tuple so the reply
  // (its reverse 5-tuple) reads `established`, letting a stateful WAN
  // program redirect return traffic back in. On a packet of a flow
  // already tracked, refresh the stamp instead — an entry the GC ages
  // on `last_seen_ns` must actually see the traffic that keeps it
  // alive, or a busy flow is collected out from under itself at
  // `timeout_s` after its FIRST packet.
  struct fwl_conn_key _ct_nk = {
    .src_addr = new_saddr, .dst_addr = daddr,
    .src_port = got, .dst_port = bpf_ntohs(dport),
    .proto = proto,
  };
  struct fwl_conn_value *_ct_ev = bpf_map_lookup_elem(&conntrack, &_ct_nk);
  if (_ct_ev) {
    _ct_ev->last_seen_ns = now;
    _ct_ev->packets += 1;
  } else {
    struct fwl_conn_value _ct_nv = {
      .last_seen_ns = now, .packets = 1, .state = 1,
    };
    bpf_map_update_elem(&conntrack, &_ct_nk, &_ct_nv, BPF_NOEXIST);
  }
  ip->saddr = new_saddr;
  fwl_fix_ip_csum(ip);
  if (proto == IPPROTO_TCP) {
    struct tcphdr *t = (void *)((__u8 *)data + l4_off);
    if ((void *)(t + 1) <= data_end) {
      t->check = fwl_l4_fix(t->check, old_saddr, new_saddr,
                            sport, new_sport);
      t->source = new_sport;
    }
  } else if (proto == IPPROTO_UDP) {
    struct udphdr *u = (void *)((__u8 *)data + l4_off);
    if ((void *)(u + 1) <= data_end) {
      if (u->check != 0) {
        __u16 c = fwl_l4_fix(u->check, old_saddr, new_saddr,
                             sport, new_sport);
        u->check = c ? c : 0xffff;
      }
      u->source = new_sport;
    }
  }
  return 0;
}

static __always_inline int fwl_masquerade(struct xdp_md *ctx) {
  __u32 k = 0;
  struct fwl_nat_cfg *cfg = bpf_map_lookup_elem(&fwl_nat_cfg, &k);
  if (cfg && cfg->masq_addr) return fwl_snat_egress(ctx, cfg->masq_addr);
  return 0;
}

// DNAT ingress: rewrite destination -> new_daddr:new_dport, fix L3 + L4
// checksums, install the reply mapping so return traffic de-NATs the
// source back to the original (public) destination. Returns -1 (and
// leaves the frame untouched) when no mapping could be claimed.
static __always_inline int fwl_dnat_ingress(
    struct xdp_md *ctx, __be32 new_daddr, __be16 new_dport) {
  __u32 ip_off;
  struct iphdr *ip = fwl_find_ipv4(ctx, &ip_off);
  if (!ip) return 0;
  __be32 old_daddr = ip->daddr;
  __be32 saddr = ip->saddr;
  __u8 proto = ip->protocol;
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  __u32 l4_off = ip_off + sizeof(struct iphdr);
  __be16 sport = 0, old_dport = 0;
  if (proto == IPPROTO_TCP) {
    struct tcphdr *t = (void *)((__u8 *)data + l4_off);
    if ((void *)(t + 1) > data_end) return 0;
    sport = t->source; old_dport = t->dest;
  } else if (proto == IPPROTO_UDP) {
    struct udphdr *u = (void *)((__u8 *)data + l4_off);
    if ((void *)(u + 1) > data_end) return 0;
    sport = u->source; old_dport = u->dest;
  } else {
    return 0;
  }
  __u64 now = bpf_ktime_get_ns();
  struct fwl_nat_key rk = {
    .src_addr = new_daddr, .dst_addr = saddr,
    .src_port = bpf_ntohs(new_dport), .dst_port = bpf_ntohs(sport),
    .proto = proto,
  };
  struct fwl_nat_value rv = {
    .last_seen_ns = now,
    .new_addr = old_daddr, .new_port = bpf_ntohs(old_dport),
    .nat_type = FWL_NAT_SNAT,
  };
  __u16 got = 0;
  // No reallocation for a destination NAT: the key's free field is the
  // CLIENT's source port, which belongs to the client, not to us.
  if (fwl_nat_claim(&rk, &rv, 0, &got) != 0) return -1;
  // Track the post-NAT forward tuple, exactly as the source-NAT side
  // does, so the internal server's reply reads `established` on the way
  // back out. Without it a stateful inside zone drops every reply to a
  // port-forwarded connection — the l11_04 defect in its DNAT form.
  struct fwl_conn_key _ct_nk = {
    .src_addr = saddr, .dst_addr = new_daddr,
    .src_port = bpf_ntohs(sport), .dst_port = bpf_ntohs(new_dport),
    .proto = proto,
  };
  struct fwl_conn_value *_ct_ev = bpf_map_lookup_elem(&conntrack, &_ct_nk);
  if (_ct_ev) {
    _ct_ev->last_seen_ns = now;
    _ct_ev->packets += 1;
  } else {
    struct fwl_conn_value _ct_nv = {
      .last_seen_ns = now, .packets = 1, .state = 1,
    };
    bpf_map_update_elem(&conntrack, &_ct_nk, &_ct_nv, BPF_NOEXIST);
  }
  ip->daddr = new_daddr;
  fwl_fix_ip_csum(ip);
  if (proto == IPPROTO_TCP) {
    struct tcphdr *t = (void *)((__u8 *)data + l4_off);
    if ((void *)(t + 1) <= data_end) {
      t->check = fwl_l4_fix(t->check, old_daddr, new_daddr,
                            old_dport, new_dport);
      t->dest = new_dport;
    }
  } else if (proto == IPPROTO_UDP) {
    struct udphdr *u = (void *)((__u8 *)data + l4_off);
    if ((void *)(u + 1) <= data_end) {
      if (u->check != 0) {
        __u16 c = fwl_l4_fix(u->check, old_daddr, new_daddr,
                             old_dport, new_dport);
        u->check = c ? c : 0xffff;
      }
      u->dest = new_dport;
    }
  }
  return 0;
}

// RFC 5508 § 4.2: translate an ICMP error off the datagram embedded in
// it. Returns 1 when the frame was translated, 0 when it was not an
// ICMP error, was truncated below the embedded datagram, or named a
// flow this NAT holds no mapping for — the caller then falls through
// to the ordinary lookup.
//
// An ICMP error carries no ports of its own, so its flow identity is
// the header of the packet that provoked it. For a translated flow
// that embedded packet is what THIS NAT put on the wire, so reversing
// its tuple yields the reply mapping's own key — the same key the
// flow's TCP reply would use. No new state and no second table: the
// mapping that de-NATs the reply de-NATs the error about it.
//
// The rewrite happens in two places at once, and either alone is
// useless. The outer destination is re-addressed to the host behind
// the NAT — without it the error stops at the firewall. The embedded
// header is put back the way that host sent it — without it the error
// arrives describing a connection the host never opened, and every
// stack on earth discards it in silence, which is the same black hole
// as never delivering it at all.
//
// The embedded TRANSPORT checksum is deliberately not touched. Only 8
// bytes of that header travel, so its checksum covers a payload the
// error does not carry: no receiver can validate it, and neither can
// an oracle. A rewrite nothing can check is a rewrite nothing holds to
// account. Linux's nf_nat skips it for the same reason — for TCP the
// checksum field is not even among the 8 bytes.
static __always_inline int fwl_nat_denat_icmp_error(
    struct xdp_md *ctx, __u32 ip_off) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct iphdr *ip = (void *)((__u8 *)data + ip_off);
  if ((void *)(ip + 1) > data_end) return 0;
  struct fwl_icmp_err *ic =
      (void *)((__u8 *)data + ip_off + sizeof(struct iphdr));
  if ((void *)(ic + 1) > data_end) return 0;
  if (!FWL_ICMP_IS_ERROR(ic->type)) return 0;
  struct iphdr *in_ip = (void *)(ic + 1);
  if ((void *)(in_ip + 1) > data_end) return 0;
  // Same restriction the outer parse takes: an embedded header with
  // options would move the ports, and nothing here would find them.
  if (in_ip->ihl != 5) return 0;
  struct fwl_inner_l4 *in_l4 = (void *)(in_ip + 1);
  if ((void *)(in_l4 + 1) > data_end) return 0;
  __u8 in_proto = in_ip->protocol;
  __be16 in_sport = 0, in_dport = 0;
  int in_has_ports = 0;
  if (in_proto == IPPROTO_TCP || in_proto == IPPROTO_UDP) {
    in_sport = in_l4->source;
    in_dport = in_l4->dest;
    in_has_ports = 1;
  }
  // The embedded tuple, reversed: what the reply to that flow looks
  // like, which is exactly how the mapping is keyed.
  struct fwl_nat_key k = {
    .src_addr = in_ip->daddr, .dst_addr = in_ip->saddr,
    .src_port = bpf_ntohs(in_dport), .dst_port = bpf_ntohs(in_sport),
    .proto = in_proto,
  };
  struct fwl_nat_value *v = bpf_map_lookup_elem(&fwl_nat, &k);
  if (!v) return 0;
  // Every datapath touch of a mapping stamps it — this is the de-NAT
  // of a reply like any other, and a flow whose errors are arriving is
  // a flow that has not gone idle.
  v->last_seen_ns = bpf_ktime_get_ns();
  fwl_nat_stat(FWL_NAT_STAT_DENAT);
  fwl_nat_stat(FWL_NAT_STAT_ICMPERR);
  __be32 new_a = v->new_addr;
  __be16 new_p = bpf_htons(v->new_port);
  __u32 d = 0;
  if (v->nat_type == FWL_NAT_DNAT) {
    // The error is coming back to a masqueraded host: the embedded
    // packet is the one it SENT, so its source is the translated one.
    __be32 old_in = in_ip->saddr;
    in_ip->saddr = new_a;
    d += fwl_csum_delta32(old_in, new_a);
    if (in_has_ports) {
      d += fwl_csum_delta16(in_l4->source, new_p);
      in_l4->source = new_p;
    }
    __be16 old_ck = in_ip->check;
    in_ip->check = fwl_csum_apply(old_ck, fwl_csum_delta32(old_in, new_a));
    // The embedded IP header's checksum is itself inside the ICMP
    // checksum, so its change folds in too.
    d += fwl_csum_delta16(old_ck, in_ip->check);
    ic->check = fwl_csum_apply(ic->check, d);
    ip->daddr = new_a;
    fwl_fix_ip_csum(ip);
  } else if (v->nat_type == FWL_NAT_SNAT) {
    // The error is heading out to a client of a port forward: the
    // embedded packet is the one the CLIENT sent, so its destination
    // is the translated one.
    __be32 old_in = in_ip->daddr;
    in_ip->daddr = new_a;
    d += fwl_csum_delta32(old_in, new_a);
    if (in_has_ports) {
      d += fwl_csum_delta16(in_l4->dest, new_p);
      in_l4->dest = new_p;
    }
    __be16 old_ck = in_ip->check;
    in_ip->check = fwl_csum_apply(old_ck, fwl_csum_delta32(old_in, new_a));
    d += fwl_csum_delta16(old_ck, in_ip->check);
    ic->check = fwl_csum_apply(ic->check, d);
    // The outer source is rewritten to the mapping's public address
    // whatever it was. An error about a forwarded connection may come
    // from the server itself or from a router inside the network, and
    // the client can only accept one address as the peer it is
    // talking to — sending it any other leaks an internal address and
    // is discarded at the far end anyway.
    ip->saddr = new_a;
    fwl_fix_ip_csum(ip);
  }
  return 1;
}

// Return-traffic de-NAT, run before any rule: if this packet matches an
// installed reply mapping, rewrite the recorded side back to the
// original endpoint.
static __always_inline void fwl_nat_denat(struct xdp_md *ctx) {
  __u32 ip_off;
  struct iphdr *ip = fwl_find_ipv4(ctx, &ip_off);
  if (!ip) return;
  __u8 proto = ip->protocol;
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  __u32 l4_off = ip_off + sizeof(struct iphdr);
  __be16 sport = 0, dport = 0;
  // An ICMP error is tried against its EMBEDDED datagram first. It has
  // no ports of its own, so the outer key below reads (router,
  // firewall, 0, 0, icmp) — a key belonging to a ping the guest may
  // have sent to the router, not to the flow the error is about. Which
  // header identifies the flow is not a preference: for an error it is
  // the inner one, and only when there is no mapping for it does the
  // outer tuple (a plain echo reply) get its turn.
  if (proto == IPPROTO_ICMP && fwl_nat_denat_icmp_error(ctx, ip_off))
    return;
  // A frame with no L4 ports still has a mapping — fwl_snat_egress
  // installs one keyed on ports 0 — and de-NAT used to return here
  // without consuming it. That combination is incoherent: the egress
  // half translated an ICMP echo and the return half left the reply
  // addressed to the firewall, so a masqueraded host could ping out and
  // never hear back. Ports stay 0 and only the address is rewritten;
  // ICMP's checksum does not cover the IP header, so nothing else has
  // to change.
  if (proto == IPPROTO_TCP) {
    struct tcphdr *t = (void *)((__u8 *)data + l4_off);
    if ((void *)(t + 1) > data_end) return;
    sport = t->source; dport = t->dest;
  } else if (proto == IPPROTO_UDP) {
    struct udphdr *u = (void *)((__u8 *)data + l4_off);
    if ((void *)(u + 1) > data_end) return;
    sport = u->source; dport = u->dest;
  }
  struct fwl_nat_key k = {
    .src_addr = ip->saddr, .dst_addr = ip->daddr,
    .src_port = bpf_ntohs(sport), .dst_port = bpf_ntohs(dport),
    .proto = proto,
  };
  struct fwl_nat_value *v = bpf_map_lookup_elem(&fwl_nat, &k);
  if (!v) return;
  // The reply half of a live flow. Stamping here is what makes the
  // daemon's sweep an IDLE timeout rather than a lifetime cap: a flow
  // that is still carrying traffic keeps its mapping, and one that
  // stopped loses it at `timeout_s`.
  v->last_seen_ns = bpf_ktime_get_ns();
  fwl_nat_stat(FWL_NAT_STAT_DENAT);
  __be16 new_p = bpf_htons(v->new_port);
  if (v->nat_type == FWL_NAT_DNAT) {
    __be32 old_d = ip->daddr;
    ip->daddr = v->new_addr;
    fwl_fix_ip_csum(ip);
    if (proto == IPPROTO_TCP) {
      struct tcphdr *t = (void *)((__u8 *)data + l4_off);
      if ((void *)(t + 1) <= data_end) {
        t->check = fwl_l4_fix(t->check, old_d, v->new_addr, dport, new_p);
        t->dest = new_p;
      }
    } else if (proto == IPPROTO_UDP) {
      struct udphdr *u = (void *)((__u8 *)data + l4_off);
      if ((void *)(u + 1) <= data_end) {
        if (u->check != 0) {
          __u16 c = fwl_l4_fix(u->check, old_d, v->new_addr, dport, new_p);
          u->check = c ? c : 0xffff;
        }
        u->dest = new_p;
      }
    }
  } else if (v->nat_type == FWL_NAT_SNAT) {
    __be32 old_s = ip->saddr;
    ip->saddr = v->new_addr;
    fwl_fix_ip_csum(ip);
    if (proto == IPPROTO_TCP) {
      struct tcphdr *t = (void *)((__u8 *)data + l4_off);
      if ((void *)(t + 1) <= data_end) {
        t->check = fwl_l4_fix(t->check, old_s, v->new_addr, sport, new_p);
        t->source = new_p;
      }
    } else if (proto == IPPROTO_UDP) {
      struct udphdr *u = (void *)((__u8 *)data + l4_off);
      if ((void *)(u + 1) <= data_end) {
        if (u->check != 0) {
          __u16 c = fwl_l4_fix(u->check, old_s, v->new_addr, sport, new_p);
          u->check = c ? c : 0xffff;
        }
        u->source = new_p;
      }
    }
  }
}
"""


# Routed-forward state (v0.4 § 6.3). Declared by any program that can
# `redirect to <zone>`, whether or not it also translates addresses.
#
# A redirect used to be one `bpf_redirect_map()`, which forwards the
# frame with the Ethernet header it arrived with. That is correct for a
# zone-to-zone hop on ONE L2 segment and wrong for every hop that
# crosses a subnet boundary: the destination MAC is still the firewall's
# own, so the next hop's NIC reports PACKET_OTHERHOST and its IP stack
# discards the frame before any socket sees it. Masquerade toward an
# upstream gateway is that second case by definition — you cannot
# translate the source to your own address and then hand the frame to a
# MAC you never addressed — so it never worked, and a promiscuous
# AF_PACKET witness could not tell (it counts frames a real stack
# drops).
_ROUTE_DECL = """\
#define FWL_ROUTE_STAT_ROUTED    0
#define FWL_ROUTE_STAT_BRIDGED   1
#define FWL_ROUTE_STAT_NO_ROUTE  2
#define FWL_ROUTE_STAT_NO_NEIGH  3
#define FWL_ROUTE_STAT_TTL       4
#define FWL_ROUTE_STAT_OFF_ZONE  5
#define FWL_ROUTE_STAT_SLOTS     6

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, FWL_ROUTE_STAT_SLOTS);
  __type(key, __u32);
  __type(value, __u64);
} fwl_route_stats SEC(".maps");
"""


# `fwl_route_l2` returns this when the box does not route this packet
# out this zone, and the caller forwards the frame unchanged — exactly
# what a redirect did before routing existed. That fallback is what
# keeps a genuine L2 zone hop (and every bridged test, and the corpus,
# where no devmap is populated at all) behaving as it always has.
_ROUTE_HELPERS = """\
#define FWL_ROUTE_BRIDGE (-1)

static __always_inline void fwl_route_stat(__u32 slot) {
  __u64 *c = bpf_map_lookup_elem(&fwl_route_stats, &slot);
  if (c) __sync_fetch_and_add(c, 1);
}

// RFC 1141 incremental checksum update for a TTL decrement. Written out
// rather than recomputed with bpf_csum_diff because the route helpers
// are emitted for programs that carry no NAT, where fwl_fix_ip_csum
// does not exist.
static __always_inline void fwl_ip_decrease_ttl(struct iphdr *ip) {
  __u32 check = (__u32)ip->check;
  check += (__u32)bpf_htons(0x0100);
  ip->check = (__u16)(check + (check >= 0xFFFF));
  ip->ttl--;
}

// Resolve the next hop for an IPv4 frame and address the frame to it.
//
// `zone_ifindex` is the egress interface the policy named (devmap slot
// 0 of the destination zone). The FIB's answer is only usable when it
// agrees: a box with a default route resolves EVERY destination, so
// without this check a zone-to-zone hop on an unrouted segment would be
// stamped with the MACs of the default gateway — which sits on a
// different interface entirely. Route through the zone the policy
// named, or do not route.
//
// Returns an XDP action, or FWL_ROUTE_BRIDGE for "this box does not
// route this packet out this zone" — the caller then forwards the frame
// with the header it arrived with, which is what a redirect has always
// done.
static __always_inline int fwl_route_l2(struct xdp_md *ctx,
                                        __u32 zone_ifindex) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end) return FWL_ROUTE_BRIDGE;
  // A tagged frame's next hop is a property of its VLAN, and rewriting
  // the MACs without touching the tag addresses the right host on the
  // wrong segment. v0.4 routes untagged IPv4 only; everything else
  // keeps the L2-adjacent behaviour. (IPv6 has no conntrack and no NAT
  // here either — same version boundary, stated once.)
  if (eth->h_proto != bpf_htons(ETH_P_IP)) return FWL_ROUTE_BRIDGE;
  struct iphdr *ip = (void *)(eth + 1);
  if ((void *)(ip + 1) > data_end) return FWL_ROUTE_BRIDGE;

  struct bpf_fib_lookup fib = {};
  fib.family = AF_INET;
  fib.l4_protocol = ip->protocol;
  fib.tot_len = bpf_ntohs(ip->tot_len);
  fib.ipv4_src = ip->saddr;
  fib.ipv4_dst = ip->daddr;
  fib.ifindex = ctx->ingress_ifindex;

  long rc = bpf_fib_lookup(ctx, &fib, sizeof(fib), 0);
  if (rc != BPF_FIB_LKUP_RET_SUCCESS) {
    // The three the kernel documents as droppable: a routing table
    // exists, was consulted, and said no. Everything else means "this
    // box is not routing this packet" (no route, forwarding disabled,
    // an encapsulating route, a bad argument) and falls back to the
    // L2-adjacent forward.
    if (rc == BPF_FIB_LKUP_RET_BLACKHOLE ||
        rc == BPF_FIB_LKUP_RET_UNREACHABLE ||
        rc == BPF_FIB_LKUP_RET_PROHIBIT) {
      fwl_route_stat(FWL_ROUTE_STAT_NO_ROUTE);
      return XDP_DROP;
    }
    // The route is known and the next hop's MAC is not. XDP cannot
    // resolve it; the stack can, so hand the frame over and let it send
    // the ARP. Counted because for a SOURCE-TRANSLATED frame the stack
    // will discard it (its source is one of our own addresses, which
    // fib_validate_source rejects as martian) — the resolution happens,
    // this packet does not survive it, and the counter is the only
    // trace.
    if (rc == BPF_FIB_LKUP_RET_NO_NEIGH) {
      fwl_route_stat(FWL_ROUTE_STAT_NO_NEIGH);
      return XDP_PASS;
    }
    return FWL_ROUTE_BRIDGE;
  }

  if (fib.ifindex != zone_ifindex) {
    fwl_route_stat(FWL_ROUTE_STAT_OFF_ZONE);
    return FWL_ROUTE_BRIDGE;
  }

  // Re-derive the packet pointers before touching the frame. The
  // verifier accepts the originals here (bpf_fib_lookup does not move
  // the packet), so this is belt and braces rather than a requirement —
  // but a rewrite through a stale pointer is the kind of bug that shows
  // up as one corrupted frame in a million, and nothing above this line
  // depends on the pointers surviving.
  data = (void *)(long)ctx->data;
  data_end = (void *)(long)ctx->data_end;
  eth = data;
  if ((void *)(eth + 1) > data_end) return FWL_ROUTE_BRIDGE;
  ip = (void *)(eth + 1);
  if ((void *)(ip + 1) > data_end) return FWL_ROUTE_BRIDGE;

  // A router decrements. Below 2 the packet dies here and the ICMP
  // time-exceeded that says so is the stack's job, not ours.
  if (ip->ttl <= 1) {
    fwl_route_stat(FWL_ROUTE_STAT_TTL);
    return XDP_PASS;
  }

  fwl_ip_decrease_ttl(ip);
  __builtin_memcpy(eth->h_dest, fib.dmac, ETH_ALEN);
  __builtin_memcpy(eth->h_source, fib.smac, ETH_ALEN);
  return XDP_REDIRECT;
}
"""


# One per redirect-destination zone: the devmap name has to be a
# compile-time constant at the bpf_redirect_map() call site, so the
# zone's redirect is a function of its own rather than an argument.
_ROUTE_ZONE_TEMPLATE = """\
static __always_inline int fwl_redirect_{zone}(struct xdp_md *ctx) {{
  __u32 _rk = 0;
  __u32 *_rif = bpf_map_lookup_elem(&fwl_devmap_{zone}, &_rk);
  int _ra = _rif ? fwl_route_l2(ctx, *_rif) : FWL_ROUTE_BRIDGE;
  if (_ra == FWL_ROUTE_BRIDGE) {{
    fwl_route_stat(FWL_ROUTE_STAT_BRIDGED);
  }} else if (_ra == XDP_REDIRECT) {{
    fwl_route_stat(FWL_ROUTE_STAT_ROUTED);
  }} else {{
    return _ra;
  }}
  return bpf_redirect_map(&fwl_devmap_{zone}, 0, 0);
}}
"""


# The record layout is `log_abi`'s, not the emitter's: its Python
# consumers unpack the same bytes, and one definition is the only way
# the two stay in step.
_LOG_EVENT_DECL = log_abi.C_DECL


_COUNTER_MAP_DECL_TEMPLATE = """\
struct {{
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, __u32);
  __type(value, __u64);
  __uint(max_entries, {n_slots});
}} {name} SEC(".maps");
"""


_LOG_SAMPLE_MAP_DECL_TEMPLATE = """\
struct {{
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, __u32);
  __type(value, __u64);
  __uint(max_entries, {n_rules});
}} {name} SEC(".maps");
"""


def _walk(node) -> list:
  """Yield all sub-conditions of `node` in pre-order."""
  if node is None:
    return []
  out = [node]
  if isinstance(node, ast.NotOp):
    out.extend(_walk(node.inner))
  elif isinstance(node, (ast.AndOp, ast.OrOp)):
    for child in node.operands:
      out.extend(_walk(child))
  return out


def _referenced_fields(program: ast.Program) -> set[str]:
  """Set of pkt.* field names mentioned anywhere in the program.

  Includes fields used in conditions, rate_limit bucket keys, AND log
  events (the log_event struct carries every L4 field). Any program
  with a `log` rule (or a Tier 2 `log` statement) needs the full
  prelude. Tier 2 statement-position field reads (assignment RHS or
  inner-condition reads) are also collected.
  """
  fields: set[str] = set()
  has_log = False
  for rule in program.rules:
    for n in _walk(rule.condition):
      if isinstance(n, ast.Comparison):
        if isinstance(n.field, ast.FieldRef):
          fields.add(n.field.name)
        if isinstance(n.operand, ast.FieldRef):
          fields.add(n.operand.name)
      elif isinstance(n, ast.BoolField):
        fields.add(n.field.name)
    if rule.modifier is not None:
      fields.add(_RL_FIELD_TO_AST[rule.modifier.per_field])
    if rule.action == ast.Action.LOG:
      has_log = True
  if program.function is not None:
    log_in_func = _collect_tier2_field_refs(
      program.function.body, fields
    )
    if log_in_func:
      has_log = True
  if has_log:
    fields.update({
      ast.FIELD_SRC_IP, ast.FIELD_DST_IP,
      ast.FIELD_SRC_PORT, ast.FIELD_DST_PORT,
      ast.FIELD_TCP_SYN, ast.FIELD_TCP_ACK,
    })
  # Conntrack builds its 5-tuple from the L4 ports and tests the SYN
  # flag for the `invalid` classification, so reading conntrack(pkt)
  # forces those reads into the prelude even when no rule names them.
  if _program_uses_conntrack(program):
    fields.update({
      ast.FIELD_SRC_PORT, ast.FIELD_DST_PORT, ast.FIELD_TCP_SYN,
    })
  return fields


def _program_uses_conntrack(program: ast.Program) -> bool:
  """True iff any rule or Tier 2 statement reads conntrack(pkt).state.

  Mirrors interpreter._program_uses_conntrack; kept separate per the
  oracle-independence rule (the emitter and interpreter do not share
  analysis code), exactly as _is_v6_active mirrors the interpreter's
  _program_touches_v6_surface.
  """
  for rule in program.rules:
    if _cond_uses_conntrack(rule.condition):
      return True
  if program.function is not None:
    if _stmts_use_conntrack(program.function.body):
      return True
  return False


def _stmts_use_conntrack(stmts) -> bool:
  for s in stmts:
    if isinstance(s, ast.AssignStmt):
      if _cond_uses_conntrack(s.rhs):
        return True
    elif isinstance(s, ast.IfStmt):
      if _cond_uses_conntrack(s.cond):
        return True
      if _stmts_use_conntrack(s.body):
        return True
      for cond, body in s.elif_branches:
        if _cond_uses_conntrack(cond):
          return True
        if _stmts_use_conntrack(body):
          return True
      if s.else_body is not None and _stmts_use_conntrack(s.else_body):
        return True
  return False


def _cond_uses_conntrack(node) -> bool:
  if isinstance(node, ast.ConntrackStateCompare):
    return True
  if isinstance(node, ast.NotOp):
    return _cond_uses_conntrack(node.inner)
  if isinstance(node, (ast.AndOp, ast.OrOp)):
    return any(_cond_uses_conntrack(c) for c in node.operands)
  return False


def _collect_tier2_field_refs(stmts, fields: set[str]) -> bool:
  """Walk Tier 2 stmts collecting referenced field names. Returns
  True iff a `log` statement is present (caller widens the field set
  to cover the log_event struct)."""
  has_log = False
  for s in stmts:
    if isinstance(s, ast.AssignStmt):
      for n in _walk_with_compares(s.rhs):
        _add_field_refs_from_node(n, fields)
    elif isinstance(s, ast.IfStmt):
      for n in _walk_with_compares(s.cond):
        _add_field_refs_from_node(n, fields)
      if _collect_tier2_field_refs(s.body, fields):
        has_log = True
      for cond, body in s.elif_branches:
        for n in _walk_with_compares(cond):
          _add_field_refs_from_node(n, fields)
        if _collect_tier2_field_refs(body, fields):
          has_log = True
      if s.else_body is not None:
        if _collect_tier2_field_refs(s.else_body, fields):
          has_log = True
    elif isinstance(s, ast.ActionStmt):
      if s.action == ast.Action.LOG:
        has_log = True
      if s.action == ast.Action.COUNT:
        # COUNT side-effect uses no field reads.
        pass
  return has_log


def _walk_with_compares(node):
  """Walk a condition/scalar_expr yielding every Comparison and BoolField."""
  if node is None:
    return
  if isinstance(node, ast.Comparison):
    yield node
    return
  if isinstance(node, ast.BoolField):
    yield node
    return
  if isinstance(node, ast.FieldRef):
    yield node
    return
  if isinstance(node, ast.NotOp):
    yield from _walk_with_compares(node.inner)
    return
  if isinstance(node, (ast.AndOp, ast.OrOp)):
    for c in node.operands:
      yield from _walk_with_compares(c)


def _add_field_refs_from_node(node, fields: set[str]) -> None:
  """Add every field name reached by `node` to `fields`."""
  if isinstance(node, ast.Comparison):
    if isinstance(node.field, ast.FieldRef):
      fields.add(node.field.name)
    if isinstance(node.operand, ast.FieldRef):
      fields.add(node.operand.name)
  elif isinstance(node, ast.BoolField):
    fields.add(node.field.name)
  elif isinstance(node, ast.FieldRef):
    fields.add(node.name)


# (field constant, C variable name, struct tcphdr bitfield name) for
# all 8 TCP flags. The prelude declares/reads a var per referenced
# flag; both the v4 and v6 TCP branches reuse this table.
_TCP_FLAG_VARS = (
  (ast.FIELD_TCP_SYN, "tcp_syn", "syn"),
  (ast.FIELD_TCP_ACK, "tcp_ack", "ack"),
  (ast.FIELD_TCP_FIN, "tcp_fin", "fin"),
  (ast.FIELD_TCP_RST, "tcp_rst", "rst"),
  (ast.FIELD_TCP_PSH, "tcp_psh", "psh"),
  (ast.FIELD_TCP_URG, "tcp_urg", "urg"),
  (ast.FIELD_TCP_ECE, "tcp_ece", "ece"),
  (ast.FIELD_TCP_CWR, "tcp_cwr", "cwr"),
)


def _needs_l4(fields: set[str]) -> bool:
  """True iff any port or TCP-flag field is referenced."""
  return bool(fields & (ast.PORT_FIELDS | ast.TCP_FLAG_FIELDS))


def _needs_tcp(fields: set[str]) -> bool:
  """True iff any TCP-flag field is referenced."""
  return bool(fields & ast.TCP_FLAG_FIELDS)


def _needs_icmp(fields: set[str]) -> bool:
  """True iff any IPv4 ICMP type/code field is referenced."""
  return bool(fields & ast.ICMP_FIELDS)


def _needs_icmp6(fields: set[str]) -> bool:
  """True iff any ICMPv6 type/code field is referenced."""
  return bool(fields & ast.ICMP6_FIELDS)


def _is_v6_active(program: ast.Program) -> bool:
  """True iff the program touches any IPv6 surface (v0.2).

  Per FWL_V02_SPEC.md "Compilation" section, a program activates the
  v6 parse path when it mentions `pkt.src_ip6`/`pkt.dst_ip6`, an
  IPv6 literal, an IPv6 CIDR, or the `icmp6` proto keyword. v0.1-
  shaped programs (no v6 surface) get v0.1's IPv4-only parse and
  preserve strict-superset semantics.

  Tier 2: walk the function body's conditions and assignment RHSs.
  """
  for rule in program.rules:
    for n in _walk(rule.condition):
      if _node_activates_v6(n):
        return True
  if program.function is not None:
    if _stmts_activate_v6(program.function.body):
      return True
  return False


def _node_activates_v6(n) -> bool:
  if isinstance(n, ast.Comparison):
    if isinstance(n.field, ast.FieldRef) and n.field.name in ast.IP6_FIELDS:
      return True
    if isinstance(n.operand, ast.FieldRef) and n.operand.name in ast.IP6_FIELDS:
      return True
    op = n.operand
    if isinstance(op, (ast.Ipv6Literal, ast.Ipv6CidrLiteral,
                       ast.Ipv6CidrListLiteral)):
      return True
    if isinstance(op, ast.ProtoLiteral) and op.proto == ast.Proto.ICMP6:
      return True
    if isinstance(op, ast.ListLiteral):
      for item in op.items:
        if isinstance(item, ast.Ipv6Literal):
          return True
  if isinstance(n, ast.FieldRef) and n.name in ast.IP6_FIELDS:
    return True
  return False


def _stmts_activate_v6(stmts) -> bool:
  for s in stmts:
    if isinstance(s, ast.AssignStmt):
      for n in _walk_with_compares(s.rhs):
        if _node_activates_v6(n):
          return True
    elif isinstance(s, ast.IfStmt):
      for n in _walk_with_compares(s.cond):
        if _node_activates_v6(n):
          return True
      if _stmts_activate_v6(s.body):
        return True
      for cond, body in s.elif_branches:
        for n in _walk_with_compares(cond):
          if _node_activates_v6(n):
            return True
        if _stmts_activate_v6(body):
          return True
      if s.else_body is not None and _stmts_activate_v6(s.else_body):
        return True
  return False


def _emit_parse_prelude(
  program: ast.Program, early_out: str = "XDP_PASS"
) -> str:
  """Emit the packet-parsing prelude.

  `early_out` is the value returned when the frame is non-IP (and not a
  tagged frame the program matches on): XDP_PASS in the top-level
  program, or FWL_CONTINUE inside a `static __noinline` helper so the
  caller keeps evaluating (v0.4 § 6.5 multi-def).

  Initializes all referenced fields to 0 and overwrites them only
  when each parse step succeeds. Truncated or non-IPv4 packets fall
  through to subsequent rules (and the default) per
  FWL_V01_SPEC.md:185-191.

  v0.2: when the program touches an IPv6 surface (FWL_V02_SPEC.md
  "Compilation" section), the prelude branches on EtherType — v4
  frames take the existing IPv4 path; v6 frames read the IPv6
  fixed header and the same L4 fields, populating the same
  variables (proto, src_port, ...) plus src_ip6_hi/lo and
  dst_ip6_hi/lo. The two paths share variable storage so the
  rule-emission code can reference them uniformly.
  """
  fields = _referenced_fields(program)
  if not fields:
    # No referenced fields still gets the non-IP early-out. FWL has
    # no L2 fields, so no construct can meaningfully act on ARP, STP,
    # LLDP, or other L2 control frames — and a program built from
    # unconditional actions otherwise WOULD act on them: an
    # unconditional `redirect` re-emits the switch's own BPDUs out
    # another port, which real switch fabric answers by blocking the
    # port (loop protection). Found on the EX2300 by the hardware
    # storm_shield test; veth-based tests cannot see it.
    return f"""\
  {{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return {early_out};
    __u16 fwl_l3p = eth->h_proto;
    if (fwl_l3p == bpf_htons(ETH_P_8021Q)) {{
      struct fwl_vlanhdr *vh = (void *)(eth + 1);
      if ((void *)(vh + 1) > data_end) return {early_out};
      fwl_l3p = vh->inner_proto;
    }}
    if (fwl_l3p != bpf_htons(ETH_P_IP) &&
        fwl_l3p != bpf_htons(ETH_P_IPV6)) return {early_out};
  }}
"""

  needs_l4 = _needs_l4(fields)
  needs_tcp = _needs_tcp(fields)
  needs_icmp = _needs_icmp(fields)
  needs_icmp6 = _needs_icmp6(fields)
  v6_active = _is_v6_active(program)
  uses_ct = _program_uses_conntrack(program)

  decls: list[str] = ["__u8 proto = 0;"]
  # v4_ok gates every v4-field comparison so that v6-packet (or non-IP
  # frame) zeros don't spuriously match `pkt.src_ip == 0.0.0.0`,
  # `pkt.src_ip in [0.0.0.0/0]`, or `pkt.dst_port == 0`. Set to 1 only
  # inside the IPv4 branch after the fixed-header bounds check
  # succeeds, mirroring the v6_ok pattern.
  decls.append("__u8 v4_ok = 0;")
  # Records "this frame is IPv6" independently of whether the v6
  # parse path was generated. The non-IP early-out must not swallow
  # IPv6 frames: FWL_V02_SPEC.md:937 requires that in a v0.1-shaped
  # program they "fall through every rule ... and reach the default
  # action". Passing them instead makes `default drop` forward all
  # IPv6 traffic.
  decls.append("__u8 is_v6_frame = 0;")
  # l4_ok gates port and TCP-flag reads. Set to 1 only inside the
  # TCP/UDP guard blocks after the L4 bounds check succeeds.
  if _needs_l4(fields):
    decls.append("__u8 l4_ok = 0;")
  if ast.FIELD_SRC_IP in fields:
    decls.append("__u32 src_ip = 0;")
  if ast.FIELD_DST_IP in fields:
    decls.append("__u32 dst_ip = 0;")
  # v6_ok gates every IPv6 comparison so that v4-packet zeros don't
  # spuriously match `pkt.src_ip6 == ::` or `pkt.src_ip6 != <non-zero>`.
  # Set to 1 only inside the v6 branch after the 40-byte fixed-header
  # bounds check succeeds. Always declared so `(v4_ok || v6_ok)` is a
  # well-formed L3-gate expression even in v0.1-shaped programs (where
  # v6_ok stays 0 and the OR degrades to v4_ok).
  decls.append("__u8 v6_ok = 0;")
  if ast.FIELD_SRC_IP6 in fields:
    decls.append("__u64 src_ip6_hi = 0, src_ip6_lo = 0;")
  if ast.FIELD_DST_IP6 in fields:
    decls.append("__u64 dst_ip6_hi = 0, dst_ip6_lo = 0;")
  if ast.FIELD_SRC_PORT in fields:
    decls.append("__u16 src_port = 0;")
  if ast.FIELD_DST_PORT in fields:
    decls.append("__u16 dst_port = 0;")
  for field_const, c_var, _bit in _TCP_FLAG_VARS:
    if field_const in fields:
      decls.append(f"__u8 {c_var} = 0;")
  # icmp_ok / icmp6_ok gate ICMP type/code reads, mirroring l4_ok.
  # Set to 1 only inside the ICMP/ICMPv6 guard blocks after the header
  # bounds check succeeds.
  if needs_icmp:
    decls.append("__u8 icmp_ok = 0;")
    if ast.FIELD_ICMP_TYPE in fields:
      decls.append("__u8 icmp_type = 0;")
    if ast.FIELD_ICMP_CODE in fields:
      decls.append("__u8 icmp_code = 0;")
  if needs_icmp6:
    decls.append("__u8 icmp6_ok = 0;")
    if ast.FIELD_ICMP6_TYPE in fields:
      decls.append("__u8 icmp6_type = 0;")
    if ast.FIELD_ICMP6_CODE in fields:
      decls.append("__u8 icmp6_code = 0;")
  # v0.4 VLAN. vlan_ok gates vlan-field comparisons so an untagged
  # frame (where the tag never parsed) cannot spuriously match
  # `pkt.vlan_id == 0`, mirroring the v4_ok/v6_ok/l4_ok pattern. Only
  # declared when a vlan field is referenced; the tag-skip dispatch
  # itself runs in every prelude (so IP rules see through the tag).
  needs_vlan_id = ast.FIELD_VLAN_ID in fields
  needs_vlan_priority = ast.FIELD_VLAN_PRIORITY in fields
  needs_vlan = needs_vlan_id or needs_vlan_priority
  if needs_vlan:
    decls.append("__u8 vlan_ok = 0;")
  if needs_vlan_id:
    decls.append("__u16 vlan_id = 0;")
  if needs_vlan_priority:
    decls.append("__u8 vlan_priority = 0;")
  # v0.4 conntrack scratch. ct_state defaults 0 (NEW) so a non-IP or
  # IPv6 frame — where the v4 ct lookup never runs — reads NEW for
  # free. ct_v4 gates entry creation to IPv4 packets; the ct_k_*
  # fields stash the forward 5-tuple so an allow can recreate the key
  # at the function tail (where `ip` is out of scope).
  if uses_ct:
    decls.append("__u8 ct_state = 0;")
    decls.append("__u8 ct_v4 = 0;")
    decls.append("__u32 ct_k_src = 0, ct_k_dst = 0;")
    decls.append("__u16 ct_k_sport = 0, ct_k_dport = 0;")
    decls.append("__u8 ct_k_proto = 0;")

  decl_block = "\n".join("  " + d for d in decls)

  ip_reads = []
  if ast.FIELD_SRC_IP in fields:
    ip_reads.append("        src_ip = bpf_ntohl(ip->saddr);")
  if ast.FIELD_DST_IP in fields:
    ip_reads.append("        dst_ip = bpf_ntohl(ip->daddr);")
  ip_read_block = "\n".join(ip_reads)
  if ip_read_block:
    ip_read_block = "\n" + ip_read_block

  # IPv4 L4 parse — variable IHL. The ip_hlen-guarded block is emitted
  # when any L4 (port/TCP-flag) OR IPv4 ICMP field is referenced; the
  # TCP/UDP/ICMP sub-branches are each emitted only when relevant.
  l4_block = ""
  if needs_l4 or needs_icmp:
    port_reads_tcp = []
    port_reads_udp = []
    if ast.FIELD_SRC_PORT in fields:
      port_reads_tcp.append(
        "              src_port = bpf_ntohs(tcp->source);"
      )
      port_reads_udp.append(
        "              src_port = bpf_ntohs(udp->source);"
      )
    if ast.FIELD_DST_PORT in fields:
      port_reads_tcp.append(
        "              dst_port = bpf_ntohs(tcp->dest);"
      )
      port_reads_udp.append(
        "              dst_port = bpf_ntohs(udp->dest);"
      )
    tcp_flag_reads = []
    if needs_tcp:
      for field_const, c_var, bit in _TCP_FLAG_VARS:
        if field_const in fields:
          tcp_flag_reads.append(f"              {c_var} = tcp->{bit};")
    tcp_branch = "\n".join(port_reads_tcp + tcp_flag_reads)
    udp_branch = "\n".join(port_reads_udp)

    tcp_block = ""
    if tcp_branch:
      tcp_block = f"""
          if (proto == IPPROTO_TCP) {{
            struct tcphdr *tcp = (void *)ip + ip_hlen;
            if ((void *)(tcp + 1) <= data_end) {{
              l4_ok = 1;
{tcp_branch}
            }}
          }}"""

    udp_block = ""
    if udp_branch:
      udp_block = f"""
          if (proto == IPPROTO_UDP) {{
            struct udphdr *udp = (void *)ip + ip_hlen;
            if ((void *)(udp + 1) <= data_end) {{
              l4_ok = 1;
{udp_branch}
            }}
          }}"""

    icmp_block = ""
    if needs_icmp:
      icmp_reads = []
      if ast.FIELD_ICMP_TYPE in fields:
        icmp_reads.append("              icmp_type = icmp->type;")
      if ast.FIELD_ICMP_CODE in fields:
        icmp_reads.append("              icmp_code = icmp->code;")
      icmp_read_block = "\n".join(icmp_reads)
      icmp_block = f"""
          if (proto == IPPROTO_ICMP) {{
            struct fwl_icmphdr *icmp = (void *)ip + ip_hlen;
            if ((void *)(icmp + 1) <= data_end) {{
              icmp_ok = 1;
{icmp_read_block}
            }}
          }}"""

    # A non-first fragment (offset != 0) carries no L4 header — the
    # bytes at ip_hlen are ordinary payload. Reading them as ports or
    # flags lets an attacker choose what the filter sees, which is the
    # classic tiny-fragment bypass: payload crafted to mimic an
    # allowed port walks through a `default drop` policy. Verified on
    # hardware before this guard existed (tests/system/hw/
    # l6_01_fragments.sh: 50/50 such fragments passed).
    #
    # Gating the whole L4 parse block leaves l4_ok/icmp_ok at 0, so
    # every port, TCP-flag, and ICMP type/code guard fails closed,
    # while pkt.proto / src_ip / dst_ip (read outside this block)
    # still match — exactly what FWL_V01_SPEC:204 specifies.
    l4_block = f"""
        __u32 ip_hlen = ip->ihl * 4;
        __u8 fwl_first_frag =
            (bpf_ntohs(ip->frag_off) & 0x1FFF) == 0;
        if (fwl_first_frag && ip_hlen >= sizeof(struct iphdr) &&
            (void *)ip + ip_hlen <= data_end) \
{{{tcp_block}{udp_block}{icmp_block}
        }}"""

  # v0.4 conntrack lookup, emitted inside the IPv4 branch where `ip` is
  # in scope. Builds the forward + reverse 5-tuple keys from the
  # network-order addresses (raw ip->saddr/daddr — NOT the host-order
  # src_ip var) and the host-order ports, probes the conntrack map
  # forward-then-reverse, and classifies the state: a hit (either
  # direction) is ESTABLISHED; a SYN-less TCP miss is INVALID; anything
  # else stays NEW. v0.4 tracks IPv4 only, so the v6 branch leaves
  # ct_state at its NEW default.
  ct_block = ""
  if uses_ct:
    ct_block = """
        ct_v4 = 1;
        ct_k_src = ip->saddr;
        ct_k_dst = ip->daddr;
        ct_k_sport = src_port;
        ct_k_dport = dst_port;
        ct_k_proto = proto;
        struct fwl_conn_key _ct_f = {
          .src_addr = ip->saddr, .dst_addr = ip->daddr,
          .src_port = src_port, .dst_port = dst_port, .proto = proto,
        };
        struct fwl_conn_key _ct_r = {
          .src_addr = ip->daddr, .dst_addr = ip->saddr,
          .src_port = dst_port, .dst_port = src_port, .proto = proto,
        };
        struct fwl_conn_value *_ct_v =
          bpf_map_lookup_elem(&conntrack, &_ct_f);
        if (!_ct_v) _ct_v = bpf_map_lookup_elem(&conntrack, &_ct_r);
        if (_ct_v) {
          ct_state = 1;
          _ct_v->last_seen_ns = bpf_ktime_get_ns();
          _ct_v->packets += 1;
        } else if (proto == IPPROTO_ICMP) {
          ct_state = fwl_ct_icmp_related(ip, data_end) ? 2 : 0;
        } else if (proto == IPPROTO_TCP && !tcp_syn) {
          ct_state = 3;
        }"""

  v6_branch = ""
  if v6_active:
    v6_branch = _emit_v6_branch(fields, needs_l4, needs_tcp, needs_icmp6)

  # v0.4 VLAN dispatch. Emitted in EVERY prelude (not just programs
  # that read vlan fields) so an existing IPv4/IPv6 rule still matches
  # a tagged frame: when the outer EtherType is 0x8100 we bounds-check
  # the 4-byte tag, advance the L3 pointer past it (offset 14 -> 18),
  # and re-read the *real* EtherType from the tag. The vlan-field
  # reads + vlan_ok are emitted only when a vlan field is referenced.
  vlan_reads: list[str] = []
  if needs_vlan:
    vlan_reads.append("        vlan_ok = 1;")
  if needs_vlan_id:
    vlan_reads.append(
      "        vlan_id = bpf_ntohs(vh->tci) & 0x0FFF;"
    )
  if needs_vlan_priority:
    vlan_reads.append(
      "        vlan_priority = (bpf_ntohs(vh->tci) >> 13) & 0x7;"
    )
  vlan_read_block = "\n".join(vlan_reads)
  if vlan_read_block:
    vlan_read_block += "\n"
  vlan_block = f"""
    if (l3_proto == bpf_htons(ETH_P_8021Q)) {{
      struct fwl_vlanhdr *vh = (void *)(eth + 1);
      if ((void *)(vh + 1) <= data_end) {{
{vlan_read_block}        l3_proto = vh->inner_proto;
        l3 = (void *)(vh + 1);
      }}
    }}"""

  # Non-IP frame early-out. Any program that references an IP-aware
  # field (and therefore generates this prelude) cannot meaningfully
  # filter on ARP, NDP, LLDP, or any other L2 control protocol — its
  # rule guards are all gated on v4_ok / v6_ok. Without this gate,
  # an explicit `drop` action (Tier 1 `default drop` or a Tier 2
  # trailing `drop` statement) compiles to `return XDP_DROP;` at the
  # function tail and silently drops ARP, killing the management
  # plane within minutes of going live. Surfaced by the v0.2 dogfood
  # soak (planning/SOAK_INCIDENTS.md Incident #3, 2026-05-02). Treated
  # as an intentional v0.2 semantic improvement per the v4_ok/l4_ok
  # precedent recorded in CLAUDE.md "Operating reminders".
  #
  # v0.4: when the program reads vlan fields, vlan_ok joins the gate
  # so a tagged non-IP frame (or a tagged frame truncated before L3)
  # still reaches the vlan-matching rules instead of early-passing.
  # ...but an IPv6 frame is IP, and the spec requires it to reach the
  # default action even when the v6 parse path was not generated.
  # Excluding it from the early-out is what makes `default drop`
  # actually deny IPv6 (verified on wire:
  # tests/system/hw/l1_13_ipv6_activation.sh).
  vlan_gate = " && !vlan_ok" if needs_vlan else ""
  vlan_gate += " && !is_v6_frame"
  return f"""\
{decl_block}
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) <= data_end) {{
    __u16 l3_proto = eth->h_proto;
    void *l3 = (void *)(eth + 1);{vlan_block}
    if (l3_proto == bpf_htons(ETH_P_IPV6)) {{
      is_v6_frame = 1;
    }}
    if (l3_proto == bpf_htons(ETH_P_IP)) {{
      struct iphdr *ip = l3;
      if ((void *)(ip + 1) <= data_end) {{
        v4_ok = 1;
        proto = ip->protocol;{ip_read_block}{l4_block}{ct_block}
      }}
    }}{v6_branch}
  }}
  if (!v4_ok && !v6_ok{vlan_gate}) return {early_out};

"""


def _emit_v6_branch(
  fields: set[str], needs_l4: bool, needs_tcp: bool,
  needs_icmp6: bool = False,
) -> str:
  """Emit the IPv6 parse branch for the dual-stack prelude (v0.2).

  Reads the 40-byte fixed header at offset 14, populates the
  src_ip6_hi/lo and dst_ip6_hi/lo locals, then parses TCP/UDP at
  the fixed offset (no extension-header chasing per FWL_V02_SPEC.md).
  v0.4 adds an ICMPv6 sub-branch reading type/code at the same fixed
  offset when next_header == IPPROTO_ICMPV6. Other next_header values
  (extension headers) leave the L4/ICMP fields at zero so rules
  touching them fall through.
  """
  reads: list[str] = []
  if ast.FIELD_SRC_IP6 in fields:
    reads.append(
      "        src_ip6_hi = "
      "((__u64)bpf_ntohl(ip6->saddr.s6_addr32[0]) << 32) | "
      "bpf_ntohl(ip6->saddr.s6_addr32[1]);\n"
      "        src_ip6_lo = "
      "((__u64)bpf_ntohl(ip6->saddr.s6_addr32[2]) << 32) | "
      "bpf_ntohl(ip6->saddr.s6_addr32[3]);"
    )
  if ast.FIELD_DST_IP6 in fields:
    reads.append(
      "        dst_ip6_hi = "
      "((__u64)bpf_ntohl(ip6->daddr.s6_addr32[0]) << 32) | "
      "bpf_ntohl(ip6->daddr.s6_addr32[1]);\n"
      "        dst_ip6_lo = "
      "((__u64)bpf_ntohl(ip6->daddr.s6_addr32[2]) << 32) | "
      "bpf_ntohl(ip6->daddr.s6_addr32[3]);"
    )
  read_block = "\n".join(reads)
  if read_block:
    read_block = "\n" + read_block

  # IPv6 L4 parse: fixed offset, TCP/UDP only. Extension headers
  # (next_header in {0, 43, 44, ...}) leave L4 fields at zero.
  l4_block = ""
  if needs_l4:
    port_tcp: list[str] = []
    port_udp: list[str] = []
    if ast.FIELD_SRC_PORT in fields:
      port_tcp.append("            src_port = bpf_ntohs(tcp->source);")
      port_udp.append("            src_port = bpf_ntohs(udp->source);")
    if ast.FIELD_DST_PORT in fields:
      port_tcp.append("            dst_port = bpf_ntohs(tcp->dest);")
      port_udp.append("            dst_port = bpf_ntohs(udp->dest);")
    tcp_flags: list[str] = []
    if needs_tcp:
      for field_const, c_var, bit in _TCP_FLAG_VARS:
        if field_const in fields:
          tcp_flags.append(f"            {c_var} = tcp->{bit};")
    tcp_branch = "\n".join(port_tcp + tcp_flags)
    udp_branch = "\n".join(port_udp)
    tcp_block = ""
    if tcp_branch:
      tcp_block = f"""
        if (proto == IPPROTO_TCP) {{
          struct tcphdr *tcp = (void *)(ip6 + 1);
          if ((void *)(tcp + 1) <= data_end) {{
            l4_ok = 1;
{tcp_branch}
          }}
        }}"""
    udp_block = ""
    if udp_branch:
      udp_block = f"""
        if (proto == IPPROTO_UDP) {{
          struct udphdr *udp = (void *)(ip6 + 1);
          if ((void *)(udp + 1) <= data_end) {{
            l4_ok = 1;
{udp_branch}
          }}
        }}"""
    l4_block = tcp_block + udp_block

  # ICMPv6 type/code parse at the fixed offset (no ext-header chasing).
  # `icmp6` derives from `ip6` (== `l3`), so it lands at the correct
  # VLAN-shifted offset on tagged frames.
  icmp6_block = ""
  if needs_icmp6:
    icmp6_reads = []
    if ast.FIELD_ICMP6_TYPE in fields:
      icmp6_reads.append("            icmp6_type = icmp6->type;")
    if ast.FIELD_ICMP6_CODE in fields:
      icmp6_reads.append("            icmp6_code = icmp6->code;")
    icmp6_read_block = "\n".join(icmp6_reads)
    icmp6_block = f"""
        if (proto == IPPROTO_ICMPV6) {{
          struct fwl_icmphdr *icmp6 = (void *)(ip6 + 1);
          if ((void *)(icmp6 + 1) <= data_end) {{
            icmp6_ok = 1;
{icmp6_read_block}
          }}
        }}"""
  l4_block = l4_block + icmp6_block

  # `l3` / `l3_proto` are the VLAN-aware L3 pointer + EtherType the
  # prelude computes once (offset 14 untagged, 18 tagged); deriving
  # ip6 from `l3` keeps the v6 path correct on tagged frames.
  return f""" else if (l3_proto == bpf_htons(ETH_P_IPV6)) {{
      struct ipv6hdr *ip6 = l3;
      if ((void *)(ip6 + 1) <= data_end) {{
        v6_ok = 1;
        proto = ip6->nexthdr;{read_block}{l4_block}
      }}
    }}"""


def _emit_condition(
  node: ast.Condition,
  counter_slots: dict[str, int] | None = None,
  zone_name: str | None = None,
) -> str:
  """Emit a C boolean expression for `node`. Parens for safety.

  `zone_name` is the zone of the @xdp block being emitted; it folds
  any `pkt.zone` comparison to a compile-time 1/0 (v0.4 § 6.4).
  """
  if isinstance(node, ast.Comparison):
    return _emit_comparison(node)
  if isinstance(node, ast.CountCompare):
    return _emit_count_compare(node, counter_slots or {})
  if isinstance(node, ast.ConntrackStateCompare):
    return _emit_ct_state_compare(node)
  if isinstance(node, ast.ZoneCompare):
    return _emit_zone_compare(node, zone_name)
  if isinstance(node, ast.BoolField):
    return _emit_bool_field(node)
  if isinstance(node, ast.NotOp):
    return f"!({_emit_condition(node.inner, counter_slots, zone_name)})"
  if isinstance(node, ast.AndOp):
    parts = [
      _emit_condition(c, counter_slots, zone_name) for c in node.operands
    ]
    return "(" + " && ".join(parts) + ")"
  if isinstance(node, ast.OrOp):
    parts = [
      _emit_condition(c, counter_slots, zone_name) for c in node.operands
    ]
    return "(" + " || ".join(parts) + ")"
  raise NotImplementedError(
    f"emitter: unsupported condition {type(node).__name__}"
  )


def _emit_zone_compare(node: ast.ZoneCompare, zone_name: str | None) -> str:
  """Fold a `pkt.zone` comparison to a compile-time 1/0 (v0.4 § 6.4).

  pkt.zone is a constant within an @xdp block — the compiler knows the
  block's zone — so the comparison resolves entirely at compile time.
  """
  if node.op == "==":
    return "1" if zone_name == node.zones[0] else "0"
  if node.op == "!=":
    return "1" if zone_name != node.zones[0] else "0"
  # `in`: membership against the listed zone names.
  return "1" if zone_name in node.zones else "0"


def _emit_count_compare(
  node: ast.CountCompare,
  counter_slots: dict[str, int],
) -> str:
  """Emit a C expression for count(name) op value."""
  slot = counter_slots.get(node.call.counter_name)
  if slot is None:
    return "0"
  val = node.operand.value  # type: ignore[union-attr]
  return (
    f"({{ __u32 _ck = {slot}; "
    f"__u64 *_cv = bpf_map_lookup_elem(&fwl_counters, &_ck); "
    f"_cv ? (*_cv {node.op} {val}) : (0 {node.op} {val}); }})"
  )


def _emit_ct_state_compare(node: ast.ConntrackStateCompare) -> str:
  """Emit a C boolean expression for a conntrack(pkt).state comparison.

  `ct_state` is the u8 the prelude computed (0=new, 1=established,
  2=related, 3=invalid). No `*_ok` gate is needed: a non-IP or IPv6
  frame leaves ct_state at 0 (NEW), which is the correct conntrack
  reading for an untracked frame.
  """
  if node.op == "==":
    return f"(ct_state == {_CT_STATE_TO_INT[node.states[0]]})"
  if node.op == "!=":
    return f"(ct_state != {_CT_STATE_TO_INT[node.states[0]]})"
  # `in`: OR over the listed states.
  parts = [f"(ct_state == {_CT_STATE_TO_INT[s]})" for s in node.states]
  return "(" + " || ".join(parts) + ")"


def _emit_bool_field(node: ast.BoolField) -> str:
  """Emit a C expression for a bare bool field.

  Gated on `l4_ok` so a non-TCP frame (or an IP frame with no L4
  parse) cannot spuriously evaluate `if pkt.tcp.syn:` to true when
  the underlying byte stays 0 (which it does on every non-TCP
  packet, by construction).
  """
  for field_const, c_var, _bit in _TCP_FLAG_VARS:
    if node.field.name == field_const:
      return f"(l4_ok && {c_var})"
  raise NotImplementedError(
    f"emitter: unsupported bool field {node.field.name}"
  )


_FIELD_TO_C = {
  ast.FIELD_PROTO: "proto",
  ast.FIELD_SRC_IP: "src_ip",
  ast.FIELD_DST_IP: "dst_ip",
  ast.FIELD_SRC_PORT: "src_port",
  ast.FIELD_DST_PORT: "dst_port",
  ast.FIELD_ICMP_TYPE: "icmp_type",
  ast.FIELD_ICMP_CODE: "icmp_code",
  ast.FIELD_ICMP6_TYPE: "icmp6_type",
  ast.FIELD_ICMP6_CODE: "icmp6_code",
  ast.FIELD_VLAN_ID: "vlan_id",
  ast.FIELD_VLAN_PRIORITY: "vlan_priority",
}


def _emit_comparison(cmp: ast.Comparison) -> str:
  """Emit a C boolean expression for a comparison."""
  field_name = cmp.field.name
  if field_name == ast.FIELD_PROTO:
    return _emit_proto_compare(cmp)
  if field_name in ast.IP_FIELDS:
    return _emit_ip_compare(cmp)
  if field_name in ast.IP6_FIELDS:
    return _emit_ip6_compare(cmp)
  if field_name in ast.PORT_FIELDS:
    return _emit_port_compare(cmp)
  if field_name in ast.ICMP_FIELDS or field_name in ast.ICMP6_FIELDS:
    return _emit_icmp_compare(cmp)
  if field_name in ast.VLAN_FIELDS:
    return _emit_vlan_compare(cmp)
  raise NotImplementedError(
    f"emitter: comparison on {field_name} not supported"
  )


def _emit_proto_compare(cmp: ast.Comparison) -> str:
  """proto == tcp, proto != udp, proto in [tcp, icmp6], etc.

  Gated on `(v4_ok || v6_ok)` so a non-IP frame (where proto is the
  zero default) cannot spuriously match `pkt.proto == 0` or
  `pkt.proto != tcp` (which evaluates true when proto stays 0).
  v6_ok is only declared in v6-active programs; for v0.1-shaped
  programs the gate degrades to `v4_ok`, which is the same as
  v0.1's implicit "non-IP frames don't match" intent.
  """
  if isinstance(cmp.operand, ast.ListLiteral):
    parts = [
      f"(proto == {_PROTO_TO_IPPROTO[item.proto]})"
      for item in cmp.operand.items
    ]
    body = "(" + " || ".join(parts) + ")"
  else:
    ipproto = _PROTO_TO_IPPROTO[cmp.operand.proto]  # type: ignore[union-attr]
    body = f"(proto {cmp.op} {ipproto})"
  return f"((v4_ok || v6_ok) && {body})"


def _emit_ip_compare(cmp: ast.Comparison) -> str:
  """src_ip/dst_ip comparisons (== / != / in).

  Gated on `v4_ok` so non-IPv4 frames (v6 packets, ARP, etc.) where
  src_ip/dst_ip stay at their zero default cannot spuriously match
  `pkt.src_ip == 0.0.0.0`, `pkt.src_ip in [0.0.0.0/0]`, or any other
  pattern that evaluates true when the field is 0.
  """
  c_field = _FIELD_TO_C[cmp.field.name]
  if cmp.op in ("==", "!="):
    val = cmp.operand.value  # type: ignore[union-attr]
    return f"(v4_ok && ({c_field} {cmp.op} 0x{val:08X}u))"
  if cmp.op == "in":
    return f"(v4_ok && {_emit_ip_in(c_field, cmp.operand)})"
  raise NotImplementedError(
    f"emitter: ip op {cmp.op} not supported"
  )


def _emit_ip_in(c_field: str, operand: ast.Operand) -> str:
  """Emit a C expression for `<ip_field> in <operand>`."""
  if isinstance(operand, ast.CidrLiteral):
    return _emit_cidr_match(c_field, operand)
  if isinstance(operand, ast.CidrListLiteral):
    parts = [_emit_cidr_match(c_field, c) for c in operand.items]
    return "(" + " || ".join(parts) + ")"
  if isinstance(operand, ast.ListLiteral):
    parts = [
      f"({c_field} == 0x{item.value:08X}u)"
      for item in operand.items
      if isinstance(item, ast.IPv4Literal)
    ]
    return "(" + " || ".join(parts) + ")"
  if isinstance(operand, ast.GeoIp):
    return f"fwl_geoip_{operand.call_index}_v4({c_field})"
  raise NotImplementedError(
    f"emitter: ip 'in' operand {type(operand).__name__} not supported"
  )


def _emit_cidr_match(c_field: str, cidr: ast.CidrLiteral) -> str:
  """Emit a C expression for a CIDR membership test."""
  if cidr.bits == 0:
    return "1"
  mask = ((1 << cidr.bits) - 1) << (32 - cidr.bits)
  return (
    f"(({c_field} & 0x{mask:08X}u) == 0x{cidr.prefix:08X}u)"
  )


_IP6_FIELD_TO_C = {
  ast.FIELD_SRC_IP6: ("src_ip6_hi", "src_ip6_lo"),
  ast.FIELD_DST_IP6: ("dst_ip6_hi", "dst_ip6_lo"),
}


def _split_ipv6_value(value: int) -> tuple[int, int]:
  """Split a 128-bit IPv6 integer into (hi 64 bits, lo 64 bits)."""
  return (value >> 64) & 0xFFFFFFFFFFFFFFFF, value & 0xFFFFFFFFFFFFFFFF


def _emit_ip6_compare(cmp: ast.Comparison) -> str:
  """Emit a C boolean expression for an IPv6 field comparison.

  ==/!= split the 128-bit literal into two 64-bit halves and compare
  each half independently — the BPF verifier dislikes 128-bit ops.
  Every comparison is gated by `v6_ok`, the flag the prelude sets to
  1 only after the v6 fixed-header bounds check succeeds. Without
  the gate, a v4 packet (where hi=lo=0) would spuriously match
  `pkt.src_ip6 == ::` and `pkt.src_ip6 != <non-zero>`.
  """
  hi_var, lo_var = _IP6_FIELD_TO_C[cmp.field.name]
  if cmp.op in ("==", "!="):
    lit = cmp.operand.value  # type: ignore[union-attr]
    lit_hi, lit_lo = _split_ipv6_value(lit)
    if cmp.op == "==":
      body = (
        f"{hi_var} == 0x{lit_hi:016X}ull && "
        f"{lo_var} == 0x{lit_lo:016X}ull"
      )
    else:
      body = (
        f"{hi_var} != 0x{lit_hi:016X}ull || "
        f"{lo_var} != 0x{lit_lo:016X}ull"
      )
    return f"(v6_ok && ({body}))"
  if cmp.op == "in":
    return f"(v6_ok && {_emit_ip6_in(hi_var, lo_var, cmp.operand)})"
  raise NotImplementedError(
    f"emitter: ipv6 op {cmp.op} not supported"
  )


def _emit_ip6_in(hi_var: str, lo_var: str, operand: ast.Operand) -> str:
  """Emit a C expression for `<ipv6_field> in <operand>`."""
  if isinstance(operand, ast.Ipv6CidrLiteral):
    return _emit_ipv6_cidr_match(hi_var, lo_var, operand)
  if isinstance(operand, ast.Ipv6CidrListLiteral):
    parts = [
      _emit_ipv6_cidr_match(hi_var, lo_var, c) for c in operand.items
    ]
    return "(" + " || ".join(parts) + ")"
  if isinstance(operand, ast.ListLiteral):
    parts = []
    for item in operand.items:
      if isinstance(item, ast.Ipv6Literal):
        lit_hi, lit_lo = _split_ipv6_value(item.value)
        parts.append(
          f"({hi_var} == 0x{lit_hi:016X}ull && "
          f"{lo_var} == 0x{lit_lo:016X}ull)"
        )
    return "(" + " || ".join(parts) + ")"
  if isinstance(operand, ast.GeoIp):
    return f"fwl_geoip_{operand.call_index}_v6({hi_var}, {lo_var})"
  raise NotImplementedError(
    f"emitter: ipv6 'in' operand {type(operand).__name__} not supported"
  )


def _emit_ipv6_cidr_match(
  hi_var: str, lo_var: str, cidr: ast.Ipv6CidrLiteral
) -> str:
  """Emit a C expression for an IPv6 CIDR membership test.

  The 128-bit prefix and mask are split across the hi/lo halves:
    bits == 0    -> always true (default-route equivalent ::/0)
    bits <= 64   -> only hi matters; lo is unconstrained
    bits == 64   -> hi must match exactly; lo is unconstrained
    bits >  64   -> hi must match exactly; lo is partially masked
    bits == 128  -> both halves must match exactly
  """
  if cidr.bits == 0:
    return "1"
  prefix_hi, prefix_lo = _split_ipv6_value(cidr.prefix)
  if cidr.bits <= 64:
    mask_hi = ((1 << cidr.bits) - 1) << (64 - cidr.bits)
    return (
      f"(({hi_var} & 0x{mask_hi:016X}ull) == 0x{prefix_hi:016X}ull)"
    )
  # bits in 65..128: hi is full mask, lo is partially masked.
  if cidr.bits == 128:
    return (
      f"({hi_var} == 0x{prefix_hi:016X}ull && "
      f"{lo_var} == 0x{prefix_lo:016X}ull)"
    )
  lo_bits = cidr.bits - 64
  mask_lo = ((1 << lo_bits) - 1) << (64 - lo_bits)
  return (
    f"({hi_var} == 0x{prefix_hi:016X}ull && "
    f"({lo_var} & 0x{mask_lo:016X}ull) == 0x{prefix_lo:016X}ull)"
  )


def _emit_port_compare(cmp: ast.Comparison) -> str:
  """Port comparisons (== / != / < / > / <= / >= / in).

  Gated on `l4_ok` so frames where the L4 parse never ran (non-IP,
  ICMPv6, IPv6 extension headers, IHL-mismatch) cannot spuriously
  match `pkt.dst_port == 0` or `pkt.dst_port != 80` (which evaluates
  true when dst_port stays 0).
  """
  c_field = _FIELD_TO_C[cmp.field.name]
  if cmp.op in ("==", "!=", "<", ">", "<=", ">="):
    val = cmp.operand.value  # type: ignore[union-attr]
    return f"(l4_ok && ({c_field} {cmp.op} {val}))"
  if cmp.op == "in":
    return f"(l4_ok && {_emit_port_in(c_field, cmp.operand)})"
  raise NotImplementedError(
    f"emitter: port op {cmp.op} not supported"
  )


def _emit_port_in(c_field: str, operand: ast.Operand) -> str:
  """Emit a C expression for `<port_field> in <operand>`."""
  if isinstance(operand, ast.RangeLiteral):
    return f"({c_field} >= {operand.lo} && {c_field} <= {operand.hi})"
  if isinstance(operand, ast.ListLiteral):
    parts = [
      f"({c_field} == {item.value})"
      for item in operand.items
      if isinstance(item, ast.IntLiteral)
    ]
    return "(" + " || ".join(parts) + ")"
  raise NotImplementedError(
    f"emitter: port 'in' operand {type(operand).__name__} not supported"
  )


def _emit_icmp_compare(cmp: ast.Comparison) -> str:
  """ICMP/ICMPv6 type/code comparisons (== / != / < / > / <= / >= / in).

  Gated on `icmp_ok` (v4) or `icmp6_ok` (v6) so a frame whose ICMP
  header never parsed (non-ICMP proto, truncated header, IPv6 ext
  headers) cannot spuriously match `pkt.icmp.type == 0` or
  `pkt.icmp.code != 3` (which evaluates true when the byte stays 0).
  """
  c_field = _FIELD_TO_C[cmp.field.name]
  ok = "icmp_ok" if cmp.field.name in ast.ICMP_FIELDS else "icmp6_ok"
  if cmp.op in ("==", "!=", "<", ">", "<=", ">="):
    val = cmp.operand.value  # type: ignore[union-attr]
    return f"({ok} && ({c_field} {cmp.op} {val}))"
  if cmp.op == "in":
    return f"({ok} && {_emit_port_in(c_field, cmp.operand)})"
  # Unreachable: the analyzer restricts ICMP type/code to exactly the
  # comparison ops handled above.
  raise AssertionError(f"unexpected icmp op {cmp.op}")


def _emit_vlan_compare(cmp: ast.Comparison) -> str:
  """VLAN field comparisons (== / != / < / > / <= / >= / in).

  Integer comparisons over u16 vlan_id / u8 vlan_priority. Gated on
  `vlan_ok` so a frame with no 802.1Q tag (where the vlan locals stay
  at their zero default) cannot spuriously match `pkt.vlan_id == 0` or
  `pkt.vlan_id != 10`. Membership reuses the port `in` helper — the
  operand shapes (integer list / lo..hi range) are identical.
  """
  c_field = _FIELD_TO_C[cmp.field.name]
  if cmp.op == "in":
    return f"(vlan_ok && {_emit_port_in(c_field, cmp.operand)})"
  # The analyzer admits only ==/!=/</>/<=/>= and `in` for vlan
  # fields, so any remaining op is one of the integer comparators.
  val = cmp.operand.value  # type: ignore[union-attr]
  return f"(vlan_ok && ({c_field} {cmp.op} {val}))"


def _emit_ct_create(indent: str = "    ") -> str:
  """Conntrack entry-creation snippet (the body before an allow return).

  Inserts the forward 5-tuple when the packet is an allowed NEW IPv4
  flow (`ct_v4 && ct_state == 0`). BPF_NOEXIST keeps it idempotent and
  lets the daemon's slow path win an insert race. Mirrors the
  interpreter's `ConntrackTable.create` on an explicit allow.
  """
  return (
    f"if (ct_v4 && ct_state == 0) {{\n"
    f"{indent}  struct fwl_conn_key _ct_ck = {{\n"
    f"{indent}    .src_addr = ct_k_src, .dst_addr = ct_k_dst,\n"
    f"{indent}    .src_port = ct_k_sport, .dst_port = ct_k_dport,\n"
    f"{indent}    .proto = ct_k_proto,\n"
    f"{indent}  }};\n"
    f"{indent}  struct fwl_conn_value _ct_cv = {{\n"
    f"{indent}    .last_seen_ns = bpf_ktime_get_ns(),"
    f" .packets = 1, .state = 1,\n"
    f"{indent}  }};\n"
    f"{indent}  bpf_map_update_elem("
    f"&conntrack, &_ct_ck, &_ct_cv, BPF_NOEXIST);\n"
    f"{indent}}}\n"
    f"{indent}"
  )


def _redirect_return(zone: str) -> str:
  """C expression that forwards out the destination zone (v0.4 § 6.3).

  `fwl_redirect_<zone>` routes when this box's own routing table says
  the destination is reachable through that zone — next-hop MAC from
  `bpf_fib_lookup`, TTL decremented — and otherwise forwards the frame
  with the Ethernet header it arrived with, which is all a redirect
  ever did. Egress is still the zone's devmap (key 0 = the zone's
  first/representative ifindex, populated by the daemon at load time);
  for a multi-interface zone the switch chip's FDB picks the physical
  port. Returns XDP_REDIRECT, or XDP_DROP/XDP_PASS when the route
  lookup says the packet must not go out as it is.
  """
  return f"fwl_redirect_{zone}(ctx)"


def _emit_rule(
  names: MapNames, rule: ast.Rule, idx: int,
  counter_slots: dict[str, int],
  ct_create: str = "", zone_name: str | None = None,
) -> str:
  """Emit C statements for one rule.

  Terminal actions return; non-terminal actions execute their side
  effect and fall through to the next rule. A rate_limit modifier
  gates the entire rule body — when blocked, neither the action's
  side effect nor return fires. `ct_create` (non-empty only when the
  program reads conntrack) is the entry-creation snippet prepended to
  an `allow` return so an allowed NEW flow is tracked.
  """
  overflow_slot = counter_slots.get(RATE_LIMIT_OVERFLOW_COUNTER)
  if rule.action in ast.TERMINAL_ACTIONS:
    if rule.action == ast.Action.REDIRECT:
      ret = _redirect_return(rule.redirect_zone)
    else:
      ret = _TERMINAL_ACTION_TO_RETURN[rule.action]
    # Only an `allow` creates conntrack state. A `redirect` forwards the
    # frame but (pre-NAT, v0.4 § 6) does not yet open a tracked flow.
    create = ct_create if rule.action == ast.Action.ALLOW else ""
    if rule.modifier is not None:
      fire_block = _emit_rate_limit_gate(
        names, rule.modifier, idx, ret, overflow_slot, create
      )
    else:
      fire_block = f"{create}return {ret};"
  else:
    # Non-terminal: emit the side effect, no return.
    if rule.action == ast.Action.LOG:
      side_effect = _emit_log(names, idx, zone_name, rule.log_sample)
    elif rule.action == ast.Action.COUNT:
      slot = counter_slots[rule.counter_name]  # type: ignore[index]
      side_effect = _emit_count(names, slot)
    elif rule.action in ast.NAT_ACTIONS:
      side_effect = _emit_nat_call(
        rule.action, rule.nat_addr, rule.nat_port
      )
    else:
      raise NotImplementedError(
        f"emitter: unsupported action {rule.action}"
      )
    if rule.modifier is not None:
      fire_block = _emit_rate_limit_side_effect(
        names, rule.modifier, idx, side_effect, overflow_slot
      )
    else:
      fire_block = side_effect

  if rule.condition is None:
    return f"  {{\n    {fire_block}\n  }}\n"
  expr = _emit_condition(rule.condition, counter_slots, zone_name)
  return f"  if ({expr}) {{\n    {fire_block}\n  }}\n"


def _emit_log(
  names: MapNames, rule_idx: int, zone_name: str | None,
  sample: int | None = None,
) -> str:
  """Emit code that submits a log_event for rule `rule_idx`.

  `zone_name` is the @xdp block being emitted. It is stamped into the
  record as `log_abi.zone_id(zone_name)` because `fwl_log_events` is
  one ring for the whole bundle while `rule_idx` is numbered per zone:
  without the tag, zone `wan`'s rule 2 and zone `lan`'s rule 2 are the
  same record and no consumer can separate them.
  """
  tag = log_abi.ZONE_ID_NONE if zone_name is None \
    else log_abi.zone_id(zone_name)
  submit = f"""struct fwl_log_event *ev =
      bpf_ringbuf_reserve(&fwl_log_events, sizeof(*ev), 0);
    if (ev) {{
      ev->magic = FWL_LOG_EVENT_MAGIC;
      ev->version = FWL_LOG_EVENT_VERSION;
      ev->event_size = sizeof(*ev);
      ev->timestamp_ns = bpf_ktime_get_ns();
      ev->zone_id = 0x{tag:08X}u;
      ev->rule_index = {rule_idx};
      ev->src_ip = src_ip;
      ev->dst_ip = dst_ip;
      ev->src_port = src_port;
      ev->dst_port = dst_port;
      ev->proto = proto;
      ev->flags = (tcp_syn ? 0x01 : 0) | (tcp_ack ? 0x02 : 0);
      ev->pad[0] = 0;
      ev->pad[1] = 0;
      bpf_ringbuf_submit(ev, 0);
    }}"""
  if sample is not None and sample > 1:
    return f"""__u32 lsk = {rule_idx};
    __u64 *lsc = bpf_map_lookup_elem(&{names.log_sample()}, &lsk);
    __u64 lsv = lsc ? *lsc + 1 : 1;
    if (lsc) {{ *lsc = lsv; }}
    if ((lsv - 1) % {sample} == 0) {{
      {submit}
    }}"""
  return submit


def _emit_count(names: MapNames, slot: int) -> str:
  """Emit code that bumps the counter at `slot`."""
  return f"""__u32 ck = {slot};
    __u64 *cnt = bpf_map_lookup_elem(&{names.counters()}, &ck);
    if (cnt) {{
      __sync_fetch_and_add(cnt, 1);
    }}"""


def _emit_rate_limit_overflow(
  names: MapNames, overflow_slot: int | None
) -> str:
  """Emit the post-update overflow check (or empty when no slot)."""
  if overflow_slot is None:
    return ""
  return f"""
    if (upd_rc == -7) {{
      __u32 ovf_slot = {overflow_slot};
      __u64 *ovf = bpf_map_lookup_elem(&{names.counters()}, &ovf_slot);
      if (ovf) __sync_fetch_and_add(ovf, 1);
    }}"""


def _rl_base_name(mod: ast.RateLimit, idx: int) -> str:
  """The unqualified name of a rate_limit rule's bucket map.

  ZONE scope uses `fwl_rl_map_<rule idx>`: PRIVATE in the registry, so
  in a bundle `MapNames` gives it the zone (`fwl_rl_<zone>_<idx>`) and
  two zones can never address one kernel map by their own rule
  indices.

  GLOBAL scope uses `fwl_rl_g<slot>`, where the slot is the
  bundle-wide number the analyzer assigned from the rule's structure.
  That name is SHARED in the registry — one name, one kernel map, one
  budget — and is therefore held to the bundle invariant that every
  zone declare it identically.
  """
  if mod.scope is ast.RlScope.GLOBAL:
    return f"fwl_rl_g{mod.global_slot}"
  return f"fwl_rl_map_{idx}"


def rl_map_name(
  mod: ast.RateLimit, idx: int, zone: str | None = None
) -> str:
  """The map a rate_limit rule's bucket lives in (v0.4 § 6.7).

  `zone` is None for a single-object emission (the test runner's BPF
  oracle seeds bucket state by this name) and the emitting zone in a
  bundle.
  """
  return MapNames(zone).rate_limit(mod, idx)


def _emit_rate_limit_side_effect(
  names: MapNames, mod: ast.RateLimit, idx: int, side_effect: str,
  overflow_slot: int | None,
) -> str:
  """Wrap a non-terminal side effect with rate_limit gating.

  Counts every matching packet in the bucket; the side effect fires
  only once the bucket count reaches the threshold (rate exceeded).
  When the per-CPU map's bucket key space is exhausted, the
  reserved `__rate_limit_overflow` counter ticks once per dropped
  insert.
  """
  c_field = _RL_FIELD_TO_C[mod.per_field]
  ovf = _emit_rate_limit_overflow(names, overflow_slot)
  rl_map = names.rate_limit(mod, idx)
  return f"""__u32 rl_key = (__u32){c_field};
    __u64 now = bpf_ktime_get_ns();
    struct fwl_rl_state *st =
      bpf_map_lookup_elem(&{rl_map}, &rl_key);
    __u32 cur = 0;
    __u64 cur_ts = now;
    if (st && now - st->ts < 1000000000ULL) {{
      cur = st->count;
      cur_ts = st->ts;
    }}
    struct fwl_rl_state new_st = {{ .ts = cur_ts, .count = cur + 1 }};
    int upd_rc = bpf_map_update_elem(
      &{rl_map}, &rl_key, &new_st, BPF_ANY);{ovf}
    if (cur >= {mod.threshold}) {{
      {side_effect}
    }}"""


def _emit_rate_limit_gate(
  names: MapNames, mod: ast.RateLimit, idx: int, ret: str,
  overflow_slot: int | None,
  ct_create: str = "",
) -> str:
  """Emit a rate-limit gate that returns `ret` only when rate exceeded.

  Reads the bucket counter from the per-CPU map; if (now - ts) >= 1s
  the counter resets. Every matching packet bumps the counter; the
  rule fires once the count has reached the threshold (matching the
  user-facing reading: `drop ... limited by rate_limit(N)` drops the
  N+1-th packet onward, not the first N). On bucket-key-space
  exhaustion, the reserved `__rate_limit_overflow` counter ticks.
  """
  c_field = _RL_FIELD_TO_C[mod.per_field]
  ovf = _emit_rate_limit_overflow(names, overflow_slot)
  rl_map = names.rate_limit(mod, idx)
  return f"""__u32 rl_key = (__u32){c_field};
    __u64 now = bpf_ktime_get_ns();
    struct fwl_rl_state *st =
      bpf_map_lookup_elem(&{rl_map}, &rl_key);
    __u32 cur = 0;
    __u64 cur_ts = now;
    if (st && now - st->ts < 1000000000ULL) {{
      cur = st->count;
      cur_ts = st->ts;
    }}
    struct fwl_rl_state new_st = {{ .ts = cur_ts, .count = cur + 1 }};
    int upd_rc = bpf_map_update_elem(
      &{rl_map}, &rl_key, &new_st, BPF_ANY);{ovf}
    if (cur >= {mod.threshold}) {{
      {ct_create}return {ret};
    }}"""


# Bucket-key capacity of every rate-limit map, zone- and global-scoped
# alike. A CONSTANT on purpose: a globally named map must be declared
# identically in every zone object or libbpf rejects the pin reuse
# (-EINVAL) the moment two zones' analyses disagree. Nothing here may
# ever be derived from a per-zone rule count.
_RL_MAX_ENTRIES = 4096


def _emit_rl_maps(
  program: ast.Program, names: MapNames, pinned_shared: bool = False
) -> str:
  """Emit the per-CPU hash map declaration for each rate_limit bucket.

  ZONE-scoped buckets get one map per rule index, unpinned and named
  for the emitting zone, so two zones can never land on one kernel
  map.

  GLOBAL-scoped buckets get one map per bundle-wide slot, pinned by
  name (in a bundle) so every zone object that holds the rule resolves
  to the SAME kernel map. Several rules in one zone may share a slot —
  that is the point — so the declarations are de-duplicated here.
  """
  blocks: list[str] = []
  emitted: set[str] = set()
  for idx, rule in enumerate(program.rules):
    if rule.modifier is None:
      continue
    name = names.rate_limit(rule.modifier, idx)
    if name in emitted:
      continue
    emitted.add(name)
    decl = f"""\
struct {{
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __type(key, __u32);
  __type(value, struct fwl_rl_state);
  __uint(max_entries, {_RL_MAX_ENTRIES});
}} {name} SEC(".maps");
"""
    if rule.modifier.scope is ast.RlScope.GLOBAL:
      decl = _maybe_pin(decl, pinned_shared)
    blocks.append(decl)
  return "\n".join(blocks)


def _collect_geoip_calls(program: ast.Program) -> list[ast.GeoIp]:
  """Walk every rule (Tier 1) and statement (Tier 2) collecting geoip
  call sites in source order. Mirrors the analyzer's call-index
  assignment so the emitted helpers' indices line up with the bundle
  manifest."""
  out: list[ast.GeoIp] = []
  for rule in program.rules:
    for n in _walk(rule.condition):
      if isinstance(n, ast.Comparison) and isinstance(n.operand, ast.GeoIp):
        out.append(n.operand)
  if program.function is not None:
    out.extend(_collect_geoip_in_stmts(program.function.body))
  return out


def _collect_geoip_in_stmts(stmts) -> list[ast.GeoIp]:
  out: list[ast.GeoIp] = []
  for s in stmts:
    if isinstance(s, ast.AssignStmt):
      for n in _walk_with_compares(s.rhs):
        if isinstance(n, ast.Comparison) and isinstance(n.operand, ast.GeoIp):
          out.append(n.operand)
    elif isinstance(s, ast.IfStmt):
      for n in _walk_with_compares(s.cond):
        if isinstance(n, ast.Comparison) and isinstance(n.operand, ast.GeoIp):
          out.append(n.operand)
      out.extend(_collect_geoip_in_stmts(s.body))
      for cond, body in s.elif_branches:
        for n in _walk_with_compares(cond):
          if isinstance(n, ast.Comparison) and isinstance(n.operand, ast.GeoIp):
            out.append(n.operand)
        out.extend(_collect_geoip_in_stmts(body))
      if s.else_body is not None:
        out.extend(_collect_geoip_in_stmts(s.else_body))
  return out


def _emit_geoip_maps_and_helpers(
  program: ast.Program, names: MapNames
) -> str:
  """Emit one BPF_MAP_TYPE_LPM_TRIE + lookup helper per geoip call site.

  Per FWL_V02_SPEC.md, each call site is bound to exactly one family
  (ipv4 or ipv6) and gets its own LPM trie. The daemon populates
  the trie at load time from `geoip.json`; the BPF program does the
  lookup. Helpers are `__always_inline` so the verifier sees a flat
  call site rather than a function-pointer indirection.

  The trie is a PRIVATE map — its call indices are numbered within the
  zone and userspace finds it by name — so its name (and the matching
  key struct) carries the zone in a bundle. The lookup helper does
  not: it is a static function with no linkage past this object, and
  its call sites elsewhere in the emitter address it by call index
  alone.
  """
  blocks: list[str] = []
  seen: set[int] = set()
  for call in _collect_geoip_calls(program):
    if call.call_index in seen:
      continue
    seen.add(call.call_index)
    trie = names.geoip(call.call_index)
    if call.family == "ipv4":
      blocks.append(f"""\
struct {trie}_key {{
  __u32 prefixlen;
  __u32 ip;
}};

struct {{
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __type(key, struct {trie}_key);
  __type(value, __u8);
  __uint(max_entries, 65536);
  __uint(map_flags, BPF_F_NO_PREALLOC);
}} {trie} SEC(".maps");

static __always_inline int fwl_geoip_{call.call_index}_v4(__u32 ip) {{
  struct {trie}_key key = {{
    .prefixlen = 32,
    .ip = bpf_htonl(ip),
  }};
  return bpf_map_lookup_elem(&{trie}, &key) != 0;
}}
""")
    elif call.family == "ipv6":
      blocks.append(f"""\
struct {trie}_key {{
  __u32 prefixlen;
  __u8  ip[16];
}};

struct {{
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __type(key, struct {trie}_key);
  __type(value, __u8);
  __uint(max_entries, 65536);
  __uint(map_flags, BPF_F_NO_PREALLOC);
}} {trie} SEC(".maps");

static __always_inline int fwl_geoip_{call.call_index}_v6(
    __u64 hi, __u64 lo) {{
  struct {trie}_key key = {{ .prefixlen = 128 }};
  key.ip[0]  = (hi >> 56) & 0xff; key.ip[1]  = (hi >> 48) & 0xff;
  key.ip[2]  = (hi >> 40) & 0xff; key.ip[3]  = (hi >> 32) & 0xff;
  key.ip[4]  = (hi >> 24) & 0xff; key.ip[5]  = (hi >> 16) & 0xff;
  key.ip[6]  = (hi >>  8) & 0xff; key.ip[7]  = (hi      ) & 0xff;
  key.ip[8]  = (lo >> 56) & 0xff; key.ip[9]  = (lo >> 48) & 0xff;
  key.ip[10] = (lo >> 40) & 0xff; key.ip[11] = (lo >> 32) & 0xff;
  key.ip[12] = (lo >> 24) & 0xff; key.ip[13] = (lo >> 16) & 0xff;
  key.ip[14] = (lo >>  8) & 0xff; key.ip[15] = (lo      ) & 0xff;
  return bpf_map_lookup_elem(&{trie}, &key) != 0;
}}
""")
    else:
      raise AssertionError(
        f"geoip call {call.call_index} has no family bound; "
        f"analyzer should have set it"
      )
  return "\n".join(blocks)


def _collect_redirect_zones(
  zp: ast.ZoneProgram,
  helpers: list[ast.FunctionDef] | None = None,
) -> list[str]:
  """Ordered, de-duplicated list of zones `zp` redirects to (v0.4 § 6.3).

  `helpers` are the unit's top-level defs. A `redirect to <zone>` that
  a helper performs emits a `fwl_devmap_<zone>` into this object just
  the same, and the daemon fills that devmap from the manifest's
  `redirects_to` — so a caller building the manifest must pass them,
  or the map stays empty and every redirected packet is dropped with
  nothing logged. `_emit_zone_source` scans the same closure.
  """
  out: list[str] = []
  seen: set[str] = set()

  def _add(z):
    if z and z not in seen:
      seen.add(z)
      out.append(z)

  units = [zp] + [
    _synth_unit(zp, h) for h in _reachable_helpers(zp, helpers or [])
  ]
  for u in units:
    for rule in u.rules:
      if rule.action == ast.Action.REDIRECT:
        _add(rule.redirect_zone)
    if u.function is not None:
      _collect_redirect_zones_stmts(u.function.body, _add)
  return out


def _collect_redirect_zones_stmts(stmts, add) -> None:
  for s in stmts:
    if isinstance(s, ast.ActionStmt) and s.action == ast.Action.REDIRECT:
      add(s.redirect_zone)
    elif isinstance(s, ast.IfStmt):
      _collect_redirect_zones_stmts(s.body, add)
      for _, body in s.elif_branches:
        _collect_redirect_zones_stmts(body, add)
      if s.else_body is not None:
        _collect_redirect_zones_stmts(s.else_body, add)


def _program_uses_nat(zp: ast.ZoneProgram) -> bool:
  """True iff `zp` contains any NAT rewrite action (Phase 5)."""
  for rule in zp.rules:
    if rule.action in ast.NAT_ACTIONS:
      return True
  if zp.function is not None:
    return _stmts_use_nat(zp.function.body)
  return False


def _stmts_use_nat(stmts) -> bool:
  for s in stmts:
    if isinstance(s, ast.ActionStmt) and s.action in ast.NAT_ACTIONS:
      return True
    if isinstance(s, ast.IfStmt):
      if _stmts_use_nat(s.body):
        return True
      for _, body in s.elif_branches:
        if _stmts_use_nat(body):
          return True
      if s.else_body is not None and _stmts_use_nat(s.else_body):
        return True
  return False


def _program_masquerades(
  zp: ast.ZoneProgram,
  helpers: list[ast.FunctionDef] | None = None,
) -> bool:
  """True iff `zp` uses the `masquerade` action.

  Only `masquerade` derives its source from the runtime `fwl_nat_cfg`
  map (the WAN address the daemon programs); `snat`/`dnat` bake fixed
  addresses into the emitted C. The daemon reads this manifest flag to
  decide which zone's fwl_nat_cfg to seed, so a non-masquerading zone
  that merely carries the shared de-NAT machinery is not mistaken for a
  masquerade source.

  `helpers` are the unit's top-level defs (v0.4 § 6.5). A `masquerade`
  reached only through a helper is still a masquerade, and the flag is
  what makes the daemon program an address at all — miss it and the
  action compiles, loads, and silently no-ops. Scanned over the same
  reachable set `_emit_zone_source` emits into the object, so the
  manifest cannot disagree with the code.
  """
  units = [zp] + [
    _synth_unit(zp, h) for h in _reachable_helpers(zp, helpers or [])
  ]
  for u in units:
    for rule in u.rules:
      if rule.action == ast.Action.MASQUERADE:
        return True
    if u.function is not None and _stmts_masquerade(u.function.body):
      return True
  return False


def _stmts_masquerade(stmts) -> bool:
  for s in stmts:
    if isinstance(s, ast.ActionStmt) and s.action == ast.Action.MASQUERADE:
      return True
    if isinstance(s, ast.IfStmt):
      if _stmts_masquerade(s.body):
        return True
      for _, body in s.elif_branches:
        if _stmts_masquerade(body):
          return True
      if s.else_body is not None and _stmts_masquerade(s.else_body):
        return True
  return False


def _emit_nat_call(action: ast.Action, nat_addr, nat_port) -> str:
  """C side-effect statement for one NAT rewrite action.

  `nat_addr` is the dotted-quad-as-int (big-endian) the parser produced;
  `bpf_htonl` converts it to the __be32 the packet carries. masquerade
  takes the source from the runtime `fwl_nat_cfg` map instead.

  A NAT action is non-terminal — it rewrites and falls through to the
  next rule — with ONE exception: a rewrite the helper could not claim a
  reply mapping for terminates the packet with XDP_DROP. Translating
  without a mapping is what makes a reply arrive at the firewall's own
  address (a full table, l11_02) or in another guest's socket (a port
  collision, l11_01), and both were silent. A drop is visible, is
  counted in `fwl_nat_stats`, and is the only outcome that cannot
  misdeliver somebody else's payload.
  """
  if action == ast.Action.MASQUERADE:
    call = "fwl_masquerade(ctx)"
  elif action == ast.Action.SNAT:
    call = f"fwl_snat_egress(ctx, bpf_htonl({nat_addr & 0xffffffff}U))"
  else:
    call = (f"fwl_dnat_ingress(ctx, bpf_htonl({nat_addr & 0xffffffff}U), "
            f"bpf_htons({nat_port}))")
  return f"if ({call} < 0) return XDP_DROP;"


def _emit_devmaps(zones: list[str], pinned: bool) -> str:
  """Emit one BPF_MAP_TYPE_DEVMAP per redirect-destination zone.

  The daemon populates each devmap at load time with the destination
  zone's interface ifindex(es). The BPF program calls
  bpf_redirect_map(&fwl_devmap_<zone>, 0, 0) (v0.4 § 6.3). In a
  multi-zone bundle the devmaps are pinned by name so the daemon can
  populate them once and every zone program sees the same map.
  """
  pin = (
    "\n  __uint(pinning, LIBBPF_PIN_BY_NAME);" if pinned else ""
  )
  blocks: list[str] = []
  for z in zones:
    blocks.append(f"""\
struct {{
  __uint(type, BPF_MAP_TYPE_DEVMAP);
  __type(key, __u32);
  __type(value, __u32);
  __uint(max_entries, 64);{pin}
}} fwl_devmap_{z} SEC(".maps");
""")
  if blocks:
    blocks.append(_maybe_pin(_ROUTE_DECL, pinned))
  return "\n".join(blocks)


def _emit_route_helpers(zones: list[str]) -> str:
  """The routing helpers, plus one redirect function per destination.

  Emitted only when the object can redirect somewhere. Must follow the
  devmap declarations (each function names its own map) and precede any
  `static __noinline` helper body, since a helper may redirect too.
  """
  if not zones:
    return ""
  return _ROUTE_HELPERS + "\n" + "\n".join(
    _ROUTE_ZONE_TEMPLATE.format(zone=z) for z in zones
  )


def _walk_calls_in_stmts(stmts):
  """Yield every CallStmt name in a statement block (all branches)."""
  for s in stmts:
    if isinstance(s, ast.CallStmt):
      yield s.name
    elif isinstance(s, ast.IfStmt):
      yield from _walk_calls_in_stmts(s.body)
      for _cond, body in s.elif_branches:
        yield from _walk_calls_in_stmts(body)
      if s.else_body is not None:
        yield from _walk_calls_in_stmts(s.else_body)


def _reachable_helpers(
  zp: ast.ZoneProgram, helpers: list[ast.FunctionDef]
) -> list[ast.FunctionDef]:
  """Transitive closure of helper defs called from a zone's body (v0.4
  § 6.5).

  Returns the reachable helpers in dependency order (callee before
  caller), so a C prototype block is unnecessary for straight-line call
  chains — though the emitter emits prototypes anyway for safety. Only
  a Tier 2 body can host a CallStmt; a Tier 1 rule zone reaches none.
  """
  by_name = {h.name: h for h in helpers}
  order: list[ast.FunctionDef] = []
  seen: set[str] = set()

  def visit(name: str) -> None:
    if name in seen or name not in by_name:
      return
    seen.add(name)
    h = by_name[name]
    for callee in _walk_calls_in_stmts(h.body):
      visit(callee)
    order.append(h)

  if zp.function is not None:
    for callee in _walk_calls_in_stmts(zp.function.body):
      visit(callee)
  return order


def _synth_unit(zp: ast.ZoneProgram, func: ast.FunctionDef) -> ast.ZoneProgram:
  """Wrap a helper def as a ZoneProgram so per-unit collectors reuse."""
  return ast.ZoneProgram(hook=zp.hook, function=func)


def _allocate_counter_slots_units(
  units: list[ast.ZoneProgram],
) -> dict[str, int]:
  """Allocate counter slots across a zone body + its reachable helpers.

  Counters of the same name in the body and a helper share one slot
  (one per-CPU map per zone object). The reserved rate-limit overflow
  slot stays last, after every user counter from every unit.
  """
  slots: dict[str, int] = {}
  uses_rl = False
  for u in units:
    for rule in u.rules:
      if rule.action == ast.Action.COUNT and rule.counter_name:
        if rule.counter_name not in slots:
          slots[rule.counter_name] = len(slots)
      for n in _walk(rule.condition):
        if isinstance(n, ast.CountCompare):
          name = n.call.counter_name
          if name not in slots:
            slots[name] = len(slots)
    if u.function is not None:
      _collect_tier2_counter_slots(u.function.body, slots)
    if _program_uses_rate_limit(u):
      uses_rl = True
  if uses_rl:
    slots[RATE_LIMIT_OVERFLOW_COUNTER] = len(slots)
  return slots


def _emit_helper_function(
  names: MapNames,
  func: ast.FunctionDef,
  counter_slots: dict[str, int],
  zp: ast.ZoneProgram,
  ct_create: str,
  zone_name: str | None,
) -> str:
  """Emit one helper `def` as a `static __noinline` BPF function (v0.4
  § 6.5).

  The helper parses the frame independently (its own prelude, whose
  non-IP early-out returns FWL_CONTINUE so the caller keeps going),
  runs its Tier 2 body, and falls through to `return FWL_CONTINUE`. A
  terminal action inside the body emits `return XDP_...`, which the
  call site propagates.
  """
  synth = _synth_unit(zp, func)
  prelude = _emit_parse_prelude(synth, early_out="FWL_CONTINUE")
  body, _ = _emit_tier2_body(
    names, func, counter_slots, synth, ct_create, zone_name
  )
  return (
    f"static __noinline int fwl_helper_{func.name}"
    f"(struct xdp_md *ctx) {{\n"
    f"{prelude}{body}  return FWL_CONTINUE;\n"
    f"}}\n"
  )


def emit(program: ast.Program, *, split: bool | None = None) -> str:
  """Emit BPF C source for the first @xdp block of `program`.

  This is the single-object entry point used by `fwl compile -o` and
  by the test runner's BPF oracle (one zone program per object,
  maps defined inline, no bpffs pinning). For a multi-zone bundle with
  bpffs-pinned shared maps, see `emit_bundle`.

  `split` (v0.4 § 6.6): None lets the estimator decide; True/False force
  a tail-call pipeline / single program. The pipeline_equivalence
  harness emits the same program both ways and checks identical
  behavior.
  """
  _check_zone_ids(program)
  return _emit_zone_source(
    program.programs[0], pinned_shared=False, helpers=program.helpers,
    split=split,
  )


def _emit_zone_source(
  zp: ast.ZoneProgram, *, pinned_shared: bool, force_nat: bool = False,
  helpers: list[ast.FunctionDef] | None = None,
  split: bool | None = None,
) -> str:
  """Emit one zone's complete BPF C source.

  `zp` is a single @xdp block. `pinned_shared` controls whether the
  bpffs-backed maps carry LIBBPF_PIN_BY_NAME (v0.4 § 6.2), and is true
  exactly for a bundle. Pinning alone does NOT make a map
  bundle-shared: the NAME decides that, and the name comes from
  `MapNames`, which gives every map classified PRIVATE in `_MAP_KINDS`
  a per-zone name so it pins to its own kernel map. Only the maps
  classified SHARED — bundle-global by construction — resolve to one
  kernel map across every zone program. Before returning, the source
  is checked against the registry (`_check_map_scopes`), so a map
  nobody classified fails the compile instead of quietly sharing.

  `helpers` are the unit's top-level helper defs (v0.4 § 6.5); the ones
  this zone reaches via CallStmt are emitted into this object as
  `static __noinline` functions, and the shared-map / counter analysis
  spans the zone body plus those reachable helpers.

  `split` (v0.4 § 6.6): None lets the estimator decide; True forces a
  tail-call pipeline (used by the pipeline_equivalence harness); False
  forces a single program. When the plan splits, the object holds N
  `fwl_stage_i` programs chained through a prog_array + per-CPU scratch
  map instead of one `fwl_prog`.

  Tier 1: prelude + per-rule blocks + final return.
  Tier 2: prelude + locals declaration + statement-by-statement body.
  """
  zone_name = zp.zone_name
  # A PRIVATE map's name carries the zone only in a bundle; a
  # single-object emission pins nothing, so base names are unambiguous
  # there and the test runner's BPF oracle can address them.
  names = MapNames(zone_name if pinned_shared else None)
  if split is False:
    plan = splitter.SplitPlan(
      split=False, stages=(), estimate=splitter.estimate(zp),
      reason="forced single",
    )
  else:
    plan = splitter.plan(zp, force_split=(split is True))
  reachable = _reachable_helpers(zp, helpers or [])
  # The zone body plus every helper it reaches, each wrapped as a unit
  # so the per-unit collectors (conntrack/NAT/log/rate-limit/counters)
  # account for helper usage — the maps are declared once, shared by the
  # body and its `static __noinline` helper functions.
  units = [zp] + [_synth_unit(zp, h) for h in reachable]
  prelude = _emit_parse_prelude(zp)
  rl_maps = _emit_rl_maps(zp, names, pinned_shared)
  geoip_block = _emit_geoip_maps_and_helpers(zp, names)
  uses_ct = any(_program_uses_conntrack(u) for u in units)
  # Redirect targets from the zone body and any reachable helper (a
  # helper may `redirect to <zone>`), de-duplicated in first-seen order.
  redirect_zones: list[str] = []
  for u in units:
    for z in _collect_redirect_zones(u):
      if z not in redirect_zones:
        redirect_zones.append(z)
  devmaps = _emit_devmaps(redirect_zones, pinned_shared)
  route_helpers = _emit_route_helpers(redirect_zones)

  # Phase 5 NAT. Emit the maps + helpers when this program uses NAT, or
  # when forced (a bundle where some other zone does — so return traffic
  # de-NATs on whichever zone it arrives). The de-NAT pass runs before
  # any rule.
  nat_active = any(_program_uses_nat(u) for u in units) or force_nat

  # A source-NAT action tracks the flow (fwl_snat_egress inserts the
  # post-NAT 5-tuple into conntrack so the reply reads `established`), so
  # the conntrack map + structs must be present whenever NAT helpers are
  # emitted — even in a program that never reads conntrack(pkt).state.
  conntrack_decl = (
    _maybe_pin(_CONNTRACK_DECL, pinned_shared)
    if (uses_ct or nat_active) else ""
  )
  # The RELATED classifier is only referenced by the prelude's ct
  # block, so it follows `uses_ct` alone — a NAT-only program declares
  # the map (for the post-NAT insert) but never reads a state.
  if uses_ct:
    conntrack_decl += _CONNTRACK_HELPERS
  ct_create = _emit_ct_create() if uses_ct else ""

  nat_decl = _maybe_pin(_NAT_DECL, pinned_shared) if nat_active else ""
  nat_helpers = _NAT_HELPERS if nat_active else ""
  nat_denat = "  fwl_nat_denat(ctx);\n" if nat_active else ""

  counter_slots = _allocate_counter_slots_units(units)
  has_log = any(_program_uses_log(u) for u in units)

  log_decl = _maybe_pin(_LOG_EVENT_DECL, pinned_shared) if has_log else ""
  sampled = sum(
    1 for r in zp.rules
    if r.action == ast.Action.LOG
    and r.log_sample is not None and r.log_sample > 1
  )
  log_sample_decl = ""
  if sampled > 0:
    log_sample_decl = _maybe_pin(
      _LOG_SAMPLE_MAP_DECL_TEMPLATE.format(
        n_rules=len(zp.rules), name=names.log_sample()
      ),
      pinned_shared,
    )
  if counter_slots:
    counter_decl = _maybe_pin(
      _COUNTER_MAP_DECL_TEMPLATE.format(
        n_slots=max(len(counter_slots), 1), name=names.counters()
      ),
      pinned_shared,
    )
    counter_table = _emit_counter_table(counter_slots)
  else:
    counter_decl = ""
    counter_table = ""

  # v0.4 § 6.5: forward-declare every reachable helper (so any call
  # order compiles), then emit their definitions before the program(s).
  # The helpers come after nat_helpers because a NAT helper
  # (fwl_masquerade etc.) may be referenced from a helper body.
  helper_protos = "".join(
    f"static __noinline int fwl_helper_{h.name}(struct xdp_md *ctx);\n"
    for h in reachable
  )
  helper_defs = "".join(
    _emit_helper_function(
      names, h, counter_slots, zp, ct_create, zone_name
    )
    + "\n"
    for h in reachable
  )

  maps_block = (
    f"{log_decl}{log_sample_decl}{counter_decl}{rl_maps}{geoip_block}"
    f"{conntrack_decl}{nat_decl}{devmaps}"
  )

  if plan.split:
    # v0.4 § 6.6: N-program tail-call pipeline in one object.
    programs = _emit_split_programs(
      names, zp, plan, counter_slots, ct_create, zone_name, prelude,
      nat_denat,
    )
    scratch_struct = _emit_scratch_struct(zp)
    # The scratch + prog_array are object-private transients (per-packet
    # per-CPU metadata; this zone's own stage table). They must NOT pin
    # by name — pinning would collide two split zones onto one kernel
    # map in a bundle, cross-wiring their pipelines. Each zone object
    # keeps its own unpinned copy. `_MAP_KINDS` classifies both PRIVATE
    # with no zone-qualified name, and `_check_map_scopes` fails the
    # compile if either ever acquires LIBBPF_PIN_BY_NAME.
    scratch_map = _SCRATCH_MAP_DECL_TEMPLATE.format(
      name=names.qualified("fwl_scratch")
    )
    prog_array = _PROG_ARRAY_DECL_TEMPLATE.format(
      n=plan.n_stages, name=names.qualified("fwl_stages")
    )
    src = f"""{_HEADER}
{scratch_struct}
{maps_block}{scratch_map}{prog_array}
{nat_helpers}{route_helpers}
{helper_protos}{helper_defs}{programs}
char _license[] SEC("license") = "GPL";
{counter_table}"""
    _check_map_scopes(src, names)
    return src

  if zp.function is not None:
    body, _ = _emit_tier2_body(
      names, zp.function, counter_slots, zp, ct_create, zone_name
    )
    # Tier 2 fall-through is an implicit XDP_PASS (no rule "allowed"
    # the packet), so it does not create conntrack state.
    final_stmt = "return XDP_PASS;"
  else:
    body = "".join(
      _emit_rule(names, r, i, counter_slots, ct_create, zone_name)
      for i, r in enumerate(zp.rules)
    )
    final_stmt = _emit_final_stmt(zp, ct_create)

  src = f"""{_HEADER}
{maps_block}
{nat_helpers}{route_helpers}
{helper_protos}{helper_defs}SEC("xdp")
int fwl_prog(struct xdp_md *ctx) {{
{prelude}{nat_denat}{body}  {final_stmt}
}}

char _license[] SEC("license") = "GPL";
{counter_table}"""
  _check_map_scopes(src, names)
  return src


def _emit_final_stmt(zp: ast.ZoneProgram, ct_create: str) -> str:
  """The default-action / fall-through return for a Tier 1 rule zone."""
  if zp.default is not None:
    ret = _TERMINAL_ACTION_TO_RETURN[zp.default.action]
    # An explicit `default allow` creates state like any allow; an
    # explicit `default drop` (or the implicit fall-through) does not.
    create = ct_create if zp.default.action == ast.Action.ALLOW else ""
    return f"{create}return {ret};"
  return "return XDP_PASS;"


# v0.4 § 6.6 pipeline maps. The scratch map is a single-entry per-CPU
# array holding the parsed-packet metadata the parse stage writes and
# every later stage reads — one entry per CPU keeps the tail-call chain
# (which stays on one CPU) race-free. The prog_array wires the stages;
# the daemon/runner populates it with each stage program's fd at load.
_SCRATCH_MAP_DECL_TEMPLATE = """\
struct {{
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, __u32);
  __type(value, struct fwl_meta);
  __uint(max_entries, 1);
}} {name} SEC(".maps");
"""

_PROG_ARRAY_DECL_TEMPLATE = """\
struct {{
  __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(__u32));
  __uint(max_entries, {n});
}} {name} SEC(".maps");
"""


def _scratch_members(zp: ast.ZoneProgram) -> list[tuple[str, str]]:
  """The (C type, name) members of `struct fwl_meta` for a split zone.

  Mirrors exactly the local declarations `_emit_parse_prelude` makes
  for the same zone, so the parse stage packs each parsed local into
  the scratch struct and every policy stage unpacks it back into an
  identically-named local — the rule/statement emitters then run
  unchanged against those bare locals (v0.4 § 6.6).
  """
  fields = _referenced_fields(zp)
  # Keep the scratch struct in lockstep with the parse prelude: when the
  # zone body references no packet fields directly (e.g. a Tier 2 body
  # that only calls helpers, which re-parse from ctx themselves),
  # _emit_parse_prelude emits nothing, so there are no parsed locals to
  # pack — the scratch is empty too.
  if not fields:
    return []
  needs_l4 = _needs_l4(fields)
  needs_icmp = _needs_icmp(fields)
  needs_icmp6 = _needs_icmp6(fields)
  uses_ct = _program_uses_conntrack(zp)
  needs_vlan_id = ast.FIELD_VLAN_ID in fields
  needs_vlan_priority = ast.FIELD_VLAN_PRIORITY in fields
  needs_vlan = needs_vlan_id or needs_vlan_priority
  m: list[tuple[str, str]] = [("__u8", "proto"), ("__u8", "v4_ok")]
  if needs_l4:
    m.append(("__u8", "l4_ok"))
  if ast.FIELD_SRC_IP in fields:
    m.append(("__u32", "src_ip"))
  if ast.FIELD_DST_IP in fields:
    m.append(("__u32", "dst_ip"))
  m.append(("__u8", "v6_ok"))
  if ast.FIELD_SRC_IP6 in fields:
    m += [("__u64", "src_ip6_hi"), ("__u64", "src_ip6_lo")]
  if ast.FIELD_DST_IP6 in fields:
    m += [("__u64", "dst_ip6_hi"), ("__u64", "dst_ip6_lo")]
  if ast.FIELD_SRC_PORT in fields:
    m.append(("__u16", "src_port"))
  if ast.FIELD_DST_PORT in fields:
    m.append(("__u16", "dst_port"))
  for field_const, c_var, _bit in _TCP_FLAG_VARS:
    if field_const in fields:
      m.append(("__u8", c_var))
  if needs_icmp:
    m.append(("__u8", "icmp_ok"))
    if ast.FIELD_ICMP_TYPE in fields:
      m.append(("__u8", "icmp_type"))
    if ast.FIELD_ICMP_CODE in fields:
      m.append(("__u8", "icmp_code"))
  if needs_icmp6:
    m.append(("__u8", "icmp6_ok"))
    if ast.FIELD_ICMP6_TYPE in fields:
      m.append(("__u8", "icmp6_type"))
    if ast.FIELD_ICMP6_CODE in fields:
      m.append(("__u8", "icmp6_code"))
  if needs_vlan:
    m.append(("__u8", "vlan_ok"))
    if needs_vlan_id:
      m.append(("__u16", "vlan_id"))
    if needs_vlan_priority:
      m.append(("__u8", "vlan_priority"))
  if uses_ct:
    m += [
      ("__u8", "ct_state"), ("__u8", "ct_v4"),
      ("__u32", "ct_k_src"), ("__u32", "ct_k_dst"),
      ("__u16", "ct_k_sport"), ("__u16", "ct_k_dport"),
      ("__u8", "ct_k_proto"),
    ]
  return m


def _emit_scratch_struct(zp: ast.ZoneProgram) -> str:
  """Emit `struct fwl_meta { ... }` for a split zone's scratch map."""
  members = _scratch_members(zp)
  # A zone whose body references no fields directly (helpers re-parse)
  # has an empty working set — but a zero-size map value is invalid, so
  # emit a one-byte placeholder to keep the per-CPU array well-formed.
  if not members:
    members = [("__u8", "_unused")]
  lines = "".join(f"  {ctype} {name};\n" for ctype, name in members)
  return (
    "// v0.4 § 6.6 per-CPU scratch: parsed once by the parse stage,\n"
    "// read by every downstream stage (no re-parsing).\n"
    f"struct fwl_meta {{\n{lines}}};\n"
  )


def _emit_scratch_lookup(scratch_map: str) -> str:
  """Emit the scratch-map lookup prologue shared by every stage."""
  return (
    "  __u32 _zero = 0;\n"
    f"  struct fwl_meta *_m = bpf_map_lookup_elem(&{scratch_map}, "
    "&_zero);\n"
    "  if (!_m) return XDP_PASS;\n"
  )


def _emit_scratch_pack(zp: ast.ZoneProgram) -> str:
  """Copy the parse stage's parsed locals into the scratch struct."""
  return "".join(
    f"  _m->{name} = {name};\n" for _ctype, name in _scratch_members(zp)
  )


def _emit_scratch_unpack(zp: ast.ZoneProgram) -> str:
  """Restore a downstream stage's bare locals from the scratch struct."""
  return "".join(
    f"  {ctype} {name} = _m->{name};\n"
    for ctype, name in _scratch_members(zp)
  )


def _emit_split_programs(
  names: MapNames,
  zp: ast.ZoneProgram,
  plan: "splitter.SplitPlan",
  counter_slots: dict[str, int],
  ct_create: str,
  zone_name: str | None,
  prelude: str,
  nat_denat: str,
) -> str:
  """Emit the N `fwl_stage_i` programs of a split pipeline (v0.4 § 6.6).

  Stage 0 parses into the scratch struct and tail-calls stage 1. Each
  policy stage restores the scratch locals, runs its slice of the
  policy, and either tail-calls the next stage or (the last stage)
  applies the default. A tail-call that finds no successor program
  falls through to `XDP_PASS` — fail-open, matching the implicit
  fall-through of a single program; the loader always populates every
  slot so this is unreachable in practice.
  """
  stages_map = names.qualified("fwl_stages")
  scratch_map = names.qualified("fwl_scratch")
  out: list[str] = []
  # Stage 0: parse + de-NAT + pack scratch, then jump to stage 1.
  out.append(
    f'SEC("xdp")\nint fwl_stage_0(struct xdp_md *ctx) {{\n'
    f"{prelude}{nat_denat}"
    f"{_emit_scratch_lookup(scratch_map)}{_emit_scratch_pack(zp)}"
    f"  bpf_tail_call(ctx, &{stages_map}, 1);\n"
    f"  return XDP_PASS;\n}}\n"
  )
  unpack = _emit_scratch_unpack(zp)
  for stage in plan.stages:
    if stage.kind == "parse":
      continue
    if stage.kind == "policy":
      body, _ = _emit_tier2_body(
        names, zp.function, counter_slots, zp, ct_create, zone_name
      )
      tail = "  return XDP_PASS;\n"
    else:
      lo, hi = stage.rule_range
      body = "".join(
        _emit_rule(
          names, zp.rules[i], i, counter_slots, ct_create, zone_name
        )
        for i in range(lo, hi)
      )
      if stage.is_last:
        tail = f"  {_emit_final_stmt(zp, ct_create)}\n"
      else:
        tail = (
          f"  bpf_tail_call(ctx, &{stages_map}, {stage.index + 1});\n"
          f"  return XDP_PASS;\n"
        )
    out.append(
      f'SEC("xdp")\nint fwl_stage_{stage.index}(struct xdp_md *ctx) {{\n'
      f"{_emit_scratch_lookup(scratch_map)}{unpack}{body}{tail}}}\n"
    )
  return "\n".join(out) + "\n"


def _maybe_pin(map_decl: str, pinned: bool) -> str:
  """Add LIBBPF_PIN_BY_NAME to a `} name SEC(".maps");` declaration.

  Inserts the pinning attribute on the last map-struct body before its
  closing brace so the map is shared by name across the bundle's zone
  programs (bpffs pinning, v0.4 § 6.2). A no-op when `pinned` is False
  (single-object emission, e.g. the test runner).
  """
  if not pinned:
    return map_decl
  out: list[str] = []
  for block in map_decl.split("\n\n"):
    if 'SEC(".maps")' in block and "LIBBPF_PIN_BY_NAME" not in block:
      idx = block.rfind("\n}")
      if idx != -1:
        block = (
          block[:idx]
          + "\n  __uint(pinning, LIBBPF_PIN_BY_NAME);"
          + block[idx:]
        )
    out.append(block)
  return "\n\n".join(out)


def emit_bundle(program: ast.Program) -> dict[str, str]:
  """Emit a multi-zone bundle: one BPF C file per @xdp block (v0.4 § 6.2).

  Returns a mapping of filename -> C source:
    - `<zone>.bpf.c` per zone program — its prelude, rules/function,
      redirect devmaps, the cross-zone shared maps it uses (conntrack,
      fwl_nat, fwl_nat_cfg, fwl_log_events, a scope=global rate-limit
      bucket) under their bundle-global names, and its zone-private
      maps (counters, zone-scoped rate limits, geoip, log-sample)
      under per-zone names. Both kinds may carry LIBBPF_PIN_BY_NAME;
      the NAME is what decides sharing, and `_MAP_KINDS` is what
      decides the name.

    - `fwl_shared.h` — a manifest header documenting the pinned maps
      every zone program shares via bpffs (the cross-zone state).

  Each zone compiles to its own .bpf.o. The daemon loads them with a
  common bpffs pin root so libbpf resolves the pin-by-name shared maps
  (above all, `conntrack`) to a single kernel map — established flows
  tracked on one zone are visible to every other zone. The single-zone
  degenerate case still goes through `emit()` (no pinning).

  Three invariants run here, on every compile:
    - per zone, `_check_map_scopes` — every map in the generated source
      has a declared scope, and carries (or does not carry) the pinning
      attribute and the zone qualifier that scope demands;
    - across zones, `_check_bundle_pinned_maps` — a name pinned by more
      than one object is declared identically in all of them;
    - across zones, `_check_zone_ids` — no two zones share the
      `zone_id` their log events are tagged with.
  The first catches a map nobody classified; the second catches one
  classified SHARED whose shape still comes from a per-zone analysis;
  the third catches the shared ring buffer's records becoming
  ambiguous again.
  """
  _check_zone_ids(program)
  # When any zone uses NAT, every zone program emits the shared NAT map
  # + de-NAT pass so return traffic is un-translated on whichever zone
  # it lands (the egress zone installs the reply mapping; the ingress
  # zone consumes it).
  bundle_nat = any(_program_uses_nat(zp) for zp in program.programs)
  files: dict[str, str] = {}
  for zp in program.programs:
    files[f"{zp.zone_name}.bpf.c"] = _emit_zone_source(
      zp, pinned_shared=True, force_nat=bundle_nat,
      helpers=program.helpers,
    )
  _check_bundle_pinned_maps(files)
  files["fwl_shared.h"] = _emit_shared_header(program)
  return files


def shared_pinned_map_names(files: dict[str, str]) -> list[str]:
  """The bundle-global pinned names an emitted bundle actually declares.

  Read back out of the generated sources rather than listed by hand:
  the manifest used to state `["conntrack"]` unconditionally, which was
  wrong in both directions — it omitted fwl_nat, the devmaps, the log
  ring and the scope=global rate-limit buckets, and it claimed
  conntrack for bundles whose policy never reads it.
  """
  names: list[str] = []
  for fname, src in sorted(files.items()):
    if not fname.endswith(".bpf.c"):
      continue
    for decl in _scan_map_decls(src):
      kind = _map_kind(decl.name)
      if (
        decl.pinned
        and kind is not None
        and kind.scope is MapScope.SHARED
        and decl.name not in names
      ):
        names.append(decl.name)
  return sorted(names)


# A `struct { ... } name SEC(".maps");` declaration in generated C.
# Map bodies never nest braces, so `[^{}]*` keeps the match anchored to
# one declaration.
_MAP_DECL_RE = re.compile(
  r"struct\s*\{(?P<body>[^{}]*)\}\s*(?P<name>\w+)\s*SEC\(\"\.maps\"\);"
)

# One `__uint(attr, value);` / `__type(attr, value);` line of a map body.
_MAP_ATTR_RE = re.compile(r"__(?:uint|type)\(\s*(\w+)\s*,\s*(.+?)\s*\)\s*;")


@dataclasses.dataclass(frozen=True)
class _DeclaredMap:
  """A map declaration found in generated source."""
  name: str
  # (attribute, value) pairs in declaration order, whitespace-normalized
  # — the shape libbpf validates when it reuses a pin.
  attrs: tuple[tuple[str, str], ...]
  pinned: bool

  def attr(self, key: str) -> str | None:
    """The value declared for `key`, or None."""
    for name, value in self.attrs:
      if name == key:
        return value
    return None


def _scan_map_decls(src: str) -> list[_DeclaredMap]:
  """Every map declared in `src`.

  The generated text is the ground truth for what the emitter produced:
  a check driven by a list the author also has to update would fail in
  exactly the case it exists for.
  """
  found: list[_DeclaredMap] = []
  for m in _MAP_DECL_RE.finditer(src):
    attrs = tuple(
      (key, " ".join(value.split()))
      for key, value in _MAP_ATTR_RE.findall(m.group("body"))
    )
    found.append(_DeclaredMap(
      name=m.group("name"),
      attrs=attrs,
      pinned="LIBBPF_PIN_BY_NAME" in m.group("body"),
    ))
  return found


def _check_map_scopes(src: str, names: MapNames) -> None:
  """Fail the compile for any map whose sharing is not declared.

  Runs on every emitted zone source, single-object and bundle alike.
  Four things must hold for each map in the generated text:

    1. it has a row in `_MAP_KINDS` — SHARED or PRIVATE, no default;
    2. a PRIVATE map that qualifies by name is emitted under its
       zone-qualified name in a bundle, not its base name;
    3. a PRIVATE map that has no zone-qualified name (the object-local
       transients) does not carry LIBBPF_PIN_BY_NAME, which would
       collide two zones onto one kernel map;
    4. a SHARED map in a bundle does carry LIBBPF_PIN_BY_NAME —
       otherwise each object gets its own copy and the state that was
       supposed to be bundle-wide silently is not.

  (1) is the one that matters most: it is what makes forgetting fail
  loudly instead of aliasing quietly.
  """
  bundle = names.zone is not None
  for decl in _scan_map_decls(src):
    kind = names.issued.get(decl.name) or _map_kind(decl.name)
    if kind is None:
      raise _unclassified_map_error(decl.name)
    if (
      bundle
      and decl.name not in names.issued
      and kind.scope is MapScope.PRIVATE
      and kind.private_name is not None
    ):
      raise _codegen_error(
        f"map '{decl.name}' is PRIVATE ({kind.why}) but zone "
        f"'{names.zone}' emits it under its bundle-global name. Take "
        f"the name from MapNames so it carries the zone: two zones "
        f"pinning this name share one kernel map, and when their "
        f"shapes happen to agree that sharing is silent."
      )
    if (
      decl.pinned
      and kind.scope is MapScope.PRIVATE
      and kind.private_name is None
    ):
      raise _codegen_error(
        f"map '{decl.name}' is object-private ({kind.why}) but is "
        f"declared with LIBBPF_PIN_BY_NAME, so every zone object in a "
        f"bundle would resolve it to one kernel map."
      )
    if bundle and kind.scope is MapScope.SHARED and not decl.pinned:
      raise _codegen_error(
        f"map '{decl.name}' is SHARED ({kind.why}) but zone "
        f"'{names.zone}' declares it without LIBBPF_PIN_BY_NAME, so "
        f"each zone object would get its own kernel map and the state "
        f"would not be bundle-wide at all."
      )


def _check_bundle_pinned_maps(files: dict[str, str]) -> None:
  """Every bundle-global pin must be one map, declared identically.

  libbpf validates a map's definition when it reuses an existing pin.
  Two zone objects that pin the same NAME with different type, key,
  value or max_entries make the second load fail with -EINVAL
  ("parameter mismatch"); two that agree only by accident load and
  share one kernel map with no error and no symptom. Both are visible
  in the artifact SET at compile time, so they are caught here rather
  than on the wire.

  This is the check that catches MISCLASSIFICATION — a map declared
  SHARED whose shape is still derived from one zone's analysis.
  `_check_map_scopes` catches the omission; this catches the
  misjudgement.
  """
  # map name -> declared shape -> the zones declaring it that way.
  seen: dict[str, dict[tuple[tuple[str, str], ...], list[str]]] = {}
  for fname, src in files.items():
    if not fname.endswith(".bpf.c"):
      continue
    zone = fname[: -len(".bpf.c")]
    for decl in _scan_map_decls(src):
      if not decl.pinned:
        continue
      seen.setdefault(decl.name, {}).setdefault(decl.attrs, []).append(zone)
  for name, shapes in sorted(seen.items()):
    if len(shapes) < 2:
      continue
    raise _codegen_error(_bundle_shape_message(name, shapes))


def _bundle_shape_message(
  name: str,
  shapes: dict[tuple[tuple[str, str], ...], list[str]],
) -> str:
  """Name the map, the zones, and every attribute they disagree on."""
  variants = [(dict(shape), zones) for shape, zones in shapes.items()]
  keys = {k for shape, _ in variants for k in shape}
  differing = sorted(
    k for k in keys
    if len({shape.get(k) for shape, _ in variants}) > 1
  )
  lines = []
  for shape, zones in variants:
    zone_list = ", ".join(f"'{z}'" for z in sorted(zones))
    values = ", ".join(
      f"{k}={shape.get(k, '(absent)')}" for k in differing
    )
    lines.append(f"  zone(s) {zone_list}: {values}")
  detail = "\n".join(lines)
  return (
    f"map '{name}' is pinned under one bundle-global name but is not "
    f"declared the same way by every zone:\n{detail}\n"
    f"A pinned name is ONE kernel map. libbpf rejects the second "
    f"object with -EINVAL when the definitions differ, and shares the "
    f"map silently when they happen to agree. Either the shape must "
    f"not come from a per-zone analysis (size it from a constant), or "
    f"the map is not bundle-wide state at all and belongs in "
    f"_MAP_KINDS as MapScope.PRIVATE so its name carries the zone."
  )


def _emit_shared_header(program: ast.Program) -> str:
  """Emit a header documenting the bundle's bpffs-pinned shared maps.

  The maps are defined (pin-by-name) inside each zone's .bpf.c; this
  header is the human/daemon-facing manifest of which maps are shared
  and which zones redirect where, so the loader knows what to pin and
  populate.
  """
  zone_lines = "\n".join(
    f"//   zone {z.name} = [{', '.join(z.interfaces)}]"
    for z in program.zones
  )
  zone_id_lines = "\n".join(
    f"//   0x{zid:08X}  {name}"
    for name, zid in log_abi.zone_ids(
      emitting_zone_names(program)
    ).items()
  )
  redirect_lines = "\n".join(
    f"//   @xdp({zp.zone_name}) redirects to: "
    f"{', '.join(_collect_redirect_zones(zp)) or '(none)'}"
    for zp in program.programs
  )
  return f"""\
// Generated by fwl. Do not edit.
// FWL multi-zone bundle manifest (v0.4 § 6.2).
//
// Each <zone>.bpf.c compiles to its own XDP program. Shared state is
// held in bpffs-pinned maps (LIBBPF_PIN_BY_NAME) so every zone program
// resolves to the SAME kernel map — load all objects with a common
// pin root. The `conntrack` map is the cross-zone state: a flow
// established on one zone is ESTABLISHED for every other zone.
//
// Zones:
{zone_lines or '//   (none — degenerate single-zone unit)'}
//
// Redirect topology (devmaps, daemon-populated with egress ifindexes):
{redirect_lines}
//
// Log-event zone ids. `fwl_log_events` is ONE ring for the bundle and
// `rule_index` is numbered per zone, so a record is read as
// (zone_id, rule_index). The machine-readable copy of this table is
// manifest.json's "zone_ids" — use that, not this comment.
{zone_id_lines or '//   (none)'}
"""


def _program_uses_log(program: ast.Program) -> bool:
  """True if any rule or Tier 2 statement uses log."""
  if any(r.action == ast.Action.LOG for r in program.rules):
    return True
  if program.function is not None:
    return _stmts_use_log(program.function.body)
  return False


def _stmts_use_log(stmts) -> bool:
  for s in stmts:
    if isinstance(s, ast.ActionStmt) and s.action == ast.Action.LOG:
      return True
    if isinstance(s, ast.IfStmt):
      if _stmts_use_log(s.body):
        return True
      for _, body in s.elif_branches:
        if _stmts_use_log(body):
          return True
      if s.else_body and _stmts_use_log(s.else_body):
        return True
  return False


_LOCAL_C_TYPE = {
  ast.LocalType.BOOL: "__u8",
  ast.LocalType.U16: "__u16",
  ast.LocalType.U32: "__u32",
  ast.LocalType.IPV4: "__u32",
  ast.LocalType.IPV6: "__u64",  # split into hi/lo halves below
  ast.LocalType.PROTO: "__u8",
}


def _collect_tier2_locals(stmts, out: dict[str, ast.LocalType]) -> None:
  """Walk Tier 2 stmts collecting (name, inferred type) pairs.

  Mirrors the analyzer's source-order first-assignment binding rule.
  """
  for s in stmts:
    if isinstance(s, ast.AssignStmt):
      if s.name not in out:
        out[s.name] = _infer_assign_type(s.rhs, out)
    elif isinstance(s, ast.IfStmt):
      _collect_tier2_locals(s.body, out)
      for _, body in s.elif_branches:
        _collect_tier2_locals(body, out)
      if s.else_body is not None:
        _collect_tier2_locals(s.else_body, out)


def _infer_assign_type(
  rhs, locals_: dict[str, ast.LocalType]
) -> ast.LocalType:
  """Light type inference for the emitter's local declarations.

  Mirrors analyzer._infer_scalar_type but doesn't run dominator
  checks — analyzer already validated the program. Recurses through
  comparison/condition exprs (always bool-typed in v0.2).
  """
  if isinstance(rhs, ast.IntLiteral):
    return ast.LocalType.U16 if rhs.value <= 0xFFFF else ast.LocalType.U32
  if isinstance(rhs, ast.IPv4Literal):
    return ast.LocalType.IPV4
  if isinstance(rhs, ast.Ipv6Literal):
    return ast.LocalType.IPV6
  if isinstance(rhs, ast.ProtoLiteral):
    return ast.LocalType.PROTO
  if isinstance(rhs, ast.LocalRead):
    return locals_[rhs.name]
  if isinstance(rhs, ast.FieldRef):
    return _FIELD_LOCAL_TYPE[rhs.name]
  if isinstance(rhs, (ast.BoolField, ast.Comparison, ast.AndOp, ast.OrOp,
                      ast.NotOp, ast.RateLimitCall)):
    return ast.LocalType.BOOL
  raise AssertionError(f"unexpected scalar expr {type(rhs).__name__}")


_FIELD_LOCAL_TYPE = {
  ast.FIELD_PROTO: ast.LocalType.PROTO,
  ast.FIELD_SRC_IP: ast.LocalType.IPV4,
  ast.FIELD_DST_IP: ast.LocalType.IPV4,
  ast.FIELD_SRC_IP6: ast.LocalType.IPV6,
  ast.FIELD_DST_IP6: ast.LocalType.IPV6,
  ast.FIELD_SRC_PORT: ast.LocalType.U16,
  ast.FIELD_DST_PORT: ast.LocalType.U16,
  ast.FIELD_TCP_SYN: ast.LocalType.BOOL,
  ast.FIELD_TCP_ACK: ast.LocalType.BOOL,
  ast.FIELD_TCP_FIN: ast.LocalType.BOOL,
  ast.FIELD_TCP_RST: ast.LocalType.BOOL,
  ast.FIELD_TCP_PSH: ast.LocalType.BOOL,
  ast.FIELD_TCP_URG: ast.LocalType.BOOL,
  ast.FIELD_TCP_ECE: ast.LocalType.BOOL,
  ast.FIELD_TCP_CWR: ast.LocalType.BOOL,
  ast.FIELD_ICMP_TYPE: ast.LocalType.U16,
  ast.FIELD_ICMP_CODE: ast.LocalType.U16,
  ast.FIELD_ICMP6_TYPE: ast.LocalType.U16,
  ast.FIELD_ICMP6_CODE: ast.LocalType.U16,
  ast.FIELD_VLAN_ID: ast.LocalType.U16,
  ast.FIELD_VLAN_PRIORITY: ast.LocalType.U16,
}


def _emit_tier2_body(
  names: MapNames,
  func: ast.FunctionDef,
  counter_slots: dict[str, int],
  program: ast.Program,
  ct_create: str = "",
  zone_name: str | None = None,
) -> tuple[str, str]:
  """Emit the body of a Tier 2 function. Returns (body, final_return)."""
  locals_: dict[str, ast.LocalType] = {}
  _collect_tier2_locals(func.body, locals_)
  decls = []
  for name, t in locals_.items():
    if t == ast.LocalType.IPV6:
      decls.append(f"  __u64 fwl_local_{name}_hi = 0;")
      decls.append(f"  __u64 fwl_local_{name}_lo = 0;")
    else:
      ctype = _LOCAL_C_TYPE[t]
      decls.append(f"  {ctype} fwl_local_{name} = 0;")
  decl_block = "\n".join(decls)
  if decl_block:
    decl_block += "\n"
  ctx = _Tier2EmitCtx(
    locals=locals_, counter_slots=counter_slots, ct_create=ct_create,
    zone_name=zone_name, names=names,
  )
  body_text = _emit_tier2_stmts(func.body, ctx, indent="  ")
  return decl_block + body_text, "XDP_PASS"


class _Tier2EmitCtx:
  """Mutable context threaded through Tier 2 emission."""
  def __init__(self, *, locals, counter_slots, names,
               ct_create="", zone_name=None):
    self.locals = locals
    self.counter_slots = counter_slots
    self.ct_create = ct_create
    # The @xdp block's zone, for folding pkt.zone (v0.4 § 6.4).
    self.zone_name = zone_name
    # The names this object's maps are emitted under (v0.4 § 6.2).
    self.names = names


def _emit_tier2_stmts(stmts, ctx: _Tier2EmitCtx, indent: str) -> str:
  out = []
  for stmt in stmts:
    out.append(_emit_tier2_stmt(stmt, ctx, indent))
  return "".join(out)


def _emit_tier2_stmt(stmt, ctx: _Tier2EmitCtx, indent: str) -> str:
  if isinstance(stmt, ast.ActionStmt):
    if stmt.action == ast.Action.ALLOW:
      return f"{indent}{ctx.ct_create}return XDP_PASS;\n"
    if stmt.action == ast.Action.DROP:
      return f"{indent}return XDP_DROP;\n"
    if stmt.action == ast.Action.REDIRECT:
      return f"{indent}return {_redirect_return(stmt.redirect_zone)};\n"
    if stmt.action == ast.Action.LOG:
      return (
        f"{indent}{{\n{indent}  "
        + _emit_log(ctx.names, 0, ctx.zone_name).replace(
          "\n", f"\n{indent}  "
        )
        + f"\n{indent}}}\n"
      )
    if stmt.action == ast.Action.COUNT:
      slot = ctx.counter_slots[stmt.counter_name]
      return (
        f"{indent}{{\n{indent}  "
        + _emit_count(ctx.names, slot).replace("\n", f"\n{indent}  ")
        + f"\n{indent}}}\n"
      )
    if stmt.action in ast.NAT_ACTIONS:
      return (
        f"{indent}"
        + _emit_nat_call(stmt.action, stmt.nat_addr, stmt.nat_port)
        + "\n"
      )
  if isinstance(stmt, ast.AssignStmt):
    return _emit_tier2_assign(stmt, ctx, indent)
  if isinstance(stmt, ast.CallStmt):
    # v0.4 § 6.5: BPF-to-BPF call. The helper returns FWL_CONTINUE when
    # it reached no terminal action; any other value is an XDP verdict
    # the caller propagates immediately.
    return (
      f"{indent}{{\n"
      f"{indent}  int _r = fwl_helper_{stmt.name}(ctx);\n"
      f"{indent}  if (_r != FWL_CONTINUE) return _r;\n"
      f"{indent}}}\n"
    )
  if isinstance(stmt, ast.IfStmt):
    return _emit_tier2_if(stmt, ctx, indent)
  raise AssertionError(f"unexpected stmt {type(stmt).__name__}")


def _emit_tier2_assign(
  stmt: ast.AssignStmt, ctx: _Tier2EmitCtx, indent: str
) -> str:
  """Emit a Tier 2 assignment: `<local> = <rhs>;`."""
  t = ctx.locals[stmt.name]
  if t == ast.LocalType.IPV6:
    hi_expr, lo_expr = _emit_ipv6_scalar(stmt.rhs, ctx)
    return (
      f"{indent}fwl_local_{stmt.name}_hi = {hi_expr};\n"
      f"{indent}fwl_local_{stmt.name}_lo = {lo_expr};\n"
    )
  expr = _emit_scalar(stmt.rhs, ctx)
  return f"{indent}fwl_local_{stmt.name} = {expr};\n"


def _emit_tier2_if(
  stmt: ast.IfStmt, ctx: _Tier2EmitCtx, indent: str
) -> str:
  cond = _emit_scalar(stmt.cond, ctx)
  inner = indent + "  "
  out = f"{indent}if ({cond}) {{\n"
  out += _emit_tier2_stmts(stmt.body, ctx, inner)
  out += f"{indent}}}"
  for elif_cond, elif_body in stmt.elif_branches:
    cond_text = _emit_scalar(elif_cond, ctx)
    out += f" else if ({cond_text}) {{\n"
    out += _emit_tier2_stmts(elif_body, ctx, inner)
    out += f"{indent}}}"
  if stmt.else_body is not None:
    out += " else {\n"
    out += _emit_tier2_stmts(stmt.else_body, ctx, inner)
    out += f"{indent}}}"
  return out + "\n"


def _emit_scalar(expr, ctx: _Tier2EmitCtx) -> str:
  """Emit a C scalar expression (non-IPv6)."""
  if isinstance(expr, ast.IntLiteral):
    return f"{expr.value}u"
  if isinstance(expr, ast.IPv4Literal):
    return f"0x{expr.value:08X}u"
  if isinstance(expr, ast.ProtoLiteral):
    return _PROTO_TO_IPPROTO[expr.proto]
  if isinstance(expr, ast.LocalRead):
    return f"fwl_local_{expr.name}"
  if isinstance(expr, ast.FieldRef):
    return _emit_field_read_scalar(expr.name)
  if isinstance(expr, ast.BoolField):
    return _emit_field_read_scalar(expr.field.name)
  if isinstance(expr, ast.Comparison):
    return _emit_tier2_comparison(expr, ctx)
  if isinstance(expr, ast.ConntrackStateCompare):
    return _emit_ct_state_compare(expr)
  if isinstance(expr, ast.ZoneCompare):
    return _emit_zone_compare(expr, ctx.zone_name)
  if isinstance(expr, ast.AndOp):
    parts = [f"({_emit_scalar(c, ctx)})" for c in expr.operands]
    return "(" + " && ".join(parts) + ")"
  if isinstance(expr, ast.OrOp):
    parts = [f"({_emit_scalar(c, ctx)})" for c in expr.operands]
    return "(" + " || ".join(parts) + ")"
  if isinstance(expr, ast.NotOp):
    return f"(!({_emit_scalar(expr.inner, ctx)}))"
  if isinstance(expr, ast.RateLimitCall):
    # v0.2 minimum-viable: emit a stub that always returns false.
    # Real rate_limit_call implementation is deferred to v0.3.
    return "(0)"
  raise AssertionError(f"unsupported scalar {type(expr).__name__}")


def _emit_field_read_scalar(field_name: str) -> str:
  """Emit a Tier 2 statement-position field read as a C lvalue."""
  if field_name == ast.FIELD_PROTO:
    return "proto"
  if field_name == ast.FIELD_SRC_IP:
    return "src_ip"
  if field_name == ast.FIELD_DST_IP:
    return "dst_ip"
  if field_name == ast.FIELD_SRC_PORT:
    return "src_port"
  if field_name == ast.FIELD_DST_PORT:
    return "dst_port"
  for field_const, c_var, _bit in _TCP_FLAG_VARS:
    if field_name == field_const:
      return c_var
  if field_name in _FIELD_TO_C and (
    field_name in ast.ICMP_FIELDS or field_name in ast.ICMP6_FIELDS
  ):
    return _FIELD_TO_C[field_name]
  if field_name == ast.FIELD_VLAN_ID:
    return "vlan_id"
  if field_name == ast.FIELD_VLAN_PRIORITY:
    return "vlan_priority"
  raise NotImplementedError(f"emitter: tier2 field read {field_name}")


def _emit_ipv6_scalar(expr, ctx: _Tier2EmitCtx) -> tuple[str, str]:
  """Emit an IPv6-typed scalar as (hi_expr, lo_expr) C strings."""
  if isinstance(expr, ast.Ipv6Literal):
    hi, lo = _split_ipv6_value(expr.value)
    return f"0x{hi:016X}ull", f"0x{lo:016X}ull"
  if isinstance(expr, ast.LocalRead):
    return f"fwl_local_{expr.name}_hi", f"fwl_local_{expr.name}_lo"
  if isinstance(expr, ast.FieldRef):
    if expr.name == ast.FIELD_SRC_IP6:
      return "src_ip6_hi", "src_ip6_lo"
    if expr.name == ast.FIELD_DST_IP6:
      return "dst_ip6_hi", "dst_ip6_lo"
  raise AssertionError(f"unsupported ipv6 scalar {type(expr).__name__}")


def _emit_tier2_comparison(cmp: ast.Comparison, ctx: _Tier2EmitCtx) -> str:
  """Emit a Tier 2 comparison's C expression.

  Reuses the Tier 1 emit helpers when both sides are field/literal
  shapes; for local-vs-local or local-vs-literal forms, emits the
  appropriate C operator directly.
  """
  field = cmp.field
  if isinstance(field, ast.FieldRef) and isinstance(cmp.operand, (
    ast.IntLiteral, ast.IPv4Literal, ast.Ipv6Literal, ast.ProtoLiteral,
    ast.CidrLiteral, ast.CidrListLiteral, ast.ListLiteral,
    ast.Ipv6CidrLiteral, ast.Ipv6CidrListLiteral, ast.RangeLiteral,
    ast.GeoIp,
  )):
    # Reuse Tier 1 path.
    return _emit_comparison(cmp)
  # Tier 2 forms: at least one side is a Local or a same-side field.
  if cmp.op == "in":
    return _emit_tier2_in(cmp, ctx)
  lhs_is_v6 = _is_ipv6_lvalue(field, ctx)
  if lhs_is_v6:
    lhs_hi, lhs_lo = _emit_ipv6_scalar(field, ctx)
    rhs_hi, rhs_lo = _emit_ipv6_scalar(cmp.operand, ctx)
    if cmp.op == "==":
      return f"({lhs_hi} == {rhs_hi} && {lhs_lo} == {rhs_lo})"
    if cmp.op == "!=":
      return f"({lhs_hi} != {rhs_hi} || {lhs_lo} != {rhs_lo})"
  lhs = _emit_scalar(field, ctx)
  rhs = _emit_scalar(cmp.operand, ctx)
  return f"({lhs} {cmp.op} {rhs})"


def _is_ipv6_lvalue(node, ctx: _Tier2EmitCtx) -> bool:
  if isinstance(node, ast.FieldRef):
    return node.name in ast.IP6_FIELDS
  if isinstance(node, ast.LocalRead):
    return ctx.locals.get(node.name) == ast.LocalType.IPV6
  return False


def _emit_tier2_in(cmp: ast.Comparison, ctx: _Tier2EmitCtx) -> str:
  """Emit a Tier 2 `<lvalue> in <set>` comparison.

  Reuses Tier 1's _emit_ip_in / _emit_ip6_in / _emit_port_in via the
  underlying field type.
  """
  field = cmp.field
  if isinstance(field, ast.FieldRef):
    return _emit_comparison(cmp)
  # local on LHS with `in`
  assert isinstance(field, ast.LocalRead)
  t = ctx.locals[field.name]
  if t == ast.LocalType.IPV4:
    return _emit_ip_in(f"fwl_local_{field.name}", cmp.operand)
  if t == ast.LocalType.IPV6:
    hi = f"fwl_local_{field.name}_hi"
    lo = f"fwl_local_{field.name}_lo"
    return _emit_ip6_in(hi, lo, cmp.operand)
  if t == ast.LocalType.U16:
    return _emit_port_in(f"fwl_local_{field.name}", cmp.operand)
  raise NotImplementedError(f"emitter: tier2 'in' on local of type {t}")


RATE_LIMIT_OVERFLOW_COUNTER = "__rate_limit_overflow"


def _allocate_counter_slots(program: ast.Program) -> dict[str, int]:
  """Assign a stable per-CPU array slot to each named counter.

  Slots are allocated in source order — Tier 1 rules first, then
  Tier 2 statements in walk order. Userspace tools read the
  name->slot mapping from the emitted fwl_counter_table comment
  block.

  When the program uses any rate_limit primitive, a reserved
  `__rate_limit_overflow` slot is appended at the end. The BPF
  emitter increments it whenever `bpf_map_update_elem` on a
  rate-limit hash map returns -E2BIG (the per-CPU bucket key
  space is exhausted). Surfaces through the same `/api/v1/counters`
  endpoint as user-defined counters; double-underscore prefix
  signals it's reserved (the analyzer's stylistic-warning pass
  excludes names starting with `__`).
  """
  slots: dict[str, int] = {}
  for rule in program.rules:
    if rule.action == ast.Action.COUNT and rule.counter_name:
      if rule.counter_name not in slots:
        slots[rule.counter_name] = len(slots)
    for n in _walk(rule.condition):
      if isinstance(n, ast.CountCompare):
        name = n.call.counter_name
        if name not in slots:
          slots[name] = len(slots)
  if program.function is not None:
    _collect_tier2_counter_slots(program.function.body, slots)
  if _program_uses_rate_limit(program):
    slots[RATE_LIMIT_OVERFLOW_COUNTER] = len(slots)
  return slots


def _program_uses_rate_limit(program: ast.Program) -> bool:
  """True iff any rule or Tier 2 statement uses a rate_limit primitive."""
  for rule in program.rules:
    if rule.modifier is not None:
      return True
  if program.function is not None:
    if _stmts_use_rate_limit(program.function.body):
      return True
  return False


def _stmts_use_rate_limit(stmts) -> bool:
  for s in stmts:
    if isinstance(s, ast.IfStmt):
      for n in _walk_with_compares(s.cond):
        pass
      if _expr_has_rate_limit(s.cond):
        return True
      if _stmts_use_rate_limit(s.body):
        return True
      for cond, body in s.elif_branches:
        if _expr_has_rate_limit(cond):
          return True
        if _stmts_use_rate_limit(body):
          return True
      if s.else_body is not None and _stmts_use_rate_limit(s.else_body):
        return True
  return False


def _expr_has_rate_limit(expr) -> bool:
  if isinstance(expr, ast.RateLimitCall):
    return True
  if isinstance(expr, ast.NotOp):
    return _expr_has_rate_limit(expr.inner)
  if isinstance(expr, (ast.AndOp, ast.OrOp)):
    return any(_expr_has_rate_limit(c) for c in expr.operands)
  return False


def _collect_tier2_counter_slots(stmts, slots: dict[str, int]) -> None:
  """Walk Tier 2 statements collecting `count <name>` action names."""
  for s in stmts:
    if isinstance(s, ast.ActionStmt) and s.action == ast.Action.COUNT:
      if s.counter_name and s.counter_name not in slots:
        slots[s.counter_name] = len(slots)
    elif isinstance(s, ast.IfStmt):
      _collect_tier2_counter_slots(s.body, slots)
      for _, body in s.elif_branches:
        _collect_tier2_counter_slots(body, slots)
      if s.else_body is not None:
        _collect_tier2_counter_slots(s.else_body, slots)


def _emit_counter_table(slots: dict[str, int]) -> str:
  """Emit a comment block mapping counter names to their slot indices.

  Userspace tools parse this to look up counters by their declared
  identifier without needing the .fw source.
  """
  lines = ["// fwl_counter_table:"]
  for name, slot in slots.items():
    lines.append(f"//   {slot}\t{name}")
  return "\n".join(lines) + "\n"
