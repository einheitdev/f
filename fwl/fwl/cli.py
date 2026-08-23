"""`fwl` command-line interface.

Subcommands:
  parse <file>             Parse only; print AST.
  check <file>             Parse + semantic check.
  compile <file>           Full compile to .bpf.c (and .bpf.o via clang).
  interpret <file> <pkt>   AST interpreter against a test packet.
  test <dir>               Run a corpus directory through the
                           verification loop.
  version                  Print version.
"""
from __future__ import annotations
import sys
from pathlib import Path

import click

from . import (
  __version__, analyzer, ast, emitter, interpreter, log_abi, parser,
  pkt, rulemeta, runner
)
from .errors import FwlException


@click.group()
def main() -> None:
  """FWL — Firewall Language compiler for eBPF/XDP."""


@main.command()
@click.argument("source", type=click.Path(exists=True, path_type=Path))
def parse(source: Path) -> None:
  """Parse SOURCE and print the AST."""
  text = source.read_text(encoding="utf-8")
  try:
    program = parser.parse(text)
  except FwlException as exc:
    click.echo(exc.error.format(), err=True)
    sys.exit(1)
  click.echo(_format_program(program))


def _format_program(p: ast.Program) -> str:
  """One-rule-per-line summary of an AST. Easier to scan than dataclass repr."""
  lines: list[str] = []
  for z in p.zones:
    lines.append(f"zone {z.name} = [{', '.join(z.interfaces)}]")
  for zp in p.programs:
    lines.append(f"@xdp({zp.hook.interface})")
    for i, rule in enumerate(zp.rules):
      parts = [rule.action.value]
      if rule.action == ast.Action.COUNT and rule.counter_name:
        parts.append(rule.counter_name)
      if rule.action == ast.Action.REDIRECT and rule.redirect_zone:
        parts.append(f"to {rule.redirect_zone}")
      if rule.condition is not None:
        parts.append(f"if {_format_condition(rule.condition)}")
      if rule.modifier is not None:
        scope = ""
        if rule.modifier.scope is not ast.RlScope.ZONE:
          scope = f", scope={rule.modifier.scope.value}"
        parts.append(
          f"limited by rate_limit({rule.modifier.threshold}, "
          f"per={rule.modifier.per_field}{scope})"
        )
      lines.append(f"  [{i}] {' '.join(parts)}")
    if zp.default is not None:
      lines.append(f"  default {zp.default.action.value}")
    if zp.function is not None:
      lines.append(f"  def {zp.function.name}(pkt): "
                   f"({len(zp.function.body)} stmts)")
  return "\n".join(lines)


def _format_condition(node: ast.Condition) -> str:
  """Pretty-print a condition AST as the source-form expression."""
  if isinstance(node, ast.Comparison):
    return f"{node.field.name} {node.op} {_format_operand(node.operand)}"
  if isinstance(node, ast.BoolField):
    return node.field.name
  if isinstance(node, ast.NotOp):
    return f"not ({_format_condition(node.inner)})"
  if isinstance(node, ast.AndOp):
    return "(" + " and ".join(
      _format_condition(c) for c in node.operands
    ) + ")"
  if isinstance(node, ast.OrOp):
    return "(" + " or ".join(
      _format_condition(c) for c in node.operands
    ) + ")"
  return repr(node)


def _format_operand(op: ast.Operand) -> str:
  """Pretty-print an operand AST as the source-form literal."""
  if isinstance(op, ast.ProtoLiteral):
    return op.proto.value
  if isinstance(op, ast.IntLiteral):
    return str(op.value)
  if isinstance(op, ast.IPv4Literal):
    return _ipv4_str(op.value)
  if isinstance(op, ast.CidrLiteral):
    return f"{_ipv4_str(op.prefix)}/{op.bits}"
  if isinstance(op, ast.RangeLiteral):
    return f"{op.lo}..{op.hi}"
  if isinstance(op, ast.ListLiteral):
    return "[" + ", ".join(_format_operand(i) for i in op.items) + "]"
  if isinstance(op, ast.CidrListLiteral):
    return "[" + ", ".join(_format_operand(i) for i in op.items) + "]"
  if isinstance(op, ast.GeoIp):
    return f"geoip({', '.join(op.codes)})"
  if isinstance(op, ast.TableRef):
    return op.name
  return repr(op)


def _ipv4_str(value: int) -> str:
  """32-bit int back to dotted-quad."""
  return ".".join(str((value >> shift) & 0xFF) for shift in (24, 16, 8, 0))


@main.command()
@click.argument("source", type=click.Path(exists=True, path_type=Path))
def check(source: Path) -> None:
  """Parse + semantic check of SOURCE without code generation."""
  text = source.read_text(encoding="utf-8")
  try:
    program = analyzer.analyze(parser.parse(text))
  except FwlException as exc:
    click.echo(exc.error.format(), err=True)
    sys.exit(1)
  _echo_warnings(program)
  click.echo("ok")


def _echo_warnings(program: ast.Program) -> None:
  """Print the analyzer's non-fatal diagnostics to stderr.

  stderr, not stdout, so a warning never contaminates a compile whose
  output is being piped — `fwl compile` writes C to stdout.
  """
  for warning in program.warnings:
    click.echo(warning.format(), err=True)


@main.command()
@click.argument("source", type=click.Path(exists=True, path_type=Path))
@click.option(
  "-o", "--output", type=click.Path(path_type=Path), default=None,
  help="Write generated C to this path instead of stdout.",
)
@click.option(
  "--bundle", "bundle_dir", type=click.Path(path_type=Path), default=None,
  help=(
    "Emit a multi-zone bundle (one <zone>.bpf.c + .bpf.o per @xdp "
    "block, a shared header, and manifest.json) into this directory."
  ),
)
@click.option(
  "--geoip", "geoip_file", type=click.Path(exists=True, path_type=Path),
  default=None,
  help=(
    "Country -> CIDR-prefix data (JSON object, e.g. "
    '{"DE": ["1.2.0.0/16"]}). Required when the program uses '
    "geoip(); the bundle gains a geoip.json the daemon loads into "
    "the LPM tries at attach time."
  ),
)
def compile(source: Path, output: Path | None, bundle_dir: Path | None,
            geoip_file: Path | None) -> None:
  """Compile SOURCE to BPF C (single object) or a multi-zone bundle."""
  text = source.read_text(encoding="utf-8")
  try:
    program = analyzer.analyze(parser.parse(text))
  except FwlException as exc:
    click.echo(exc.error.format(), err=True)
    sys.exit(1)
  _echo_warnings(program)

  geoip_data = None
  if geoip_file is not None:
    import json
    geoip_data = json.loads(geoip_file.read_text(encoding="utf-8"))

  if bundle_dir is not None:
    # Codegen errors were escaping as tracebacks: only `analyze` was
    # wrapped, so anything the emitter refuses -- an unclassified map,
    # a pipeline deeper than the kernel will follow -- reached the
    # operator as a Python stack instead of a sentence.
    try:
      _emit_bundle_dir(program, bundle_dir, geoip_data,
                       source=source, source_text=text)
    except FwlException as exc:
      click.echo(exc.error.format(), err=True)
      sys.exit(1)
    except TableResolutionError as exc:
      # A table whose contents cannot be resolved is a compile error
      # for the same reason an undeclared one is: the alternative is a
      # map that loads empty, and a rule that never matches is a hole
      # nothing on the running box reports.
      click.echo(f"error: {exc}", err=True)
      sys.exit(1)
    return

  # A multi-zone unit has more than one program; a single C file cannot
  # represent it. Point the user at --bundle.
  if len(program.programs) > 1:
    click.echo(
      "error: this file declares multiple @xdp zones; use --bundle "
      "<dir> to emit one object per zone",
      err=True,
    )
    sys.exit(1)

  try:
    c_source = emitter.emit(program)
  except FwlException as exc:
    click.echo(exc.error.format(), err=True)
    sys.exit(1)
  if output is None:
    click.echo(c_source, nl=False)
  else:
    output.write_text(c_source, encoding="utf-8")


def _collect_bundle_geoip(
  program: ast.Program,
) -> list[tuple[str, ast.GeoIp]]:
  """(zone, call) for every geoip() site across every @xdp block."""
  calls: list[tuple[str, ast.GeoIp]] = []
  for zp in program.programs:
    for rule in zp.rules:
      for n in emitter._walk(rule.condition):
        if (isinstance(n, ast.Comparison)
            and isinstance(n.operand, ast.GeoIp)):
          calls.append((zp.zone_name, n.operand))
    if zp.function is not None:
      calls.extend(
        (zp.zone_name, c)
        for c in emitter._collect_geoip_in_stmts(zp.function.body)
      )
  return calls


def _build_geoip_bundle_file(
  program: ast.Program, geoip_data: dict | None
) -> dict | None:
  """Resolve geoip() call sites against the data file.

  Returns the geoip.json payload ({"tries": [...]}), or None when the
  program has no geoip() calls. Errors out (exit 1) when calls exist
  but no data was provided, or when a referenced country has no
  prefixes of the call's family (a silently empty trie would make the
  rule a no-op). Trie names are zone-qualified to match the emitter's
  per-zone private-map naming.
  """
  calls = _collect_bundle_geoip(program)
  if not calls:
    return None
  if geoip_data is None:
    click.echo(
      "error: this program uses geoip() but no --geoip data file "
      "was provided; the tries would load empty and never match",
      err=True,
    )
    sys.exit(1)
  import ipaddress
  tries: dict[str, dict] = {}
  for zone, call in calls:
    # The name comes from the emitter's own map registry rather than
    # being spelled out again here: a trie is zone-private state, and a
    # second copy of the naming rule is a second thing to forget.
    name = emitter.MapNames(zone).geoip(call.call_index)
    prefixes: list[str] = []
    for code in call.codes:
      family_hits = 0
      for cidr in geoip_data.get(code, ()):
        net = ipaddress.ip_network(cidr, strict=False)
        is_v4 = isinstance(net, ipaddress.IPv4Network)
        if (call.family == "ipv4") == is_v4:
          prefixes.append(str(net))
          family_hits += 1
      if family_hits == 0:
        click.echo(
          f"error: geoip data has no {call.family} prefixes for "
          f"country '{code}'",
          err=True,
        )
        sys.exit(1)
    tries[name] = {
      "map": name, "family": call.family,
      "prefixes": sorted(prefixes),
    }
  return {"tries": [tries[k] for k in sorted(tries)]}


class TableResolutionError(Exception):
  """A `table` declaration whose contents could not be resolved.

  Carries the sentence an operator reads. Raised rather than exited on
  so that `_emit_bundle_dir`'s caller reports it through the same path
  as every other compile error, and so the resolution is testable
  without catching SystemExit.
  """


def _referenced_tables(program: ast.Program) -> list[ast.TableDecl]:
  """The declared tables some rule in this unit actually matches against.

  A table nobody references emits no map (the emitter declares only
  what a lookup needs), so resolving its source would read a file for
  a trie that does not exist. The analyzer already warns about the
  declaration; this is the other half of the same decision.
  """
  by_name = {t.name: t for t in program.tables}
  out: list[ast.TableDecl] = []
  seen: set[str] = set()
  for ref in analyzer.table_refs(program):
    if ref.resolved in seen:
      continue
    seen.add(ref.resolved)
    out.append(by_name[ref.resolved])
  return out


def _read_table_source(
  decl: ast.TableDecl, base_dir: Path
) -> list[str]:
  """Read a table's source file into a list of prefix strings.

  One entry per line; `#` starts a comment; blank lines are ignored.
  That is the shape a threat feed or a list under configuration
  management already has, so a file can be used without a conversion
  step that would be one more thing to get wrong.

  A relative `source` resolves against the directory holding the
  policy file, so a policy and its feed travel together and a compile
  does not depend on the working directory it was started from.
  """
  path = Path(decl.source)
  if not path.is_absolute():
    path = base_dir / path
  if not path.is_file():
    raise TableResolutionError(
      f"{decl.span.line}:{decl.span.column}: table '{decl.name}' "
      f"reads its contents from '{decl.source}', which does not "
      f"exist (looked at {path}). A table that cannot be filled is a "
      f"rule that never matches, so this is an error rather than an "
      f"empty map."
    )
  entries: list[str] = []
  for raw in path.read_text(encoding="utf-8").splitlines():
    line = raw.split("#", 1)[0].strip()
    if line:
      entries.append(line)
  return entries


def _resolve_table_entries(
  decl: ast.TableDecl, base_dir: Path
) -> list[str]:
  """A table's prefixes, validated against its `kind` and its `max`.

  Every failure here is a compile error rather than a smaller table,
  because every one of them is silent at runtime: a blocklist short of
  the entries it was meant to hold forwards the traffic it was meant
  to drop, and nothing about the running box says so.
  """
  import ipaddress
  want_v4 = decl.kind == "cidr4"
  raw = _read_table_source(decl, base_dir)
  if not raw:
    raise TableResolutionError(
      f"{decl.span.line}:{decl.span.column}: table '{decl.name}' "
      f"resolved to no entries from '{decl.source}'. An empty table "
      f"never matches, which in a blocklist is an open firewall."
    )
  prefixes: list[str] = []
  for lineno, item in enumerate(raw, 1):
    try:
      net = ipaddress.ip_network(item, strict=False)
    except ValueError as exc:
      raise TableResolutionError(
        f"{decl.span.line}:{decl.span.column}: table "
        f"'{decl.name}': '{decl.source}' line {lineno}: {exc}"
      ) from None
    is_v4 = isinstance(net, ipaddress.IPv4Network)
    if is_v4 != want_v4:
      raise TableResolutionError(
        f"{decl.span.line}:{decl.span.column}: table "
        f"'{decl.name}' is kind = {decl.kind}, but "
        f"'{decl.source}' line {lineno} holds '{item}'"
      )
    prefixes.append(str(net))
  # De-duplicate before the capacity check: the same prefix twice is
  # one entry in an LPM trie, so counting it twice would refuse a file
  # the map would have held.
  unique = sorted(set(prefixes))
  if len(unique) > decl.max_entries:
    raise TableResolutionError(
      f"{decl.span.line}:{decl.span.column}: table '{decl.name}' "
      f"declares max = {decl.max_entries} but '{decl.source}' holds "
      f"{len(unique)} distinct prefixes. Refused rather than "
      f"truncated: a table quietly missing "
      f"{len(unique) - decl.max_entries} of its entries fails open if "
      f"it is a blocklist. Raise max, or shorten the file."
    )
  return unique


def _build_table_bundle_tries(
  program: ast.Program, base_dir: Path
) -> list[dict]:
  """Resolve every referenced table into a loader trie entry.

  The payload rows are the same shape the geoip tries use — `map`,
  `family`, `prefixes` — because the daemon's loader already fills any
  named LPM trie from that shape and neither knows nor cares where the
  prefixes came from. Emitting into it is what makes phase 1 need no
  daemon change at all.
  """
  ids = analyzer.table_map_id(program)
  tries: list[dict] = []
  for decl in _referenced_tables(program):
    tries.append({
      "map": emitter.MapNames().table(ids[decl.name]),
      "family": ast.TABLE_KIND_FAMILY[decl.kind],
      "prefixes": _resolve_table_entries(decl, base_dir),
    })
  return tries


def _manifest_tables(program: ast.Program, tries: list[dict]) -> dict:
  """The manifest's `tables` block: full name -> what the kernel calls it.

  TABLES.md: the writer names a table whatever reads well and never
  types the id; the kernel is the only place with a limit. The mapping
  ships with the bundle so `fd` reads it instead of re-deriving it
  from the name -- a second implementation of the rule in another
  language is how the same defect got in three times.

  Aliases are listed against the table they resolve to, so an operator
  reading a policy with a pasted block can answer "what is `badhosts`
  actually" without reading the whole file.
  """
  ids = analyzer.table_map_id(program)
  by_map = {t["map"]: t for t in tries}
  tables: dict[str, dict] = {}
  for decl in program.tables:
    map_name = emitter.MapNames().table(ids[decl.name])
    row = by_map.get(map_name)
    tables[decl.name] = {
      "id": ids[decl.name],
      "map": map_name,
      "kind": decl.kind,
      "max": decl.max_entries,
      "source": decl.source,
      # None, not 0, for a declared table nobody matches against: no
      # map is emitted for it, so "how many entries does it hold" has
      # no answer rather than the answer zero.
      "entries": len(row["prefixes"]) if row is not None else None,
    }
  aliases = {a.name: a.target for a in program.table_aliases}
  return {"tables": tables, "table_aliases": aliases}


def _manifest_zones(program: ast.Program) -> list[dict]:
  """Every zone the daemon must attach to, with its interfaces.

  The declared zones, plus one implicit zone per `@xdp` block whose
  argument is not a declared zone. That second case is the simple form
  the language has had since v0.1 — `@xdp(eth0)`, no `zone` line,
  where FWL_V04_SPEC.md § 6.2 says the argument names "one implicit
  zone whose name is the @xdp argument" and the v0.1 spec spells the
  hook `@xdp(<interface>)`. It is the form every example teaches and
  the first one anybody writes.

  Writing it out here rather than leaving the array empty is the same
  decision `emitter.emitting_zone_names` already made for the log ABI,
  and for the same reason: a consumer given only `program.zones` cannot
  resolve a unit that emits records under a name that is not in it. The
  daemon was that consumer, and the interfaces it derived from an empty
  array were an empty set — so it attached the program to nothing and
  reported a successful load.
  """
  zones = [
    {"name": z.name, "interfaces": list(z.interfaces)}
    for z in program.zones
  ]
  declared = {z["name"] for z in zones}
  for zp in program.programs:
    if zp.zone_name not in declared:
      zones.append(
        {"name": zp.zone_name, "interfaces": [zp.zone_name]}
      )
      declared.add(zp.zone_name)
  return zones


def _emit_bundle_dir(program: ast.Program, bundle_dir: Path,
                     geoip_data: dict | None = None,
                     source: Path | None = None,
                     source_text: str | None = None) -> None:
  """Write a multi-zone bundle to `bundle_dir`.

  Emits each zone's `<zone>.bpf.c` and the shared header, compiles each
  C file to `<zone>.bpf.o` when clang is available, and writes a
  `manifest.json` describing the zones, per-zone objects, redirect
  topology, the per-zone RULES, and the bpffs-pinned shared maps the
  daemon must wire up. With geoip() in the program, also writes
  `geoip.json` (resolved prefix lists per trie) for the daemon to load.

  `source`/`source_text` are the policy file this program was compiled
  from. They are optional because tests and other callers build a
  bundle straight from an AST; when they are absent the manifest says
  the source is unknown rather than naming a file it did not read.
  """
  import json
  import subprocess

  from . import bpf_runner

  geoip_payload = _build_geoip_bundle_file(program, geoip_data)

  # A relative `source =` resolves against the policy file's own
  # directory, so a policy and the feed beside it travel together. With
  # no policy file (a caller building a bundle straight from an AST)
  # there is nothing to be relative to, so relative paths resolve
  # against the working directory.
  table_base = source.parent if source is not None else Path.cwd()
  table_tries = _build_table_bundle_tries(program, table_base)
  if table_tries:
    # Into geoip.json's existing `tries` array rather than a file of
    # its own: `ParseGeoipFile` returns {map_name: prefixes} and
    # `PopulateGeoipTrie` fills any named LPM trie from it, knowing
    # nothing about where the prefixes came from. Phase 1 therefore
    # needs no daemon change, and the two mechanisms cannot drift
    # apart in the loader.
    if geoip_payload is None:
      geoip_payload = {"tries": []}
    geoip_payload["tries"] = sorted(
      geoip_payload["tries"] + table_tries, key=lambda t: t["map"]
    )

  bundle_dir.mkdir(parents=True, exist_ok=True)
  files = emitter.emit_bundle(program)
  for name, c_source in files.items():
    (bundle_dir / name).write_text(c_source, encoding="utf-8")

  programs_meta = []
  for zp in program.programs:
    c_name = f"{zp.zone_name}.bpf.c"
    o_name = f"{zp.zone_name}.bpf.o"
    try:
      result = bpf_runner.compile_c(
        files[c_name], work_dir=bundle_dir
      )
      # compile_c writes fwl_prog.bpf.o; move it to the zone name.
      result.obj_path.replace(bundle_dir / o_name)
      compiled = True
    except (bpf_runner.BpfUnavailable, subprocess.CalledProcessError):
      compiled = False
    programs_meta.append({
      "zone": zp.zone_name,
      "source": c_name,
      "object": o_name if compiled else None,
      # Helpers included: the daemon fills each `fwl_devmap_<zone>`
      # from this list, and a redirect performed inside a helper emits
      # the devmap all the same.
      "redirects_to": emitter._collect_redirect_zones(
        zp, program.helpers),
      # The daemon seeds fwl_nat_cfg (the masquerade source address)
      # only for zones that actually masquerade; a zone that merely
      # carries the shared de-NAT pass must not be treated as one.
      "masquerades": emitter._program_masquerades(zp, program.helpers),
      # This zone's policy as an operator reads it: the rules in
      # policy order, each with its action and its match. The loader
      # captures it in the same call that opens the object, so a
      # consumer never re-derives it from the bundle directory — the
      # same rule the counter table follows, for the same reason.
      "rules": rulemeta.zone_rules(zp),
    })

  # The TC clsact egress conntrack tracker (v0.4 § 6.9). One object for
  # the whole bundle — what it does is a property of the box, not of a
  # policy — compiled and reported exactly like a zone object, because
  # the failure it must not have is the one zone objects already had: a
  # `null` here and a load that says "ok".
  egress_meta = None
  e_src = emitter.EGRESS_TRACKER_SOURCE
  if e_src in files:
    e_obj = e_src.replace(".bpf.c", ".bpf.o")
    try:
      result = bpf_runner.compile_c(files[e_src], work_dir=bundle_dir)
      result.obj_path.replace(bundle_dir / e_obj)
      e_compiled = True
    except (bpf_runner.BpfUnavailable, subprocess.CalledProcessError):
      e_compiled = False
    egress_meta = {
      "source": e_src,
      "object": e_obj if e_compiled else None,
      "program": emitter.EGRESS_TRACKER_PROG,
    }

  manifest = {
    "version": "0.4",
    # Declared zones AND the implicit zone of a simple `@xdp(eth0)`
    # unit. The daemon derives every interface it attaches to from
    # this array; a program entry naming a zone the array does not
    # carry got no interfaces and was attached to none of them.
    "zones": _manifest_zones(program),
    "programs": programs_meta,
    # zone name -> the id its log events carry. The lookup table for
    # `fwl_log_events`, which is one ring for the whole bundle: a
    # record is (zone_id, rule_index), and a numeric id a consumer
    # cannot resolve to a name is no better than no id at all. It
    # ships with the bundle so the resolution needs nothing but the
    # artifact the events came from.
    "zone_ids": log_abi.zone_ids(emitter.emitting_zone_names(program)),
    "shared_pinned_maps": emitter.shared_pinned_map_names(files),
    # The pins fd may carry across a policy change; everything else
    # under its pin root is left over from a previous compilation and
    # is removed before the load. Taken from _MAP_KINDS so the decision
    # lives in one place and reaches the daemon without being restated.
    "persistent_maps": list(emitter.persistent_map_names()),
    # Present only when this policy reads conntrack at all. `fd`
    # attaches it to every interface the bundle attaches XDP to, and a
    # bundle that declares one and cannot attach it is a failed load —
    # see LoadZoneBundle. A bundle compiled before this field existed
    # has no tracker, and fd says so rather than assuming one.
    "egress_tracker": egress_meta,
    # The identity of the policy TEXT this bundle was compiled from,
    # so a box can be asked whether the `.fw` on disk is still the one
    # in the packet path. `null` when the caller built the bundle from
    # an AST and there is no file to name — an unknown source is a
    # state, not a reason to invent a digest.
    # TABLES.md: full names in the language, a short mapped id in the
    # kernel, and the mapping carried here so `fd` never re-derives it.
    **_manifest_tables(program, table_tries),
    "policy_source": (
      rulemeta.source_identity(str(source), source_text)
      if source is not None and source_text is not None else None),
  }
  (bundle_dir / "manifest.json").write_text(
    json.dumps(manifest, indent=2), encoding="utf-8"
  )
  if geoip_payload is not None:
    (bundle_dir / "geoip.json").write_text(
      json.dumps(geoip_payload, indent=2), encoding="utf-8"
    )
  # Drop the scratch source compile_c leaves behind in the bundle dir.
  stray = bundle_dir / "fwl_prog.bpf.c"
  if stray.exists():
    stray.unlink()
  # Count what was compiled, not what was intended. When clang is
  # unavailable every entry gets `"object": null` and the bundle
  # cannot enforce anything, yet the sentence "wrote bundle: 2 zone
  # program(s)" read exactly the same as a successful compile —
  # `fd` refusing the bundle on load was the first anyone heard of it.
  built = sum(1 for p in programs_meta if p["object"] is not None)
  total = len(programs_meta)
  click.echo(
    f"wrote bundle: {built}/{total} zone program(s) compiled to "
    f"{bundle_dir}"
  )
  if built < total:
    missing = [p["zone"] for p in programs_meta if p["object"] is None]
    click.echo(
      f"warning: no compiled object for zone(s) "
      f"{', '.join(missing)} — clang/bpftool unavailable. This "
      f"bundle cannot be loaded; `fd` will refuse it.",
      err=True,
    )


@main.command()
@click.argument("source", type=click.Path(exists=True, path_type=Path))
@click.argument("pkt_file", type=click.Path(exists=True, path_type=Path))
def interpret(source: Path, pkt_file: Path) -> None:
  """Run SOURCE against the packet in PKT_FILE via the AST interpreter."""
  text = source.read_text(encoding="utf-8")
  try:
    program = analyzer.analyze(parser.parse(text))
  except FwlException as exc:
    click.echo(exc.error.format(), err=True)
    sys.exit(1)
  case = pkt.load(pkt_file)
  action = interpreter.evaluate(
    program, case.packet.fields, case.state
  )
  fired = _which_rule_fired(program, case.packet.fields, case.state)
  click.echo(f"{action.value} ({fired})")


def _which_rule_fired(
  program, packet, state
) -> str:
  """Return a human-readable label for which rule produced the action.

  Mirrors the interpreter's match logic — kept separate so the
  interpreter doesn't carry diagnostic responsibilities into its
  oracle role.
  """
  state = interpreter.resolve_bucket_state(program, state)
  for idx, rule in enumerate(program.rules):
    if (rule.condition is not None
        and not interpreter._eval(rule.condition, packet)):
      continue
    if rule.modifier is not None:
      if not interpreter._rate_limit_allows(
        rule.modifier, idx, packet, state
      ):
        continue
    if rule.action in interpreter._TERMINAL_ACTION_TO_XDP:
      return f"rule {idx}: {rule.action.value}"
  if program.default is not None:
    return f"default: {program.default.action.value}"
  return "no rule matched (implicit allow)"


@main.command()
@click.argument(
  "directory", type=click.Path(exists=True, file_okay=False, path_type=Path)
)
def test(directory: Path) -> None:
  """Run all .pkt cases under DIRECTORY through all three oracles."""
  results = runner.run_directory(directory)
  click.echo(runner.format_results(results))
  if not all(r.passed for r in results):
    sys.exit(1)


@main.command()
def version() -> None:
  """Print the FWL compiler version."""
  click.echo(__version__)
