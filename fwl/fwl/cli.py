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
import subprocess
import sys
from pathlib import Path

import click

from . import (
  __version__, analyzer, ast, emitter, interpreter, log_abi, parser,
  pkt, rulemeta, runner, splitter
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


_BRANCH_RANGE_ERROR = "Branch target out of insn range"


def _compile_one(c_source: str, bundle_dir: Path, obj_name: str,
                 isa: str) -> bool:
  """Compile one generated C file into the bundle. True when it worked.

  Raises `subprocess.CalledProcessError` only for the branch-range
  failure, which the caller answers by rebuilding the whole bundle with
  a wider jump. Every other compile failure returns False, because a
  bundle with a missing object is already reported -- loudly, and by
  the caller -- as one `fd` will refuse.
  """
  from . import bpf_runner
  try:
    result = bpf_runner.compile_c(
      c_source, work_dir=bundle_dir, cpu=isa or None)
  except bpf_runner.BpfUnavailable:
    return False
  except subprocess.CalledProcessError as exc:
    stderr = (exc.stderr or b"")
    if isinstance(stderr, bytes):
      stderr = stderr.decode("utf-8", "replace")
    if _BRANCH_RANGE_ERROR in stderr:
      raise
    return False
  # compile_c writes fwl_prog.bpf.o; move it to the caller's name.
  result.obj_path.replace(bundle_dir / obj_name)
  return True


def _compile_zone_objects(program: ast.Program, files: dict,
                          bundle_dir: Path):
  """Compile every zone object, widening the jump once if clang asks.

  Returns `({zone: compiled}, isa_actually_used)`. The retry rebuilds
  ALL of them rather than only the one that failed: the manifest states
  one kernel floor for the bundle, so the objects have to agree about
  which instruction set they were built for.
  """
  for attempt_isa in ("", "v4"):
    compiled = {}
    try:
      for zp in program.programs:
        compiled[zp.zone_name] = _compile_one(
          files[f"{zp.zone_name}.bpf.c"], bundle_dir,
          f"{zp.zone_name}.bpf.o", attempt_isa)
    except subprocess.CalledProcessError:
      # The branch-range failure, and only that one — `_compile_one`
      # swallows every other compile error. Fall through to the wider
      # instruction set.
      continue
    return compiled, attempt_isa
  return {zp.zone_name: False for zp in program.programs}, ""


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

  from . import bpf_runner

  geoip_payload = _build_geoip_bundle_file(program, geoip_data)

  bundle_dir.mkdir(parents=True, exist_ok=True)
  files = emitter.emit_bundle(program)
  for name, c_source in files.items():
    (bundle_dir / name).write_text(c_source, encoding="utf-8")

  # One ISA for the whole bundle, decided by what clang actually does
  # rather than by an estimate of what it will do.
  #
  # The default instruction set loads on every kernel this project
  # supports and emits a signed 16-bit branch offset, which stops at
  # about 32,767 instructions. `-mcpu=v4` adds `gotol` and removes the
  # limit, at the price of needing kernel 6.6. So the default is tried
  # first, always, and the wider jump is used only when clang says in
  # so many words that it needs one.
  #
  # An estimate was tried here first and it was wrong in the expensive
  # direction: a Tier 2 body of 1,200 branches ESTIMATES at 29,000
  # instructions and clang emits 161, because it folds repeated
  # comparisons into something far smaller than the source suggests.
  # Choosing v4 from that estimate would have stamped a kernel-6.6
  # floor onto bundles that load anywhere, i.e. refused them on boxes
  # that could run them perfectly.
  #
  # Bundle-wide because the manifest carries ONE kernel floor: a bundle
  # is loaded or refused whole, and a floor that applied to some of its
  # objects and not others would be a refusal nobody could act on.
  compiled_objects, isa = _compile_zone_objects(
    program, files, bundle_dir)
  min_kernel = bpf_runner.BPF_ISA_MIN_KERNEL.get(isa) if isa else None

  programs_meta = []
  for zp in program.programs:
    c_name = f"{zp.zone_name}.bpf.c"
    o_name = f"{zp.zone_name}.bpf.o"
    compiled = compiled_objects.get(zp.zone_name, False)
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
    # Built with the bundle's ISA, whatever the zone objects settled
    # on: one bundle, one kernel floor.
    e_compiled = _compile_one(files[e_src], bundle_dir, e_obj, isa)
    egress_meta = {
      "source": e_src,
      "object": e_obj if e_compiled else None,
      "program": emitter.EGRESS_TRACKER_PROG,
    }

  manifest = {
    "version": "0.4",
    # The BPF ISA these objects were assembled for, and the kernel that
    # implies. `null` is clang's default and loads anywhere; "v4" needs
    # 6.6 for `gotol`, and on an older kernel the verifier rejects the
    # opcode with a message that names an instruction rather than a
    # cause. fd compares this against `uname -r` before the load, so an
    # operator gets a sentence instead.
    "bpf_isa": isa or None,
    "min_kernel": min_kernel,
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
  if min_kernel:
    click.echo(
      f"note: built for BPF ISA {isa}, which needs kernel "
      f"{min_kernel} or newer. A zone in this policy is too large to "
      f"assemble with clang's default 16-bit branch offsets. `fd` "
      f"refuses the bundle on an older kernel rather than letting the "
      f"verifier reject an opcode it has never seen."
    )
  # What the rule count will cost, before it is paid. The compiler
  # knows the number and the operator has no other way to find out
  # short of measuring the box.
  for zp in program.programs:
    advice = splitter.advisory(zp)
    if advice:
      click.echo(f"note: zone {zp.zone_name!r}: {advice}", err=True)
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
