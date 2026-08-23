"""TABLES.md named tables: the compiler half, end to end.

The argument for tables is a measurement, so the tests that matter are
the ones that would notice the measurement stopping being true: that
the emitted program does not grow with the table, and that a table
which cannot be filled refuses to compile rather than loading empty.
"""
import dataclasses
import json
import subprocess
from pathlib import Path

import pytest
from click.testing import CliRunner

from fwl import analyzer, ast, bpf_runner, cli, emitter, parser, pkt
from fwl import runner as fwl_runner
from fwl import splitter
from fwl.errors import FwlException


_CORPUS = Path(__file__).resolve().parent.parent / "corpus" / "27_tables"


# Seeded `drop` cases whose verdict is deliberately NOT produced by a
# table hit, with the reason. They are asserted in the opposite
# direction rather than skipped.
_VERDICT_NOT_FROM_A_TABLE_HIT = {
  "inter_table_under_not": (
    "the rule fires BECAUSE the address is absent, so an empty table "
    "gives the same answer"
  ),
  "inter_table_in_or_branch": (
    "the other arm of the `or` produces the drop"
  ),
  "inter_table_beside_geoip": (
    "the geoip() rule produces the drop"
  ),
}


def _seeded_drop_cases() -> list[Path]:
  """Corpus cases that seed a table and expect a drop."""
  out = []
  for path in sorted(_CORPUS.glob("*.pkt")):
    case = pkt.load(path)
    if case.table_data and case.expected.get("bpf_action") == "drop":
      out.append(path)
  return out


def _with_empty_tables(case: pkt.PktCase) -> pkt.PktCase:
  """The same case with every table's contents removed."""
  return dataclasses.replace(case, table_data={})


_TABLE_POSITIVE_CASES = [
  p for p in _seeded_drop_cases()
  if p.stem not in _VERDICT_NOT_FROM_A_TABLE_HIT
]
_TABLE_NEGATIVE_CASES = [
  p for p in _seeded_drop_cases()
  if p.stem in _VERDICT_NOT_FROM_A_TABLE_HIT
]


def _analyze(src: str) -> ast.Program:
  return analyzer.analyze(parser.parse(src))


def _policy(max_entries: int, source: str = "feed.txt") -> str:
  return (
    f"table badhosts {{\n"
    f"  kind = cidr4\n"
    f"  max = {max_entries}\n"
    f'  source = "{source}"\n'
    f"}}\n"
    f"\n"
    f"@xdp(eth0)\n"
    f"drop if pkt.src_ip in badhosts\n"
    f"default allow\n"
  )


def _feed(path: Path, count: int, v6: bool = False) -> None:
  """Write `count` distinct prefixes, one per line."""
  lines = []
  if v6:
    for i in range(count):
      lines.append(f"2001:db8:{i:x}::/48")
  else:
    for i in range(count):
      lines.append(f"{10 + i // 65536}.{(i // 256) % 256}.{i % 256}.0/24")
  path.write_text("# generated feed\n" + "\n".join(lines) + "\n")


def _compile_bundle(tmp_path: Path, policy: str, bundle_name="bundle"):
  src = tmp_path / "p.fw"
  src.write_text(policy)
  bundle = tmp_path / bundle_name
  result = CliRunner().invoke(
    cli.main, ["compile", str(src), "--bundle", str(bundle)]
  )
  return result, bundle


# --------------------------------------------------------------------
class TestTheProgramDoesNotGrowWithTheTable:
  """The whole point, asserted on the artifact rather than argued.

  A policy of N prefixes written as N rules is a linear code chain --
  2,000 rules measured 385,826 pps against 3,226,454 for an empty
  policy, and 2,048 is the hard ceiling. The same policy as one lookup
  against an LPM trie measured 227 instructions and 99% of line rate at
  every size from 1,000 to 50,000 prefixes. That flatness is what these
  tests hold: the size lives in the map, so the program cannot see it.
  """

  @staticmethod
  def _instruction_count(c_source: str) -> int:
    # The context manager, not a bare call: compile_c owns the scratch
    # directory it creates, and leaking one moves the ground under
    # test_bpf_runner's cleanup assertions.
    with bpf_runner.compile_c(c_source) as result:
      dump = subprocess.run(
        ["llvm-objdump", "-d", str(result.obj_path)],
        capture_output=True, text=True, check=True,
      )
    return sum(
      1 for line in dump.stdout.splitlines()
      if "\t" in line and line.strip()[:1].isdigit()
    )

  def test_declared_capacity_does_not_change_the_program(self):
    # `max` reaches the object as one field of one map declaration.
    # If it ever reached the instruction stream, this is where a
    # 50,000-entry blocklist would start costing what 50,000 rules
    # cost.
    counts = {
      n: self._instruction_count(emitter.emit(_analyze(_policy(n))))
      for n in (1000, 10000, 50000)
    }
    # Equal is only meaningful if the number is real. A counter that
    # returned 0 for everything would satisfy the assertion below and
    # prove nothing — the same shape of false pass the rig's ACL sweep
    # hit when it read $? instead of the translated size.
    assert all(c > 10 for c in counts.values()), counts
    assert len(set(counts.values())) == 1, counts

  def test_the_bundle_does_not_depend_on_the_feed_at_all(
    self, tmp_path
  ):
    # Tables are disk-authoritative: `source` names a path on the
    # APPLIANCE and `fd` reads it at load. So the compiler never opens
    # it, and the artifact must be identical whether the build host
    # happens to have that file, has a ten-line version of it, or has
    # a fifty-thousand-line one. A compiler whose output moved with a
    # file on the build machine would make `fwl compile` unreproducible
    # and would put the wrong box's data in the bundle.
    outputs = []
    for name, feed in (
      ("absent", None), ("small", 10), ("huge", 50000),
    ):
      d = tmp_path / name
      d.mkdir()
      if feed is not None:
        _feed(d / "feed.txt", feed)
      result, bundle = _compile_bundle(
        d, _policy(100000, "feed.txt"), bundle_name="out"
      )
      assert result.exit_code == 0, result.output
      outputs.append((
        (bundle / "eth0.bpf.c").read_text(),
        json.loads((bundle / "manifest.json").read_text())["tables"],
      ))
    assert outputs[0] == outputs[1] == outputs[2]

  def test_no_prefix_reaches_the_bundle(self, tmp_path):
    # The compiler must not be a second reader of the feed. Nothing in
    # the bundle may carry a prefix, and geoip.json -- which used to
    # carry them under the compile-time model -- must not exist for a
    # policy whose only data is a table.
    _feed(tmp_path / "feed.txt", 20)
    result, bundle = _compile_bundle(tmp_path, _policy(1000))
    assert result.exit_code == 0, result.output
    assert not (bundle / "geoip.json").exists()
    for path in sorted(bundle.iterdir()):
      if path.is_file():
        assert "10.0.0.0/24" not in path.read_text(errors="replace"), (
          f"{path.name} carries a prefix from the feed"
        )


# --------------------------------------------------------------------
class TestAnUnresolvableTableRefusesToCompile:
  """The refusals the COMPILER still owns.

  A name is resolvable or it is not, and that is a property of the
  policy text alone. Whether the feed behind a resolvable name can be
  read is a property of the appliance at load time, so it is refused by
  `fd` (tests/test_bpf_loader.cc) and not here -- the file is not
  supposed to exist on the build host at all.
  """

  def test_undeclared_name_errors_with_the_name_and_the_line(self):
    src = (
      "@xdp(eth0)\n"
      "allow if pkt.dst_ip == 10.0.0.1\n"
      "drop if pkt.src_ip in mystery\n"
      "default allow\n"
    )
    with pytest.raises(FwlException) as exc:
      _analyze(src)
    err = exc.value.error
    assert "mystery" in err.message
    assert err.span is not None and err.span.line == 3
    assert err.category == "semantic"

  def test_undeclared_name_lists_the_tables_that_do_exist(self):
    src = (
      "table badhosts {\n  kind = cidr4\n  max = 10\n"
      '  source = "/var/lib/f/feeds/b.txt"\n}\n'
      "@xdp(eth0)\n"
      "drop if pkt.src_ip in badhost\n"
      "default allow\n"
    )
    with pytest.raises(FwlException) as exc:
      _analyze(src)
    assert "badhosts" in exc.value.error.message

  def test_a_missing_feed_is_not_a_compile_error(self, tmp_path):
    # It cannot be. The path names a file on the appliance, and the
    # build host is a different machine -- refusing here would make
    # every cross-compiled bundle unbuildable.
    result, bundle = _compile_bundle(
      tmp_path, _policy(10, "/var/lib/f/feeds/not-on-this-host.txt")
    )
    assert result.exit_code == 0, result.output
    manifest = json.loads((bundle / "manifest.json").read_text())
    assert manifest["tables"]["badhosts"]["source"] == (
      "/var/lib/f/feeds/not-on-this-host.txt"
    )

  def test_a_declared_but_unmatched_table_warns(self):
    program = _analyze(
      "table badhosts {\n  kind = cidr4\n  max = 10\n"
      '  source = "/var/lib/f/feeds/b.txt"\n}\n'
      "@xdp(eth0)\n"
      "default allow\n"
    )
    assert len(program.warnings) == 1
    assert "badhosts" in program.warnings[0].message


# --------------------------------------------------------------------
class TestTheBundleCarriesTheDeclarationNotTheData:
  """What `fd` needs in order to go and read the feed itself."""

  POLICY = (
    "table corporate_blocklist {\n"
    "  kind = cidr4\n"
    "  max = 100000\n"
    '  source = "/var/lib/f/feeds/corp.txt"\n'
    "}\n"
    "\n"
    "table badhosts = corporate_blocklist\n"
    "\n"
    "table v6_blocklist {\n"
    "  kind = cidr6\n"
    "  max = 100\n"
    '  source = "/var/lib/f/feeds/corp6.txt"\n'
    "}\n"
    "\n"
    "zone wan = [eth0]\n"
    "zone lan = [eth1]\n"
    "\n"
    "@xdp(wan)\n"
    "drop if pkt.src_ip in badhosts\n"
    "drop if pkt.src_ip6 in v6_blocklist\n"
    "default allow\n"
    "\n"
    "@xdp(lan)\n"
    "drop if pkt.dst_ip in corporate_blocklist\n"
    "default allow\n"
  )

  @pytest.fixture
  def manifest(self, tmp_path):
    result, bundle = _compile_bundle(tmp_path, self.POLICY)
    assert result.exit_code == 0, result.output
    self._bundle = bundle
    return json.loads((bundle / "manifest.json").read_text())

  def test_the_manifest_maps_full_names_to_kernel_ids(self, manifest):
    row = manifest["tables"]["corporate_blocklist"]
    assert row["id"] == 0
    assert row["map"] == "fwl_tbl_0"
    assert row["kind"] == "cidr4"
    assert row["max"] == 100000
    assert row["source"] == "/var/lib/f/feeds/corp.txt"
    assert manifest["tables"]["v6_blocklist"]["id"] == 1

  def test_the_manifest_states_no_entry_count(self, manifest):
    # The compiler does not know it and cannot know it: the file is on
    # another machine. A number here would be the build host's guess
    # about an appliance's blocklist, and a stale guess about how much
    # a blocklist holds is worse than no answer. `table show` reports
    # the count from the live map, which is the only place it is true.
    for row in manifest["tables"].values():
      assert "entries" not in row

  def test_the_manifest_lists_aliases_against_their_table(
    self, manifest
  ):
    assert manifest["table_aliases"] == {
      "badhosts": "corporate_blocklist"
    }

  def test_an_alias_allocates_no_second_table(self, manifest):
    assert set(manifest["tables"]) == {
      "corporate_blocklist", "v6_blocklist"
    }

  def test_a_table_nobody_matches_is_marked_unreferenced(
    self, tmp_path
  ):
    policy = (
      "table unused {\n  kind = cidr4\n  max = 10\n"
      '  source = "/var/lib/f/feeds/u.txt"\n}\n'
      "@xdp(eth0)\n"
      "default allow\n"
    )
    result, bundle = _compile_bundle(tmp_path, policy)
    assert result.exit_code == 0, result.output
    manifest = json.loads((bundle / "manifest.json").read_text())
    # No object declares its map, so this is the daemon's instruction
    # not to go looking for a pin that was never created -- and, more
    # to the point, not to fail the load because a feed nothing reads
    # is missing.
    assert manifest["tables"]["unused"]["referenced"] is False
    assert "fwl_tbl_0" not in manifest["persistent_maps"]

  def test_every_zone_declares_the_shared_table_pinned(self, manifest):
    assert "fwl_tbl_0" in manifest["shared_pinned_maps"]
    for zone in ("wan", "lan"):
      src = (self._bundle / f"{zone}.bpf.c").read_text()
      decls = {d.name: d for d in emitter._scan_map_decls(src)}
      assert decls["fwl_tbl_0"].pinned

  def test_the_two_zones_declare_the_table_identically(self, manifest):
    wan = {
      d.name: d.attrs for d in emitter._scan_map_decls(
        (self._bundle / "wan.bpf.c").read_text())
    }
    lan = {
      d.name: d.attrs for d in emitter._scan_map_decls(
        (self._bundle / "lan.bpf.c").read_text())
    }
    assert wan["fwl_tbl_0"] == lan["fwl_tbl_0"]

  def test_the_rules_read_back_with_the_name_the_author_wrote(
    self, manifest
  ):
    wan = next(p for p in manifest["programs"] if p["zone"] == "wan")
    assert wan["rules"]["rules"][0]["match"] == (
      "pkt.src_ip in badhosts"
    )


# --------------------------------------------------------------------
class TestATableSurvivesAPolicyEdit:
  """MapLifetime.EXTERNAL, from the compiler's side.

  A policy edit says nothing about whether an address is still
  hostile. Discarding the trie because the rules changed would throw
  away state this compilation neither produced nor invalidated, and a
  table erased by every policy edit is not a table. `fd` decides what
  to keep by reading `persistent_maps` out of the manifest and
  re-derives nothing, so this is where that decision is made.
  """

  def test_the_row_is_external_and_shared(self):
    kind = emitter._map_kind("fwl_tbl_0")
    assert kind.lifetime is emitter.MapLifetime.EXTERNAL
    assert kind.scope is emitter.MapScope.SHARED
    assert kind.lifetime_why.strip()

  def test_external_is_neither_of_the_other_two(self):
    # The registry exists to stop a map's sharing being derived from a
    # different question. A table is not POLICY (its contents are not
    # this compilation's output) and not FLOW (its key space is a
    # declaration, not a wire fact), and calling it either would be a
    # lie in the one place that is supposed to prevent them.
    assert emitter.MapLifetime.EXTERNAL not in (
      emitter.MapLifetime.POLICY, emitter.MapLifetime.FLOW
    )

  def test_the_manifest_names_every_referenced_table_as_persistent(
    self, tmp_path
  ):
    policy = (
      "table a {\n  kind = cidr4\n  max = 10\n"
      '  source = "/var/lib/f/feeds/a.txt"\n}\n'
      "table b {\n  kind = cidr6\n  max = 10\n"
      '  source = "/var/lib/f/feeds/b.txt"\n}\n'
      "@xdp(eth0)\n"
      "drop if pkt.src_ip in a\n"
      "drop if pkt.src_ip6 in b\n"
      "default allow\n"
    )
    result, bundle = _compile_bundle(tmp_path, policy)
    assert result.exit_code == 0, result.output
    manifest = json.loads((bundle / "manifest.json").read_text())
    persistent = manifest["persistent_maps"]
    # The flow-keyed names are still there; the tables join them.
    assert "fwl_tbl_0" in persistent
    assert "fwl_tbl_1" in persistent

  def test_a_unit_with_no_tables_persists_exactly_what_it_used_to(self):
    # The EXTERNAL row must not widen the list for policies that
    # declare no table. `fd` sweeps every pin not on this list, so a
    # name added unconditionally would keep a map alive that nothing
    # declares.
    program = _analyze("@xdp(eth0)\ndefault allow\n")
    assert emitter.persistent_map_names(program) == (
      "conntrack", "fwl_nat"
    )

  def test_the_names_are_literal_so_the_daemon_compares_strings(self):
    program = _analyze(
      "table a {\n  kind = cidr4\n  max = 10\n"
      '  source = "/var/lib/f/feeds/a.txt"\n}\n'
      "@xdp(eth0)\n"
      "drop if pkt.src_ip in a\n"
      "default allow\n"
    )
    names = emitter.persistent_map_names(program)
    assert "fwl_tbl_0" in names
    # No patterns: fd compares a string against a pin's filename, and
    # a regex crossing the language boundary is the second copy of a
    # decision that this registry exists to prevent.
    for name in names:
      assert emitter._LITERAL_NAME_RE.fullmatch(name), name

  def test_a_private_external_row_is_a_contradiction(self, monkeypatch):
    rows = tuple(
      dataclasses.replace(k, scope=emitter.MapScope.PRIVATE)
      if k.lifetime is emitter.MapLifetime.EXTERNAL else k
      for k in emitter._MAP_KINDS
    )
    monkeypatch.setattr(emitter, "_MAP_KINDS", rows)
    with pytest.raises(FwlException) as exc:
      emitter.persistent_map_names()
    assert "EXTERNAL" in exc.value.error.message


# The headline number from the rig: 50,000 prefixes at 99% of line
# rate, in a program that stayed 227 instructions. The kernel tests
# below use the same count so that "the map really held them all" is
# asserted at the size the claim is made at.
_BIG_TABLE_COUNT = 50000


@pytest.fixture(scope="module")
def big_table(tmp_path_factory):
  """A compiled 50,000-prefix policy plus the map seed for its trie.

  The prefixes come from the FEED FILE, which is where `fd` gets them:
  the bundle carries only the declaration, and the manifest's `source`
  is what says where to look. Reading the file here rather than the
  bundle is the point -- it is the same path the daemon walks.
  """
  if not bpf_runner._can_load_bpf():
    pytest.skip("kernel BPF load unavailable (needs root)")
  d = tmp_path_factory.mktemp("bigtable")
  feed = d / "feed.txt"
  _feed(feed, _BIG_TABLE_COUNT)
  policy = _policy(_BIG_TABLE_COUNT, str(feed))
  result, bundle = _compile_bundle(d, policy)
  assert result.exit_code == 0, result.output
  manifest = json.loads((bundle / "manifest.json").read_text())
  assert manifest["tables"]["badhosts"]["source"] == str(feed)
  prefixes = sorted(
    line.split("#", 1)[0].strip()
    for line in feed.read_text().splitlines()
    if line.split("#", 1)[0].strip()
  )
  assert len(prefixes) == _BIG_TABLE_COUNT
  program = _analyze(policy)
  map_init = fwl_runner._build_table_map_init(
    program, {"badhosts": prefixes}
  )
  assert len(map_init["fwl_tbl_0"]) == _BIG_TABLE_COUNT
  return emitter.emit(program), map_init, prefixes


# --------------------------------------------------------------------
class TestTheKernelHoldsTheWholeTable:
  """A real LPM trie, a real 50,000 prefixes, real lookups.

  The rig would answer this with `bpftool map dump | wc -l`. This
  answers it without hardware and asks a harder question: the entries
  go into a kernel map through bpf_map_update_elem, and then
  BPF_PROG_TEST_RUN is asked about addresses drawn from the start, the
  middle and the end of the file. A trie that took the first few
  thousand and stopped would load without complaint and answer wrong,
  which is exactly the failure this is looking for.

  Skips without CAP_BPF, like the corpus's own BPF oracle. A green run
  unprivileged does not include this.
  """

  @staticmethod
  def _first_address(cidr: str) -> str:
    return cidr.split("/")[0]

  @pytest.mark.parametrize("position", ["first", "middle", "last"])
  def test_an_address_from_anywhere_in_the_file_is_dropped(
    self, big_table, position
  ):
    c_source, map_init, prefixes = big_table
    index = {
      "first": 0, "middle": len(prefixes) // 2, "last": -1,
    }[position]
    addr = self._first_address(prefixes[index])
    packet = pkt._build_from_spec(
      f'tcp(src_ip="{addr}", dst_port=80)', None
    )
    action = bpf_runner.run(c_source, packet.raw, map_init)
    assert action.name == "DROP", (
      f"{addr} is prefix {index} of {len(prefixes)} in the loaded "
      f"trie and the program did not drop it"
    )

  def test_an_address_in_no_prefix_is_allowed(self, big_table):
    # The near-miss half: 50,000 entries must not make the lookup
    # answer yes to everything.
    c_source, map_init, _ = big_table
    packet = pkt._build_from_spec(
      'tcp(src_ip="203.0.113.7", dst_port=80)', None
    )
    action = bpf_runner.run(c_source, packet.raw, map_init)
    assert action.name == "PASS"

  def test_a_map_too_small_for_the_entries_fails_the_load(
    self, big_table
  ):
    # Plant the defect the tests above exist to catch. Same 50,000
    # entries, a map declared with room for 1,000: the kernel returns
    # E2BIG and the seeding raises. Without this, "the lookups
    # answered right" would be consistent with a map that quietly
    # took a fraction of the file -- and the passing runs above would
    # be proving much less than they appear to.
    _, map_init, _ = big_table
    small = emitter.emit(_analyze(_policy(1000, "/var/lib/f/feeds/x")))
    with pytest.raises(OSError, match="bpf_map_update_elem"):
      bpf_runner.run(small, b"\x00" * 64, map_init)


# --------------------------------------------------------------------
class TestTablesAndGeoipNoLongerShareAPayload:
  """The same map type, and no longer the same data path.

  geoip() prefixes come from the COMPILATION -- a country list the
  build host resolved -- and ship in geoip.json. A table's prefixes
  come from a file on the appliance and never enter the bundle.
  Converging the two mechanisms is a real simplification and an open
  question in TABLES.md; converging them by ACCIDENT, so that a table
  quietly acquired a compile-time snapshot, is the failure mode.
  """

  def test_geoip_still_ships_its_prefixes_and_the_table_does_not(
    self, tmp_path
  ):
    (tmp_path / "geo.json").write_text(
      json.dumps({"DE": ["10.9.0.0/16"]}))
    src = tmp_path / "p.fw"
    src.write_text(
      "table badhosts {\n  kind = cidr4\n  max = 10\n"
      '  source = "/var/lib/f/feeds/b.txt"\n}\n'
      "@xdp(eth0)\n"
      "drop if pkt.src_ip in badhosts\n"
      "drop if pkt.src_ip in geoip(DE)\n"
      "default allow\n"
    )
    bundle = tmp_path / "out"
    result = CliRunner().invoke(cli.main, [
      "compile", str(src), "--bundle", str(bundle),
      "--geoip", str(tmp_path / "geo.json"),
    ])
    assert result.exit_code == 0, result.output
    payload = json.loads((bundle / "geoip.json").read_text())
    assert {t["map"] for t in payload["tries"]} == {"fwl_geoip_eth0_0"}
    manifest = json.loads((bundle / "manifest.json").read_text())
    assert manifest["tables"]["badhosts"]["map"] == "fwl_tbl_0"

  def test_the_two_tries_have_opposite_lifetimes(self):
    # Same map type, opposite answers to "may these contents outlive
    # this compilation". A geoip trie is repopulated from the bundle
    # at every load and adopting one would answer for a country the
    # new call site never asked about; a table's contents are not the
    # compilation's to discard.
    assert emitter._map_kind("fwl_geoip_0").lifetime is (
      emitter.MapLifetime.POLICY)
    assert emitter._map_kind("fwl_tbl_0").lifetime is (
      emitter.MapLifetime.EXTERNAL)


# --------------------------------------------------------------------
class TestTheDaemonReadsWhatTheCompilerWrites:
  """The compiler/daemon contract, held from both ends.

  tests/test_bpf_loader.cc::TableSpecTest::
  ParsesTheDeclarationTheCompilerShips feeds `ParseTableSpecs` the
  exact JSON below and asserts the TableSpecs it yields. This asserts
  the compiler still produces it. Either side drifting turns one of
  the two red -- which matters more under the disk-authoritative model
  than it did before, because this block is now the only thing the two
  languages share about a file neither of them has seen.
  """

  # Byte-for-byte what tests/test_bpf_loader.cc has pasted into it.
  EXPECTED_TABLES = {
    "corporate_blocklist": {
      "id": 0,
      "map": "fwl_tbl_0",
      "kind": "cidr4",
      "max": 100000,
      "source": "/var/lib/f/feeds/corp.txt",
      "referenced": True,
    },
    "v6_blocklist": {
      "id": 1,
      "map": "fwl_tbl_1",
      "kind": "cidr6",
      "max": 100,
      "source": "/var/lib/f/feeds/corp6.txt",
      "referenced": True,
    },
  }

  POLICY = (
    "table corporate_blocklist {\n"
    "  kind = cidr4\n"
    "  max = 100000\n"
    '  source = "/var/lib/f/feeds/corp.txt"\n'
    "}\n"
    "\n"
    "table v6_blocklist {\n"
    "  kind = cidr6\n"
    "  max = 100\n"
    '  source = "/var/lib/f/feeds/corp6.txt"\n'
    "}\n"
    "\n"
    "@xdp(eth0)\n"
    "drop if pkt.src_ip in corporate_blocklist\n"
    "drop if pkt.src_ip6 in v6_blocklist\n"
    "default allow\n"
  )

  def test_the_manifest_block_is_what_the_loader_test_pins(
    self, tmp_path
  ):
    result, bundle = _compile_bundle(tmp_path, self.POLICY)
    assert result.exit_code == 0, result.output
    manifest = json.loads((bundle / "manifest.json").read_text())
    assert manifest["tables"] == self.EXPECTED_TABLES


# --------------------------------------------------------------------
class TestIdAllocation:
  """Full names in the language, a short mapped id in the kernel."""

  def test_ids_follow_declaration_order_not_reference_order(self):
    program = _analyze(
      "table alpha {\n  kind = cidr4\n  max = 10\n"
      '  source = "a.txt"\n}\n'
      "table beta {\n  kind = cidr4\n  max = 10\n"
      '  source = "b.txt"\n}\n'
      "@xdp(eth0)\n"
      "drop if pkt.src_ip in beta\n"
      "drop if pkt.src_ip in alpha\n"
      "default allow\n"
    )
    assert analyzer.table_map_id(program) == {"alpha": 0, "beta": 1}

  def test_an_alias_resolves_to_its_target_id(self):
    program = _analyze(
      "table alpha {\n  kind = cidr4\n  max = 10\n"
      '  source = "a.txt"\n}\n'
      "table pasted = alpha\n"
      "@xdp(eth0)\n"
      "drop if pkt.src_ip in pasted\n"
      "default allow\n"
    )
    ref = program.programs[0].rules[0].condition.operand
    assert (ref.name, ref.resolved, ref.table_id) == ("pasted", "alpha", 0)

  def test_the_map_name_fits_the_kernel_name_limit(self):
    # BPF_OBJ_NAME_LEN is 16, so an in-kernel map name truncates at 15
    # characters. The id exists so that it never does.
    assert len(emitter.MapNames().table(999999)) <= 15


# --------------------------------------------------------------------
class TestTheSplitterChargesTheLookup:
  """An under-estimating splitter is the direction that hurts."""

  def test_a_table_rule_costs_what_a_geoip_rule_costs(self):
    table_zone = _analyze(
      "table badhosts {\n  kind = cidr4\n  max = 10\n"
      '  source = "b.txt"\n}\n'
      "@xdp(eth0)\n"
      "drop if pkt.src_ip in badhosts\n"
      "default allow\n"
    ).programs[0]
    geoip_zone = _analyze(
      "@xdp(eth0)\n"
      "drop if pkt.src_ip in geoip(DE)\n"
      "default allow\n"
    ).programs[0]
    plain_zone = _analyze(
      "@xdp(eth0)\n"
      "drop if pkt.src_ip in 10.0.0.0/8\n"
      "default allow\n"
    ).programs[0]
    assert (
      splitter.estimate(table_zone).instructions
      == splitter.estimate(geoip_zone).instructions
    )
    assert (
      splitter.estimate(table_zone).instructions
      > splitter.estimate(plain_zone).instructions
    )


# --------------------------------------------------------------------
class TestTheShippedExample:
  """`fwl/examples/blocklist_table.fw` is policy we ship.

  An example is what an operator copies, so it is held to the bar
  test_examples.py sets: not "it compiles" but "this packet gets this
  verdict". The table contents come from the same feed files the
  compiler reads, so the assertion is against the artifact rather than
  against a restatement of it.
  """

  EXAMPLES = Path(__file__).resolve().parents[2] / "examples"

  @staticmethod
  def _feed(path: Path) -> list[str]:
    out = []
    for raw in path.read_text().splitlines():
      line = raw.split("#", 1)[0].strip()
      if line:
        out.append(line)
    return out

  @pytest.fixture
  def program(self):
    return _analyze((self.EXAMPLES / "blocklist_table.fw").read_text())

  @pytest.fixture
  def table_data(self):
    return {
      "corporate_blocklist": self._feed(
        self.EXAMPLES / "feeds" / "blocklist.txt"),
      "corporate_blocklist6": self._feed(
        self.EXAMPLES / "feeds" / "blocklist6.txt"),
    }

  def _run(self, program, table_data, builder: str):
    packet = pkt._build_from_spec(builder, None)
    from fwl import interpreter
    return interpreter.evaluate(
      program, packet.fields, table_data=table_data
    )

  def test_it_compiles_on_a_host_that_has_none_of_the_feeds(
    self, tmp_path
  ):
    # `source` names a path on the appliance. A build host does not
    # have /var/lib/f/feeds, and must not need it: the bundle carries
    # the declaration and `fd` reads the file.
    assert not Path("/var/lib/f/feeds/blocklist.txt").exists()
    bundle = tmp_path / "out"
    result = CliRunner().invoke(cli.main, [
      "compile", str(self.EXAMPLES / "blocklist_table.fw"),
      "--bundle", str(bundle),
    ])
    assert result.exit_code == 0, result.output
    manifest = json.loads((bundle / "manifest.json").read_text())
    assert manifest["tables"]["corporate_blocklist"]["source"] == (
      "/var/lib/f/feeds/blocklist.txt")
    assert manifest["tables"]["corporate_blocklist6"]["map"] == (
      "fwl_tbl_1")
    assert not (bundle / "geoip.json").exists()

  def test_the_sample_feeds_are_what_the_daemon_would_accept(self):
    # The files beside the example are a sample of the format an
    # operator copies onto the box, so they have to BE that format --
    # a sample the daemon would refuse teaches the wrong thing. The
    # authority is tests/test_bpf_loader.cc::TableFeedTest; this is
    # the same rules applied to the shipped files.
    import ipaddress
    for name, want_v4 in (
      ("blocklist.txt", True), ("blocklist6.txt", False),
    ):
      entries = self._feed(self.EXAMPLES / "feeds" / name)
      assert entries, name
      for item in entries:
        assert "/" in item, f"{name}: {item} has no prefix length"
        net = ipaddress.ip_network(item, strict=False)
        assert isinstance(net, ipaddress.IPv4Network) is want_v4, (
          f"{name}: {item} is the wrong family")

  def test_a_listed_v4_source_is_dropped(self, program, table_data):
    from fwl.interpreter import XdpAction
    assert self._run(
      program, table_data,
      'tcp(src_ip="203.0.113.9", dst_port=443)',
    ) == XdpAction.DROP

  def test_the_single_host_entry_is_dropped(self, program, table_data):
    # The /32 in the feed, which the surrounding /24 does NOT cover.
    from fwl.interpreter import XdpAction
    assert self._run(
      program, table_data,
      'tcp(src_ip="198.51.100.77", dst_port=443)',
    ) == XdpAction.DROP

  def test_an_unlisted_source_on_an_allowed_port_passes(
    self, program, table_data
  ):
    from fwl.interpreter import XdpAction
    assert self._run(
      program, table_data,
      'tcp(src_ip="10.0.0.5", dst_port=443)',
    ) == XdpAction.PASS

  def test_an_unlisted_source_on_a_closed_port_is_dropped(
    self, program, table_data
  ):
    from fwl.interpreter import XdpAction
    assert self._run(
      program, table_data,
      'tcp(src_ip="10.0.0.5", dst_port=23)',
    ) == XdpAction.DROP

  def test_a_listed_v6_source_is_dropped(self, program, table_data):
    from fwl.interpreter import XdpAction
    assert self._run(
      program, table_data,
      'tcp6(src_ip="2001:db8::1", dst_port=443)',
    ) == XdpAction.DROP

  def test_the_alias_and_its_target_are_one_table(self, program):
    # `badhosts` in the rule, `corporate_blocklist` in the feed key:
    # the assertions above only hold because the two are one table.
    ref = program.programs[0].rules[0].condition.operand
    assert ref.name == "badhosts"
    assert ref.resolved == "corporate_blocklist"


# --------------------------------------------------------------------
class TestTheCorpusIsNotVacuous:
  """Plant the defect: empty every table and require the cases to go red.

  A corpus case that asserts `drop` proves the lookup works only if the
  same case with an empty table asserts something else. This is the
  vacuity sweep the rig runs, applied to the one construct whose
  failure mode is a map that loads empty.
  """

  def test_there_are_cases_to_sweep(self):
    # A sweep over nothing is green for the wrong reason.
    assert len(_TABLE_POSITIVE_CASES) >= 8

  def test_every_seeded_drop_case_is_accounted_for(self):
    # An exclusion list nobody checks is an exclusion list that grows.
    # Every seeded `drop` case is either swept or named below with its
    # reason, and the two sets must exhaust the directory.
    covered = {p.stem for p in _TABLE_POSITIVE_CASES}
    covered |= set(_VERDICT_NOT_FROM_A_TABLE_HIT)
    assert covered == {p.stem for p in _seeded_drop_cases()}

  @pytest.mark.parametrize(
    "path", _TABLE_POSITIVE_CASES, ids=lambda p: p.stem
  )
  def test_emptying_the_table_flips_the_verdict(self, path):
    result = fwl_runner.run_case(_with_empty_tables(pkt.load(path)))
    assert not result.passed, (
      f"{path.name} still passes with every table empty, so it does "
      f"not prove the lookup reads the table"
    )

  @pytest.mark.parametrize(
    "path", _TABLE_NEGATIVE_CASES, ids=lambda p: p.stem
  )
  def test_a_verdict_from_elsewhere_survives_an_empty_table(self, path):
    # The other direction, asserted rather than skipped: these three
    # drop for a reason that is not a table hit, so emptying the table
    # must leave them alone. If one ever starts depending on the
    # lookup, this goes red and it moves into the sweep above.
    result = fwl_runner.run_case(_with_empty_tables(pkt.load(path)))
    assert result.passed, (
      f"{path.name} changed verdict when its tables were emptied — "
      f"{_VERDICT_NOT_FROM_A_TABLE_HIT[path.stem]} no longer holds"
    )
