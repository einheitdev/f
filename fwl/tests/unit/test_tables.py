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

  def test_fifty_thousand_prefixes_do_not_change_the_program(
    self, tmp_path
  ):
    # The contents half. The prefixes never enter the program at all --
    # they are resolved into the bundle payload and loaded into the map
    # -- so a table of 50,000 must emit the same object as one of 10.
    sources = {}
    for count in (10, 50000):
      d = tmp_path / f"n{count}"
      d.mkdir()
      _feed(d / "feed.txt", count)
      result, bundle = _compile_bundle(
        d, _policy(100000), bundle_name="out"
      )
      assert result.exit_code == 0, result.output
      sources[count] = (bundle / "eth0.bpf.c").read_text()
      payload = json.loads((bundle / "geoip.json").read_text())
      assert len(payload["tries"][0]["prefixes"]) == count
    assert sources[10] == sources[50000]


# --------------------------------------------------------------------
class TestAnUnfillableTableRefusesToCompile:
  """A silently empty table is a rule that never matches.

  In a blocklist that is an open firewall, and nothing on the running
  box reports it. Every way the contents can fall short of what the
  policy asked for is therefore an error, not a smaller table.
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
      '  source = "f.txt"\n}\n'
      "@xdp(eth0)\n"
      "drop if pkt.src_ip in badhost\n"
      "default allow\n"
    )
    with pytest.raises(FwlException) as exc:
      _analyze(src)
    assert "badhosts" in exc.value.error.message

  def test_missing_source_file_is_an_error(self, tmp_path):
    result, _ = _compile_bundle(tmp_path, _policy(10, "nowhere.txt"))
    assert result.exit_code == 1
    assert "badhosts" in result.output
    assert "nowhere.txt" in result.output

  def test_a_source_file_of_only_comments_is_an_error(self, tmp_path):
    (tmp_path / "feed.txt").write_text("# nothing\n\n   \n")
    result, _ = _compile_bundle(tmp_path, _policy(10))
    assert result.exit_code == 1
    assert "never matches" in result.output

  def test_more_prefixes_than_max_is_refused_not_truncated(
    self, tmp_path
  ):
    # TABLES.md: refuse, never evict. A table quietly missing entries
    # fails open if it is a blocklist, so the message says how many did
    # not fit rather than leaving the operator to count.
    _feed(tmp_path / "feed.txt", 12)
    result, bundle = _compile_bundle(tmp_path, _policy(10))
    assert result.exit_code == 1
    assert "max = 10" in result.output
    assert "12 distinct prefixes" in result.output
    assert not (bundle / "geoip.json").exists()

  def test_duplicate_prefixes_do_not_count_against_capacity(
    self, tmp_path
  ):
    # The same prefix twice is one entry in an LPM trie, so counting it
    # twice would refuse a file the map would have held.
    (tmp_path / "feed.txt").write_text(
      "10.0.0.0/8\n10.0.0.0/8\n192.168.0.0/16\n"
    )
    result, bundle = _compile_bundle(tmp_path, _policy(2))
    assert result.exit_code == 0, result.output
    payload = json.loads((bundle / "geoip.json").read_text())
    assert payload["tries"][0]["prefixes"] == [
      "10.0.0.0/8", "192.168.0.0/16"
    ]

  def test_an_entry_of_the_wrong_family_is_an_error(self, tmp_path):
    (tmp_path / "feed.txt").write_text("10.0.0.0/8\n2001:db8::/32\n")
    result, _ = _compile_bundle(tmp_path, _policy(10))
    assert result.exit_code == 1
    assert "kind = cidr4" in result.output
    assert "line 2" in result.output

  def test_an_unparseable_line_is_an_error_with_its_line_number(
    self, tmp_path
  ):
    (tmp_path / "feed.txt").write_text("10.0.0.0/8\nnot-an-address\n")
    result, _ = _compile_bundle(tmp_path, _policy(10))
    assert result.exit_code == 1
    assert "line 2" in result.output

  def test_a_declared_but_unmatched_table_warns(self):
    program = _analyze(
      "table badhosts {\n  kind = cidr4\n  max = 10\n"
      '  source = "f.txt"\n}\n'
      "@xdp(eth0)\n"
      "default allow\n"
    )
    assert len(program.warnings) == 1
    assert "badhosts" in program.warnings[0].message


# --------------------------------------------------------------------
class TestTheBundleTellsTheDaemonEverything:
  """Phase 1 needs no daemon change, which is a claim about the payload.

  `ParseGeoipFile` returns {map_name: prefixes} and
  `PopulateGeoipTrie` fills any named LPM trie from it. These tests
  hold the compiler to the shape that loader already reads.
  """

  @pytest.fixture
  def bundle(self, tmp_path):
    _feed(tmp_path / "corp.txt", 5)
    _feed(tmp_path / "corp6.txt", 3, v6=True)
    policy = (
      "table corporate_blocklist {\n"
      "  kind = cidr4\n"
      "  max = 100000\n"
      '  source = "corp.txt"\n'
      "}\n"
      "\n"
      "table badhosts = corporate_blocklist\n"
      "\n"
      "table v6_blocklist {\n"
      "  kind = cidr6\n"
      "  max = 100\n"
      '  source = "corp6.txt"\n'
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
    result, out = _compile_bundle(tmp_path, policy)
    assert result.exit_code == 0, result.output
    return out

  def test_the_payload_carries_every_prefix_under_the_map_name(
    self, bundle
  ):
    payload = json.loads((bundle / "geoip.json").read_text())
    by_map = {t["map"]: t for t in payload["tries"]}
    assert by_map["fwl_tbl_0"]["family"] == "ipv4"
    assert len(by_map["fwl_tbl_0"]["prefixes"]) == 5
    assert by_map["fwl_tbl_1"]["family"] == "ipv6"
    assert len(by_map["fwl_tbl_1"]["prefixes"]) == 3

  def test_the_manifest_maps_full_names_to_kernel_ids(self, bundle):
    manifest = json.loads((bundle / "manifest.json").read_text())
    tables = manifest["tables"]
    assert tables["corporate_blocklist"]["id"] == 0
    assert tables["corporate_blocklist"]["map"] == "fwl_tbl_0"
    assert tables["corporate_blocklist"]["kind"] == "cidr4"
    assert tables["corporate_blocklist"]["max"] == 100000
    assert tables["corporate_blocklist"]["entries"] == 5
    assert tables["v6_blocklist"]["id"] == 1

  def test_the_manifest_lists_aliases_against_their_table(self, bundle):
    manifest = json.loads((bundle / "manifest.json").read_text())
    assert manifest["table_aliases"] == {
      "badhosts": "corporate_blocklist"
    }

  def test_an_alias_is_the_same_map_not_a_second_one(self, bundle):
    payload = json.loads((bundle / "geoip.json").read_text())
    # Two names, two rules, one trie: the alias allocates nothing.
    assert len(payload["tries"]) == 2

  def test_every_zone_declares_the_shared_table_pinned(self, bundle):
    manifest = json.loads((bundle / "manifest.json").read_text())
    assert "fwl_tbl_0" in manifest["shared_pinned_maps"]
    for zone in ("wan", "lan"):
      src = (bundle / f"{zone}.bpf.c").read_text()
      decls = {
        d.name: d for d in emitter._scan_map_decls(src)
      }
      assert decls["fwl_tbl_0"].pinned

  def test_the_two_zones_declare_the_table_identically(self, bundle):
    wan = {
      d.name: d.attrs
      for d in emitter._scan_map_decls((bundle / "wan.bpf.c").read_text())
    }
    lan = {
      d.name: d.attrs
      for d in emitter._scan_map_decls((bundle / "lan.bpf.c").read_text())
    }
    assert wan["fwl_tbl_0"] == lan["fwl_tbl_0"]

  def test_the_rules_read_back_with_the_name_the_author_wrote(
    self, bundle
  ):
    manifest = json.loads((bundle / "manifest.json").read_text())
    wan = next(
      p for p in manifest["programs"] if p["zone"] == "wan"
    )
    assert wan["rules"]["rules"][0]["match"] == (
      "pkt.src_ip in badhosts"
    )

  def test_a_table_nobody_matches_reports_no_entry_count(
    self, tmp_path
  ):
    _feed(tmp_path / "feed.txt", 3)
    policy = (
      "table unused {\n  kind = cidr4\n  max = 10\n"
      '  source = "feed.txt"\n}\n'
      "@xdp(eth0)\n"
      "default allow\n"
    )
    result, bundle = _compile_bundle(tmp_path, policy)
    assert result.exit_code == 0, result.output
    manifest = json.loads((bundle / "manifest.json").read_text())
    # No map is emitted for it, so "how many entries" has no answer
    # rather than the answer zero.
    assert manifest["tables"]["unused"]["entries"] is None
    assert not (bundle / "geoip.json").exists()


# --------------------------------------------------------------------
class TestTablesAndGeoipShareOnePayload:
  """Both mechanisms are the same map; the loader must see both."""

  def test_a_program_with_both_emits_both_tries(self, tmp_path):
    _feed(tmp_path / "feed.txt", 4)
    (tmp_path / "geo.json").write_text(json.dumps({"DE": ["10.9.0.0/16"]}))
    src = tmp_path / "p.fw"
    src.write_text(
      "table badhosts {\n  kind = cidr4\n  max = 10\n"
      '  source = "feed.txt"\n}\n'
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
    maps = {t["map"] for t in payload["tries"]}
    assert maps == {"fwl_geoip_eth0_0", "fwl_tbl_0"}


# The headline number from the rig: 50,000 prefixes at 99% of line
# rate, in a program that stayed 227 instructions. The kernel tests
# below use the same count so that "the map really held them all" is
# asserted at the size the claim is made at.
_BIG_TABLE_COUNT = 50000


@pytest.fixture(scope="module")
def big_table(tmp_path_factory):
  """A compiled 50,000-prefix policy plus the map seed for its trie."""
  if not bpf_runner._can_load_bpf():
    pytest.skip("kernel BPF load unavailable (needs root)")
  d = tmp_path_factory.mktemp("bigtable")
  _feed(d / "feed.txt", _BIG_TABLE_COUNT)
  result, bundle = _compile_bundle(d, _policy(_BIG_TABLE_COUNT))
  assert result.exit_code == 0, result.output
  payload = json.loads((bundle / "geoip.json").read_text())
  prefixes = payload["tries"][0]["prefixes"]
  assert len(prefixes) == _BIG_TABLE_COUNT
  program = _analyze(_policy(_BIG_TABLE_COUNT))
  map_init = fwl_runner._build_table_map_init(
    program, {"badhosts": prefixes}
  )
  assert len(map_init["fwl_tbl_0"]) == _BIG_TABLE_COUNT
  return emitter.emit(program), map_init, sorted(prefixes)


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
    small = emitter.emit(_analyze(_policy(1000)))
    with pytest.raises(OSError, match="bpf_map_update_elem"):
      bpf_runner.run(small, b"\x00" * 64, map_init)


# --------------------------------------------------------------------
class TestTheDaemonReadsWhatTheCompilerWrites:
  """The "phase 1 needs no daemon change" claim, held from both ends.

  tests/test_bpf_loader.cc::GeoipParseTest::
  ReadsATablePayloadTheCompilerEmitted feeds the unmodified
  `ParseGeoipFile` the exact JSON below and asserts the entries it
  yields. This test asserts the compiler still produces it. Either
  side drifting turns one of the two red.
  """

  # Byte-for-byte what tests/test_bpf_loader.cc has pasted into it.
  EXPECTED_PAYLOAD = {
    "tries": [
      {
        "map": "fwl_tbl_0",
        "family": "ipv4",
        "prefixes": ["10.99.77.0/24", "192.0.2.0/25"],
      },
      {
        "map": "fwl_tbl_1",
        "family": "ipv6",
        "prefixes": ["2001:db8::/32"],
      },
    ]
  }

  POLICY = (
    "table corporate_blocklist {\n"
    "  kind = cidr4\n"
    "  max = 100000\n"
    '  source = "corp.txt"\n'
    "}\n"
    "\n"
    "table v6_blocklist {\n"
    "  kind = cidr6\n"
    "  max = 100\n"
    '  source = "corp6.txt"\n'
    "}\n"
    "\n"
    "@xdp(eth0)\n"
    "drop if pkt.src_ip in corporate_blocklist\n"
    "drop if pkt.src_ip6 in v6_blocklist\n"
    "default allow\n"
  )

  def test_the_payload_is_what_the_loader_test_pins(self, tmp_path):
    (tmp_path / "corp.txt").write_text("10.99.77.0/24\n192.0.2.0/25\n")
    (tmp_path / "corp6.txt").write_text("2001:db8::/32\n")
    result, bundle = _compile_bundle(tmp_path, self.POLICY)
    assert result.exit_code == 0, result.output
    payload = json.loads((bundle / "geoip.json").read_text())
    assert payload == self.EXPECTED_PAYLOAD


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

  def test_it_compiles_to_a_bundle_with_the_feeds_loaded(
    self, tmp_path
  ):
    bundle = tmp_path / "out"
    result = CliRunner().invoke(cli.main, [
      "compile", str(self.EXAMPLES / "blocklist_table.fw"),
      "--bundle", str(bundle),
    ])
    assert result.exit_code == 0, result.output
    payload = json.loads((bundle / "geoip.json").read_text())
    by_map = {t["map"]: t["prefixes"] for t in payload["tries"]}
    assert "198.51.100.77/32" in by_map["fwl_tbl_0"]
    assert by_map["fwl_tbl_1"] == ["2001:db8::/32"]

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
