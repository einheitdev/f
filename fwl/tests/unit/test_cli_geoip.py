"""Bundle-time geoip.json emission (`fwl compile --bundle --geoip`).

The daemon loads geoip LPM tries from the bundle's geoip.json at
attach time; these tests pin the compiler half of that contract.
"""
import json
from pathlib import Path

from click.testing import CliRunner

from fwl import cli

GEOIP_POLICY = """\
@xdp(eth0)

drop if pkt.src_ip in geoip(DE)
default allow
"""

MULTI_COUNTRY_POLICY = """\
@xdp(eth0)

drop if pkt.src_ip in geoip(DE, FR)
default allow
"""

DATA = {
  "DE": ["10.99.77.0/24", "2001:db8:de::/48"],
  "FR": ["10.99.78.0/24"],
}


def _compile_bundle(tmp_path: Path, policy: str, data: dict | None):
  src = tmp_path / "p.fw"
  src.write_text(policy)
  bundle = tmp_path / "bundle"
  args = ["compile", str(src), "--bundle", str(bundle)]
  if data is not None:
    geoip = tmp_path / "geoip-data.json"
    geoip.write_text(json.dumps(data))
    args += ["--geoip", str(geoip)]
  result = CliRunner().invoke(cli.main, args)
  return result, bundle


def test_bundle_writes_geoip_json(tmp_path):
  result, bundle = _compile_bundle(tmp_path, GEOIP_POLICY, DATA)
  assert result.exit_code == 0, result.output
  payload = json.loads((bundle / "geoip.json").read_text())
  assert payload["tries"] == [{
    "map": "fwl_geoip_0",
    "family": "ipv4",
    "prefixes": ["10.99.77.0/24"],
  }]


def test_bundle_unions_multi_country(tmp_path):
  result, bundle = _compile_bundle(
    tmp_path, MULTI_COUNTRY_POLICY, DATA
  )
  assert result.exit_code == 0, result.output
  payload = json.loads((bundle / "geoip.json").read_text())
  assert payload["tries"][0]["prefixes"] == [
    "10.99.77.0/24", "10.99.78.0/24",
  ]


def test_geoip_program_without_data_is_an_error(tmp_path):
  result, bundle = _compile_bundle(tmp_path, GEOIP_POLICY, None)
  assert result.exit_code == 1
  assert "no --geoip data file" in result.output
  assert not (bundle / "geoip.json").exists()


def test_country_without_family_prefixes_is_an_error(tmp_path):
  # DE has only v6 prefixes here, but the call is bound to ipv4.
  result, _ = _compile_bundle(
    tmp_path, GEOIP_POLICY, {"DE": ["2001:db8:de::/48"]}
  )
  assert result.exit_code == 1
  assert "no ipv4 prefixes" in result.output


def test_plain_bundle_has_no_geoip_json(tmp_path):
  result, bundle = _compile_bundle(
    tmp_path, "@xdp(eth0)\n\ndefault allow\n", None
  )
  assert result.exit_code == 0, result.output
  assert not (bundle / "geoip.json").exists()
