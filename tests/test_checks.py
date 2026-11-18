from pathlib import Path

import pytest

from ot_sec import checks, inventory, vulns
from ot_sec.__main__ import run
from ot_sec.network import Network

DATA = Path(__file__).resolve().parents[1] / "data"


@pytest.fixture
def net():
    return Network.from_json(DATA / "network.json")


@pytest.fixture
def df():
    return inventory.load_assets(DATA / "assets.csv")


def by_check(findings, name):
    return [f for f in findings if f.check == name]


def test_inventory_detects_duplicate_ip_and_wrong_zone(df, net):
    f = inventory.validate_inventory(df, net)
    assert by_check(f, "DUPLICATE_IP")[0].detail.startswith("IP 10.20.0.5")
    assert {x.asset for x in by_check(f, "WRONG_ZONE")} == {"iot-humid-02", "plc-packaging"}


def test_windows_hosts_do_not_need_firmware(df, net):
    incomplete = {x.asset: x.detail for x in by_check(inventory.validate_inventory(df, net), "INCOMPLETE_RECORD")}
    assert "it-ws-01" not in incomplete
    assert incomplete["iot-humid-02"] == "missing: owner"


def test_it_to_control_direct_paths(df, net):
    hosts = {f.asset for f in checks.check_it_to_control_paths(df, net)}
    assert "plc-granulator" in hosts          # via TEMP-vendor-remote-access (Modbus)
    assert "iot-temp-01" in hosts             # via route that skips the firewall


def test_firewall_rule_review(net):
    f = checks.check_firewall_rules(net)
    assert by_check(f, "OVERLY_PERMISSIVE_RULE")[0].asset == "Troubleshooting-any"
    assert {x.asset for x in by_check(f, "INSECURE_PROTOCOL_CROSS_ZONE")} == {"TEMP-vendor-remote-access", "Engineering-legacy-telnet"}


def test_vulnerability_matching_uses_version_compare(df, net):
    f = vulns.match_advisories(df, DATA / "advisories.json", net)
    hosts = {x.asset for x in f}
    assert "plc-granulator" in hosts          # 1.8.2 < 2.0.0
    assert "plc-tablet-press" not in hosts    # 2.1.0 is patched
    assert "hmi-line-1" not in hosts          # 2.4.0 == fixed_in
    assert vulns.version_tuple("1.10.0") > vulns.version_tuple("1.9.0")


def test_hardened_network_has_no_it_to_control_paths(df, net):
    net.rules = [r for r in net.rules if r.name not in ("TEMP-vendor-remote-access", "Troubleshooting-any")]
    net.routes = [r for r in net.routes if str(r.destination) != "10.60.0.0/24"]
    assert checks.check_it_to_control_paths(df, net) == []


def test_end_to_end_report(tmp_path):
    findings = run(DATA, tmp_path)
    assert findings[0].severity == "Critical"
    text = (tmp_path / "assessment_report.md").read_text()
    assert "Executive summary" in text and "Purdue" in text
    assert "Threat scenario" in text and "Ransomware" in text
    assert (tmp_path / "findings.csv").read_text().count("\n") == len(findings) + 1
