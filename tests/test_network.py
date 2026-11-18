from pathlib import Path

import pytest

from ot_sec.network import Network

DATA = Path(__file__).resolve().parents[1] / "data"


@pytest.fixture
def net():
    return Network.from_json(DATA / "network.json")


def test_vlan_of_ip(net):
    assert net.vlan_of_ip("10.21.0.11").id == 21
    assert net.vlan_of_ip("192.168.1.1") is None


def test_longest_prefix_match_prefers_specific_route(net):
    # 10.20.0.5 matches 10.20.0.0/16 and 0.0.0.0/0 -> the /16 wins
    assert net.lookup_route("10.20.0.5").next_hop == "fw-ot"
    assert net.lookup_route("8.8.8.8").next_hop == "null"


def test_firewall_first_match_and_default_deny(net):
    ok, reason = net.is_reachable("10.20.0.5", "10.21.0.11", "tcp", 502)
    assert ok and "SCADA-to-PLC-Modbus" in reason
    ok, reason = net.is_reachable("10.50.0.10", "10.21.0.11", "tcp", 3389)
    assert not ok and "Default-deny" in reason


def test_same_vlan_is_not_filtered(net):
    ok, reason = net.is_reachable("10.21.0.11", "10.21.0.12", "tcp", 23)
    assert ok and "same VLAN" in reason


def test_unrouted_destination_is_blackholed(net):
    ok, reason = net.is_reachable("10.10.10.21", "172.16.0.1", "tcp", 443)
    assert not ok and "no route" in reason


def test_route_without_firewall_is_reported(net):
    ok, reason = net.is_reachable("10.10.10.21", "10.60.0.51", "tcp", 1883)
    assert ok and "WITHOUT firewall" in reason
