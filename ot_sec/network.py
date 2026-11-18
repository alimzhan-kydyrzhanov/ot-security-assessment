"""Network model: VLANs/subnets, routing (longest prefix match) and firewall rules.

Uses only the standard `ipaddress` module, so every IP/subnet decision is explicit.
"""
from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Vlan:
    id: int
    name: str
    subnet: ipaddress.IPv4Network
    purdue_level: float
    zone: str


@dataclass(frozen=True)
class Route:
    destination: ipaddress.IPv4Network
    next_hop: str
    via_firewall: bool


@dataclass(frozen=True)
class FirewallRule:
    name: str
    src: str
    dst: str
    proto: str
    port: str | int
    action: str

    def matches(self, src_ip, dst_ip, proto: str, port: int) -> bool:
        return (
            _in(src_ip, self.src)
            and _in(dst_ip, self.dst)
            and self.proto in ("any", proto)
            and self.port in ("any", port)
        )


def _in(ip, cidr: str) -> bool:
    return cidr == "any" or ipaddress.ip_address(ip) in ipaddress.ip_network(cidr)


class Network:
    def __init__(self, site: str, vlans: list[Vlan], routes: list[Route], rules: list[FirewallRule]):
        self.site = site
        self.vlans = {v.id: v for v in vlans}
        self.routes = routes
        self.rules = rules

    @classmethod
    def from_json(cls, path: str | Path) -> "Network":
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        vlans = [Vlan(v["id"], v["name"], ipaddress.ip_network(v["subnet"]), v["purdue_level"], v["zone"]) for v in raw["vlans"]]
        routes = [Route(ipaddress.ip_network(r["destination"]), r["next_hop"], r["via_firewall"]) for r in raw["routes"]]
        rules = [FirewallRule(**r) for r in raw["firewall_rules"]]
        return cls(raw["site"], vlans, routes, rules)

    def vlan_of_ip(self, ip: str) -> Vlan | None:
        addr = ipaddress.ip_address(ip)
        return next((v for v in self.vlans.values() if addr in v.subnet), None)

    def lookup_route(self, dst_ip: str) -> Route | None:
        """Longest prefix match, exactly like a router's forwarding table."""
        addr = ipaddress.ip_address(dst_ip)
        candidates = [r for r in self.routes if addr in r.destination]
        return max(candidates, key=lambda r: r.destination.prefixlen, default=None)

    def first_matching_rule(self, src_ip, dst_ip, proto, port) -> FirewallRule | None:
        return next((r for r in self.rules if r.matches(src_ip, dst_ip, proto, port)), None)

    def is_reachable(self, src_ip: str, dst_ip: str, proto: str, port: int) -> tuple[bool, str]:
        """Can a packet src->dst:port get through? Returns (allowed, reason)."""
        if self.vlan_of_ip(src_ip) == self.vlan_of_ip(dst_ip):
            return True, "same VLAN (layer 2, no routing or firewall)"
        route = self.lookup_route(dst_ip)
        if route is None or route.next_hop == "null":
            return False, "no route (blackholed)"
        if not route.via_firewall:
            return True, f"routed via {route.next_hop} WITHOUT firewall inspection"
        rule = self.first_matching_rule(src_ip, dst_ip, proto, port)
        if rule is None or rule.action == "deny":
            return False, f"denied by {rule.name if rule else 'implicit deny'}"
        return True, f"allowed by rule '{rule.name}'"
