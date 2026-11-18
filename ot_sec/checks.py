"""Network security architecture checks: segmentation, insecure protocols, risky rules."""
from __future__ import annotations

import pandas as pd

from .inventory import Finding
from .network import Network

# Cleartext / unauthenticated protocols that are risky when they cross a zone boundary.
INSECURE_PORTS = {21: "FTP", 23: "Telnet", 80: "HTTP", 502: "Modbus/TCP", 102: "S7comm", 5900: "VNC"}
FR5 = "IEC 62443 FR5 Restricted Data Flow"
FR1 = "IEC 62443 FR1 Identification & Authentication"


def check_it_to_control_paths(df: pd.DataFrame, net: Network) -> list[Finding]:
    """Purdue rule: Enterprise IT (level 4) must never reach control (level <= 2) directly; only via the DMZ."""
    findings = []
    it_hosts = df[df.vlan.map(lambda v: net.vlans[v].purdue_level == 4)]
    targets = df[df.vlan.map(lambda v: net.vlans[v].purdue_level <= 2)]
    for t in targets.itertuples():
        paths = []
        for src in it_hosts.itertuples():
            for port in t.open_ports:
                ok, reason = net.is_reachable(src.ip, t.ip, "tcp", port)
                if ok:
                    paths.append(f"{src.ip}->{t.ip}:{port} ({reason})")
        if paths:
            findings.append(Finding("IT_TO_CONTROL_DIRECT", "Critical", t.hostname,
                                    f"{len(paths)} direct path(s) from Enterprise IT: " + "; ".join(paths),
                                    FR5, "Remove the rule/route; force IT access through the OT DMZ (jump host)."))
    return findings


def check_routes_bypass_firewall(net: Network) -> list[Finding]:
    findings = []
    for v in net.vlans.values():
        route = net.lookup_route(str(v.subnet.network_address + 1))
        if v.purdue_level <= 3.5 and route and route.next_hop != "null" and not route.via_firewall:
            findings.append(Finding("ROUTE_BYPASSES_FIREWALL", "High", f"VLAN {v.id} {v.name}",
                                    f"route {route.destination} -> {route.next_hop} is not inspected by the OT firewall",
                                    FR5, "Route this subnet through the OT firewall."))
    return findings


def check_firewall_rules(net: Network) -> list[Finding]:
    findings = []
    for r in net.rules:
        if r.action != "allow":
            continue
        if r.src == "any" or r.dst == "any" or r.port == "any":
            findings.append(Finding("OVERLY_PERMISSIVE_RULE", "High", r.name,
                                    f"allow {r.src} -> {r.dst} proto={r.proto} port={r.port}",
                                    FR5, "Replace with least-privilege rule (exact source, destination, port)."))
        if r.port in INSECURE_PORTS and r.src != "any":
            src_v, dst_v = net.vlan_of_ip(r.src.split("/")[0]), net.vlan_of_ip(r.dst.split("/")[0])
            if src_v and dst_v and src_v.zone != dst_v.zone:
                findings.append(Finding("INSECURE_PROTOCOL_CROSS_ZONE", "High", r.name,
                                        f"{INSECURE_PORTS[r.port]} allowed from {src_v.zone} to {dst_v.zone}",
                                        FR1, "Use a secure protocol (SSH, OPC UA with security) or a protocol-aware gateway."))
    return findings


def check_exposed_services(df: pd.DataFrame) -> list[Finding]:
    findings = []
    for row in df.itertuples():
        for p in row.open_ports:
            if p in (21, 23):
                findings.append(Finding("CLEARTEXT_SERVICE", "Medium", row.hostname,
                                        f"{INSECURE_PORTS[p]} (port {p}) is open", FR1,
                                        "Disable the service if not needed (system hardening)."))
    return findings


def run_all(df: pd.DataFrame, net: Network) -> list[Finding]:
    return (check_it_to_control_paths(df, net) + check_routes_bypass_firewall(net)
            + check_firewall_rules(net) + check_exposed_services(df))
