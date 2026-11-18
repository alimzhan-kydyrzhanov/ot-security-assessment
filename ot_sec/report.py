"""Stakeholder report in Markdown: executive summary, zone map, prioritized findings."""
from __future__ import annotations

from collections import Counter

import pandas as pd

from .inventory import Finding
from .network import Network


# Threat scenario behind each check: answers "what could an attacker actually do?"
THREATS = {
    "IT_TO_CONTROL_DIRECT": "Ransomware or an attacker on an office PC pivots straight into the control network",
    "ROUTE_BYPASSES_FIREWALL": "Malicious traffic reaches OT devices without inspection or logging",
    "OVERLY_PERMISSIVE_RULE": "Any compromised host can reach SCADA/HMI services",
    "INSECURE_PROTOCOL_CROSS_ZONE": "Unauthenticated commands or credential sniffing across zones",
    "CLEARTEXT_SERVICE": "Credential theft and remote login to the controller",
    "VULNERABLE_FIRMWARE": "Exploitation of a known vulnerability; process stop or manipulation",
    "WRONG_ZONE": "Weak device gives an attacker a foothold next to critical controllers",
    "DUPLICATE_IP": "Spoofed or rogue device hidden behind an IP conflict",
    "IP_NOT_IN_VLAN_SUBNET": "Inventory does not match reality; blind spots in monitoring",
    "INCOMPLETE_RECORD": "Unowned or unpatched asset is missed during incident response",
    "INVALID_IP": "Inventory does not match reality; blind spots in monitoring",
}


def zone_map(df: pd.DataFrame, net: Network) -> str:
    lines = []
    for v in sorted(net.vlans.values(), key=lambda v: -v.purdue_level):
        hosts = ", ".join(df[df.vlan == v.id].hostname) or "-"
        lines.append(f"L{v.purdue_level:<4} VLAN {v.id:<3} {v.subnet!s:<15} {v.zone:<11} | {hosts}")
    return "\n".join(lines)


def render(df: pd.DataFrame, net: Network, findings: list[Finding]) -> str:
    sev = Counter(f.severity for f in findings)
    out = [
        f"# OT Security Assessment - {net.site}",
        "",
        "## Executive summary",
        f"- Assets reviewed: {len(df)} across {len(net.vlans)} VLANs; firewall rules reviewed: {len(net.rules)}",
        f"- Findings: {len(findings)} (Critical {sev['Critical']}, High {sev['High']}, Medium {sev['Medium']}, Low {sev['Low']})",
        "- Top priority: close direct paths from Enterprise IT to the control network and patch vulnerable PLC firmware.",
        "",
        "## Zone map (Purdue model)",
        "```",
        zone_map(df, net),
        "```",
        "",
        "## Findings (prioritized)",
        "| # | Severity | Check | Asset / rule | Detail | Threat scenario | Standard | Recommendation |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for i, f in enumerate(findings, 1):
        threat = THREATS.get(f.check, "-")
        out.append(f"| {i} | {f.severity} | {f.check} | {f.asset} | {f.detail} | {threat} | {f.standard} | {f.recommendation} |")
    return "\n".join(out) + "\n"
