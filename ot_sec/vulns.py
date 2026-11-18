"""Vulnerability management: match assets to advisories and prioritize by risk."""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from .inventory import Finding
from .network import Network

SEVERITY_WEIGHT = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}


def version_tuple(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in v.split("."))


def match_advisories(df: pd.DataFrame, advisories_path, net: Network) -> list[Finding]:
    advisories = json.loads(Path(advisories_path).read_text(encoding="utf-8"))
    findings = []
    for row in df.itertuples():
        if not row.firmware:
            continue  # reported by the inventory check instead
        for adv in advisories:
            if (adv["vendor"], adv["model"]) == (row.vendor, row.model) and version_tuple(row.firmware) < version_tuple(adv["fixed_in"]):
                level = net.vlans[row.vlan].purdue_level
                exposure = 1.5 if level <= 2 else 1.0  # control-level devices hit the physical process
                risk = round(adv["cvss"] * row.criticality / 5 * exposure, 1)
                sev = "Critical" if risk >= 9 else "High" if risk >= 7 else "Medium" if risk >= 4 else "Low"
                findings.append(Finding("VULNERABLE_FIRMWARE", sev, row.hostname,
                                        f"{adv['id']} {adv['title']}: firmware {row.firmware} < {adv['fixed_in']} (CVSS {adv['cvss']})",
                                        "IEC 62443 FR3 System Integrity / patch management",
                                        f"Plan update to {adv['fixed_in']} in a maintenance window; until then restrict access.",
                                        score=risk))
    return findings


def prioritize(findings: list[Finding]) -> list[Finding]:
    for f in findings:
        if not f.score:
            f.score = SEVERITY_WEIGHT[f.severity] * 2.5
    return sorted(findings, key=lambda f: (-SEVERITY_WEIGHT[f.severity], -f.score))
