"""Asset inventory: load the CSV and validate it against the network model."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

import pandas as pd

from .network import Network

# Where each asset type belongs in the Purdue model (reference architecture for OT).
EXPECTED_LEVEL = {
    "PLC": 1, "DCS Controller": 1, "IoT Sensor": "IoT",
    "HMI": 2, "SCADA Server": 2,
    "Historian": 3, "Engineering Workstation": 3,
    "Historian Web": 3.5,
    "IT Workstation": 4,
}


@dataclass
class Finding:
    check: str
    severity: str  # Critical / High / Medium / Low
    asset: str
    detail: str
    standard: str  # IEC 62443 foundational requirement / NIST CSF category
    recommendation: str
    score: float = field(default=0.0)


def load_assets(path) -> pd.DataFrame:
    df = pd.read_csv(path, dtype=str).fillna("")
    df["vlan"] = df["vlan"].astype(int)
    df["criticality"] = df["criticality"].astype(int)
    df["open_ports"] = df["open_ports"].apply(lambda s: [int(p) for p in s.split(",") if p.strip()])
    return df


def validate_inventory(df: pd.DataFrame, net: Network) -> list[Finding]:
    findings: list[Finding] = []
    inv = "NIST CSF ID.AM (Asset Management)"

    for ip, group in df[df.duplicated("ip", keep=False)].groupby("ip"):
        findings.append(Finding("DUPLICATE_IP", "High", ", ".join(group.hostname), f"IP {ip} is used by {len(group)} assets",
                                inv, "Resolve the IP conflict; confirm which device is real."))

    for row in df.itertuples():
        try:
            ipaddress.ip_address(row.ip)
        except ValueError:
            findings.append(Finding("INVALID_IP", "Medium", row.hostname, f"'{row.ip}' is not a valid IPv4 address", inv, "Fix the record."))
            continue

        vlan = net.vlans.get(row.vlan)
        if vlan is None or ipaddress.ip_address(row.ip) not in vlan.subnet:
            findings.append(Finding("IP_NOT_IN_VLAN_SUBNET", "Medium", row.hostname,
                                    f"{row.ip} is outside VLAN {row.vlan} subnet {vlan.subnet if vlan else '?'}",
                                    inv, "Correct the inventory or re-address the device."))

        expected = EXPECTED_LEVEL.get(row.asset_type)
        if vlan is not None and expected is not None:
            wrong = (vlan.zone != "IoT") if expected == "IoT" else (vlan.purdue_level != expected)
            if wrong:
                findings.append(Finding("WRONG_ZONE", "High", row.hostname,
                                        f"{row.asset_type} sits in VLAN {vlan.id} '{vlan.name}' (level {vlan.purdue_level}), expected level {expected}",
                                        "IEC 62443 FR5 Restricted Data Flow (zones & conduits)",
                                        "Move the device to the correct VLAN/zone."))

        # Embedded OT devices are tracked by firmware; Windows hosts are tracked by OS patch level instead.
        needs_firmware = "Windows" not in row.os
        missing = [c for c in ("firmware", "owner") if not getattr(row, c) and (c != "firmware" or needs_firmware)]
        if missing:
            findings.append(Finding("INCOMPLETE_RECORD", "Low", row.hostname, f"missing: {', '.join(missing)}", inv,
                                    "Complete the record: every asset needs a responsible owner and a known firmware "
                                    "version, otherwise it cannot be vulnerability-checked or escalated."))
    return findings
