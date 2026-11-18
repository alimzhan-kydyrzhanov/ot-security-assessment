"""CLI: python -m ot_sec --data data --out reports"""
from __future__ import annotations

import argparse
import csv
from dataclasses import asdict
from pathlib import Path

from . import checks, inventory, report, vulns
from .network import Network


def run(data_dir: Path, out_dir: Path) -> list[inventory.Finding]:
    net = Network.from_json(data_dir / "network.json")
    df = inventory.load_assets(data_dir / "assets.csv")
    findings = (inventory.validate_inventory(df, net) + checks.run_all(df, net)
                + vulns.match_advisories(df, data_dir / "advisories.json", net))
    findings = vulns.prioritize(findings)

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "assessment_report.md").write_text(report.render(df, net, findings), encoding="utf-8")
    with open(out_dir / "findings.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(asdict(findings[0]).keys()) if findings else ["check"])
        w.writeheader()
        w.writerows(asdict(f) for f in findings)
    return findings


def main() -> None:
    ap = argparse.ArgumentParser(description="OT network security assessment (synthetic data)")
    ap.add_argument("--data", type=Path, default=Path("data"))
    ap.add_argument("--out", type=Path, default=Path("reports"))
    args = ap.parse_args()
    findings = run(args.data, args.out)
    print(f"{len(findings)} findings -> {args.out / 'assessment_report.md'}")
    for f in findings[:5]:
        print(f"  [{f.severity}] {f.check}: {f.asset}")


if __name__ == "__main__":
    main()
