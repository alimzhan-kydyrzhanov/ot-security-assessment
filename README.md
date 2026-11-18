# OT Security Assessment Toolkit

A small Python tool that performs an **Operational Technology (OT) security assessment** of a (fictional) pharmaceutical manufacturing site. All data is **synthetic**: the site, devices and the `SYN-ADV-*` advisories are made up.

It reads an **asset inventory**, a **network architecture** (VLANs, subnets, routing table, firewall rules) and **vulnerability advisories**, then produces a prioritized findings report for stakeholders.

## What it checks

| Area | Check | Standard reference |
|---|---|---|
| Asset inventory | duplicate IPs, IP outside its VLAN subnet, device in the wrong Purdue zone, missing owner/firmware | NIST CSF ID.AM, IEC 62443 FR5 |
| Network segmentation | direct paths from Enterprise IT (Purdue level 4) to the control network (levels 1-2) that bypass the OT DMZ | IEC 62443 FR5 |
| Routing | subnets routed around the OT firewall (longest prefix match) | IEC 62443 FR5 |
| Firewall rules | any/any rules, cleartext protocols (Modbus/TCP, Telnet, FTP) crossing zones | IEC 62443 FR1, FR5 |
| System hardening | open cleartext services on PLCs/DCS | IEC 62443 FR1 |
| Vulnerability management | firmware older than the fixed version; risk = CVSS x criticality x exposure | IEC 62443 FR3 |

## Run

```bash
pip install -r requirements.txt
python -m ot_sec --data data --out reports   # writes reports/assessment_report.md and findings.csv
pytest -q                                    # 13 unit + integration tests
```

Docker (Linux container, non-root user):

```bash
docker build -t ot-sec .
docker run --rm -v "$PWD/reports:/app/reports" ot-sec
```

CI: GitHub Actions runs the tests and uploads the report as a build artifact.

## Layout

```
data/            network.json (VLANs, routes, firewall rules), assets.csv, advisories.json
ot_sec/network.py    IP/subnet model, routing (longest prefix match), firewall first-match evaluation
ot_sec/inventory.py  asset inventory loading + validation against the network
ot_sec/checks.py     segmentation, routing, firewall rule and hardening checks
ot_sec/vulns.py      advisory matching, version comparison, risk prioritization
ot_sec/report.py     Markdown report: executive summary, Purdue zone map, findings table with threat scenarios
tests/               pytest
```
