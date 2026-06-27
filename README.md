# SOC Analyst L1 Portfolio

**Praisel Ekpenyong** · SOC Analyst L1

**Email:** [ekpenyongpraisel@gmail.com](mailto:ekpenyongpraisel@gmail.com)  
**LinkedIn:** [linkedin.com/in/praiselekpenyong](https://www.linkedin.com/in/praiselekpenyong)

**Education:** Bachelor of Science in Cybersecurity

**Certifications:** Google Cybersecurity Certificate · CompTIA Security+ · Microsoft SC-200 (Security Operations Analyst)

Hands-on security operations projects and incident triage logs from my **live home lab**. Endpoint cases use **[Apache Caldera](https://caldera.apache.org/)** adversary emulation on real agents. Identity and VPN cases use **live** Entra authentication attempts and **live** pfSense OpenVPN failures forwarded into Sentinel — not log replay or mock SIEM data.

> [!NOTE]
> **Live evidence:** Each `INC-2026-00X` report is backed by artifacts exported at run time. See [`docs/live-evidence-ledger.md`](docs/live-evidence-ledger.md) for operation windows, alert sources, and file paths.

> [!NOTE]
> **Timeline & Order:** The walk-through sequence below is optimized for interviews. Incident IDs follow execution dates (June 13–18). The [shift prioritization exercise](tickets/high-volume-shift-example.md) is a separate narrative — it does not replace per-incident evidence.

> **Start walk-through here:** [INC-2026-005 — Phishing](incidents/INC-2026-005-phishing-chain.md) (analyzing stages: delivered → executed → contained)

### 10-Minute Hiring Manager Path
If you are short on time, follow this quick path to evaluate my technical skills and SOC workflows:
1. **The Anchor Case:** [INC-2026-005 — Phishing Chain](incidents/INC-2026-005-phishing-chain.md) shows my core email header analysis and staged containment.
2. **Prioritization & Fatigue Management:** [High-Volume Shift Triage (prioritization exercise)](tickets/high-volume-shift-example.md) demonstrates how I prioritize alerts and tune out noise.
3. **Automated Tooling:** Check [parse_email.py](scripts/parse_email.py) for my scripting and automation capabilities.
4. **Validation:** Run the test suite (`python -m pytest tests/`) to verify all 61 passing test assertions.

## Lab Navigation Guide

1. The phishing case linked above walks through a full triage workflow — from user report through analysis, containment, and ticket closure.
2. Validate evidence from raw artifacts first: [`docs/live-evidence-ledger.md`](docs/live-evidence-ledger.md), `artifacts/logs/`, `artifacts/caldera-operation-*.json`, `detections/`, and `tickets/sample-tickets.md`.
3. Indicators such as `203.0.113.0/24` are sanitized documentation IPs. Reputation conclusions in the case notes describe the lab scenario, not live lookup results for those reserved addresses.
4. Run `.\build.ps1` to regenerate `artifacts/enrichment_report.json` and Caldera timeline CSVs from the checked-in inputs.

---

## Core Cases & Incident Logs

| # | Case type | Incident | Key skill |
|---|-----------|----------|-----------|
| **1** | Phishing + endpoint correlation | [INC-2026-005](incidents/INC-2026-005-phishing-chain.md) | Headers, staged conclusions, mail scope |
| **2** | Password spray + Azure/Entra ID sign-in | [INC-2026-002](incidents/INC-2026-002-entra-password-spray.md) | Identity logs, post-auth checks |
| **3** | LOLBin (living-off-the-land binary) | [INC-2026-001](incidents/INC-2026-001-bits-job-download.md) | Process tree, benign vs malicious |
| **4** | Scheduled-task persistence | [INC-2026-003](incidents/INC-2026-003-scheduled-task-persistence.md) | Baseline comparison, task XML |
| **5** | False positive + tuning | [INC-2026-004](incidents/INC-2026-004-false-positive-vpn.md) | Close safely, before/after rules |
| **6** | RDP Lateral + Network Sniffing | [INC-2026-006](incidents/INC-2026-006-rdp-lateral-movement.md) | Wireshark/tshark PCAP forensics, RDP port baselines |

### Supplemental Network Modules

| Module | Location | Key skill |
|--------|----------|-----------|
| DNS exfiltration analysis | [`network/sample-dns-exfil-analysis.md`](network/sample-dns-exfil-analysis.md) | DNS packet decoding, subdomain length entropy, Splunk SPL tuning |

---

## Skills Demonstrated

### Lab Environments

| Lab | What I Operate |
|-----|----------------|
| **Lab 1 — On-Prem** | Wazuh (HIDS), Suricata (NIDS), Splunk (SIEM), Sysmon, Active Directory (`corp.lab.local`), pfSense Firewall, Wireshark |
| **Lab 2 — Microsoft Azure** | Microsoft Sentinel (SIEM), Microsoft Defender for Endpoint (EDR), Entra ID (`pe-soc-lab` tenant), Log Analytics, KQL (Kusto Query Language) |

### Skill-to-Evidence Map

| Domain | Evidence |
|--------|----------|
| Phishing / email | INC-2026-005, `phishing/`, `artifacts/phishing-invoice.eml`, `scripts/parse_email.py` |
| Identity / Entra | INC-2026-002, `detections/sentinel/password_spray_entra.kql` |
| Endpoint / LOLBin | INC-2026-001, Sysmon, Microsoft Defender for Endpoint (EDR), Windows Event Logs |
| Persistence | INC-2026-003, Task Scheduler + Wazuh custom rule, AD-wide persistence check |
| False positive / tuning | INC-2026-004, `artifacts/tuning/`, tuned KQL |
| Network / PCAP Forensics | INC-2026-006, `network/pcap-analysis-guide.md`, tshark filters |
| IOC enrichment | `scripts/ioc_enrichment.py`, `artifacts/enrichment_report.json` |
| Caldera emulation | `caldera/adversary-profiles.md`, `caldera/operations-runbook.md` |
| Ticketing | [`tickets/sample-tickets.md`](tickets/sample-tickets.md) · [`tickets/high-volume-shift-example.md`](tickets/high-volume-shift-example.md) |

---

## Lab Architecture

Two environments — on-prem endpoint SOC + Microsoft Azure SOC. Full topology: [`docs/lab-architecture.md`](docs/lab-architecture.md)

**Run live attack simulations:** [`docs/attack-simulations/`](docs/attack-simulations/) — per-case step-by-step guides (index: [`README.md`](docs/attack-simulations/README.md))

---

## Detections

Detection content is written for lab validation and operational review. Production deployment would require environment-specific baselining, allowlists, and change-management integration.

| Platform | Location |
|----------|----------|
| Wazuh | `detections/wazuh/local_rules.xml` |
| Splunk | `detections/splunk/` |
| Sentinel | `detections/sentinel/` (includes original + tuned VPN rules) |

---

## Scripts

Utility scripts for alert triage, IOC enrichment, and email analysis:

```powershell
python scripts/ioc_enrichment.py --input scripts/sample_iocs.txt --output artifacts/enrichment_report.json
python scripts/parse_email.py --input artifacts/phishing-invoice.eml --output artifacts/phishing_analysis.md
.\scripts\triage_alert.ps1 -Hostname WKSTN-042 -AlertId 48291
```

---

## Build & Validation Tests

```powershell
# Run the build script to generate reports and timelines
.\build.ps1

# Run the test suite to validate all SecOps scripting utilities
python -m pytest tests/
```

Regenerates IOC enrichment reports and Caldera timeline CSVs from **checked-in live-run exports** in `artifacts/`. IOC classification runs locally (no API keys required for lab/reserved IPs). The test suite uses **mocks for unit tests only** — incident evidence comes from live runs documented in the ledger.

---

## Disclaimer

All offensive activity was performed in isolated lab environments with authorization. Incident write-ups reflect **live emulations** with SIEM/EDR alerts generated from real activity. The reuse of a single workstation (`WKSTN-042`) and user account (`jsmith`) across cases is an intentional lab design choice for baseline comparison and correlation practice.
