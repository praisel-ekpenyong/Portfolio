# SOC Analyst L1 Portfolio

**Praisel Ekpenyong** · SOC Analyst L1

**Email:** [ekpenyongpraisel@gmail.com](mailto:ekpenyongpraisel@gmail.com)  
**LinkedIn:** [linkedin.com/in/praiselekpenyong](https://www.linkedin.com/in/praiselekpenyong)

**Certifications:** Google Cybersecurity Certificate · CompTIA Security+ · Microsoft SC-200 (Security Operations Analyst)

Hands-on security operations projects and incident triage logs from my home lab. Endpoint attack scenarios use **[Apache Caldera](https://caldera.apache.org/)** for adversary emulation. Identity and noise-alert scenarios use custom lab scripts and simulated log data.

> [!NOTE]
> **Timeline & Order:** The walk-through sequence recommended below is optimized for storytelling during interviews. The chronological incident IDs and the compressed shift timeline (which synthesizes multiple days into a single 8-hour shift narrative) are structured for pedagogical training and differ from the actual lab execution order.

> **Start walk-through here:** [INC-2026-005 — Phishing](incidents/INC-2026-005-phishing-chain.md) (analyzing stages: delivered → executed → contained)

### 10-Minute Hiring Manager Path
If you are short on time, follow this quick path to evaluate my technical skills and SOC workflows:
1. **The Anchor Case:** [INC-2026-005 — Phishing Chain](incidents/INC-2026-005-phishing-chain.md) shows my core email header analysis and staged containment.
2. **Prioritization & Fatigue Management:** [Simulated High-Volume Shift Triage](tickets/high-volume-shift-example.md) demonstrates how I prioritize alerts and tune out noise.
3. **Automated Tooling:** Check [parse_email.py](scripts/parse_email.py) for my scripting and automation capabilities.
4. **Validation:** Run the test suite (`python -m pytest tests/`) to verify all 61 passing test assertions.

## Lab Navigation Guide

1. The phishing case linked above walks through a full triage workflow — from user report through analysis, containment, and ticket closure.
2. Validate evidence from raw artifacts first: `artifacts/logs/`, `artifacts/caldera-operation-*.json`, `detections/`, and `tickets/sample-tickets.md`.
3. Indicators such as `203.0.113.0/24` are sanitized documentation IPs. Reputation conclusions in the case notes describe the lab scenario, not live lookup results for those reserved addresses.
4. Run `.\build.ps1` to regenerate `artifacts/enrichment_report.json` and Caldera timeline CSVs from the checked-in inputs.

---

## Core Cases & Incident Logs

| # | Case type | Incident | Key skill |
|---|-----------|----------|-----------|
| **1** | Phishing + endpoint correlation | [INC-2026-005](incidents/INC-2026-005-phishing-chain.md) | Headers, staged conclusions, mail scope |
| **2** | Password spray + cloud sign-in | [INC-2026-002](incidents/INC-2026-002-entra-password-spray.md) | Identity logs, post-auth checks |
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
| **Lab 1 — On-Prem** | Wazuh, Splunk, Sysmon, Active Directory (`corp.lab.local`), pfSense, Wireshark |
| **Lab 2 — Cloud** | Sentinel, Defender, Entra ID (`pe-soc-lab` tenant), Log Analytics, KQL (Kusto Query Language) |

### Skill-to-Evidence Map

| Domain | Evidence |
|--------|----------|
| Phishing / email | INC-2026-005, `phishing/`, `artifacts/phishing-invoice.eml`, `scripts/parse_email.py` |
| Identity / Entra | INC-2026-002, `detections/sentinel/password_spray_entra.kql` |
| Endpoint / LOLBin | INC-2026-001, Sysmon, Defender |
| Persistence | INC-2026-003, Task Scheduler + Wazuh custom rule, AD-wide persistence check |
| False positive / tuning | INC-2026-004, `artifacts/tuning/`, tuned KQL |
| Network / PCAP Forensics | INC-2026-006, `network/pcap-analysis-guide.md`, tshark filters |
| IOC enrichment | `scripts/ioc_enrichment.py`, `artifacts/enrichment_report.json` |
| Caldera emulation | `caldera/adversary-profiles.md`, `caldera/operations-runbook.md` |
| Ticketing | [`tickets/sample-tickets.md`](tickets/sample-tickets.md) · [`tickets/high-volume-shift-example.md`](tickets/high-volume-shift-example.md) |

---

## Lab Architecture

Two environments — on-prem endpoint SOC + Microsoft cloud SOC. Full topology: [`docs/lab-architecture.md`](docs/lab-architecture.md)

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

Generates IOC enrichment reports and Caldera timeline CSVs in `artifacts/`. All classification runs locally — no public API keys required, so the outputs are fully reproducible. The test suite covers regex patterns, API response mocks, data classification, and email parsing.

---

## Disclaimer

All offensive activity was performed in isolated lab environments with authorization. Note that the reuse of a single workstation (`WKSTN-042`) and user account (`jsmith`) across the emulations is an intentional lab design choice to facilitate consistent baseline comparisons and correlation tracking across different attack vectors.
