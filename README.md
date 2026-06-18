# SOC Analyst L1 Portfolio

**Praisel Ekpenyong** · SOC Analyst L1

| | |
|---|---|
| **Email** | [ekpenyongpraisel@gmail.com](mailto:ekpenyongpraisel@gmail.com) |
| **GitHub** | [github.com/praisel-ekpenyong/Portfolio](https://github.com/praisel-ekpenyong/Portfolio) |
| **LinkedIn** | [linkedin.com/in/praiselekpenyong](https://www.linkedin.com/in/praiselekpenyong) |

**Certifications:** Google Cybersecurity Certificate · CompTIA Security+ · Microsoft SC-200 (Security Operations Analyst)

Entry-level security operations portfolio structured around **five Tier 1 case types** hiring managers expect. Endpoint scenarios use **[Apache Caldera](https://caldera.apache.org/)**; identity and noise cases use lab scripts or organic telemetry.

> **Start interviews here:** [INC-2026-005 — Phishing](incidents/INC-2026-005-phishing-chain.md) (staged conclusions: delivered → executed → contained)

## Reviewer Guide

1. Start with [INC-2026-005 - Phishing](incidents/INC-2026-005-phishing-chain.md) to see the full Tier 1 workflow: user report, header review, endpoint correlation, containment, and closure.
2. Validate evidence from raw artifacts first: `artifacts/logs/`, `artifacts/caldera-operation-*.json`, `detections/`, and `tickets/sample-tickets.md`.
3. Indicators such as `203.0.113.0/24` are sanitized documentation IPs. Reputation conclusions in the case notes describe the lab scenario, not live lookup results for those reserved addresses.
4. Run `.\build.ps1` to regenerate `artifacts/enrichment_report.json` and Caldera timeline CSVs from the checked-in inputs.

## Build Artifacts

```powershell
.\build.ps1
```

Generates IOC enrichment and Caldera timeline CSV files in `artifacts/`. The build performs local classification for private lab IPs, internal lab domains, and sanitized documentation IPs so the sample artifacts are reproducible without public API access.

---

## Core Cases (Interview Order)

| # | Case type | Incident | Key skill |
|---|-----------|----------|-----------|
| **1** | Phishing + endpoint correlation | [INC-2026-005](incidents/INC-2026-005-phishing-chain.md) | Headers, staged conclusions, mail scope |
| **2** | Password spray + cloud sign-in | [INC-2026-002](incidents/INC-2026-002-entra-password-spray.md) | Identity logs, post-auth checks |
| **3** | LOLBin / endpoint execution | [INC-2026-001](incidents/INC-2026-001-bits-job-download.md) | Process tree, benign vs malicious |
| **4** | Scheduled-task persistence | [INC-2026-003](incidents/INC-2026-003-scheduled-task-persistence.md) | Baseline comparison, task XML |
| **5** | False positive + tuning | [INC-2026-004](incidents/INC-2026-004-false-positive-vpn.md) | Close safely, before/after rules |

### Supplemental modules (not core five)

| Module | Location |
|--------|----------|
| RDP / PCAP lateral (stretch) | [`network/supplemental-rdp-lateral-case.md`](network/supplemental-rdp-lateral-case.md) |
| DNS exfil drill | [`network/sample-dns-exfil-analysis.md`](network/sample-dns-exfil-analysis.md) |

---

## Skills Demonstrated

| Lab | What I Operate |
|-----|----------------|
| **Lab 1 — On-Prem** | Wazuh, Splunk, Sysmon, AD (`corp.lab.local`), pfSense, Wireshark |
| **Lab 2 — Cloud** | Sentinel, Defender, Entra ID (`pe-soc-lab` tenant), Log Analytics, KQL |

| Domain | Evidence |
|--------|----------|
| Phishing / email | INC-2026-005, `phishing/`, `artifacts/phishing-invoice.eml` |
| Identity / Entra | INC-2026-002, `detections/sentinel/password_spray_entra.kql` |
| Endpoint / LOLBin | INC-2026-001, Sysmon, Defender |
| Persistence | INC-2026-003, Task Scheduler + Wazuh 180002, domain-scope check |
| False positive / tuning | INC-2026-004, `artifacts/tuning/`, tuned KQL |
| IOC enrichment | `scripts/ioc_enrichment.py`, `artifacts/enrichment_report.json` |
| Caldera emulation | `caldera/adversary-profiles.md`, `caldera/operations-runbook.md` |
| Ticketing | `tickets/sample-tickets.md` |

---

## Lab Architecture

Two environments — on-prem endpoint SOC + Microsoft cloud SOC. Full topology: [`docs/lab-architecture.md`](docs/lab-architecture.md)

---

## Detections

Detection content is written for lab validation and interview discussion. Production deployment would require environment-specific baselining, allowlists, and change-management integration.

| Platform | Location |
|----------|----------|
| Wazuh | `detections/wazuh/local_rules.xml` |
| Splunk | `detections/splunk/` |
| Sentinel | `detections/sentinel/` (includes original + tuned VPN rules) |

---

## Scripts

```powershell
python scripts/ioc_enrichment.py --input scripts/sample_iocs.txt --output artifacts/enrichment_report.json
.\scripts\triage_alert.ps1 -Hostname WKSTN-042 -AlertId 48291
```

---

## Disclaimer

All offensive activity was performed in isolated lab environments with authorization. Note that the reuse of a single workstation (`WKSTN-042`) and user account (`jsmith`) across the emulations is an intentional lab design choice to facilitate consistent baseline comparisons and correlation tracking across different attack vectors.
