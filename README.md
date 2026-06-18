# SOC Analyst L1 Portfolio — Praisel Ekpenyong

**Certifications:** CompTIA Security+ · Microsoft SC-200 · Google Cybersecurity Certificate  
**Contact:** [ekpenyongpraisel@gmail.com](mailto:ekpenyongpraisel@gmail.com) · [LinkedIn](https://www.linkedin.com/in/praiselekpenyong) · [GitHub](https://github.com/praisel-ekpenyong/Portfolio)

Five Tier 1 case types, two lab environments (on-prem + Microsoft cloud), validated with Apache Caldera.

---

## Start Here

> 👉 **[INC-2026-005 — Phishing](incidents/INC-2026-005-phishing-chain.md)** — the anchor case. Shows the full Tier 1 workflow: user report → header analysis → endpoint correlation → containment → closure.

---

## The Five Cases

| # | Type | Incident | Key skill |
|---|------|----------|-----------|
| 1 | Phishing + endpoint | [INC-2026-005](incidents/INC-2026-005-phishing-chain.md) | Staged conclusions, mail scope |
| 2 | Password spray | [INC-2026-002](incidents/INC-2026-002-entra-password-spray.md) | Identity logs, post-auth checks |
| 3 | LOLBin execution | [INC-2026-001](incidents/INC-2026-001-bits-job-download.md) | Process tree, benign vs malicious |
| 4 | Scheduled task persistence | [INC-2026-003](incidents/INC-2026-003-scheduled-task-persistence.md) | Baseline comparison, task XML |
| 5 | False positive + tuning | [INC-2026-004](incidents/INC-2026-004-false-positive-vpn.md) | Safe closure, before/after rule |

---

## Labs

| | Lab 1 — On-Prem | Lab 2 — Cloud |
|-|-----------------|---------------|
| **Tools** | Wazuh, Splunk, Sysmon, pfSense, AD | Sentinel, Defender, Entra ID, KQL |
| **Domain** | `corp.lab.local` | `pe-soc-lab` tenant |
| **Full topology** | [`docs/lab-architecture.md`](docs/lab-architecture.md) | ← same doc |

---

## What's in the Repo

| Folder | Contents |
|--------|----------|
| `incidents/` | Five incident reports (the core portfolio) |
| `detections/` | Wazuh rules, Splunk SPL, Sentinel KQL (original + tuned) |
| `artifacts/` | `.eml`, Caldera operation JSON, enrichment report, screenshots |
| `tickets/` | osTicket records for all five cases + shift handoff |
| `phishing/` | Email header walkthrough |
| `scripts/` | IOC enrichment (Python) + triage alert (PowerShell) |
| `docs/` | Lab architecture, resume bullets, playbooks |
| `caldera/` | Adversary profiles + operations runbook |
| `network/` | Supplemental RDP/PCAP and DNS exfil drills |

---

## 15-Minute Interview Walkthrough

1. **INC-2026-005** (5 min) — staged conclusions table; `.eml` + Defender process tree
2. **INC-2026-002 vs INC-2026-004** (3 min) — same T1110 family: true positive vs false positive
3. **INC-2026-001** (3 min) — LOLBin with benign SCCM comparator
4. **INC-2026-003** (2 min) — scheduled task baseline comparison
5. **INC-2026-004 tuning** (2 min) — before/after KQL rule + logtest results

Resume bullets: [`docs/resume-highlights.md`](docs/resume-highlights.md)

---

## Notes for Reviewers

- IPs like `203.0.113.x` are sanitized documentation addresses — reputation conclusions describe the lab scenario, not live lookups.
- `WKSTN-042` and `jsmith` appear across all cases intentionally — consistent baseline for cross-case correlation.
- Run `.\build.ps1` to regenerate `artifacts/enrichment_report.json` and Caldera timeline CSVs locally.
- All offensive activity was performed in isolated lab environments with authorization.
