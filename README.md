# SOC Analyst L1 Portfolio

**Praisel Ekpenyong** · SOC Analyst L1

| | |
|---|---|
| **Email** | [Ekpenyongpraisel@gmail.com](mailto:Ekpenyongpraisel@gmail.com) |
| **GitHub** | [github.com/praisel-ekpenyong/Portfolio](https://github.com/praisel-ekpenyong/Portfolio) |
| **LinkedIn** | [linkedin.com/in/praiselekpenyong](https://www.linkedin.com/in/praiselekpenyong) |

**Certifications:** Google Cybersecurity Certificate · CompTIA Security+ · Microsoft SC-200 (Security Operations Analyst)

Entry-level security operations portfolio structured around **five Tier 1 case types** hiring managers expect. Endpoint scenarios use **[Apache Caldera](https://caldera.apache.org/)**; identity and noise cases use lab scripts or organic telemetry.

> **Start interviews here:** [INC-2026-005 — Phishing](incidents/INC-2026-005-phishing-chain.md) (staged conclusions: delivered → executed → contained)

## Build Artifacts

```powershell
.\build.ps1
```

Generates IOC enrichment and Caldera timeline CSV in `artifacts/`.

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
| Phishing / email | INC-005, `phishing/`, `artifacts/phishing-invoice.eml` |
| Identity / Entra | INC-002, `detections/sentinel/password_spray_entra.kql` |
| Endpoint / LOLBin | INC-001, Sysmon, Defender |
| Persistence | INC-003, Task Scheduler + Wazuh 180002 |
| False positive / tuning | INC-004, `artifacts/tuning/`, tuned KQL |
| IOC enrichment | `scripts/ioc_enrichment.py` |
| Ticketing | `tickets/sample-tickets.md` |

---

## Lab Architecture

Two environments — on-prem endpoint SOC + Microsoft cloud SOC. Full topology: [`docs/lab-architecture.md`](docs/lab-architecture.md)

---

## Detections

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

## Interview Walkthrough (15 min)

1. **INC-005** (5 min) — staged conclusions table; show `.eml` + Defender process tree
2. **INC-002 vs INC-004** (3 min) — same T1110 family: TP vs FP
3. **INC-001** (3 min) — LOLBin with benign SCCM comparator
4. **INC-003** (2 min) — scheduled task baseline
5. **INC-004 tuning** (2 min) — before/after rule + logtest

Resume bullets: [`docs/resume-highlights.md`](docs/resume-highlights.md)

---

## Disclaimer

All offensive activity was performed in isolated lab environments with authorization.