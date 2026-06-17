# SOC Analyst L1 Portfolio

**Praisel Ekpenyong** · SOC Analyst L1

| | |
|---|---|
| **Email** | [Ekpenyongpraisel@gmail.com](mailto:Ekpenyongpraisel@gmail.com) |
| **GitHub** | [github.com/praisel-ekpenyong/Portfolio](https://github.com/praisel-ekpenyong/Portfolio) |
| **LinkedIn** | [linkedin.com/in/praiselekpenyong](https://www.linkedin.com/in/praiselekpenyong) |

**Certifications:** Google Cybersecurity Certificate · CompTIA Security+ · Microsoft SC-200 (Security Operations Analyst)

Entry-level security operations portfolio demonstrating alert triage, incident investigation, documentation, and detection engineering across **two operational labs** — on-premises endpoint SOC and Microsoft cloud SOC. Endpoint attack paths are validated with **[Apache Caldera](https://caldera.apache.org/)**; identity and noise scenarios use **lab scripts or organic telemetry** (INC-2026-002, INC-2026-004).

> **Highlight incident for interviews:** [INC-2026-001 — BITS job download](incidents/INC-2026-001-bits-job-download.md) (detection → containment in 13 minutes)

## Build Artifacts

```powershell
.\build.ps1
```

This generates IOC enrichment and Caldera timeline CSV in `artifacts/`.

---

## Skills Demonstrated

| Lab | What I Operate |
|-----|----------------|
| **Lab 1 — On-Prem** | Wazuh, Splunk, Sysmon, AD (`corp.lab.local`), pfSense, Wireshark |
| **Lab 2 — Cloud** | Sentinel, Defender, Entra ID (`pe-soc-lab` tenant), Log Analytics, KQL |

| Domain | Evidence in This Repo |
|--------|----------------------|
| SIEM / log analysis | Splunk SPL, Microsoft Sentinel KQL, Wazuh rules |
| Alert triage & escalation | `incidents/`, `tickets/` (osTicket), `templates/ticket-triage.md` |
| False-positive analysis | `incidents/INC-2026-004-false-positive-vpn.md` |
| Incident response lifecycle | Detection → validation → enrichment → containment → eradication → recovery → post-incident |
| Documentation | Structured incident records with timeline, evidence, severity, and recommendations |
| Ticketing | osTicket samples in `tickets/sample-tickets.md` |
| Network analysis | TCP/IP, DNS, HTTP/S, PCAP interpretation in `network/` |
| Windows / AD / Entra ID | Sysmon, Windows Event Logs, Entra sign-in correlation |
| Microsoft XDR / EDR / KQL | Sentinel detections, Defender for Endpoint queries |
| Scripting | `scripts/ioc_enrichment.py`, `scripts/triage_alert.ps1` |
| Cloud (Azure / Entra ID) | Sentinel analytics, Entra sign-in enrichment |
| MITRE ATT&CK mapping | Every scenario and detection mapped to techniques |
| Phishing / email headers | `phishing/email-header-analysis.md` |
| IOC enrichment | IPs, domains, URLs, file hashes via `scripts/ioc_enrichment.py` |
| Tool evidence (screenshots) | `artifacts/screenshots/` — static PNG captures per incident |
| Practice exercises | `network/sample-dns-exfil-analysis.md` — DNS triage (not a closed incident) |

---

## Lab Architecture

Two environments, one workflow — the same setup many Alberta MSSPs run.

### Lab 1 — On-Premises SOC (`corp.lab.local`)

```
Caldera C2 ──► Win10 workstations / AD (corp.lab.local)
                    │
                    ▼
         Wazuh alert queue │ Splunk │ pfSense VPN/firewall logs
```

**Covers:** endpoint triage, AD logon events, PCAP/firewall analysis.

### Lab 2 — Cloud Security Operations (`pe-soc-lab` tenant)

```
Lab 1 hosts ──► AMA + Defender ──► Log Analytics (law-pe-soc-prod)
Entra ID      ──► Sign-in connector ──► Microsoft Sentinel incident queue
```

**Covers:** KQL investigation, Defender isolation, Entra risky sign-in correlation, cloud-side false-positive handling.

Full topology, IP plan, connectors, and agent enrollment: [`docs/lab-architecture.md`](docs/lab-architecture.md)

---

## Scenarios

| # | Scenario | Lab | Trigger | Incident Report |
|---|----------|-----|---------|-----------------|
| 01 | Windows download & execution | Hybrid | Caldera `T1-Windows-Download-Exec` | [INC-2026-001](incidents/INC-2026-001-bits-job-download.md) |
| 02 | Entra password spray & risky sign-in | Lab 2 | Lab spray script | [INC-2026-002](incidents/INC-2026-002-entra-password-spray.md) |
| 03 | Lateral movement & RDP abuse | Hybrid | Caldera `T1-Windows-Lateral` | [INC-2026-003](incidents/INC-2026-003-rdp-port-modification.md) |
| 04 | VPN auth failure storm | Lab 2 | Organic noise | [INC-2026-004](incidents/INC-2026-004-false-positive-vpn.md) |
| 05 | Phishing → endpoint compromise chain | Lab 2 | Caldera `T1-Phish-to-Host` | [INC-2026-005](incidents/INC-2026-005-phishing-chain.md) |

Caldera setup and operation steps: [`caldera/operations-runbook.md`](caldera/operations-runbook.md)

---

## Incident Response Lifecycle (How Each Case Is Structured)

Every incident document follows the same operational flow a Tier 1 analyst would execute on shift:

1. **Detection** — Alert source, rule name, initial severity
2. **Validation** — Confirm true positive vs. benign activity
3. **Enrichment** — IOC lookup, asset context, user/account context
4. **Containment** — Host isolation, account disable, firewall block
5. **Eradication** — Malware removal, scheduled task deletion, Caldera cleanup
6. **Recovery** — Restore services, re-enable after verification
7. **Escalation** — When and why Tier 2/IR was engaged
8. **Post-incident** — Timeline, lessons learned, detection tuning

Template: [`templates/incident-report.md`](templates/incident-report.md)

---

## Detections

| Platform | Location | Example Techniques Covered |
|----------|----------|---------------------------|
| Splunk | `detections/splunk/` | T1197 BITS, DNS tunneling |
| Microsoft Sentinel | `detections/sentinel/` | KQL analytics rules, Entra ID correlation |
| Wazuh | `detections/wazuh/` | Custom local rules for Caldera-emulated TTPs |

---

## Scripts & Automation

```powershell
# Quick IOC enrichment (IPs, domains, URLs, hashes)
python scripts/ioc_enrichment.py --input scripts/sample_iocs.txt --output artifacts/enrichment_report.json

# Tier 1 alert triage helper (pulls host context, recent alerts)
.\scripts\triage_alert.ps1 -Hostname WKSTN-042 -AlertId ALT-88421
```

---

## About

**Praisel Ekpenyong** is an entry-level SOC Analyst building practical, job-ready skills through certification-backed training and hands-on home lab work. This repository documents end-to-end Tier 1 workflows — not just tools listed on a resume.

**Lab environments:**

- **Lab 1 (on-prem):** `corp.lab.local` — Wazuh, Splunk, Sysmon, AD, pfSense
- **Lab 2 (cloud):** `pe-soc-lab` tenant — Sentinel, Defender for Endpoint, Entra ID, Log Analytics

**Focus areas aligned to SC-200 / Security+:** KQL analytics, alert triage, incident documentation, MITRE ATT&CK mapping, phishing investigation, and IOC enrichment.

### Resume highlights (copy-ready)

See [`docs/resume-highlights.md`](docs/resume-highlights.md) — bullets split by lab with keywords, how, where (system/queue), and plain-language why.

## How to Use This Portfolio (Interview / Hiring Manager)

1. **Start with README** — shows breadth of Tier 1 competencies.
2. **Anchor case** — [INC-2026-001](incidents/INC-2026-001-bits-job-download.md) (endpoint, 13 min containment).
3. **Identity pair** — [INC-2026-002](incidents/INC-2026-002-entra-password-spray.md) (true positive) vs [INC-2026-004](incidents/INC-2026-004-false-positive-vpn.md) (false positive).
4. **Open matching detection** — explain what the alert looks for and why.
5. **Caldera operations** (INC-001, 003, 005) — prove endpoint alerts came from controlled emulation.
6. **Run IOC script** — `.\build.ps1` or `python scripts/ioc_enrichment.py`.

---

## Quick Links

- [Resume highlights](docs/resume-highlights.md)
- [Lab setup](docs/lab-architecture.md)
- [Caldera install & agents](docs/caldera-setup.md)
- [SOC playbooks](docs/soc-playbooks.md)
- [Ticketing samples](tickets/sample-tickets.md)
- [PCAP analysis walkthrough](network/pcap-analysis-guide.md)
- [Email header investigation](phishing/email-header-analysis.md)

---

## Disclaimer

All offensive activity documented here was performed in an isolated lab against systems you own. Caldera agents, payloads, and C2 traffic must never be run on production networks without explicit authorization.