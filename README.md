# SOC Analyst L1 Portfolio

**Praisel Ekpenyong** · SOC Analyst L1

| | |
|---|---|
| **Email** | [Ekpenyongpraisel@gmail.com](mailto:Ekpenyongpraisel@gmail.com) |
| **GitHub** | [github.com/praisel-ekpenyong](https://github.com/praisel-ekpenyong) |
| **LinkedIn** | [linkedin.com/in/praiselekpenyong](https://www.linkedin.com/in/praiselekpenyong) |

**Certifications:** Google Cybersecurity Certificate · CompTIA Security+ · Microsoft SC-200 (Security Operations Analyst)

Entry-level security operations portfolio demonstrating alert triage, incident investigation, documentation, and detection engineering across **two operational labs** — on-premises endpoint SOC and Microsoft cloud SOC. **All attack simulations are executed with [Apache Caldera](https://caldera.apache.org/)** against controlled environments I own and operate.

> **Highlight incident for interviews:** [INC-2026-001 — BITS job download](incidents/INC-2026-001-bits-job-download.md) (detection → containment in 13 minutes)

## Open Portfolio (local)

```powershell
.\build.ps1
```

This generates artifacts (IOC enrichment, Caldera timeline) and opens **`portfolio/index.html`** in your browser. No GitHub push required.

---

## Skills Demonstrated

| Lab | What I Operate |
|-----|----------------|
| **Lab 1 — On-Prem** | Wazuh, Splunk, Sysmon, AD (`corp.lab.local`), Linux, pfSense, Wireshark |
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
| Windows / Linux / AD | Sysmon, Windows Event Logs, auth logs, AD sign-in correlation |
| Microsoft XDR / EDR / KQL | Sentinel detections, Defender for Endpoint queries |
| Scripting | `scripts/ioc_enrichment.py`, `scripts/triage_alert.ps1` |
| Cloud (Azure / Entra ID) | Sentinel analytics, Entra sign-in enrichment |
| MITRE ATT&CK mapping | Every scenario and detection mapped to techniques |
| Phishing / email headers | `phishing/email-header-analysis.md` |
| IOC enrichment | IPs, domains, URLs, file hashes via `scripts/ioc_enrichment.py` |
| Tool evidence (screenshots) | `artifacts/screenshots/` — Wazuh, Defender, Sentinel, osTicket, Sysmon |

---

## Lab Architecture

Two environments, one workflow — the same setup many Alberta MSSPs run.

### Lab 1 — On-Premises SOC (`corp.lab.local`)

```
Caldera C2 ──► Win10 / Linux / AD (corp.lab.local)
                    │
                    ▼
         Wazuh alert queue │ Splunk │ pfSense VPN/firewall logs
```

**Covers:** endpoint triage, Linux forensics, AD logon events, PCAP/firewall analysis.

### Lab 2 — Cloud Security Operations (`pe-soc-lab` tenant)

```
Lab 1 hosts ──► AMA + Defender ──► Log Analytics (law-pe-soc-prod)
Entra ID      ──► Sign-in connector ──► Microsoft Sentinel incident queue
```

**Covers:** KQL investigation, Defender isolation, Entra risky sign-in correlation, cloud-side false-positive handling.

Full topology, IP plan, connectors, and agent enrollment: [`docs/lab-architecture.md`](docs/lab-architecture.md)

---

## Caldera-Driven Scenarios

| # | Scenario | Lab | Caldera Profile | Incident Report |
|---|----------|-----|-----------------|-----------------|
| 01 | Windows download & execution | Hybrid | `T1-Windows-Download-Exec` | [INC-2026-001](incidents/INC-2026-001-bits-job-download.md) |
| 02 | Linux persistence & account abuse | Lab 1 | `T1-Linux-Persistence` | [INC-2026-002](incidents/INC-2026-002-linux-account-creation.md) |
| 03 | Lateral movement & RDP abuse | Hybrid | `T1-Windows-Lateral` | [INC-2026-003](incidents/INC-2026-003-rdp-port-modification.md) |
| 04 | VPN auth failure storm (no Caldera) | Lab 2 | — | [INC-2026-004](incidents/INC-2026-004-false-positive-vpn.md) |
| 05 | Phishing → endpoint compromise chain | Lab 2 | `T1-Phish-to-Host` | [phishing/sample-phishing-incident.md](phishing/sample-phishing-incident.md) |

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
| Splunk | `detections/splunk/` | T1197 BITS, T1136 account creation, DNS tunneling |
| Microsoft Sentinel | `detections/sentinel/` | KQL analytics rules, Entra ID correlation |
| Wazuh | `detections/wazuh/` | Custom local rules for Caldera-emulated TTPs |

---

## Scripts & Automation

```powershell
# Quick IOC enrichment (IPs, domains, URLs, hashes)
python scripts/ioc_enrichment.py --input iocs.txt --output enrichment_report.json

# Tier 1 alert triage helper (pulls host context, recent alerts)
.\scripts\triage_alert.ps1 -Hostname WKSTN-042 -AlertId ALT-88421
```

---

## About

**Praisel Ekpenyong** is an entry-level SOC Analyst building practical, job-ready skills through certification-backed training and hands-on home lab work. This repository documents end-to-end Tier 1 workflows — not just tools listed on a resume.

**Lab environments:**

- **Lab 1 (on-prem):** `corp.lab.local` — Wazuh, Splunk, Sysmon, AD, Linux, pfSense
- **Lab 2 (cloud):** `pe-soc-lab` tenant — Sentinel, Defender for Endpoint, Entra ID, Log Analytics

**Focus areas aligned to SC-200 / Security+:** KQL analytics, alert triage, incident documentation, MITRE ATT&CK mapping, phishing investigation, and IOC enrichment.

### Resume highlights (copy-ready)

See [`docs/resume-highlights.md`](docs/resume-highlights.md) — bullets split by lab with keywords, how, where (system/queue), and plain-language why.

## How to Use This Portfolio (Interview / Hiring Manager)

1. **Start with README** — shows breadth of Tier 1 competencies.
2. **Pick one incident** (e.g., INC-2026-001) — walk through triage → escalation in 5 minutes.
3. **Open matching detection** — explain what the alert looks for and why.
4. **Show Caldera operation** — prove the alert was triggered by controlled emulation, not fabricated logs.
5. **Run IOC script** — demonstrate practical enrichment workflow.
6. **Discuss false positive** (INC-2026-004) — shows maturity beyond "everything is malware."

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