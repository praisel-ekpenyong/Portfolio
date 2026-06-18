# SOC Analyst L1 Portfolio

**Praisel Ekpenyong** · SOC Analyst L1

| | |
|---|---|
| **Email** | [ekpenyongpraisel@gmail.com](mailto:ekpenyongpraisel@gmail.com) |
| **GitHub** | [github.com/praisel-ekpenyong/Portfolio](https://github.com/praisel-ekpenyong/Portfolio) |
| **LinkedIn** | [linkedin.com/in/praiselekpenyong](https://www.linkedin.com/in/praiselekpenyong) |

**Certifications:** Google Cybersecurity Certificate · CompTIA Security+ · Microsoft SC-200 (Security Operations Analyst)

Entry-level security operations portfolio covering five Tier 1 case types across two lab environments — an on-premises endpoint SOC and a Microsoft cloud SOC.

---

## Cases

| # | Case type | Incident | Key skill |
|---|-----------|----------|-----------|
| **1** | Phishing + endpoint correlation | [INC-2026-005](incidents/INC-2026-005-phishing-chain.md) | Headers, staged conclusions, mail scope |
| **2** | Password spray + cloud sign-in | [INC-2026-002](incidents/INC-2026-002-entra-password-spray.md) | Identity logs, post-auth checks |
| **3** | LOLBin / endpoint execution | [INC-2026-001](incidents/INC-2026-001-bits-job-download.md) | Process tree, benign vs malicious |
| **4** | Scheduled-task persistence | [INC-2026-003](incidents/INC-2026-003-scheduled-task-persistence.md) | Baseline comparison, task XML |
| **5** | False positive + tuning | [INC-2026-004](incidents/INC-2026-004-false-positive-vpn.md) | Close safely, before/after rules |

---

## Skills & Tools

| Lab | Tools |
|-----|-------|
| **On-Premises SOC** | Wazuh · Splunk · Sysmon · Active Directory · pfSense · Wireshark |
| **Cloud SOC** | Microsoft Sentinel · Defender for Endpoint · Entra ID · Log Analytics · KQL |

| Skill area | Coverage |
|------------|----------|
| Phishing & email analysis | SPF/DKIM/DMARC, header review, attachment triage, recipient scoping |
| Identity & cloud security | Password spray detection, session revocation, post-auth investigation |
| Endpoint & LOLBin triage | Process tree analysis, BITS abuse, benign vs malicious baseline comparison |
| Persistence detection | Scheduled task auditing, registry/WMI/startup sweep, domain-scope check |
| False positive handling | Change ticket correlation, severity downgrade, detection tuning |
| IOC enrichment | Python scripting, local classification, VirusTotal-compatible workflow |
| Adversary emulation | Apache Caldera, MITRE ATT&CK mapping, detection regression |
| Ticketing & documentation | osTicket, MTTA/MTTC tracking, escalation notes, shift handoff |

---

## Lab Architecture

Two connected environments — on-premises endpoint SOC (`corp.lab.local`) and Microsoft cloud SOC (`pe-soc-lab` tenant). Full topology: [docs/lab-architecture.md](docs/lab-architecture.md)

---

## Disclaimer

All offensive activity was performed in isolated lab environments with authorization. The reuse of a single workstation (`WKSTN-042`) and user account (`jsmith`) across cases is an intentional lab design choice for consistent baseline comparison and cross-case correlation.
