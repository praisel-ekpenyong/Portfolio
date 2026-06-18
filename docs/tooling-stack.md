# Tooling Stack

Tools used across **Lab 1 (on-prem)** and **Lab 2 (cloud)**. Tier 1 tasks listed as performed on shift.

**Analyst:** Praisel Ekpenyong · Security+ · SC-200 · Google Cybersecurity Certificate

---

## Lab 1 — On-Premises SOC

### SIEM

| Tool | Use in Portfolio | Tier 1 Tasks |
|------|------------------|--------------|
| **Wazuh** | `detections/wazuh/` | Review alert queue, drill into rule level, check agent inventory |
| **Splunk** | `detections/splunk/` | Run SPL, pivot on `src_host`, save notable events |

### Endpoint & Network

| Tool | Use in Portfolio | Tier 1 Tasks |
|------|------------------|--------------|
| **Sysmon** | INC-2026-001, 003 | Process lineage, command-line arguments |
| **Active Directory** | INC-2026-001, 003 | Logon events, account context on `corp.lab.local` |
| **Wireshark** | `network/pcap-analysis-guide.md`, supplemental RDP case | Follow TCP streams, filter DNS, export objects |
| **pfSense** | INC-2026-004 source logs | Verify blocked C2, VPN auth failures |
| **Suricata/Zeek** (optional) | DNS exfil scenario | Review IDS sid and flow logs |

---

## Lab 2 — Cloud Security Operations

### SIEM / XDR

| Tool | Use in Portfolio | Tier 1 Tasks |
|------|------------------|--------------|
| **Microsoft Sentinel** | `detections/sentinel/` | Execute KQL, triage incident queue, link alerts |
| **Microsoft Defender for Endpoint** | INC-2026-001, 003, 005 | View alert story, isolate machine, file quarantine |
| **Entra ID** | INC-2026-005, cross-incident | Risky sign-in review, user context |

### Connectors

| Connector | Source | Destination |
|-----------|--------|-------------|
| Defender XDR | MDE alerts | Sentinel incidents |
| Entra ID | Sign-in logs | Sentinel tables |
| AMA | Windows events (Lab 1 hosts) | `law-pe-soc-prod` workspace |

---

## Shared (Both Labs)

### Emulation

| Tool | Use in Portfolio | Tier 1 Tasks |
|------|------------------|--------------|
| **Apache Caldera** | All attack scenarios | Validate detections in both SIEM layers |

### Enrichment

| Tool | Use in Portfolio | Tier 1 Tasks |
|------|------------------|--------------|
| **VirusTotal** | `scripts/ioc_enrichment.py` | Hash and domain reputation |
| **IP reputation sources** | IOC script | Optional public IP enrichment when real, non-sanitized IOCs are supplied |
| **URLhaus / PhishTank** | Phishing scenario | URL reputation |
| **MXToolbox** | Email header guide | SPF/DKIM/DMARC lookup |

### Ticketing

| Tool | Example |
|------|---------|
| **osTicket** | `tickets/sample-tickets.md` — Security Operations department, internal notes, linked incidents |

### Scripting

| Script | Language | Purpose |
|--------|----------|---------|
| `ioc_enrichment.py` | Python | Batch IOC lookup |
| `triage_alert.ps1` | PowerShell | Host + user context pull |
| `caldera_log_parser.py` | Python | Map emulation to SIEM timeline |

---

## Which Lab for Which Incident

| Incident | Lab 1 tools | Lab 2 tools |
|----------|-------------|-------------|
| INC-2026-001 | Wazuh, Sysmon | Defender, Sentinel KQL |
| INC-2026-002 | — | Sentinel, Entra ID, Defender |
| INC-2026-003 | Wazuh, Sysmon, Splunk | Defender |
| INC-2026-004 | pfSense (log source) | Sentinel |
| INC-2026-005 | Email headers | Sentinel, Defender, Entra |
