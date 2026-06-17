# Tooling Stack

Tools referenced throughout this portfolio and how a Tier 1 analyst uses each on shift.

**Analyst:** Praisel Ekpenyong · Security+ · SC-200 · Google Cybersecurity Certificate

## SIEM

| Tool | Use in Portfolio | Tier 1 Tasks |
|------|------------------|--------------|
| **Wazuh** | `detections/wazuh/` | Review alerts, drill into rule level, check agent inventory |
| **Splunk** | `detections/splunk/` | Run SPL, pivot on `src_host`, save notable events |
| **Microsoft Sentinel** | `detections/sentinel/` | Execute KQL, triage Incidents, link to Entra sign-ins |

## Endpoint / XDR

| Tool | Use in Portfolio | Tier 1 Tasks |
|------|------------------|--------------|
| **Microsoft Defender for Endpoint** | INC-2026-001, 003 | View alert story, isolate machine, collect file quarantine |
| **Sysmon** | All Windows scenarios | Process lineage, command-line arguments |

## Emulation

| Tool | Use in Portfolio | Tier 1 Tasks |
|------|------------------|--------------|
| **Apache Caldera** | All attack scenarios | Validate detections; never operate in prod |

## Network

| Tool | Use in Portfolio | Tier 1 Tasks |
|------|------------------|--------------|
| **Wireshark** | `network/pcap-analysis-guide.md` | Follow TCP streams, filter DNS, export objects |
| **pfSense** | Lab firewall logs | Verify blocked C2, VPN false positives |
| **Suricata/Zeek** (optional) | DNS exfil scenario | Review IDS sid and flow logs |

## Enrichment

| Tool | Use in Portfolio | Tier 1 Tasks |
|------|------------------|--------------|
| **VirusTotal** | `scripts/ioc_enrichment.py` | Hash and domain reputation |
| **AbuseIPDB / IPinfo** | IOC script | IP geolocation and abuse score |
| **URLhaus / PhishTank** | Phishing scenario | URL reputation |
| **MXToolbox** | Email header guide | SPF/DKIM/DMARC lookup |

## Ticketing

| Tool | Example |
|------|---------|
| Jira Service Management | `tickets/sample-tickets.md` |
| ServiceNow SecOps | Same templates, different field names |

## Scripting

| Script | Language | Purpose |
|--------|----------|---------|
| `ioc_enrichment.py` | Python | Batch IOC lookup |
| `triage_alert.ps1` | PowerShell | Host + user context pull |
| `caldera_log_parser.py` | Python | Map emulation to SIEM timeline |