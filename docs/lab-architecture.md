# SOC Lab Architecture

**Analyst:** Praisel Ekpenyong · Tier 1 SOC  
**Status:** Both environments operational. Attack traffic originates exclusively from **Apache Caldera** operations.

The portfolio runs on **two connected labs** — the same way many MSSPs and enterprises do: on-prem endpoints and network gear feeding a Microsoft cloud security stack.

---

## Overview

| Lab | Name | Purpose | Primary tools |
|-----|------|---------|---------------|
| **Lab 1** | On-Premises SOC | Endpoint, AD, and network alert triage | Wazuh, Splunk, Sysmon, pfSense, AD DS |
| **Lab 2** | Cloud Security Operations | Microsoft XDR/SIEM triage and identity correlation | Sentinel, Defender for Endpoint, Entra ID, Log Analytics |

**Hybrid link:** Lab 1 hosts forward logs and alerts into Lab 2 via AMA, Defender, and Entra connectors. The same Caldera-driven attacks are visible in both layers.

```
                    ┌─────────────────────────────────────┐
                    │     Apache Caldera C2 (Lab 1)       │
                    │           10.10.30.10                 │
                    └──────────────┬──────────────────────┘
                                   │ sandcat agents
     LAB 1 — ON-PREM              │              LAB 2 — CLOUD
     ─────────────────             │              ─────────────────
     Win10 / Linux / AD            │              Microsoft Sentinel
     Wazuh + Splunk                ├────────────► Log Analytics workspace
     pfSense firewall              │              Defender for Endpoint
     Sysmon / auditd               │              Entra ID sign-in logs
```

---

## Lab 1 — On-Premises SOC Environment

**Domain:** `corp.lab.local`  
**Function:** Tier 1 triage on endpoint, server, AD, and firewall telemetry.

### Network Diagram

```
Internet (simulated) ──► pfSense Firewall ──► 10.10.0.0/24 (DMZ)
                                              │
                    ┌─────────────────────────┼─────────────────────────┐
                    │                         │                         │
              10.10.10.0/24            10.10.20.0/24            10.10.30.0/24
              (Workstations)           (Servers)                (Security Tools)
                    │                         │                         │
         ┌──────────┴──────────┐    ┌─────────┴─────────┐    ┌─────────┴─────────┐
         │ WKSTN-042  Win10    │    │ SRV-LNX-01 Ubuntu │    │ CALDERA 10.10.30.10│
         │ WKSTN-099  Win10    │    │ SRV-DC-01  AD DS  │    │ WAZUH  10.10.30.20 │
         └─────────────────────┘    └───────────────────┘    │ SPLUNK 10.10.30.30 │
                                                              └───────────────────┘
```

### Asset Inventory

| Hostname | IP | OS | Role | Agents / Logging |
|----------|-----|-----|------|------------------|
| CALDERA-SRV | 10.10.30.10 | Ubuntu 22.04 | C2 / emulation | Caldera server |
| WKSTN-042 | 10.10.10.42 | Windows 10 | User workstation | Sysmon, Wazuh agent |
| WKSTN-099 | 10.10.10.99 | Windows 10 | Finance user | Sysmon, Wazuh agent |
| SRV-LNX-01 | 10.10.20.15 | Ubuntu 22.04 | Web/app server | Wazuh agent, auditd |
| SRV-DC-01 | 10.10.20.10 | Windows Server 2019 | Domain Controller | Windows Events → Wazuh / Splunk |
| WAZUH-SRV | 10.10.30.20 | Ubuntu 22.04 | SIEM (Wazuh manager) | Alert queue, custom rules |
| SPLUNK-SRV | 10.10.30.30 | Ubuntu 22.04 | SIEM (Splunk) | HF + indexer |
| PFSENSE-01 | 10.10.0.1 | pfSense | Perimeter / VPN | Firewall + OpenVPN logs |

### Log Sources (Lab 1)

| Source | Platform | Key Events |
|--------|----------|------------|
| Microsoft-Windows-Sysmon/Operational | Windows endpoints | Process create (1), network (3), DNS (22) |
| Security | Windows / AD | 4624/4625 logon, 4720 account created, 4740 lockout |
| /var/log/auth.log | Linux | SSH auth, sudo |
| auditd | Linux | execve, useradd, crontab |
| pfSense | Firewall | Blocked/allowed flows, VPN auth failures |
| Zeek / Suricata (optional) | IDS | DNS anomalies, ET rules |

### SIEM Routing (Lab 1)

- **Wazuh** — Agents on all endpoints → Wazuh manager → Dashboard alert queue. Custom rules in `detections/wazuh/local_rules.xml`.
- **Splunk** — Universal Forwarders → HF → Indexer. Indexes: `wineventlog`, `sysmon`, `linux`, `network`, `caldera_ops`.

### Incidents Validated in Lab 1

| Incident | Primary Lab 1 sources |
|----------|----------------------|
| INC-2026-001 | Wazuh rule 180001, Sysmon on WKSTN-042 |
| INC-2026-003 | Sysmon, pfSense flows, Wireshark PCAP on WKSTN-099 |
| INC-2026-004 | pfSense VPN logs (forwarded to Sentinel) |

---

## Lab 2 — Cloud Security Operations

**Tenant:** `pe-soc-lab.onmicrosoft.com`  
**Resource group:** `rg-pe-soc-lab` (Canada Central)  
**Function:** Tier 1 triage in the Microsoft stack — same shift workflow as an MSSP client on Sentinel + Defender.

### Cloud Inventory

| Resource | Name | Role |
|----------|------|------|
| Log Analytics workspace | `law-pe-soc-prod` | Central log store for Sentinel |
| Microsoft Sentinel | On `law-pe-soc-prod` | Incident queue, KQL analytics, SOAR playbooks |
| Microsoft Defender for Endpoint | Tenant-wide | Endpoint alerts, host isolation, alert story |
| Entra ID | `pe-soc-lab.onmicrosoft.com` | Sign-in logs, risky sign-in, account context |
| Azure Monitor Agent | On WKSTN-042, WKSTN-099, SRV-DC-01 | Forwards Windows events to LAW |
| Data connectors | Defender XDR, Entra ID, Windows Security Events | Alert and log ingestion |

### Connectors & Data Flow

```
Lab 1 endpoints ──► AMA / MDE agent ──► Log Analytics (law-pe-soc-prod)
Entra ID          ──► Sign-in connector ──► Sentinel
Defender XDR      ──► Incident & alert API ──► Sentinel incident queue
pfSense VPN logs  ──► Syslog forwarder    ──► Sentinel (Custom table: VPNLogs)
```

### Detections (Lab 2)

Analytics rules and KQL live in `detections/sentinel/`. Examples:

- Suspicious BITS transfer (INC-2026-001 correlation)
- Password spray against valid user (INC-2026-002)
- Multiple failed VPN logins (INC-2026-004)
- PowerShell download cradle (phishing chain)
- Entra risky sign-in correlation

### Incidents Validated in Lab 2

| Incident | Primary Lab 2 sources |
|----------|----------------------|
| INC-2026-001 | Defender alert story, Sentinel KQL, host isolation |
| INC-2026-002 | Sentinel `password_spray_entra`, Entra risky sign-in, session revoke |
| INC-2026-003 | Defender process chain on WKSTN-099 |
| INC-2026-004 | Sentinel analytics `Multiple failed VPN logins` |
| INC-2026-005 | Sentinel + Defender + Entra user context (phishing chain) |

---

## Hybrid Incidents (Both Labs)

Some cases are intentionally run across both environments to mirror real MSSP work:

| Incident | Lab 1 signal | Lab 2 signal | Why both |
|----------|--------------|--------------|----------|
| INC-2026-001 | Wazuh 180001 fires first | Defender + Sentinel confirm | Prove cross-SIEM correlation on one attack |
| INC-2026-003 | PCAP + firewall in Splunk | Defender lateral movement alert | Network + endpoint view |
| INC-2026-005 | User report + email headers | Sentinel PowerShell rule | Email layer + cloud EDR |

### Practice Modules (No INC Record)

| Module | Location | Purpose |
|--------|----------|---------|
| DNS exfil drill | `network/sample-dns-exfil-analysis.md` | Splunk/Wireshark tuning exercise |

---

## Caldera Integration (Shared)

1. Deploy **sandcat** agents on WKSTN-042 and SRV-LNX-01 (`docs/caldera-setup.md`).
2. Tag agents with group `blue-team-lab` for operation filtering.
3. Run adversary profiles in `caldera/adversary-profiles.md`.
4. Correlate Caldera operation timestamps with **both** Wazuh and Sentinel alert times.

---

## Firewall / Network Controls

| Rule | Action | Purpose |
|------|--------|---------|
| LAN → CALDERA:8888 | Allow | Agent beaconing (lab only) |
| CALDERA → Internet | Deny | Prevent accidental egress |
| DMZ → DC (LDAP/Kerberos) | Allow | AD auth simulation |
| Lab → Azure (HTTPS 443) | Allow | AMA and Defender cloud connectivity |
| Any → Splunk 514/9997 | Allow | Log forwarding |

---

## Isolation & Safety

- Lab VLAN has no route to corporate production.
- Azure tenant is a dedicated sandbox subscription.
- Snapshots taken before each Caldera operation.
- Caldera `--insecure` flag used only in lab; credentials rotated after demos.
- Cleanup: stop Caldera operation → verify agent removal → restore VM snapshot if needed.

---

## Quick Reference — Where to Triage What

| Alert type | First console | Escalation data |
|------------|---------------|-----------------|
| Windows malware / process abuse | Wazuh (Lab 1) or Defender (Lab 2) | Sysmon lineage, MDE alert story |
| VPN / perimeter noise | Sentinel (Lab 2) | pfSense logs, change ticket |
| Identity / sign-in risk | Sentinel + Entra (Lab 2) | Sign-in logs, user risk |
| Phishing + endpoint follow-on | Email triage → Sentinel (Lab 2) | Defender on affected host |