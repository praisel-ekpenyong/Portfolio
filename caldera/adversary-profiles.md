# Caldera Adversary Profiles

Profiles used in this portfolio. Create each in Caldera UI: **Campaigns → Adversaries → + New**.

## T1-Windows-Download-Exec

**Description:** Simulates opportunistic malware delivery via BITS job. Maps to INC-2026-001.

| Order | Ability (stockpile) | MITRE ID | Expected Alert |
|-------|---------------------|----------|----------------|
| 1 | Download file using BITSAdmin | T1197 | Wazuh 180001 / Splunk `T1197_BITS_download` |
| 2 | Save payload to disk | T1105 | Sysmon Event ID 11 |
| 3 | Execute downloaded binary | T1059.003 | Sysmon Event ID 1, Defender alert |

**Target agent:** WKSTN-042 (Windows)  
**Group:** blue-team-lab  
**Planner:** atomic

## T1-Scheduled-Task

**Description:** Masquerading scheduled task persistence. Maps to INC-2026-003.

| Order | Ability | MITRE ID | Expected Alert |
|-------|---------|----------|----------------|
| 1 | Create scheduled task (ChromeUpdate name) | T1053.005 | Wazuh 180002 |
| 2 | Execute action script from user Temp | T1059.001 | Sysmon EID 1, Defender |
| 3 | (Cleanup) Delete scheduled task | — (operational cleanup) | On operation stop |

**Target agent:** WKSTN-042 (Windows)

## T1-Windows-Lateral

**Description:** Remote Desktop Protocol lateral movement and packet capturing. Maps to INC-2026-006.

| Order | Ability | MITRE ID | Expected Alert |
|-------|---------|----------|----------------|
| 1 | Lateral Movement via Remote Desktop Protocol | T1021.001 | Wazuh 180003 (registry port mod if changed) |
| 2 | Modify RDP registry port to 8443 | T1112 | Wazuh 180003 |
| 3 | Execute tcpdump.exe packet sniffer | T1040 | Wazuh 180004 |

**Target agent:** WKSTN-099 (Windows)  
**Group:** blue-team-lab  
**Planner:** atomic


## T1-Phish-to-Host

**Description:** User execution after phishing link (Caldera simulates post-click). Maps to phishing incident doc.

| Order | Ability | MITRE ID | Expected Alert |
|-------|---------|----------|----------------|
| 1 | PowerShell download cradle | T1059.001 | Script block logging 4104 |
| 2 | Write file to `%TEMP%` | T1204.002 | Sysmon 11 |
| 3 | Establish HTTP beacon pattern | T1071.001 | Proxy / firewall deny + DNS |

**Note:** Email delivery is documented separately in `phishing/` (headers, user report). Caldera executes **post-click** TTPs only.

## Operation Settings

| Setting | Value | Rationale |
|---------|-------|-----------|
| Autonomous | Enabled | Hands-free for demo recording |
| Jitter | 20% | Slightly realistic beacon timing |
| Visibility | 50 | Mixed stealth for tuning exercises |
| State | running → stop for cleanup | Ensures cleanup abilities fire |

## MITRE ATT&CK Coverage Matrix

| Tactic | Techniques Emulated |
|--------|---------------------|
| Initial Access | T1566.001 (documented), T1190 |
| Execution | T1059.001, T1059.003 |
| Persistence | T1053.005 (scheduled task), — (see INC-2026-002 Entra spray — non-Caldera) |
| Privilege Escalation | — (lab uses elevated agents) |
| Defense Evasion | T1197 (BITS), T1112 (Registry Modify - INC-2026-006) |
| Credential Access | T1110.003 (INC-2026-002), T1040 (Network Sniffing - INC-2026-006) |
| Discovery | T1087.002 |
| Lateral Movement | T1021.001 (RDP - INC-2026-006) |
| C2 | T1071.001 |
| Impact | T1531 (cleanup) |