# INC-2026-003 — Suspicious Scheduled Task Persistence (Case #4)

| Field | Value |
|-------|-------|
| **Incident ID** | INC-2026-003 |
| **Focus Area** | **Scheduled Tasks & Persistence** |
| **osTicket** | #48318 |
| **Severity** | P2 — High |
| **Status** | Closed — True Positive (Lab Emulation) |
| **Detection Source** | Wazuh 180002 + Sysmon EID 1/11 + Defender |
| **Caldera Operation** | `2026-06-15-SCHTASK-LAB` |
| **MITRE ATT&CK** | T1053.005 (Scheduled Task), T1059.001 (PowerShell) |
| **Analyst** | Praisel Ekpenyong |
| **Lab Environment** | Hybrid — Lab 1 (Wazuh/Sysmon/Splunk) + Lab 2 (Defender) |

---

## Executive Summary

Wazuh and Defender detected a scheduled task named `ChromeUpdate` executing PowerShell from a user-writable Temp path. I validated it against a legitimate SCCM baseline, confirmed it was local to WKSTN-042, checked for other persistence mechanisms, and escalated to Tier 2 for confirmed persistence on a finance workstation. Cleanup removed the task and script with no recurrence.

### MITRE Evidence Map

| Technique | Evidence |
|-----------|----------|
| T1053.005 Scheduled Task | `schtasks /Create /TN ChromeUpdate` in Sysmon EID 1 |
| T1059.001 PowerShell | Task action launches `powershell.exe` against `update.ps1` |

---

## 1. Detection

**2026-06-15 16:04:18 UTC** — Wazuh Rule 180002:

```
Suspicious scheduled task created — ChromeUpdate name with user-writable action path
Host: WKSTN-042
User: CORP\jsmith
```

**16:04:52 UTC** — Defender: *Persistence mechanism: scheduled task with suspicious action*

---

## 2. Validation

| Check | Result |
|-------|--------|
| Legitimate Chrome enterprise update? | No — real Chrome GPO tasks use `Google\Update` path under `Program Files` |
| Change ticket for software deployment? | None |
| Task name `ChromeUpdate` | Matches attacker mimicry pattern (plausible name, wrong path) |
| Action executes from user profile? | `C:\Users\jsmith\AppData\Local\Temp\update.ps1` |
| Initiating process chain (Sysmon EID 1) | `cmd.exe` → `schtasks.exe` (not `svchost.exe` or SCCM `CcmExec.exe`) |
| Task action (`\ChromeUpdate`) | `powershell.exe -WindowStyle Hidden -File ...\update.ps1` (unsigned script from Temp) |
| Caldera correlation | T1053.005 ability finished 16:04:16 UTC |

### Baseline comparison — legitimate vs suspicious

| Attribute | Legitimate SCCM task (WKSTN-099) | Suspicious task (WKSTN-042) |
|-----------|----------------------------------|----------------------------|
| Registration chain | `CcmExec.exe` (SCCM) | `cmd.exe` → `schtasks.exe` (user session) |
| Task action | Signed binary under `C:\Windows\CCM\...` | `powershell.exe` → `%LocalAppData%\Temp\update.ps1` |
| Change ticket | CHG-8810 | None |
| Signature | Signed Microsoft binary chain | Unsigned `.ps1` |
| **Verdict** | **Benign — do not escalate** | **Malicious — escalate** |

**Determination:** True positive — masquerading scheduled task persistence.

---

## 3. Enrichment

### Task Scheduler evidence

```
Event ID 4698 (Security) / Sysmon EID 1
Task: \ChromeUpdate
Command: schtasks /Create /TN ChromeUpdate /TR "powershell.exe -WindowStyle Hidden -File C:\Users\jsmith\AppData\Local\Temp\update.ps1" /SC ONLOGON
Initiating chain: cmd.exe → schtasks.exe
Task action: powershell.exe -WindowStyle Hidden -File C:\Users\jsmith\AppData\Local\Temp\update.ps1
User: CORP\jsmith
```

### Task XML excerpt

```xml
<Actions Context="Author">
  <Exec>
    <Command>powershell.exe</Command>
    <Arguments>-WindowStyle Hidden -File C:\Users\jsmith\AppData\Local\Temp\update.ps1</Arguments>
  </Exec>
</Actions>
```

### Domain-scope check — DC Security 4698

Queried the domain controller to determine whether `ChromeUpdate` propagated via GPO or appeared on other hosts:

```spl
index=wineventlog EventCode=4698 host=SRV-DC-01
| search TaskName="*ChromeUpdate*"
| stats count by dest, SubjectUserName, TaskName
```

**Result:** Zero matches on SRV-DC-01 — task was created locally on WKSTN-042 only, not pushed by Group Policy.

```spl
index=sysmon EventCode=1 CommandLine="*ChromeUpdate*"
| stats count by host User Image CommandLine
```

**Result:** Unique to WKSTN-042 — confirmed no lateral propagation across the endpoint fleet.

### Sentinel KQL — Defender persistence correlation

```kql
DeviceEvents
| where DeviceName == "WKSTN-042"
| where Timestamp between (datetime(2026-06-15 16:00:00) .. datetime(2026-06-15 16:15:00))
| where ActionType in ("ScheduledTaskCreated", "ScheduledTaskUpdated")
| project Timestamp, ActionType, FileName, ProcessCommandLine, InitiatingProcessFileName, AccountName
```

**Result:** Single `ScheduledTaskCreated` event at 16:04:18 UTC — Defender confirmed task creation with `powershell.exe` as initiator.

### Post-containment persistence checks

| Check | Query / Source | Result |
|-------|----------------|--------|
| Other scheduled tasks by `jsmith` | `schtasks /Query /FO LIST /V` on WKSTN-042 | Only `\ChromeUpdate` — no additional rogue tasks |
| Registry Run keys | `reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | Clean — no persistence in Run/RunOnce |
| WMI subscriptions | `Get-WMIObject -Namespace root\Subscription -Class __EventFilter` | None — no WMI persistence |
| Startup folder | `dir %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` | Empty — no startup shortcuts |

**Post-containment verdict:** Single persistence mechanism (`\ChromeUpdate` scheduled task). No additional footholds found.

### IOCs

| IOC | Type |
|-----|------|
| `\ChromeUpdate` task name | Persistence |
| `update.ps1` (SHA256: `b7e2c9f53e25d4871b695e2d19f8e404b9012a64c8d35f492b49c719ef164f91`) | Script |
| `10.10.30.10:8888` | C2 (lab) |

---

## 4. Containment

| Time (UTC) | Action | Performed By |
|------------|--------|--------------|
| 16:10 | Disabled task `\ChromeUpdate` | Praisel Ekpenyong |
| 16:12 | Isolated WKSTN-042 (Defender) | Praisel Ekpenyong |
| 16:15 | Escalated to Tier 2 | Praisel Ekpenyong |

---

## 5. Eradication

| Time (UTC) | Action |
|------------|--------|
| 16:25 | Deleted task via `schtasks /Delete /TN ChromeUpdate /F` |
| 16:28 | Quarantined `update.ps1` |
| 16:30 | Caldera operation stopped; cleanup abilities confirmed |

---

## 6. Recovery

| Time (UTC) | Action |
|------------|--------|
| 16:45 | Full AV scan — clean |
| 17:00 | Verified no task recurrence (`schtasks /Query /TN ChromeUpdate` → "not found") |
| 17:15 | Removed Defender isolation after T2 review; workstation returned to service |

---

## 7. Escalation

**Escalated to Tier 2 at 16:15 UTC** — Reason: confirmed persistence mechanism on finance VLAN workstation via masquerading scheduled task. T2 validated scope (single host, single persistence mechanism), approved recovery.

**Not escalated to IR team** — No domain admin involvement, no lateral movement, single persistence vector cleaned.

---

## 8. Timeline (UTC)

| Time | Event |
|------|-------|
| 16:02 | Caldera op started |
| 16:04:16 | `schtasks /Create /TN ChromeUpdate` executed (Sysmon EID 1) |
| 16:04:17 | Task file written to `C:\Windows\System32\Tasks\` (Sysmon EID 11) |
| 16:04:18 | Caldera T1053.005 ability completed; Wazuh 180002 alert fired |
| 16:04:52 | Defender persistence alert |
| 16:06 | Tier 1 acknowledged osTicket #48318 |
| 16:10 | Task disabled |
| 16:12 | Host isolated |
| 16:15 | Escalated to Tier 2 |
| 16:25 | Task deleted |
| 16:30 | Eradication complete |
| 17:15 | Closed |

---

## 9. Evidence

### Skills Demonstrated

- Scheduled task baseline comparison (SCCM benign vs. attacker masquerade)
- Domain-scope query to rule out GPO propagation
- Multi-persistence sweep (Run keys, WMI, startup folder) after primary vector found
- Cross-SIEM correlation: Wazuh 180002 + Defender + Splunk on same event
- Task XML inspection for hidden arguments

### Artifacts

| Artifact | Path |
|----------|------|
| Sysmon export | `artifacts/logs/sysmon-INC003-schtask.json` |
| Splunk query | `detections/splunk/T1053_scheduled_task.spl` |
| Wazuh rule | `detections/wazuh/local_rules.xml` (180002) |
| Logtest validation | `artifacts/tuning/wazuh-logtest-results.txt` (Test 3 + 4) |

---

## 10. Evidence Screenshots

Screenshots are supplemental walkthrough visuals. The Sysmon export, SPL/KQL, Wazuh rule, and logtest validation are the primary evidence for this case.

| Tool | Capture |
|------|---------|
| Wazuh | `artifacts/screenshots/wazuh-inc003.png` |
| Microsoft Defender | `artifacts/screenshots/defender-inc003.png` |
| osTicket | `tickets/sample-tickets.md` (Ticket #48318) |
| Sysmon (Event Viewer) | `artifacts/screenshots/sysmon-inc003.png` |

---

## 11. Recommendations

1. **Detection** — Alert when task **name** resembles known software (Chrome, Edge, Teams) but **action path** is user-writable (`%TEMP%`, `%APPDATA%`, `Downloads`).
2. **Correlation** — Cross-check task creation (4698) with the initiating process chain (`schtasks.exe` parent); flag when parent ≠ `svchost.exe`, `CcmExec.exe`, or `intune-agent`, or when the task action runs from user-writable paths.
3. **Hardening** — Restrict `schtasks.exe` and `Register-ScheduledTask` via AppLocker for standard users on finance VLAN.
4. **Monitoring** — Forward Security 4698/4702 events from all endpoints to Splunk and Sentinel for centralized task audit.
5. **Emulation** — Quarterly Caldera replay of `T1-Scheduled-Task` profile to validate detection regression.
6. **Registry Monitoring:** Deploy detections monitoring Registry Event ID 12/13 under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree` to detect scheduled tasks created via direct registry write. Evasive malware frequently bypasses XML task file creation (Sysmon Event ID 11) by writing properties directly to the registry cache.

---

## 12. Analyst Notes

This incident was triggered by a **live** Caldera operation (`2026-06-15-SCHTASK-LAB`) to validate Wazuh rule 180002 and Defender persistence detection. Evidence: [`docs/live-evidence-ledger.md`](../docs/live-evidence-ledger.md). The domain-scope query (DC 4698 + Splunk fleet-wide) confirmed the task did not propagate laterally. Production analysts would follow identical triage steps — baseline comparison, persistence sweep, scope check.
