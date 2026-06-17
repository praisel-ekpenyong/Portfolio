# INC-2026-003 — Suspicious Scheduled Task Persistence (Case #4)

| Field | Value |
|-------|-------|
| **Incident ID** | INC-2026-003 |
| **Portfolio order** | **4 — Persistence** |
| **osTicket** | #48318 |
| **Severity** | P2 — High |
| **Status** | Closed — True Positive (Lab Emulation) |
| **Detection Source** | Wazuh 180002 + Sysmon EID 1/11 + Defender |
| **Caldera Operation** | `2026-06-19-SCHTASK-LAB` |
| **MITRE ATT&CK** | T1053.005 (Scheduled Task), T1059.001 (PowerShell) |
| **Analyst** | Praisel Ekpenyong |
| **Lab Environment** | Hybrid — Lab 1 (Wazuh/Sysmon/Splunk) + Lab 2 (Defender) |

---

## 1. Detection

**2026-06-19 16:04:18 UTC** — Wazuh Rule 180002:

```
Suspicious scheduled task created — ChromeUpdate name with user-writable action path
Host: WKSTN-042
User: CORP\jsmith
```

**16:04:52 UTC** — Defender: *Persistence mechanism: scheduled task with suspicious action*

Task created **4 minutes after** PowerShell execution from INC-2026-005 drill window (same lab user — unrelated closed case).

---

## 2. Validation

| Check | Result |
|-------|--------|
| Legitimate Chrome enterprise update? | No — real Chrome GPO tasks use `Google\Update` path under `Program Files` |
| Change ticket for software deployment? | None |
| Task name `ChromeUpdate` | Matches attacker mimicry pattern (plausible name, wrong path) |
| Action executes from user profile? | `C:\Users\jsmith\AppData\Local\Temp\update.ps1` |
| Creator process | `powershell.exe` (not `svchost.exe` or SCCM `CcmExec.exe`) |
| Caldera correlation | T1053.005 ability finished 16:04:16 UTC |

### Baseline comparison — legitimate vs suspicious

| Attribute | Legitimate SCCM task (WKSTN-099) | Suspicious task (WKSTN-042) |
|-----------|----------------------------------|----------------------------|
| Creator | `CcmExec.exe` | `powershell.exe` |
| Action path | `C:\Windows\CCM\...` | `%LocalAppData%\Temp\update.ps1` |
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
Action: powershell.exe -WindowStyle Hidden -File C:\Users\jsmith\AppData\Local\Temp\update.ps1
Author: CORP\jsmith
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

### Enterprise scoping (Splunk)

```spl
index=sysmon EventCode=1
| search CommandLine="*schtasks*" OR CommandLine="*Register-ScheduledTask*"
| search CommandLine="*ChromeUpdate*"
| stats count by host User Image CommandLine
```

**Result:** Unique to WKSTN-042 — not widespread deployment.

### IOCs

| IOC | Type |
|-----|------|
| `\ChromeUpdate` task name | Persistence |
| `update.ps1` SHA256 `b7e2...4f91` | Script |
| `10.10.30.10:8888` | C2 (lab) |

---

## 4. Containment

| Time (UTC) | Action |
|------------|--------|
| 16:10 | Disabled task `\ChromeUpdate` |
| 16:12 | Isolated WKSTN-042 (Defender) |
| 16:15 | Escalated to Tier 2 |

---

## 5. Eradication

| Time (UTC) | Action |
|------------|--------|
| 16:25 | Deleted task via `schtasks /Delete /TN ChromeUpdate /F` |
| 16:28 | Quarantined `update.ps1` |
| 16:30 | Caldera operation stopped |

---

## 6. Recovery

Host de-isolated 17:15 UTC after clean scan. No task recurrence.

---

## 7. Escalation

Tier 2 at 16:15 — persistence on WKSTN-042. Scoped to single host.

---

## 8. Timeline (UTC)

| Time | Event |
|------|-------|
| 16:02 | Caldera op started |
| 16:04:16 | Scheduled task ability completed |
| 16:04:18 | Wazuh 180002 alert |
| 16:04:52 | Defender persistence alert |
| 16:10 | Task disabled |
| 16:30 | Eradication complete |
| 17:15 | Closed |

---

## 9. Evidence

| Artifact | Path |
|----------|------|
| Sysmon export | `artifacts/logs/sysmon-INC003-schtask.json` |
| Splunk query | `detections/splunk/T1053_scheduled_task.spl` |
| Wazuh rule | `detections/wazuh/local_rules.xml` (180002) |

---

## 10. Recommendations

1. Alert when task **name** resembles known software but **action path** is user-writable.
2. Correlate task creation (4698) with initiating process ≠ SCCM/Intune.
3. Quarterly Caldera replay of `T1-Scheduled-Task` profile.