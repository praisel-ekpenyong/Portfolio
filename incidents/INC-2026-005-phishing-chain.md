# INC-2026-005 — Phishing → Endpoint Compromise (Caldera T1-Phish-to-Host)

| Field | Value |
|-------|-------|
| **Incident ID** | INC-2026-005 |
| **osTicket** | #48340 |
| **Severity** | P2 — High |
| **Status** | Closed — True Positive (Lab Emulation) |
| **Detection Source** | User report + Sentinel PowerShell rule |
| **Caldera Operation** | `2026-06-20-PHISH-LAB` |
| **MITRE ATT&CK** | T1566.001, T1204.002, T1059.001, T1071.001 |
| **Related** | Email analysis: [`phishing/email-header-analysis.md`](../phishing/email-header-analysis.md) |
| **Analyst** | Praisel Ekpenyong |
| **Lab Environment** | Lab 2 — Cloud SOC (Sentinel, Defender, Entra ID) |

---

## 1. Detection

Dual detection path:

1. **13:57 UTC** — User reported suspicious email (ServiceDesk → SOC)
2. **14:01 UTC** — Sentinel: PowerShell download cradle on WKSTN-042

Praisel Ekpenyong acknowledged osTicket #48340 within 4 minutes.

---

## 2. Validation

| Email indicators | Endpoint indicators |
|------------------|---------------------|
| SPF/DKIM/DMARC fail | `powershell.exe -enc ...` parent `outlook.exe` |
| Spoofed vendor domain | File write to `%TEMP%\update.ps1` |
| Reply-To ProtonMail | Outbound HTTP to 10.10.30.10:8888 (Caldera lab C2) |
| Caldera correlation | T1-Phish-to-Host abilities finished 14:00 UTC |

**Determination:** True positive — phishing led to code execution.

---

## 3. Enrichment

### Email IOCs

| IOC | Type |
|-----|------|
| `login-update.tk` | Domain |
| `203.0.113.88` | Sending IP |
| `attacker-drop@protonmail.com` | Reply-To |

### Endpoint IOCs

| IOC | Type |
|-----|------|
| `%TEMP%\update.ps1` | File |
| `10.10.30.10:8888` | C2 URL |
| SHA256 `b7e2...4f91` | Script hash |

### Sentinel KQL Used

```kql
DeviceProcessEvents
| where DeviceName == "WKSTN-042"
| where Timestamp between (datetime(2026-06-20 13:55:00) .. datetime(2026-06-20 14:10:00))
| where FileName =~ "powershell.exe"
| where InitiatingProcessFileName =~ "outlook.exe"
| project Timestamp, AccountName, ProcessCommandLine, InitiatingProcessFileName
```

---

## 4. Containment

| Time (UTC) | Action | Performed By |
|------------|--------|--------------|
| 14:05 | Reset `jsmith` password | Praisel Ekpenyong |
| 14:06 | Isolate WKSTN-042 via Defender | Praisel Ekpenyong |
| 14:08 | Block `login-update.tk` on proxy | Tier 1 |
| 14:10 | Mail trace — 3 other recipients; no other clicks | Tier 1 |

---

## 5. Eradication

| Time (UTC) | Action |
|------------|--------|
| 14:20 | Quarantine `update.ps1` via MDE |
| 14:25 | Stop Caldera operation; sandcat process terminated |
| 14:30 | No persistence beyond Caldera agent confirmed |

---

## 6. Recovery

| Time (UTC) | Action |
|------------|--------|
| 15:45 | Full AV scan — clean |
| 16:00 | User training scheduled |
| 16:30 | Host de-isolated; returned to service |

---

## 7. Escalation

**Escalated to Tier 2 at 14:15 UTC** — mail gateway policy review (DMARC `p=none` on lookalike domain). T2 filed change request for vendor-domain DMARC hardening.

---

## 8. Timeline (UTC)

| Time | Event |
|------|-------|
| 13:55 | Phishing email delivered |
| 13:57 | User reported phish to ServiceDesk |
| 13:58 | User clicked link |
| 13:59 | PowerShell cradle executed |
| 14:00 | Caldera T1-Phish-to-Host abilities complete |
| 14:01 | Sentinel alert |
| 14:05 | Containment began |
| 16:30 | Closed |

---

## 9. Recommendations

1. Move DMARC to `p=quarantine` for vendor domains category
2. Attack simulation training — report phish button
3. ASR rule: block Office child process PowerShell
4. Annual Caldera phishing chain regression test

---

## 10. Evidence Screenshots

| Tool | Capture |
|------|---------|
| Microsoft Sentinel | `artifacts/screenshots/sentinel-inc005.png` |
| Microsoft Defender | `artifacts/screenshots/defender-inc005.png` |
| osTicket | `artifacts/screenshots/osticket-48340.png` |

---

## 11. Analyst Notes

Email delivery is documented in `phishing/`; Caldera executes post-click TTPs only. Production analysts follow the same correlation: headers → user report → endpoint telemetry → containment.