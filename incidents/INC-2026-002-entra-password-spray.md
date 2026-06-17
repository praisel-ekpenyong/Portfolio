# INC-2026-002 — Password Spray & Successful Cloud Sign-in (Case #2)

| Field | Value |
|-------|-------|
| **Incident ID** | INC-2026-002 |
| **Portfolio order** | **2 — Identity** |
| **osTicket** | #48305 |
| **Severity** | P2 — High |
| **Status** | Closed — True Positive (Lab-Controlled Spray) |
| **Detection Source** | Sentinel Analytics `Password spray against valid user` + Entra ID Protection risky sign-in |
| **Caldera** | N/A — lab red-team spray script against test account |
| **MITRE ATT&CK** | T1110.003 (Password Spray), T1078 (Valid Accounts) |
| **Analyst** | Praisel Ekpenyong |
| **Lab Environment** | Lab 2 — Cloud SOC (`pe-soc-lab` tenant) |

---

## 1. Detection

**2026-06-18 11:10:14 UTC** — Microsoft Sentinel incident:

```
Alert: Password spray against valid user
Rule: password_spray_entra (analytics)
User: jsmith@corp.lab
Source IP: 203.0.113.55
Failed attempts: 18 in 8 minutes
Successful sign-in: 1 at 11:09:42 UTC
```

**11:10:28 UTC** — Entra ID Protection:

```
Risk level: High
Risk detail: unfamiliarFeatures, anonymous IP
User: jsmith@corp.lab (CORP\jsmith)
App: Office 365 Exchange Online
```

Praisel Ekpenyong (SOC Analyst L1) acknowledged osTicket #48305 within 2 minutes.

---

## 2. Validation

| Check | Result |
|-------|--------|
| Valid AD / Entra user? | **Yes** — `jsmith` is active finance analyst |
| Change ticket / expected lockout test? | None |
| Spray pattern (low-and-slow, one user)? | Yes — 18 failures then 1 success |
| IP reputation | AbuseIPDB score 78 — known malicious range |
| User self-reported? | No — user did not open ServiceDesk ticket |
| MFA satisfied on success? | Yes — attacker had valid password (lab spray succeeded) |
| Correlated endpoint activity? | Defender: interactive session on WKSTN-042 within 3 min of sign-in |

**Determination:** True positive — successful password spray against valid corporate account.

**Contrast with INC-2026-004:** INC-004 used **invalid** usernames (admin, root) with **zero** successes and matched change ticket CHG-8821. INC-002 targets a **real** user with a **successful** authentication — containment required.

---

## 3. Enrichment

### User & Account Context

| Attribute | Value |
|-----------|-------|
| UPN | jsmith@corp.lab |
| SAM | CORP\jsmith |
| Department | Finance |
| MFA registered | Yes (Authenticator app) |
| Last normal sign-in | 2026-06-17 08:14 UTC — Calgary, CA (office IP) |
| Risky sign-in location | Bucharest, RO (203.0.113.55) |

### IOC Enrichment

| IOC | Type | Enrichment Result |
|-----|------|-------------------|
| `203.0.113.55` | IP | AbuseIPDB 78 — malicious; not corp VPN |
| `jsmith@corp.lab` | Account | Valid user; no travel ticket |
| User-Agent on success | `Mozilla/5.0 ...` | Linux x86_64 — user normally Windows |

```kql
// Sentinel — failure → success sequence
SigninLogs
| where UserPrincipalName == "jsmith@corp.lab"
| where TimeGenerated between (datetime(2026-06-18 11:00:00) .. datetime(2026-06-18 11:15:00))
| project TimeGenerated, ResultType, ResultDescription, IPAddress, Location, AppDisplayName, RiskLevelDuringSignIn
| order by TimeGenerated asc
```

```kql
// Endpoint correlation — same user, post-compromise window
DeviceLogonEvents
| where AccountName == "jsmith"
| where Timestamp > datetime(2026-06-18 11:09:00)
| project Timestamp, DeviceName, LogonType, ActionType, RemoteIP
```

**Result:** Single interactive logon to WKSTN-042 after cloud sign-in — no lateral movement to other hosts.

### Post-authentication investigation (11:10–11:20 UTC)

| Check | Query / source | Result |
|-------|----------------|--------|
| MFA method registration | Entra audit: `Add authentication method` | **None** — no attacker MFA enrollment |
| Mailbox forwarding rules | `Get-InboxRule` / EXO audit | **None added** |
| OAuth app consent | Entra audit `Consent to application` | **None** |
| SharePoint mass download | `OfficeActivity` blob download spike | **None** — normal activity only |
| Unmanaged device sign-in | Conditional Access | **Non-compliant device** — flagged in risky sign-in |
| Pre vs post-auth window | Timeline | 18 failures (11:02–11:09) → 1 success (11:09:42) → Tier 1 action (11:15) |

```kql
AuditLogs
| where TimeGenerated between (datetime(2026-06-18 11:09:00) .. datetime(2026-06-18 11:30:00))
| where InitiatedBy has "jsmith"
| where OperationName in ("Add mailbox forwarding rule", "Add member to group", "Consent to application", "Add authentication method")
| project TimeGenerated, OperationName, Result, InitiatedBy
```

**Post-auth verdict:** Successful login occurred; **no** mailbox persistence or OAuth abuse before containment.

### Related Alerts (Last 24 hr)

- INC-2026-001 (2026-06-17) — same user/host; unrelated BITS case, already closed

---

## 4. Containment

| Time (UTC) | Action | Performed By |
|------------|--------|--------------|
| 11:15:00 | Revoked all Entra refresh tokens for `jsmith@corp.lab` | Praisel Ekpenyong |
| 11:16:00 | Disabled account in Entra ID (temporary) | Praisel Ekpenyong |
| 11:18:00 | Forced sign-out from all Office 365 sessions | Praisel Ekpenyong |
| 11:20:00 | Blocked source IP `203.0.113.55` at conditional access (emergency policy) | Tier 1 via playbook |
| 11:22:00 | Isolated WKSTN-042 via Defender (precautionary) | Praisel Ekpenyong |

---

## 5. Eradication

| Time (UTC) | Action |
|------------|--------|
| 11:35:00 | Password reset via helpdesk workflow — user verified by phone |
| 11:40:00 | MFA re-registration — old Authenticator revoked |
| 11:45:00 | Reviewed mailbox rules and OAuth app consents — none added |
| 11:50:00 | Full AV scan on WKSTN-042 — clean |

---

## 6. Recovery

| Time (UTC) | Action |
|------------|--------|
| 11:55:00 | Re-enabled Entra account after password + MFA reset |
| 12:00:00 | Removed Defender isolation on WKSTN-042 after T2 review |
| 12:15:00 | User briefed on credential reuse risk; temporary CA policy retained 24 hr |

---

## 7. Escalation

**Escalated to Tier 2 at 11:22 UTC** — Reason: successful authentication after password spray against valid finance user; potential account takeover.

Tier 2 confirmed no mail forwarding rules, no inbox delegation, and no additional hosts touched. Closed as contained spray — no further IR engagement.

---

## 8. Timeline (UTC)

| Time | Event |
|------|-------|
| 11:02:00 | Lab spray script begins — failed logons from 203.0.113.55 |
| 11:09:42 | Successful sign-in to Exchange Online |
| 11:09:55 | Entra ID Protection flags risky sign-in |
| 11:10:14 | Sentinel incident #2863 created |
| 11:12:00 | Tier 1 investigation began |
| 11:16:00 | Account disabled |
| 11:22:00 | Escalated to Tier 2 |
| 11:35:00 | Password reset complete |
| 12:15:00 | Incident closed |

---

## 9. Evidence

### SigninLogs Excerpt

```
2026-06-18T11:08:12Z  jsmith@corp.lab  50126  Invalid username or password  203.0.113.55  Bucharest, RO
2026-06-18T11:09:42Z  jsmith@corp.lab  0      Success                       203.0.113.55  Bucharest, RO  Risk: high
```

### Sentinel Analytics Rule

See `detections/sentinel/password_spray_entra.kql`

### Splunk (DC Security Log — optional cross-check)

```spl
index=wineventlog EventCode=4625 OR EventCode=4624
| search TargetUserName="jsmith"
| table _time EventCode TargetUserName IpAddress LogonType
```

---

## 10. Recommendations

1. **Detection** — Alert when `>15` failures + `1` success for same UPN within 15 minutes (current rule).
2. **Conditional Access** — Block legacy auth; require compliant device for finance group.
3. **Identity** — Enable Entra smart lockout; review password policy for sprayed accounts.
4. **Training** — Finance users: unique passwords, report unexpected MFA prompts.
5. **Contrast doc** — Keep INC-2026-004 as paired false-positive example for onboarding.

---

## 11. Evidence Screenshots

| Tool | Capture |
|------|---------|
| Microsoft Sentinel | `artifacts/screenshots/sentinel-inc002.png` |
| osTicket | `artifacts/screenshots/osticket-48305.png` |

---

## 12. Analyst Notes

Password spray was executed with a controlled lab script against the `jsmith` test account to validate Sentinel analytics and Entra risky-sign-in correlation. Production analysts would follow identical triage steps: confirm valid user, check for successful auth, revoke sessions, reset credentials, and escalate when account takeover is confirmed.