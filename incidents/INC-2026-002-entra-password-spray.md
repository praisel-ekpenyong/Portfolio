# INC-2026-002 — Password Spray & Successful Cloud Sign-in (Case #2)

| Field | Value |
|-------|-------|
| **Incident ID** | INC-2026-002 |
| **Focus Area** | **Identity Logs & Cloud Sign-ins** |
| **osTicket** | #48305 |
| **Severity** | P2 — High |
| **Status** | Closed — True Positive (Lab-Controlled Spray) |
| **Detection Source** | Sentinel Analytics `Password spray against valid user` + Entra ID Protection risky sign-in |
| **Caldera Operation** | N/A — lab red-team spray script against test account |
| **MITRE ATT&CK** | T1110.003 (Password Spray), T1078 (Valid Accounts) |
| **Analyst** | Praisel Ekpenyong |
| **Lab Environment** | Lab 2 — Cloud SOC (`pe-soc-lab` tenant) |

---

## Executive Summary

Sentinel detected repeated failed sign-ins followed by one successful authentication for a valid finance user. I validated the account context, checked for post-authentication abuse, documented lab containment actions, and escalated because a successful login changed the case from noise to account-takeover risk. No mailbox rules, OAuth consent, MFA changes, or lateral movement were found before recovery.

### MITRE Evidence Map

| Technique | Evidence |
|-----------|----------|
| T1110.003 Password Spray | 18 failed sign-ins from the same source before success |
| T1078 Valid Accounts | Successful Exchange Online sign-in as `jsmith@corp.lab` |

---

## 1. Detection

**2026-06-14 11:10:14 UTC** — Microsoft Sentinel incident:

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
| Source IP context | Sanitized lab IP representing attacker infrastructure |
| User self-reported? | No — user did not open ServiceDesk ticket |
| MFA satisfied on success? | No — bypassed via legacy authentication (e.g., ActiveSync) which allowed authentication to succeed without triggering an interactive MFA challenge. |
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
| Last normal sign-in | 2026-06-13 08:14 UTC — Calgary, CA (office IP) |
| Risky sign-in location | Bucharest, RO (203.0.113.55) |

### IOC Enrichment

| IOC | Type | Enrichment Result |
|-----|------|-------------------|
| `203.0.113.55` | IP | Sanitized documentation IP used to represent malicious infrastructure; not corp VPN |
| `jsmith@corp.lab` | Account | Valid user; no travel ticket |
| User-Agent on success | `Mozilla/5.0 ...` | Linux x86_64 — user normally Windows |

```kql
// Sentinel — failure → success sequence
SigninLogs
| where UserPrincipalName == "jsmith@corp.lab"
| where TimeGenerated between (datetime(2026-06-14 11:00:00) .. datetime(2026-06-14 11:15:00))
| project TimeGenerated, ResultType, ResultDescription, IPAddress, Location, AppDisplayName, RiskLevelDuringSignIn
| order by TimeGenerated asc
```

```kql
// Endpoint correlation — same user, post-compromise window
DeviceLogonEvents
| where AccountName == "jsmith"
| where Timestamp > datetime(2026-06-14 11:09:00)
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
| where TimeGenerated between (datetime(2026-06-14 11:09:00) .. datetime(2026-06-14 11:30:00))
| where InitiatedBy has "jsmith"
| where OperationName in ("Add mailbox forwarding rule", "Add member to group", "Consent to application", "Add authentication method")
| project TimeGenerated, OperationName, Result, InitiatedBy
```

**Post-auth verdict:** Successful login occurred; **no** mailbox persistence or OAuth abuse before containment.

### Related Alerts (Last 24 hr)

- INC-2026-001 (2026-06-13) — same user/host; unrelated BITS case, already closed

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
2026-06-14T11:08:12Z  jsmith@corp.lab  50126  Invalid username or password  203.0.113.55  Bucharest, RO
2026-06-14T11:09:42Z  jsmith@corp.lab  0      Success                       203.0.113.55  Bucharest, RO  Risk: high
```

### Entra ID ResultType Reference
The following Microsoft Entra ID authentication event codes were utilized to parse the spray sequence:

| ResultType | Description | SOC Relevance / Action |
|------------|-------------|-------------------------|
| **`0`** | Success | Indicates successful authentication; flags potential compromise if preceded by failures. |
| **`50126`** | Invalid credentials | Represents a single failed authentication attempt (spray indicator). |
| **`50053`** | Account locked | Indicates account lockout due to repeated failures (targeted brute-force indicator). |
| **`50076`** / **`50079`** | MFA challenge required | Password was correct, but blocked/prompted by MFA. Critical for detecting partial bypasses. |

### Sentinel Analytics Rule

See `detections/sentinel/password_spray_entra.kql`

### Splunk (DC Security Log — optional cross-check)

```spl
index=wineventlog EventCode=4625 OR EventCode=4624
| search TargetUserName="jsmith"
| table _time EventCode TargetUserName IpAddress LogonType
```

---

## 10. Recommendations & Conditional Access Hardening

To mitigate password spray risks and secure the `pe-soc-lab` tenant, I recommend implementing the following Conditional Access (CA) and Identity Protection policies:

### 1. Block Legacy Authentication (Zero Trust Policy)
*   **Action**: Deploy a Conditional Access policy targeting all users, applying to all cloud apps.
*   **Control**: Under **Conditions → Client apps**, select **Legacy authentication clients** (Exchange ActiveSync, Other clients - MAPI, SMTP, POP3, IMAP4, etc.).
*   **Grant**: Set to **Block access**.
*   **Why**: Legacy protocols do not support interactive multi-factor authentication (MFA) prompts, making them prime targets for password sprays attempting to bypass MFA.

### 2. Risk-Based Sign-In Policies (Entra ID Protection)
*   **Action**: Configure a Sign-In Risk policy.
*   **Control**: Under **Conditions → Sign-in risk**, select **High** and **Medium** risk levels (triggered by anonymous IP addresses, atypical travel, or unfamiliar sign-in properties).
*   **Grant**: Require **MFA** or **Block access** if the user is outside corporate networks.
*   **Why**: This would have automatically blocked or challenged the Bucharest, RO login (detected as "High" risk by Entra ID Protection due to anonymous/unfamiliar features) before Exchange Online access was granted.

### 3. Require Compliant/Hybrid Joined Devices for High-Value Roles
*   **Action**: Deploy a policy targeting the **Finance** and **IT Admins** groups.
*   **Control**: Target all cloud apps.
*   **Grant**: Select **Grant access** → **Require device to be marked as compliant** (Intune) OR **Require Microsoft Entra hybrid joined device**.
*   **Why**: Even if an attacker compromises a valid password, they cannot authenticate because their device is non-compliant/unmanaged (Linux x86_64 in this incident).

### 4. Geographical Restrictions (Named Locations)
*   **Action**: Create Named Locations for authorized corporate operating regions (e.g., Canada and US) and office IP ranges.
*   **Control**: Apply a Conditional Access policy blocking sign-ins from all locations except the defined Named Locations, or requiring MFA + phishing-resistant credentials (FIDO2) for external regions.
*   **Why**: Directly blocks spray and authentication attempts originating from non-business regions (e.g., Romania).

### 5. Detection & Lockout Tuning
*   **Smart Lockout**: Configure Entra ID Smart Lockout thresholds to lock accounts after 5 failed attempts from a single IP, preventing brute force while minimizing legitimate user lockouts.
*   **Analytics Rule Tune**: Continue utilizing [password_spray_entra.kql](../detections/sentinel/password_spray_entra.kql) to identify any anomalous spray trends that bypass individual smart lockout thresholds.

### 6. Training & Process Transfer
*   **Training**: Educate high-privilege users (specifically finance) about credential reuse risks and to immediately report unexpected MFA prompts (MFA fatigue/push exhaustion attacks).
*   **Process Transfer**: Keep [INC-2026-004](INC-2026-004-false-positive-vpn.md) as a paired false-positive contrast example for onboarding new analysts.


---

## 11. Evidence Screenshots

Screenshots are supplemental walkthrough visuals. The SigninLogs excerpt, Sentinel rule, and post-authentication checks are the primary evidence for this case.

| Tool | Capture |
|------|---------|
| Microsoft Sentinel | `artifacts/screenshots/sentinel-inc002.png` |
| osTicket | `artifacts/screenshots/osticket-48305.png` |

---

## 12. Analyst Notes

Password spray was executed with a controlled lab script against the `jsmith` test account to validate Sentinel analytics and Entra risky-sign-in correlation. Production analysts would follow identical triage steps: confirm valid user, check for successful auth, revoke sessions, reset credentials, and escalate when account takeover is confirmed.
