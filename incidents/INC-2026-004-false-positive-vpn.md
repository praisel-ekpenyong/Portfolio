# INC-2026-004 — False Positive & Detection Tuning (Case #5)

| Field | Value |
|-------|-------|
| **Incident ID** | INC-2026-004 |
| **Focus Area** | **Alert Tuning & Noise Reduction** |
| **osTicket** | #48322 |
| **Severity** | Initial P3 (Normal) → Downgraded to P5 (Low) |
| **Status** | Closed — False Positive |
| **Detection Source** | Sentinel Analytics `Multiple failed VPN logins` |
| **Caldera Operation** | N/A — live OpenVPN auth failures (pfSense → Sentinel); not log replay |
| **MITRE (ruled out)** | T1110.001 Brute Force |
| **Analyst** | Praisel Ekpenyong |
| **Lab Environment** | Lab 2 — Azure Cloud SOC (`pe-soc-lab` / Sentinel) |

---

## Executive Summary

Sentinel created a VPN brute-force alert after **47 live failed OpenVPN attempts** recorded on pfSense and forwarded to Sentinel `VPNLogs` from a sanitized scanner source (`203.0.113.45`). I validated there were no valid AD users, no successful authentication, no related EDR/DC alerts, and a matching VPN geo-block change ticket (CHG-8821). The case was downgraded, closed as a false positive, and used to tune the VPN rule. Evidence: [`docs/live-evidence-ledger.md`](../docs/live-evidence-ledger.md).

### MITRE Evidence Map

| Technique | Evidence |
|-----------|----------|
| T1110.001 Brute Force (ruled out) | Invalid usernames, zero successes, and matching CHG-8821 change window |

---

## 1. Detection

**2026-06-16 03:12:00 UTC** — Sentinel incident:

```
Alert: Multiple failed VPN logins from single source
Source IP: 203.0.113.45
Target: vpn.corp.lab (pfSense OpenVPN)
Failed attempts: 47 in 10 minutes
Usernames: admin, root, test, vpnuser, ...
```

---

## 2. Validation (False Positive Analysis)

| Check | Result |
|-------|--------|
| Source IP context | Sanitized documentation IP representing commercial VPN/scanner noise |
| Internal user involved? | No — usernames do not exist in AD |
| Successful login after failures? | Zero successes |
| Correlated internal compromise? | No EDR/DC alerts |
| Business event? | **Yes** — pfSense geo-block rule deployed 03:00 UTC; external scanner retried old paths |

### Additional Context

Change ticket **CHG-8821**: "Enable geo-blocking on VPN interface — APAC region test."

Scanner IP 203.0.113.45 represents a sanitized source in the region now blocked; failures are **expected noise** at rule cutover.

---

## 3. Enrichment

```kql
// Sentinel — confirm zero successful sign-ins from source IP
SigninLogs
| where TimeGenerated > ago(24h)
| where IPAddress == "203.0.113.45"
| summarize Failed = countif(ResultType != "0"), Succeeded = countif(ResultType == "0") by UserPrincipalName

// Result: no matching sign-ins (VPN is separate IdP; no Entra activity from IP)
```

Firewall log sample:

```
openvpn: 203.0.113.45:52144 AUTH FAILED (tls-auth failure)
openvpn: 203.0.113.45:52144 Connection reset
```

**IOC enrichment** (`scripts/ioc_enrichment.py`):

| IOC | Verdict |
|-----|---------|
| 203.0.113.45 | Sanitized scanner / VPN-exit source — not targeted APT |

---

## 4. Decision

| Action | Taken? |
|--------|--------|
| Block IP permanently | No — geo-block already effective |
| Escalate to IR | No |
| User account disable | N/A |
| Tune detection | Yes — see recommendations |

**Closed as false positive** at 03:45 UTC with documentation.

---

## 5. Operational Takeaway

This case highlights key operational practices for alert triage:

- Not every alert is an incident.
- Always correlate with **change management** before escalating.
- Distinguish external internet noise/scanning from real credential stuffing campaigns.
- Downgrade severities properly and write descriptive ticket closure notes.

---

## 6. osTicket Closure Note (Sample)

```
Investigated 47 failed OpenVPN auth attempts from 203.0.113.45 between 03:02-03:12 UTC.
No valid AD users attempted. No successful authentication. Activity coincides with CHG-8821
geo-block deployment. Classified as external scan noise. No containment required.
Detection tuning request filed: exclude first 24h post geo-block change window.
```

---

## 7. Recommendations

1. Add Sentinel suppression window linked to change tickets tagged `vpn-policy`.
2. Alert only when **valid username** + **>10 failures** + **same /24 as prior successful user login**.
3. Weekly report of blocked VPN countries for leadership — not individual tickets.
4. **Dynamic Change Management Integration:** In a production environment, rather than hardcoding change windows inline using static `datatable` variables in KQL, the analytics rule should perform an inner join or lookup on a Sentinel table populated by change-management API logs (e.g. from ServiceNow or Jira Service Desk). This automates suppression based on approved change windows dynamically.

---

## 8. Evidence Screenshots

Screenshots are supplemental walkthrough visuals. The VPN log sample, tuned KQL, and ticket closure note are the primary evidence for this case.

| Tool | Capture |
|------|---------|
| Microsoft Sentinel | `artifacts/screenshots/sentinel-inc004.png` |
| osTicket | `artifacts/screenshots/osticket-48322.png` |

---

## 9. Detection Tuning Artifacts

### Original rule

`detections/sentinel/vpn_failed_logins.kql` — fires on `>30` failures from single IP in 10 minutes (no username validity check).

### Tuned rule

`detections/sentinel/vpn_failed_logins_tuned.kql` — requires **valid AD username** and `>10` failures; change-window suppression linked to ticket tag `vpn-policy`.

The lab rule uses an inline `vpnPolicyChangeWindows` datatable for CHG-8821; in production this would be replaced by a join to the change-management source of record.

### Validation (`artifacts/tuning/wazuh-logtest-results.txt`)

| Test | Input | Original | Tuned |
|------|-------|----------|-------|
| INC-004 VPN noise | 47 fails, invalid users, post CHG-8821 | **MATCH** | **NO MATCH** |
| INC-002 spray TP | Valid user + success after failures | N/A (Entra rule) | N/A |
| INC-003 schtask | `ChromeUpdate` from Temp | N/A | Rule 180002 **MATCH** |
| SCCM benign task | `CcmExec` + `CCM\RemoteUpdate.exe` | N/A | Rule 180002 **NO MATCH** |

### Residual risk

Tuning reduces geo-block cutover noise. Risk accepted: spray against valid users still caught by `password_spray_entra.kql` (INC-002).

### Linked tuning ticket

osTicket **#48355** — acceptance: no High/Normal VPN tickets during tagged change windows.

### Live evidence

All VPN failure events were **live** `AUTH_FAILED` records on pfSense during the CHG-8821 window, forwarded to Sentinel — not replayed or injected logs. See [`docs/live-evidence-ledger.md`](../docs/live-evidence-ledger.md).

---

## 10. Contrast with Identity Scenarios

| Attribute | INC-2026-004 (FP) | INC-2026-002 (TP identity) | INC-2026-001 (TP endpoint) |
|-----------|-------------------|---------------------------|---------------------------|
| Alert type | VPN auth failures | Entra password spray | BITS download |
| User validity | Invalid usernames | **Valid** user (`jsmith`) | Real user context |
| Successful auth | Zero | **One** after 18 failures | N/A (execution) |
| Change ticket | Explains spike | None | None |
| Action | Close + tune | Revoke sessions + reset creds | Contain + eradicate |
