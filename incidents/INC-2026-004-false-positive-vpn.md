# INC-2026-004 — False Positive: VPN Concentrator Auth Failure Storm

| Field | Value |
|-------|-------|
| **Incident ID** | INC-2026-004 |
| **osTicket** | #48322 |
| **Severity** | Initial P3 → Downgraded to P5 |
| **Status** | Closed — False Positive |
| **Detection Source** | Sentinel Analytics `Multiple failed VPN logins` |
| **Caldera** | N/A — organic noise (not emulation) |
| **MITRE (ruled out)** | T1110.001 Brute Force |
| **Analyst** | Praisel Ekpenyong |
| **Lab Environment** | Lab 2 — Cloud SOC (`pe-soc-lab` / Sentinel) |

---

## 1. Detection

**2026-06-20 03:12:00 UTC** — Sentinel incident:

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
| Source IP reputation | AbuseIPDB score 12 — known commercial VPN exit node |
| Internal user involved? | No — usernames do not exist in AD |
| Successful login after failures? | Zero successes |
| Correlated internal compromise? | No EDR/DC alerts |
| Business event? | **Yes** — pfSense geo-block rule deployed 03:00 UTC; external scanner retried old paths |

### Additional Context

Change ticket **CHG-8821**: "Enable geo-blocking on VPN interface — APAC region test."

Scanner IP 203.0.113.45 geolocated to region now blocked; failures are **expected noise** at rule cutover.

---

## 3. Enrichment

```kql
// Sentinel — confirm no success
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType != "0"
| where IPAddress == "203.0.113.45"
| summarize Failed=count() by UserPrincipalName, ResultType

// Result: no matching Entra sign-ins (VPN is separate IdP)
```

Firewall log sample:

```
openvpn: 203.0.113.45:52144 AUTH FAILED (tls-auth failure)
openvpn: 203.0.113.45:52144 Connection reset
```

**IOC enrichment** (`scripts/ioc_enrichment.py`):

| IOC | Verdict |
|-----|---------|
| 203.0.113.45 | Generic scanner / VPN exit — not targeted APT |

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

## 5. Why This Matters for Tier 1

Demonstrates:

- Not every alert is an incident
- Correlation with **change management** before escalation
- Distinguishing internet background noise from credential stuffing against real accounts
- Proper severity downgrade and ticket closure notes

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

---

## 8. Evidence Screenshots

| Tool | Capture |
|------|---------|
| Microsoft Sentinel | `artifacts/screenshots/sentinel-inc004.png` |
| osTicket | `artifacts/screenshots/osticket-48322.png` |

Regenerate: `python scripts/render_screenshots.py`

---

## 9. Contrast with Identity Scenarios

| Attribute | INC-2026-004 (FP) | INC-2026-002 (TP identity) | INC-2026-001 (TP endpoint) |
|-----------|-------------------|---------------------------|---------------------------|
| Alert type | VPN auth failures | Entra password spray | BITS download |
| User validity | Invalid usernames | **Valid** user (`jsmith`) | Real user context |
| Successful auth | Zero | **One** after 18 failures | N/A (execution) |
| Change ticket | Explains spike | None | None |
| Action | Close + tune | Revoke sessions + reset creds | Contain + eradicate |