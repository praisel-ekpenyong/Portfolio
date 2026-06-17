# Phishing & Email Header Investigation (Tier 1)

Supports **T1-Phish-to-Host** Caldera chain — user reports email; Caldera executes post-click TTPs on endpoint.

## Tier 1 Workflow

```
User report / mail gateway alert
    → Preserve headers (.eml)
    → Authentication triad (SPF, DKIM, DMARC)
    → Display vs envelope addresses
    → URL / attachment IOC extraction
    → Cross-check proxy and EDR for click
    → Open ticket + link to endpoint incident if confirmed
```

## Sample Suspicious Email Summary

| Field | Value |
|-------|-------|
| Reported by | jsmith@corp.lab |
| Subject | URGENT: Invoice Overdue #88421 |
| Display From | Accounts Payable <payable@vendor-secure.com> |
| Received | 2026-06-17 13:55 UTC |

## Header Analysis (Key Lines)

```
Return-Path: <bounce+xyz@mail.vendor-secure.com>
Received: from mail-sender-unknown (203.0.113.88) by mx.corp.lab
Authentication-Results: mx.corp.lab;
    spf=fail (sender IP 203.0.113.88) smtp.mailfrom=vendor-secure.com;
    dkim=none;
    dmarc=fail action=none header.from=vendor-secure.com
From: Accounts Payable <payable@vendor-secure.com>
Reply-To: attacker-drop@protonmail.com
Message-ID: <not-random@DESKTOP-EVIL>
```

## Authentication Triad

| Check | Result | Tier 1 Interpretation |
|-------|--------|----------------------|
| **SPF** | fail | Sending IP not authorized for domain |
| **DKIM** | none | No cryptographic signature |
| **DMARC** | fail | Policy violation — treat as spoofed |

**Verdict:** Likely phishing / spoofed vendor.

## Address Anomalies

| Anomaly | Detail |
|---------|--------|
| Display vs Reply-To | From shows vendor; reply goes to ProtonMail |
| Return-Path mismatch | Bounce domain ≠ From domain |
| Message-ID | Local PC hostname pattern — mass-mail tool |

## URL Extraction

Body link (defanged):

```
hxxps://vendor-secure[.]com[.]login-update[.]tk/invoice?id=88421
```

| IOC | Enrichment |
|-----|------------|
| Domain `login-update.tk` | Suspicious TLD |
| Path `/invoice` | Credential harvest pattern |

## Mail Gateway vs Client

- **Gateway** should quarantine on DMARC fail — if delivered, check policy mode (`p=none` vs `p=reject`)
- **Client** — user clicked before report; correlate with proxy logs

## Proxy / EDR Correlation

```spl
index=proxy user=jsmith url="*login-update*"
| table _time url action status
```

```kql
DeviceNetworkEvents
| where InitiatingProcessAccountName == "jsmith"
| where RemoteUrl has "login-update"
| project Timestamp, RemoteUrl, ActionType
```

## Link to Caldera (Post-Click)

After user execution, run Caldera **T1-Phish-to-Host** on WKSTN-042:

| Time | Event |
|------|-------|
| 13:58 | User click (proxy log) |
| 13:59 | PowerShell download cradle (Sysmon) |
| 14:00 | Caldera ability complete |

Full incident: `sample-phishing-incident.md`

## Tier 1 Ticket Notes

Document:

1. Header authentication results (copy/paste)
2. All URLs and hashes (attachments)
3. User actions (clicked? enabled macros? forwarded?)
4. Whether other users received same campaign (mail trace)

## Tools Reference

| Tool | Use |
|------|-----|
| Outlook → View Source | Export headers |
| MXToolbox Header Analyzer | Quick SPF/DKIM parse |
| `ioc_enrichment.py` | Domain/URL reputation |
| Microsoft 365 Threat Explorer | Campaign scope (if M365) |